import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from sqlmodel import Session, select

from app.config import AUTO_BLOCK_SCORE, BLOCK_HOURS, NOTIFY_MIN_SCORE
from app.db import engine, get_session, init_db
from app.enrich import lookup_hash, lookup_ip
from app.models import Alert, AlertIn, Block, BlockIn, Severity, Status, StatusUpdate
from app.notify import format_alert, notify
from app.response import BlockRefused, active_blocks, block_ip, unblock_ip
from app.scoring import priority_for, score_alert
from app.security import require_api_key

log = logging.getLogger("alertsense")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    mode = f"AUTO (score >= {AUTO_BLOCK_SCORE})" if AUTO_BLOCK_SCORE else "APPROVAL (analyst confirms)"
    log.warning("AlertSense response mode: %s", mode)
    yield


app = FastAPI(title="AlertSense", version="0.4.0", lifespan=lifespan)


# ---------------------------------------------------------------- triage
def triage(alert_id: int) -> None:
    """Enrich, score, maybe auto-block, maybe notify. Runs after the API has replied."""
    try:
        with Session(engine) as session:
            alert = session.get(Alert, alert_id)
            if not alert:
                return
            intel: dict = {}
            if alert.src_ip:
                intel["ip"] = lookup_ip(alert.src_ip)
            if alert.file_hash:
                intel["hash"] = lookup_hash(alert.file_hash)

            repeats = 0
            if alert.src_ip:
                since = datetime.now(timezone.utc) - timedelta(hours=24)
                repeats = len(session.exec(
                    select(Alert.id).where(Alert.src_ip == alert.src_ip,
                                           Alert.id != alert.id,
                                           Alert.created_at >= since)
                ).all())

            severity = getattr(alert.severity, "value", alert.severity)
            score, reasons = score_alert(severity, alert.description, intel, repeats)
            alert.intel = json.dumps(intel)
            alert.score_reasons = json.dumps(reasons)
            alert.risk_score = score
            alert.priority = priority_for(score)
            if alert.status == Status.new:
                alert.status = Status.triaged
            session.add(alert)
            session.commit()
            session.refresh(alert)

            auto_blocked = False
            if AUTO_BLOCK_SCORE and score >= AUTO_BLOCK_SCORE and alert.src_ip:
                try:
                    block_ip(session, alert.src_ip,
                             reason=f"auto: alert #{alert.id} {alert.rule_name} (score {score})",
                             alert_id=alert.id, created_by="auto")
                    alert.status = Status.blocked
                    session.add(alert)
                    session.commit()
                    session.refresh(alert)
                    auto_blocked = True
                    log.warning("AUTO-BLOCKED %s (alert #%s, score %s)", alert.src_ip, alert.id, score)
                except BlockRefused as exc:
                    log.warning("Auto-block skipped for %s: %s", alert.src_ip, exc)

            if score >= NOTIFY_MIN_SCORE or auto_blocked:
                notify(format_alert(alert, auto_blocked), key=f"{alert.src_ip}:{alert.rule_name}")
    except Exception:
        log.exception("Triage failed for alert %s", alert_id)


# ---------------------------------------------------------------- alerts
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/alerts", response_model=Alert, status_code=201,
          dependencies=[Depends(require_api_key)])
def create_alert(alert: AlertIn, background: BackgroundTasks,
                 session: Session = Depends(get_session)):
    db_alert = Alert.model_validate(alert)
    session.add(db_alert)
    session.commit()
    session.refresh(db_alert)
    background.add_task(triage, db_alert.id)
    return db_alert


@app.get("/alerts", response_model=list[Alert],
         dependencies=[Depends(require_api_key)])
def list_alerts(
    severity: Severity | None = None,
    status: Status | None = None,
    min_score: float | None = Query(None, ge=0, le=100),
    sort: Literal["newest", "risk"] = "newest",
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_session),
):
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if min_score is not None:
        query = query.where(Alert.risk_score >= min_score)
    if sort == "risk":
        query = query.order_by(Alert.risk_score.desc(), Alert.id.desc())
    else:
        query = query.order_by(Alert.id.desc())
    return session.exec(query.limit(limit)).all()


@app.get("/alerts/{alert_id}", response_model=Alert,
         dependencies=[Depends(require_api_key)])
def get_alert(alert_id: int, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/alerts/{alert_id}/retriage", response_model=Alert,
          dependencies=[Depends(require_api_key)])
def retriage(alert_id: int, session: Session = Depends(get_session)):
    if not session.get(Alert, alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    triage(alert_id)
    session.expire_all()
    return session.get(Alert, alert_id)


@app.patch("/alerts/{alert_id}/status", response_model=Alert,
           dependencies=[Depends(require_api_key)])
def update_status(alert_id: int, update: StatusUpdate,
                  session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = update.status
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


@app.post("/alerts/{alert_id}/block", response_model=Block,
          dependencies=[Depends(require_api_key)])
def block_alert_source(alert_id: int, background: BackgroundTasks,
                       hours: int = Query(BLOCK_HOURS, ge=1, le=24 * 30),
                       session: Session = Depends(get_session)):
    """Analyst approval: block the source IP of this alert."""
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert.src_ip:
        raise HTTPException(status_code=400, detail="Alert has no source IP")
    try:
        block = block_ip(session, alert.src_ip, hours=hours, alert_id=alert.id,
                         reason=f"analyst: alert #{alert.id} {alert.rule_name}")
    except BlockRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    alert.status = Status.blocked
    session.add(alert)
    session.commit()
    session.refresh(block)
    background.add_task(notify, f"🛑 AlertSense: {block.ip} blocked for {hours}h "
                                f"(alert #{alert.id} {alert.rule_name})")
    return block


# ---------------------------------------------------------------- blocklist
@app.get("/blocks", response_model=list[Block], dependencies=[Depends(require_api_key)])
def list_blocks(session: Session = Depends(get_session)):
    """Active, non-expired blocks. The enforcer polls this."""
    return active_blocks(session)


@app.post("/blocks", response_model=Block, status_code=201,
          dependencies=[Depends(require_api_key)])
def create_block(data: BlockIn, background: BackgroundTasks,
                 session: Session = Depends(get_session)):
    try:
        block = block_ip(session, data.ip, reason=data.reason or "manual", hours=data.hours)
    except BlockRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    background.add_task(notify, f"🛑 AlertSense: {block.ip} blocked manually for {data.hours}h")
    return block


@app.delete("/blocks/{ip}", dependencies=[Depends(require_api_key)])
def delete_block(ip: str, session: Session = Depends(get_session)):
    try:
        n = unblock_ip(session, ip)
    except BlockRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    if n == 0:
        raise HTTPException(status_code=404, detail="No active block for this IP")
    return {"unblocked": ip, "count": n}


# dashboard (D5)
from pathlib import Path  # noqa: E402

from fastapi.responses import FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from sqlalchemy import func  # noqa: E402

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

SECURITY_HEADERS = {
    # Only scripts/styles from this server may run: a stored-XSS payload cannot execute.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html", headers=SECURITY_HEADERS)


@app.get("/stats", dependencies=[Depends(require_api_key)])
def stats(session: Session = Depends(get_session)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    total = session.exec(select(func.count(Alert.id))).one()
    last_24h = session.exec(select(func.count(Alert.id)).where(Alert.created_at >= since)).one()
    open_count = session.exec(
        select(func.count(Alert.id)).where(Alert.status.in_([Status.new, Status.triaged]))
    ).one()
    by_priority = {
        str(p or "pending"): n
        for p, n in session.exec(select(Alert.priority, func.count(Alert.id)).group_by(Alert.priority)).all()
    }
    top_ips = [
        [ip, n]
        for ip, n in session.exec(
            select(Alert.src_ip, func.count(Alert.id))
            .where(Alert.src_ip.is_not(None), Alert.created_at >= since)
            .group_by(Alert.src_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(5)
        ).all()
    ]
    return {
        "total": total,
        "last_24h": last_24h,
        "open": open_count,
        "by_priority": by_priority,
        "active_blocks": len(active_blocks(session)),
        "top_ips": top_ips,
        "auto_block_score": AUTO_BLOCK_SCORE,
    }
