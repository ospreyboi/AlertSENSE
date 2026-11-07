import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from sqlmodel import Session, select

from app.db import engine, get_session, init_db
from app.enrich import lookup_hash, lookup_ip
from app.models import Alert, AlertIn, Severity, Status, StatusUpdate
from app.scoring import priority_for, score_alert
from app.security import require_api_key

log = logging.getLogger("alertsense")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AlertSense", version="0.3.0", lifespan=lifespan)


def triage(alert_id: int) -> None:
    """Enrich + score one alert. Runs in the background after the API has replied."""
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
    except Exception:
        log.exception("Triage failed for alert %s", alert_id)


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
