from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlmodel import Session, select

from app.db import get_session, init_db
from app.models import Alert, AlertIn, Severity, Status, StatusUpdate
from app.security import require_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AlertSense", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/alerts", response_model=Alert, status_code=201,
          dependencies=[Depends(require_api_key)])
def create_alert(alert: AlertIn, session: Session = Depends(get_session)):
    db_alert = Alert.model_validate(alert)
    session.add(db_alert)
    session.commit()
    session.refresh(db_alert)
    return db_alert


@app.get("/alerts", response_model=list[Alert],
         dependencies=[Depends(require_api_key)])
def list_alerts(
    severity: Severity | None = None,
    status: Status | None = None,
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_session),
):
    query = select(Alert).order_by(Alert.id.desc())
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    return session.exec(query.limit(limit)).all()


@app.get("/alerts/{alert_id}", response_model=Alert,
         dependencies=[Depends(require_api_key)])
def get_alert(alert_id: int, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


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
