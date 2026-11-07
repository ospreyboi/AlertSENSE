from datetime import datetime, timezone
from enum import Enum

from pydantic import field_validator
from sqlmodel import Field, SQLModel


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Status(str, Enum):
    new = "new"
    triaged = "triaged"
    blocked = "blocked"
    resolved = "resolved"
    false_positive = "false_positive"


class AlertBase(SQLModel):
    source: str = Field(schema_extra={"examples": ["wazuh"]})
    rule_name: str = Field(schema_extra={"examples": ["SQL injection attempt"]})
    severity: Severity
    src_ip: str | None = None
    dest_ip: str | None = None
    url: str | None = None
    file_hash: str | None = None
    description: str = ""
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def normalize_to_utc(cls, v: datetime) -> datetime:
        """Store every timestamp in UTC so events from different systems line up."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class AlertIn(AlertBase):
    """What a sensor/SIEM sends to AlertSense."""


class Alert(AlertBase, table=True):
    """What AlertSense stores (adds id, status, triage results)."""
    id: int | None = Field(default=None, primary_key=True)
    status: Status = Status.new
    risk_score: float | None = None
    priority: str | None = None
    intel: str | None = None           # JSON text: enrichment results
    score_reasons: str | None = None   # JSON text: why the score is what it is
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StatusUpdate(SQLModel):
    status: Status
