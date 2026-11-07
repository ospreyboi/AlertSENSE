"""Containment: manage the IP blocklist with safety checks."""
import ipaddress
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from app.config import ALLOWLIST, BLOCK_HOURS
from app.models import Block


class BlockRefused(ValueError):
    """Raised when an IP must not be blocked (invalid or allowlisted)."""


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise BlockRefused(f"not a valid IP address: {ip!r}") from None


def block_ip(session: Session, ip: str, reason: str = "", hours: int = BLOCK_HOURS,
             alert_id: int | None = None, created_by: str = "analyst") -> Block:
    ip = normalize_ip(ip)
    if ip in ALLOWLIST:
        raise BlockRefused(f"{ip} is on the allowlist and can never be blocked")
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=hours)
    block = session.exec(
        select(Block).where(Block.ip == ip, Block.active.is_(True), Block.expires_at > now)
    ).first()
    if block:                                  # already blocked: extend instead of duplicating
        block.expires_at = expires
        block.reason = reason or block.reason
    else:
        block = Block(ip=ip, reason=reason, alert_id=alert_id,
                      created_by=created_by, expires_at=expires)
    session.add(block)
    session.commit()
    session.refresh(block)
    return block


def unblock_ip(session: Session, ip: str) -> int:
    ip = normalize_ip(ip)
    blocks = session.exec(select(Block).where(Block.ip == ip, Block.active.is_(True))).all()
    for b in blocks:
        b.active = False
        session.add(b)
    session.commit()
    return len(blocks)


def active_blocks(session: Session) -> list[Block]:
    now = datetime.now(timezone.utc)
    return list(session.exec(
        select(Block).where(Block.active.is_(True), Block.expires_at > now)
        .order_by(Block.created_at.desc())
    ).all())
