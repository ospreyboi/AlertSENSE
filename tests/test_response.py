from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.models import Block
from app.response import BlockRefused, active_blocks, block_ip, unblock_ip
from sensors.enforcer import render_nginx


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def test_block_and_list(session):
    block_ip(session, "203.0.113.9", reason="test")
    assert [b.ip for b in active_blocks(session)] == ["203.0.113.9"]


def test_blocking_twice_extends_instead_of_duplicating(session):
    block_ip(session, "203.0.113.9")
    block_ip(session, "203.0.113.9")
    assert len(active_blocks(session)) == 1


def test_unblock(session):
    block_ip(session, "203.0.113.9")
    assert unblock_ip(session, "203.0.113.9") == 1
    assert active_blocks(session) == []


def test_allowlisted_ip_is_refused(session):
    with pytest.raises(BlockRefused):
        block_ip(session, "127.0.0.1")


def test_config_injection_is_refused(session):
    with pytest.raises(BlockRefused):
        block_ip(session, "1.2.3.4; allow all")


def test_expired_block_is_not_active(session):
    block_ip(session, "203.0.113.10", hours=1)
    b = session.exec(select(Block)).first()
    b.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    session.add(b)
    session.commit()
    assert active_blocks(session) == []


def test_enforcer_drops_invalid_ips():
    out = render_nginx(["203.0.113.9", "1.1.1.1; allow all", "198.51.100.7"])
    assert "deny 203.0.113.9;" in out and "deny 198.51.100.7;" in out
    assert "allow" not in out
