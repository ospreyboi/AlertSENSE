from app.enrich import lookup_hash, lookup_ip
from app.scoring import priority_for, score_alert


def test_base_score_only():
    score, reasons = score_alert("medium", "", {}, 0)
    assert score == 30 and len(reasons) == 1


def test_abusive_ip_raises_score():
    score, _ = score_alert("high", "", {"ip": {"abuse_score": 100, "reports": 500}}, 0)
    assert score == 75


def test_successful_attack_bonus():
    score, reasons = score_alert("high", "[lab] T1190 | GET -> 200 (512 B)", {}, 0)
    assert score == 60 and any("succeeded" in r for r in reasons)


def test_repeat_offender_capped():
    score, _ = score_alert("low", "", {}, 100)
    assert score == 25          # 10 base + max 15


def test_score_is_clamped_to_100():
    intel = {"ip": {"abuse_score": 100, "is_tor": True}, "hash": {"malicious": 60}}
    score, _ = score_alert("critical", "GET -> 200 (1 B)", intel, 10)
    assert score == 100


def test_priority_labels():
    assert [priority_for(s) for s in (90, 65, 40, 10)] == ["critical", "high", "medium", "low"]


def test_private_ip_is_not_looked_up():
    assert "skipped" in lookup_ip("172.18.0.1")


def test_invalid_hash_never_reaches_the_network():
    assert "skipped" in lookup_hash("../../etc/passwd")
