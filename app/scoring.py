"""Explainable risk score (0-100). Every point comes with a written reason.

Designed so an ML model can replace score_alert() later without changing the API.
"""
import re

SEVERITY_BASE = {"low": 10, "medium": 30, "high": 50, "critical": 70}
SERVER_ACCEPTED = re.compile(r"-> 2\d\d ")   # sensor writes e.g. "GET -> 200 (512 B)"


def score_alert(severity: str, description: str, intel: dict, repeat_count: int) -> tuple[int, list[str]]:
    base = SEVERITY_BASE.get(severity, 30)
    score, reasons = base, [f"+{base} base ({severity} severity)"]

    ip = intel.get("ip", {})
    abuse = ip.get("abuse_score") or 0
    if abuse:
        pts = round(abuse * 0.25)
        score += pts
        reasons.append(f"+{pts} source IP abuse confidence {abuse}% ({ip.get('reports', 0)} reports)")
    if ip.get("is_tor"):
        score += 5
        reasons.append("+5 source IP is a Tor exit node")

    malicious = intel.get("hash", {}).get("malicious") or 0
    if malicious:
        pts = min(malicious, 25)
        score += pts
        reasons.append(f"+{pts} file flagged by {malicious} antivirus engines")

    if repeat_count > 0:
        pts = min(repeat_count * 3, 15)
        score += pts
        reasons.append(f"+{pts} {repeat_count} earlier alert(s) from this IP in 24h")

    if SERVER_ACCEPTED.search(description or ""):
        score += 10
        reasons.append("+10 server answered 2xx: the attack may have succeeded")

    return max(0, min(score, 100)), reasons


def priority_for(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
