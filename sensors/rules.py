"""Detection rules for web access logs.

1. Signatures: a single request is enough (SQLi, XSS, traversal, command injection ...).
2. Rates:      many requests from one IP in a short window (brute force, directory scanning).
"""
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

from sensors.log_parser import LogEntry


@dataclass(frozen=True)
class Signature:
    name: str
    severity: str
    mitre: str
    field: str  # "path" or "ua"
    pattern: re.Pattern


@dataclass
class Detection:
    rule_name: str
    severity: str
    mitre: str
    evidence: str


SIGNATURES = [
    Signature("SQL injection attempt", "high", "T1190", "path", re.compile(
        r"union\s+(all\s+)?select|'\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+|\bor\s+1\s*=\s*1"
        r"|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema"
        r"|'\s*(--|#)|;\s*(drop|delete|insert|update)\s")),
    Signature("Cross-site scripting attempt", "medium", "T1189", "path", re.compile(
        r"<\s*script|javascript\s*:|on(error|load|mouseover|focus)\s*=|<\s*(img|svg|iframe)\b"
        r"|alert\s*\(|document\.(cookie|location)")),
    Signature("Path traversal / file inclusion attempt", "high", "T1083", "path", re.compile(
        r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|\b(php|file|data|expect)://|\x00|c:\\windows")),
    Signature("Command injection attempt", "critical", "T1059", "path", re.compile(
        r"(;|\|\|?|&&|`|\$\()\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|ping|nslookup)\b")),
    Signature("Known attack tool detected", "medium", "T1595", "ua", re.compile(
        r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|\bdirb\b|wpscan|nuclei|hydra|zgrab"
        r"|acunetix|nessus|openvas|wfuzz|ffuf")),
    Signature("Sensitive file probe", "medium", "T1595.003", "path", re.compile(
        r"/\.env\b|/\.git/|wp-config\.php|/phpmyadmin|/server-status|/\.aws/|/id_rsa"
        r"|\.(bak|old|sql|swp)(\?|$)")),
]

LOGIN_PATH = re.compile(r"login|signin|/auth|/brute/|wp-login")


def normalize(text: str) -> str:
    """URL-decode repeatedly (attackers double-encode to dodge filters), then lowercase."""
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


class Detector:
    def __init__(self, window_s: int = 60, brute_threshold: int = 10,
                 notfound_threshold: int = 20, cooldown_s: int = 60):
        self.window = timedelta(seconds=window_s)
        self.cooldown = timedelta(seconds=cooldown_s)
        self.brute_threshold = brute_threshold
        self.notfound_threshold = notfound_threshold
        self._hits: dict[tuple, deque] = defaultdict(deque)   # (kind, ip) -> timestamps
        self._last_alert: dict[tuple, datetime] = {}           # (rule, ip) -> last alert time

    def _count(self, key: tuple, now: datetime) -> int:
        """Sliding window: add this hit, drop hits older than the window, return the count."""
        q = self._hits[key]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q)

    def _cooled_down(self, rule: str, ip: str, now: datetime) -> bool:
        """True if we have not alerted on this rule+IP recently (and records this alert)."""
        last = self._last_alert.get((rule, ip))
        if last and now - last < self.cooldown:
            return False
        self._last_alert[(rule, ip)] = now
        return True

    def check(self, e: LogEntry) -> list[Detection]:
        found: list[Detection] = []
        fields = {"path": normalize(e.path), "ua": e.user_agent.lower()}

        for sig in SIGNATURES:
            m = sig.pattern.search(fields[sig.field])
            if m and self._cooled_down(sig.name, e.ip, e.time):
                found.append(Detection(sig.name, sig.severity, sig.mitre,
                                       f"matched '{m.group(0)[:80]}'"))

        if LOGIN_PATH.search(fields["path"]):
            n = self._count(("login", e.ip), e.time)
            if n >= self.brute_threshold and self._cooled_down("brute", e.ip, e.time):
                found.append(Detection("Brute-force login attempt", "high", "T1110",
                                       f"{n} login requests in {self.window.seconds}s"))

        if e.status == 404:
            n = self._count(("404", e.ip), e.time)
            if n >= self.notfound_threshold and self._cooled_down("scan", e.ip, e.time):
                found.append(Detection("Directory scanning", "medium", "T1595.003",
                                       f"{n} not-found responses in {self.window.seconds}s"))
        return found
