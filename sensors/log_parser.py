"""Parse Apache/Nginx 'combined' access-log lines into structured entries.

Example line:
1.2.3.4 - - [31/Oct/2026:09:00:00 +0000] "GET /path?x=1 HTTP/1.1" 200 512 "referer" "user-agent"
"""
import re
from dataclasses import dataclass
from datetime import datetime

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


@dataclass
class LogEntry:
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str


def parse_line(line: str) -> LogEntry | None:
    """Return a LogEntry, or None if the line is not a valid combined-format line."""
    m = COMBINED.match(line.strip())
    if not m:
        return None
    parts = m["request"].split()
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    try:
        time = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return LogEntry(
        ip=m["ip"],
        time=time,
        method=method,
        path=path,
        status=int(m["status"]),
        size=0 if m["size"] == "-" else int(m["size"]),
        referer=m["referer"] or "",
        user_agent=m["ua"] or "",
    )
