"""AlertSense web sensor: watches an Apache/Nginx access log and reports attacks.

Usage:
    python -m sensors.web_sensor --log lab/logs/access.log
"""
import argparse
import logging
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

from sensors.log_parser import LogEntry, parse_line
from sensors.rules import Detection, Detector

log = logging.getLogger("web_sensor")


def follow(path: Path, from_start: bool = False):
    """Yield new lines as they are written to a log file (like `tail -F`)."""
    while not path.exists():
        log.info("Waiting for %s to appear...", path)
        time.sleep(2)
    f = path.open("r", errors="replace")
    if not from_start:
        f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    buffer = ""
    while True:
        chunk = f.readline()
        if chunk:
            buffer += chunk
            if buffer.endswith("\n"):
                yield buffer
                buffer = ""
            continue
        time.sleep(0.5)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != inode or st.st_size < f.tell():  # log rotated or truncated
            log.info("Log rotated, reopening %s", path)
            f.close()
            f = path.open("r", errors="replace")
            inode = os.fstat(f.fileno()).st_ino


class AlertSender:
    def __init__(self, api_url: str, api_key: str, site: str):
        self.client = httpx.Client(base_url=api_url, headers={"X-API-Key": api_key}, timeout=5)
        self.site = site

    def send(self, entry: LogEntry, det: Detection) -> None:
        payload = {
            "source": "web_sensor",
            "rule_name": det.rule_name,
            "severity": det.severity,
            "src_ip": entry.ip,
            "url": entry.path[:2000],
            "description": (f"[{self.site}] {det.mitre} | {entry.method} -> {entry.status} "
                            f"({entry.size} B) | {det.evidence} | UA: {entry.user_agent[:150]}"),
            "timestamp": entry.time.isoformat(),
        }
        for attempt in range(3):
            try:
                r = self.client.post("/alerts", json=payload)
            except httpx.HTTPError as exc:
                log.warning("API unreachable (%s), retry %d/3", exc, attempt + 1)
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 201:
                log.warning("ALERT #%s  %s  from %s", r.json()["id"], det.rule_name, entry.ip)
            else:
                log.error("API rejected alert: %s %s", r.status_code, r.text[:200])
            return
        log.error("Dropped alert after 3 attempts: %s", det.rule_name)


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description="AlertSense web log sensor")
    p.add_argument("--log", default="lab/logs/access.log", help="access log to watch")
    p.add_argument("--api", default=os.getenv("ALERTSENSE_API_URL", "http://127.0.0.1:8000"))
    p.add_argument("--site", default="dvwa-lab", help="name of the website being protected")
    p.add_argument("--from-start", action="store_true", help="also scan lines already in the log")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    key = os.getenv("ALERTSENSE_API_KEY")
    if not key:
        sys.exit("ALERTSENSE_API_KEY is not set (check .env)")

    detector = Detector()
    sender = AlertSender(args.api, key, args.site)
    log.info("Watching %s -> %s", args.log, args.api)
    try:
        for line in follow(Path(args.log), args.from_start):
            entry = parse_line(line)
            if entry is None:
                continue
            for det in detector.check(entry):
                sender.send(entry, det)
    except KeyboardInterrupt:
        log.info("Sensor stopped")


if __name__ == "__main__":
    main()
