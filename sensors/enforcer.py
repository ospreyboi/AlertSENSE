"""AlertSense enforcer: pulls the active blocklist from the API and applies it to Nginx.

Runs ON the web server. The AlertSense API never needs shell access to your servers.

Usage (lab):
    python -m sensors.enforcer
Usage (real server):
    python -m sensors.enforcer --file /etc/nginx/alertsense/blocklist.conf --reload-cmd "nginx -s reload"
"""
import argparse
import ipaddress
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

log = logging.getLogger("enforcer")
HEADER = "# Managed by AlertSense enforcer - do not edit by hand\n"


def render_nginx(ips: list[str]) -> str:
    """Turn IPs into nginx 'deny' lines. Anything that is not a real IP is dropped."""
    lines = []
    for raw in sorted(set(ips)):
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            log.warning("Ignoring invalid IP from API: %r", raw)
            continue
        lines.append(f"deny {ip};\n")
    return HEADER + "".join(lines)


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)          # rename is atomic: nginx never reads a half-written file


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description="AlertSense Nginx enforcer")
    p.add_argument("--api", default=os.getenv("ALERTSENSE_API_URL", "http://127.0.0.1:8000"))
    p.add_argument("--file", default="lab/blocklist/blocklist.conf")
    p.add_argument("--reload-cmd",
                   default="docker compose -f lab/docker-compose.yml exec -T proxy nginx -s reload")
    p.add_argument("--interval", type=int, default=5, help="seconds between checks")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    key = os.getenv("ALERTSENSE_API_KEY")
    if not key:
        sys.exit("ALERTSENSE_API_KEY is not set (check .env)")

    path = Path(args.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    client = httpx.Client(base_url=args.api, headers={"X-API-Key": key}, timeout=5)
    applied: str | None = None
    log.info("Enforcing blocklist from %s into %s every %ss", args.api, path, args.interval)

    try:
        while True:
            try:
                r = client.get("/blocks")
                r.raise_for_status()
                ips = [b["ip"] for b in r.json()]
                desired = render_nginx(ips)
                if desired != applied:
                    write_atomic(path, desired)
                    res = subprocess.run(args.reload_cmd, shell=True, capture_output=True,
                                         text=True, timeout=20)
                    if res.returncode == 0:
                        applied = desired
                        log.warning("APPLIED blocklist: %d IP(s) blocked %s", len(ips), ips[:5])
                    else:
                        log.error("Nginx reload failed (will retry): %s", res.stderr.strip()[:300])
            except httpx.HTTPError as exc:
                # fail safe: keep the last applied blocklist if AlertSense is unreachable
                log.warning("API unreachable (%s), keeping current blocklist", type(exc).__name__)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Enforcer stopped")


if __name__ == "__main__":
    main()
