# AlertSense

Open-source AI-powered alert triage and response for SOC teams and small organisations.

## Status
🚧 In development — Phase 1: Core API

## Features
- [x] Alert intake API with validation (FastAPI + Pydantic)
- [x] Persistent storage (SQLite) + API-key authentication
- [x] Web log sensor (SQLi, XSS, path traversal, brute force, scanners)
- [x] IOC enrichment (AbuseIPDB, VirusTotal)
- [x] Explainable risk score + priority (ML model planned for v2)
- [x] Response: IP blocking (approval / auto), Nginx enforcer, Telegram/Slack notifications
- [ ] LLM summaries + MITRE ATT&CK mapping
- [x] Web dashboard + Docker deploy

## Run (GitHub Codespaces)
1. Code → Codespaces → Create codespace
2. `cp .env.example .env` and set `ALERTSENSE_API_KEY`
3. `uvicorn app.main:app --reload`
4. Open port 8000 → `/docs`

## Web sensor
Watches any Nginx/Apache access log (combined format) and reports attacks to AlertSense.

    python -m sensors.web_sensor --log /var/log/nginx/access.log --site my-website

Detects: SQL injection, XSS, path traversal / LFI, command injection, attack tools
(sqlmap, nikto ...), sensitive file probes, brute-force logins, directory scanning.

## Practice lab (DVWA)
    docker compose -f lab/docker-compose.yml up -d
    python -m sensors.web_sensor          # terminal 2
    ./lab/attack_demo.sh                  # terminal 3

## Response (blocking)
AlertSense keeps a blocklist; the **enforcer** runs on the web server, pulls it every 5s and
applies it to Nginx (`deny <ip>;`). The API never needs shell access to your servers.

    python -m sensors.enforcer --file /etc/nginx/alertsense/blocklist.conf --reload-cmd "nginx -s reload"

| Setting (.env) | Default | Meaning |
|---|---|---|
| `ALERTSENSE_AUTO_BLOCK_SCORE` | `0` | 0 = approval mode; e.g. 80 = auto-block alerts scoring ≥ 80 |
| `ALERTSENSE_BLOCK_HOURS` | `24` | Blocks expire automatically |
| `ALERTSENSE_ALLOWLIST` | `127.0.0.1,::1` | IPs that can never be blocked |
| `ALERTSENSE_NOTIFY_MIN_SCORE` | `60` | Minimum score for a notification |

## Dashboard
Open `http://<server>:8000/` and enter the API key. Live alert queue (highest risk first),
score explanations, threat intel, and one-click Block / Resolve / False-positive.
All attacker-controlled data is rendered as text only, plus a strict Content-Security-Policy.

## Quick start (demo)
    ./scripts/run_all.sh      # lab + API + sensor + enforcer in the background
    ./lab/attack_demo.sh      # simulated attacks
    ./scripts/stop_all.sh

## Deploy with Docker
    cp .env.example .env      # set ALERTSENSE_API_KEY and optional intel/notification keys
    ACCESS_LOG_DIR=/var/log/nginx SITE_NAME=my-site docker compose -f deploy/docker-compose.yml up -d --build
    # on the web server:
    python -m sensors.enforcer --file /etc/nginx/alertsense/blocklist.conf --reload-cmd "nginx -s reload"
