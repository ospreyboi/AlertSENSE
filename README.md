# AlertSense

Open-source AI-powered alert triage and response for SOC teams and small organisations.

## Status
🚧 In development — Phase 1: Core API

## Features
- [x] Alert intake API with validation (FastAPI + Pydantic)
- [x] Persistent storage (SQLite) + API-key authentication
- [ ] Web log sensor (SQLi, XSS, path traversal, brute force, scanners)
- [ ] IOC enrichment (AbuseIPDB, VirusTotal)
- [ ] ML triage risk score
- [ ] Response: IP blocking (approval / auto), notifications
- [ ] LLM summaries + MITRE ATT&CK mapping
- [ ] Dashboard + Docker deploy

## Run (GitHub Codespaces)
1. Code → Codespaces → Create codespace
2. `cp .env.example .env` and set `ALERTSENSE_API_KEY`
3. `uvicorn app.main:app --reload`
4. Open port 8000 → `/docs`
