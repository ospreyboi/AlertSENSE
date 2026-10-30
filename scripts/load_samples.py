import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv()
API = "http://127.0.0.1:8000"
HEADERS = {"X-API-Key": os.getenv("ALERTSENSE_API_KEY", "")}

alerts = json.loads(Path("samples/alerts.json").read_text())
for a in alerts:
    r = httpx.post(f"{API}/alerts", json=a, headers=HEADERS)
    if r.status_code == 201:
        print(r.status_code, "created id", r.json()["id"])
    else:
        print(r.status_code, r.text[:300])
        sys.exit(1)
