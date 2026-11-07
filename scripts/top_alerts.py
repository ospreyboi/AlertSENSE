"""Print the highest-risk alerts with the reasons for each score."""
import json
import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv()
limit = int(sys.argv[1]) if len(sys.argv) > 1 else 10
r = httpx.get("http://127.0.0.1:8000/alerts",
              params={"sort": "risk", "limit": limit},
              headers={"X-API-Key": os.getenv("ALERTSENSE_API_KEY", "")}, timeout=5)
if r.status_code != 200:
    sys.exit(f"API error {r.status_code}: {r.text[:200]}")
for a in r.json():
    print(f"#{a['id']:<4} score={a.get('risk_score')!s:<5} {a.get('priority') or '-':<9} {a['rule_name']}  ({a.get('src_ip')})")
    for reason in json.loads(a.get("score_reasons") or "[]"):
        print(f"        {reason}")
