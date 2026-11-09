from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_is_served_with_csp():
    r = client.get("/")
    assert r.status_code == 200 and "AlertSense" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]


def test_dashboard_never_renders_api_data_as_html():
    # Alerts contain attacker payloads (e.g. <script>); they must only ever be shown as text.
    js = Path("app/static/dashboard.js").read_text()
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js


def test_stats_requires_api_key():
    assert client.get("/stats").status_code == 401
