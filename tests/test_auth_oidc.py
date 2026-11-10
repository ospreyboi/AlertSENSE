"""Tests for OAuth2 / OIDC sign-in, bearer tokens, roles and CSRF (app/auth_oidc.py)."""
import base64
import json
import secrets
import time

import pytest
from authlib.jose import JsonWebKey, JsonWebToken
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from app import auth_oidc
from app.auth_oidc import Settings, domain_allowed, install_auth, role_for

API_KEY = "test-api-key-" + "x" * 20
SECRET = "s" * 40
ISSUER = "https://idp.example.edu"
AUDIENCE = "api://alertsense"


# --------------------------------------------------------------------------- a stand-in AlertSense API
def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(401, "Invalid or missing API key")


def make_app(**overrides) -> tuple[FastAPI, Settings]:
    app = FastAPI()

    @app.get("/stats")
    def stats(_=Depends(require_api_key)):
        return {"ok": True}

    @app.patch("/alerts/{alert_id}/status")
    def set_status(alert_id: int, _=Depends(require_api_key)):
        return {"id": alert_id}

    base = dict(enabled=True, issuer=ISSUER, client_id="cid", client_secret="csecret",
                redirect_uri="https://alertsense.example.edu/auth/callback", session_secret=SECRET,
                api_audience=AUDIENCE, api_issuer=ISSUER, cookie_secure=False)
    base.update(overrides)
    s = Settings(**base)
    install_auth(app, s, guard_modules=(__name__,))
    return app, s


def session_cookie(data: dict) -> str:
    """Build a cookie exactly as Starlette's SessionMiddleware would."""
    payload = base64.b64encode(json.dumps(data).encode())
    return TimestampSigner(SECRET).sign(payload).decode()


def login_as(client: TestClient, role: str, csrf: str = "csrf-token-123", **extra):
    user = {"sub": "u1", "email": "analyst@example.edu", "name": "Analyst", "role": role, "iat": int(time.time())}
    user.update(extra)
    client.cookies.set("alertsense_session", session_cookie({"user": user, "csrf": csrf}))


# --------------------------------------------------------------------------- API key path is unchanged
def test_no_credentials_is_rejected():
    app, _ = make_app()
    assert TestClient(app).get("/stats").status_code == 401


def test_api_key_still_works_for_sensors():
    app, _ = make_app()
    c = TestClient(app)
    assert c.get("/stats", headers={"X-API-Key": API_KEY}).status_code == 200
    assert c.patch("/alerts/1/status", headers={"X-API-Key": API_KEY}).status_code == 200
    assert c.get("/stats", headers={"X-API-Key": "wrong"}).status_code == 401


def test_works_with_sso_disabled():
    app, _ = make_app(enabled=False)
    c = TestClient(app)
    assert c.get("/auth/config").json() == {"oidc": False, "provider": None, "api_key_login": True}
    assert c.get("/stats").status_code == 401
    assert c.get("/stats", headers={"X-API-Key": API_KEY}).status_code == 200


# --------------------------------------------------------------------------- session (browser) path
def test_viewer_session_can_read_but_not_change():
    app, _ = make_app()
    c = TestClient(app)
    login_as(c, "viewer")
    assert c.get("/stats").status_code == 200
    r = c.patch("/alerts/1/status", headers={"X-CSRF-Token": "csrf-token-123"})
    assert r.status_code == 403 and "read-only" in r.json()["detail"]


def test_responder_needs_csrf_token():
    app, _ = make_app()
    c = TestClient(app)
    login_as(c, "responder")
    assert c.patch("/alerts/1/status").status_code == 403
    assert c.patch("/alerts/1/status", headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert c.patch("/alerts/1/status", headers={"X-CSRF-Token": "csrf-token-123"}).status_code == 200


def test_tampered_or_expired_session_is_rejected():
    app, s = make_app()
    c = TestClient(app)
    c.cookies.set("alertsense_session", session_cookie({"user": {"sub": "u", "role": "responder", "iat": int(time.time())}})[:-4] + "AAAA")
    assert c.get("/stats").status_code == 401
    login_as(c, "responder", iat=int(time.time()) - s.session_hours * 3600 - 10)
    assert c.get("/stats").status_code == 401


def test_me_returns_identity_and_csrf():
    app, _ = make_app()
    c = TestClient(app)
    assert c.get("/auth/me").status_code == 401
    login_as(c, "viewer")
    me = c.get("/auth/me").json()
    assert me["role"] == "viewer" and me["csrf"] == "csrf-token-123" and me["email"] == "analyst@example.edu"


def test_login_redirects_to_provider_with_pkce(monkeypatch):
    app, _ = make_app()
    meta = {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks"}

    async def fake_load(self):
        self.server_metadata = meta
        return meta
    from authlib.integrations.starlette_client.apps import StarletteOAuth2App
    monkeypatch.setattr(StarletteOAuth2App, "load_server_metadata", fake_load)
    r = TestClient(app).get("/auth/login", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(f"{ISSUER}/authorize?")
    for part in ("response_type=code", "code_challenge=", "code_challenge_method=S256", "state=", "nonce=", "scope=openid"):
        assert part in loc


# --------------------------------------------------------------------------- bearer (service) path
@pytest.fixture
def signing_key():
    return JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})


def make_token(key, **claims):
    now = int(time.time())
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "svc-sensor", "iat": now, "exp": now + 600, "roles": ["alertsense.responder"]}
    body.update(claims)
    return JsonWebToken(["RS256"]).encode({"alg": "RS256", "kid": "k1"}, body, key).decode()


def with_jwks(monkeypatch, key):
    jwks = {"keys": [key.as_dict(is_private=False)]}

    async def fake_jwks(self, force=False):
        return jwks
    monkeypatch.setattr(auth_oidc._Provider, "jwks", fake_jwks)


def test_valid_bearer_token_is_accepted(monkeypatch, signing_key):
    with_jwks(monkeypatch, signing_key)
    app, _ = make_app()
    c = TestClient(app)
    tok = make_token(signing_key)
    assert c.get("/stats", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert c.patch("/alerts/1/status", headers={"Authorization": f"Bearer {tok}"}).status_code == 200  # no CSRF for bearer


@pytest.mark.parametrize("claims", [
    {"aud": "api://someone-else"},
    {"iss": "https://evil.example.com"},
    {"exp": int(time.time()) - 3600},
])
def test_bad_bearer_tokens_are_rejected(monkeypatch, signing_key, claims):
    with_jwks(monkeypatch, signing_key)
    app, _ = make_app()
    r = TestClient(app).get("/stats", headers={"Authorization": f"Bearer {make_token(signing_key, **claims)}"})
    assert r.status_code == 401


def test_bearer_signed_by_unknown_key_is_rejected(monkeypatch, signing_key):
    with_jwks(monkeypatch, signing_key)
    other = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "k1"})
    app, _ = make_app()
    r = TestClient(app).get("/stats", headers={"Authorization": f"Bearer {make_token(other)}"})
    assert r.status_code == 401


def test_unsigned_alg_none_token_is_rejected(monkeypatch, signing_key):
    with_jwks(monkeypatch, signing_key)
    app, _ = make_app()
    head = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps({"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": 9999999999,
                                                "roles": ["alertsense.responder"]}).encode()).rstrip(b"=").decode()
    r = TestClient(app).get("/stats", headers={"Authorization": f"Bearer {head}.{body}."})
    assert r.status_code == 401


def test_viewer_bearer_cannot_change_state(monkeypatch, signing_key):
    with_jwks(monkeypatch, signing_key)
    app, _ = make_app()
    tok = make_token(signing_key, roles=["alertsense.viewer"])
    c = TestClient(app)
    assert c.get("/stats", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert c.patch("/alerts/1/status", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


# --------------------------------------------------------------------------- identity rules
def test_role_mapping():
    s = Settings(responder_emails=["lead@thapar.edu"], role_claim="realm_access.roles")
    assert role_for({"realm_access": {"roles": ["alertsense.responder"]}}, s) == "responder"
    assert role_for({"realm_access": {"roles": ["alertsense.viewer"]}}, s) == "viewer"
    assert role_for({"email": "LEAD@thapar.edu"}, s) == "responder"
    assert role_for({"email": "student@thapar.edu"}, s) is None
    assert role_for({"email": "student@thapar.edu"}, Settings(default_role="viewer")) == "viewer"


def test_domain_restriction():
    s = Settings(allowed_domains=["thapar.edu"])
    assert domain_allowed({"email": "a@thapar.edu", "email_verified": True}, s)
    assert not domain_allowed({"email": "a@gmail.com", "email_verified": True}, s)
    assert not domain_allowed({"email": "a@thapar.edu", "email_verified": False}, s)
    assert domain_allowed({"email": "a@x.com", "hd": "thapar.edu"}, s)
    assert domain_allowed({"email": "anyone@anywhere.com"}, Settings())


def test_settings_validation():
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        Settings(enabled=True, issuer=ISSUER, client_id="a", client_secret="b", redirect_uri="https://x/cb", session_secret="short").validate()
    with pytest.raises(RuntimeError, match="https"):
        Settings(enabled=True, issuer="http://idp.example.com", client_id="a", client_secret="b", redirect_uri="https://x/cb", session_secret=SECRET).validate()
    with pytest.raises(RuntimeError, match="OIDC_CLIENT_ID"):
        Settings(enabled=True, issuer=ISSUER, client_secret="b", redirect_uri="https://x/cb", session_secret=SECRET).validate()


# --------------------------------------------------------------------------- the real AlertSense app
def test_real_app_is_wired():
    from app.main import app
    c = TestClient(app)
    assert c.get("/auth/config").status_code == 200
    assert c.get("/stats").status_code == 401
    assert any(getattr(f, "__name__", "").startswith("oidc_or_") for f in app.dependency_overrides.values())
