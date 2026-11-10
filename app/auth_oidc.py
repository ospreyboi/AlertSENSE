"""OAuth 2.0 / OpenID Connect single sign-on for AlertSense.

Adds three ways to authenticate, alongside the existing X-API-Key check:

* Analysts   - Authorization Code flow with PKCE against the organisation's identity
               provider (Microsoft Entra ID, Google Workspace, Okta, Keycloak, ...).
               The result is a signed, HttpOnly session cookie.
* Services   - OAuth 2.0 bearer access tokens (client-credentials flow), validated
               locally against the provider's JWKS.  Optional: set OIDC_API_AUDIENCE.
* Sensors    - the existing X-API-Key header, still validated by app/security.py.

Roles: "responder" may change state (block, resolve, ...); "viewer" is read-only.
Cookie sessions must send X-CSRF-Token on every state-changing request.

Wiring (one line at the end of app/main.py):
    from app.auth_oidc import install_auth; install_auth(app)
"""
from __future__ import annotations

import inspect
import json
import logging
import os
import secrets
import time
import typing
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

import warnings

import httpx
from authlib.integrations.starlette_client import OAuth

with warnings.catch_warnings():
    warnings.simplefilter("ignore")                     # authlib.jose deprecation notice (stable until authlib 2.0)
    from authlib.jose import JsonWebKey, JsonWebToken
    from authlib.jose.errors import JoseError
from fastapi import APIRouter, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.security.api_key import APIKeyHeader
from starlette.middleware.sessions import SessionMiddleware

log = logging.getLogger("alertsense.auth")
audit = logging.getLogger("alertsense.audit")

ROLES = ("viewer", "responder")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
JWT_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"]  # never "none" / HS*


# ----------------------------------------------------------------------------- settings
def _load_dotenv(path: Path = Path(".env")) -> None:
    """Read KEY=VALUE lines from .env without overriding real environment variables."""
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        os.environ.setdefault(key, val)


def _csv(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None or v == "" else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    enabled: bool = False
    provider_name: str = "your organisation"
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    scopes: str = "openid email profile"
    allowed_domains: list[str] = field(default_factory=list)
    role_claim: str = "roles"
    responder_values: list[str] = field(default_factory=lambda: ["alertsense.responder"])
    viewer_values: list[str] = field(default_factory=lambda: ["alertsense.viewer"])
    responder_emails: list[str] = field(default_factory=list)
    viewer_emails: list[str] = field(default_factory=list)
    default_role: str = "none"
    api_audience: str = ""
    api_issuer: str = ""
    session_secret: str = ""
    session_hours: int = 8
    cookie_secure: bool = True
    api_key_login: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv()
        issuer = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
        return cls(
            enabled=_bool("OIDC_ENABLED", False),
            provider_name=os.environ.get("OIDC_PROVIDER_NAME", "your organisation").strip() or "your organisation",
            issuer=issuer,
            client_id=os.environ.get("OIDC_CLIENT_ID", "").strip(),
            client_secret=os.environ.get("OIDC_CLIENT_SECRET", "").strip(),
            redirect_uri=os.environ.get("OIDC_REDIRECT_URI", "").strip(),
            scopes=os.environ.get("OIDC_SCOPES", "openid email profile").strip(),
            allowed_domains=[d.lower().lstrip("@") for d in _csv("OIDC_ALLOWED_DOMAINS")],
            role_claim=os.environ.get("OIDC_ROLE_CLAIM", "roles").strip(),
            responder_values=_csv("OIDC_RESPONDER_VALUES", "alertsense.responder"),
            viewer_values=_csv("OIDC_VIEWER_VALUES", "alertsense.viewer"),
            responder_emails=[e.lower() for e in _csv("OIDC_RESPONDER_EMAILS")],
            viewer_emails=[e.lower() for e in _csv("OIDC_VIEWER_EMAILS")],
            default_role=os.environ.get("OIDC_DEFAULT_ROLE", "none").strip().lower(),
            api_audience=os.environ.get("OIDC_API_AUDIENCE", "").strip(),
            api_issuer=os.environ.get("OIDC_API_ISSUER", "").strip().rstrip("/") or issuer,
            session_secret=os.environ.get("SESSION_SECRET", "").strip(),
            session_hours=int(os.environ.get("SESSION_HOURS", "8")),
            cookie_secure=_bool("SESSION_COOKIE_SECURE", True),
            api_key_login=_bool("DASHBOARD_API_KEY_LOGIN", True),
        )

    def validate(self) -> None:
        if not self.enabled:
            return
        missing = [n for n, v in [("OIDC_ISSUER", self.issuer), ("OIDC_CLIENT_ID", self.client_id),
                                  ("OIDC_CLIENT_SECRET", self.client_secret), ("OIDC_REDIRECT_URI", self.redirect_uri)] if not v]
        if missing:
            raise RuntimeError(f"OIDC_ENABLED=true but these are not set: {', '.join(missing)}")
        if len(self.session_secret) < 32:
            raise RuntimeError("SESSION_SECRET must be at least 32 characters when OIDC is enabled")
        if not self.issuer.startswith("https://") and not self.issuer.startswith("http://127.0.0.1") and not self.issuer.startswith("http://localhost"):
            raise RuntimeError("OIDC_ISSUER must be an https:// URL")
        if self.default_role not in (*ROLES, "none"):
            raise RuntimeError("OIDC_DEFAULT_ROLE must be viewer, responder or none")

    @property
    def metadata_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"


# ----------------------------------------------------------------------------- identity rules
@dataclass
class Principal:
    kind: str           # "session" | "bearer" | "api_key"
    subject: str
    role: str
    name: str = ""
    email: str = ""

    @property
    def can_respond(self) -> bool:
        return self.role == "responder"


def _claim(claims: dict, path: str):
    """Read a claim, allowing dotted paths such as realm_access.roles (Keycloak)."""
    cur: typing.Any = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return v.split()
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v]
    return [str(v)]


def email_of(claims: dict) -> str:
    return str(claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "").lower()


def domain_allowed(claims: dict, s: Settings) -> bool:
    if not s.allowed_domains:
        return True
    if claims.get("email_verified") is False:
        return False
    email = email_of(claims)
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    hd = str(claims.get("hd", "")).lower()           # Google Workspace hosted domain
    return domain in s.allowed_domains or (hd and hd in s.allowed_domains)


def role_for(claims: dict, s: Settings) -> str | None:
    """Map identity-provider claims to an AlertSense role. None means no access."""
    values = set(_as_list(_claim(claims, s.role_claim))) | set(_as_list(claims.get("scp"))) | set(_as_list(claims.get("scope")))
    email = email_of(claims)
    if values & set(s.responder_values) or (email and email in s.responder_emails):
        return "responder"
    if values & set(s.viewer_values) or (email and email in s.viewer_emails):
        return "viewer"
    return s.default_role if s.default_role in ROLES else None


# ----------------------------------------------------------------------------- provider metadata / JWKS cache
class _Provider:
    def __init__(self, s: Settings):
        self.s = s
        self._meta: dict | None = None
        self._meta_at = 0.0
        self._jwks: dict | None = None
        self._jwks_at = 0.0

    async def metadata(self) -> dict:
        if self._meta is None or time.time() - self._meta_at > 3600:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(self.s.metadata_url)
                r.raise_for_status()
                self._meta, self._meta_at = r.json(), time.time()
        return self._meta

    def jwks_stale(self, seconds: int) -> bool:
        return time.time() - self._jwks_at > seconds

    async def jwks(self, force: bool = False) -> dict:
        if force or self._jwks is None or time.time() - self._jwks_at > 3600:
            meta = await self.metadata()
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(meta["jwks_uri"])
                r.raise_for_status()
                self._jwks, self._jwks_at = r.json(), time.time()
        return self._jwks


def decode_access_token(token: str, jwks: dict, s: Settings) -> dict:
    """Validate signature, issuer, audience and expiry of a JWT access token."""
    claims = JsonWebToken(JWT_ALGS).decode(
        token, JsonWebKey.import_key_set(jwks),
        claims_options={
            "iss": {"essential": True, "values": [s.api_issuer]},
            "aud": {"essential": True, "values": [s.api_audience]},
            "exp": {"essential": True},
        },
    )
    claims.validate(leeway=60)
    return dict(claims)


# ----------------------------------------------------------------------------- install
def install_auth(app: FastAPI, settings: Settings | None = None, guard_modules: tuple[str, ...] = ("app.security",)) -> Settings:
    """Attach SSO routes and wrap every API-key dependency defined in `guard_modules`."""
    s = settings or Settings.from_env()
    s.validate()
    if not audit.handlers:                               # audit trail -> stderr (run/api.log) and run/audit.log
        audit.setLevel(logging.INFO)
        audit.propagate = False
        fmt = logging.Formatter("AUDIT %(message)s")
        handlers: list[logging.Handler] = [logging.StreamHandler()]
        if Path("run").is_dir():
            handlers.append(logging.FileHandler("run/audit.log"))
        for h in handlers:
            h.setFormatter(fmt)
            audit.addHandler(h)
    provider = _Provider(s) if s.enabled else None
    oauth = OAuth()
    if s.enabled:
        oauth.register(
            name="idp", client_id=s.client_id, client_secret=s.client_secret,
            server_metadata_url=s.metadata_url,
            client_kwargs={"scope": s.scopes, "code_challenge_method": "S256"},
        )
        app.add_middleware(
            SessionMiddleware, secret_key=s.session_secret, session_cookie="alertsense_session",
            max_age=s.session_hours * 3600, same_site="lax", https_only=s.cookie_secure,
        )

    # ---- who is calling? -------------------------------------------------------------
    def session_principal(request: Request) -> Principal | None:
        if not s.enabled or "session" not in request.scope:
            return None
        u = request.session.get("user")
        if not u or time.time() - u.get("iat", 0) > s.session_hours * 3600 or u.get("role") not in ROLES:
            return None
        return Principal("session", u["sub"], u["role"], u.get("name", ""), u.get("email", ""))

    async def bearer_principal(request: Request) -> Principal | None:
        auth = request.headers.get("authorization", "")
        if not (s.enabled and s.api_audience and auth.lower().startswith("bearer ")):
            return None
        token = auth[7:].strip()
        try:
            try:
                claims = decode_access_token(token, await provider.jwks(), s)
            except (JoseError, ValueError):
                if not provider.jwks_stale(300):
                    raise
                claims = decode_access_token(token, await provider.jwks(force=True), s)   # signing-key rotation
        except httpx.HTTPError:
            raise HTTPException(503, "Identity provider unreachable")
        except Exception as e:  # noqa: BLE001 - malformed / forged tokens must never cause a 500
            log.info("bearer token rejected: %s", type(e).__name__)
            raise HTTPException(401, "Invalid or expired bearer token", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        role = role_for(claims, s)
        if role is None:
            raise HTTPException(403, "Token has no AlertSense role")
        return Principal("bearer", str(claims.get("sub", "")), role, str(claims.get("azp") or claims.get("client_id") or ""))

    def enforce(request: Request, p: Principal) -> Principal:
        if request.method not in SAFE_METHODS:
            if not p.can_respond:
                raise HTTPException(403, "Your role is read-only (viewer)")
            if p.kind == "session":
                sent = request.headers.get("x-csrf-token", "")
                good = request.session.get("csrf", "")
                if not (sent and good and secrets.compare_digest(sent, good)):
                    raise HTTPException(403, "Missing or invalid CSRF token")
        request.state.principal = p
        return p

    # ---- wrap the existing API-key dependency ------------------------------------------
    def wrap(orig):
        try:
            hints = typing.get_type_hints(orig, include_extras=True)
        except Exception:  # unresolved forward references - keep annotations as written
            hints = {}
        params = []
        for p in inspect.signature(orig).parameters.values():
            dep = getattr(p.default, "dependency", None)
            if isinstance(dep, APIKeyHeader):            # don't let auto_error reject cookie/bearer users
                p = p.replace(default=Header(default=None, alias=dep.model.name), annotation=typing.Optional[str])
            elif p.name in hints:
                p = p.replace(annotation=hints[p.name])
            params.append(p.replace(kind=inspect.Parameter.KEYWORD_ONLY))

        async def guarded(**kw):
            request: Request = kw.pop("_alertsense_request")
            p = session_principal(request) or await bearer_principal(request)
            if p is not None:
                return enforce(request, p)
            result = orig(**kw)                         # original X-API-Key validation (fails closed)
            if inspect.isawaitable(result):
                result = await result
            request.state.principal = Principal("api_key", "api-key", "responder", "API key")
            return result

        req = inspect.Parameter("_alertsense_request", inspect.Parameter.KEYWORD_ONLY, annotation=Request)
        guarded.__signature__ = inspect.Signature([req, *params])
        guarded.__name__ = f"oidc_or_{orig.__name__}"
        return guarded

    def walk(dependant, seen):
        for d in dependant.dependencies:
            call = d.call
            if callable(call) and getattr(call, "__module__", None) in guard_modules and inspect.isfunction(call) and call not in seen:
                seen.add(call)
            walk(d, seen)

    guards: set = set()
    for r in app.routes:
        if isinstance(r, APIRoute):
            walk(r.dependant, guards)
    if not guards:
        msg = f"install_auth: no auth dependency from {guard_modules} found on any route"
        if s.enabled:
            raise RuntimeError(msg)
        log.warning(msg)
    for g in guards:
        app.dependency_overrides[g] = wrap(g)
    log.info("SSO %s; wrapped auth dependencies: %s", "enabled" if s.enabled else "disabled", ", ".join(g.__name__ for g in guards))

    # ---- audit trail for every state change ---------------------------------------------
    @app.middleware("http")
    async def audit_log(request: Request, call_next):
        response = await call_next(request)
        if request.method not in SAFE_METHODS and not request.url.path.startswith("/auth/"):
            p = getattr(request.state, "principal", None)
            audit.info(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "actor": p.email or p.subject if p else None,
                "via": p.kind if p else None, "role": p.role if p else None,
                "method": request.method, "path": request.url.path, "status": response.status_code}))
        return response

    # ---- /auth routes --------------------------------------------------------------------
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.get("/config")
    async def auth_config():
        return {"oidc": s.enabled, "provider": s.provider_name if s.enabled else None, "api_key_login": s.api_key_login or not s.enabled}

    @router.get("/me")
    async def me(request: Request):
        p = session_principal(request)
        if not p:
            raise HTTPException(401, "Not signed in")
        return {"name": p.name, "email": p.email, "role": p.role, "csrf": request.session.get("csrf")}

    if s.enabled:
        def fail(code: str) -> RedirectResponse:
            return RedirectResponse("/?" + urlencode({"auth_error": code}), status_code=303)

        @router.get("/login")
        async def login(request: Request):
            request.session.pop("user", None)
            try:
                return await oauth.idp.authorize_redirect(request, s.redirect_uri)
            except httpx.HTTPError:
                log.exception("cannot reach identity provider")
                return fail("provider_unreachable")

        @router.get("/callback")
        async def callback(request: Request):
            if request.query_params.get("error"):
                return fail("denied")
            try:
                token = await oauth.idp.authorize_access_token(request)   # checks state, PKCE, ID-token signature, iss, aud, nonce, exp
            except Exception as e:  # noqa: BLE001 - any failure here must end in a clean, logged refusal
                log.warning("OIDC callback failed: %s: %s", type(e).__name__, e)
                if oauth.idp.server_metadata:
                    oauth.idp.server_metadata.pop("jwks", None)          # re-fetch signing keys next time (key rotation)
                return fail("provider_unreachable" if isinstance(e, httpx.HTTPError) else "login_failed")
            claims = dict(token.get("userinfo") or {})
            if not claims.get("sub"):
                return fail("login_failed")
            if not domain_allowed(claims, s):
                log.warning("SSO login refused (domain) for %s", email_of(claims))
                return fail("domain")
            role = role_for(claims, s)
            if role is None:
                log.warning("SSO login refused (no role) for %s", email_of(claims))
                return fail("no_role")
            request.session.clear()                                         # fresh session after login
            request.session["user"] = {"sub": str(claims["sub"]), "email": email_of(claims),
                                       "name": str(claims.get("name") or email_of(claims)), "role": role, "iat": int(time.time())}
            request.session["csrf"] = secrets.token_urlsafe(32)
            audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "login",
                                   "actor": email_of(claims), "role": role}))
            return RedirectResponse("/", status_code=303)

        @router.post("/logout")
        async def logout(request: Request):
            p = session_principal(request)
            if p:
                audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "logout", "actor": p.email}))
            request.session.clear()
            return JSONResponse({"ok": True})

    app.include_router(router)
    return s
