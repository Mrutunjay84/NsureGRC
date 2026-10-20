"""Test helpers: HTTPS+CSRF API client, software WebAuthn authenticator, TOTP and login drivers. TEST-ONLY code."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import Client

ORIGIN = "https://testserver"
RP_ID = "testserver"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Api:
    """Browser-like client: keeps cookies, fetches and sends the CSRF token, speaks JSON over HTTPS."""

    def __init__(self, prefix: str = "/api/v1", origin: str = ORIGIN, csrf: bool = True, ip: str | None = None):
        self.c = Client(enforce_csrf_checks=True)
        self.prefix, self.origin, self.use_csrf, self.token = prefix, origin, csrf, None
        # own source address per client: IP throttling state must not leak between independent tests
        self.ip = ip or f"10.{os.urandom(1)[0]}.{os.urandom(1)[0]}.{os.urandom(1)[0] or 1}"

    def _csrf(self):
        if self.token is None:
            r = self.c.get(f"{self.prefix}/auth/csrf/", secure=True, HTTP_ORIGIN=self.origin, REMOTE_ADDR=self.ip)
            self.token = r.json()["csrfToken"]
        return self.token

    def _hdr(self, extra):
        h = {"HTTP_ORIGIN": self.origin, "REMOTE_ADDR": self.ip, **extra}
        if self.use_csrf:
            h["HTTP_X_CSRFTOKEN"] = self._csrf()
        return h

    def get(self, path, **extra):
        return self.c.get(self.prefix + path, secure=True, HTTP_ORIGIN=self.origin, REMOTE_ADDR=self.ip, **extra)

    def post(self, path, data=None, **extra):
        return self.c.post(self.prefix + path, data=json.dumps(data or {}), content_type="application/json", secure=True,
                           **self._hdr(extra))

    def patch(self, path, data=None, **extra):
        return self.c.patch(self.prefix + path, data=json.dumps(data or {}), content_type="application/json", secure=True,
                            **self._hdr(extra))

    def delete(self, path, **extra):
        return self.c.delete(self.prefix + path, secure=True, **self._hdr(extra))

    def raw(self, method, path, **kw):
        kw.setdefault("REMOTE_ADDR", self.ip)
        return getattr(self.c, method)(self.prefix + path, secure=True, **kw)

    def cookie(self, name):
        m = self.c.cookies.get(name)
        return m.value if m else None

    def set_cookie(self, name, value):
        self.c.cookies[name] = value

    def refresh_csrf(self):
        self.token = None


class Authenticator:
    """Minimal ES256 platform authenticator with UV, `none` attestation. Counter increments on every assertion."""

    def __init__(self, rp_id=RP_ID, origin=ORIGIN, uv=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.rp_id, self.origin, self.uv, self.counter = rp_id, origin, uv, 0

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _flags(self, attested: bool) -> int:
        return 0x01 | (0x04 if self.uv else 0) | (0x40 if attested else 0)

    def register(self, options: dict, *, origin=None, challenge=None) -> dict:
        ch = challenge or options["challenge"]
        cdj = json.dumps({"type": "webauthn.create", "challenge": ch, "origin": origin or self.origin, "crossOrigin": False}).encode()
        ad = hashlib.sha256(self.rp_id.encode()).digest() + bytes([self._flags(True)]) + struct.pack(">I", self.counter)
        ad += b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att), "transports": []},
                "clientExtensionResults": {}}

    def assert_(self, options: dict, *, origin=None, challenge=None, counter=None, rp_id=None) -> dict:
        ch = challenge or options["challenge"]
        self.counter = counter if counter is not None else self.counter + 1
        cdj = json.dumps({"type": "webauthn.get", "challenge": ch, "origin": origin or self.origin, "crossOrigin": False}).encode()
        ad = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([self._flags(False)]) + struct.pack(">I", self.counter)
        sig = self.key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(ad), "signature": b64u(sig),
                             "userHandle": None},
                "clientExtensionResults": {}}


class Totp:
    """TOTP generator that moves forward one 30 s step per code so replay protection never trips on accident."""

    def __init__(self, secret: str):
        self.t = pyotp.TOTP(secret)
        self.step = None

    def code(self, now_ts: int, *, advance: bool = True) -> str:
        base = now_ts // 30
        self.step = base if self.step is None else (max(self.step + 1, base) if advance else self.step)
        return self.t.at(self.step * 30)


# ------------------------------------------------------------------------------------------------------ login drivers
def enroll_totp_and_login(email: str, password: str, now_ts: int, api: Api | None = None):
    """Password login -> TOTP enrolment -> active customer session. Returns (api, totp, recovery_codes)."""
    api = api or Api()
    r = api.post("/auth/login/", {"email": email, "password": password})
    assert r.status_code == 200 and r.json()["stage"] == "enroll_mfa", r.content
    b = api.post("/auth/mfa/totp/enroll/begin/")
    assert b.status_code == 200, b.content
    totp = Totp(b.json()["secret"])
    c = api.post("/auth/mfa/totp/enroll/confirm/", {"code": totp.code(now_ts)})
    assert c.status_code == 200 and c.json()["stage"] == "active", c.content
    api.refresh_csrf()
    return api, totp, c.json()["recovery_codes"]


def login_with_totp(email: str, password: str, totp: Totp, now_ts: int, api: Api | None = None):
    api = api or Api()
    r = api.post("/auth/login/", {"email": email, "password": password})
    assert r.status_code == 200 and r.json()["stage"] == "password_ok", r.content
    v = api.post("/auth/mfa/totp/verify/", {"code": totp.code(now_ts)})
    assert v.status_code == 200, v.content
    api.refresh_csrf()
    return api


def operator_login(email: str, password: str, auth: Authenticator | None, *, api: Api | None = None):
    """Operator password login + WebAuthn (enrol on first use). Returns (api, authenticator)."""
    api = api or Api(prefix="/ops/api/v1")
    r = api.post("/auth/login/", {"email": email, "password": password})
    assert r.status_code == 200, r.content
    stage = r.json()["stage"]
    if stage == "enroll_mfa":
        auth = auth or Authenticator()
        opts = api.post("/auth/mfa/webauthn/register/begin/").json()
        done = api.post("/auth/mfa/webauthn/register/complete/", {"credential": auth.register(opts)})
        assert done.status_code == 200, done.content
    else:
        opts = api.post("/auth/mfa/webauthn/authenticate/begin/").json()
        done = api.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts)})
        assert done.status_code == 200, done.content
    api.refresh_csrf()
    return api, auth


def operator_stepup(api: Api, auth: Authenticator):
    opts = api.post("/auth/stepup/webauthn/begin/").json()
    r = api.post("/auth/stepup/webauthn/complete/", {"credential": auth.assert_(opts)})
    assert r.status_code == 200, r.content


# ------------------------------------------------------------------------------------------------------ audit queries
def audit_events(*, tenant_id=None, action: str | None = None, platform: bool = False, **where) -> list[dict]:
    """Read audit events as the independent verifier role (read-only). Filters: action, tenant, reason_code, actor_id ..."""
    from .conftest import role_connect

    table = "audit.platform_event" if platform else "audit.tenant_event"
    tcol = "related_tenant_id" if platform else "tenant_id"
    conds, args = [], []
    if tenant_id is not None:
        conds.append(f"{tcol} = %s")
        args.append(str(tenant_id))
    if action:
        conds.append("action = %s")
        args.append(action)
    for k, v in where.items():
        conds.append(f"{k} = %s")
        args.append(str(v))
    sql = (f"SELECT seq, action, result, reason_code, actor_id::text, actor_type, on_behalf_of_grant::text, details::text, "
           f"object_id FROM {table}" + (" WHERE " + " AND ".join(conds) if conds else "") + " ORDER BY occurred_at")
    with role_connect("ngrc_audit_verifier") as c:
        rows = c.execute(sql, args).fetchall()
    keys = ("seq", "action", "result", "reason_code", "actor_id", "actor_type", "grant", "details", "object_id")
    return [dict(zip(keys, r, strict=True)) for r in rows]


def last_mail_token(outbox, to: str) -> str:
    """Extract the single-use token from the most recent email to `to` (token lives in the URL fragment)."""
    import re

    for m in reversed(outbox):
        if to in m.to:
            return re.search(r"#token=([A-Za-z0-9_-]+)", m.body).group(1)
    raise AssertionError(f"no email to {to}")
