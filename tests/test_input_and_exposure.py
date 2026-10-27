"""SQL injection, XSS/response hardening, hostile input, and secret exposure (responses, logs, audit trail, email, repository)."""
import json
import logging
import re
import time
from pathlib import Path

import pytest
from django.conf import settings
from django.core import mail

from ngrc.core.logging import JsonFormatter, RedactingFilter, redact

from .conftest import TEST_PASSWORD, make_account, role_connect
from .helpers import Api, audit_events

pytestmark = pytest.mark.security

SQLI = ["' OR '1'='1", "'; DROP TABLE ten_role; --", "1; SELECT pg_sleep(4)--", "' UNION SELECT password_hash FROM idn_account--",
        "\" OR \"\"=\"", "') OR ('a'='a", "admin'--", "%27%20OR%201=1", "\\'; SELECT 1;--", "$$; SELECT pg_sleep(4); $$"]
ROOT = Path(__file__).resolve().parent.parent


def _count(sql):
    with role_connect("ngrc_owner") as c:
        return c.execute(sql).fetchone()[0]


# ------------------------------------------------------------------------------------------------ SQL injection
@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_in_login_fields(payload, account):
    api = Api()
    t0 = time.monotonic()
    r = api.post("/auth/login/", {"email": payload, "password": payload})
    assert r.status_code == 401 and time.monotonic() - t0 < 3.5
    assert r.json() == {"error": "invalid_credentials"}
    r = api.post("/auth/password/reset/request/", {"email": payload})
    assert r.status_code == 202


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_in_tenant_api_inputs(payload, tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    roles_before = _count("SELECT count(*) FROM pg_class WHERE relname = 'ten_role'")
    t0 = time.monotonic()
    for body in ({"key": payload, "name": payload, "permissions": [payload]},
                 {"key": "inj-ok", "name": payload, "permissions": ["tenant.view"]}):
        r = owner.api.post("/tenant/roles/", body)
        assert r.status_code in (201, 400, 409), (r.status_code, r.content)
    for q in (f"?after_seq={payload}", f"?limit={payload}", f"?after_seq=1{payload}"):
        assert owner.api.get("/tenant/audit/events/" + q).status_code in (200, 400)
    r = owner.api.post("/tenant/invitations/", {"email": payload, "role_id": payload})
    assert r.status_code == 400
    assert time.monotonic() - t0 < 6
    assert _count("SELECT count(*) FROM pg_class WHERE relname = 'ten_role'") == roles_before  # the table still exists
    # a payload stored as a name is inert data, returned verbatim as JSON
    stored = [x for x in owner.api.get("/tenant/roles/").json()["roles"] if x["key"] == "inj-ok"]
    assert stored and stored[0]["name"] == payload


def test_sql_injection_cannot_reach_other_tenants_or_credentials(two_tenant_users):
    a, b = two_tenant_users
    marker = "zz-b-marker-role"
    b.api.post("/tenant/roles/", {"key": marker, "name": "B", "permissions": ["tenant.view"]})
    r = a.api.get("/tenant/roles/?key=' OR tenant_id IS NOT NULL --&name=%27%20OR%201=1")
    assert marker not in r.content.decode() and "argon2" not in r.content.decode()


def test_operator_api_inputs_are_parameterised(login_operator):
    sec = login_operator("platform_security")
    t0 = time.monotonic()
    for payload in SQLI:
        assert sec.api.get(f"/audit/platform/?after_seq={payload}&limit={payload}").status_code == 400
    assert time.monotonic() - t0 < 4


def test_no_string_built_sql_outside_the_reviewed_set():
    """Static guard: every `execute(f"...")` must be in this reviewed list (identifiers validated or constants only)."""
    reviewed = {
        "ngrc/audit/service.py": 2,   # {_SQL_ARGS} is a module constant of %s placeholders
        "ngrc/tenancy/views.py": 0,
    }
    found = {}
    for path in (ROOT / "ngrc").rglob("*.py"):
        rel = path.relative_to(ROOT).as_posix()
        if "/migrations/" in rel or rel.endswith("sqlgen.py"):
            continue  # migrations & generators run only as ngrc_owner from reviewed code; identifiers are regex-validated
        n = len(re.findall(r"execute\(\s*f[\"']", path.read_text(encoding="utf-8")))
        if n:
            found[rel] = n
    assert found == {k: v for k, v in reviewed.items() if v}, f"new f-string SQL execute() calls: {found}"
    assert not any(".raw(" in p.read_text(encoding="utf-8") or ".extra(" in p.read_text(encoding="utf-8")
                   for p in (ROOT / "ngrc").rglob("*.py") if "/migrations/" not in p.as_posix())


# ------------------------------------------------------------------------------------------------ hostile input
@pytest.mark.parametrize("bad", ["\x00", "a\x00b", "\ud800"])
def test_nul_and_invalid_unicode_never_cause_a_server_error(bad, tenant_a, make_user):
    api = Api()
    for path in ("/auth/login/", "/auth/password/reset/request/"):
        r = api.post(path, {"email": f"x{bad}@example.test", "password": f"p{bad}w"})
        assert r.status_code < 500, (path, r.status_code)
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/roles/", {"key": "nul-role", "name": f"n{bad}", "permissions": ["tenant.view"]})
    assert r.status_code < 500, r.content
    assert owner.api.post("/auth/mfa/totp/verify/", {"code": bad}).status_code < 500


def test_malformed_and_oversized_bodies_are_rejected_cleanly(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    hdr = {"HTTP_X_CSRFTOKEN": owner.api._csrf(), "HTTP_ORIGIN": "https://testserver", "secure": True}
    cases = [("{not json", "application/json"), ("[1,2,3]", "application/json"), ('"string"', "application/json"),
             ("a=b&c=d", "application/x-www-form-urlencoded"), ("<xml/>", "application/xml"), ("x" * 20, "text/plain")]
    for body, ctype in cases:
        r = owner.api.c.post("/api/v1/tenant/roles/", data=body, content_type=ctype, REMOTE_ADDR=owner.api.ip, **hdr)
        assert 400 <= r.status_code < 500 and r.headers["Content-Type"].startswith("application/json"), (ctype, r.status_code)
    big = json.dumps({"key": "big-body", "name": "x" * (2 * 1024 * 1024), "permissions": []})
    r = owner.api.c.post("/api/v1/tenant/roles/", data=big, content_type="application/json", REMOTE_ADDR=owner.api.ip, **hdr)
    assert r.status_code in (400, 413)
    deep = "[" * 5000 + "]" * 5000
    r = owner.api.c.post("/api/v1/tenant/roles/", data=deep, content_type="application/json", REMOTE_ADDR=owner.api.ip, **hdr)
    assert r.status_code < 500
    too_many = {"key": "many-perms", "name": "M", "permissions": ["tenant.view"] * 1000}
    assert owner.api.post("/tenant/roles/", too_many).status_code == 400


def test_http_method_override_is_not_honoured(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/me/?_method=DELETE", {}, HTTP_X_HTTP_METHOD_OVERRIDE="DELETE")
    assert r.status_code == 405


# ------------------------------------------------------------------------------------------------ XSS / response hardening
HTML = "<script>alert(1)</script><img src=x onerror=alert(2)>"


def test_all_responses_are_json_with_hardening_headers(tenant_a, make_user, login_operator):
    owner = make_user(tenant_a, "owner")
    op = login_operator("platform_admin")
    probes = [owner.api.get("/tenant/me/"), owner.api.get("/tenant/nope/"), owner.api.post("/tenant/me/", {}),
              Api().get("/auth/session/"), Api().post("/auth/login/", {"email": 1}), op.api.get("/auth/session/"),
              Api().c.get("/definitely/not/here", secure=True), Api().c.get("/healthz", secure=True),
              Api().c.post("/api/v1/auth/login/", data="x", content_type="text/html", secure=True)]
    for r in probes:
        assert r.headers["Content-Type"].startswith("application/json"), r.request["PATH_INFO"]
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'none'" in r.headers["Content-Security-Policy"] and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["Cache-Control"] == "no-store"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "max-age=31536000" in r.headers["Strict-Transport-Security"]
        assert r.headers.get("X-Request-ID")
        assert "Server" not in r.headers or "gunicorn" not in r.headers["Server"].lower()


def test_html_payloads_are_stored_as_inert_json_text(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/roles/", {"key": "xss-role", "name": HTML, "permissions": ["tenant.view"]})
    assert r.status_code == 201
    got = owner.api.get("/tenant/roles/")
    assert got.headers["Content-Type"].startswith("application/json") and got.headers["X-Content-Type-Options"] == "nosniff"
    assert [x for x in got.json()["roles"] if x["key"] == "xss-role"][0]["name"] == HTML
    # nothing in this service renders HTML: user input is not placed into emails either
    owner.api.post("/tenant/invitations/", {"email": "visitor@example.test", "role_id": str(tenant_a.role_id("member"))})
    body = [m for m in mail.outbox if "visitor@example.test" in m.to][-1].body
    assert "<" not in body and HTML not in body


def test_reflected_input_in_errors_is_not_echoed_back():
    r = Api().post("/auth/login/", {"email": HTML, "password": HTML})
    assert HTML not in r.content.decode() and "<" not in r.content.decode()
    r = Api().get(f"/{HTML}")
    assert r.status_code == 404 and HTML not in r.content.decode()


def test_unhandled_exceptions_return_a_generic_body(tenant_a, make_user, monkeypatch):
    from ngrc.tenancy import views

    owner = make_user(tenant_a, "owner")
    owner.api.c.raise_request_exception = False

    def explode(self, request):
        raise RuntimeError("SELECT * FROM idn_account WHERE password_hash = 'secret-internal-detail'")

    monkeypatch.setattr(views.MeView, "get", explode)
    r = owner.api.get("/tenant/me/")
    assert r.status_code == 500 and r.json() == {"error": "server_error"}
    assert "secret-internal-detail" not in r.content.decode() and "Traceback" not in r.content.decode()


def test_cors_is_default_deny(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = owner.api.c.get("/api/v1/tenant/me/", secure=True, HTTP_ORIGIN="https://evil.example", REMOTE_ADDR=owner.api.ip)
    assert not any(h.lower().startswith("access-control-") for h in r.headers)
    pre = owner.api.c.options("/api/v1/tenant/roles/", secure=True, HTTP_ORIGIN="https://evil.example",
                              HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST", REMOTE_ADDR=owner.api.ip)
    assert not any(h.lower().startswith("access-control-allow") for h in pre.headers)


# ------------------------------------------------------------------------------------------------ secret exposure
def _scan_audit_for(*secrets):
    with role_connect("ngrc_audit_verifier") as c:
        for table in ("audit.tenant_event", "audit.platform_event"):
            rows = c.execute(f"SELECT row_to_json(t)::text FROM {table} t").fetchall()  # noqa: S608 - constant table names
            blob = "\n".join(r[0] for r in rows)
            for s in secrets:
                assert s not in blob, f"secret material found in {table}"


def test_no_secret_ever_reaches_the_audit_trail(tenant_a, make_user, caplog):
    u = make_user(tenant_a, "owner")
    sid, csrf_cookie = u.api.cookie(settings.CUSTOMER_COOKIE_NAME), u.api.cookie(settings.CSRF_COOKIE_NAME)  # before the reset kills them
    Api().post("/auth/login/", {"email": u.email, "password": "Wrong-Guess-Not-Real-1!"})
    u.api.post("/tenant/invitations/", {"email": "audit.probe@example.test", "role_id": str(tenant_a.role_id("member"))})
    Api().post("/auth/password/reset/request/", {"email": u.email})
    token = re.search(r"#token=([\w-]+)", mail.outbox[-1].body).group(1)
    new_pw = "Totally-New-Passphrase-31337!"
    Api().post("/auth/password/reset/confirm/", {"token": token, "new_password": new_pw})
    codes = u.recovery_codes
    secrets = [TEST_PASSWORD, "Wrong-Guess-Not-Real-1!", new_pw, token, u.totp.t.secret, codes[0], codes[0].replace("-", ""),
               sid, csrf_cookie, "argon2id"]
    assert all(secrets), [i for i, s in enumerate(secrets) if not s]  # an empty "secret" would match everything
    _scan_audit_for(*secrets)
    # identifiers are keyed hashes, never raw addresses
    assert u.email not in json.dumps([e["details"] for e in audit_events(platform=True, action="auth.login.failure")])


def test_secrets_are_not_logged(tenant_a, make_user, caplog):
    caplog.set_level(logging.DEBUG)
    u = make_user(tenant_a, "owner")
    Api().post("/auth/login/", {"email": u.email, "password": "Log-Probe-Passphrase-123!"})
    u.api.post("/tenant/invitations/", {"email": "log.probe@example.test", "role_id": str(tenant_a.role_id("member"))})
    text = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    for secret in ("Log-Probe-Passphrase-123!", TEST_PASSWORD, u.totp.t.secret, u.api.cookie(settings.CUSTOMER_COOKIE_NAME),
                   re.search(r"#token=([\w-]+)", mail.outbox[-1].body).group(1)):
        assert secret not in text


def test_redaction_filter_and_formatter():
    samples = {
        "password=hunter2hunter2": "hunter2hunter2", "Authorization: Bearer abcdefghijklmnop12345": "abcdefghijklmnop12345",
        "token: 'tok_live_abcdefghijklmnopqrstuvwx'": "tok_live", "csrf=abcdef123456": "abcdef123456",
        "cookie=__Host-ngrc-sid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": "AAAAAAAAAAAAAAAA",
        "secret_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "aaaaaaaaaaaaaaaa",
    }
    for text, leaked in samples.items():
        assert leaked not in redact(text), text
    rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed with password=%s", ("p@ssw0rd-long-value",), None)
    assert RedactingFilter().filter(rec)
    out = json.loads(JsonFormatter().format(rec))
    assert "p@ssw0rd" not in json.dumps(out) and out["level"] == "ERROR"
    try:
        raise ValueError("SELECT secret FROM x WHERE token='leak-me-please'")
    except ValueError:
        import sys

        rec = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    RedactingFilter().filter(rec)
    assert "leak-me-please" not in json.dumps(json.loads(JsonFormatter().format(rec)))


def test_api_responses_never_contain_credentials_or_hashes(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    blobs = [u.api.get(p).content.decode() for p in ("/auth/session/", "/auth/tenants/", "/tenant/me/", "/tenant/members/", "/tenant/roles/",
                                                      "/tenant/invitations/", "/tenant/audit/events/", "/tenant/support/grants/")]
    joined = "\n".join(blobs)
    for needle in ("argon2", "password_hash", "secret_sealed", "token_hash", "digest", u.totp.t.secret, "$argon2"):
        assert needle not in joined, needle
    login = Api().post("/auth/login/", {"email": u.email, "password": u.password})
    assert set(login.json()) == {"stage", "methods"} and "token" not in login.content.decode().lower()


def test_totp_secret_is_shown_exactly_once(tenant_a):
    from .conftest import add_member

    acct = make_account()
    add_member(tenant_a, acct, "member")
    api = Api()
    api.post("/auth/login/", {"email": acct.email, "password": TEST_PASSWORD})
    first = api.post("/auth/mfa/totp/enroll/begin/").json()["secret"]
    second = api.post("/auth/mfa/totp/enroll/begin/").json()["secret"]
    assert first != second  # unconfirmed enrolment is replaced; there is no endpoint that re-reads a stored secret
    assert api.get("/auth/mfa/totp/").status_code == 404


def test_emails_carry_tokens_only_in_the_url_fragment(account, tenant_a, make_user):
    Api().post("/auth/password/reset/request/", {"email": account.email})
    owner = make_user(tenant_a, "owner")
    owner.api.post("/tenant/invitations/", {"email": "frag@example.test", "role_id": str(tenant_a.role_id("member"))})
    for m in mail.outbox:
        for url in re.findall(r"https?://\S+", m.body):
            assert "?" not in url or "token" not in url.split("?", 1)[1]
            if "token" in url:
                assert "#token=" in url and url.startswith(settings.PUBLIC_BASE_URL)
        assert TEST_PASSWORD not in m.body


def test_repository_contains_no_hardcoded_secrets():
    patterns = [r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"xox[baprs]-[0-9A-Za-z-]{10,}",
                r"ghp_[0-9A-Za-z]{30,}", r"(?i)\b(secret_key|password|passwd|api_key|token)\s*=\s*[\"'][^\"'\s]{12,}[\"']"]
    allowed_files = {"tests/conftest.py", "tests/helpers.py"}  # test-only fixtures; reviewed (TEST_PASSWORD etc.)
    hits = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if (not path.is_file() or any(part in {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "evidence", ".git",
                                               ".dev-certs", "node_modules"}  # .dev-certs: gitignored local dev TLS
                                      # key (D-P6-001, scripts/gen_dev_cert.sh), regenerated per machine, never committed
                                      for part in path.parts) or path.suffix in {".pyc", ".lock", ".png"}):
            continue
        if rel in allowed_files or rel.startswith("tests/"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in patterns:
            if re.search(pat, text):
                hits.append((rel, pat))
    assert hits == [], hits
    assert not [p for p in ROOT.rglob(".env*") if ".venv" not in p.parts and p.is_file()], "an .env file is inside the repository"


def test_error_pages_do_not_disclose_framework_details():
    for r in (Api().c.get("/nope", secure=True), Api().c.get("/api/v1/auth/login/", secure=True), Api().c.put("/api/v1/auth/login/", secure=True)):
        body = r.content.decode().lower()
        assert not any(w in body for w in ("django", "traceback", "exception", "debug", "settings", "postgres", "psycopg"))


@pytest.fixture
def two_tenant_users(make_user):
    from .conftest import provision_tenant

    return make_user(provision_tenant(), "owner"), make_user(provision_tenant(), "owner")
