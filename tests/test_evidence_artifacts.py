"""Evidence artifacts: each test produces a machine-readable file under evidence/ AND asserts its content, so an artifact exists
only if the corresponding control check passed. Files are overwritten on every run; evidence/MANIFEST.json (written by
scripts/security_gate.py) records their SHA-256 digests. No secrets are written (settings are filtered, hashes are not secrets).
"""
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from django.conf import settings
from django.urls import URLPattern, URLResolver, get_resolver

from ngrc.audit import sealer, verifier
from ngrc.audit.signer import get_signer

from .conftest import role_connect
from .test_table_classification import EXPECTED, MANIFEST, PRIVS, RUNTIME_ROLES

pytestmark = pytest.mark.security
EVIDENCE = Path(__file__).resolve().parent.parent / "evidence"


def _write(name: str, payload: dict) -> Path:
    EVIDENCE.mkdir(exist_ok=True)
    body = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "generator": f"tests/test_evidence_artifacts.py::{name}",
            "database": settings.DB_NAME, **payload}
    path = EVIDENCE / name
    path.write_text(json.dumps(body, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def test_rls_coverage_report():
    manifest = {t["table"]: t for t in yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["tables"]}
    rows = {}
    with role_connect("ngrc_owner") as c:
        for t, e in manifest.items():
            oid = c.execute("SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                            "WHERE n.nspname = %s AND c.relname = %s", ["audit" if t.startswith("audit.") else "public", t.split(".")[-1]]
                            ).fetchone()[0]
            flags = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s", [oid]).fetchone()
            pols = [r[0] for r in c.execute("SELECT polname FROM pg_policy WHERE polrelid = %s ORDER BY 1", [oid]).fetchall()]
            rows[t] = {"class": e["class"], "data_class": e["data_class"], "rls_expected": e["rls"], "rls_enabled": flags[0],
                       "rls_forced": flags[1], "policies": pols}
    ten = {t: r for t, r in rows.items() if r["class"] == "TEN"}
    assert ten and all(r["rls_enabled"] and r["rls_forced"] and r["policies"] for r in ten.values())
    assert all(r["rls_enabled"] == (r["rls_expected"] == "required") for r in rows.values())
    _write("rls_coverage.json", {"tables": rows, "ten_tables_without_forced_rls": [t for t, r in ten.items() if not r["rls_forced"]]})


def test_privilege_matrix_report():
    manifest = list(yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["tables"])
    actual: dict = {}
    with role_connect("ngrc_owner") as c:
        for role in RUNTIME_ROLES:
            actual[role] = {}
            for e in manifest:
                t = e["table"]
                oid = c.execute("SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s "
                                "AND c.relname = %s", ["audit" if t.startswith("audit.") else "public", t.split(".")[-1]]).fetchone()[0]
                got = sorted(p for p in PRIVS if c.execute("SELECT has_table_privilege(%s, %s::oid, %s)", [role, oid, p]).fetchone()[0])
                if got:
                    actual[role][t] = got
            assert {k: sorted(v) for k, v in EXPECTED[role].items()} == actual[role], role
        attrs = c.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin FROM pg_roles "
            "WHERE rolname LIKE 'ngrc\\_%' ORDER BY 1").fetchall()
    runtime = [r for r in attrs if r[0] in RUNTIME_ROLES or r[0] in {"ngrc_owner", "ngrc_audit_owner"}]
    assert not any(r[1] or r[2] or r[3] or r[4] or r[5] for r in runtime)
    _write("privilege_matrix.json", {"table_privileges_by_role": actual,
                                     "role_attributes": [dict(zip(("role", "superuser", "bypassrls", "createrole", "createdb", "replication",
                                                                   "can_login"), r, strict=True)) for r in attrs]})


def test_route_policy_inventory():
    def walk(patterns, prefix=""):
        for p in patterns:
            if isinstance(p, URLResolver):
                yield from walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                yield prefix + str(p.pattern), p.callback

    routes = []
    for path, cb in walk(get_resolver().url_patterns):
        cls = getattr(cb, "cls", None) or getattr(cb, "view_class", None)
        pol = getattr(cls, "ngrc_policy", None)
        routes.append({"route": "/" + path, "view": f"{cls.__module__}.{cls.__name__}",
                       "methods": sorted(m.upper() for m in ("get", "post", "patch", "delete") if hasattr(cls, m)),
                       "scope": pol.scope if pol else ("public (healthz)" if path == "healthz" else None),
                       "permission": pol.permission if pol else None, "step_up": pol.step_up if pol else None,
                       "stages": list(pol.stages) if pol else None, "public_reason": (pol.reason if pol and pol.scope == "public" else None)})
    assert all(r["scope"] for r in routes), "a route without a declared policy"
    _write("route_policy_inventory.json", {"route_count": len(routes), "routes": sorted(routes, key=lambda r: r["route"])})


def test_audit_chain_verification_report(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    for i in range(3):
        assert owner.api.post("/tenant/roles/", {"key": f"evidence-role-{i}", "name": f"E{i}", "permissions": ["tenant.view"]}).status_code == 201
    sealed = sealer.seal_all()
    signer = get_signer()
    res = verifier.verify_stream(str(tenant_a.id), {signer.key_id: signer.public_key_raw()}, require_export=True)
    assert res.ok and res.verified_through_seq >= 4  # session-selected + 3 role creations
    _write("audit_chain_verification.json", {
        "scope": "fresh tenant created by this test (the shared test database also holds deliberately tampered streams)",
        "stream": str(tenant_a.id), "ok": res.ok, "verified_through_seq": res.verified_through_seq, "violations": res.violations,
        "checkpoints_issued": [s for s in sealed if s["stream_key"] == str(tenant_a.id)],
        "signer": {"algorithm": signer.algorithm, "key_id": signer.key_id, "dev_only": True,
                   "note": "DEV-ONLY Ed25519 key on the same host as the DB; NOT the production control (open item O-4)"},
        "export_sink": "local directory (NOT WORM storage)"})


def test_security_configuration_snapshot():
    keep = ["NGRC_ENV", "NGRC_PLANE", "DEBUG", "ALLOWED_HOSTS", "SECURE_SSL_REDIRECT", "SECURE_HSTS_SECONDS", "SECURE_CONTENT_TYPE_NOSNIFF",
            "X_FRAME_OPTIONS", "CSRF_COOKIE_NAME", "CSRF_COOKIE_SECURE", "CSRF_COOKIE_HTTPONLY", "CSRF_COOKIE_SAMESITE", "CUSTOMER_COOKIE_NAME",
            "OPERATOR_COOKIE_NAME", "SESSION_POLICY", "AUTH_THROTTLE", "PASSWORD_POLICY", "STEP_UP_T1_WINDOW_S", "SUPPORT_GRANT_DEFAULT_MINUTES",
            "SUPPORT_GRANT_MAX_MINUTES", "BREAK_GLASS_MAX_MINUTES", "KEY_PROVIDER", "AUDIT_SIGNER_BACKEND", "DATA_UPLOAD_MAX_MEMORY_SIZE",
            "INSTALLED_APPS", "MIDDLEWARE", "REST_FRAMEWORK"]
    snap = {k: getattr(settings, k, None) for k in keep}
    snap["PASSWORD_POLICY"] = {k: v for k, v in snap["PASSWORD_POLICY"].items() if k != "blocklist_path"}
    snap["PASSWORD_HASHING_PRODUCTION_TARGET_NOTE"] = "test settings use the OWASP floor for speed; production target is in config/settings/base.py"
    snap["DATABASE_ROLES"] = {a: d["USER"] for a, d in settings.DATABASES.items()}
    snap["DEV_ONLY_COMPONENTS"] = ["KEY_PROVIDER=local", "AUDIT_SIGNER_BACKEND=dev_file"]
    blob = json.dumps(snap, default=str)
    for secret_setting in ("SECRET_KEY", "FIELD_ENCRYPTION_KEY", "TOKEN_PEPPER"):
        assert getattr(settings, secret_setting) not in blob
    assert all("PASSWORD" not in k or k == "PASSWORD_POLICY" or k.startswith("PASSWORD_HASHING") for k in snap)
    _write("config_snapshot.json", snap)
