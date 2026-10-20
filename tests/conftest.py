"""Test harness (Phase 1).

* Builds a THROW-AWAY database `ngrc_test` once per session: drop/create via the dev-only `ngrc_test_admin` role, run
  `db/bootstrap/02_database_setup.sql`, then `manage.py migrate --database=owner` exactly like a deployment.
* Tests run against the real runtime roles (ngrc_app, ngrc_auth, ngrc_ops, ...) - never as a superuser - so RLS, grants and
  triggers are exercised as in production. pytest-django's DB wrapper is NOT used (it would run tests as the app role inside
  a TestCase transaction and flush with TRUNCATE); the DB blocker is lifted for the session instead.
* Every test creates its own uuid-keyed data; nothing is deleted between tests (audit tables are append-only by design).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import uuid
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from django.conf import settings
from django.core.management import call_command
from django.db import connections

BOOTSTRAP_DIR = Path(__file__).resolve().parent.parent / "db" / "bootstrap"
TEST_PASSWORD = "Correct-Horse-Battery-Staple-9!"  # noqa: S105 - test-only strong password (not in the blocklist)


def _dsn(user_env_pw: str, user: str, dbname: str) -> dict:
    return dict(host=os.environ.get("NGRC_DB_HOST", "127.0.0.1"), port=int(os.environ.get("NGRC_DB_PORT", "5432")),
                user=user, password=os.environ[user_env_pw], dbname=dbname, connect_timeout=20)


@pytest.fixture(scope="session", autouse=True)
def _database(django_db_blocker, tmp_path_factory):
    dbname = settings.DB_NAME
    assert dbname.endswith("_test"), "refusing to rebuild a database that is not a *_test database"
    with psycopg.connect(**_dsn("NGRC_DB_TESTADMIN_PASSWORD", "ngrc_test_admin", "postgres"), autocommit=True) as admin:
        admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        admin.execute(f'CREATE DATABASE "{dbname}" OWNER ngrc_owner')
    sql = (BOOTSTRAP_DIR / "02_database_setup.sql").read_text(encoding="utf-8").replace(':"dbname"', f'"{dbname}"')
    with psycopg.connect(**_dsn("NGRC_DB_OWNER_PASSWORD", "ngrc_owner", dbname), autocommit=True) as owner:
        owner.execute(sql)
    django_db_blocker.unblock()
    # audit signing material + local checkpoint export (DEV/TEST ONLY, never production controls)
    keydir = tmp_path_factory.mktemp("audit")
    settings.EVIDENCE_STORE_DIR = str(tmp_path_factory.mktemp("evidence"))   # DEV-ONLY local store, private to this test session
    settings.AUDIT_SIGNER_BACKEND = "dev_file"
    settings.AUDIT_SIGNER_KEY_PATH = str(keydir / "signer.pem")
    settings.AUDIT_CHECKPOINT_EXPORT_DIR = str(keydir / "export")
    call_command("migrate", database="owner", verbosity=0, interactive=False)
    yield
    for alias in connections:
        connections[alias].close()


# ---------------------------------------------------------------------------------------------------------------- raw SQL
def raw(alias: str, sql: str, params=None, *, fetch: bool = True):
    """Run SQL on a runtime connection in autocommit-per-statement style (Django default); returns rows or None."""
    with connections[alias].cursor() as cur:
        cur.execute(sql, params or [])
        return cur.fetchall() if fetch and cur.description else None


@pytest.fixture
def sql():
    return raw


def _system_roles():
    """The SAME role definitions production provisioning uses (ngrc.authz.permissions.SYSTEM_ROLES)."""
    from ngrc.authz import permissions as perm

    return [{"key": k, "name": r["name"], "permissions": r["permissions"]} for k, r in perm.SYSTEM_ROLES.items()]


SYSTEM_ROLES = _system_roles()


class Tenant:
    def __init__(self, id_, slug, owner_invite_hash):
        self.id, self.slug, self.owner_invite_hash = id_, slug, owner_invite_hash

    def role_id(self, key: str):
        from ngrc.core.context import tenant_context

        with tenant_context(self.id), connections["default"].cursor() as cur:
            cur.execute("SELECT id FROM ten_role WHERE key = %s", [key])
            return cur.fetchone()[0]


def provision_tenant(slug: str | None = None) -> Tenant:
    """Provision a tenant through the SECURITY DEFINER provisioning function (as ngrc_ops), like production."""
    slug = slug or f"t-{secrets.token_hex(5)}"
    token_hash = secrets.token_hex(32)
    with connections["ops"].cursor() as cur:
        cur.execute("SELECT plt_provision_tenant(%s,%s,%s,%s,now() + interval '7 days',%s::jsonb)",
                    [slug, slug.upper(), f"owner@{slug}.example", token_hash, json.dumps(SYSTEM_ROLES)])
        tid = cur.fetchone()[0]
    return Tenant(tid, slug, token_hash)


@pytest.fixture
def tenant_a() -> Tenant:
    return provision_tenant()


@pytest.fixture
def tenant_b() -> Tenant:
    return provision_tenant()


def make_account(email: str | None = None, password: str = TEST_PASSWORD, *, verified: bool = True):
    from ngrc.iam import services

    email = email or f"user-{secrets.token_hex(5)}@example.test"
    return services.create_account(email, password, "Test User", verified=verified)


@pytest.fixture
def account():
    return make_account()


def add_member(tenant: Tenant, account, role: str = "member", kind: str = "member", expires_at=None) -> uuid.UUID:
    """Create a membership as the schema owner under that tenant's context (test fixture shortcut; the owner is the only
    identity that may create system-role memberships outside the invitation flow)."""
    from django.db import transaction

    mid = uuid.uuid4()
    with transaction.atomic(using="owner"), connections["owner"].cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant.id)])
        cur.execute("SELECT id FROM ten_role WHERE key = %s AND tenant_id = %s", [role, str(tenant.id)])
        rid = cur.fetchone()[0]
        cur.execute("INSERT INTO ten_membership (id, tenant_id, principal_id, role_id, kind, status, expires_at, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,'active',%s,now())",
                    [str(mid), str(tenant.id), str(account.id), str(rid), kind, expires_at])
    return mid


@pytest.fixture
def make_member():
    return add_member


def future(**kw):
    from ngrc.core import clock

    return clock.now() + timedelta(**kw)


_ID = re.compile(r"^[a-z_][a-z0-9_.]*$")


def role_connect(role: str):
    """Open a NEW psycopg connection as a runtime role (outside Django) for privilege-matrix probing."""
    pw_env = {"ngrc_app": "NGRC_DB_APP_PASSWORD", "ngrc_auth": "NGRC_DB_AUTH_PASSWORD", "ngrc_ops": "NGRC_DB_OPS_PASSWORD",
              "ngrc_owner": "NGRC_DB_OWNER_PASSWORD", "ngrc_audit_reader_platform": "NGRC_DB_AUDIT_READER_PASSWORD",
              "ngrc_audit_sealer": "NGRC_DB_AUDIT_SEALER_PASSWORD", "ngrc_audit_verifier": "NGRC_DB_AUDIT_VERIFIER_PASSWORD"}
    assert _ID.match(role)
    return psycopg.connect(**_dsn(pw_env[role], role, settings.DB_NAME), autocommit=False)


# ---------------------------------------------------------------------------------------------------------------- clock
@pytest.fixture
def clock_ctl(monkeypatch):
    """Shift ngrc.core.clock.now() forward (TOTP steps, idle/absolute timeouts, expiry). DB-side now() is NOT shifted."""
    from ngrc.core import clock

    real = clock.now

    class Ctl:
        offset = 0

        def advance(self, **kw):
            self.offset += int(timedelta(**kw).total_seconds())

        def ts(self) -> int:
            return int(clock.now().timestamp())

    ctl = Ctl()
    monkeypatch.setattr(clock, "now", lambda: real() + timedelta(seconds=ctl.offset))
    return ctl


# ---------------------------------------------------------------------------------------------------------------- people
class CustomerUser:
    def __init__(self, account, password, tenant, role, api, totp, recovery_codes, clock):
        self.account, self.password, self.tenant, self.role = account, password, tenant, role
        self.api, self.totp, self.recovery_codes, self.clock = api, totp, recovery_codes, clock

    @property
    def email(self):
        return self.account.email

    def stepup(self):
        self.clock.advance(seconds=31)  # a fresh TOTP time step per step-up (replay protection rejects reuse of a step)
        r = self.api.post("/auth/stepup/", {"method": "totp", "code": self.totp.code(self.clock.ts())})
        assert r.status_code == 200, r.content

    def relogin(self):
        from .helpers import login_with_totp

        self.api = login_with_totp(self.email, self.password, self.totp, self.clock.ts())
        return self.api


@pytest.fixture
def make_user(clock_ctl):
    """Account + membership in `tenant` with `role`, MFA enrolled via the real API, session active with tenant selected."""
    from .helpers import enroll_totp_and_login

    def _make(tenant: Tenant, role: str = "owner", *, select_tenant: bool = True, kind: str = "member") -> CustomerUser:
        acct = make_account()
        add_member(tenant, acct, role, kind=kind)
        api, totp, codes = enroll_totp_and_login(acct.email, TEST_PASSWORD, clock_ctl.ts())
        if select_tenant:
            r = api.post("/auth/tenants/select/", {"tenant_id": str(tenant.id)})
            assert r.status_code == 200, r.content
            api.refresh_csrf()
        return CustomerUser(acct, TEST_PASSWORD, tenant, role, api, totp, codes, clock_ctl)

    return _make


@pytest.fixture
def make_operator():
    from ngrc.control_plane.operators import create_operator

    def _make(*roles: str):
        email = f"op-{secrets.token_hex(5)}@nsuregrc.test"
        op = create_operator(email, "Op Erator", TEST_PASSWORD, list(roles))
        return op

    return _make


class OperatorUser:
    def __init__(self, account, auth, api):
        self.account, self.auth, self.api = account, auth, api

    def stepup(self):
        from .helpers import operator_stepup

        operator_stepup(self.api, self.auth)

    def relogin(self):
        from .helpers import operator_login

        self.api, _ = operator_login(self.account.email, TEST_PASSWORD, self.auth)
        return self.api


@pytest.fixture
def login_operator(make_operator):
    from .helpers import operator_login

    def _login(*roles: str) -> OperatorUser:
        op = make_operator(*roles)
        api, auth = operator_login(op.email, TEST_PASSWORD, None)
        return OperatorUser(op, auth, api)

    return _login
