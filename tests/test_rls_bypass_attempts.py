"""RLS bypass attempts by a hostile session that can run arbitrary SQL AS the runtime role (e.g. via an injection bug).

Honest scope: PostgreSQL RLS here defends against *application-logic* mistakes and limits what injected SQL can do. A session that can
execute SQL as `ngrc_app` can still set `app.tenant_id` itself (it is an ordinary GUC); that is why the other layers exist
(no string-built SQL, parameterised queries, least-privilege roles, no DDL, no credential tables). Each test below proves one
escalation path is closed.
"""
import uuid

import psycopg
import pytest

from .conftest import make_account, role_connect

pytestmark = pytest.mark.security


def _app(tenant=None, role="ngrc_app"):
    c = role_connect(role)
    if tenant is not None:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant)])
    return c


def test_disabling_row_security_makes_queries_fail_not_leak(tenant_a, tenant_b):
    with _app(tenant_a.id) as c:
        c.execute("SET row_security = off")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # "query would be affected by row-level security policy"
            c.execute("SELECT * FROM ten_role").fetchall()


@pytest.mark.parametrize("stmt", [
    "SET ROLE ngrc_owner", "SET ROLE ngrc_audit_owner", "SET ROLE postgres", "SET SESSION AUTHORIZATION ngrc_owner",
    "SET SESSION AUTHORIZATION postgres",
])
def test_role_switching_is_impossible(stmt, tenant_a):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.Error):
        c.execute(stmt)


@pytest.mark.parametrize("stmt", [
    "ALTER TABLE ten_role DISABLE ROW LEVEL SECURITY", "ALTER TABLE ten_role NO FORCE ROW LEVEL SECURITY",
    "DROP POLICY tenant_isolation ON ten_role", "CREATE POLICY open ON ten_role USING (true)",
    "ALTER TABLE ten_role OWNER TO ngrc_app", "CREATE TABLE sneaky (id int)", "CREATE TEMP TABLE sneaky (id int)",
    "CREATE FUNCTION ngrc_current_tenant() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$",
    "CREATE OR REPLACE FUNCTION ngrc_current_tenant() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL::uuid $$",
    "CREATE VIEW leak AS SELECT * FROM ten_role", "CREATE SCHEMA evil", "CREATE EXTENSION IF NOT EXISTS pg_stat_statements",
    "ALTER ROLE ngrc_app BYPASSRLS", "ALTER ROLE ngrc_app SUPERUSER", "CREATE ROLE evil SUPERUSER",
    "DROP TABLE ten_role", "TRUNCATE ten_role", "ALTER TABLE ten_role DISABLE TRIGGER USER",
])
def test_ddl_and_privilege_changes_are_denied(stmt, tenant_a):
    for role in ("ngrc_app", "ngrc_auth", "ngrc_ops"):
        with _app(tenant_a.id, role) as c, pytest.raises(psycopg.errors.Error):
            c.execute(stmt)


def test_a_non_owner_cannot_grant_itself_or_public_more_access(tenant_a):
    """GRANT by a non-owner is a silent no-op WARNING in PostgreSQL (not an error), so assert the EFFECT."""
    for role in ("ngrc_app", "ngrc_auth", "ngrc_ops"):
        for stmt in ("GRANT ALL ON ten_role TO PUBLIC", "GRANT TRUNCATE ON ten_role TO ngrc_app"):
            with _app(tenant_a.id, role) as c:
                try:
                    c.execute(stmt)  # either a no-op WARNING or "permission denied": both are safe
                    c.commit()
                except psycopg.errors.Error:
                    c.rollback()
    with role_connect("ngrc_owner") as c:
        public = c.execute("SELECT count(*) FROM pg_class c, LATERAL aclexplode(c.relacl) a WHERE c.relname = 'ten_role' AND a.grantee = 0").fetchone()[0]
        trunc = c.execute("SELECT has_table_privilege('ngrc_app', 'ten_role', 'TRUNCATE')").fetchone()[0]
    assert public == 0 and trunc is False


@pytest.mark.parametrize("stmt", [
    "COPY (SELECT 1) TO PROGRAM 'id'", "COPY ten_role TO '/tmp/x'", "SELECT pg_read_file('/etc/passwd')", "SELECT * FROM pg_authid",
    "SELECT lo_import('/etc/passwd')", "SELECT pg_ls_dir('.')", "SELECT * FROM pg_shadow",
    "SELECT pg_reload_conf()", "CREATE EXTENSION dblink", "ALTER SYSTEM SET log_statement = 'all'", "DO $$ BEGIN PERFORM 1; END $$ LANGUAGE plpgsql; SELECT 1/0",
])
def test_server_side_file_program_and_catalogue_secrets_are_unreachable(stmt, tenant_a):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.Error):
        c.execute(stmt)


def test_runtime_roles_cannot_terminate_other_sessions(tenant_a):
    with role_connect("ngrc_owner") as other, _app(tenant_a.id) as c:
        pid = other.execute("SELECT pg_backend_pid()").fetchone()[0]
        with pytest.raises(psycopg.errors.Error):
            c.execute("SELECT pg_terminate_backend(%s)", [pid])
        c.rollback()
        with pytest.raises(psycopg.errors.Error):
            c.execute("SELECT pg_cancel_backend(%s)", [pid])


def test_definer_functions_enforce_the_callers_own_tenant(tenant_a, tenant_b):
    role_b = tenant_b.role_id("member")
    with _app(tenant_a.id) as c:
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(uuid.uuid4())])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # inviting INTO tenant B while bound to A
            c.execute("SELECT idn_create_invitation(%s::uuid,'x@example.test',%s::uuid,'member',NULL,%s,now() + interval '1 day')",
                      [str(tenant_b.id), str(role_b), uuid.uuid4().hex])
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):  # B's role under A's tenant
        c.execute("SELECT idn_create_invitation(%s::uuid,'x@example.test',%s::uuid,'member',NULL,%s,now() + interval '1 day')",
                  [str(tenant_a.id), str(role_b), uuid.uuid4().hex])
    with _app(tenant_a.id) as c:  # only A's own (provisioning-time Owner) invitation is visible - never B's
        assert [r[0] for r in c.execute("SELECT email FROM idn_list_invitations()").fetchall()] == [f"owner@{tenant_a.slug}.example"]
        assert c.execute("SELECT count(*) FROM plt_list_grants_for_tenant()").fetchone()[0] == 0
    with _app() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):  # no tenant context at all
        c.execute("SELECT count(*) FROM idn_list_invitations()")


def test_audit_append_binds_the_events_to_the_callers_own_tenant(tenant_a, tenant_b):
    sql = ("SELECT audit.append_tenant_event(%s::uuid,'user',NULL,NULL,'tenant.role.created',NULL,NULL,'success',NULL,NULL,NULL,NULL,NULL,"
           "'{}'::jsonb,'C')")
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute(sql, [str(tenant_b.id)])
    with _app(tenant_a.id) as c:
        assert c.execute(sql, [str(tenant_a.id)]).fetchone()[0] >= 1


def test_every_security_definer_function_pins_search_path_and_is_not_public():
    """Search-path hijack and PUBLIC-EXECUTE audit over the real catalogue."""
    with role_connect("ngrc_owner") as c:
        fns = c.execute(
            "SELECT n.nspname || '.' || p.proname, p.proconfig, coalesce(pg_get_userbyid(p.proowner), ''), "
            "has_function_privilege('public', p.oid, 'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE p.prosecdef AND n.nspname IN ('public', 'audit')").fetchall()
    assert len(fns) >= 10, "expected the reviewed SECURITY DEFINER functions"
    for name, config, _owner, public_exec in fns:
        assert config and any(x.startswith("search_path=") for x in config), f"{name}: search_path is not pinned"
        assert any("pg_catalog" in x for x in config if x.startswith("search_path=")), f"{name}: pg_catalog must come first"
        assert not public_exec, f"{name}: EXECUTE is granted to PUBLIC"


def test_a_hijacked_search_path_cannot_change_definer_behaviour(tenant_a):
    """A hostile session creates nothing (no CREATE), and even a changed search_path does not alter pinned definer functions."""
    with _app(tenant_a.id) as c:
        c.execute("SET search_path = pg_temp, public")
        assert [r[0] for r in c.execute("SELECT email FROM idn_list_invitations()").fetchall()] == [f"owner@{tenant_a.slug}.example"]
        c.commit()
    with _app(tenant_a.id) as c:
        c.execute("SET search_path = pg_temp, public")
        with pytest.raises(psycopg.errors.Error):
            c.execute("CREATE TEMP TABLE ten_role (id int)")


def test_runtime_roles_cannot_read_other_roles_secrets_via_settings():
    for role in ("ngrc_app", "ngrc_auth", "ngrc_ops"):
        with role_connect(role) as c:
            assert c.execute("SELECT current_setting('is_superuser')").fetchone()[0] == "off"
            assert c.execute("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()[0] is False
            with pytest.raises(psycopg.errors.Error):
                c.execute("SELECT rolpassword FROM pg_authid WHERE rolname = 'ngrc_owner'")


def test_connection_and_statement_limits_are_applied_to_runtime_roles():
    with role_connect("ngrc_owner") as c:
        rows = dict(c.execute("SELECT r.rolname, array_to_string(s.setconfig, ',') FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole "
                              "WHERE r.rolname IN ('ngrc_app','ngrc_auth','ngrc_ops')").fetchall())
    for role in ("ngrc_app", "ngrc_auth", "ngrc_ops"):
        assert "statement_timeout=30s" in rows[role] and "row_security=on" in rows[role], role


def test_unrelated_account_cannot_be_enumerated_through_the_profile_projection(tenant_a):
    victim = make_account()
    with _app(tenant_a.id) as c:
        assert c.execute("SELECT count(*) FROM idn_account WHERE id = %s", [str(victim.id)]).fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM idn_account WHERE email = %s", [victim.email]).fetchone()[0] == 0
