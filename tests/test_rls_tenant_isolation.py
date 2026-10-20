"""D-P0-003 testing requirements: PostgreSQL RLS tenant isolation, exercised as the real `ngrc_app` role, bypassing the ORM."""
import uuid

import psycopg
import pytest
from django.db import connections, transaction

from ngrc.core.context import current_tenant_id, tenant_context
from ngrc.core.errors import InvalidTenantContext, TenantContextMissing, TenantContextSwitch
from ngrc.tenancy.models import TenantRole

from .conftest import add_member, make_account, role_connect

pytestmark = pytest.mark.security


def _app(tenant_id):
    """psycopg connection as ngrc_app bound to `tenant_id` for the open transaction (None => no context)."""
    conn = role_connect("ngrc_app")
    if tenant_id is not None:
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_id)])
    return conn


def test_runtime_roles_have_no_dangerous_attributes():
    with role_connect("ngrc_owner") as c:
        rows = c.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication FROM pg_roles "
            "WHERE rolname IN ('ngrc_app','ngrc_auth','ngrc_ops','ngrc_audit_reader_platform','ngrc_audit_sealer',"
            "'ngrc_audit_verifier','ngrc_audit_owner','ngrc_owner')").fetchall()
    assert len(rows) == 8
    for name, sup, bypass, crole, cdb, repl in rows:
        assert not (sup or bypass or crole or cdb or repl), f"{name} has a dangerous attribute"


def test_runtime_roles_own_nothing():
    with role_connect("ngrc_owner") as c:
        owned = c.execute(
            "SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind = 'r' AND pg_get_userbyid(c.relowner) <> 'ngrc_owner'").fetchall()
    assert owned == []


def test_cross_tenant_read_denied(tenant_a, tenant_b):
    with _app(tenant_a.id) as c:
        ids = {r[0] for r in c.execute("SELECT tenant_id FROM ten_role").fetchall()}
    assert ids == {tenant_a.id}


def test_cross_tenant_update_and_delete_affect_zero_rows(tenant_a, tenant_b):
    with _app(tenant_a.id) as c:
        cur = c.execute("UPDATE ten_role SET name = 'hijacked' WHERE tenant_id = %s", [str(tenant_b.id)])
        assert cur.rowcount == 0
        cur = c.execute("DELETE FROM ten_role WHERE tenant_id = %s", [str(tenant_b.id)])
        assert cur.rowcount == 0


def test_cross_tenant_insert_denied(tenant_a, tenant_b):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("INSERT INTO ten_role (id, tenant_id, key, name, permissions, is_system, created_at) "
                  "VALUES (%s,%s,'x-role','X','[]',false,now())", [str(uuid.uuid4()), str(tenant_b.id)])


def test_no_context_reads_nothing_and_writes_fail(tenant_a):
    with _app(None) as c:
        assert c.execute("SELECT count(*) FROM ten_role").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM plt_tenant").fetchone()[0] == 0
    with _app(None) as c, pytest.raises(psycopg.errors.Error):
        c.execute("INSERT INTO ten_role (id, key, name, permissions, is_system, created_at) "
                  "VALUES (%s,'x-role','X','[]',false,now())", [str(uuid.uuid4())])


def test_malformed_context_fails_closed():
    with role_connect("ngrc_app") as c:
        c.execute("SELECT set_config('app.tenant_id', 'not-a-uuid', true)")
        with pytest.raises(psycopg.errors.InvalidTextRepresentation):
            c.execute("SELECT count(*) FROM ten_role")


def test_own_tenant_row_only_in_registry(tenant_a, tenant_b):
    with _app(tenant_a.id) as c:
        assert [r[0] for r in c.execute("SELECT id FROM plt_tenant").fetchall()] == [tenant_a.id]


def test_tenant_id_is_immutable(tenant_a, tenant_b):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE ten_role SET tenant_id = %s WHERE tenant_id = %s", [str(tenant_b.id), str(tenant_a.id)])


def test_composite_fk_rejects_cross_tenant_parent(tenant_a, tenant_b):
    acct = make_account()
    role_b = tenant_b.role_id("member")
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.ForeignKeyViolation):
        c.execute("INSERT INTO ten_membership (id, tenant_id, principal_id, role_id, kind, status, created_at) "
                  "VALUES (%s,%s,%s,%s,'member','active',now())",
                  [str(uuid.uuid4()), str(tenant_a.id), str(acct.id), str(role_b)])


def test_unique_constraints_are_tenant_scoped(tenant_a, tenant_b):
    """Both tenants own a role keyed 'member' (system role) - uniqueness is per tenant, not global."""
    assert tenant_a.role_id("member") != tenant_b.role_id("member")


def test_tenant_roles_cannot_carry_platform_permissions(tenant_a):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute("INSERT INTO ten_role (id, tenant_id, key, name, permissions, is_system, created_at) "
                  "VALUES (%s,%s,'sneaky','S','[\"platform.tenants.provision\"]',false,now())",
                  [str(uuid.uuid4()), str(tenant_a.id)])


def test_system_roles_immutable_for_tenant_plane(tenant_a):
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE ten_role SET permissions = '[\"audit.export\"]' WHERE key = 'member'")
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("DELETE FROM ten_role WHERE key = 'member'")
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("INSERT INTO ten_role (id, tenant_id, key, name, permissions, is_system, created_at) "
                  "VALUES (%s,%s,'owner2','O','[]',true,now())", [str(uuid.uuid4()), str(tenant_a.id)])


def test_last_owner_cannot_be_removed(tenant_a):
    acct = make_account()
    mid = add_member(tenant_a, acct, "owner")
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute("DELETE FROM ten_membership WHERE id = %s", [str(mid)])
    with _app(tenant_a.id) as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute("UPDATE ten_membership SET status = 'suspended' WHERE id = %s", [str(mid)])
    # a second owner makes removal of the first legal
    add_member(tenant_a, make_account(), "owner")
    with _app(tenant_a.id) as c:
        assert c.execute("DELETE FROM ten_membership WHERE id = %s", [str(mid)]).rowcount == 1


# --------------------------------------------------------------------------------------------- Django-layer context handling
def test_context_cannot_be_switched_inside_open_context(tenant_a, tenant_b):
    with tenant_context(tenant_a.id):
        with pytest.raises(TenantContextSwitch), tenant_context(tenant_b.id):
            pass
        with tenant_context(tenant_a.id):  # same tenant: allowed (savepoint)
            assert current_tenant_id() == tenant_a.id


def test_invalid_tenant_identifier_rejected():
    with pytest.raises(InvalidTenantContext), tenant_context("'; DROP TABLE ten_role; --"):
        pass


def test_context_does_not_leak_across_transactions(tenant_a):
    """Pooling test: same physical connection, next transaction sees no tenant (is_local = true)."""
    with tenant_context(tenant_a.id), connections["default"].cursor() as cur:
        cur.execute("SELECT current_setting('app.tenant_id', true)")
        assert cur.fetchone()[0] == str(tenant_a.id)
    assert current_tenant_id() is None
    with transaction.atomic(), connections["default"].cursor() as cur:
        cur.execute("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
        assert cur.fetchone()[0] is None
        cur.execute("SELECT count(*) FROM ten_role")
        assert cur.fetchone()[0] == 0


def test_orm_guard_requires_context(tenant_a):
    with pytest.raises(TenantContextMissing):
        list(TenantRole.objects.all())
    with pytest.raises(TenantContextMissing):
        TenantRole(key="x-role", name="X", permissions=[]).save()
    with tenant_context(tenant_a.id):
        assert {r.key for r in TenantRole.objects.all()} == {"owner", "admin", "member"}
        r = TenantRole(key="auditor-x", name="Auditor", permissions=["tenant.view"])
        r.save()
        assert r.tenant_id == tenant_a.id


def test_orm_cannot_see_other_tenants_rows(tenant_a, tenant_b):
    with tenant_context(tenant_a.id):
        assert not TenantRole.objects.filter(tenant_id=tenant_b.id).exists()
