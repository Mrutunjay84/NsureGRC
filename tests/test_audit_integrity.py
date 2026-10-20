"""D-P0-006 testing requirements: append-only enforcement, hash chain, signed checkpoints, tamper detection, stream isolation.

Tampering is simulated by an attacker who OWNS the audit schema (worst case short of superuser): they disable RLS and the
guard triggers inside one transaction, alter data, and put the protections back. The independent Python verifier must notice.
"""
import json
import uuid
from contextlib import contextmanager

import psycopg
import pytest
from django.db import connections, transaction

from ngrc.audit import sealer, service, verifier
from ngrc.audit.actions import ACTIONS
from ngrc.audit.signer import get_signer
from ngrc.core.context import tenant_context
from ngrc.core.errors import AuditWriteFailed
from ngrc.tenancy.models import TenantRole

from .conftest import role_connect

pytestmark = pytest.mark.security

TENANT_TABLES = ("audit.tenant_event", "audit.platform_event", "audit.chain_head", "audit.checkpoint",
                 "audit.verification_run", "audit.action_registry")


def _emit(tenant, n=3):
    with tenant_context(tenant.id):
        for i in range(n):
            service.emit_tenant("default", "tenant.role.created", tenant.id, object_type="role", object_id=f"r{i}",
                                details={"role_key": f"k{i}", "permissions": 1})


def _keys():
    s = get_signer()
    return {s.key_id: s.public_key_raw()}



def _seed_every_audit_table(tenant):
    from ngrc.core import clock

    _emit(tenant, 1)
    service.emit_platform("auth", "auth.logout", actor_type="user")
    sealer.seal_all()
    verifier.record_run(verifier.verify_stream(str(tenant.id), _keys()), clock.now())


@contextmanager
def attacker(table: str):
    """Audit-schema owner with protections lifted for `table`, restored before COMMIT."""
    conn = role_connect("ngrc_owner")
    try:
        conn.execute("SET LOCAL ROLE ngrc_audit_owner")
        conn.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        yield conn
        conn.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")
        conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------------------------- append-only enforcement
@pytest.mark.parametrize("role", ["ngrc_app", "ngrc_auth", "ngrc_ops"])
@pytest.mark.parametrize("table", TENANT_TABLES)
def test_runtime_roles_cannot_mutate_audit_tables(role, table):
    for stmt in (f"UPDATE {table} SET seq = seq", f"DELETE FROM {table}", f"TRUNCATE {table}",
                 f"INSERT INTO {table} SELECT * FROM {table}"):
        with role_connect(role) as c, pytest.raises(psycopg.errors.Error):
            c.execute(stmt)


@pytest.mark.parametrize("table", ["audit.tenant_event", "audit.platform_event", "audit.checkpoint", "audit.verification_run",
                                   "audit.action_registry"])
def test_triggers_block_even_the_schema_owner(table, tenant_a):
    """Defence in depth: with every GRANT ignored (owner role), the triggers still reject UPDATE/DELETE/TRUNCATE."""
    _seed_every_audit_table(tenant_a)  # row-level triggers only fire when there is a row to touch
    for stmt in (f"UPDATE {table} SET {'action' if table.endswith(('event', 'registry')) else 'stream_key'} = 'x'",
                 f"DELETE FROM {table}", f"TRUNCATE {table}"):
        conn = role_connect("ngrc_owner")
        try:
            conn.execute("SET LOCAL ROLE ngrc_audit_owner")
            # RLS would hide every row from the owner (no policy) so a row trigger would never be reached: lift it for the probe
            conn.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            conn.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
            # TRUNCATE of an FK-referenced table is refused by PostgreSQL itself before the trigger runs - also acceptable
            with pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.FeatureNotSupported)):
                conn.execute(stmt)
        finally:
            conn.rollback()
            conn.close()


def test_chain_head_may_only_advance_by_one(tenant_a):
    _emit(tenant_a, 1)
    conn = role_connect("ngrc_owner")
    try:
        conn.execute("SET LOCAL ROLE ngrc_audit_owner")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE audit.chain_head SET seq = seq + 5 WHERE stream_key = %s", [str(tenant_a.id)])
        conn.rollback()
        conn.execute("SET LOCAL ROLE ngrc_audit_owner")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM audit.chain_head WHERE stream_key = %s", [str(tenant_a.id)])
    finally:
        conn.rollback()
        conn.close()


# --------------------------------------------------------------------------------------------- append function rules
def test_append_chains_events_and_verifier_accepts(tenant_a):
    _emit(tenant_a, 4)
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert res.ok, res.violations
    assert res.verified_through_seq == 4


def test_unregistered_action_rejected(tenant_a):
    with tenant_context(tenant_a.id), pytest.raises(AuditWriteFailed):
        service.emit_tenant("default", "tenant.nonexistent.action", tenant_a.id)
    with role_connect("ngrc_audit_verifier") as c:  # nothing was appended for the rejected event
        assert c.execute("SELECT count(*) FROM audit.tenant_event WHERE tenant_id = %s", [str(tenant_a.id)]).fetchone()[0] == 0


def test_secret_like_detail_keys_rejected(tenant_a):
    for key in ("password", "token", "secret", "free_text", "email"):
        with tenant_context(tenant_a.id), pytest.raises(AuditWriteFailed):
            service.emit_tenant("default", "tenant.role.created", tenant_a.id, details={key: "x"})


def test_detail_size_and_shape_limits(tenant_a):
    with tenant_context(tenant_a.id), pytest.raises(AuditWriteFailed):
        service.emit_tenant("default", "tenant.role.created", tenant_a.id, details={"role_key": "x" * 5000})


def test_writer_role_must_be_registered_for_action(tenant_a):
    """ngrc_app may not emit an auth-service action; ngrc_auth may not emit tenant administration events."""
    with tenant_context(tenant_a.id), pytest.raises(AuditWriteFailed):
        service.emit_tenant("default", "auth.session.tenant_selected", tenant_a.id)  # writers = [ngrc_auth]
    with pytest.raises(AuditWriteFailed):
        service.emit_tenant("auth", "tenant.role.created", tenant_a.id, details={"role_key": "x"})


def test_app_cannot_write_to_another_tenants_stream(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), pytest.raises(AuditWriteFailed):
        service.emit_tenant("default", "tenant.role.created", tenant_b.id, details={"role_key": "x"})


def test_ops_needs_a_support_grant_to_write_tenant_stream(tenant_a):
    with pytest.raises(AuditWriteFailed):
        service.emit_tenant("ops", "support.action", tenant_a.id, details={"operation": "x"})


def test_action_registry_matches_code(sql):
    rows = sql("audit_verifier", "SELECT action, category, severity, stream, allowed_detail_keys, writers "
                                 "FROM audit.action_registry")
    db = {r[0]: (r[1], r[2], r[3], tuple(r[4]), tuple(r[5])) for r in rows}
    code = {a.name: (a.category, a.severity, a.stream, a.detail_keys, a.writers) for a in ACTIONS}
    assert db == code, "audit.action_registry drifted from ngrc.audit.actions (add a NEW migration, never edit 0002)"


# --------------------------------------------------------------------------------------------- stream isolation
def test_tenant_cannot_read_other_tenants_audit(tenant_a, tenant_b):
    _emit(tenant_a, 2)
    _emit(tenant_b, 2)
    with tenant_context(tenant_a.id), connections["default"].cursor() as cur:
        cur.execute("SELECT DISTINCT tenant_id FROM audit.tenant_event")
        assert [r[0] for r in cur.fetchall()] == [tenant_a.id]
    with role_connect("ngrc_app") as c:  # no context at all
        assert c.execute("SELECT count(*) FROM audit.tenant_event").fetchone()[0] == 0


@pytest.mark.parametrize("role", ["ngrc_app", "ngrc_ops", "ngrc_auth"])
def test_platform_stream_unreadable_by_runtime_roles(role):
    with role_connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT * FROM audit.platform_event")


def test_platform_reader_can_read_platform_stream_only(tenant_a):
    service.emit_platform("auth", "auth.logout", actor_type="user")
    with role_connect("ngrc_audit_reader_platform") as c:
        assert c.execute("SELECT count(*) FROM audit.platform_event").fetchone()[0] >= 1
    with role_connect("ngrc_audit_reader_platform") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT * FROM audit.tenant_event")


# --------------------------------------------------------------------------------------------- tamper detection
def test_tampered_row_detected(tenant_a):
    _emit(tenant_a, 4)
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'forged' WHERE tenant_id = %s AND seq = 2", [str(tenant_a.id)])
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert not res.ok and any("does not match its hash at seq 2" in v for v in res.violations)


def test_deleted_row_detected(tenant_a):
    _emit(tenant_a, 4)
    with attacker("audit.tenant_event") as c:
        c.execute("DELETE FROM audit.tenant_event WHERE tenant_id = %s AND seq = 2", [str(tenant_a.id)])
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert not res.ok and any("seq 3" in v for v in res.violations)


def test_reordered_rows_detected(tenant_a):
    _emit(tenant_a, 3)
    with attacker("audit.tenant_event") as c:
        for src, dst in ((2, 1000), (3, 2), (1000, 3)):  # swap through a temporary value (unique (tenant_id, seq))
            c.execute("UPDATE audit.tenant_event SET seq = %s WHERE tenant_id = %s AND seq = %s", [dst, str(tenant_a.id), src])
    assert not verifier.verify_stream(str(tenant_a.id), _keys()).ok


def test_truncated_tail_detected(tenant_a):
    _emit(tenant_a, 3)
    with attacker("audit.tenant_event") as c:
        c.execute("DELETE FROM audit.tenant_event WHERE tenant_id = %s AND seq = 3", [str(tenant_a.id)])
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert not res.ok and any("chain head" in v for v in res.violations)


def test_signed_checkpoint_accepted_then_rewrite_after_checkpoint_detected(tenant_a):
    _emit(tenant_a, 3)
    sealed = sealer.seal_all()
    assert any(s["stream_key"] == str(tenant_a.id) and s["seq"] == 3 for s in sealed)
    assert verifier.verify_stream(str(tenant_a.id), _keys(), require_export=True).ok
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'rewritten' WHERE tenant_id = %s AND seq = 3", [str(tenant_a.id)])
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert not res.ok


def test_full_chain_recompute_rewrite_is_caught_by_checkpoint_and_export(tenant_a):
    """Attacker with DB-write access recomputes every later hash so the DB chain is internally consistent - the signed
    checkpoint (and the exported copy) still disagree."""
    _emit(tenant_a, 3)
    sealer.seal_all()
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'rewritten' WHERE tenant_id = %s AND seq = 2", [str(tenant_a.id)])
        rows = c.execute(
            "SELECT event_id, seq FROM audit.tenant_event WHERE tenant_id = %s ORDER BY seq", [str(tenant_a.id)]).fetchall()
        prev = c.execute("SELECT prev_hash FROM audit.tenant_event WHERE tenant_id = %s AND seq = 2", [str(tenant_a.id)]).fetchone()[0]
        for eid, seq in rows:
            if seq < 2:
                continue
            h = c.execute(
                "SELECT audit._event_hash(%s, seq, %s, event_id, occurred_at, tenant_id, actor_type, actor_id, on_behalf_of_grant,"
                " action, object_type, object_id, result, reason_code, source_ip, user_agent, session_ref, request_id,"
                " details, data_class, schema_version) FROM audit.tenant_event WHERE event_id = %s",
                [str(tenant_a.id), prev, eid]).fetchone()[0]
            c.execute("UPDATE audit.tenant_event SET prev_hash = %s, hash = %s WHERE event_id = %s", [prev, h, eid])
            prev = h
        c.execute("ALTER TABLE audit.chain_head DISABLE TRIGGER USER")
        c.execute("UPDATE audit.chain_head SET last_hash = %s WHERE stream_key = %s", [prev, str(tenant_a.id)])
        c.execute("ALTER TABLE audit.chain_head ENABLE TRIGGER USER")
    res = verifier.verify_stream(str(tenant_a.id), _keys(), require_export=True)
    assert not res.ok
    assert any("checkpoint" in v for v in res.violations), res.violations


def test_forged_checkpoint_signature_rejected(tenant_a):
    _emit(tenant_a, 2)
    key_id = get_signer().key_id
    with attacker("audit.checkpoint") as c:
        head = c.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [str(tenant_a.id)]).fetchone()
        c.execute("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature) "
                  "VALUES (%s,%s,%s,now(),%s,'ed25519',%s)", [str(tenant_a.id), head[0], head[1], key_id, b"\x00" * 64])
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    assert not res.ok and any("signature invalid" in v for v in res.violations)


def test_checkpoint_by_unknown_key_rejected(tenant_a):
    _emit(tenant_a, 2)
    with attacker("audit.checkpoint") as c:
        head = c.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [str(tenant_a.id)]).fetchone()
        c.execute("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature) "
                  "VALUES (%s,%s,%s,now(),'attacker-key','ed25519',%s)", [str(tenant_a.id), head[0], head[1], b"\x01" * 64])
    assert any("unknown key" in v for v in verifier.verify_stream(str(tenant_a.id), _keys()).violations)


def test_integrity_violation_is_recorded_and_alerted(tenant_a):
    from ngrc.core import clock

    _emit(tenant_a, 2)
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'x' WHERE tenant_id = %s AND seq = 1", [str(tenant_a.id)])
    started = clock.now()
    res = verifier.verify_stream(str(tenant_a.id), _keys())
    verifier.record_run(res, started)
    with connections["audit_verifier"].cursor() as cur:
        cur.execute("SELECT status FROM audit.verification_run WHERE stream_key = %s", [str(tenant_a.id)])
        assert cur.fetchone()[0] == "violation"
        cur.execute("SELECT count(*) FROM audit.platform_event WHERE action = 'audit.integrity_violation'")
        assert cur.fetchone()[0] >= 1


# --------------------------------------------------------------------------------------------- atomicity (C-4)
def test_denial_event_persists_after_request_rollback(tenant_a):
    actor = uuid.uuid4()
    with pytest.raises(RuntimeError), transaction.atomic(using="default"):
        service.emit_denied(permission="tenant.members.manage", route="/api/v1/tenant/members/", reason="missing_permission",
                            tenant_id=tenant_a.id, actor_id=actor)
        raise RuntimeError("request failed after the denial")
    with role_connect("ngrc_audit_verifier") as c:
        n = c.execute("SELECT count(*) FROM audit.tenant_event WHERE tenant_id = %s AND action = 'authz.denied' AND actor_id = %s",
                      [str(tenant_a.id), str(actor)]).fetchone()[0]
    assert n == 1


def test_business_transaction_fails_if_audit_append_fails(tenant_a):
    with pytest.raises(AuditWriteFailed), tenant_context(tenant_a.id), service.unit_of_work(tenant_a.id) as uow:
        TenantRole(key="atomic-role", name="A", permissions=[]).save()
        uow.record("tenant.role.created", details={"definitely_not_allowed": 1})
        uow.flush()
    with tenant_context(tenant_a.id):
        assert not TenantRole.objects.filter(key="atomic-role").exists()


def test_business_change_and_audit_commit_together(tenant_a):
    with tenant_context(tenant_a.id), service.unit_of_work(tenant_a.id) as uow:
        TenantRole(key="atomic-ok", name="A", permissions=[]).save()
        uow.record("tenant.role.created", details={"role_key": "atomic-ok", "permissions": 0})
        assert uow.flush() == 1
    with tenant_context(tenant_a.id):
        assert TenantRole.objects.filter(key="atomic-ok").exists()
    assert verifier.verify_stream(str(tenant_a.id), _keys()).ok


def test_sealer_checkpoints_are_signed_and_exported(tenant_a, tmp_path):
    _emit(tenant_a, 2)
    sealed = sealer.seal_all()
    mine = [s for s in sealed if s["stream_key"] == str(tenant_a.id)]
    assert mine and mine[0]["algorithm"] == "ed25519" and "NOT WORM" in mine[0]["sink"]
    from pathlib import Path

    from django.conf import settings

    lines = (Path(settings.AUDIT_CHECKPOINT_EXPORT_DIR) / "checkpoints.jsonl").read_text().splitlines()
    assert any(json.loads(line)["stream_key"] == str(tenant_a.id) for line in lines)


# --------------------------------------------------------------------------------------------- migration identity
def test_migration_identity_cannot_write_audit_without_set_role(tenant_a):
    """ngrc_owner may SET ROLE to the audit owner inside reviewed audit migrations, but must NOT inherit its privileges:
    otherwise a compromised migration credential could forge audit rows (found and fixed during Phase 1 testing)."""
    _emit(tenant_a, 1)
    with role_connect("ngrc_owner") as c:
        m = c.execute("SELECT m.inherit_option, m.set_option FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                      "JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'ngrc_owner' AND r.rolname = 'ngrc_audit_owner'"
                      ).fetchone()
    assert m == (False, True)
    for stmt in ("INSERT INTO audit.chain_head VALUES ('forged', 0, decode('00', 'hex'))",
                 "SELECT count(*) FROM audit.tenant_event",
                 "SELECT audit._event_hash('s', 1, decode('00', 'hex'), gen_random_uuid(), now(), NULL, 'user', NULL, NULL, 'auth.logout', "
                 "NULL, NULL, 'success', NULL, NULL, NULL, NULL, NULL, '{}', 'C', 1)"):
        with role_connect("ngrc_owner") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(stmt)
