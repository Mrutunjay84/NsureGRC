"""P2-4 / H-01 regression: the support-grant guard TRIGGER (migration control_plane/0004) is as strict as the application.

Why this matters for audit integrity: `audit.append_tenant_event` accepts operator `support.action` events only while the referenced
grant is `active` and `expires_at > now()`. If a database-level actor could extend `expires_at` (or plant approvers / rewrite times)
without a state transition, the tenant audit stream would keep accepting operator actions after the approved window.

Every negative case asserts the trigger's OWN message (not just "some error"), and is paired with a positive control so a test
cannot pass because the setup is broken. Direct SQL runs as the real `ngrc_ops` / `ngrc_owner` roles.
"""
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from psycopg.types.json import Jsonb

from .conftest import role_connect
from .test_support_access import activate_and_start, approve, consented_grant, env, request_grant  # noqa: F401  (env is a fixture)

pytestmark = pytest.mark.security


# ------------------------------------------------------------------------------------------------ helpers
def run(role, sql, params=()):
    with role_connect(role) as c:
        cur = c.execute(sql, params)
        rows = cur.fetchall() if cur.description else None
        c.commit()
        return rows


def refused(role, sql, params, fragment):
    """The statement must fail with OUR trigger's message (guards against passing on an unrelated privilege error)."""
    with role_connect(role) as c, pytest.raises(psycopg.errors.Error) as exc:
        c.execute(sql, params)
    assert fragment in exc.value.diag.message_primary, exc.value.diag.message_primary


def grant_row(gid):
    return run("ngrc_ops", "SELECT state, approver_id, second_approver_id, approved_at, activated_at, expires_at, ended_at, ended_by_type "
                           "FROM plt_support_access_grant WHERE id = %s", [gid])[0]


def insert_grant(tenant_id, requester_id, **over):
    row = {"id": uuid.uuid4(), "subject_tenant_id": tenant_id, "requester_id": requester_id, "ticket_ref": "T-1", "reason": "r",
           "profile": "diagnostic_metadata", "scope": Jsonb([]), "duration_minutes": 30, "break_glass": False, "state": "requested",
           "restricted_class_consent": False, "ended_by_type": "", "created_at": datetime.now(UTC)} | over
    cols = ", ".join(row)
    with role_connect("ngrc_ops") as c:
        c.execute(f"INSERT INTO plt_support_access_grant ({cols}) VALUES ({', '.join(['%s'] * len(row))})", list(row.values()))
        c.commit()
    return row["id"]


def append_support_action(tenant_id, actor_id, grant_id):
    return run("ngrc_ops", "SELECT audit.append_tenant_event(%s::uuid,'operator',%s::uuid,%s::uuid,'support.action',NULL,NULL,'success',"
                           "NULL,NULL,NULL,NULL,NULL,'{}'::jsonb,'C')", [str(tenant_id), str(actor_id), str(grant_id)])[0][0]


@pytest.fixture
def active(env):  # noqa: F811
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    return env, gid


# ------------------------------------------------------------------------------------------------ H-01: who may request
@pytest.mark.parametrize("roles", [("platform_admin",), ("platform_security",), ("platform_curator",), ("platform_admin", "platform_security")])
def test_only_platform_support_can_be_the_requester_even_by_direct_insert(roles, tenant_a, make_operator):
    op = make_operator(*roles)
    with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.Error) as exc:
        c.execute("INSERT INTO plt_support_access_grant (id, subject_tenant_id, requester_id, ticket_ref, reason, profile, scope, duration_minutes,"
                  " break_glass, state, restricted_class_consent, ended_by_type, created_at) VALUES (%s,%s,%s,'T','r','diagnostic_metadata',"
                  "'[]'::jsonb,30,false,'requested',false,'',now())", [uuid.uuid4(), tenant_a.id, op.id])
    assert "requester must be an active Platform Support operator" in exc.value.diag.message_primary


def test_a_disabled_support_operator_cannot_open_a_request_and_the_positive_control_works(tenant_a, make_operator):
    good = make_operator("platform_support")
    assert insert_grant(tenant_a.id, good.id)  # control: the insert helper and trigger accept a legitimate requester
    run("ngrc_ops", "UPDATE plt_operator_account SET status = 'disabled' WHERE id = %s", [good.id])
    with pytest.raises(psycopg.errors.Error) as exc:
        insert_grant(tenant_a.id, good.id)
    assert "active Platform Support" in exc.value.diag.message_primary


@pytest.mark.parametrize("over,fragment", [
    ({"approved_at": datetime(2020, 1, 1, tzinfo=UTC)}, "must be empty on insert"),
    ({"ended_at": datetime(2020, 1, 1, tzinfo=UTC)}, "must be empty on insert"),
    ({"ended_by_type": "tenant"}, "must be empty on insert"),
    ({"consented_at": datetime(2020, 1, 1, tzinfo=UTC)}, "must be empty on insert"),
    ({"scope": Jsonb({"a": 1})}, "scope must be a list"),
    ({"scope": Jsonb(["billing"])}, "scope must be a list"),  # metadata-only profile carries no scope
])
def test_insert_cannot_preload_decision_fields_or_an_inconsistent_scope(over, fragment, tenant_a, make_operator):
    sup = make_operator("platform_support")
    with pytest.raises(psycopg.errors.Error) as exc:
        insert_grant(tenant_a.id, sup.id, **over)
    assert fragment in exc.value.diag.message_primary
    assert insert_grant(tenant_a.id, sup.id, profile="read_limited", scope=Jsonb(["billing"]))  # control: a scoped profile may carry scope


# ------------------------------------------------------------------------------------------------ same-state tampering (the real hole)
@pytest.mark.parametrize("sql,fragment", [
    ("UPDATE plt_support_access_grant SET expires_at = expires_at + interval '1 day' WHERE id = %s", "expiry can only be shortened"),
    ("UPDATE plt_support_access_grant SET expires_at = NULL WHERE id = %s", "expiry can only be shortened"),
    ("UPDATE plt_support_access_grant SET activated_at = activated_at + interval '1 hour' WHERE id = %s", "activation time cannot be changed"),
    ("UPDATE plt_support_access_grant SET approved_at = now() WHERE id = %s", "approval time cannot be changed"),
    ("UPDATE plt_support_access_grant SET ended_at = now() WHERE id = %s", "end fields change only when the grant ends"),
    ("UPDATE plt_support_access_grant SET ended_by_type = 'tenant' WHERE id = %s", "end fields change only when the grant ends"),
    ("UPDATE plt_support_access_grant SET approver_id = requester_id WHERE id = %s", "approver cannot be changed"),
    ("UPDATE plt_support_access_grant SET second_approver_id = requester_id WHERE id = %s", "second approver is recorded only"),
])
def test_an_active_grant_cannot_be_widened_or_rewritten_without_a_state_transition(active, sql, fragment):
    e, gid = active
    before = grant_row(gid)
    refused("ngrc_ops", sql, [gid], fragment)
    assert grant_row(gid) == before


def test_expiry_may_be_cut_short_but_never_extended_and_audit_follows_the_real_expiry(active):
    """The audit-integrity property: operator actions are accepted into the tenant audit stream only inside the approved window,
    and no database path can reopen the window."""
    e, gid = active
    before = grant_row(gid)
    assert append_support_action(e.tenant.id, e.sup.account.id, gid) >= 1  # control: inside the window the event is accepted
    # an extension attempt is refused ...
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET expires_at = expires_at + interval '8 hours' WHERE id = %s", [gid],
            "expiry can only be shortened")
    assert grant_row(gid)[5] == before[5]
    # ... cutting it short is the one allowed same-state write (early termination)
    run("ngrc_ops", "UPDATE plt_support_access_grant SET expires_at = now() - interval '1 minute' WHERE id = %s", [gid])
    # the window is closed: the audit function refuses the event
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
        append_support_action(e.tenant.id, e.sup.account.id, gid)
    assert "no valid support grant" in exc.value.diag.message_primary
    # and the closed window cannot be reopened by any route
    for sql in ("UPDATE plt_support_access_grant SET expires_at = now() + interval '1 hour' WHERE id = %s",
                "UPDATE plt_support_access_grant SET expires_at = now() + interval '1 hour', activated_at = now() WHERE id = %s",
                "UPDATE plt_support_access_grant SET state = 'active', expires_at = now() + interval '1 hour' WHERE id = %s"):
        with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.Error):
            c.execute(sql, [gid])
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        append_support_action(e.tenant.id, e.sup.account.id, gid)


def test_state_transitions_cannot_smuggle_changes_to_other_columns(active):
    """Ending a grant must not also rewrite the activation window or approvers in the same statement."""
    e, gid = active
    before = grant_row(gid)
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET state = 'revoked', ended_at = now(), ended_by_type = 'operator', "
                        "expires_at = expires_at + interval '1 day' WHERE id = %s", [gid], "expiry can only be shortened")
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET state = 'revoked', ended_at = now(), ended_by_type = 'operator', "
                        "approved_at = now() WHERE id = %s", [gid], "approval time cannot be changed")
    assert grant_row(gid) == before
    run("ngrc_ops", "UPDATE plt_support_access_grant SET state = 'revoked', ended_at = now(), ended_by_type = 'operator' WHERE id = %s", [gid])
    assert grant_row(gid)[0] == "revoked"  # control: a clean end works


# ------------------------------------------------------------------------------------------------ planting approvers
def test_an_approver_cannot_be_planted_without_the_approval_transition(env):  # noqa: F811
    gid = request_grant(env.sup, env.tenant).json()["id"]  # ordinary grant, state requested
    before = grant_row(gid)
    sec = env.sec.account.id
    for sql in ("UPDATE plt_support_access_grant SET approver_id = %s WHERE id = %s",
                "UPDATE plt_support_access_grant SET approver_id = %s, approved_at = now() WHERE id = %s"):
        refused("ngrc_ops", sql, [sec, gid], "approval fields change only when the request is approved")
    assert grant_row(gid) == before


def test_break_glass_first_approval_is_validated_in_full(env):  # noqa: F811
    bg = request_grant(env.sup, env.tenant, break_glass=True, duration_minutes=60, ticket_ref="INC-1").json()["id"]
    upd = "UPDATE plt_support_access_grant SET approver_id = %s, approved_at = now() WHERE id = %s"
    refused("ngrc_ops", upd, [env.adm.account.id, bg], "approver must be an active Platform Security operator")  # wrong role
    refused("ngrc_ops", upd, [env.sup.account.id, bg], "requester cannot approve own request")  # the requester
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET approver_id = %s WHERE id = %s", [env.sec.account.id, bg], "approval incomplete")
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET approver_id = %s, approved_at = now(), second_approver_id = %s WHERE id = %s",
            [env.sec.account.id, env.adm.account.id, bg], "second approver is recorded only")  # both seats in one step, no transition
    run("ngrc_ops", "UPDATE plt_operator_account SET status = 'disabled' WHERE id = %s", [env.sec.account.id])
    refused("ngrc_ops", upd, [env.sec.account.id, bg], "approver must be an active Platform Security operator")  # disabled security operator
    run("ngrc_ops", "UPDATE plt_operator_account SET status = 'active' WHERE id = %s", [env.sec.account.id])
    run("ngrc_ops", upd, [env.sec.account.id, bg])  # control: a genuine Platform Security approver is accepted
    assert grant_row(bg)[1] == env.sec.account.id and grant_row(bg)[0] == "requested"


def test_a_requester_who_is_also_security_cannot_be_recorded_as_their_own_approver(tenant_a, make_operator):
    both = make_operator("platform_support", "platform_security")
    gid = insert_grant(tenant_a.id, both.id, break_glass=True, duration_minutes=60)
    refused("ngrc_ops", "UPDATE plt_support_access_grant SET approver_id = %s, approved_at = now() WHERE id = %s", [both.id, gid],
            "requester cannot approve own request")


# ------------------------------------------------------------------------------------------------ consent & activation
def test_consent_columns_cannot_be_written_outside_the_consent_transition_even_by_the_owner_role(env):  # noqa: F811
    gid = request_grant(env.sup, env.tenant).json()["id"]
    refused("ngrc_owner", "UPDATE plt_support_access_grant SET consent_user_id = gen_random_uuid(), consented_at = now() WHERE id = %s",
            [gid], "tenant consent can only be recorded by the tenant")
    approve(env.sec, gid)
    refused("ngrc_owner", "UPDATE plt_support_access_grant SET restricted_class_consent = true WHERE id = %s", [gid],
            "tenant consent can only be recorded by the tenant")


def test_activation_requires_the_requester_to_still_hold_platform_support(env):  # noqa: F811
    activate = ("UPDATE plt_support_access_grant SET state = 'active', activated_at = now(), "
                "expires_at = now() + interval '30 minutes' WHERE id = %s")
    ok = consented_grant(env)
    run("ngrc_ops", activate, [ok])  # control: legitimate activation through the same SQL
    assert grant_row(ok)[0] == "active"
    other = consented_grant(env)
    run("ngrc_ops", "DELETE FROM plt_operator_role WHERE operator_id = %s AND role = 'platform_support'", [env.sup.account.id])
    refused("ngrc_ops", activate, [other], "requester no longer holds Platform Support")
    assert grant_row(other)[0] == "tenant_consented"
