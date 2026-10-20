"""F-ATH-015 - lost-factor recovery (D-P0-008 s7.4): admin-assisted reset by a DIFFERENT Owner/Admin with step-up, cooling-off (BASELINE 24 h) with a
cancel link, all other sessions revoked on completion, the sole Owner via Platform Security, and no path at all for platform support.
Time: the application clock is shiftable in tests, the database clock is not - "time passes" is simulated by moving the stored timestamps back as the
schema owner (the only role that could), which is itself part of what the trigger tests below try to forbid for every other role."""
import psycopg
import pytest
from django.conf import settings
from django.core import mail
from django.urls import Resolver404, resolve

from ngrc.authz import permissions as perm
from ngrc.iam.models import Account, RecoveryCode, RecoveryRequest, TotpFactor, WebAuthnCredential

from .conftest import TEST_PASSWORD, make_account, provision_tenant, role_connect
from .helpers import Api, Totp, audit_events, enroll_totp_and_login, last_mail_token

pytestmark = pytest.mark.security


class Team:
    pass


@pytest.fixture
def team(tenant_a, make_user):
    t = Team()
    t.tenant, t.owner, t.admin, t.member = tenant_a, make_user(tenant_a, "owner"), make_user(tenant_a, "admin"), make_user(tenant_a, "member")
    return t


def password_session(u):
    api = Api()
    r = api.post("/auth/login/", {"email": u.email, "password": u.password})
    assert r.status_code == 200 and r.json()["stage"] == "password_ok", r.content
    return api


def request_recovery(u, **body):
    api = password_session(u)
    return api, api.post("/auth/recovery/request/", body)


def approve_as(admin, rid, action="approve"):
    admin.stepup()
    return admin.api.post(f"/tenant/recovery/{rid}/{action}/", {})


def fast_forward(request_id, hours=25):
    """Simulate elapsed time for an APPROVED request: move approval and cooling-off back (schema-owner action, triggers lifted for the probe only)."""
    with role_connect("ngrc_owner") as c:
        c.execute("ALTER TABLE idn_recovery_request DISABLE TRIGGER USER")
        c.execute("UPDATE idn_recovery_request SET approved_at = approved_at - make_interval(hours => %s), "
                  "cooling_until = cooling_until - make_interval(hours => %s) WHERE id = %s", [hours, hours, request_id])
        c.execute("ALTER TABLE idn_recovery_request ENABLE TRIGGER USER")
        c.commit()


def state_of(rid):
    return RecoveryRequest.objects.using("auth").get(pk=rid).state


def ev(**kw):
    return audit_events(**kw)


# ------------------------------------------------------------------------------------------------ the full flow
def test_admin_assisted_recovery_end_to_end(team):
    m = team.member
    old_api = m.api
    mail.outbox.clear()
    sess, r = request_recovery(m)
    assert r.status_code == 201 and r.json()["kind"] == "admin_assisted"
    rid = r.json()["id"]
    cancel_token = last_mail_token(mail.outbox, m.email)
    notified = {addr for msg in mail.outbox for addr in msg.to}
    assert {team.owner.email, team.admin.email} <= notified and "cancel" in mail.outbox[0].body.lower()
    for stream in ({"platform": True}, {"tenant_id": team.tenant.id}):
        assert ev(action="auth.recovery.requested", actor_id=m.account.id, **stream)

    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 409          # nothing approved yet
    assert any(x["id"] == rid and x["state"] == "requested" for x in team.admin.api.get("/tenant/recovery/").json()["requests"])
    assert approve_as(team.admin, rid).status_code == 200
    assert ev(action="auth.recovery.approved", actor_id=team.admin.account.id, tenant_id=team.tenant.id)
    assert any(m.email in msg.to and "approved" in msg.subject.lower() for msg in mail.outbox)    # the real user is told
    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 409          # COOLING-OFF is running
    assert state_of(rid) == "approved"

    fast_forward(rid)
    done = sess.post("/auth/recovery/complete/", {"request_id": rid})
    assert done.status_code == 200 and done.json() == {"stage": "enroll_mfa"}
    assert TotpFactor.objects.using("auth").filter(account=m.account).count() == 0
    assert WebAuthnCredential.objects.using("auth").filter(account=m.account).count() == 0
    assert RecoveryCode.objects.using("auth").filter(account=m.account).count() == 0
    assert old_api.get("/auth/session/").status_code == 401                                        # every other session is gone
    assert state_of(rid) == "completed"
    # the completing session is now an ENROLMENT session: enrol a new factor, get fresh recovery codes
    b = sess.post("/auth/mfa/totp/enroll/begin/")
    assert b.status_code == 200
    fresh = Totp(b.json()["secret"])
    c = sess.post("/auth/mfa/totp/enroll/confirm/", {"code": fresh.code(int(__import__("time").time()) + m.clock.offset)})
    assert c.status_code == 200 and c.json()["stage"] == "active" and len(c.json()["recovery_codes"]) == 10
    assert ev(action="auth.recovery.completed", actor_id=m.account.id, platform=True)
    assert any(m.email in msg.to and "reset" in msg.subject.lower() for msg in mail.outbox)
    assert cancel_token and len(cancel_token) >= 40


def test_a_pending_password_session_is_required_to_ask_for_recovery(team, tenant_a):
    assert Api().post("/auth/recovery/request/", {}).status_code == 401
    assert team.member.api.post("/auth/recovery/request/", {}).status_code == 403          # a fully signed-in session does not need recovery
    assert Api().post("/auth/recovery/complete/", {"request_id": "00000000-0000-0000-0000-000000000000"}).status_code == 401
    assert team.member.api.post("/auth/recovery/complete/", {"request_id": "00000000-0000-0000-0000-000000000000"}).status_code == 403


def test_tenant_selection_rules_for_the_request(team, make_user):
    # an account with an enrolled factor but NO membership
    acct = make_account()
    _, totp, _ = enroll_totp_and_login(acct.email, TEST_PASSWORD, __import__("time").time().__int__())
    api = Api()
    assert api.post("/auth/login/", {"email": acct.email, "password": TEST_PASSWORD}).json()["stage"] == "password_ok"
    assert api.post("/auth/recovery/request/", {}).json() == {"error": "no_tenant"}
    other = provision_tenant()
    r = password_session(team.member).post("/auth/recovery/request/", {"tenant_id": str(other.id)})
    assert r.status_code == 403 and audit_events(platform=True, action="authz.denied", reason_code="not_a_member", actor_id=team.member.account.id)
    _ = totp


# ------------------------------------------------------------------------------------------------ who may approve
def test_nobody_can_approve_their_own_recovery(team):
    adm = team.admin
    _, r = request_recovery(adm)
    rid = r.json()["id"]
    assert r.json()["kind"] == "admin_assisted"                                                   # the Owner is a peer
    res = approve_as(adm, rid)
    assert res.status_code == 403 and state_of(rid) == "requested"
    assert audit_events(tenant_id=team.tenant.id, action="authz.denied", reason_code="self_approval", actor_id=adm.account.id)
    with role_connect("ngrc_app") as c:                                                           # and the database itself refuses (hostile ngrc_app)
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(team.tenant.id)])
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(adm.account.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="decide on their own recovery"):   # the FUNCTION layer
            c.execute("SELECT * FROM idn_recovery_tenant_decide(%s::uuid, 'approve')", [rid])
    with role_connect("ngrc_owner") as c, pytest.raises(psycopg.errors.InsufficientPrivilege, match="approve their own recovery"):   # the TRIGGER layer
        c.execute("UPDATE idn_recovery_request SET state = 'approved', approver_id = account_id, approver_realm = 'tenant', approved_at = now(), "
                  "cooling_until = now() + cooling_seconds * interval '1 second' WHERE id = %s", [rid])


def test_only_tenant_owners_and_admins_see_or_decide_and_a_fresh_step_up_is_required(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    plain = team.member
    assert plain.api.get("/tenant/recovery/").status_code == 403
    assert plain.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code == 403
    team.admin.clock.advance(minutes=11)                                                         # no recent step-up
    assert team.admin.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code in (401, 403)
    assert state_of(rid) == "requested"
    with role_connect("ngrc_app") as c:                                                           # a plain member principal, straight at the function
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(team.tenant.id)])
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(team.member.account.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="Owner or Administrator may see"):
            c.execute("SELECT * FROM idn_recovery_tenant_list()")
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(team.tenant.id)])
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(team.member.account.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="Owner or Administrator may decide"):
            c.execute("SELECT * FROM idn_recovery_tenant_decide(%s::uuid, 'approve')", [rid])


def test_another_tenants_admin_cannot_see_or_approve(team, make_user):
    other = provision_tenant()
    foreign_admin = make_user(other, "owner")
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    assert rid not in str(foreign_admin.api.get("/tenant/recovery/").json())
    foreign_admin.stepup()
    assert foreign_admin.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code == 404
    assert state_of(rid) == "requested"


def test_a_denied_request_ends_and_the_user_is_told(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    mail.outbox.clear()
    assert approve_as(team.owner, rid, "deny").status_code == 200
    assert state_of(rid) == "cancelled" and ev(action="auth.recovery.denied", actor_id=team.owner.account.id, platform=True)
    assert any(team.member.email in m.to for m in mail.outbox)
    assert approve_as(team.admin, rid).status_code == 409                                         # cannot approve a closed request


# ------------------------------------------------------------------------------------------------ cancel
def test_the_emailed_link_cancels_once_and_nothing_can_follow(team):
    mail.outbox.clear()
    _, r = request_recovery(team.member)
    rid, tok = r.json()["id"], last_mail_token(mail.outbox, team.member.email)
    assert Api().post("/auth/recovery/cancel/", {"token": tok}).json() == {"status": "cancelled"}
    assert state_of(rid) == "cancelled"
    assert Api().post("/auth/recovery/cancel/", {"token": tok}).status_code == 400              # single use
    assert approve_as(team.admin, rid).status_code == 409
    assert ev(action="auth.recovery.cancelled", actor_id=team.member.account.id, platform=True)


def test_cancelling_during_the_cooling_off_stops_the_completion(team):
    sess, r = request_recovery(team.member)
    rid = r.json()["id"]
    assert approve_as(team.admin, rid).status_code == 200
    stranger = password_session(team.owner)
    assert stranger.post(f"/auth/recovery/{rid}/cancel/").status_code == 404                     # not mine
    assert sess.post(f"/auth/recovery/{rid}/cancel/").status_code == 200                           # mine, from a (password-stage) session
    fast_forward(rid)
    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 409
    assert TotpFactor.objects.using("auth").filter(account=team.member.account, confirmed_at__isnull=False).count() == 1


def test_the_cancel_endpoint_is_throttled_and_does_not_reveal_anything(team):
    api = Api(ip="203.0.113.50")
    codes = {api.post("/auth/recovery/cancel/", {"token": f"{i:040d}"}).status_code for i in range(8)}
    assert codes == {400, 429}
    assert Api().post("/auth/recovery/cancel/", {"token": "x" * 129}).status_code == 400


# ------------------------------------------------------------------------------------------------ the database is the authority
def test_the_cooling_off_and_the_state_machine_hold_even_against_the_owner_role(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    approve_as(team.admin, rid)

    def owner(sql, *params):
        with role_connect("ngrc_owner") as c, pytest.raises(psycopg.errors.Error) as exc:
            c.execute(sql, [*params])
        return exc.value.diag.message_primary

    assert "write-once" in owner("UPDATE idn_recovery_request SET cooling_until = now() WHERE id = %s", rid)
    assert "cooling-off period has not elapsed" in owner("UPDATE idn_recovery_request SET state = 'completed', ended_at = now() WHERE id = %s", rid)
    assert "identity is immutable" in owner("UPDATE idn_recovery_request SET cooling_seconds = 3600, kind = 'last_owner' WHERE id = %s", rid)
    assert "never deleted" in owner("DELETE FROM idn_recovery_request WHERE id = %s", rid)
    assert "never deleted" in owner("TRUNCATE idn_recovery_request")
    assert "idn_recovery_cooling_floor" in owner("INSERT INTO idn_recovery_request (id, account_id, subject_tenant_id, kind, state, created_at, expires_at, cooling_seconds, "
                                     "cancel_token_hash) VALUES (gen_random_uuid(), %s, %s, 'admin_assisted', 'requested', now(), now() + interval '1 day', 60, repeat('a', 64))",
                                     team.owner.account.id, team.tenant.id)
    with role_connect("ngrc_auth") as c, pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
        c.execute("SELECT idn_recovery_complete(%s::uuid, %s::uuid)", [rid, str(team.member.account.id)])
    assert "recovery cannot complete before the cooling-off period has elapsed" in exc.value.diag.message_primary   # the FUNCTION layer
    assert state_of(rid) == "approved"


def test_no_runtime_role_can_write_or_read_the_request_table_directly(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    for role, sql, allowed in (
        ("ngrc_auth", "UPDATE idn_recovery_request SET state = 'approved' WHERE id = %s", False),
        ("ngrc_auth", "INSERT INTO idn_recovery_request (id) VALUES (gen_random_uuid())", False),
        ("ngrc_auth", "DELETE FROM idn_recovery_request WHERE id = %s", False),
        ("ngrc_auth", "SELECT state FROM idn_recovery_request WHERE id = %s", True),
        ("ngrc_app", "SELECT state FROM idn_recovery_request", False),
        ("ngrc_ops", "SELECT state FROM idn_recovery_request", False),
    ):
        with role_connect(role) as c:
            if allowed:
                c.execute(sql, [rid])
            else:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    c.execute(sql, [rid] if "%s" in sql else [])
    # a hostile ngrc_auth cannot call the tenant or platform decision functions, a hostile ngrc_app cannot call create/complete
    for role, sql in (("ngrc_auth", "SELECT * FROM idn_recovery_tenant_decide(gen_random_uuid(), 'approve')"),
                      ("ngrc_auth", "SELECT * FROM plt_recovery_platform_decide(gen_random_uuid(), gen_random_uuid(), 'approve')"),
                      ("ngrc_app", "SELECT idn_recovery_complete(gen_random_uuid(), gen_random_uuid())"),
                      ("ngrc_ops", "SELECT idn_recovery_complete(gen_random_uuid(), gen_random_uuid())")):
        with role_connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)


def test_only_one_request_is_open_and_requests_are_throttled(team):
    api = password_session(team.member)
    first = api.post("/auth/recovery/request/", {})
    assert first.status_code == 201
    assert api.post("/auth/recovery/request/", {}).status_code == 409 and first.json()["id"]
    statuses = []
    for _ in range(8):
        rid = api.get("/auth/recovery/status/").json()["request"]
        if rid and rid["state"] in {"requested", "approved"}:
            api.post(f"/auth/recovery/{rid['id']}/cancel/")
        statuses.append(api.post("/auth/recovery/request/", {}).status_code)
    assert 429 in statuses, statuses


def test_expired_requests_cannot_be_approved_and_are_replaced_by_a_new_one(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    with role_connect("ngrc_owner") as c:
        c.execute("ALTER TABLE idn_recovery_request DISABLE TRIGGER USER")
        c.execute("UPDATE idn_recovery_request SET created_at = created_at - interval '30 days', expires_at = now() - interval '1 minute' WHERE id = %s", [rid])
        c.execute("ALTER TABLE idn_recovery_request ENABLE TRIGGER USER")
        c.commit()
    assert approve_as(team.admin, rid).status_code == 409
    again = password_session(team.member).post("/auth/recovery/request/", {})
    assert again.status_code == 201 and state_of(rid) == "expired"


# ------------------------------------------------------------------------------------------------ the sole Owner and platform support
def test_a_sole_owner_needs_platform_security_and_the_same_cooling_off(login_operator, make_user):
    solo = provision_tenant()
    owner = make_user(solo, "owner")
    sess, r = request_recovery(owner)
    assert r.status_code == 201 and r.json()["kind"] == "last_owner"
    rid = r.json()["id"]
    owner.stepup()
    assert owner.api.get("/tenant/recovery/").json() == {"requests": []}                       # the tenant plane never sees last-owner requests
    assert state_of(rid) == "requested"
    with role_connect("ngrc_app") as c:                                                           # nor can any tenant principal decide it
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(solo.id)])
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(owner.account.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM idn_recovery_tenant_decide(%s::uuid, 'approve')", [rid])

    for roles in (("platform_support",), ("platform_admin",), ("platform_curator",)):          # support can NEVER reset MFA; nor can other roles
        op = login_operator(*roles)
        assert op.api.get("/recovery/").status_code == 403
        op.stepup()
        assert op.api.post(f"/recovery/{rid}/approve/begin/").status_code == 403
        assert op.api.post(f"/recovery/{rid}/deny/", {}).status_code == 403
    sup = login_operator("platform_support")
    with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.InsufficientPrivilege, match="Platform Security"):
        c.execute("SELECT * FROM plt_recovery_platform_decide(%s::uuid, %s::uuid, 'approve')", [rid, str(sup.account.id)])

    sec = login_operator("platform_security")
    listed = sec.api.get("/recovery/").json()["requests"]
    assert any(x["id"] == rid and x["email"] == owner.email for x in listed)
    sec.stepup()
    mail.outbox.clear()
    opts = sec.api.post(f"/recovery/{rid}/approve/begin/").json()
    assert sec.api.post(f"/recovery/{rid}/approve/", {"credential": sec.auth.assert_(opts)}).status_code == 200
    assert state_of(rid) == "approved" and any(owner.email in m.to for m in mail.outbox)
    assert ev(action="auth.recovery.approved", platform=True, actor_id=sec.account.id)
    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 409           # cooling-off applies to Platform Security too
    fast_forward(rid)
    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 200


def test_the_platform_approval_assertion_is_bound_to_that_one_request(login_operator, make_user):
    ra, rb = [], []
    for bucket in (ra, rb):
        t = provision_tenant()
        u = make_user(t, "owner")
        bucket.append(request_recovery(u)[1].json()["id"])
    sec = login_operator("platform_security")
    sec.stepup()
    opts_for_a = sec.api.post(f"/recovery/{ra[0]}/approve/begin/").json()
    cred = sec.auth.assert_(opts_for_a)
    assert sec.api.post(f"/recovery/{rb[0]}/approve/", {"credential": cred}).status_code == 401      # cannot be replayed on another request
    assert state_of(rb[0]) == "requested"
    assert sec.api.post(f"/recovery/{ra[0]}/approve/", {"credential": cred}).status_code == 401        # and the failed attempt burned the challenge


def test_no_support_session_route_can_touch_recovery(login_operator):
    for path in ("/ops/api/v1/support/tenant/recovery/", "/ops/api/v1/support/recovery/", "/ops/api/v1/support/tenant/users/x/reset-mfa/"):
        with pytest.raises(Resolver404):
            resolve(path)
    assert "platform.recovery.approve" not in perm.PLATFORM_ROLES["platform_support"]
    assert "platform.recovery.approve" in perm.PLATFORM_ROLES["platform_security"]
    assert not [p for p in perm.SUPPORT_PROFILE_PERMISSIONS.values() if any("recovery" in k for k in p)]


# ------------------------------------------------------------------------------------------------ hygiene
def test_neither_the_audit_trail_nor_the_database_holds_a_usable_cancel_token(team):
    mail.outbox.clear()
    _, r = request_recovery(team.member)
    rid, tok = r.json()["id"], last_mail_token(mail.outbox, team.member.email)
    stored = RecoveryRequest.objects.using("auth").get(pk=rid).cancel_token_hash
    assert stored != tok and len(stored) == 64 and tok not in stored
    for e in ev(action="auth.recovery.requested", platform=True) + ev(action="auth.recovery.requested", tenant_id=team.tenant.id):
        assert tok not in e["details"] and team.member.email not in e["details"] and set(__import__("json").loads(e["details"])) == {"kind"}
    assert Account.objects.using("auth").filter(pk=team.member.account.id).exists()
    assert settings.RECOVERY_COOLING_OFF_S >= 3600


def test_recovery_events_are_registered_and_stay_in_their_streams():
    from ngrc.audit.actions import BY_NAME

    for name in ("requested", "approved", "denied", "cancelled", "completed"):
        a = BY_NAME[f"auth.recovery.{name}"]
        assert a.stream == "both" and a.detail_keys[0] == "kind"


def test_the_trigger_rejects_forged_approvals_even_from_the_owner_role(team):
    """Defence in depth: the functions never produce these rows, so each rule is exercised by a forged UPDATE as the schema owner."""
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    base = ("UPDATE idn_recovery_request SET state = 'approved', approver_id = %s, approver_realm = %s, approved_at = now(), "
            "cooling_until = now() + {cool} WHERE id = %s")
    full = "cooling_seconds * interval '1 second'"

    def forged(sql, *params):
        with role_connect("ngrc_owner") as c, pytest.raises(psycopg.errors.Error) as exc:
            c.execute(sql, [*params])
        return exc.value.diag.message_primary

    approver = str(team.admin.account.id)
    assert "different approver realm" in forged(base.format(cool=full), approver, "platform", rid)        # a tenant admin posing as Platform Security
    assert "cooling-off window cannot be shortened" in forged(base.format(cool="interval '1 hour'"), approver, "tenant", rid)
    assert "approval time must be current" in forged(
        "UPDATE idn_recovery_request SET state = 'approved', approver_id = %s, approver_realm = 'tenant', approved_at = now() - interval '3 days', "
        "cooling_until = now() - interval '3 days' + cooling_seconds * interval '1 second' WHERE id = %s", approver, rid)
    assert state_of(rid) == "requested"
    # a genuine path still works, so the refusals above are not an artefact of a broken fixture
    assert approve_as(team.admin, rid).status_code == 200


def test_terminal_states_cannot_be_reopened_even_by_the_owner_role(team):
    _, r = request_recovery(team.member)
    rid = r.json()["id"]
    assert approve_as(team.admin, rid, "deny").status_code == 200 and state_of(rid) == "cancelled"
    with role_connect("ngrc_owner") as c, pytest.raises(psycopg.errors.InsufficientPrivilege, match="terminal state"):
        c.execute("UPDATE idn_recovery_request SET state = 'requested', ended_at = NULL, ended_reason = NULL WHERE id = %s", [rid])


def test_after_a_completed_recovery_only_the_completing_session_may_enrol_for_a_short_window(team):
    m = team.member
    sess, r = request_recovery(m)
    rid = r.json()["id"]
    approve_as(team.admin, rid)
    fast_forward(rid)
    assert sess.post("/auth/recovery/complete/", {"request_id": rid}).status_code == 200
    # someone who only knows the password logs in right afterwards and tries to enrol first
    intruder = Api()
    assert intruder.post("/auth/login/", {"email": m.email, "password": m.password}).json()["stage"] == "enroll_mfa"
    for path, body in (("/auth/mfa/totp/enroll/begin/", {}), ("/auth/mfa/totp/enroll/confirm/", {"code": "123456"}),
                       ("/auth/mfa/webauthn/register/begin/", {}), ("/auth/mfa/webauthn/register/complete/", {"credential": {}})):
        r2 = intruder.post(path, body)
        assert r2.status_code == 403 and r2.json() == {"error": "recovery_enrolment_reserved"}, path
    assert TotpFactor.objects.using("auth").filter(account=m.account).count() == 0
    assert sess.post("/auth/mfa/totp/enroll/begin/").status_code == 200                         # the completing session is not blocked
    # the reservation is a short window, not a permanent state: it ends (documented limit)
    with role_connect("ngrc_owner") as c:
        c.execute("ALTER TABLE idn_recovery_request DISABLE TRIGGER USER")
        c.execute("UPDATE idn_recovery_request SET ended_at = ended_at - make_interval(secs => %s) WHERE id = %s",
                  [settings.RECOVERY_ENROLMENT_WINDOW_S + 60, rid])
        c.execute("ALTER TABLE idn_recovery_request ENABLE TRIGGER USER")
        c.commit()
    assert intruder.post("/auth/mfa/totp/enroll/begin/", {}).status_code == 200
