"""D-P0-005 testing requirements: operator realm, separation of duties, support grants, break-glass, tenant consent, mirrored audit."""
import uuid

import pytest
from django.conf import settings
from django.core import mail
from django.db import connections, transaction

from ngrc.control_plane.models import SupportAccessGrant

from .conftest import TEST_PASSWORD, provision_tenant
from .helpers import Api, Authenticator, audit_events, last_mail_token

pytestmark = pytest.mark.security
OPS_SID = settings.OPERATOR_COOKIE_NAME


# ------------------------------------------------------------------------------------------------ helpers
def request_grant(op, tenant, **over):
    op.stepup()
    body = {"tenant_id": str(tenant.id), "ticket_ref": "TICKET-1001", "reason": "Customer reports sync failures",
            "profile": "diagnostic_metadata", "duration_minutes": 60, **over}
    return op.api.post("/support/grants/", body)


def approve(op, grant_id, *, binding_id=None):
    """T2: challenge bound to the grant id, then assertion."""
    opts = op.api.post(f"/support/grants/{binding_id or grant_id}/approve/begin/")
    assert opts.status_code == 200, opts.content
    return op.api.post(f"/support/grants/{grant_id}/approve/", {"credential": op.auth.assert_(opts.json())})


def consent(owner, grant_id):
    owner.stepup()
    return owner.api.post(f"/tenant/support/grants/{grant_id}/consent/", {})


def activate_and_start(op, grant_id):
    op.stepup()
    a = op.api.post(f"/support/grants/{grant_id}/activate/")
    assert a.status_code == 200, a.content
    s = op.api.post(f"/support/grants/{grant_id}/start/")
    assert s.status_code == 200, s.content
    op.api.refresh_csrf()


@pytest.fixture
def env(tenant_a, make_user, login_operator):
    class Env:
        pass

    e = Env()
    e.tenant = tenant_a
    e.owner = make_user(tenant_a, "owner")
    e.sup = login_operator("platform_support")
    e.sec = login_operator("platform_security")
    e.adm = login_operator("platform_admin")
    return e


def consented_grant(e, **over):
    g = request_grant(e.sup, e.tenant, **over)
    assert g.status_code == 201, g.content
    gid = g.json()["id"]
    assert approve(e.sec, gid).json()["status"] == "approved"
    assert consent(e.owner, gid).status_code == 200
    return gid


# ------------------------------------------------------------------------------------------------ happy path & audit mirroring
def test_support_access_end_to_end_with_mirrored_audit(env):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    diag = env.sup.api.get("/support/tenant/diagnostics/")
    assert diag.status_code == 200 and diag.json()["tenant"]["id"] == str(env.tenant.id)
    # diagnostic_metadata profile: no tenant content (role definitions are outside the profile)
    assert env.sup.api.get("/support/tenant/roles/").status_code == 403
    assert env.sup.api.post("/support/session/end/").status_code == 200
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 403  # nothing survives the end of the session

    t = {e["action"] for e in audit_events(tenant_id=env.tenant.id)}
    assert {"support.grant.requested", "support.grant.approved", "tenant.support.consented", "support.session.started",
            "support.action", "support.session.ended", "authz.denied"} <= t
    p = {e["action"] for e in audit_events(platform=True, tenant_id=env.tenant.id)}
    assert {"platform.support.requested", "platform.support.approved", "platform.support.consented", "platform.support.activated",
            "platform.support.action", "platform.support.ended"} <= p
    acts = [e for e in audit_events(tenant_id=env.tenant.id, action="support.action")]
    assert acts and all(e["actor_type"] == "operator" and e["grant"] == gid for e in acts)  # attributed to the operator, never a user
    denied = audit_events(tenant_id=env.tenant.id, action="authz.denied", reason_code="outside_grant_profile")
    assert denied and denied[0]["actor_type"] == "operator"
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "revoked"


def test_tenant_owner_sees_the_grant_and_its_actions(env):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    env.sup.api.get("/support/tenant/diagnostics/")
    listing = env.owner.api.get("/tenant/support/grants/").json()["grants"]
    assert [g for g in listing if g["id"] == gid][0]["state"] == "active"
    events = env.owner.api.get("/tenant/audit/events/").json()["events"]
    assert any(e["action"] == "support.action" and e["support_grant"] == gid for e in events)


# ------------------------------------------------------------------------------------------------ separation of duties
def test_requester_cannot_approve_their_own_request(tenant_a, login_operator):
    both = login_operator("platform_support", "platform_security")
    gid = request_grant(both, tenant_a).json()["id"]
    r = approve(both, gid)
    assert r.status_code == 403
    assert audit_events(platform=True, action="authz.denied", reason_code="self_approval", actor_id=both.account.id)
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "requested"


def test_only_platform_security_can_approve(env):
    gid = request_grant(env.sup, env.tenant).json()["id"]
    for op in (env.sup, env.adm):
        opts = op.api.post(f"/support/grants/{gid}/approve/begin/")
        assert opts.status_code == 403
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "requested"


def test_approval_requires_an_assertion_bound_to_that_exact_grant(env):
    g1 = request_grant(env.sup, env.tenant).json()["id"]
    g2 = request_grant(env.sup, env.tenant, ticket_ref="TICKET-2").json()["id"]
    # assertion obtained for grant 1 cannot approve grant 2
    opts = env.sec.api.post(f"/support/grants/{g1}/approve/begin/").json()
    cred = env.sec.auth.assert_(opts)
    assert env.sec.api.post(f"/support/grants/{g2}/approve/", {"credential": cred}).status_code == 401
    # a generic T1 step-up challenge cannot be used for a T2 approval
    env.sec.stepup()
    t1 = env.sec.api.post("/auth/stepup/webauthn/begin/").json()
    assert env.sec.api.post(f"/support/grants/{g2}/approve/", {"credential": env.sec.auth.assert_(t1)}).status_code == 401
    # no challenge at all
    assert env.sec.api.post(f"/support/grants/{g2}/approve/", {"credential": env.sec.auth.assert_({"challenge": "AAAA"})}).status_code == 401
    assert SupportAccessGrant.objects.using("ops").get(pk=g2).state == "requested"
    # every failed attempt BURNS the pending challenge: the earlier (valid-for-g1) assertion no longer works either
    assert env.sec.api.post(f"/support/grants/{g1}/approve/", {"credential": cred}).status_code == 401
    # a fresh challenge bound to grant 1 works exactly once
    opts = env.sec.api.post(f"/support/grants/{g1}/approve/begin/").json()
    good = env.sec.auth.assert_(opts)
    assert env.sec.api.post(f"/support/grants/{g1}/approve/", {"credential": good}).status_code == 200
    assert env.sec.api.post(f"/support/grants/{g1}/approve/", {"credential": good}).status_code in (401, 409)  # replay


def test_request_needs_ticket_reason_and_valid_profile(env):
    for bad in ({"ticket_ref": ""}, {"reason": ""}, {"ticket_ref": "   "}, {"profile": "god_mode"},
                {"scope": ["billing"]}, {"duration_minutes": 481}, {"duration_minutes": 0}):
        r = request_grant(env.sup, env.tenant, **bad)
        assert r.status_code in (400,), (bad, r.status_code, r.content)
    assert request_grant(env.sup, type("T", (), {"id": uuid.uuid4()})).status_code == 404


def test_only_support_engineers_may_request(tenant_a, login_operator):
    """Approvers (security, admin) and curators cannot request: the requester is never one of the approvers."""
    for roles in (("platform_security",), ("platform_curator",), ("platform_admin",)):
        op = login_operator(*roles)
        assert request_grant(op, tenant_a).status_code == 403


def test_request_requires_recent_step_up(env, clock_ctl):
    r = env.sup.api.post("/support/grants/", {"tenant_id": str(env.tenant.id), "ticket_ref": "T", "reason": "r"})
    # login just happened so a step-up is still fresh; age it out
    from ngrc.authn.realms import OPERATOR  # noqa: F401

    clock_ctl.advance(minutes=11)
    r = env.sup.api.post("/support/grants/", {"tenant_id": str(env.tenant.id), "ticket_ref": "T", "reason": "r"})
    assert r.status_code in (401, 403)


# ------------------------------------------------------------------------------------------------ tenant consent
def test_activation_is_impossible_without_tenant_consent(env):
    gid = request_grant(env.sup, env.tenant).json()["id"]
    approve(env.sec, gid)
    env.sup.stepup()
    assert env.sup.api.post(f"/support/grants/{gid}/activate/").status_code == 409
    assert env.sup.api.post(f"/support/grants/{gid}/start/").status_code == 403


def test_only_a_tenant_owner_can_consent(env, make_user):
    adm = make_user(env.tenant, "admin")
    gid = request_grant(env.sup, env.tenant).json()["id"]
    approve(env.sec, gid)
    adm.stepup()
    assert adm.api.post(f"/tenant/support/grants/{gid}/consent/", {}).status_code == 403
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "approved"


def test_another_tenants_owner_cannot_see_or_decide_the_grant(env, make_user):
    other = provision_tenant()
    other_owner = make_user(other, "owner")
    gid = request_grant(env.sup, env.tenant).json()["id"]
    approve(env.sec, gid)
    other_owner.stepup()
    assert other_owner.api.post(f"/tenant/support/grants/{gid}/consent/", {}).status_code == 404
    assert gid not in other_owner.api.get("/tenant/support/grants/").content.decode()


def test_consent_before_approval_is_refused(env):
    gid = request_grant(env.sup, env.tenant).json()["id"]
    assert consent(env.owner, gid).status_code == 409


def test_tenant_has_no_write_path_to_approval_columns(env):
    import psycopg

    from .conftest import role_connect

    gid = request_grant(env.sup, env.tenant).json()["id"]
    for stmt in ("UPDATE plt_support_access_grant SET state = 'active'", "DELETE FROM plt_support_access_grant"):
        with role_connect("ngrc_app") as c:
            c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(env.tenant.id)])
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(stmt)
    for stmt in ("UPDATE plt_support_access_grant SET consent_user_id = gen_random_uuid()",
                 "UPDATE plt_support_access_grant SET restricted_class_consent = true"):
        with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):  # operators cannot forge consent
            c.execute(stmt)
    _ = gid


def test_state_machine_trigger_rejects_illegal_transitions_even_for_the_owner_role(env):
    """Skipping states or forging consent directly in SQL is refused by plt_support_grant_guard."""
    import psycopg

    from .conftest import role_connect

    gid = request_grant(env.sup, env.tenant).json()["id"]
    with role_connect("ngrc_ops") as c:
        for stmt in ("UPDATE plt_support_access_grant SET state = 'active', activated_at = now(), expires_at = now() + interval '1 hour' "
                     "WHERE id = %s", "UPDATE plt_support_access_grant SET state = 'tenant_consented' WHERE id = %s"):
            with pytest.raises(psycopg.errors.Error):
                c.execute(stmt, [gid])
            c.rollback()
        with pytest.raises(psycopg.errors.Error):
            c.execute("DELETE FROM plt_support_access_grant WHERE id = %s", [gid])
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "requested"


# ------------------------------------------------------------------------------------------------ time-boxing & revocation
def test_expired_grant_stops_working_immediately(env):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 200
    with transaction.atomic(using="ops"), connections["ops"].cursor() as cur:
        cur.execute("UPDATE plt_support_access_grant SET expires_at = now() - interval '1 minute' WHERE id = %s", [gid])
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 403
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "expired"
    assert [e for e in audit_events(platform=True, action="platform.support.ended") if e["grant"] == gid]


def test_tenant_owner_revocation_is_immediate(env):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 200
    env.owner.stepup()
    assert env.owner.api.post(f"/tenant/support/grants/{gid}/revoke/", {}).status_code == 200
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 403
    assert audit_events(tenant_id=env.tenant.id, action="tenant.support.revoked")


def test_grant_duration_is_capped(env):
    r = request_grant(env.sup, env.tenant, duration_minutes=settings.SUPPORT_GRANT_MAX_MINUTES + 1)
    assert r.status_code == 400


def test_support_session_cannot_be_used_on_the_platform_side_or_by_others(env, login_operator):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    assert env.sup.api.get("/tenants/").status_code == 403  # platform permissions are not usable inside a grant
    other = login_operator("platform_support")
    other.stepup()
    assert other.api.post(f"/support/grants/{gid}/start/").status_code == 404  # not the requester
    assert other.api.get("/support/tenant/diagnostics/").status_code == 403  # no grant bound to this session


def test_operator_session_never_works_on_the_customer_api(env):
    gid = consented_grant(env)
    activate_and_start(env.sup, gid)
    ops_cookie = env.sup.api.cookie(OPS_SID)
    cust = Api()
    cust.set_cookie(settings.CUSTOMER_COOKIE_NAME, ops_cookie)
    assert cust.get("/tenant/me/").status_code == 401
    assert cust.get("/tenant/roles/").status_code == 401
    direct = Api()
    direct.set_cookie(OPS_SID, ops_cookie)  # operator cookie on the customer path is simply not read
    assert direct.get("/tenant/me/").status_code == 401


# ------------------------------------------------------------------------------------------------ break-glass
def test_break_glass_needs_two_distinct_approvers_and_skips_consent(env):
    r = request_grant(env.sup, env.tenant, break_glass=True, duration_minutes=60, ticket_ref="INC-77")
    assert r.status_code == 201, r.content
    gid = r.json()["id"]
    assert audit_events(platform=True, action="platform.breakglass.requested", actor_id=env.sup.account.id)
    # nothing is usable after the first approval
    assert approve(env.sec, gid).json()["status"] == "awaiting_second_approver"
    env.sup.stepup()
    assert env.sup.api.post(f"/support/grants/{gid}/activate/").status_code == 409
    # the first approver again and the requester (who has no approve right) are refused
    assert approve(env.sec, gid).status_code == 403
    assert env.sup.api.post(f"/support/grants/{gid}/approve/begin/").status_code == 403
    assert approve(env.adm, gid).json()["status"] == "approved"  # second, distinct approver holding Platform Admin
    activate_and_start(env.sup, gid)  # no tenant consent for break-glass
    assert env.sup.api.get("/support/tenant/diagnostics/").status_code == 200
    assert audit_events(platform=True, action="platform.breakglass.approved")
    ev = audit_events(tenant_id=env.tenant.id, action="support.session.started")
    assert ev  # the tenant is told, even though it was not asked


def test_break_glass_duration_is_capped_lower(env):
    r = request_grant(env.sup, env.tenant, break_glass=True, duration_minutes=settings.BREAK_GLASS_MAX_MINUTES + 1)
    assert r.status_code == 400


def test_approvers_cannot_request_break_glass(env):
    for op in (env.adm, env.sec):
        assert request_grant(op, env.tenant, break_glass=True).status_code == 403


def test_break_glass_second_approver_must_be_a_different_platform_admin(env, login_operator):
    gid = request_grant(env.sup, env.tenant, break_glass=True, duration_minutes=60).json()["id"]
    sec2 = login_operator("platform_security")
    assert approve(env.sec, gid).json()["status"] == "awaiting_second_approver"
    assert approve(sec2, gid).status_code == 403  # a second Platform Security person is not enough: Admin required
    assert SupportAccessGrant.objects.using("ops").get(pk=gid).state == "requested"


# ------------------------------------------------------------------------------------------------ operator realm authentication
def test_operator_requires_webauthn_with_user_verification(make_operator):
    op = make_operator("platform_admin")
    api = Api(prefix="/ops/api/v1")
    assert api.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD}).json() == {"stage": "enroll_mfa", "methods": ["webauthn"]}
    opts = api.post("/auth/mfa/webauthn/register/begin/").json()
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    assert api.post("/auth/mfa/webauthn/register/complete/", {"credential": Authenticator(uv=False).register(opts)}).status_code == 400
    assert api.get("/auth/session/").json()["stage"] == "enroll_mfa"
    assert api.get("/tenants/").status_code == 403
    for dead in ("/auth/mfa/totp/verify/", "/auth/mfa/recovery/verify/", "/auth/mfa/totp/enroll/begin/"):
        assert api.post(dead, {}).status_code == 404  # no TOTP and no recovery codes in the platform realm


def test_operator_password_alone_grants_nothing(make_operator):
    op = make_operator("platform_security")
    api = Api(prefix="/ops/api/v1")
    api.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD})
    for path in ("/tenants/", "/audit/platform/", "/support/grants/"):
        assert api.get(path).status_code == 403


def test_operator_login_is_throttled_harder_than_customer_login(make_operator):
    op = make_operator("platform_admin")
    api = Api(prefix="/ops/api/v1")
    free = settings.AUTH_THROTTLE["operator_account_free_failures"]
    codes = [api.post("/auth/login/", {"email": op.email, "password": "wrong-password-xyz"}).status_code for _ in range(free)]
    assert codes == [401] * free
    assert api.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD}).status_code == 429
    assert audit_events(platform=True, action="platform.operator.throttle.triggered")


def test_operator_login_does_not_enumerate(make_operator):
    op = make_operator("platform_admin")
    api = Api(prefix="/ops/api/v1")
    a = api.post("/auth/login/", {"email": op.email, "password": "wrong-password-xyz"})
    b = api.post("/auth/login/", {"email": "nobody@nsuregrc.test", "password": "wrong-password-xyz"})
    assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"error": "invalid_credentials"})


def test_operator_cookie_attributes(login_operator):
    op = login_operator("platform_admin")
    m = op.api.c.cookies[OPS_SID]
    assert OPS_SID.startswith("__Host-") and m["secure"] and m["httponly"] and m["samesite"] == "Lax" and m["path"] == "/"


def test_operator_session_is_short_lived(login_operator, clock_ctl):
    op = login_operator("platform_admin")
    assert op.api.get("/auth/session/").status_code == 200
    clock_ctl.advance(minutes=16)
    assert op.api.get("/auth/session/").status_code == 401


def test_operator_counter_regression_blocks_the_credential(make_operator):
    op = make_operator("platform_admin")
    from .helpers import operator_login

    api, auth = operator_login(op.email, TEST_PASSWORD, None)
    api.post("/auth/logout/")
    for counter, ok in ((10, True), (4, False)):
        a = Api(prefix="/ops/api/v1")
        a.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD})
        opts = a.post("/auth/mfa/webauthn/authenticate/begin/").json()
        r = a.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts, counter=counter)})
        assert (r.status_code == 200) is ok
    assert audit_events(platform=True, action="auth.webauthn.counter_regression", actor_id=op.id)
    a = Api(prefix="/ops/api/v1")
    a.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD})
    assert a.post("/auth/mfa/webauthn/authenticate/begin/").status_code == 400
    assert a.post("/auth/mfa/webauthn/register/begin/").status_code == 403  # and a password alone cannot enrol a replacement


# ------------------------------------------------------------------------------------------------ platform administration
def test_only_platform_admin_can_provision_and_it_needs_step_up(login_operator):
    sup, adm = login_operator("platform_support"), login_operator("platform_admin")
    body = {"slug": f"acme-{uuid.uuid4().hex[:6]}", "name": "Acme", "owner_email": "owner@acme.example"}
    sup.stepup()
    assert sup.api.post("/tenants/", body).status_code == 403
    from ngrc.core.context import tenant_context  # noqa: F401

    r = adm.api.post("/tenants/", body)  # login-time step-up is still fresh
    assert r.status_code == 201, r.content
    assert "token" not in r.content.decode()
    assert adm.api.post("/tenants/", body).status_code == 409
    token = last_mail_token(mail.outbox, "owner@acme.example")
    joiner = Api()
    ok = joiner.post("/auth/invitations/accept/", {"token": token, "password": TEST_PASSWORD, "display_name": "Acme Owner"})
    assert ok.status_code == 201
    assert audit_events(platform=True, action="platform.tenant.provisioned", actor_id=adm.account.id)


def test_provisioning_needs_a_fresh_step_up(login_operator, clock_ctl):
    adm = login_operator("platform_admin")
    clock_ctl.advance(minutes=11)
    r = adm.api.post("/tenants/", {"slug": "late", "name": "Late", "owner_email": "x@late.example"})
    assert r.status_code in (401, 403)


def test_platform_audit_stream_is_for_platform_security_only(login_operator):
    sec = login_operator("platform_security")
    for roles in (("platform_support",), ("platform_admin",), ("platform_curator",)):
        assert login_operator(*roles).api.get("/audit/platform/").status_code == 403
    r = sec.api.get("/audit/platform/?limit=5")
    assert r.status_code == 200 and r.json()["events"]
    assert audit_events(platform=True, action="platform.audit.read", actor_id=sec.account.id)
    assert sec.api.get("/audit/platform/?after_seq=abc").status_code == 400
    assert sec.api.get("/audit/platform/?after_seq=-5&limit=999999").status_code == 200


def test_tenant_users_cannot_use_platform_apis(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    ops_view = Api(prefix="/ops/api/v1")
    ops_view.c.cookies = owner.api.c.cookies
    ops_view.set_cookie(OPS_SID, owner.api.cookie(settings.CUSTOMER_COOKIE_NAME))
    assert ops_view.get("/tenants/").status_code == 401
    assert ops_view.get("/audit/platform/").status_code == 401
