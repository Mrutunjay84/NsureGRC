"""Authorization: default-deny route registry, privilege escalation, BOLA/IDOR, tenant-context edge cases, audit-write failure."""
import uuid

import pytest
from django.conf import settings
from django.db import connections, transaction
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from ngrc.audit import service as audit_service
from ngrc.authz.drf import NgrcAPIView
from ngrc.core.errors import AuditWriteFailed
from ngrc.iam.models import Session
from ngrc.tenancy.models import TenantRole

from .conftest import TEST_PASSWORD, add_member, make_account, provision_tenant
from .helpers import Api, audit_events

pytestmark = pytest.mark.security

# Reviewed allow-list of PUBLIC routes. A new public route must be added here deliberately (security review hook).
PUBLIC_PATHS = {
    "api/v1/auth/csrf/", "api/v1/auth/login/", "api/v1/auth/password/reset/request/", "api/v1/auth/password/reset/confirm/",
    "api/v1/auth/email/verify/", "api/v1/auth/invitations/accept/", "ops/api/v1/auth/csrf/", "ops/api/v1/auth/login/",
    "api/v1/auth/recovery/cancel/",  # single-use cancel link from the recovery notification e-mail (F-ATH-015)
}


def _walk(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLResolver):
            yield from _walk(p.url_patterns, prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            yield prefix + str(p.pattern), p.callback


def _routes():
    out = []
    for path, cb in _walk(get_resolver().url_patterns):
        cls = getattr(cb, "cls", None) or getattr(cb, "view_class", None)
        out.append((path, cls))
    return out


def _fill(path: str) -> str:
    import re

    return "/" + re.sub(r"<uuid:\w+>", lambda _m: str(uuid.uuid4()), path)


# ------------------------------------------------------------------------------------------------ default deny
def test_every_route_is_an_ngrc_view_with_a_declared_policy():
    routes = _routes()
    assert len(routes) > 30
    for path, cls in routes:
        if path == "healthz":
            assert getattr(cls, "ngrc_public_reason", ""), "healthz must justify being public"
            continue
        assert cls is not None and issubclass(cls, NgrcAPIView), f"{path}: not an NgrcAPIView"
        assert cls.ngrc_policy is not None, f"{path}: no declared policy (default-deny registry)"


def test_public_routes_match_the_reviewed_allow_list_and_state_a_reason():
    public = {path for path, cls in _routes() if cls is not None and issubclass(cls, NgrcAPIView) and cls.ngrc_policy.scope == "public"}
    assert public == PUBLIC_PATHS, f"unreviewed public route(s): {public ^ PUBLIC_PATHS}"
    for path, cls in _routes():
        if path in PUBLIC_PATHS:
            assert cls.ngrc_policy.reason


def test_every_non_public_route_rejects_anonymous_callers_on_every_method():
    api = Api(csrf=True)
    for path, cls in _routes():
        if path == "healthz" or path in PUBLIC_PATHS:
            continue
        url = _fill(path)
        for method in (m for m in ("get", "post", "patch", "delete") if hasattr(cls, m)):
            r = getattr(api.c, method)(url, secure=True, content_type="application/json", HTTP_ORIGIN="https://testserver",
                                       **({"HTTP_X_CSRFTOKEN": api._csrf()} if method != "get" else {}))
            assert r.status_code in (401, 403), (method.upper(), url, r.status_code)


def test_view_without_policy_is_denied():
    class Undeclared(NgrcAPIView):
        def get(self, request):  # pragma: no cover - must never run
            raise AssertionError("handler reached without a policy")

    class PlainDrf(APIView):
        def get(self, request):  # pragma: no cover
            raise AssertionError("handler reached with DRF defaults")

    for view in (Undeclared, PlainDrf):
        req = APIRequestFactory().get("/x")
        req.ngrc_principal = None
        resp = view.as_view()(req)
        assert resp.status_code in (401, 403)


def test_drf_defaults_fail_closed():
    rf = settings.REST_FRAMEWORK
    assert rf["DEFAULT_PERMISSION_CLASSES"] == ["ngrc.authz.drf_defaults.DenyAll"]
    assert rf["DEFAULT_AUTHENTICATION_CLASSES"] == ["ngrc.authz.drf_defaults.NgrcSessionAuthentication"]
    assert rf["DEFAULT_PARSER_CLASSES"] == ["ngrc.core.parsers.StrictJSONParser"]


def test_endpoint_inventory_is_reviewed():
    """Any new route fails this test until the inventory (and therefore its authz/IDOR tests) is consciously extended.
    Search and download exist since the P2 gate work (F-AUZ-005, F-DAT-004) and are listed explicitly; their cross-tenant tests live in
    tests/test_cross_tenant_search.py and tests/test_evidence_download.py. The reporting dashboard (D-P6-001, Phase 6) is the first
    "report" route - its tenant-isolation test lives in tests/test_reporting_api.py::test_dashboard_tenant_isolation. Export/job/
    notification endpoints still do not exist."""
    names = {p for p, _ in _routes()}
    sensitive = {p for p in names if any(w in p for w in ("search", "download", "upload", "file", "attachment", "export", "report"))}
    assert sensitive == {"api/v1/tenant/search/", "api/v1/tenant/evidence/<uuid:pk>/revisions/<uuid:rid>/download/",
                         "api/v1/tenant/audit/export/", "api/v1/tenant/reporting/dashboard/"}, sensitive
    assert len(names) == 1 + 29 + 21 + 49  # healthz + customer auth (+factors, +recovery) + tenant (+recovery, +evidence, +search, +reporting, +controls/findings/tasks, +risk, +governance, +compliance_audit, +privacy) + operator plane (+recovery)


# ------------------------------------------------------------------------------------------------ privilege escalation
def test_member_has_no_tenant_admin_rights(tenant_a, make_user):
    m = make_user(tenant_a, "member")
    assert m.api.get("/tenant/me/").status_code == 200
    for path in ("/tenant/roles/", "/tenant/invitations/", "/tenant/audit/events/", "/tenant/support/grants/"):
        assert m.api.get(path).status_code == 403, path
    assert m.api.post("/tenant/roles/", {"key": "evil", "name": "E", "permissions": ["tenant.view"]}).status_code == 403


def test_admin_cannot_create_a_role_with_permissions_it_does_not_hold(tenant_a, make_user):
    adm = make_user(tenant_a, "admin")
    r = adm.api.post("/tenant/roles/", {"key": "sneaky", "name": "S", "permissions": ["audit.export"]})
    assert r.status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="privilege_escalation", actor_id=adm.account.id)
    ok = adm.api.post("/tenant/roles/", {"key": "viewer-x", "name": "V", "permissions": ["tenant.view"]})
    assert ok.status_code == 201


def test_platform_permissions_can_never_be_put_in_a_tenant_role(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/roles/", {"key": "godmode", "name": "G", "permissions": ["platform.tenants.provision"]})
    assert r.status_code == 400 and r.json()["error"] == "unknown_permission"


def test_admin_cannot_promote_anyone_to_owner_or_modify_owners(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    adm = make_user(tenant_a, "admin")
    mem = make_user(tenant_a, "member")
    members = {m["principal_id"]: m for m in adm.api.get("/tenant/members/").json()["members"]}
    owner_role = tenant_a.role_id("owner")
    assert adm.api.patch(f"/tenant/members/{members[str(mem.account.id)]['id']}/", {"role_id": str(owner_role)}).status_code == 403
    assert adm.api.patch(f"/tenant/members/{members[str(owner.account.id)]['id']}/", {"status": "suspended"}).status_code == 403
    reasons = {e["reason_code"] for e in audit_events(tenant_id=tenant_a.id, action="authz.denied", actor_id=adm.account.id)}
    assert {"privilege_escalation", "target_outranks_caller"} <= reasons


def test_nobody_can_modify_their_own_membership(tenant_a, make_user):
    adm = make_user(tenant_a, "admin")
    mine = [m for m in adm.api.get("/tenant/members/").json()["members"] if m["principal_id"] == str(adm.account.id)][0]
    assert adm.api.patch(f"/tenant/members/{mine['id']}/", {"role_id": str(tenant_a.role_id("owner"))}).status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="self_modification")


def test_system_roles_are_immutable_through_the_api(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    rid = tenant_a.role_id("member")
    assert owner.api.patch(f"/tenant/roles/{rid}/", {"permissions": ["audit.export"]}).status_code == 403
    assert owner.api.delete(f"/tenant/roles/{rid}/").status_code == 403


def test_role_creation_validation_and_mass_assignment(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    for key in ("owner", "admin", "member", "A", "x", "has space", "in\nner", "../etc", "ünïcode"):
        r = owner.api.post("/tenant/roles/", {"key": key, "name": "N", "permissions": ["tenant.view"]})
        assert r.status_code == 400, (key, r.status_code)
    r = owner.api.post("/tenant/roles/", {"key": "mass-assign", "name": "M", "permissions": ["tenant.view"], "is_system": True,
                                           "tenant_id": str(uuid.uuid4()), "id": str(uuid.uuid4())})
    assert r.status_code == 201 and r.json()["is_system"] is False
    r2 = owner.api.post("/tenant/roles/", {"key": "padded-key\n", "name": "P", "permissions": ["tenant.view"]})
    assert r2.status_code == 201 and r2.json()["key"] == "padded-key"  # surrounding whitespace is normalised, never stored
    other = provision_tenant()
    from ngrc.core.context import tenant_context

    with tenant_context(other.id):
        assert not TenantRole.objects.filter(key="mass-assign").exists()


def test_mutations_require_recent_step_up(tenant_a, make_user, clock_ctl):
    owner = make_user(tenant_a, "owner")
    clock_ctl.advance(minutes=11)
    r = owner.api.post("/tenant/roles/", {"key": "late-role", "name": "L", "permissions": ["tenant.view"]})
    assert r.status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="step_up_expired", actor_id=owner.account.id)
    owner.stepup()
    assert owner.api.post("/tenant/roles/", {"key": "late-role", "name": "L", "permissions": ["tenant.view"]}).status_code == 201


def test_role_permission_reduction_revokes_holders_sessions(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    role = owner.api.post("/tenant/roles/", {"key": "reader-x", "name": "R", "permissions": ["tenant.view", "tenant.roles.read"]}).json()
    holder = make_user(tenant_a, "reader-x")
    assert holder.api.get("/tenant/roles/").status_code == 200
    assert owner.api.patch(f"/tenant/roles/{role['id']}/", {"permissions": ["tenant.view"]}).status_code == 200
    assert holder.api.get("/tenant/roles/").status_code == 401  # session ended, not just downgraded
    holder.relogin()
    assert holder.api.get("/tenant/roles/").status_code in (401, 403)


def test_cannot_delete_role_in_use_and_last_owner_is_protected(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    role = owner.api.post("/tenant/roles/", {"key": "in-use", "name": "I", "permissions": ["tenant.view"]}).json()
    make_user(tenant_a, "in-use")
    assert owner.api.delete(f"/tenant/roles/{role['id']}/").status_code == 409
    second = make_user(tenant_a, "owner")
    members = {m["principal_id"]: m["id"] for m in owner.api.get("/tenant/members/").json()["members"]}
    assert owner.api.patch(f"/tenant/members/{members[str(second.account.id)]}/", {"status": "suspended"}).status_code == 200


def test_invitation_flow_enforces_no_escalation_and_hides_token(tenant_a, make_user):
    from django.core import mail

    from .helpers import last_mail_token

    adm = make_user(tenant_a, "admin")
    r = adm.api.post("/tenant/invitations/", {"email": "new.hire@example.test", "role_id": str(tenant_a.role_id("owner"))})
    assert r.status_code == 403  # admin cannot invite an Owner
    r = adm.api.post("/tenant/invitations/", {"email": "new.hire@example.test", "role_id": str(tenant_a.role_id("member"))})
    assert r.status_code == 201 and "token" not in r.content.decode()
    listing = adm.api.get("/tenant/invitations/").content.decode()
    assert "token" not in listing
    tok = last_mail_token(mail.outbox, "new.hire@example.test")
    joiner = Api()
    r = joiner.post("/auth/invitations/accept/", {"token": tok, "password": TEST_PASSWORD, "display_name": "New Hire"})
    assert r.status_code == 201 and r.json()["tenant_id"] == str(tenant_a.id)
    assert joiner.post("/auth/invitations/accept/", {"token": tok, "password": TEST_PASSWORD}).status_code == 400  # single use


def test_external_auditor_invitation_requires_expiry(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/invitations/", {"email": "aud@example.test", "role_id": str(tenant_a.role_id("member")), "kind": "external_auditor"})
    assert r.status_code == 400 and r.json()["error"] == "expiry_required"


# ------------------------------------------------------------------------------------------------ BOLA / IDOR
@pytest.fixture
def two_tenants(make_user):
    a, b = provision_tenant(), provision_tenant()
    return a, b, make_user(a, "owner"), make_user(b, "owner")


def test_idor_roles_members_invitations_across_tenants(two_tenants):
    a, b, ua, ub = two_tenants
    b_role = ub.api.post("/tenant/roles/", {"key": "b-secret-role", "name": "B Secret", "permissions": ["tenant.view"]}).json()
    b_member = [m for m in ub.api.get("/tenant/members/").json()["members"]][0]
    inv_b = ub.api.post("/tenant/invitations/", {"email": "b.person@example.test", "role_id": str(b.role_id("member"))}).json()
    # tenant A's owner uses tenant B's identifiers
    assert ua.api.get(f"/tenant/roles/{b_role['id']}/").status_code == 404
    assert ua.api.patch(f"/tenant/roles/{b_role['id']}/", {"name": "pwned"}).status_code == 404
    assert ua.api.delete(f"/tenant/roles/{b_role['id']}/").status_code == 404
    assert ua.api.get(f"/tenant/members/{b_member['id']}/").status_code == 404
    assert ua.api.patch(f"/tenant/members/{b_member['id']}/", {"status": "suspended"}).status_code == 404
    assert ua.api.delete(f"/tenant/invitations/{inv_b['id']}/").status_code == 404
    assert ua.api.post(f"/tenant/support/grants/{uuid.uuid4()}/consent/", {}).status_code == 404
    # B's data is untouched
    assert ub.api.get(f"/tenant/roles/{b_role['id']}/").json()["name"] == "B Secret"
    assert ub.api.get(f"/tenant/members/{b_member['id']}/").json()["status"] == "active"
    # and A's own lists never contain B's objects
    assert "b-secret-role" not in ua.api.get("/tenant/roles/").content.decode()
    assert b_member["email"] not in ua.api.get("/tenant/members/").content.decode()
    assert "b.person" not in ua.api.get("/tenant/invitations/").content.decode()


def test_idor_attempts_do_not_leak_existence(two_tenants):
    a, b, ua, ub = two_tenants
    b_role = ub.api.post("/tenant/roles/", {"key": "b-only", "name": "B", "permissions": ["tenant.view"]}).json()
    foreign = ua.api.get(f"/tenant/roles/{b_role['id']}/")
    missing = ua.api.get(f"/tenant/roles/{uuid.uuid4()}/")
    assert foreign.status_code == missing.status_code == 404 and foreign.json() == missing.json()


def test_tenant_identifier_in_requests_is_never_trusted(two_tenants):
    a, b, ua, ub = two_tenants
    r = ua.api.get(f"/tenant/me/?tenant_id={b.id}&tenant={b.id}", HTTP_X_TENANT_ID=str(b.id), HTTP_X_TENANT=str(b.slug))
    assert r.status_code == 200 and r.json()["tenant"]["id"] == str(a.id)
    r = ua.api.post("/tenant/roles/", {"key": "into-b", "name": "X", "permissions": ["tenant.view"], "tenant_id": str(b.id)})
    assert r.status_code == 201
    assert "into-b" not in ub.api.get("/tenant/roles/").content.decode()


def test_audit_trail_and_export_never_cross_tenants(two_tenants):
    a, b, ua, ub = two_tenants
    ub.api.post("/tenant/roles/", {"key": "b-audit-marker", "name": "B", "permissions": ["tenant.view"]})
    ua.api.post("/tenant/roles/", {"key": "a-audit-marker", "name": "A", "permissions": ["tenant.view"]})
    ua.stepup()
    listing = ua.api.get("/tenant/audit/events/").content.decode()
    export = ua.api.get("/tenant/audit/export/").content.decode()
    for blob in (listing, export):
        assert "a-audit-marker" in blob and "b-audit-marker" not in blob and str(b.id) not in blob


def test_selecting_a_tenant_without_membership_is_denied_and_audited(tenant_a, tenant_b, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/auth/tenants/select/", {"tenant_id": str(tenant_b.id)})
    assert r.status_code == 403
    assert audit_events(platform=True, action="authz.denied", reason_code="not_a_member", actor_id=u.account.id)
    assert u.api.post("/auth/tenants/select/", {"tenant_id": "not-a-uuid"}).status_code == 400
    assert str(tenant_b.id) not in u.api.get("/auth/tenants/").content.decode()


# ------------------------------------------------------------------------------------------------ missing / invalid tenant context
def test_no_tenant_selected_blocks_tenant_routes(tenant_a, make_user):
    u = make_user(tenant_a, "owner", select_tenant=False)
    for path in ("/tenant/me/", "/tenant/roles/", "/tenant/members/"):
        assert u.api.get(path).status_code == 403
    assert audit_events(platform=True, action="authz.denied", reason_code="no_tenant_selected", actor_id=u.account.id)


def test_tampered_session_tenant_is_not_honoured(tenant_a, tenant_b, make_user):
    u = make_user(tenant_a, "owner")
    sid = Session.objects.using("auth").get(account=u.account)
    Session.objects.using("auth").filter(pk=sid.pk).update(active_tenant_id=tenant_b.id)  # no membership in B
    assert u.api.get("/tenant/me/").status_code == 403
    Session.objects.using("auth").filter(pk=sid.pk).update(active_tenant_id=uuid.uuid4())  # tenant that does not exist
    assert u.api.get("/tenant/me/").status_code == 403
    assert u.api.get("/tenant/roles/").status_code == 403


def test_removing_membership_takes_effect_on_the_next_request(tenant_a, make_user):
    u = make_user(tenant_a, "admin")
    assert u.api.get("/tenant/roles/").status_code == 200
    with transaction.atomic(using="owner"), connections["owner"].cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        cur.execute("DELETE FROM ten_membership WHERE principal_id = %s", [str(u.account.id)])
    assert u.api.get("/tenant/roles/").status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="not_a_member") or \
        audit_events(platform=True, action="authz.denied", reason_code="not_a_member", actor_id=u.account.id)


def test_suspended_tenant_denies_access(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    with transaction.atomic(using="ops"), connections["ops"].cursor() as cur:
        cur.execute("UPDATE plt_tenant SET status = 'suspended' WHERE id = %s", [str(tenant_a.id)])
    assert u.api.get("/tenant/me/").status_code == 403


def test_expired_membership_denies_access(tenant_a, make_user, clock_ctl):
    from .conftest import future

    acct = make_account()
    add_member(tenant_a, acct, "member", kind="external_auditor", expires_at=future(minutes=5))
    from .helpers import enroll_totp_and_login

    api, _t, _c = enroll_totp_and_login(acct.email, TEST_PASSWORD, clock_ctl.ts())
    assert api.post("/auth/tenants/select/", {"tenant_id": str(tenant_a.id)}).status_code == 200
    api.refresh_csrf()
    assert api.get("/tenant/me/").status_code == 200
    clock_ctl.advance(minutes=6)
    assert api.get("/tenant/me/").status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="membership_expired")


# ------------------------------------------------------------------------------------------------ audit-write failure (C-4)
def test_business_change_is_rolled_back_when_the_audit_append_fails(tenant_a, make_user, monkeypatch):
    owner = make_user(tenant_a, "owner")

    def boom(using, ev):
        raise AuditWriteFailed("simulated audit outage")

    monkeypatch.setattr(audit_service, "append_tenant", boom)
    r = owner.api.post("/tenant/roles/", {"key": "no-audit-no-change", "name": "N", "permissions": ["tenant.view"]})
    assert r.status_code == 500 and r.json() == {"error": "audit_unavailable"}
    monkeypatch.undo()
    assert "no-audit-no-change" not in owner.api.get("/tenant/roles/").content.decode()


def test_a_denial_stays_a_denial_when_the_audit_service_is_down(tenant_a, make_user, monkeypatch):
    m = make_user(tenant_a, "member")
    monkeypatch.setattr(audit_service, "append_tenant", lambda using, ev: (_ for _ in ()).throw(AuditWriteFailed("down")))
    monkeypatch.setattr(audit_service, "append_platform", lambda using, ev: (_ for _ in ()).throw(AuditWriteFailed("down")))
    assert m.api.get("/tenant/roles/").status_code == 403  # fails closed; never "allow because we could not log"


def test_failed_requests_leave_no_partial_state(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    before = owner.api.get("/tenant/roles/").json()["roles"]
    owner.api.post("/tenant/roles/", {"key": "half-done", "name": "H", "permissions": ["tenant.view", "no.such.permission"]})
    assert owner.api.get("/tenant/roles/").json()["roles"] == before
