"""Platform (operator) plane API, mounted under /ops/api/v1/ on its own process/hostname in production (D-P0-005).

* Authentication reuses the realm-generic hardened flow with the OPERATOR realm: password -> WebAuthn (mandatory,
  user verification REQUIRED, no TOTP, no recovery codes) -> active session.
* No operator ever "becomes" a customer user. Access to tenant data exists only through an ACTIVE support grant bound to the
  operator session; every request is re-validated against the grant (ngrc.authz.drf.PolicyPermission) and double-audited.
* Separation of duties lives in the database (trigger plt_support_grant_guard); the checks here fail early with clean codes.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, connections, transaction
from django.middleware.csrf import get_token
from rest_framework import serializers
from rest_framework.response import Response

from ngrc.audit import service as audit
from ngrc.authn import flow, sessions, webauthn_
from ngrc.authn.realms import OPERATOR
from ngrc.authz import permissions as perm
from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.core import clock
from ngrc.core.context import tenant_context  # noqa: F401  (re-exported for tests)
from ngrc.core.crypto import hash_token, new_token
from ngrc.core.net import normalize_ip

from .models import OperatorSession, SupportAccessGrant, Tenant

log = logging.getLogger("ngrc.ops")
ANY_STAGE = ("password_ok", "enroll_mfa", "active")


def _ip(request):
    return normalize_ip(request.META.get("REMOTE_ADDR"))


def _ua(request):
    return request.META.get("HTTP_USER_AGENT", "")[:256]


def _session_account(request):
    s = OperatorSession.objects.using("ops").select_related("account").get(pk=request.user.session_id)
    return s, s.account


def _err(code: str, http: int = 400) -> Response:
    return Response({"error": code}, status=http)


def _with_cookie(response: Response, raw: str) -> Response:
    sessions.set_cookie(response, OPERATOR, raw)
    return response


def _emit(action: str, request, **kw):
    p = request.user
    audit.emit_platform("ops", action, actor_type="operator", actor_id=p.account_id, **kw)


# ------------------------------------------------------------------------------------------------------ authentication
class CsrfView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="issues a CSRF token; no data access")

    def get(self, request):
        return Response({"csrfToken": get_token(request._request)})


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=254)
    password = serializers.CharField(max_length=1024, trim_whitespace=False)


class LoginView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="operator credential submission; throttled, uniform responses")

    def post(self, request):
        d = LoginSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        res = flow.password_login(OPERATOR, d.validated_data["email"], d.validated_data["password"], ip=_ip(request),
                                  user_agent=_ua(request))
        if res.status == "throttled":
            r = Response({"error": "throttled", "retry_after": res.retry_after}, status=429)
            r["Retry-After"] = str(res.retry_after)
            return r
        if res.status != "ok":
            return _err("invalid_credentials", 401)
        return _with_cookie(Response({"stage": res.stage, "methods": ["webauthn"]}), res.raw_token)


class SessionView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=ANY_STAGE)

    def get(self, request):
        s, a = _session_account(request)
        return Response({"stage": s.stage, "operator": {"id": str(a.id), "email": a.email, "display_name": a.display_name},
                         "roles": sorted(request.user.operator_roles), "support_grant_id": str(s.support_grant_id) if s.support_grant_id else None,
                         "expires_at": s.expires_at.isoformat()})


class LogoutView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=ANY_STAGE)

    def post(self, request):
        s, _a = _session_account(request)
        sessions.revoke(OPERATOR, s, "logout")
        _emit("platform.operator.logout", request)
        r = Response({"status": "ok"})
        sessions.clear_cookie(r, OPERATOR)
        return r


class CredentialSerializer(serializers.Serializer):
    credential = serializers.DictField()
    nickname = serializers.CharField(max_length=100, required=False, allow_blank=True)


class WebAuthnRegisterBeginView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=("enroll_mfa", "active"))

    def post(self, request):
        s, a = _session_account(request)
        if s.stage == "active":
            from ngrc.authz.policy import Denied, require_recent_step_up

            try:
                require_recent_step_up(request.user, "T1")
            except Denied:
                return _err("forbidden", 403)
        return Response(webauthn_.registration_options(OPERATOR, s, a, require_uv=True))


class WebAuthnRegisterCompleteView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=("enroll_mfa", "active"))

    def post(self, request):
        d = CredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        try:
            webauthn_.complete_registration(OPERATOR, s, a, d.validated_data["credential"], require_uv=True,
                                            nickname=d.validated_data.get("nickname", ""))
        except webauthn_.WebAuthnError:
            return _err("registration_failed")
        _emit("platform.operator.webauthn.registered", request)
        if s.stage == "enroll_mfa":
            return _with_cookie(Response({"stage": "active"}), flow.mfa_succeeded(OPERATOR, s, a, "webauthn"))
        return Response({"stage": "active"})


class WebAuthnAuthBeginView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=("password_ok",))

    def post(self, request):
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(OPERATOR, s, a, require_uv=True))
        except webauthn_.WebAuthnError:
            return _err("no_credentials")


class WebAuthnAuthCompleteView(NgrcAPIView):
    ngrc_policy = Policy("operator_session", stages=("password_ok",))

    def post(self, request):
        d = CredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = flow.mfa_retry_after(OPERATOR, a, _ip(request))
        if wait:
            r = _err("throttled", 429)
            r["Retry-After"] = str(wait)
            return r
        try:
            webauthn_.complete_authentication(OPERATOR, s, a, d.validated_data["credential"], require_uv=True)
        except webauthn_.WebAuthnError as exc:
            if exc.code == "counter_regression":
                audit.emit_platform("ops", "auth.webauthn.counter_regression", actor_type="operator", actor_id=a.id, result="failure")
            flow.mfa_failed(OPERATOR, a, _ip(request), "webauthn")
            return _err("invalid_assertion", 401)
        return _with_cookie(Response({"stage": "active"}), flow.mfa_succeeded(OPERATOR, s, a, "webauthn"))


class StepUpBeginView(NgrcAPIView):
    ngrc_policy = Policy("operator_session")

    def post(self, request):
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(OPERATOR, s, a, require_uv=True, purpose="stepup", binding="T1"))
        except webauthn_.WebAuthnError:
            return _err("no_credentials")


class StepUpCompleteView(NgrcAPIView):
    ngrc_policy = Policy("operator_session")

    def post(self, request):
        d = CredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        try:
            webauthn_.complete_authentication(OPERATOR, s, a, d.validated_data["credential"], require_uv=True, purpose="stepup",
                                              binding="T1")
        except webauthn_.WebAuthnError:
            _emit("platform.operator.stepup.failure", request, result="denied", details={"tier": "T1", "binding": "T1"})
            return _err("invalid_assertion", 401)
        sessions.mark_step_up(OPERATOR, s, "webauthn")
        _emit("platform.operator.stepup.success", request, details={"tier": "T1", "binding": "T1"})
        return Response({"status": "ok", "valid_for_seconds": settings.STEP_UP_T1_WINDOW_S})


# ------------------------------------------------------------------------------------------------------ tenants
class TenantProvisionSerializer(serializers.Serializer):
    slug = serializers.SlugField(max_length=63)
    name = serializers.CharField(max_length=200)
    owner_email = serializers.EmailField(max_length=254)


class TenantListView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.support.read")

    def get(self, request):
        rows = Tenant.objects.using("ops").order_by("name")
        return Response({"tenants": [{"id": str(t.id), "slug": t.slug, "name": t.name, "status": t.status} for t in rows]})

    def post(self, request):
        self.require(request, "platform.tenants.provision", step_up="T1")
        d = TenantProvisionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        v = d.validated_data
        raw = new_token()
        roles = [{"key": k, "name": r["name"], "permissions": r["permissions"]} for k, r in perm.SYSTEM_ROLES.items()]
        import json

        try:
            with transaction.atomic(using="ops"), connections["ops"].cursor() as cur:
                cur.execute("SELECT plt_provision_tenant(%s,%s,%s,%s,%s,%s::jsonb)",
                            [v["slug"], v["name"], v["owner_email"].lower(), hash_token(raw),
                             clock.now() + timedelta(seconds=settings.INVITATION_TTL_S), json.dumps(roles)])
                tid = cur.fetchone()[0]
        except IntegrityError:
            return _err("slug_exists", 409)
        send_mail("Your NsureGRC workspace is ready",
                  f"Accept your Owner invitation: {settings.PUBLIC_BASE_URL}/accept-invitation#token={raw}\nThis link expires in 7 days.",
                  None, [v["owner_email"].lower()], fail_silently=False)
        _emit("platform.tenant.provisioned", request, tenant_id=tid, object_type="tenant", object_id=str(tid),
              details={"slug": v["slug"]})
        return Response({"id": str(tid), "slug": v["slug"]}, status=201)  # the invitation token is never returned


# ------------------------------------------------------------------------------------------------------ support grants
def _grant_json(g: SupportAccessGrant) -> dict:
    iso = lambda x: x.isoformat() if x else None  # noqa: E731
    return {"id": str(g.id), "tenant_id": str(g.subject_tenant_id), "requester_id": str(g.requester_id), "ticket_ref": g.ticket_ref,
            "reason": g.reason, "profile": g.profile, "scope": g.scope, "duration_minutes": g.duration_minutes,
            "break_glass": g.break_glass, "state": g.state, "approved_at": iso(g.approved_at), "consented_at": iso(g.consented_at),
            "activated_at": iso(g.activated_at), "expires_at": iso(g.expires_at), "ended_at": iso(g.ended_at)}


class GrantRequestSerializer(serializers.Serializer):
    tenant_id = serializers.UUIDField()
    ticket_ref = serializers.CharField(max_length=100)
    reason = serializers.CharField(max_length=2000)
    profile = serializers.ChoiceField(choices=[c for c, _ in SupportAccessGrant.Profile.choices],
                                      default="diagnostic_metadata")
    scope = serializers.ListField(child=serializers.CharField(max_length=64), max_length=32, default=list)
    duration_minutes = serializers.IntegerField(min_value=1, required=False)
    break_glass = serializers.BooleanField(default=False)


class GrantListView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.support.read")

    def get(self, request):
        qs = SupportAccessGrant.objects.using("ops").order_by("-created_at")[:200]
        return Response({"grants": [_grant_json(g) for g in qs]})

    def post(self, request):
        self.require(request, "platform.support.request", step_up="T1")
        d = GrantRequestSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        v = d.validated_data
        if v["break_glass"]:
            self.require(request, "platform.breakglass.request", step_up="T1")
        if v["profile"] == "diagnostic_metadata" and v["scope"]:
            return _err("scope_not_allowed_for_profile")
        if not Tenant.objects.using("ops").filter(id=v["tenant_id"]).exists():
            return _err("tenant_not_found", 404)
        minutes = v.get("duration_minutes") or (settings.BREAK_GLASS_MAX_MINUTES if v["break_glass"] else settings.SUPPORT_GRANT_DEFAULT_MINUTES)
        a = OperatorSession.objects.using("ops").get(pk=request.user.session_id).account
        try:
            with transaction.atomic(using="ops"):
                g = SupportAccessGrant.objects.using("ops").create(
                    subject_tenant_id=v["tenant_id"], requester=a, ticket_ref=v["ticket_ref"].strip(), reason=v["reason"].strip(),
                    profile=v["profile"], scope=v["scope"], duration_minutes=minutes, break_glass=v["break_glass"])
        except Exception as exc:  # noqa: BLE001 - DB guard rejects empty ticket/reason, excess duration, unauthorised requester
            log.info("support grant request rejected: %s", type(exc).__name__)
            return _err("grant_rejected", 400)
        if g.break_glass:
            _emit("platform.breakglass.requested", request, tenant_id=g.subject_tenant_id, grant_id=g.id, object_type="support_grant",
                  object_id=str(g.id), details={"ticket_ref": g.ticket_ref})
        _emit("platform.support.requested", request, tenant_id=g.subject_tenant_id, grant_id=g.id, object_type="support_grant",
              object_id=str(g.id), details={"profile": g.profile, "ticket_ref": g.ticket_ref, "break_glass": g.break_glass})
        audit.emit_tenant("ops", "support.grant.requested", g.subject_tenant_id, actor_type="operator", actor_id=request.user.account_id,
                          grant_id=g.id, object_type="support_grant", object_id=str(g.id),
                          details={"profile": g.profile, "break_glass": g.break_glass})
        return Response(_grant_json(g), status=201)


def _grant_or_404(pk):
    return SupportAccessGrant.objects.using("ops").filter(pk=pk).first()


def _require_approver_for(view, request, g) -> None:
    """Route policy admits any approver role; the permission needed depends on the step of the ceremony:
    ordinary grant / first break-glass approver => Platform Security (`support.approve`);
    second break-glass approver => Platform Admin (`breakglass.approve` + role checked again at the decision)."""
    if not g.break_glass or g.approver_id is None:
        view.require(request, "platform.support.approve")
    else:
        view.require(request, "platform.breakglass.approve")


class GrantApproveBeginView(NgrcAPIView):
    """T2: the approver first obtains a WebAuthn challenge bound to THIS grant id."""

    ngrc_policy = Policy("operator", "platform.breakglass.approve")

    def post(self, request, pk):
        g = _grant_or_404(pk)
        if g is None:
            return _err("not_found", 404)
        _require_approver_for(self, request, g)
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(OPERATOR, s, a, require_uv=True, purpose="stepup",
                                                             binding=f"support.approve:{g.id}"))
        except webauthn_.WebAuthnError:
            return _err("no_credentials")


class GrantApproveView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.breakglass.approve")

    def post(self, request, pk):
        d = CredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        g = _grant_or_404(pk)
        if g is None:
            return _err("not_found", 404)
        _require_approver_for(self, request, g)
        s, a = _session_account(request)
        if g.requester_id == a.id:
            self.deny(request, "platform.support.approve", "self_approval")
        if g.state != "requested":
            return _err("illegal_transition", 409)
        try:  # per-action assertion whose challenge is bound to this grant (no reuse, no other grant, no T1 reuse)
            webauthn_.complete_authentication(OPERATOR, s, a, d.validated_data["credential"], require_uv=True, purpose="stepup",
                                              binding=f"support.approve:{g.id}")
        except webauthn_.WebAuthnError:
            _emit("platform.operator.stepup.failure", request, result="denied", details={"tier": "T2", "binding": "support.approve"})
            return _err("invalid_assertion", 401)
        _emit("platform.operator.stepup.success", request, details={"tier": "T2", "binding": "support.approve"})
        now = clock.now()
        roles = request.user.operator_roles
        U = SupportAccessGrant.objects.using("ops").filter(pk=g.pk)
        try:
            with transaction.atomic(using="ops"):
                if not g.break_glass:
                    U.update(state="approved", approver_id=a.id, approved_at=now)
                    outcome = "approved"
                elif g.approver_id is None:  # first of two approvers (Platform Security)
                    U.update(approver_id=a.id, approved_at=now)
                    outcome = "awaiting_second_approver"
                else:  # second approver must be a different person holding Platform Admin
                    if a.id == g.approver_id or "platform_admin" not in roles:
                        self.deny(request, "platform.breakglass.approve", "second_approver_invalid")
                    U.update(second_approver_id=a.id, state="approved")
                    outcome = "approved"
        except Exception as exc:  # noqa: BLE001 - DB separation-of-duties guard
            if exc.__class__.__name__ == "PermissionDenied":
                raise
            log.info("support approval rejected by database guard: %s", type(exc).__name__)
            return _err("approval_rejected", 403)
        action = "platform.breakglass.approved" if g.break_glass else "platform.support.approved"
        _emit(action, request, tenant_id=g.subject_tenant_id, grant_id=g.id, object_type="support_grant", object_id=str(g.id),
              **({} if g.break_glass else {"details": {"break_glass": False}}))
        if outcome == "approved":
            audit.emit_tenant("ops", "support.grant.approved", g.subject_tenant_id, actor_type="operator", actor_id=a.id, grant_id=g.id,
                              object_type="support_grant", object_id=str(g.id), details={"break_glass": g.break_glass})
        return Response({"status": outcome})


class GrantActivateView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.support.use")

    def post(self, request, pk):
        self.require(request, "platform.support.use", step_up="T1")
        g = _grant_or_404(pk)
        if g is None or g.requester_id != request.user.account_id:
            return _err("not_found", 404)
        ready = (g.state == "tenant_consented") or (g.state == "approved" and g.break_glass)
        if not ready:
            return _err("illegal_transition", 409)
        now = clock.now()
        try:
            with transaction.atomic(using="ops"):
                SupportAccessGrant.objects.using("ops").filter(pk=g.pk).update(
                    state="active", activated_at=now, expires_at=now + timedelta(minutes=g.duration_minutes))
        except Exception as exc:  # noqa: BLE001
            log.info("support activation rejected by database guard: %s", type(exc).__name__)
            return _err("illegal_transition", 409)
        _emit("platform.support.activated", request, tenant_id=g.subject_tenant_id, grant_id=g.id, object_type="support_grant",
              object_id=str(g.id), details={"profile": g.profile, "break_glass": g.break_glass})
        return Response(_grant_json(_grant_or_404(g.pk)))


class SupportSessionStartView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.support.use")

    def post(self, request, pk):
        g = _grant_or_404(pk)
        if g is None or g.requester_id != request.user.account_id:
            return _err("not_found", 404)
        if g.state != "active" or g.expires_at is None or g.expires_at <= clock.now():
            self.deny(request, "platform.support.use", "grant_inactive")
        s, _a = _session_account(request)
        if s.support_grant_id is not None:
            return _err("support_session_already_open", 409)
        OperatorSession.objects.using("ops").filter(pk=s.pk).update(
            support_grant_id=g.id, expires_at=min(s.expires_at, g.expires_at))
        s.support_grant_id = g.id
        raw = sessions.rotate(OPERATOR, s)
        audit.emit_tenant("ops", "support.session.started", g.subject_tenant_id, actor_type="operator", actor_id=request.user.account_id,
                          grant_id=g.id, details={"profile": g.profile})
        return _with_cookie(Response({"status": "ok", "tenant_id": str(g.subject_tenant_id), "expires_at": g.expires_at.isoformat()}), raw)


class SupportSessionEndView(NgrcAPIView):
    """Runs inside the grant (operator_support) so it is tenant-bound and re-validated; unbinds the session and ends the grant."""

    ngrc_policy = Policy("operator_support", "support.diagnostics.read")

    def post(self, request):
        p = request.user
        request._request.ngrc_skip_support_action = True  # this view records its own, more specific events
        OperatorSession.objects.using("ops").filter(pk=p.session_id).update(support_grant_id=None)
        n = SupportAccessGrant.objects.using("ops").filter(pk=p.grant_id, state="active").update(
            state="revoked", ended_at=clock.now(), ended_by_type="operator")
        audit.emit_tenant("ops", "support.session.ended", p.tenant_id, actor_type="operator", actor_id=p.account_id, grant_id=p.grant_id,
                          details={"by": "operator"})
        if n:
            audit.emit_platform("ops", "platform.support.ended", actor_type="operator", actor_id=p.account_id, grant_id=p.grant_id,
                                tenant_id=p.tenant_id, details={"by": "operator", "state": "revoked"})
        return Response({"status": "ok"})


# ------------------------------------------------------------------------------------------------------ inside a grant
class TenantDiagnosticsView(NgrcAPIView):
    """diagnostic_metadata profile: platform-level metadata about the tenant. No tenant content."""

    ngrc_policy = Policy("operator_support", "support.diagnostics.read")
    ngrc_operation = "diagnostics.read"

    def get(self, request):
        from ngrc.tenancy.models import TenantRole

        t = Tenant.objects.using("default").get(id=request.user.tenant_id)
        return Response({"tenant": {"id": str(t.id), "slug": t.slug, "status": t.status}, "role_count": TenantRole.objects.count(),
                         "support_grant_id": str(request.user.grant_id)})


class TenantRolesView(NgrcAPIView):
    """read_limited profile (and above): tenant role definitions."""

    ngrc_policy = Policy("operator_support", "tenant.roles.read")
    ngrc_operation = "roles.read"

    def get(self, request):
        from ngrc.tenancy.models import TenantRole

        return Response({"roles": [{"key": r.key, "name": r.name, "permissions": r.permissions} for r in TenantRole.objects.order_by("key")]})


# ------------------------------------------------------------------------------------------------------ platform audit
class PlatformAuditView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.audit.read")

    def get(self, request):
        try:
            after = max(0, int(request.query_params.get("after_seq", 0)))
            limit = min(500, max(1, int(request.query_params.get("limit", 100))))
        except ValueError:
            return _err("invalid_request")
        with connections["audit_reader"].cursor() as cur:
            cur.execute("SELECT seq, occurred_at, actor_type, actor_id::text, action, result, reason_code, related_tenant_id::text, "
                        "encode(hash,'hex') FROM audit.platform_event WHERE seq > %s ORDER BY seq LIMIT %s", [after, limit])
            rows = cur.fetchall()
        _emit("platform.audit.read", request, details={"count": len(rows)})
        return Response({"events": [{"seq": r[0], "occurred_at": r[1].isoformat(), "actor_type": r[2], "actor_id": r[3], "action": r[4],
                                     "result": r[5], "reason_code": r[6], "related_tenant_id": r[7], "hash": r[8]} for r in rows]})


# ----------------------------------------------------------------- last-Owner recovery (F-ATH-015): Platform Security only
def _platform_recovery_requests() -> list[dict]:
    cols = ("id", "tenant_id", "tenant_name", "display_name", "email", "state", "created_at", "expires_at", "approved_at", "cooling_until")
    with connections["ops"].cursor() as cur:
        cur.execute("SELECT id, tenant_id, tenant_name, display_name, email, state, created_at, expires_at, approved_at, cooling_until "
                    "FROM plt_recovery_platform_list()")
        return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


class RecoveryListView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.recovery.approve")

    def get(self, request):
        iso = lambda d: d.isoformat() if d else None  # noqa: E731
        return Response({"requests": [{"id": str(r["id"]), "tenant": r["tenant_name"], "member": r["display_name"] or r["email"], "email": r["email"],
                                       "state": r["state"], "created_at": iso(r["created_at"]), "expires_at": iso(r["expires_at"]),
                                       "cooling_until": iso(r["cooling_until"])} for r in _platform_recovery_requests()]})


class RecoveryApproveBeginView(NgrcAPIView):
    """T2: the approver first obtains a WebAuthn challenge bound to THIS recovery request id."""

    ngrc_policy = Policy("operator", "platform.recovery.approve")

    def post(self, request, pk):
        if not any(str(r["id"]) == str(pk) for r in _platform_recovery_requests()):
            return _err("not_found", 404)
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(OPERATOR, s, a, require_uv=True, purpose="stepup", binding=f"recovery.approve:{pk}"))
        except webauthn_.WebAuthnError:
            return _err("no_credentials")


class RecoveryApproveView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.recovery.approve")

    def post(self, request, pk):
        d = CredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        if not any(str(r["id"]) == str(pk) for r in _platform_recovery_requests()):
            return _err("not_found", 404)
        s, a = _session_account(request)
        try:
            webauthn_.complete_authentication(OPERATOR, s, a, d.validated_data["credential"], require_uv=True, purpose="stepup",
                                              binding=f"recovery.approve:{pk}")
        except webauthn_.WebAuthnError:
            _emit("platform.operator.stepup.failure", request, result="denied", details={"tier": "T2", "binding": "recovery.approve"})
            return _err("invalid_assertion", 401)
        _emit("platform.operator.stepup.success", request, details={"tier": "T2", "binding": "recovery.approve"})
        try:
            with transaction.atomic(using="ops"), connections["ops"].cursor() as cur:
                cur.execute("SELECT account_id, cooling_until, email FROM plt_recovery_platform_decide(%s::uuid, %s::uuid, 'approve')", [str(pk), str(a.id)])
                account_id, cooling_until, email = cur.fetchone()
        except Exception:  # noqa: BLE001 - function raises 42501: not Platform Security / wrong state
            self.deny(request, "platform.recovery.approve", "decision_refused")
        _emit("auth.recovery.approved", request, object_type="recovery_request", object_id=str(pk), details={"kind": "last_owner"})
        send_mail("Your NsureGRC sign-in recovery was approved",
                      f"NsureGRC Platform Security approved your recovery. You can complete it after {cooling_until.isoformat()}. If you did not ask for "
                      "this, cancel it now with the link in the earlier e-mail, or sign in and cancel it from your account.", None, [email], fail_silently=True)
        _ = account_id
        return Response({"status": "ok", "cooling_until": cooling_until.isoformat()})


class RecoveryDenyView(NgrcAPIView):
    ngrc_policy = Policy("operator", "platform.recovery.approve", step_up="T1")

    def post(self, request, pk):
        _s, a = _session_account(request)
        try:
            with transaction.atomic(using="ops"), connections["ops"].cursor() as cur:
                cur.execute("SELECT account_id, cooling_until, email FROM plt_recovery_platform_decide(%s::uuid, %s::uuid, 'deny')", [str(pk), str(a.id)])
                cur.fetchone()
        except Exception:  # noqa: BLE001
            return _err("illegal_transition", 409)
        _emit("auth.recovery.denied", request, object_type="recovery_request", object_id=str(pk), details={"kind": "last_owner"})
        return Response({"status": "ok"})
