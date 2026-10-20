"""Customer-realm authentication API (D-P0-008). Every view declares an explicit Policy; CSRF is enforced on all unsafe methods."""
from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction
from django.middleware.csrf import get_token
from rest_framework import serializers
from rest_framework.response import Response

from ngrc.audit import service as audit
from ngrc.authn import flow, passwords, recovery, sessions, throttle, totp, webauthn_
from ngrc.authn.realms import CUSTOMER
from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.core import clock
from ngrc.core.crypto import keyed_identifier_hash
from ngrc.core.net import normalize_ip

from . import recovery_service as rs
from . import services
from .models import Session

log = logging.getLogger("ngrc.iam")
ANY_STAGE = ("password_ok", "enroll_mfa", "active")


def _ip(request):
    return normalize_ip(request.META.get("REMOTE_ADDR"))


def _ua(request):
    return request.META.get("HTTP_USER_AGENT", "")[:256]


def _session_account(request):
    s = Session.objects.using("auth").select_related("account").get(pk=request.user.session_id)
    return s, s.account


def _uv(account) -> bool:
    """D-P0-008 s7.2: userVerification is REQUIRED for tenant privileged roles (preferred otherwise)."""
    from ngrc.authz.permissions import is_privileged

    return any(is_privileged(m["permissions"]) for m in services.list_memberships(account.id))


def _with_cookie(response: Response, raw: str) -> Response:
    sessions.set_cookie(response, CUSTOMER, raw)
    return response


def _throttled(wait: int) -> Response:
    r = Response({"error": "throttled", "retry_after": wait}, status=429)
    r["Retry-After"] = str(wait)
    return r


def _audit_both(account, action: str, session=None, **kw):
    """Identity-level event: always the platform stream; also the tenant stream when a tenant is selected."""
    audit.emit_platform("auth", action, actor_id=account.id, **kw)
    if session is not None and getattr(session, "active_tenant_id", None):
        audit.emit_tenant("auth", action, session.active_tenant_id, actor_id=account.id, **kw)


def _enrolment_reserved(s, a) -> bool:
    """After a COMPLETED lost-factor recovery the account has no factor; for a short window only the session that completed it may enrol one, so that
    someone who merely knows the password cannot log in and enrol first. (A partial mitigation: after the window, or for a user who loses that session,
    enrolment is again possible with the password alone - the same as for any brand-new account.)"""
    from datetime import timedelta

    from django.db.models import DateTimeField, ExpressionWrapper
    from django.db.models.functions import Now

    from .models import RecoveryRequest

    if s.stage != "enroll_mfa" or "recovery_enrolment" in (s.auth_methods or []):
        return False
    since = ExpressionWrapper(Now() - timedelta(seconds=int(settings.RECOVERY_ENROLMENT_WINDOW_S)), output_field=DateTimeField())
    return RecoveryRequest.objects.using("auth").filter(account=a, state="completed", ended_at__gte=since).exists()


_RESERVED = {"error": "recovery_enrolment_reserved"}


# --------------------------------------------------------------------------------------------- public
class CsrfView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="issues a CSRF token; no data access")

    def get(self, request):
        return Response({"csrfToken": get_token(request._request)})


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=254)
    password = serializers.CharField(max_length=1024, trim_whitespace=False)


class LoginView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="credential submission endpoint; throttled, uniform responses")

    def post(self, request):
        data = LoginSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        res = flow.password_login(CUSTOMER, data.validated_data["email"], data.validated_data["password"],
                                  ip=_ip(request), user_agent=_ua(request))
        if res.status == "throttled":
            return _throttled(res.retry_after)
        if res.status != "ok":
            return Response({"error": "invalid_credentials"}, status=401)
        return _with_cookie(Response({"stage": res.stage, "methods": ["totp", "webauthn", "recovery"] if res.stage == "password_ok"
                                      else ["totp", "webauthn"]}), res.raw_token)


class ResetRequestView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="password reset request; generic response, rate limited")

    def post(self, request):
        s = serializers.Serializer(data=request.data)
        email = flow.normalize_email(str(request.data.get("email", "")) if isinstance(request.data, dict) else "")
        _ = s
        wait = throttle.retry_after(CUSTOMER, email, _ip(request), scope="reset")
        if not wait:
            throttle.record_failure(CUSTOMER, email, _ip(request), scope="reset")  # counts requests (not failures)
            audit.emit_platform("auth", "auth.password.reset_requested", actor_type="anonymous",
                                details={"identifier_hash": keyed_identifier_hash(email)})
            account = services.Account.objects.using("auth").filter(email=email).exclude(status="disabled").first() if email else None
            if account is not None:
                services.send_reset_email(account)
        return Response({"status": "accepted"}, status=202)  # identical for known / unknown / throttled


class ResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)
    new_password = serializers.CharField(max_length=1024, trim_whitespace=False)


class ResetConfirmView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="completes password reset with a single-use token")

    def post(self, request):
        d = ResetConfirmSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        raw, new_pw = d.validated_data["token"], d.validated_data["new_password"]
        acct = services.peek_token(raw, "password_reset")
        if acct is None:
            return Response({"error": "invalid_token"}, status=400)
        try:  # validate BEFORE consuming so a weak password does not burn the token
            passwords.check_policy(new_pw, context_terms=services.context_terms(acct.email, acct.display_name))
        except passwords.PolicyViolation as exc:
            return Response({"error": "invalid_password", "reason": exc.code}, status=400)
        acct = services.consume_token(raw, "password_reset")
        if acct is None:
            return Response({"error": "invalid_token"}, status=400)  # replay / race lost
        with transaction.atomic(using="auth"):
            services.set_password(acct, new_pw)
            now = clock.now()
            fields = {"status": "active"}
            if acct.email_verified_at is None:
                fields["email_verified_at"] = now  # mailbox control proven by the reset link
            if acct.status != "disabled":
                services.Account.objects.using("auth").filter(pk=acct.pk).update(**fields)
            sessions.revoke_all(CUSTOMER, acct.id, reason="password_reset")
            services.AuthToken.objects.using("auth").filter(account=acct, purpose="password_reset", used_at__isnull=True).update(used_at=now)
        audit.emit_platform("auth", "auth.password.reset_completed", actor_id=acct.id)
        services.send_notice(acct, "Your NsureGRC password was reset",
                             "Your password was just reset. MFA is still required at sign-in. If this was not you, contact your administrator.")
        return Response({"status": "ok"})


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)


class VerifyEmailView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="email verification with a single-use token")

    def post(self, request):
        d = VerifyEmailSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        acct = services.consume_token(d.validated_data["token"], "verify_email")
        if acct is None:
            return Response({"error": "invalid_token"}, status=400)
        services.Account.objects.using("auth").filter(pk=acct.pk, status="pending").update(status="active", email_verified_at=clock.now())
        services.Account.objects.using("auth").filter(pk=acct.pk, email_verified_at__isnull=True).update(email_verified_at=clock.now())
        audit.emit_platform("auth", "auth.email.verified", actor_id=acct.id)
        return Response({"status": "ok"})


class AcceptInvitationSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)
    password = serializers.CharField(max_length=1024, trim_whitespace=False, required=False, allow_blank=True)
    display_name = serializers.CharField(max_length=200, required=False, allow_blank=True)


class AcceptInvitationView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="invitation acceptance; token proves mailbox control; existing users must be signed in")

    def post(self, request):
        d = AcceptInvitationSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        inv = services.get_usable_invitation(d.validated_data["token"])
        if inv is None:
            return Response({"error": "invalid_token"}, status=400)
        existing = services.Account.objects.using("auth").filter(email=inv.email).first()
        if existing is not None:
            p = getattr(request._request, "ngrc_principal", None)
            if p is None or p.stage != "active" or p.account_id != existing.id:
                return Response({"error": "sign_in_required"}, status=401)
            account = existing
        else:
            try:
                account = services.create_account(inv.email, d.validated_data.get("password") or "",
                                                  d.validated_data.get("display_name", ""), verified=True)
            except services.ServiceError as exc:
                return Response({"error": "invalid_password", "reason": exc.code}, status=400)
        try:
            services.accept_invitation(inv, account)
        except Exception:  # noqa: BLE001 - e.g. already a member / lost race; generic response
            return Response({"error": "invalid_token"}, status=400)
        from ngrc.tenancy.roles import role_key_for

        key = role_key_for(inv.subject_tenant_id, inv.role_id, account.id)
        audit.emit_platform("auth", "auth.invitation.accepted", actor_id=account.id, tenant_id=inv.subject_tenant_id,
                            details={"role_key": key})
        audit.emit_tenant("auth", "auth.invitation.accepted", inv.subject_tenant_id, actor_id=account.id,
                          details={"role_key": key})
        return Response({"status": "ok", "tenant_id": str(inv.subject_tenant_id)}, status=201)


# --------------------------------------------------------------------------------------------- session-scoped
class SessionView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=ANY_STAGE)

    def get(self, request):
        s, a = _session_account(request)
        return Response({"stage": s.stage, "account": {"id": str(a.id), "email": a.email, "display_name": a.display_name},
                         "tenant_id": str(s.active_tenant_id) if s.active_tenant_id else None,
                         "expires_at": s.expires_at.isoformat(), "auth_methods": s.auth_methods})


class LogoutView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=ANY_STAGE)

    def post(self, request):
        s, a = _session_account(request)
        sessions.revoke(CUSTOMER, s, "logout")
        audit.emit_platform("auth", "auth.logout", actor_id=a.id)
        r = Response({"status": "ok"})
        sessions.clear_cookie(r, CUSTOMER)
        return r


class CodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=64)


def _finish_mfa(request, s, a, method: str) -> Response:
    raw = flow.mfa_succeeded(CUSTOMER, s, a, method)
    return _with_cookie(Response({"stage": "active"}), raw)


class TotpVerifyView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))

    def post(self, request):
        d = CodeSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = flow.mfa_retry_after(CUSTOMER, a, _ip(request))
        if wait:
            return _throttled(wait)
        result = totp.verify(a, d.validated_data["code"])
        if result == "ok":
            return _finish_mfa(request, s, a, "totp")
        if result == "replay":
            audit.emit_platform("auth", "auth.totp.replay_rejected", actor_id=a.id, result="denied")
        flow.mfa_failed(CUSTOMER, a, _ip(request), "totp")
        return Response({"error": "invalid_code"}, status=401)


class RecoveryVerifyView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))

    def post(self, request):
        d = CodeSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = flow.mfa_retry_after(CUSTOMER, a, _ip(request))
        if wait:
            return _throttled(wait)
        if recovery.consume(a, d.validated_data["code"]):
            audit.emit_platform("auth", "auth.recovery_codes.used", actor_id=a.id)
            r = _finish_mfa(request, s, a, "recovery")
            r.data["recovery_codes_remaining"] = recovery.remaining(a)
            services.send_notice(a, "A NsureGRC recovery code was used", "A recovery code was used to sign in to your account.")
            return r
        audit.emit_platform("auth", "auth.recovery_codes.failed", actor_id=a.id, result="denied")
        flow.mfa_failed(CUSTOMER, a, _ip(request), "recovery")
        return Response({"error": "invalid_code"}, status=401)


class WebAuthnAuthBeginView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))

    def post(self, request):
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(CUSTOMER, s, a, require_uv=_uv(a)))
        except webauthn_.WebAuthnError:
            return Response({"error": "no_credentials"}, status=400)


class WebAuthnCredentialSerializer(serializers.Serializer):
    credential = serializers.DictField()
    nickname = serializers.CharField(max_length=100, required=False, allow_blank=True)


class WebAuthnAuthCompleteView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))

    def post(self, request):
        d = WebAuthnCredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = flow.mfa_retry_after(CUSTOMER, a, _ip(request))
        if wait:
            return _throttled(wait)
        try:
            webauthn_.complete_authentication(CUSTOMER, s, a, d.validated_data["credential"], require_uv=_uv(a))
        except webauthn_.WebAuthnError as exc:
            if exc.code == "counter_regression":
                audit.emit_platform("auth", "auth.webauthn.counter_regression", actor_id=a.id, result="failure")
            flow.mfa_failed(CUSTOMER, a, _ip(request), "webauthn")
            return Response({"error": "invalid_assertion"}, status=401)
        return _finish_mfa(request, s, a, "webauthn")


# ------------------------------------------------------------ enrolment (allowed while enrolling or when fully signed in)
class TotpEnrollBeginView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("enroll_mfa", "active"), step_up=None)

    def post(self, request):
        s, a = _session_account(request)
        if _enrolment_reserved(s, a):
            return Response(_RESERVED, status=403)
        if s.stage == "active":
            from ngrc.authz.policy import Denied, require_recent_step_up
            try:
                require_recent_step_up(request.user, "T1")
            except Denied:
                return Response({"error": "forbidden"}, status=403)
        secret, uri = totp.begin_enrollment(a)
        return Response({"secret": secret, "otpauth_uri": uri})  # shown once; stored sealed


class TotpEnrollConfirmView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("enroll_mfa", "active"))

    def post(self, request):
        d = CodeSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        if _enrolment_reserved(s, a):
            return Response(_RESERVED, status=403)
        wait = flow.mfa_retry_after(CUSTOMER, a, _ip(request))
        if wait:
            return _throttled(wait)
        if not totp.confirm_enrollment(a, d.validated_data["code"]):
            flow.mfa_failed(CUSTOMER, a, _ip(request), "totp")
            return Response({"error": "invalid_code"}, status=400)
        _audit_both(a, "auth.mfa.enrolled", session=s, details={"method": "totp"})
        codes = None
        if recovery.remaining(a) == 0:
            codes = recovery.generate(a)
            _audit_both(a, "auth.recovery_codes.generated", session=s)
        if s.stage == "enroll_mfa":
            resp = _finish_mfa(request, s, a, "totp")
        else:
            resp = Response({"stage": "active"})
        if codes:
            resp.data["recovery_codes"] = codes  # shown exactly once
        return resp


class WebAuthnRegisterBeginView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("enroll_mfa", "active"))

    def post(self, request):
        s, a = _session_account(request)
        if _enrolment_reserved(s, a):
            return Response(_RESERVED, status=403)
        if s.stage == "active":
            from ngrc.authz.policy import Denied, require_recent_step_up
            try:
                require_recent_step_up(request.user, "T1")
            except Denied:
                return Response({"error": "forbidden"}, status=403)
        return Response(webauthn_.registration_options(CUSTOMER, s, a, require_uv=_uv(a)))


class WebAuthnRegisterCompleteView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("enroll_mfa", "active"))

    def post(self, request):
        d = WebAuthnCredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        if _enrolment_reserved(s, a):
            return Response(_RESERVED, status=403)
        try:
            webauthn_.complete_registration(CUSTOMER, s, a, d.validated_data["credential"], require_uv=_uv(a),
                                            nickname=d.validated_data.get("nickname", ""))
        except webauthn_.WebAuthnError:
            return Response({"error": "registration_failed"}, status=400)
        _audit_both(a, "auth.webauthn.registered", session=s)
        _audit_both(a, "auth.mfa.enrolled", session=s, details={"method": "webauthn"})
        codes = None
        if recovery.remaining(a) == 0:
            codes = recovery.generate(a)
            _audit_both(a, "auth.recovery_codes.generated", session=s)
        resp = _finish_mfa(request, s, a, "webauthn") if s.stage == "enroll_mfa" else Response({"stage": "active"})
        if codes:
            resp.data["recovery_codes"] = codes
        return resp


# ------------------------------------------------------------------------------------------- fully authenticated
class TenantsView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def get(self, request):
        return Response({"tenants": [{"tenant_id": str(m["tenant_id"]), "slug": m["slug"], "name": m["name"], "role": m["role"]}
                                     for m in services.list_memberships(request.user.account_id)]})


class SelectTenantSerializer(serializers.Serializer):
    tenant_id = serializers.UUIDField()


class SelectTenantView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def post(self, request):
        d = SelectTenantSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        m = services.find_membership(a.id, d.validated_data["tenant_id"])
        if m is None:
            audit.emit_denied(permission="session.select_tenant", route=request.path, reason="not_a_member",
                              actor_id=a.id, using="autonomous")
            return Response({"error": "forbidden"}, status=403)
        from ngrc.authz.permissions import is_privileged

        raw = sessions.set_tenant(CUSTOMER, s, m["tenant_id"], privileged=is_privileged(m["permissions"]))
        audit.emit_tenant("auth", "auth.session.tenant_selected", m["tenant_id"], actor_id=a.id)
        return _with_cookie(Response({"tenant_id": str(m["tenant_id"]), "role": m["role"]}), raw)


class StepUpSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=["totp", "recovery"])
    code = serializers.CharField(max_length=64)


class StepUpView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def post(self, request):
        d = StepUpSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = flow.mfa_retry_after(CUSTOMER, a, _ip(request))
        if wait:
            return _throttled(wait)
        method, code = d.validated_data["method"], d.validated_data["code"]
        ok = (totp.verify(a, code) == "ok") if method == "totp" else recovery.consume(a, code)
        if not ok:
            flow.mfa_failed(CUSTOMER, a, _ip(request), method)
            audit.emit_platform("auth", "auth.stepup.failure", actor_id=a.id, result="denied",
                                details={"tier": "T1", "method": method})
            return Response({"error": "invalid_code"}, status=401)
        sessions.mark_step_up(CUSTOMER, s, method)
        _audit_both(a, "auth.stepup.success", session=s, details={"tier": "T1", "method": method})
        return Response({"status": "ok", "valid_for_seconds": 600})


class StepUpWebAuthnBeginView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def post(self, request):
        s, a = _session_account(request)
        try:
            return Response(webauthn_.authentication_options(CUSTOMER, s, a, require_uv=_uv(a), purpose="stepup", binding="T1"))
        except webauthn_.WebAuthnError:
            return Response({"error": "no_credentials"}, status=400)


class StepUpWebAuthnCompleteView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def post(self, request):
        d = WebAuthnCredentialSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        try:
            webauthn_.complete_authentication(CUSTOMER, s, a, d.validated_data["credential"], require_uv=_uv(a),
                                              purpose="stepup", binding="T1")
        except webauthn_.WebAuthnError:
            audit.emit_platform("auth", "auth.stepup.failure", actor_id=a.id, result="denied",
                                details={"tier": "T1", "method": "webauthn"})
            return Response({"error": "invalid_assertion"}, status=401)
        sessions.mark_step_up(CUSTOMER, s, "webauthn")
        _audit_both(a, "auth.stepup.success", session=s, details={"tier": "T1", "method": "webauthn"})
        return Response({"status": "ok", "valid_for_seconds": 600})


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=1024, trim_whitespace=False)
    new_password = serializers.CharField(max_length=1024, trim_whitespace=False)


class PasswordChangeView(NgrcAPIView):
    ngrc_policy = Policy("session", step_up="T1")

    def post(self, request):
        d = PasswordChangeSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = throttle.retry_after(CUSTOMER, a.email, _ip(request), scope="pwchange")
        if wait:
            return _throttled(wait)
        if not passwords.verify_password(a.password_hash, d.validated_data["current_password"]):
            throttle.record_failure(CUSTOMER, a.email, _ip(request), scope="pwchange")
            return Response({"error": "invalid_credentials"}, status=401)
        try:
            services.set_password(a, d.validated_data["new_password"])
        except passwords.PolicyViolation as exc:
            return Response({"error": "invalid_password", "reason": exc.code}, status=400)
        sessions.revoke_all(CUSTOMER, a.id, except_id=s.id, reason="password_changed")
        _audit_both(a, "auth.password.changed", session=s)
        services.send_notice(a, "Your NsureGRC password was changed", "Your password was changed. If this was not you, contact your administrator.")
        return Response({"status": "ok"})


# ----------------------------------------------------------------------------------------- MFA factors (F-ATH-014)
def _factor_rows(account) -> list[dict]:
    from .models import TotpFactor, WebAuthnCredential

    rows = [{"id": str(f.id), "method": "totp", "nickname": "", "created_at": f.created_at.isoformat(), "last_used_at": None, "usable": True}
            for f in TotpFactor.objects.using("auth").filter(account=account, confirmed_at__isnull=False).order_by("created_at")]
    rows += [{"id": str(w.id), "method": "webauthn", "nickname": w.nickname, "created_at": w.created_at.isoformat(),
              "last_used_at": w.last_used_at.isoformat() if w.last_used_at else None, "usable": not w.flagged_clone}
             for w in WebAuthnCredential.objects.using("auth").filter(account=account).order_by("created_at")]
    return rows


class FactorListView(NgrcAPIView):
    ngrc_policy = Policy("session")

    def get(self, request):
        _s, a = _session_account(request)
        return Response({"factors": _factor_rows(a), "recovery_codes_remaining": recovery.remaining(a)})


class FactorDetailView(NgrcAPIView):
    """Remove one of MY OWN factors (D-P0-008 s7): step-up, never the last usable factor, always >= 2 recovery options afterwards, every other
    session revoked, the caller's session id rotated, the user notified. The database refuses to delete the last usable factor even if this
    code were bypassed (trigger idn_factor_guard)."""

    ngrc_policy = Policy("session", step_up="T1")

    def delete(self, request, pk):
        from django.db import DatabaseError

        from .models import Account, TotpFactor, WebAuthnCredential

        s, a = _session_account(request)
        with transaction.atomic(using="auth"):
            Account.objects.using("auth").select_for_update().get(pk=a.pk)  # serialise concurrent removals for this account
            target, method = TotpFactor.objects.using("auth").filter(pk=pk, account=a, confirmed_at__isnull=False).first(), "totp"
            if target is None:
                target, method = WebAuthnCredential.objects.using("auth").filter(pk=pk, account=a).first(), "webauthn"
            if target is None:
                audit.emit_denied(permission="auth.mfa.remove", route=request.path, reason="factor_not_found", actor_id=a.id, using="autonomous")
                return Response({"error": "not_found"}, status=404)
            if method == "totp" or not target.flagged_clone:  # removing an UNUSABLE (cloned) credential never reduces what the user can do
                left = [f for f in _factor_rows(a) if f["usable"] and f["id"] != str(pk)]
                if not left:
                    return Response({"error": "last_factor"}, status=409)
                if len(left) + (1 if recovery.remaining(a) > 0 else 0) < 2:
                    return Response({"error": "recovery_options"}, status=409)
            try:
                with transaction.atomic(using="auth"):
                    target.delete()
            except DatabaseError:  # the trigger idn_factor_guard is the last line of defence
                return Response({"error": "last_factor"}, status=409)
        sessions.revoke_all(CUSTOMER, a.id, except_id=s.id, reason="mfa_factor_removed")
        raw = sessions.rotate(CUSTOMER, s)
        _audit_both(a, "auth.mfa.removed", session=s, details={"method": method})
        services.send_notice(a, "An authentication factor was removed from your NsureGRC account",
                             f"A {method} factor was removed and all your other sessions were signed out. If this was not you, contact your administrator.")
        return _with_cookie(Response({"status": "ok"}), raw)


# ----------------------------------------------------------------------------------------- lost-factor recovery (F-ATH-015)
class RecoveryStartSerializer(serializers.Serializer):
    tenant_id = serializers.UUIDField(required=False)


def _recovery_json(r) -> dict:
    return {"id": str(r.id), "kind": r.kind, "state": r.state, "expires_at": r.expires_at.isoformat(),
            "approved_at": r.approved_at.isoformat() if r.approved_at else None,
            "cooling_until": r.cooling_until.isoformat() if r.cooling_until else None, "can_complete": rs.can_complete(r)}


def _recovery_audit(a, action: str, tenant_id, kind: str, **extra):
    audit.emit_platform("auth", action, actor_id=a.id, tenant_id=tenant_id, details={"kind": kind, **extra})
    audit.emit_tenant("auth", action, tenant_id, actor_id=a.id, details={"kind": kind, **extra})


class RecoveryRequestView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))   # the PASSWORD was proven; the lost second factor is what is being replaced

    def post(self, request):
        d = RecoveryStartSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = throttle.retry_after(CUSTOMER, a.email, _ip(request), scope="recovery")
        if wait:
            return _throttled(wait)
        throttle.record_failure(CUSTOMER, a.email, _ip(request), scope="recovery")   # counts requests, not failures
        mems = services.list_memberships(a.id)
        wanted = d.validated_data.get("tenant_id")
        if wanted is not None:
            m = next((x for x in mems if x["tenant_id"] == wanted), None)
        elif len(mems) == 1:
            m = mems[0]
        else:
            return Response({"error": "tenant_required" if mems else "no_tenant"}, status=400)
        if m is None:
            audit.emit_denied(permission="auth.recovery.request", route=request.path, reason="not_a_member", actor_id=a.id, using="autonomous")
            return Response({"error": "forbidden"}, status=403)
        try:
            res = rs.start(a, m["tenant_id"], _ip(request))
        except rs.RecoveryError as exc:
            return Response({"error": exc.code}, status=409 if exc.code == "request_already_open" else 403)
        _recovery_audit(a, "auth.recovery.requested", m["tenant_id"], res["kind"])
        who = "A tenant Owner or Administrator" if res["kind"] == "admin_assisted" else "NsureGRC Platform Security"
        services.send_notice(a, "A recovery of your NsureGRC sign-in factors was requested",
                             f"Someone with your password asked to replace your lost second factor. {who} must approve it, followed by a "
                             f"{settings.RECOVERY_COOLING_OFF_S // 3600}-hour waiting period. If this was NOT you, cancel it now: "
                             f"{rs.cancel_link(res['cancel_token'])}")
        if res["kind"] == "admin_assisted":
            for addr in rs.approver_emails(res["id"]):
                services.send_mail_notice(addr, "A colleague needs a sign-in recovery approved",
                                          f"{a.display_name or a.email} asked to replace their second factor. Review and approve or deny it in NsureGRC "
                                          "(approval needs a fresh second-factor check). Approve only if you have confirmed it is really them.")
        return Response({"id": str(res["id"]), "kind": res["kind"], "expires_at": res["expires_at"].isoformat()}, status=201)


class RecoveryStatusView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok", "active"))

    def get(self, request):
        _s, a = _session_account(request)
        r = rs.latest(a)
        return Response({"request": _recovery_json(r) if r else None})


class RecoveryCompleteSerializer(serializers.Serializer):
    request_id = serializers.UUIDField()


class RecoveryCompleteView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok",))

    def post(self, request):
        d = RecoveryCompleteSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        s, a = _session_account(request)
        wait = throttle.retry_after(CUSTOMER, a.email, _ip(request), scope="recovery")
        if wait:
            return _throttled(wait)
        from .models import RecoveryRequest

        r = RecoveryRequest.objects.using("auth").filter(pk=d.validated_data["request_id"], account=a).first()
        if r is None:
            return Response({"error": "not_found"}, status=404)
        try:
            rs.complete(a, r.id)   # the database enforces: approved, cooling-off elapsed, not expired
        except rs.RecoveryError:
            throttle.record_failure(CUSTOMER, a.email, _ip(request), scope="recovery")
            return Response({"error": "not_ready"}, status=409)
        sessions.revoke_all(CUSTOMER, a.id, except_id=s.id, reason="recovery_completed")
        raw = sessions.demote_to_enrollment(CUSTOMER, s)
        _recovery_audit(a, "auth.recovery.completed", r.subject_tenant_id, r.kind)
        services.send_notice(a, "Your NsureGRC sign-in factors were reset",
                             "Your recovery was completed: your old factors and recovery codes were removed and all other sessions signed out. "
                             "Enrol a new factor now. If this was not you, contact your administrator immediately.")
        return _with_cookie(Response({"stage": "enroll_mfa"}), raw)


class RecoveryCancelSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=128)


class RecoveryCancelView(NgrcAPIView):
    ngrc_policy = Policy("public", reason="cancel link from the notification e-mail; possession of the single-use 256-bit token is the authorisation")

    def post(self, request):
        d = RecoveryCancelSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        ip = _ip(request) or "unknown"
        wait = throttle.retry_after(CUSTOMER, ip, ip, scope="rcancel")
        if wait:
            return _throttled(wait)
        found = rs.cancel_with_token(d.validated_data["token"])
        if found is None:
            throttle.record_failure(CUSTOMER, ip, ip, scope="rcancel")
            return Response({"error": "invalid_token"}, status=400)
        account_id, tenant_id, kind = found
        a = services.Account.objects.using("auth").get(pk=account_id)
        _recovery_audit(a, "auth.recovery.cancelled", tenant_id, kind, by="email_link")
        services.send_notice(a, "Your NsureGRC recovery request was cancelled", "The recovery request on your account was cancelled.")
        return Response({"status": "cancelled"})


class RecoveryCancelSessionView(NgrcAPIView):
    ngrc_policy = Policy("session", stages=("password_ok", "active"))

    def post(self, request, pk):
        s, a = _session_account(request)
        found = rs.cancel_for_account(pk, a.id)
        if found is None:
            return Response({"error": "not_found"}, status=404)
        tenant_id, kind = found
        _recovery_audit(a, "auth.recovery.cancelled", tenant_id, kind, by="session")
        return Response({"status": "cancelled"})
