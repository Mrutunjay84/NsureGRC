"""DRF integration: default-deny, declared route policies, CSRF on every unsafe method, tenant-scoped transactions,
atomic audit flush (Phase 1 steps 15-18, 25).

Every API view MUST subclass `NgrcAPIView` and declare `ngrc_policy`. The global DRF default is `DenyAll`, and the route
registry test fails the build for any route lacking a policy.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from django.db import transaction
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from rest_framework import exceptions, permissions
from rest_framework.views import APIView

from ngrc.audit import service as audit
from ngrc.core.context import tenant_context
from ngrc.core.errors import AuditWriteFailed, TenantContextError

from .drf_defaults import DenyAll, NgrcSessionAuthentication, exception_handler  # noqa: F401  (re-exported)
from .policy import Denied, authorize

log = logging.getLogger("ngrc.authz")
SAFE = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class Policy:
    """Declared access policy of a route.

    scope: public | session | tenant | operator_session | operator | operator_support
    permission: catalogue permission required (None only for public/session scopes that need no role)
    stages: authentication stages allowed (default: fully authenticated only)
    step_up: 'T1' to require a recent second-factor verification
    reason: mandatory justification for public routes
    """

    scope: str
    permission: str | None = None
    stages: tuple[str, ...] = ("active",)
    step_up: str | None = None
    reason: str = ""

    def __post_init__(self):
        if self.scope not in {"public", "session", "tenant", "operator_session", "operator", "operator_support"}:
            raise ValueError("invalid policy scope")
        if self.scope == "public" and not self.reason:
            raise ValueError("public routes must state a justification")
        if self.scope in {"tenant", "operator", "operator_support"} and not self.permission:
            raise ValueError("this scope requires a permission")


def _realm_using(principal) -> str:
    return "ops" if principal is not None and principal.kind == "operator" else "autonomous"


class PolicyPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        pol: Policy | None = getattr(view, "ngrc_policy", None)
        if pol is None:
            return False  # fail closed
        if pol.scope == "public":
            return True
        principal = request.user
        if principal is None:
            raise exceptions.NotAuthenticated()
        route = request.path
        try:
            if pol.scope in {"session", "tenant"} and principal.kind != "customer":
                raise Denied("realm_mismatch")
            if pol.scope in {"operator_session", "operator", "operator_support"} and principal.kind != "operator":
                raise Denied("realm_mismatch")
            if principal.stage not in pol.stages:
                raise Denied("insufficient_authentication_stage")
            if pol.scope == "tenant" and principal.tenant_id is None:
                raise Denied("no_tenant_selected")
            if pol.scope == "operator_support":
                from ngrc.control_plane.support import load_active_grant

                request._request.ngrc_support_grant = load_active_grant(principal)  # raises Denied
            if pol.permission:
                authorize(principal, pol.permission, step_up=pol.step_up)
            elif pol.step_up:  # session-scope routes can demand a recent second factor without a catalogue permission
                from .policy import require_recent_step_up

                require_recent_step_up(principal, pol.step_up)
        except Denied as d:
            tenant = principal.tenant_id if pol.scope in {"tenant", "operator_support"} else None
            audit.emit_denied(permission=pol.permission or pol.scope, route=route, reason=d.reason, tenant_id=tenant,
                              actor_id=principal.account_id, actor_type=principal.actor_type,
                              grant_id=principal.grant_id if principal.kind == "operator" else None,
                              using=_realm_using(principal))
            raise exceptions.PermissionDenied() from None
        except TenantContextError:
            raise exceptions.PermissionDenied() from None
        return True


def enforce_csrf(request) -> None:
    """Same mechanism DRF's SessionAuthentication uses: Django's CSRF check (token + Origin/Referer validation)."""
    check = CsrfViewMiddleware(lambda r: None)
    check.process_request(request)
    if check.process_view(request, None, (), {}) is not None:
        raise exceptions.PermissionDenied("CSRF failed")


class NgrcAPIView(APIView):
    ngrc_policy: Policy | None = None
    ngrc_operation: str = ""  # operator-support views: recorded in the `support.action` mirror event
    authentication_classes = [NgrcSessionAuthentication]
    permission_classes = [PolicyPermission]

    # -- CSRF is enforced on EVERY unsafe method, authenticated or not (login CSRF included)
    def initial(self, request, *args, **kwargs):
        if request.method not in SAFE:
            try:
                enforce_csrf(request._request)
            except exceptions.PermissionDenied:
                principal = getattr(request._request, "ngrc_principal", None)
                if principal is not None:  # audit only authenticated CSRF failures (avoid log flooding by anonymous callers)
                    audit.emit_denied(permission="csrf", route=request.path, reason="csrf_failed",
                                      tenant_id=None, actor_id=principal.account_id, actor_type=principal.actor_type,
                                      using=_realm_using(principal))
                raise
        super().initial(request, *args, **kwargs)

    def require(self, request, permission: str, *, step_up: str | None = None) -> None:
        """Additional in-handler authorisation (e.g. a mutation needing a stronger permission than the read policy)."""
        try:
            authorize(request.user, permission, step_up=step_up)
        except Denied as d:
            self.deny(request, permission, d.reason)

    def deny(self, request, permission: str, reason: str):
        p = request.user
        audit.emit_denied(permission=permission, route=request.path, reason=reason, tenant_id=p.tenant_id, actor_id=p.account_id,
                          actor_type=p.actor_type, using=_realm_using(p))
        raise exceptions.PermissionDenied()

    def dispatch(self, request, *args, **kwargs):
        pol = self.ngrc_policy
        principal = getattr(request, "ngrc_principal", None)
        tenant_id = None
        if pol is not None and principal is not None and principal.stage == "active":
            if pol.scope == "tenant" and principal.kind == "customer":
                tenant_id = principal.tenant_id
            elif pol.scope == "operator_support" and principal.kind == "operator" and principal.grant_id:
                tenant_id = principal.tenant_id
        if tenant_id is None:
            return super().dispatch(request, *args, **kwargs)
        try:
            with tenant_context(tenant_id, principal.account_id if principal.kind == "customer" else None):
                if pol.scope == "tenant":
                    with audit.unit_of_work(tenant_id) as uow:
                        response = super().dispatch(request, *args, **kwargs)
                        return self._finish_customer(response, uow)
                response = super().dispatch(request, *args, **kwargs)
                return self._finish_support(request, principal, response)
        except AuditWriteFailed:
            return JsonResponse({"error": "audit_unavailable"}, status=500)

    @staticmethod
    def _finish_customer(response, uow):
        """Business transaction + audit events commit together or not at all (C-4)."""
        if response.status_code >= 400:
            transaction.set_rollback(True)  # failed request leaves no partial state; denials are audited independently
            return response
        try:
            uow.flush()
        except AuditWriteFailed:
            transaction.set_rollback(True)
            return JsonResponse({"error": "audit_unavailable"}, status=500)
        return response

    def _finish_support(self, request, principal, response):
        if response.status_code >= 400:
            transaction.set_rollback(True)
            return response
        grant = getattr(request, "ngrc_support_grant", None)
        if getattr(request, "ngrc_skip_support_action", False):  # view recorded its own, more specific events (session end)
            return response
        try:
            with transaction.atomic(using="ops"):
                audit.emit_tenant("ops", "support.action", principal.tenant_id, actor_type="operator",
                                  actor_id=principal.account_id, grant_id=principal.grant_id,
                                  details={"operation": self.ngrc_operation or "read"})
                audit.emit_platform("ops", "platform.support.action", actor_type="operator", actor_id=principal.account_id,
                                    grant_id=principal.grant_id, tenant_id=principal.tenant_id,
                                    details={"operation": self.ngrc_operation or "read"})
        except AuditWriteFailed:
            transaction.set_rollback(True)
            return JsonResponse({"error": "audit_unavailable"}, status=500)
        _ = grant
        return response
