"""Session authentication middleware: cookie -> server-side session -> Principal. Also publishes request metadata
(ip / UA / request id / hashed session ref) for audit events. No state is trusted from the client except the opaque id."""
from __future__ import annotations

from dataclasses import replace

from ngrc.audit import service as audit
from ngrc.authz.principal import Principal

from . import sessions
from .realms import OPERATOR, realm_for_path


def build_principal(realm, s) -> Principal:
    acct = s.account
    common = dict(
        account_id=acct.id, session_id=s.id, stage=s.stage, email=acct.email, session_ref=s.token_hash[:16],
        mfa_at=s.mfa_at, step_up_at=s.step_up_at, step_up_method=s.step_up_method,
        auth_methods=tuple(s.auth_methods or ()),
    )
    if realm is OPERATOR:
        roles = frozenset(acct.roles.values_list("role", flat=True)) if hasattr(acct, "roles") else frozenset()
        grant_id = s.support_grant_id
        tenant_id = None
        if grant_id:
            from ngrc.control_plane.models import SupportAccessGrant

            g = SupportAccessGrant.objects.using("ops").filter(pk=grant_id).first()
            tenant_id = g.subject_tenant_id if g else None
        return Principal(kind="operator", tenant_id=tenant_id, operator_roles=roles, grant_id=grant_id, **common)
    return Principal(kind="customer", tenant_id=s.active_tenant_id, **common)


class SessionAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        realm = realm_for_path(request.path)
        request.ngrc_principal = None
        bad_cookie = False
        raw = request.COOKIES.get(realm.cookie_name)
        if raw:
            s = sessions.lookup(realm, raw)
            if s is None:
                bad_cookie = True
            else:
                request.ngrc_principal = build_principal(realm, s)
        meta = audit.RequestMeta(
            ip=request.META.get("REMOTE_ADDR"), user_agent=request.META.get("HTTP_USER_AGENT", "")[:256],
            request_id=getattr(request, "request_id", None),
            session_ref=request.ngrc_principal.session_ref if request.ngrc_principal else None,
        )
        token = audit.set_meta(meta)
        try:
            response = self.get_response(request)
        finally:
            audit._meta.reset(token)
        if bad_cookie:
            sessions.clear_cookie(response, realm)
        return response


__all__ = ["SessionAuthMiddleware", "build_principal", "replace"]
