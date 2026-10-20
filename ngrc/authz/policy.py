"""Central policy resolver: authorize(principal, permission, ...) - fail closed, server-side (D-P0-003 s1, 05_SECURITY).

Every protected view goes through `PolicyPermission` -> here. Any unexpected condition denies.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings

from ngrc.core import clock

from . import permissions as perm


class Denied(Exception):
    """Authorisation failure. `reason` is a stable machine code recorded in the audit trail, never shown to the caller."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TenantAuthz:
    membership_id: object
    role_id: object
    role_key: str
    role_is_system: bool
    permissions: frozenset[str]
    kind: str
    privileged: bool


def resolve_tenant_authz(principal) -> TenantAuthz:
    """Load the caller's membership/role inside the active tenant context (RLS-scoped queries)."""
    from ngrc.control_plane.models import Tenant
    from ngrc.tenancy.models import Membership, TenantRole

    if principal.kind != "customer" or principal.tenant_id is None:
        raise Denied("no_tenant")
    cached = principal.extra.get("tenant_authz")
    if cached is not None:
        return cached
    tenant = Tenant.objects.using("default").filter(id=principal.tenant_id).first()
    if tenant is None or tenant.status != "active":
        raise Denied("tenant_unavailable")
    m = Membership.objects.filter(principal_id=principal.account_id).first()
    if m is None:
        raise Denied("not_a_member")
    if m.status != "active":
        raise Denied("membership_suspended")
    if m.expires_at is not None and m.expires_at <= clock.now():
        raise Denied("membership_expired")
    role = TenantRole.objects.filter(id=m.role_id).first()
    if role is None:
        raise Denied("role_missing")
    keys = frozenset(k for k in role.permissions if perm.get(k) is not None and perm.get(k).realm == "tenant")
    ta = TenantAuthz(m.id, role.id, role.key, role.is_system, keys, m.kind, perm.is_privileged(keys))
    principal.extra["tenant_authz"] = ta
    return ta


def require_recent_step_up(principal, tier: str) -> None:
    if tier != "T1":
        raise Denied("unsupported_step_up_tier")
    if principal.step_up_at is None or principal.step_up_method not in {"totp", "webauthn", "recovery"}:
        raise Denied("step_up_required")
    if clock.now() - principal.step_up_at > timedelta(seconds=settings.STEP_UP_T1_WINDOW_S):
        raise Denied("step_up_expired")


def authorize(principal, permission: str, *, step_up: str | None = None, obj_tenant_id=None) -> None:
    """Raise Denied unless `principal` may exercise `permission`. Returns None on success."""
    p = perm.get(permission)
    if p is None and not permission.startswith("support."):
        raise Denied("unknown_permission")
    if principal is None or principal.stage != "active":
        raise Denied("not_fully_authenticated")

    if principal.kind == "customer":
        if p is None or p.realm != "tenant":
            raise Denied("realm_mismatch")
        ta = resolve_tenant_authz(principal)
        if permission not in ta.permissions:
            raise Denied("permission_missing")
        if obj_tenant_id is not None and obj_tenant_id != principal.tenant_id:
            raise Denied("object_tenant_mismatch")  # defence in depth; RLS already hides foreign rows
    elif principal.kind == "operator":
        if principal.grant_id is not None:
            # acting inside a tenant under a support grant: only the profile's permissions, never platform ones
            grant = principal.extra.get("grant")
            if grant is None:
                raise Denied("grant_unverified")
            allowed = perm.SUPPORT_PROFILE_PERMISSIONS.get(grant.profile, frozenset())
            if permission not in allowed:
                raise Denied("outside_grant_profile")
            if obj_tenant_id is not None and obj_tenant_id != principal.tenant_id:
                raise Denied("object_tenant_mismatch")
        else:
            if p is None or p.realm != "platform":
                raise Denied("realm_mismatch")
            granted = frozenset().union(*[perm.PLATFORM_ROLES.get(r, frozenset()) for r in principal.operator_roles])
            if permission not in granted:
                raise Denied("permission_missing")
    else:
        raise Denied("unknown_principal")

    if step_up:
        require_recent_step_up(principal, step_up)
