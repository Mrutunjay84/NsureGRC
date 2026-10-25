"""Permission catalogue (D-P0-005 s2). Two disjoint partitions: `tenant.*`-style permissions that tenant roles may carry,
and `platform.*` permissions that only platform-realm roles may carry. The DB also rejects any `platform.` string inside
a tenant role (CHECK ten_role_no_platform_perms) so a tenant can never obtain a platform right.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Permission:
    key: str
    privileged: bool
    realm: str  # 'tenant' | 'platform'


_REGISTRY: dict[str, Permission] = {}


def register(key: str, *, privileged: bool, realm: str) -> Permission:
    if realm == "tenant" and key.startswith("platform."):
        raise ValueError("tenant permissions must not use the platform. prefix")
    if realm == "platform" and not key.startswith("platform."):
        raise ValueError("platform permissions must use the platform. prefix")
    p = Permission(key, privileged, realm)
    _REGISTRY[key] = p
    return p


def get(key: str) -> Permission | None:
    return _REGISTRY.get(key)


def all_permissions() -> dict[str, Permission]:
    return dict(_REGISTRY)


# ---- tenant permissions (privileged => shorter sessions, halved throttling, step-up where noted; ADR-008 s12)
for _k, _priv in [
    ("tenant.view", False),
    ("tenant.members.read", False),
    ("tenant.members.manage", True),
    ("tenant.roles.read", False),
    ("tenant.roles.manage", True),
    ("tenant.invitations.manage", True),
    ("tenant.support.read", False),
    ("tenant.support.consent", True),
    ("tenant.settings.manage", True),
    ("tenant.recovery.approve", True),
    ("evidence.read", False),
    ("evidence.upload", False),
    ("evidence.read_restricted", True),
    ("audit.read", True),
    ("audit.export", True),
    ("framework.read", False),
    ("framework.manage", True),  # D-P2-001: activate/pin a framework version, migrate, override a mapping
    ("control.read", False),
    ("control.manage", True),  # D-P3-001: create/edit common & implementation controls, assert against requirements
    ("risk.read", False),
    ("risk.manage", True),  # D-P4-002: create/edit risk assessments/scenarios, record risk acceptances
    ("governance.read", False),
    ("governance.manage", True),  # D-P4-004: create/edit policies, objectives, issues
    ("compliance_audit.read", False),
    ("compliance_audit.manage", True),  # D-P4-005: create/edit compliance audits and audit items
    ("privacy.read", False),
    ("privacy.manage", True),  # D-P4-006: create/edit processing activities, rights requests, breaches
    ("third_party.read", False),
    ("third_party.manage", True),  # D-P7-001: create/edit third-party entities, representatives, solutions, assessments
    ("asset.read", False),
    ("asset.manage", True),  # D-P7-002: create/edit assets and record BIAs
    ("notification.read", False),
    ("notification.manage", False),  # D-P5-007: mark own notifications read - not privileged, same as read
]:
    register(_k, privileged=_priv, realm="tenant")

# ---- platform permissions
for _k, _priv in [
    ("platform.tenants.provision", True),
    ("platform.tenants.suspend", True),
    ("platform.operators.manage", True),
    ("platform.support.read", True),
    ("platform.support.request", True),
    ("platform.support.approve", True),
    ("platform.support.use", True),
    ("platform.breakglass.request", True),
    ("platform.breakglass.approve", True),
    ("platform.audit.read", True),
    ("platform.catalogue.curate", True),
    ("platform.recovery.approve", True),
]:
    register(_k, privileged=True, realm="platform")

TENANT_KEYS = sorted(k for k, p in _REGISTRY.items() if p.realm == "tenant")

# System roles seeded at provisioning (immutable to the tenant plane: trigger ten_role_system_guard).
SYSTEM_ROLES: dict[str, dict] = {
    "owner": {"name": "Owner", "permissions": list(TENANT_KEYS)},
    "admin": {
        "name": "Administrator",
        "permissions": ["tenant.view", "tenant.members.read", "tenant.members.manage", "tenant.roles.read",
                        "tenant.roles.manage", "tenant.invitations.manage", "tenant.support.read", "tenant.recovery.approve", "evidence.read", "evidence.upload", "audit.read",
                        "framework.read", "framework.manage", "control.read", "control.manage", "risk.read", "risk.manage",
                        "governance.read", "governance.manage", "compliance_audit.read", "compliance_audit.manage",
                        "privacy.read", "privacy.manage", "third_party.read", "third_party.manage",
                        "asset.read", "asset.manage", "notification.read", "notification.manage"],
    },
    "member": {"name": "Member", "permissions": ["tenant.view", "tenant.members.read", "framework.read", "control.read",
                                                  "risk.read", "governance.read", "compliance_audit.read", "privacy.read",
                                                  "third_party.read", "asset.read", "notification.read", "notification.manage"]},
}

# Platform role -> permissions. Deliberately no role has standing access to tenant content (D-P0-005 s2).
PLATFORM_ROLES: dict[str, frozenset[str]] = {
    # Admin co-approves break-glass but cannot REQUEST support/break-glass access (D-P0-005 s2/s4: requester != approvers).
    "platform_admin": frozenset({"platform.tenants.provision", "platform.tenants.suspend", "platform.operators.manage", "platform.support.read",
                                 "platform.breakglass.approve"}),
    "platform_security": frozenset({"platform.audit.read", "platform.support.read", "platform.support.approve", "platform.breakglass.approve",
                                    "platform.recovery.approve"}),
    "platform_curator": frozenset({"platform.catalogue.curate"}),
    "platform_support": frozenset({"platform.support.read", "platform.support.request", "platform.support.use",
                                   "platform.breakglass.request"}),
}

# What an operator may do INSIDE a tenant under an active grant (least privilege by profile; D-P0-005 s3.3).
SUPPORT_PROFILE_PERMISSIONS: dict[str, frozenset[str]] = {
    "diagnostic_metadata": frozenset({"support.diagnostics.read"}),
    "read_limited": frozenset({"support.diagnostics.read", "tenant.view", "tenant.roles.read"}),
    "write_limited": frozenset({"support.diagnostics.read", "tenant.view", "tenant.roles.read"}),  # no write op exists yet
}


def is_privileged(permission_keys) -> bool:
    return any((p := _REGISTRY.get(k)) is not None and p.privileged for k in permission_keys)
