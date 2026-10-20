"""Security event model: the registry of permitted audit actions (D-P0-006 s2, Phase 1 step 28).

Each action declares: stream (tenant | platform | both), the DB login roles allowed to emit it, and the ONLY detail keys
permitted in its `details` JSON (allow-list; no secrets, no free-form PII). The database enforces this in
`audit.append_*` - an unregistered action, an unauthorised writer or a stray detail key is rejected.
Changing this tuple after release requires a NEW migration (see migration 0002 + test_registry_drift).
"""
from __future__ import annotations

from dataclasses import dataclass

APP, AUTH, OPS = "ngrc_app", "ngrc_auth", "ngrc_ops"
VERIFIER = "ngrc_audit_verifier"


@dataclass(frozen=True)
class Action:
    name: str
    category: str
    severity: str  # info | notice | warning | critical
    stream: str  # tenant | platform | both
    writers: tuple[str, ...]
    detail_keys: tuple[str, ...] = ()


def _a(name, category, severity, stream, writers, keys=()):
    return Action(name, category, severity, stream, tuple(writers), tuple(keys))


ACTIONS: tuple[Action, ...] = (
    # ---- authentication (customer realm). Pre-tenant events land in the PLATFORM stream.
    _a("auth.login.success", "auth", "info", "platform", [AUTH], ["stage"]),
    _a("auth.login.failure", "auth", "notice", "platform", [AUTH], ["identifier_hash"]),
    _a("auth.throttle.triggered", "auth", "warning", "platform", [AUTH], ["scope", "identifier_hash"]),
    _a("auth.account.locked", "auth", "warning", "platform", [AUTH], ["reason"]),
    _a("auth.logout", "auth", "info", "platform", [AUTH]),
    _a("auth.session.revoked", "auth", "notice", "platform", [AUTH, APP], ["reason"]),
    _a("auth.session.expired", "auth", "info", "platform", [AUTH], ["kind"]),
    _a("auth.session.tenant_selected", "auth", "info", "tenant", [AUTH]),
    _a("auth.password.changed", "auth", "notice", "both", [AUTH]),
    _a("auth.password.reset_requested", "auth", "notice", "platform", [AUTH], ["identifier_hash"]),
    _a("auth.password.reset_completed", "auth", "notice", "platform", [AUTH]),
    _a("auth.password.blocklist_rejected", "auth", "info", "platform", [AUTH]),
    _a("auth.email.verification_sent", "auth", "info", "platform", [AUTH]),
    _a("auth.email.verified", "auth", "info", "platform", [AUTH]),
    _a("auth.invitation.accepted", "auth", "notice", "both", [AUTH], ["role_key"]),
    _a("auth.mfa.enrolled", "auth", "notice", "both", [AUTH], ["method"]),
    _a("auth.mfa.removed", "auth", "warning", "both", [AUTH], ["method"]),
    _a("auth.mfa.verified", "auth", "info", "platform", [AUTH], ["method"]),
    _a("auth.mfa.failed", "auth", "notice", "platform", [AUTH], ["method"]),
    _a("auth.mfa.locked", "auth", "warning", "platform", [AUTH], ["method"]),
    _a("auth.totp.replay_rejected", "auth", "warning", "platform", [AUTH]),
    _a("auth.webauthn.registered", "auth", "notice", "both", [AUTH]),
    _a("auth.webauthn.counter_regression", "auth", "critical", "platform", [AUTH, OPS]),
    _a("auth.recovery_codes.generated", "auth", "notice", "both", [AUTH]),
    _a("auth.recovery_codes.used", "auth", "warning", "platform", [AUTH]),
    _a("auth.recovery_codes.failed", "auth", "notice", "platform", [AUTH]),
    _a("auth.stepup.success", "auth", "info", "both", [AUTH, APP], ["tier", "method"]),
    _a("auth.stepup.failure", "auth", "notice", "platform", [AUTH, APP], ["tier", "method"]),
    # ---- authorisation
    _a("authz.denied", "authz", "notice", "both", [APP, AUTH, OPS], ["permission", "route"]),
    # ---- tenant administration (tenant stream; written inside the business transaction)
    _a("tenant.role.created", "tenant_admin", "notice", "tenant", [APP], ["role_key", "permissions"]),
    _a("tenant.role.updated", "tenant_admin", "notice", "tenant", [APP], ["role_key", "added", "removed"]),
    _a("tenant.role.deleted", "tenant_admin", "notice", "tenant", [APP], ["role_key"]),
    _a("tenant.member.role_changed", "tenant_admin", "warning", "tenant", [APP], ["from_role", "to_role"]),
    _a("tenant.member.status_changed", "tenant_admin", "warning", "tenant", [APP], ["status"]),
    _a("tenant.invitation.created", "tenant_admin", "notice", "tenant", [APP], ["invitee_hash", "role_key", "kind"]),
    _a("tenant.invitation.revoked", "tenant_admin", "notice", "tenant", [APP]),
    _a("tenant.support.consented", "tenant_admin", "warning", "tenant", [APP], ["profile", "restricted"]),
    _a("tenant.support.denied", "tenant_admin", "notice", "tenant", [APP]),
    _a("tenant.support.revoked", "tenant_admin", "warning", "tenant", [APP]),
    _a("audit.read", "audit", "info", "tenant", [APP], ["count"]),
    _a("audit.export", "audit", "notice", "tenant", [APP], ["count"]),
    # ---- support / operator activity mirrored into the tenant stream (writer: ops, grant-checked in the DB)
    _a("support.session.started", "support", "warning", "tenant", [OPS], ["profile"]),
    _a("support.action", "support", "warning", "tenant", [OPS], ["operation"]),
    _a("support.session.ended", "support", "notice", "tenant", [OPS], ["by"]),
    _a("support.grant.requested", "support", "notice", "tenant", [OPS], ["profile", "break_glass"]),
    _a("support.grant.approved", "support", "notice", "tenant", [OPS], ["break_glass"]),
    # ---- platform stream
    _a("platform.operator.login.success", "platform_auth", "info", "platform", [OPS], ["stage"]),
    _a("platform.operator.login.failure", "platform_auth", "warning", "platform", [OPS], ["identifier_hash"]),
    _a("platform.operator.throttle.triggered", "platform_auth", "warning", "platform", [OPS], ["scope"]),
    _a("platform.operator.logout", "platform_auth", "info", "platform", [OPS]),
    _a("platform.operator.mfa.verified", "platform_auth", "info", "platform", [OPS], ["method"]),
    _a("platform.operator.mfa.failed", "platform_auth", "warning", "platform", [OPS], ["method"]),
    _a("platform.operator.webauthn.registered", "platform_auth", "notice", "platform", [OPS]),
    _a("platform.operator.stepup.success", "platform_auth", "info", "platform", [OPS], ["tier", "binding"]),
    _a("platform.operator.stepup.failure", "platform_auth", "warning", "platform", [OPS], ["tier", "binding"]),
    _a("platform.operator.created", "platform_admin", "notice", "platform", [OPS], ["roles"]),
    _a("platform.operator.role_changed", "platform_admin", "warning", "platform", [OPS], ["added", "removed"]),
    _a("platform.tenant.provisioned", "platform_admin", "notice", "platform", [OPS], ["slug"]),
    _a("platform.tenant.status_changed", "platform_admin", "warning", "platform", [OPS], ["status"]),
    _a("platform.support.requested", "platform_support", "notice", "platform", [OPS], ["profile", "ticket_ref", "break_glass"]),
    _a("platform.support.approved", "platform_support", "notice", "platform", [OPS], ["break_glass"]),
    _a("platform.support.consented", "platform_support", "notice", "platform", [APP], ["restricted"]),
    _a("platform.support.denied", "platform_support", "notice", "platform", [APP, OPS]),
    _a("platform.support.activated", "platform_support", "warning", "platform", [OPS], ["profile", "break_glass"]),
    _a("platform.support.ended", "platform_support", "notice", "platform", [OPS, APP], ["by", "state"]),
    _a("platform.support.action", "platform_support", "warning", "platform", [OPS], ["operation"]),
    _a("platform.breakglass.requested", "platform_support", "critical", "platform", [OPS], ["ticket_ref"]),
    _a("platform.breakglass.approved", "platform_support", "critical", "platform", [OPS]),
    _a("platform.audit.read", "audit", "info", "platform", [OPS, "ngrc_audit_reader_platform"], ["count"]),
    _a("audit.integrity_violation", "audit", "critical", "platform", [VERIFIER], ["stream", "detail"]),
)

BY_NAME = {a.name: a for a in ACTIONS}
if len(BY_NAME) != len(ACTIONS):  # explicit raise: asserts vanish under `python -O`
    raise RuntimeError("duplicate audit action names")

_FORBIDDEN_KEY_FRAGMENTS = ("password", "secret", "token", "cookie", "otp", "recovery", "private", "authorization")
for _a_ in ACTIONS:
    for _k in _a_.detail_keys:
        if any(f in _k for f in _FORBIDDEN_KEY_FRAGMENTS):
            raise RuntimeError(f"secret-like detail key {_k!r} in {_a_.name}")
