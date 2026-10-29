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


ACTIONS_P1: tuple[Action, ...] = (
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

# Actions added after the Phase 1 registry was released: seeded by migration audit/0003 (0002 is frozen to ACTIONS_P1).
ACTIONS_P2: tuple[Action, ...] = (
    # ---- DEF-15 / D-P1-001: suspicious-login detection (temporary baseline while recovery does not exist)
    _a("auth.login.suspicious", "auth", "warning", "platform", [AUTH], ["reason", "failures", "distinct_sources"]),
    _a("platform.operator.login.suspicious", "platform_auth", "critical", "platform", [OPS], ["reason", "failures", "distinct_sources"]),
    # ---- F-ATH-015: lost-factor recovery (tenant stream where a tenant is involved; platform stream always)
    _a("auth.recovery.requested", "auth", "warning", "both", [AUTH], ["kind"]),
    _a("auth.recovery.approved", "auth", "warning", "both", [APP, OPS], ["kind"]),
    _a("auth.recovery.denied", "auth", "notice", "both", [APP, OPS], ["kind"]),
    _a("auth.recovery.cancelled", "auth", "warning", "both", [AUTH], ["kind", "by"]),
    _a("auth.recovery.completed", "auth", "critical", "both", [AUTH], ["kind"]),
    # ---- F-DAT-004 / F-DAT-005: evidence lifecycle and downloads (tenant stream, written by the tenant plane)
    _a("evidence.created", "evidence", "info", "tenant", [APP], ["data_class"]),
    _a("evidence.revision.added", "evidence", "notice", "tenant", [APP], ["revision_no", "size_bytes", "detected_type"]),
    _a("evidence.scan.clean", "evidence", "info", "tenant", [APP], ["revision_no"]),
    _a("evidence.scan.quarantined", "evidence", "critical", "tenant", [APP], ["revision_no", "detail"]),
    _a("evidence.scan.error", "evidence", "warning", "tenant", [APP], ["revision_no"]),
    _a("evidence.upload_rejected", "evidence", "notice", "tenant", [APP], ["reason"]),
    _a("evidence.downloaded", "evidence", "notice", "tenant", [APP], ["revision_no", "revision_sha256", "size_bytes"]),
    _a("evidence.hash_mismatch", "evidence", "critical", "tenant", [APP], ["revision_no", "expected_sha256", "actual_sha256"]),
    # ---- F-AUZ-005: search (the query text is never recorded; only its length and the result count)
    _a("search.executed", "search", "info", "tenant", [APP], ["count", "query_length"]),
    # ---- F-AUD-007: scheduled verification (writer: the verifier identity)
    _a("audit.verification.completed", "audit", "info", "platform", [VERIFIER], ["mode", "streams", "violations"]),
    _a("audit.verification.overdue", "audit", "critical", "platform", [VERIFIER], ["max_age_h", "last_run"]),
)

ACTIONS_FRAMEWORK: tuple[Action, ...] = (
    # ---- D-P2-001: Framework Engine. Curator/operator actions (platform stream, writer OPS); tenant
    # activation/override actions (tenant stream, writer APP).
    _a("framework.version.drafted", "framework", "info", "platform", [OPS], ["framework_urn", "version_label"]),
    _a("framework.version.published", "framework", "notice", "platform", [OPS],
       ["framework_urn", "version_label", "requirement_count"]),
    _a("framework.changeset.recorded", "framework", "info", "platform", [OPS],
       ["framework_urn", "from_version_label", "to_version_label", "added", "removed", "changed"]),
    _a("framework.activation.created", "framework", "notice", "tenant", [APP], ["framework_urn", "version_label"]),
    _a("framework.activation.migrated", "framework", "notice", "tenant", [APP],
       ["framework_urn", "from_version_label", "to_version_label"]),
    _a("framework.mapping_override.created", "framework", "info", "tenant", [APP],
       ["framework_urn", "source_requirement_urn", "target_requirement_urn", "relationship"]),
)

# ACTIONS_FRAMEWORK was already seeded by migration 0005 - frozen, same convention as ACTIONS_P1/ACTIONS_P2.
# D-P2-003: tenant-authored custom frameworks get their own new batch + migration (0006).
ACTIONS_CUSTOM_FRAMEWORK: tuple[Action, ...] = (
    _a("framework.custom_framework.created", "framework", "info", "tenant", [APP], ["framework_urn"]),
    _a("framework.custom_version.published", "framework", "notice", "tenant", [APP],
       ["framework_urn", "version_label"]),
)

# D-P3-001: Common/Implementation controls and control assertions.
ACTIONS_CONTROLS: tuple[Action, ...] = (
    _a("control.common_control.created", "control", "info", "tenant", [APP], ["key"]),
    _a("control.implementation_control.created", "control", "info", "tenant", [APP], ["common_control_key"]),
    _a("control.assertion.created", "control", "info", "tenant", [APP],
       ["framework_urn", "requirement_urn"]),
)

# D-P3-002: Evidence requirements and evidence links (connecting EvidenceRevision to a ControlAssertion).
ACTIONS_EVIDENCE_LINKS: tuple[Action, ...] = (
    _a("control.evidence_requirement.created", "control", "info", "tenant", [APP], ["evidence_type"]),
    _a("control.evidence_link.created", "control", "info", "tenant", [APP], ["review_state"]),
    _a("control.evidence_link.reviewed", "control", "notice", "tenant", [APP], ["from_state", "to_state"]),
)

# D-P3-003: Tests and test results.
ACTIONS_TESTS: tuple[Action, ...] = (
    _a("control.test.created", "control", "info", "tenant", [APP], ["test_type"]),
    _a("control.test_result.scheduled", "control", "info", "tenant", [APP]),
    _a("control.test_result.transitioned", "control", "notice", "tenant", [APP], ["from_status", "to_status"]),
)

# D-P3-004: real satisfaction_state derivation from EvidenceLink + TestResult signals.
ACTIONS_SATISFACTION: tuple[Action, ...] = (
    _a("control.assertion.satisfaction_recomputed", "control", "info", "tenant", [APP], ["from_state", "to_state"]),
)

# D-P3-004: closes the gap D-P3-001 left open - mark_assertion_reviewed's own event (separate migration,
# 0011, from ACTIONS_SATISFACTION's 0010 - two distinct concerns, each gets its own batch per convention).
ACTIONS_ASSERTION_REVIEW: tuple[Action, ...] = (
    _a("control.assertion.reviewed", "control", "notice", "tenant", [APP]),
)

# D-P3-005: tasks and control plans.
ACTIONS_TASKS: tuple[Action, ...] = (
    _a("control.control_plan.created", "control", "info", "tenant", [APP]),
    _a("control.task.created", "control", "info", "tenant", [APP]),
    _a("control.task.transitioned", "control", "info", "tenant", [APP], ["from_status", "to_status"]),
)

# D-P4-001: findings and (security) exceptions.
ACTIONS_FINDINGS: tuple[Action, ...] = (
    _a("control.finding.raised", "control", "notice", "tenant", [APP], ["source", "severity"]),
    _a("control.finding.transitioned", "control", "notice", "tenant", [APP], ["from_status", "to_status"]),
    _a("control.security_exception.recorded", "control", "warning", "tenant", [APP]),
)

# D-P4-002: risk assessments, scenarios and acceptances.
ACTIONS_RISK: tuple[Action, ...] = (
    _a("risk.assessment.created", "risk", "info", "tenant", [APP]),
    _a("risk.scenario.created", "risk", "notice", "tenant", [APP], ["risk_level"]),
    _a("risk.scenario.treatment_set", "risk", "info", "tenant", [APP], ["treatment"]),
    _a("risk.scenario.transitioned", "risk", "notice", "tenant", [APP], ["from_status", "to_status"]),
    _a("risk.acceptance.recorded", "risk", "warning", "tenant", [APP]),
)

# D-P4-003: incidents.
ACTIONS_INCIDENTS: tuple[Action, ...] = (
    _a("risk.incident.raised", "risk", "warning", "tenant", [APP], ["severity"]),
    _a("risk.incident.transitioned", "risk", "notice", "tenant", [APP], ["from_status", "to_status"]),
)

# D-P4-004: policies, objectives and issues.
ACTIONS_GOVERNANCE: tuple[Action, ...] = (
    _a("governance.policy.created", "governance", "info", "tenant", [APP]),
    _a("governance.policy.transitioned", "governance", "notice", "tenant", [APP], ["from_status", "to_status"]),
    _a("governance.objective.created", "governance", "info", "tenant", [APP]),
    _a("governance.objective.transitioned", "governance", "info", "tenant", [APP], ["from_status", "to_status"]),
    _a("governance.issue.raised", "governance", "notice", "tenant", [APP], ["severity"]),
    _a("governance.issue.transitioned", "governance", "info", "tenant", [APP], ["from_status", "to_status"]),
)

# D-P4-005: compliance audits and audit items (new ngrc.compliance_audit app - deliberately not "audit.*",
# which already belongs to the security audit-log system, ngrc.audit).
ACTIONS_COMPLIANCE_AUDIT: tuple[Action, ...] = (
    _a("compliance_audit.audit.created", "compliance_audit", "info", "tenant", [APP], ["framework_urn"]),
    _a("compliance_audit.audit.transitioned", "compliance_audit", "notice", "tenant", [APP],
       ["from_status", "to_status"]),
    _a("compliance_audit.item.added", "compliance_audit", "info", "tenant", [APP], ["requirement_urn"]),
    _a("compliance_audit.item.result_set", "compliance_audit", "notice", "tenant", [APP], ["result"]),
)

# D-P4-006: privacy foundation (processing activities, purposes, personal data, rights requests, breaches).
ACTIONS_PRIVACY: tuple[Action, ...] = (
    _a("privacy.processing_activity.created", "privacy", "info", "tenant", [APP], ["role"]),
    _a("privacy.processing_activity.transitioned", "privacy", "info", "tenant", [APP],
       ["from_status", "to_status"]),
    _a("privacy.purpose.added", "privacy", "info", "tenant", [APP], ["lawful_basis"]),
    _a("privacy.personal_data.added", "privacy", "notice", "tenant", [APP], ["special_category"]),
    _a("privacy.rights_request.created", "privacy", "notice", "tenant", [APP], ["request_type"]),
    _a("privacy.rights_request.transitioned", "privacy", "notice", "tenant", [APP],
       ["from_status", "to_status"]),
    _a("privacy.breach.raised", "privacy", "critical", "tenant", [APP], ["severity"]),
    _a("privacy.breach.transitioned", "privacy", "critical", "tenant", [APP], ["from_status", "to_status"]),
    _a("privacy.breach.authority_notified", "privacy", "critical", "tenant", [APP]),
    _a("privacy.breach.subjects_notified", "privacy", "critical", "tenant", [APP]),
)

# D-P5-007: notification service core (event-triggered, in-app only).
ACTIONS_NOTIFICATIONS: tuple[Action, ...] = (
    _a("notification.created", "notifications", "info", "tenant", [APP], ["category"]),
)

# Owner request 2026-10-29: NGRC_MFA_REQUIRED=False (dev-only, never True-only in production - validators.py)
# skips MFA enrolment/verification. A distinct action, not extra keys crammed into auth.login.success's frozen
# ["stage"] allow-list, so the skip is always visible in the audit trail on its own line, never blended in.
ACTIONS_MFA_DEV_BYPASS: tuple[Action, ...] = (
    _a("auth.mfa.skipped_dev_only", "auth", "warning", "platform", [AUTH], ["reason"]),
    _a("platform.operator.mfa.skipped_dev_only", "platform_auth", "warning", "platform", [OPS], ["reason"]),
)

# D-P7-001: Third Parties (Entity/Representative/Solution/Assessment).
ACTIONS_THIRD_PARTY: tuple[Action, ...] = (
    _a("third_party.entity.created", "third_party", "info", "tenant", [APP]),
    _a("third_party.representative.created", "third_party", "info", "tenant", [APP]),
    _a("third_party.solution.created", "third_party", "info", "tenant", [APP]),
    _a("third_party.assessment.created", "third_party", "info", "tenant", [APP]),
    _a("third_party.assessment.transitioned", "third_party", "notice", "tenant", [APP], ["from_status", "to_status"]),
)

# D-P7-002: Assets + BIA. Incident's audit actions already exist under ACTIONS_INCIDENTS (D-P4-003); this is
# a new action for the asset catalogue itself.
ACTIONS_ASSETS: tuple[Action, ...] = (
    _a("asset.created", "risk", "info", "tenant", [APP]),
    _a("asset.bia.recorded", "risk", "notice", "tenant", [APP], ["impact_rating"]),
)

ACTIONS: tuple[Action, ...] = (
    ACTIONS_P1 + ACTIONS_P2 + ACTIONS_FRAMEWORK + ACTIONS_CUSTOM_FRAMEWORK + ACTIONS_CONTROLS
    + ACTIONS_EVIDENCE_LINKS + ACTIONS_TESTS + ACTIONS_SATISFACTION + ACTIONS_ASSERTION_REVIEW + ACTIONS_TASKS
    + ACTIONS_FINDINGS + ACTIONS_RISK + ACTIONS_INCIDENTS + ACTIONS_GOVERNANCE + ACTIONS_COMPLIANCE_AUDIT
    + ACTIONS_PRIVACY + ACTIONS_NOTIFICATIONS + ACTIONS_MFA_DEV_BYPASS + ACTIONS_THIRD_PARTY + ACTIONS_ASSETS
)

BY_NAME = {a.name: a for a in ACTIONS}
if len(BY_NAME) != len(ACTIONS):  # explicit raise: asserts vanish under `python -O`
    raise RuntimeError("duplicate audit action names")

_FORBIDDEN_KEY_FRAGMENTS = ("password", "secret", "token", "cookie", "otp", "recovery", "private", "authorization")
for _a_ in ACTIONS:
    for _k in _a_.detail_keys:
        if any(f in _k for f in _FORBIDDEN_KEY_FRAGMENTS):
            raise RuntimeError(f"secret-like detail key {_k!r} in {_a_.name}")
