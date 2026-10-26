"""Compliance audits and audit items (D-P4-005).

All plain TEN writes (no new DB role). Callers must already be inside the target tenant's
`tenant_context()` and have checked `compliance_audit.manage` - services trust an already-authorized
caller, same convention as `ngrc.controls.services`/`ngrc.risk.services`/`ngrc.governance.services`.
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.controls.models import ControlAssertion
from ngrc.core import clock
from ngrc.framework import services as framework_services

from .models import Audit, AuditItem


class ComplianceAuditError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_audit(framework_urn: str, name: str, *, created_by, description: str = "", assigned_to=None,
                  reviewer=None) -> Audit:
    """Fails closed: framework_urn must actually resolve (the tenant has it activated) - same reuse-the-
    resolver reasoning as ControlAssertion (D-P3-001)."""
    try:
        framework_services.resolve_requirements(framework_urn)
    except framework_services.FrameworkError as exc:
        raise ComplianceAuditError(f"framework_not_resolved:{exc.code}") from exc
    audit_obj = Audit.objects.create(
        framework_urn=framework_urn, name=name, description=description, assigned_to=assigned_to,
        reviewer=reviewer, created_by=created_by,
    )
    audit.record("compliance_audit.audit.created", actor_id=created_by, object_type="audit",
                 object_id=str(audit_obj.id), details={"framework_urn": framework_urn})
    return audit_obj


_ALLOWED_AUDIT_TRANSITIONS: dict[str, set[str]] = {
    Audit.Status.DRAFT: {Audit.Status.ASSIGNED},
    Audit.Status.ASSIGNED: {Audit.Status.IN_PROGRESS},
    Audit.Status.IN_PROGRESS: {Audit.Status.SUBMITTED},
    Audit.Status.SUBMITTED: {Audit.Status.REVIEW},
    Audit.Status.REVIEW: {Audit.Status.CHANGES_REQUESTED, Audit.Status.ACCEPTED},
    Audit.Status.CHANGES_REQUESTED: {Audit.Status.IN_PROGRESS},
    Audit.Status.ACCEPTED: {Audit.Status.SIGNOFF},
    Audit.Status.SIGNOFF: {Audit.Status.LOCKED},
    Audit.Status.LOCKED: set(),
}


def transition_audit(audit_obj: Audit, new_status: str, *, actor_id) -> Audit:
    """Fails closed: 07_CONTROL_EVIDENCE.md's exact eight-plus-fork stage graph. No edge leaves `locked`
    (D-P4-005) - a locked, signed-off audit is a deliverable, not a record to reopen."""
    allowed = _ALLOWED_AUDIT_TRANSITIONS.get(audit_obj.status, set())
    if new_status not in allowed:
        raise ComplianceAuditError(f"invalid_transition:{audit_obj.status}->{new_status}")
    from_status = audit_obj.status
    audit_obj.status = new_status
    update_fields = ["status"]
    if new_status == Audit.Status.LOCKED:
        audit_obj.locked_at = clock.now()
        update_fields.append("locked_at")
    audit_obj.save(update_fields=update_fields)
    audit.record("compliance_audit.audit.transitioned", actor_id=actor_id, object_type="audit",
                 object_id=str(audit_obj.id), details={"from_status": from_status, "to_status": new_status})
    return audit_obj


def add_audit_item(audit_obj: Audit, requirement_urn: str, *, created_by,
                    control_assertion: ControlAssertion | None = None) -> AuditItem:
    """Fails closed: requirement_urn must resolve within the audit's own framework_urn, same pattern as
    create_audit itself."""
    resolved_urns = {r.urn for r in framework_services.resolve_requirements(audit_obj.framework_urn)}
    if requirement_urn not in resolved_urns:
        raise ComplianceAuditError("requirement_not_resolved")
    item = AuditItem.objects.create(
        audit=audit_obj, requirement_urn=requirement_urn, control_assertion=control_assertion,
        created_by=created_by,
    )
    audit.record("compliance_audit.item.added", actor_id=created_by, object_type="audit_item",
                 object_id=str(item.id), details={"requirement_urn": requirement_urn})
    return item


def set_audit_item_result(item: AuditItem, result: str, *, actor_id, observation: str = "") -> AuditItem:
    """No transition graph: a verdict can be revised freely (D-P4-005) - never auto-derived from
    item.control_assertion.satisfaction_state, an independent human judgment call."""
    item.result = result
    update_fields = ["result"]
    if observation:
        item.observation = observation
        update_fields.append("observation")
    item.save(update_fields=update_fields)
    audit.record("compliance_audit.item.result_set", actor_id=actor_id, object_type="audit_item",
                 object_id=str(item.id), details={"result": result})
    return item
