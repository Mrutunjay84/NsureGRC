"""Compliance audits and audit items (D-P4-005). Plain TEN - D-P0-009's "audit (assessment)" domain has no
CAT/PLT content.

Named `ngrc.compliance_audit`, deliberately NOT `ngrc.audit` - that existing app is the security/integrity
audit-LOG system (hash chains, checkpoints, D-P0-006), a completely different concept from a compliance
"audit" (a human-run assessment exercise against a framework). See the ADR for why this collision matters.
"""
from __future__ import annotations

from django.db import models

from ngrc.controls.models import ControlAssertion
from ngrc.core.models import TenantOwnedModel


class Audit(TenantOwnedModel):
    """07_CONTROL_EVIDENCE.md's exact workflow: draft -> assigned -> in_progress -> submitted -> review ->
    changes_requested/accepted -> signoff -> locked. No edge leaves `locked` - see the ADR's judgment call
    (a locked, signed-off audit is a deliverable real third parties may rely on)."""

    class Status(models.TextChoices):
        DRAFT = "draft"
        ASSIGNED = "assigned"
        IN_PROGRESS = "in_progress"
        SUBMITTED = "submitted"
        REVIEW = "review"
        CHANGES_REQUESTED = "changes_requested"
        ACCEPTED = "accepted"
        SIGNOFF = "signoff"
        LOCKED = "locked"

    framework_urn = models.SlugField(max_length=200)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    assigned_to = models.UUIDField(null=True)
    reviewer = models.UUIDField(null=True)
    locked_at = models.DateTimeField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_compliance_audit"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_compliance_audit_tenant_id_uniq"),
        ]


class AuditItem(TenantOwnedModel):
    """One requirement's verdict inside one Audit (D-P4-005). `result` is the auditor's own judgment -
    never auto-derived from a linked ControlAssertion.satisfaction_state (that would be the system grading
    its own homework); the link itself is optional (no control asserted against a requirement is itself a
    valid, often negative, finding)."""

    class Result(models.TextChoices):
        """CISO Assistant's own RequirementAssessment.Result vocabulary, reused - no spec document in this
        pack enumerates per-requirement audit verdicts."""
        NOT_ASSESSED = "not_assessed"
        COMPLIANT = "compliant"
        PARTIALLY_COMPLIANT = "partially_compliant"
        NON_COMPLIANT = "non_compliant"
        NOT_APPLICABLE = "not_applicable"

    audit = models.ForeignKey(Audit, on_delete=models.PROTECT, related_name="items")
    requirement_urn = models.SlugField(max_length=250)
    control_assertion = models.ForeignKey(ControlAssertion, on_delete=models.PROTECT, related_name="audit_items",
                                           null=True, blank=True)
    result = models.CharField(max_length=20, choices=Result.choices, default=Result.NOT_ASSESSED)
    observation = models.TextField(blank=True, max_length=2000)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_audit_item"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_audit_item_tenant_id_uniq"),
            models.UniqueConstraint(fields=["tenant", "audit", "requirement_urn"], name="ten_audit_item_unique_requirement"),
        ]
