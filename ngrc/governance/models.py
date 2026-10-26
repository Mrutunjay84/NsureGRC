"""Policies, objectives and issues (D-P4-004). Plain TEN - D-P0-009's `policy / governance / finding /
remediation` domain row has no CAT/PLT content for this slice (Finding/remediation already landed in
ngrc.controls, D-P4-001 - documented there as a deliberate deviation from this grouping)."""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel


class Policy(TenantOwnedModel):
    class Status(models.TextChoices):
        DRAFT = "draft"
        ACTIVE = "active"
        RETIRED = "retired"

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.DRAFT)
    effective_date = models.DateField(null=True)
    next_review_date = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_policy"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_policy_tenant_id_uniq"),
        ]


class Objective(TenantOwnedModel):
    """No metric linkage yet (D-P4-004) - status is a human-recorded judgment call, not computed against a
    metric system that doesn't exist (Phase 5's own "configurable metrology" scope)."""

    class Status(models.TextChoices):
        OPEN = "open"
        ACHIEVED = "achieved"
        MISSED = "missed"

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    target_date = models.DateField(null=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.OPEN)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_objective"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_objective_tenant_id_uniq"),
        ]


class Issue(TenantOwnedModel):
    """Deliberately lighter-weight than Finding (D-P4-001): a tenant-root governance concern, not anchored
    to one ImplementationControl, and its close does NOT require a verification step - nothing in any spec
    document asks for that gate on Issue specifically, only on Finding."""

    class Severity(models.TextChoices):
        """Same four-band vocabulary as Finding/Incident - one severity scale across this codebase's
        governance objects."""
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class Status(models.TextChoices):
        OPEN = "open"
        IN_PROGRESS = "in_progress"
        RESOLVED = "resolved"
        CLOSED = "closed"

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.OPEN)
    owner = models.UUIDField(null=True)
    due_date = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_issue"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_issue_tenant_id_uniq"),
        ]
