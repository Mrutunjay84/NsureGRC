"""Privacy foundation (D-P4-006): processing activities, purposes, personal data categories, data-subject
rights requests and breaches. Plain TEN - D-P0-009's "privacy" domain has no CAT/PLT content.

Grounded directly in GDPR's own structure (Art. 30 Records of Processing Activities; Art. 6(1)'s six
lawful bases; Art. 9's special categories; Art. 15-22's data-subject rights; Art. 33-34's breach
notification duties) - no reference implementation and no project-specific spec sentence back this one
(see the ADR), flagged as the least spec-grounded increment in Phase 4.
"""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel


class ProcessingActivity(TenantOwnedModel):
    """The root of a Record of Processing Activities (ROPA) entry. Purpose and PersonalData are both
    separate FKs to this model (siblings), not nested inside each other - see the ADR's judgment call on
    why the data-model tree's arrows are read as informal chain notation, not a literal FK chain."""

    class Role(models.TextChoices):
        CONTROLLER = "controller"
        PROCESSOR = "processor"

    class Status(models.TextChoices):
        DRAFT = "draft"
        ACTIVE = "active"
        RETIRED = "retired"

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    role = models.CharField(max_length=10, choices=Role.choices)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.DRAFT)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_processing_activity"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_processing_activity_tenant_id_uniq"),
        ]


class Purpose(TenantOwnedModel):
    class LawfulBasis(models.TextChoices):
        """GDPR Art. 6(1)'s exact six lawful bases - a fixed, legally-defined list, not a judgment call."""
        CONSENT = "consent"
        CONTRACT = "contract"
        LEGAL_OBLIGATION = "legal_obligation"
        VITAL_INTERESTS = "vital_interests"
        PUBLIC_TASK = "public_task"
        LEGITIMATE_INTERESTS = "legitimate_interests"

    processing_activity = models.ForeignKey(ProcessingActivity, on_delete=models.PROTECT, related_name="purposes")
    description = models.TextField(max_length=1000)
    lawful_basis = models.CharField(max_length=24, choices=LawfulBasis.choices)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_purpose"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_purpose_tenant_id_uniq"),
        ]


class PersonalData(TenantOwnedModel):
    """category and retention_period are free text - GDPR does not fix a data-category taxonomy or a
    retention-period structure; inventing one would be guessing (D-P4-006)."""

    processing_activity = models.ForeignKey(ProcessingActivity, on_delete=models.PROTECT,
                                             related_name="personal_data_categories")
    category = models.CharField(max_length=200)
    special_category = models.BooleanField(default=False)
    retention_period = models.CharField(max_length=200, blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_personal_data"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_personal_data_tenant_id_uniq"),
        ]


class RightsRequest(TenantOwnedModel):
    """Tenant-root, not FK'd to any ProcessingActivity - a request can span several. requester_reference is
    the tenant's own case reference, never raw data-subject PII (D-P4-006). due_date is caller-supplied,
    never auto-computed - GDPR and DPDP's own response windows differ by jurisdiction."""

    class RequestType(models.TextChoices):
        """GDPR Art. 15-21's six data-subject request types."""
        ACCESS = "access"
        ERASURE = "erasure"
        RECTIFICATION = "rectification"
        PORTABILITY = "portability"
        RESTRICTION = "restriction"
        OBJECTION = "objection"

    class Status(models.TextChoices):
        RECEIVED = "received"
        IN_PROGRESS = "in_progress"
        FULFILLED = "fulfilled"
        REJECTED = "rejected"
        CLOSED = "closed"

    requester_reference = models.CharField(max_length=200)
    request_type = models.CharField(max_length=14, choices=RequestType.choices)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.RECEIVED)
    due_date = models.DateField(null=True)
    owner = models.UUIDField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_rights_request"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_rights_request_tenant_id_uniq"),
        ]


class Breach(TenantOwnedModel):
    """Tenant-root, strictly linear lifecycle (same reasoning as Incident, D-P4-003): each stage is a real
    precondition for the next. notified_authority_at/notified_subjects_at (GDPR Art. 33/34's two distinct
    duties) are set independently of the `notified` transition and of each other."""

    class Severity(models.TextChoices):
        """Same four-band vocabulary as Finding/Incident/Issue - one severity scale across this codebase's
        governance objects."""
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class Status(models.TextChoices):
        OPEN = "open"
        INVESTIGATING = "investigating"
        CONTAINED = "contained"
        NOTIFIED = "notified"
        CLOSED = "closed"

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=14, choices=Status.choices, default=Status.OPEN)
    discovered_at = models.DateTimeField()
    notified_authority_at = models.DateTimeField(null=True)
    notified_subjects_at = models.DateTimeField(null=True)
    affected_data_subjects_estimate = models.IntegerField(null=True)
    owner = models.UUIDField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_privacy_breach"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_privacy_breach_tenant_id_uniq"),
        ]
