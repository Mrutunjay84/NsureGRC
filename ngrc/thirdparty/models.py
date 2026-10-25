"""Third Parties: Entity -> Solution/Representative -> Assessment (D-P7-001). Plain TEN - D-P0-009's
domain row has no CAT/PLT content for this slice, same shape as ngrc.governance."""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel

# Same four-band severity/criticality vocabulary as Finding/Incident/Issue - one scale across this codebase
# (not programmatically linked, same documented reasoning as Incident's reuse of Finding's Severity).
CRITICALITY_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class ThirdPartyEntity(TenantOwnedModel):
    class Category(models.TextChoices):
        VENDOR = "vendor"
        PROCESSOR = "processor"
        PARTNER = "partner"
        OTHER = "other"

    class Status(models.TextChoices):
        ACTIVE = "active"
        INACTIVE = "inactive"

    name = models.CharField(max_length=200)
    category = models.CharField(max_length=10, choices=Category.choices)
    criticality = models.CharField(max_length=10, choices=CRITICALITY_CHOICES)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    description = models.TextField(blank=True, max_length=2000)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_third_party_entity"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_tp_entity_tenant_id_uniq"),
        ]


class ThirdPartyRepresentative(TenantOwnedModel):
    entity = models.ForeignKey(ThirdPartyEntity, on_delete=models.CASCADE, related_name="representatives")
    name = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    role = models.CharField(max_length=200, blank=True)
    phone = models.CharField(max_length=32, blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_third_party_representative"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_tp_rep_tenant_id_uniq"),
        ]


class ThirdPartySolution(TenantOwnedModel):
    entity = models.ForeignKey(ThirdPartyEntity, on_delete=models.CASCADE, related_name="solutions")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    data_classification_note = models.CharField(max_length=500, blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_third_party_solution"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_tp_solution_tenant_id_uniq"),
        ]


class ThirdPartyAssessment(TenantOwnedModel):
    """draft -> in_progress -> completed -> draft (reopen), same cycle as Issue (D-P4-004) - nothing in the
    spec asks for a verification gate on this the way Finding has one (D-P4-001)."""

    class Status(models.TextChoices):
        DRAFT = "draft"
        IN_PROGRESS = "in_progress"
        COMPLETED = "completed"

    entity = models.ForeignKey(ThirdPartyEntity, on_delete=models.CASCADE, related_name="assessments")
    solution = models.ForeignKey(ThirdPartySolution, on_delete=models.CASCADE, related_name="assessments",
                                 null=True, blank=True)
    scope = models.TextField(blank=True, max_length=2000)
    risk_rating = models.CharField(max_length=10, choices=CRITICALITY_CHOICES, blank=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.DRAFT)
    assessor = models.UUIDField(null=True)
    started_at = models.DateField(null=True)
    completed_at = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_third_party_assessment"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_tp_assessment_tenant_id_uniq"),
        ]
