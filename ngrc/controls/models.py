"""Common/Implementation controls and control assertions (D-P3-001). Plain TEN - D-P0-009's
`control / evidence / test` domain row has no CAT/PLT/IDN content, unlike the Framework Engine."""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel


class Lifecycle(models.TextChoices):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


class CommonControl(TenantOwnedModel):
    key = models.SlugField(max_length=100)
    name = models.CharField(max_length=200)
    objective = models.TextField(blank=True, max_length=2000)
    category = models.CharField(max_length=100, blank=True)
    lifecycle = models.CharField(max_length=10, choices=Lifecycle.choices, default=Lifecycle.DRAFT)
    owner = models.UUIDField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_common_control"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_common_control_tenant_id_uniq"),
            models.UniqueConstraint(fields=["tenant", "key"], name="ten_common_control_tenant_key_uniq"),
        ]


class ImplementationControl(TenantOwnedModel):
    common_control = models.ForeignKey(CommonControl, on_delete=models.PROTECT, related_name="implementations")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=4000)
    owner = models.UUIDField(null=True)
    reviewer = models.UUIDField(null=True)
    due_date = models.DateField(null=True)
    lifecycle = models.CharField(max_length=10, choices=Lifecycle.choices, default=Lifecycle.DRAFT)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_implementation_control"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_implementation_control_tenant_id_uniq"),
        ]


class SatisfactionState(models.TextChoices):
    UNKNOWN = "unknown"
    NEEDS_ATTENTION = "needs_attention"
    PARTIALLY_EFFECTIVE = "partially_effective"
    EFFECTIVE = "effective"
    VERIFIED = "verified"


class ControlAssertion(TenantOwnedModel):
    """Links an ImplementationControl to a framework requirement by stable (framework_urn, requirement_urn)
    keys, never an ORM FK into cat_requirement/ten_framework_custom_requirement - same D-P0-009 s2.3
    reasoning as MappingOverride (D-P2-001/003): must survive a version migration, and must work the same
    whether the requirement is catalogue- or custom-sourced."""

    class ReviewState(models.TextChoices):
        UNREVIEWED = "unreviewed"
        REVIEWED = "reviewed"

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="assertions")
    framework_urn = models.SlugField(max_length=200)
    requirement_urn = models.SlugField(max_length=250)
    coverage = models.IntegerField(null=True)
    satisfaction_state = models.CharField(max_length=20, choices=SatisfactionState.choices, default=SatisfactionState.UNKNOWN)
    review_state = models.CharField(max_length=12, choices=ReviewState.choices, default=ReviewState.UNREVIEWED)
    valid_from = models.DateField(null=True)
    valid_to = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_control_assertion"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_control_assertion_tenant_id_uniq"),
            models.UniqueConstraint(
                fields=["tenant", "implementation_control", "framework_urn", "requirement_urn"],
                name="ten_control_assertion_unique_link",
            ),
        ]
