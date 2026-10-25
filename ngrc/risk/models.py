"""Risk assessments, scenarios and acceptances (D-P4-002); incidents (D-P4-003); assets + BIA (D-P7-002).
Plain TEN - D-P0-009's `risk / bia / asset / incident` domain row has no CAT/PLT content beyond threat/CWE
catalogues, explicitly deferred to P1."""
from __future__ import annotations

from django.db import models

from ngrc.controls.models import ImplementationControl
from ngrc.core.models import TenantOwnedModel


class AssessmentStatus(models.TextChoices):
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class RiskAssessment(TenantOwnedModel):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    status = models.CharField(max_length=12, choices=AssessmentStatus.choices, default=AssessmentStatus.DRAFT)
    period_start = models.DateField(null=True)
    period_end = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_risk_assessment"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_risk_assessment_tenant_id_uniq"),
        ]


class RiskScenario(TenantOwnedModel):
    """likelihood/impact are the raw 1-5 ISO 27005 inputs; risk_level (ngrc.risk.services.risk_level) is a
    pure function of them, never stored - same reasoning as Task's derived overdue (D-P3-005)."""

    class Treatment(models.TextChoices):
        MITIGATE = "mitigate"
        AVOID = "avoid"
        TRANSFER = "transfer"
        ACCEPT = "accept"

    class Status(models.TextChoices):
        OPEN = "open"
        TREATING = "treating"
        ACCEPTED = "accepted"
        CLOSED = "closed"

    risk_assessment = models.ForeignKey(RiskAssessment, on_delete=models.PROTECT, related_name="scenarios")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    threat = models.TextField(blank=True, max_length=1000)
    vulnerability = models.TextField(blank=True, max_length=1000)
    likelihood = models.IntegerField()
    impact = models.IntegerField()
    treatment = models.CharField(max_length=10, choices=Treatment.choices, null=True, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.OPEN)
    owner = models.UUIDField(null=True)
    asset = models.ForeignKey("Asset", on_delete=models.PROTECT, related_name="risk_scenarios", null=True, blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_risk_scenario"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_risk_scenario_tenant_id_uniq"),
            models.CheckConstraint(condition=models.Q(likelihood__gte=1, likelihood__lte=5), name="ten_risk_scenario_likelihood_range"),
            models.CheckConstraint(condition=models.Q(impact__gte=1, impact__lte=5), name="ten_risk_scenario_impact_range"),
        ]


class RiskAcceptance(TenantOwnedModel):
    """Append-only, DB-immutable (migration 0002_security's ten_risk_acceptance_guard trigger) - same
    pattern as ngrc.controls.models.SecurityException: approver/approved_at captured at creation, required
    expiry_date, no UPDATE grant to ngrc_app at all."""

    risk_scenario = models.ForeignKey(RiskScenario, on_delete=models.PROTECT, related_name="acceptances")
    justification = models.TextField(max_length=2000)
    approver = models.UUIDField()
    approved_at = models.DateTimeField()
    expiry_date = models.DateField()
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_risk_acceptance"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_risk_acceptance_tenant_id_uniq"),
        ]


class Incident(TenantOwnedModel):
    """Detect-through-close lifecycle (D-P4-003, NIST SP 800-61 stages named as states) - same app/domain
    as Risk per D-P0-009's risk/bia/asset/incident grouping. Both control/scenario links are optional:
    incidents are often raised before investigation connects them to a specific risk or control."""

    class Severity(models.TextChoices):
        """Deliberately the same four literal values as ngrc.controls.models.Finding.Severity (D-P4-001) -
        one severity scale across this codebase's governance objects, not two that would need reconciling
        in Phase 5's cross-object reporting. Not programmatically derived from it (a cross-enum value
        reference is fragile); kept in sync by convention and this comment."""
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class Status(models.TextChoices):
        DETECTED = "detected"
        INVESTIGATING = "investigating"
        CONTAINED = "contained"
        RESOLVED = "resolved"
        CLOSED = "closed"

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=14, choices=Status.choices, default=Status.DETECTED)
    detected_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True)
    closed_at = models.DateTimeField(null=True)
    owner = models.UUIDField(null=True)
    risk_scenario = models.ForeignKey(RiskScenario, on_delete=models.PROTECT, related_name="incidents", null=True, blank=True)
    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="incidents",
                                                null=True, blank=True)
    asset = models.ForeignKey("Asset", on_delete=models.PROTECT, related_name="incidents", null=True, blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_incident"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_incident_tenant_id_uniq"),
        ]


# D-P7-002: Assets + BIA. 02_PRD.md s13's extensibility requirement ("risks, controls and incidents can
# reference assets") is met by RiskScenario.asset and Incident.asset above (both optional, same pattern as
# Incident's existing risk_scenario/implementation_control links) - no asset FK added to ControlAssertion in
# this pass; 04_DATA_MODEL.md's tree draws Asset -> BIA as its own branch with no drawn edge into Control,
# and the PRD sentence is the only source naming "controls" here, so this is flagged for the owner rather
# than decided unilaterally (00_CONTROL/PHASE7/D-P7-002_Assets_And_BIA.md).
CRITICALITY_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class Asset(TenantOwnedModel):
    class AssetType(models.TextChoices):
        HARDWARE = "hardware"
        SOFTWARE = "software"
        DATA = "data"
        FACILITY = "facility"
        PERSONNEL = "personnel"
        SERVICE = "service"
        OTHER = "other"

    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=10, choices=AssetType.choices)
    criticality = models.CharField(max_length=10, choices=CRITICALITY_CHOICES)
    owner = models.UUIDField(null=True)
    description = models.TextField(blank=True, max_length=2000)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_asset"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_asset_tenant_id_uniq"),
        ]


class AssetBIA(TenantOwnedModel):
    """A point-in-time business impact analysis of one asset - its own queryable record, re-assessable over
    time, not a field on Asset (same shape as ThirdPartyAssessment, D-P7-001). New BIA = new row; an old one
    is never edited in place, same "a point-in-time assessment is immutable history" reasoning as
    EvidenceRevision/ControlAssertion review history - no status lifecycle needed."""

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="bias")
    recovery_time_objective_hours = models.FloatField(null=True, blank=True)
    recovery_point_objective_hours = models.FloatField(null=True, blank=True)
    impact_rating = models.CharField(max_length=10, choices=CRITICALITY_CHOICES)
    notes = models.TextField(blank=True, max_length=2000)
    assessor = models.UUIDField(null=True)
    assessed_at = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_asset_bia"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_asset_bia_tenant_id_uniq"),
        ]
