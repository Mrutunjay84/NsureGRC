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
    """The canonical six-value Status Vocabulary (02_PRD.md s16): "unknown | not_assessed | needs_attention
    | partially_effective | effective | verified". DEF-22: this enum originally shipped (D-P3-001/004) with
    only five values, missing not_assessed - a real spec gap, not a style choice. Per 11_MASTER_CLAUDE_BUILD_SPEC.md's
    own Status Rule ("Use `unknown` for unavailable/stale source data"), `unknown` means a genuine data
    problem (the derivation could not even be attempted); `not_assessed` means the derivation ran and found
    nothing to go on yet (no Test, no EvidenceLink) - the normal state for a freshly-created assertion.
    `unknown` is declared to complete the vocabulary but is not yet produced by any code path in this
    codebase - no part of the current derivation detects source-data unavailability, so inventing a branch
    that fabricates reaching it would itself be exactly the kind of fake completeness this project's rules
    forbid. Left reachable only by a future increment that actually detects that condition."""
    UNKNOWN = "unknown"
    NOT_ASSESSED = "not_assessed"
    NEEDS_ATTENTION = "needs_attention"
    PARTIALLY_EFFECTIVE = "partially_effective"
    EFFECTIVE = "effective"
    VERIFIED = "verified"


class Frequency(models.TextChoices):
    ON_DEMAND = "on_demand"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"
    ANNUAL = "annual"


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
    satisfaction_state = models.CharField(max_length=20, choices=SatisfactionState.choices, default=SatisfactionState.NOT_ASSESSED)
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


class EvidenceRequirement(TenantOwnedModel):
    """A standing expectation attached to an ImplementationControl (D-P3-002): what evidence is expected,
    not evidence itself. Fulfilment is a read-model question over EvidenceLink rows, not a stored flag here
    (see the ADR's judgment call 2) - this is why there is no requested/collected/... state on this model."""

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT,
                                                related_name="evidence_requirements")
    evidence_type = models.CharField(max_length=100)
    source_system = models.CharField(max_length=150, blank=True)
    frequency = models.CharField(max_length=12, choices=Frequency.choices, default=Frequency.ON_DEMAND)
    freshness_days = models.IntegerField(null=True)
    acceptance_criteria = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    reviewer = models.UUIDField(null=True)
    lifecycle = models.CharField(max_length=10, choices=Lifecycle.choices, default=Lifecycle.DRAFT)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_evidence_requirement"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_evidence_requirement_tenant_id_uniq"),
            models.CheckConstraint(condition=models.Q(freshness_days__gte=0) | models.Q(freshness_days__isnull=True),
                                    name="ten_evidence_requirement_freshness_nonneg"),
        ]


class EvidenceLink(TenantOwnedModel):
    """Governed link from a pinned, already-collected EvidenceRevision to a ControlAssertion (D-P3-002).
    `evidence_revision_id` is a plain UUID field, not a Django ForeignKey: the same-tenant composite FK
    (tenant_id, evidence_revision_id) -> ten_evidence_revision(tenant_id, id) is created in raw SQL in
    migration 0005, identical pattern to EvidenceRevision.evidence_id's own link to ten_evidence - a plain
    single-column FK's referential check runs as the table owner and does not honour RLS, so anything
    pointing into the evidence domain specifically uses the stronger composite constraint."""

    class ReviewState(models.TextChoices):
        COLLECTED = "collected"
        IN_REVIEW = "in_review"
        ACCEPTED = "accepted"
        REJECTED = "rejected"
        EXPIRED = "expired"
        SUPERSEDED = "superseded"

    control_assertion = models.ForeignKey(ControlAssertion, on_delete=models.PROTECT, related_name="evidence_links")
    evidence_requirement = models.ForeignKey(EvidenceRequirement, on_delete=models.PROTECT, related_name="links",
                                              null=True, blank=True)
    evidence_revision_id = models.UUIDField()
    review_state = models.CharField(max_length=12, choices=ReviewState.choices, default=ReviewState.COLLECTED)
    reviewed_by = models.UUIDField(null=True)
    reviewed_at = models.DateTimeField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_evidence_link"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_evidence_link_tenant_id_uniq"),
            models.UniqueConstraint(
                fields=["tenant", "control_assertion", "evidence_revision_id"],
                name="ten_evidence_link_unique_revision_per_assertion",
            ),
        ]


class Test(TenantOwnedModel):
    """A standing test procedure attached to an ImplementationControl (D-P3-003) - verifies the
    implementation itself, independent of which framework requirement it happens to be asserted against
    (04_DATA_MODEL.md's tree places Test as a sibling of Evidence/Finding/Exception under
    ImplementationControl, not under ControlAssertion)."""

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="tests")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    test_type = models.CharField(max_length=100, blank=True)
    frequency = models.CharField(max_length=12, choices=Frequency.choices, default=Frequency.ON_DEMAND)
    owner = models.UUIDField(null=True)
    reviewer = models.UUIDField(null=True)
    lifecycle = models.CharField(max_length=10, choices=Lifecycle.choices, default=Lifecycle.DRAFT)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_test"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_test_tenant_id_uniq"),
        ]


class TestResult(TenantOwnedModel):
    """One execution's outcome (D-P3-003). Lifecycle: scheduled -> running -> passed/failed/unknown ->
    remediating -> verified (07_CONTROL_EVIDENCE.md) - only a failed result continues into remediation
    (see the ADR's judgment call); passed/unknown/verified are terminal for that row. Transitions are
    service-enforced (ngrc.controls.services), no DB trigger - same precedent as EvidenceLink.review_state."""

    class Status(models.TextChoices):
        SCHEDULED = "scheduled"
        RUNNING = "running"
        PASSED = "passed"
        FAILED = "failed"
        UNKNOWN = "unknown"
        REMEDIATING = "remediating"
        VERIFIED = "verified"

    test = models.ForeignKey(Test, on_delete=models.PROTECT, related_name="results")
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.SCHEDULED)
    executed_at = models.DateTimeField(null=True)
    detail = models.TextField(blank=True, max_length=2000)
    deadline = models.DateField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_test_result"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_test_result_tenant_id_uniq"),
        ]


class ControlPlan(TenantOwnedModel):
    """A named grouping of tasks under a broader initiative (D-P3-005) - a label, an owner and a target
    date, deliberately thin: nothing in any available spec document asks for more structure than that."""

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    target_date = models.DateField(null=True)
    lifecycle = models.CharField(max_length=10, choices=Lifecycle.choices, default=Lifecycle.DRAFT)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_control_plan"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_control_plan_tenant_id_uniq"),
        ]


class Task(TenantOwnedModel):
    """An assignable, due-dated unit of work against an ImplementationControl (D-P3-005) - sibling of
    EvidenceRequirement/Test under ImplementationControl, never FK'd to Evidence/EvidenceLink directly
    (07_CONTROL_EVIDENCE.md: supporting operations must not create duplicate control/evidence state).
    No stored "overdue" status - derivable from status != done and due_date < today, computed on read."""

    class Status(models.TextChoices):
        OPEN = "open"
        IN_PROGRESS = "in_progress"
        DONE = "done"

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="tasks")
    control_plan = models.ForeignKey(ControlPlan, on_delete=models.PROTECT, related_name="tasks", null=True, blank=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    assigned_to = models.UUIDField(null=True)
    due_date = models.DateField(null=True)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.OPEN)
    completed_at = models.DateTimeField(null=True)
    completed_by = models.UUIDField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_task"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_task_tenant_id_uniq"),
        ]


class Finding(TenantOwnedModel):
    """A mutable, verified-close lifecycle record of a control gap (D-P4-001) - sibling of Evidence/Tests
    under ImplementationControl per the P0 Required Model tree. Remediation is this model's own
    in_remediation state + remediation_notes, not a separate model - nothing in any spec document gives
    Remediation distinct fields of its own."""

    class Source(models.TextChoices):
        TEST = "test"
        AUDIT = "audit"
        RISK = "risk"
        MANUAL = "manual"
        INTEGRATION = "integration"
        AI_PROPOSAL = "ai_proposal"

    class Severity(models.TextChoices):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class Status(models.TextChoices):
        OPEN = "open"
        IN_REMEDIATION = "in_remediation"
        PENDING_VERIFICATION = "pending_verification"
        CLOSED = "closed"

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="findings")
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, max_length=2000)
    source = models.CharField(max_length=12, choices=Source.choices)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    remediation_notes = models.TextField(blank=True, max_length=2000)
    owner = models.UUIDField(null=True)
    verified_by = models.UUIDField(null=True)
    verified_at = models.DateTimeField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_finding"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_finding_tenant_id_uniq"),
        ]


class SecurityException(TenantOwnedModel):
    """Append-only governed waiver (D-P4-001, 07_CONTROL_EVIDENCE.md's "Exceptions" section). Named
    SecurityException, not Exception, to avoid shadowing Python's own builtin - same naming this project's
    own reference notes (CISO Assistant) already use for the identical object, not a coincidence. No status
    field: an exception is either live or expired, derived from expiry_date, never stored - same reasoning
    as Task's derived overdue (D-P3-005). DB-immutable: see migration 0010_security's
    ten_security_exception_guard trigger, same pattern as ten_evidence_revision_guard."""

    implementation_control = models.ForeignKey(ImplementationControl, on_delete=models.PROTECT, related_name="exceptions")
    scope = models.TextField(max_length=2000)
    reason = models.TextField(max_length=2000)
    approver = models.UUIDField()
    approved_at = models.DateTimeField()
    expiry_date = models.DateField()
    compensating_control = models.TextField(blank=True, max_length=2000)
    residual_risk = models.TextField(blank=True, max_length=2000)
    auditor_visible = models.BooleanField(default=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_security_exception"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_security_exception_tenant_id_uniq"),
        ]
