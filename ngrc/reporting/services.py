"""Posture, control health, framework coverage, evidence coverage, high-finding ageing, overdue-task,
audit-bottleneck metrics and the tenant metrics report (D-P5-001..006, D-P5-008).

Pure read-model computation over ngrc.controls/ngrc.framework/ngrc.compliance_audit data - no models, no
migrations, nothing stored here. Callers must already be inside the target tenant's `tenant_context()`,
same convention as every other domain's service module; these functions are read-only (no audit events -
nothing is being decided or changed, only measured, same reasoning as ngrc.risk.services.risk_level and
ngrc.controls.services._fresh_accepted_links).
"""
from __future__ import annotations

from datetime import timedelta

from ngrc.compliance_audit.models import Audit
from ngrc.controls import services as control_services
from ngrc.controls.models import (
    ControlAssertion,
    ControlPlan,
    EvidenceLink,
    EvidenceRequirement,
    Finding,
    ImplementationControl,
    SatisfactionState,
    SecurityException,
    Task,
)
from ngrc.core import clock
from ngrc.framework import services as framework_services
from ngrc.framework.models import FrameworkActivation
from ngrc.governance.models import Issue, Objective, Policy
from ngrc.privacy.models import RightsRequest
from ngrc.risk.models import RiskAcceptance

# Excluded entirely from both sides of the posture ratio - per the Status Rule ("never infer compliance
# from missing values"), an assertion nobody has evaluated yet cannot honestly score as a measured 0% or
# 100%. Any SatisfactionState not listed here is excluded, not defaulted to anything.
_EFFECTIVENESS_SCORE: dict[str, float] = {
    SatisfactionState.NEEDS_ATTENTION: 0.0,
    SatisfactionState.PARTIALLY_EFFECTIVE: 0.5,
    SatisfactionState.EFFECTIVE: 1.0,
    SatisfactionState.VERIFIED: 1.0,
}

# Worst-first severity order for control_health's rollup - lower index is worse. not_assessed/unknown rank
# worse than needs_attention here specifically: an implementation with an unevaluated requirement is not
# "healthy" merely because its other requirements happen to be fine.
_HEALTH_SEVERITY_ORDER: tuple[str, ...] = (
    SatisfactionState.NOT_ASSESSED,
    SatisfactionState.UNKNOWN,
    SatisfactionState.NEEDS_ATTENTION,
    SatisfactionState.PARTIALLY_EFFECTIVE,
    SatisfactionState.EFFECTIVE,
    SatisfactionState.VERIFIED,
)


def tenant_posture() -> dict:
    """Weighted posture across every ControlAssertion in the current tenant context (D-P5-001). Weight is
    `coverage` (0-100) if set, else 100 (full weight - the honest default for "unknown coverage" is "count
    it like any other row", not zero or one hundred by assumption). `posture_pct` is None, not 0, when
    nothing has been scored yet - a real absence of measurement, not a 0% score pretending to be one."""
    weighted_sum = 0.0
    weight_total = 0.0
    scored_count = 0
    excluded_count = 0
    for state, coverage in ControlAssertion.objects.values_list("satisfaction_state", "coverage"):
        score = _EFFECTIVENESS_SCORE.get(state)
        if score is None:
            excluded_count += 1
            continue
        weight = 100.0 if coverage is None else float(coverage)
        weighted_sum += weight * score
        weight_total += weight
        scored_count += 1
    posture_pct = (weighted_sum / weight_total * 100.0) if weight_total > 0 else None
    return {"posture_pct": posture_pct, "scored_count": scored_count, "excluded_count": excluded_count}


def control_health(implementation_control: ImplementationControl) -> dict:
    """Worst-assertion rollup for one ImplementationControl (D-P5-001) - a control with nine effective
    assertions and one failing one is not 90% healthy, it has a real gap (same "weakest link" reasoning
    this project's CISO Assistant reference notes flag as a good pattern)."""
    assertions = list(
        ControlAssertion.objects.filter(implementation_control=implementation_control)
        .values_list("id", "satisfaction_state")
    )
    if not assertions:
        return {"health": SatisfactionState.NOT_ASSESSED, "worst_assertion_id": None, "assertion_count": 0}
    worst_id, worst_state = None, None
    worst_rank = -1
    for assertion_id, state in assertions:
        rank = _HEALTH_SEVERITY_ORDER.index(state) if state in _HEALTH_SEVERITY_ORDER else 0
        if worst_rank == -1 or rank < worst_rank:
            worst_rank, worst_id, worst_state = rank, assertion_id, state
    return {"health": worst_state, "worst_assertion_id": worst_id, "assertion_count": len(assertions)}


def framework_coverage(framework_urn: str) -> dict:
    """What fraction of a resolved framework's requirements have at least one ControlAssertion (D-P5-002) -
    "mapped", not "effective" (see the ADR's judgment call; tenant_posture/control_health answer the
    effectiveness question instead). Fails closed the same way assert_control does: raises
    ngrc.framework.services.FrameworkError if the tenant has not activated this framework."""
    resolved_urns = {r.urn for r in framework_services.resolve_requirements(framework_urn)}
    asserted_urns = set(
        ControlAssertion.objects.filter(framework_urn=framework_urn)
        .values_list("requirement_urn", flat=True).distinct()
    )
    covered = resolved_urns & asserted_urns
    total = len(resolved_urns)
    coverage_pct = (len(covered) / total * 100.0) if total > 0 else None
    return {
        "total_requirements": total,
        "covered_count": len(covered),
        "coverage_pct": coverage_pct,
        "uncovered_requirement_urns": sorted(resolved_urns - asserted_urns),
    }


def evidence_coverage(implementation_control: ImplementationControl) -> dict:
    """What fraction of an ImplementationControl's EvidenceRequirements are satisfied by at least one fresh,
    accepted EvidenceLink (D-P5-003). Every EvidenceRequirement row counts, regardless of its `lifecycle`
    field - that field (draft/active/retired) has no transition service anywhere in `ngrc.controls` yet
    (same for CommonControl/ImplementationControl/ControlPlan's own `lifecycle`, confirmed by
    `test_tasks_and_plans.py`'s `plan.lifecycle == "draft"` check), so every row created through
    `create_evidence_requirement` sits at its `draft` default forever today - gating this metric on
    `lifecycle == active` would make it report `None`/zero for every real tenant until an activation
    workflow exists that nothing in this codebase builds. The model's own docstring already defines an
    EvidenceRequirement as "a standing expectation" the moment it exists, with no lifecycle qualifier -
    this metric takes that definition literally rather than inventing a gate the data can never satisfy.
    Freshness/acceptance reuses `ngrc.controls.services.is_link_fresh` rather than re-deriving it - that
    staleness arithmetic has exactly one definition in this codebase. `coverage_pct` is `0.0` (a real
    measurement), not `None`, when requirements exist but none are satisfied - same "known denominator"
    reasoning as `framework_coverage`; it is `None` only when the control has no EvidenceRequirements at
    all."""
    requirements = list(EvidenceRequirement.objects.filter(implementation_control=implementation_control))
    if not requirements:
        return {"total_requirements": 0, "covered_count": 0, "coverage_pct": None, "uncovered_requirement_ids": []}

    links = list(
        EvidenceLink.objects.filter(
            evidence_requirement__in=requirements, review_state=EvidenceLink.ReviewState.ACCEPTED,
        ).select_related("evidence_requirement")
    )
    covered_ids = {link.evidence_requirement_id for link in links if control_services.is_link_fresh(link)}
    total = len(requirements)
    covered_count = len(covered_ids)
    return {
        "total_requirements": total,
        "covered_count": covered_count,
        "coverage_pct": covered_count / total * 100.0,
        "uncovered_requirement_ids": sorted(r.id for r in requirements if r.id not in covered_ids),
    }


def high_finding_ageing() -> dict:
    """How long the current tenant's currently-open high/critical Findings have been open (D-P5-004). "High
    finding" reuses `ngrc.controls.services.HIGH_FINDING_SEVERITIES` - the same definition D-P5-007's
    `raise_finding` notification trigger uses, not re-derived here. Age is `now() - created_at` in days -
    `Finding` has no per-status timestamp to measure time-in-current-state instead (same data limitation
    `is_link_fresh` already works within). Tenant-wide, not per-control - ageing is inherently a
    cross-control worklist question, unlike `control_health`/`evidence_coverage`. `oldest_age_days` is
    `None` only when there are no open high/critical findings at all - a real (good) state, not an absence
    of measurement."""
    now = clock.now()
    findings = (
        Finding.objects.filter(severity__in=control_services.HIGH_FINDING_SEVERITIES)
        .exclude(status=Finding.Status.CLOSED)
        .values_list("id", "severity", "status", "created_at", "implementation_control_id")
    )
    rows = [
        {
            "id": finding_id,
            "severity": severity,
            "status": status,
            "age_days": (now - created_at).days,
            "implementation_control_id": implementation_control_id,
        }
        for finding_id, severity, status, created_at, implementation_control_id in findings
    ]
    rows.sort(key=lambda row: row["age_days"], reverse=True)
    return {
        "count": len(rows),
        "oldest_age_days": rows[0]["age_days"] if rows else None,
        "findings": rows,
    }


def overdue_tasks() -> dict:
    """The tenant's currently-open Tasks whose due_date has passed (D-P5-005) - the owner-bottleneck half of
    `02_PRD.md`'s "remediation and review bottlenecks" metric. Exactly what `Task`'s own docstring (D-P3-005)
    already specifies: "No stored overdue status - derivable from status != done and due_date < today,
    computed on read." A Task with no due_date is never overdue - nothing to measure it against. The
    review-workflow half of this metric (Audit/AuditItem, EvidenceLink's in_review state) is a separate,
    not-yet-made judgment call and is NOT built here - see the ADR's scope note."""
    today = clock.now().date()
    tasks = (
        Task.objects.exclude(status=Task.Status.DONE)
        .filter(due_date__lt=today)
        .values_list("id", "title", "assigned_to", "due_date", "implementation_control_id")
    )
    rows = [
        {
            "id": task_id,
            "title": title,
            "assigned_to": assigned_to,
            "due_date": due_date,
            "days_overdue": (today - due_date).days,
            "implementation_control_id": implementation_control_id,
        }
        for task_id, title, assigned_to, due_date, implementation_control_id in tasks
    ]
    rows.sort(key=lambda row: row["days_overdue"], reverse=True)
    return {
        "count": len(rows),
        "most_overdue_days": rows[0]["days_overdue"] if rows else None,
        "tasks": rows,
    }


# Every non-terminal Audit.Status except the two where the *current owner* is the one making forward
# progress (D-P5-006's judgment call, drawn from ngrc.compliance_audit.services._ALLOWED_AUDIT_TRANSITIONS'
# own graph, not invented): draft (being set up) and in_progress (being actively worked by the assignee).
_AUDIT_NOT_A_BOTTLENECK = (Audit.Status.DRAFT, Audit.Status.IN_PROGRESS, Audit.Status.LOCKED)


def audit_bottlenecks() -> dict:
    """The tenant's compliance Audits currently waiting on someone other than their current owner
    (D-P5-006) - the review-workflow half of `02_PRD.md`'s "remediation and review bottlenecks" metric
    (D-P5-005 is the task/owner half). Age is `now() - created_at`, same data limitation as
    `high_finding_ageing`/`overdue_tasks`: `Audit` has no per-status timestamp, so this necessarily includes
    time spent in `draft`/`in_progress` before the audit became a bottleneck - the only honest measurement
    this data supports."""
    now = clock.now()
    audits = (
        Audit.objects.exclude(status__in=_AUDIT_NOT_A_BOTTLENECK)
        .values_list("id", "status", "created_at", "assigned_to", "reviewer", "framework_urn")
    )
    rows = [
        {
            "id": audit_id,
            "status": status,
            "age_days": (now - created_at).days,
            "assigned_to": assigned_to,
            "reviewer": reviewer,
            "framework_urn": framework_urn,
        }
        for audit_id, status, created_at, assigned_to, reviewer, framework_urn in audits
    ]
    rows.sort(key=lambda row: row["age_days"], reverse=True)
    return {
        "count": len(rows),
        "oldest_age_days": rows[0]["age_days"] if rows else None,
        "audits": rows,
    }


def tenant_report() -> dict:
    """Every Phase 5 metric for the current tenant, assembled into one snapshot (D-P5-008) - "reports" from
    `11_MASTER_CLAUDE_BUILD_SPEC.md`'s Phase 5 line, scoped as structured data only: no rendering/UI exists
    anywhere in this project, and nothing here invents one. Pure composition of already-built, already-
    tested functions - no new metric logic. `control_health`/`evidence_coverage` are rolled up across every
    ImplementationControl in the tenant; `framework_coverage` across every framework the tenant has an
    active FrameworkActivation for - a report wants the whole picture, not one call site."""
    controls = list(ImplementationControl.objects.all())
    framework_urns = (
        FrameworkActivation.objects.filter(status=FrameworkActivation.Status.ACTIVE)
        .values_list("framework_urn", flat=True).distinct()
    )
    return {
        "posture": tenant_posture(),
        "high_finding_ageing": high_finding_ageing(),
        "overdue_tasks": overdue_tasks(),
        "audit_bottlenecks": audit_bottlenecks(),
        "control_health": {str(c.id): control_health(c) for c in controls},
        "evidence_coverage": {str(c.id): evidence_coverage(c) for c in controls},
        "framework_coverage": {urn: framework_coverage(urn) for urn in framework_urns},
    }


def calendar_deadlines(window_days: int = 90) -> list[dict]:
    """D-P7-003: Calendar, built as a read-only aggregation over every due-date-bearing field this
    codebase already has - no new model, no migration (07_CONTROL_EVIDENCE.md: "Tasks, control plans,
    calendar and control-health/X-ray views are operational surfaces over the same core objects; they must
    not create duplicate control/evidence state"). `overdue` is computed on read, never stored - same
    reasoning as Task's own existing "no stored overdue status". `window_days` only bounds how far into the
    future a date may be to be included; anything already overdue is always included regardless of how long
    ago, matching overdue_tasks()'s own unbounded look-back."""
    today = clock.now().date()
    horizon = today + timedelta(days=window_days)

    def _entry(date, domain, object_type, object_id, title):
        return {"date": date, "domain": domain, "object_type": object_type, "object_id": str(object_id),
                "title": title, "overdue": date < today}

    rows: list[dict] = []
    for t in Task.objects.exclude(status=Task.Status.DONE).exclude(due_date=None):
        rows.append(_entry(t.due_date, "controls", "task", t.id, t.title))
    for p in ControlPlan.objects.exclude(target_date=None):
        rows.append(_entry(p.target_date, "controls", "control_plan", p.id, p.name))
    for c in ImplementationControl.objects.exclude(due_date=None):
        rows.append(_entry(c.due_date, "controls", "implementation_control", c.id, c.name))
    for e in SecurityException.objects.all():
        rows.append(_entry(e.expiry_date, "controls", "security_exception", e.id, e.scope[:200]))
    for a in RiskAcceptance.objects.all():
        rows.append(_entry(a.expiry_date, "risk", "risk_acceptance", a.id, a.justification[:200]))
    for p in Policy.objects.filter(status=Policy.Status.ACTIVE).exclude(next_review_date=None):
        rows.append(_entry(p.next_review_date, "governance", "policy", p.id, p.title))
    for o in Objective.objects.filter(status=Objective.Status.OPEN).exclude(target_date=None):
        rows.append(_entry(o.target_date, "governance", "objective", o.id, o.title))
    for i in Issue.objects.exclude(status__in=[Issue.Status.RESOLVED, Issue.Status.CLOSED]).exclude(due_date=None):
        rows.append(_entry(i.due_date, "governance", "issue", i.id, i.title))
    for r in (RightsRequest.objects
              .exclude(status__in=[RightsRequest.Status.FULFILLED, RightsRequest.Status.REJECTED, RightsRequest.Status.CLOSED])
              .exclude(due_date=None)):
        rows.append(_entry(r.due_date, "privacy", "rights_request", r.id, r.requester_reference))

    rows = [r for r in rows if r["overdue"] or r["date"] <= horizon]
    rows.sort(key=lambda r: r["date"])
    return rows
