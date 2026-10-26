"""Posture, control health and framework coverage metrics (D-P5-001, D-P5-002).

Pure read-model computation over ngrc.controls/ngrc.framework data - no models, no migrations, nothing
stored here. Callers must already be inside the target tenant's `tenant_context()`, same convention as
every other domain's service module; these functions are read-only (no audit events - nothing is being
decided or changed, only measured, same reasoning as ngrc.risk.services.risk_level and
ngrc.controls.services._fresh_accepted_links).
"""
from __future__ import annotations

from ngrc.controls import services as control_services
from ngrc.controls.models import (
    ControlAssertion,
    EvidenceLink,
    EvidenceRequirement,
    ImplementationControl,
    SatisfactionState,
)
from ngrc.framework import services as framework_services

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
