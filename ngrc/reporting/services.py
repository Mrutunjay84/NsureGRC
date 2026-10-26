"""Posture and control health metrics (D-P5-001).

Pure read-model computation over ngrc.controls data - no models, no migrations, nothing stored here. Callers
must already be inside the target tenant's `tenant_context()`, same convention as every other domain's
service module; these functions are read-only (no audit events - nothing is being decided or changed, only
measured, same reasoning as ngrc.risk.services.risk_level and ngrc.controls.services._fresh_accepted_links).
"""
from __future__ import annotations

from ngrc.controls.models import ControlAssertion, ImplementationControl, SatisfactionState

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
