"""Risk assessments, scenarios and acceptances (D-P4-002); incidents (D-P4-003); assets + BIA (D-P7-002).

All plain TEN writes (no new DB role - D-P0-009's risk/bia/asset/incident domain has no CAT/PLT content
beyond the P1-deferred threat/CWE catalogues). Callers must already be inside the target tenant's
`tenant_context()` and have checked `risk.manage` - services trust an already-authorized caller, same
convention as `ngrc.controls.services` (no HTTP layer exists yet for this app either).
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.core import clock

from .models import Asset, AssetBIA, Incident, RiskAcceptance, RiskAssessment, RiskScenario


class RiskError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_LEVEL_THRESHOLDS = (
    (15, "critical"),
    (9, "high"),
    (4, "medium"),
)


def risk_level(likelihood: int, impact: int) -> str:
    """likelihood * impact (1-25) mapped to a band by fixed thresholds (D-P4-002) - a pure function of the
    two stored inputs, never itself stored."""
    score = likelihood * impact
    for floor, label in _LEVEL_THRESHOLDS:
        if score >= floor:
            return label
    return "low"


def create_risk_assessment(name: str, *, created_by, description: str = "", owner=None, period_start=None,
                            period_end=None) -> RiskAssessment:
    assessment = RiskAssessment.objects.create(
        name=name, description=description, owner=owner, period_start=period_start, period_end=period_end,
        created_by=created_by,
    )
    audit.record("risk.assessment.created", actor_id=created_by, object_type="risk_assessment",
                 object_id=str(assessment.id), details={})
    return assessment


def create_risk_scenario(risk_assessment: RiskAssessment, name: str, *, likelihood: int, impact: int, created_by,
                          description: str = "", threat: str = "", vulnerability: str = "", owner=None,
                          asset: Asset | None = None) -> RiskScenario:
    if not (1 <= likelihood <= 5) or not (1 <= impact <= 5):
        raise RiskError("likelihood_and_impact_must_be_1_to_5")
    scenario = RiskScenario.objects.create(
        risk_assessment=risk_assessment, name=name, description=description, threat=threat,
        vulnerability=vulnerability, likelihood=likelihood, impact=impact, created_by=created_by, owner=owner,
        asset=asset,
    )
    audit.record("risk.scenario.created", actor_id=created_by, object_type="risk_scenario",
                 object_id=str(scenario.id), details={"risk_level": risk_level(likelihood, impact)})
    return scenario


def set_treatment(scenario: RiskScenario, treatment: str, *, actor_id) -> RiskScenario:
    scenario.treatment = treatment
    scenario.save(update_fields=["treatment"])
    audit.record("risk.scenario.treatment_set", actor_id=actor_id, object_type="risk_scenario",
                 object_id=str(scenario.id), details={"treatment": treatment})
    return scenario


_ALLOWED_SCENARIO_TRANSITIONS: dict[str, set[str]] = {
    RiskScenario.Status.OPEN: {RiskScenario.Status.TREATING, RiskScenario.Status.ACCEPTED},
    RiskScenario.Status.TREATING: {RiskScenario.Status.ACCEPTED, RiskScenario.Status.CLOSED},
    RiskScenario.Status.ACCEPTED: {RiskScenario.Status.CLOSED},
    RiskScenario.Status.CLOSED: {RiskScenario.Status.OPEN},
}


def _transition_scenario(scenario: RiskScenario, new_status: str, *, actor_id) -> RiskScenario:
    allowed = _ALLOWED_SCENARIO_TRANSITIONS.get(scenario.status, set())
    if new_status not in allowed:
        raise RiskError(f"invalid_transition:{scenario.status}->{new_status}")
    from_status = scenario.status
    scenario.status = new_status
    scenario.save(update_fields=["status"])
    audit.record("risk.scenario.transitioned", actor_id=actor_id, object_type="risk_scenario",
                 object_id=str(scenario.id), details={"from_status": from_status, "to_status": new_status})
    return scenario


def transition_scenario(scenario: RiskScenario, new_status: str, *, actor_id) -> RiskScenario:
    """Fails closed: `accepted` is reachable only through `accept_risk_scenario()`, which creates the
    `RiskAcceptance` and transitions atomically - calling this directly with `accepted` is rejected so the
    two objects can never go out of sync (D-P4-002)."""
    if new_status == RiskScenario.Status.ACCEPTED:
        raise RiskError("accepted_requires_accept_risk_scenario")
    return _transition_scenario(scenario, new_status, actor_id=actor_id)


def accept_risk_scenario(scenario: RiskScenario, justification: str, *, approver, expiry_date,
                          created_by) -> RiskAcceptance:
    """Creates the RiskAcceptance (append-only, approver/approved_at captured now) and transitions the
    scenario to `accepted` in one call (D-P4-002) - fails closed via the same transition graph as every
    other edge, so an already-accepted or already-closed scenario cannot be accepted again."""
    _transition_scenario(scenario, RiskScenario.Status.ACCEPTED, actor_id=created_by)
    acceptance = RiskAcceptance.objects.create(
        risk_scenario=scenario, justification=justification, approver=approver, approved_at=clock.now(),
        expiry_date=expiry_date, created_by=created_by,
    )
    audit.record("risk.acceptance.recorded", actor_id=created_by, object_type="risk_acceptance",
                 object_id=str(acceptance.id), details={})
    return acceptance


def raise_incident(title: str, *, severity: str, created_by, description: str = "", owner=None,
                    detected_at=None, risk_scenario: RiskScenario | None = None,
                    implementation_control=None, asset: Asset | None = None) -> Incident:
    incident = Incident.objects.create(
        title=title, description=description, severity=severity, owner=owner,
        detected_at=detected_at or clock.now(), risk_scenario=risk_scenario,
        implementation_control=implementation_control, asset=asset, created_by=created_by,
    )
    audit.record("risk.incident.raised", actor_id=created_by, object_type="incident", object_id=str(incident.id),
                 details={"severity": severity})
    return incident


_ALLOWED_INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    Incident.Status.DETECTED: {Incident.Status.INVESTIGATING},
    Incident.Status.INVESTIGATING: {Incident.Status.CONTAINED},
    Incident.Status.CONTAINED: {Incident.Status.RESOLVED},
    Incident.Status.RESOLVED: {Incident.Status.CLOSED},
    Incident.Status.CLOSED: {Incident.Status.DETECTED},
}


def transition_incident(incident: Incident, new_status: str, *, actor_id) -> Incident:
    """Fails closed: strictly linear forward progression through the NIST SP 800-61 stages, no skipping -
    only `closed -> detected` reopens (D-P4-003). resolved_at/closed_at are stamped entering their
    respective states and cleared together on reopening."""
    allowed = _ALLOWED_INCIDENT_TRANSITIONS.get(incident.status, set())
    if new_status not in allowed:
        raise RiskError(f"invalid_transition:{incident.status}->{new_status}")
    from_status = incident.status
    incident.status = new_status
    update_fields = ["status"]
    if new_status == Incident.Status.RESOLVED:
        incident.resolved_at = clock.now()
        update_fields.append("resolved_at")
    elif new_status == Incident.Status.CLOSED:
        incident.closed_at = clock.now()
        update_fields.append("closed_at")
    elif new_status == Incident.Status.DETECTED and from_status == Incident.Status.CLOSED:
        incident.resolved_at, incident.closed_at = None, None
        update_fields += ["resolved_at", "closed_at"]
    incident.save(update_fields=update_fields)
    audit.record("risk.incident.transitioned", actor_id=actor_id, object_type="incident", object_id=str(incident.id),
                 details={"from_status": from_status, "to_status": new_status})
    return incident


def create_asset(name: str, *, asset_type: str, criticality: str, created_by, owner=None,
                  description: str = "") -> Asset:
    asset = Asset.objects.create(
        name=name, asset_type=asset_type, criticality=criticality, owner=owner, description=description,
        created_by=created_by,
    )
    audit.record("asset.created", actor_id=created_by, object_type="asset", object_id=str(asset.id), details={})
    return asset


def record_bia(asset: Asset, *, impact_rating: str, created_by, recovery_time_objective_hours=None,
               recovery_point_objective_hours=None, notes: str = "", assessor=None, assessed_at=None) -> AssetBIA:
    """A new BIA is a new row, never an edit to a prior one (D-P7-002) - same "point-in-time assessment is
    immutable history" reasoning as EvidenceRevision/ControlAssertion review history."""
    bia = AssetBIA.objects.create(
        asset=asset, impact_rating=impact_rating, recovery_time_objective_hours=recovery_time_objective_hours,
        recovery_point_objective_hours=recovery_point_objective_hours, notes=notes, assessor=assessor,
        assessed_at=assessed_at, created_by=created_by,
    )
    audit.record("asset.bia.recorded", actor_id=created_by, object_type="asset_bia", object_id=str(bia.id),
                 details={"impact_rating": impact_rating})
    return bia
