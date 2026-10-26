"""D-P4-002: risk assessments, scenarios and acceptances - risk_level thresholds, the scenario transition
graph (accept only through accept_risk_scenario), and risk acceptance append-only enforcement."""
from __future__ import annotations

import uuid

import psycopg
import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.risk import services as risk_services
from ngrc.risk.models import RiskAssessment, RiskScenario

from .conftest import role_connect

pytestmark = pytest.mark.security


def _assessment():
    return risk_services.create_risk_assessment("2027 Annual", created_by=uuid.uuid4())


def _scenario(assessment, *, likelihood=3, impact=3):
    return risk_services.create_risk_scenario(assessment, "Unpatched legacy server", likelihood=likelihood,
                                               impact=impact, created_by=uuid.uuid4())


@pytest.mark.parametrize("likelihood,impact,expected", [
    (1, 1, "low"),       # score 1
    (2, 2, "medium"),    # score 4 (medium floor)
    (2, 3, "medium"),    # score 6
    (3, 3, "high"),      # score 9 (high floor)
    (3, 4, "high"),      # score 12
    (5, 2, "high"),      # score 10
    (4, 4, "critical"),  # score 16 (critical floor is 15)
    (5, 5, "critical"),  # score 25
    (4, 5, "critical"),  # score 20
])
def test_risk_level_thresholds(likelihood, impact, expected):
    assert risk_services.risk_level(likelihood, impact) == expected


def test_create_risk_assessment_and_scenario(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment, likelihood=4, impact=4)
        uow.flush()
    assert scenario.risk_assessment_id == assessment.id
    assert scenario.status == RiskScenario.Status.OPEN
    assert scenario.treatment is None


def test_create_risk_scenario_fails_closed_on_out_of_range_scores(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        uow.flush()
        with pytest.raises(risk_services.RiskError, match="likelihood_and_impact_must_be_1_to_5"):
            risk_services.create_risk_scenario(assessment, "x", likelihood=6, impact=3, created_by=uuid.uuid4())
        with pytest.raises(risk_services.RiskError, match="likelihood_and_impact_must_be_1_to_5"):
            risk_services.create_risk_scenario(assessment, "x", likelihood=3, impact=0, created_by=uuid.uuid4())


def test_set_treatment(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        scenario = risk_services.set_treatment(scenario, RiskScenario.Treatment.MITIGATE, actor_id=uuid.uuid4())
    assert scenario.treatment == RiskScenario.Treatment.MITIGATE


def test_scenario_transition_graph_happy_path(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        scenario = risk_services.transition_scenario(scenario, RiskScenario.Status.TREATING, actor_id=uuid.uuid4())
        assert scenario.status == RiskScenario.Status.TREATING
        scenario = risk_services.transition_scenario(scenario, RiskScenario.Status.CLOSED, actor_id=uuid.uuid4())
        assert scenario.status == RiskScenario.Status.CLOSED
        scenario = risk_services.transition_scenario(scenario, RiskScenario.Status.OPEN, actor_id=uuid.uuid4())
        assert scenario.status == RiskScenario.Status.OPEN


def test_transition_scenario_rejects_accepted_directly(tenant_a):
    """accepted is reachable only through accept_risk_scenario (D-P4-002)."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        with pytest.raises(risk_services.RiskError, match="accepted_requires_accept_risk_scenario"):
            risk_services.transition_scenario(scenario, RiskScenario.Status.ACCEPTED, actor_id=uuid.uuid4())


def test_accept_risk_scenario_creates_acceptance_and_transitions_atomically(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        approver = uuid.uuid4()
        acceptance = risk_services.accept_risk_scenario(
            scenario, "Low exposure, cost to remediate exceeds residual risk", approver=approver,
            expiry_date="2027-12-31", created_by=uuid.uuid4(),
        )
        scenario.refresh_from_db()
    assert scenario.status == RiskScenario.Status.ACCEPTED
    assert acceptance.approver == approver
    assert str(acceptance.expiry_date) == "2027-12-31"


def test_cannot_accept_an_already_accepted_or_closed_scenario(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        risk_services.accept_risk_scenario(scenario, "reason", approver=uuid.uuid4(), expiry_date="2027-12-31",
                                            created_by=uuid.uuid4())
        with pytest.raises(risk_services.RiskError, match="invalid_transition"):
            risk_services.accept_risk_scenario(scenario, "reason again", approver=uuid.uuid4(),
                                                expiry_date="2027-12-31", created_by=uuid.uuid4())


def test_risk_acceptance_is_append_only_rejects_update_delete_truncate(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        acceptance = risk_services.accept_risk_scenario(
            scenario, "reason", approver=uuid.uuid4(), expiry_date="2027-12-31", created_by=uuid.uuid4(),
        )
        acceptance_id = acceptance.id
    with role_connect("ngrc_owner") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only and immutable"):
            c.execute("UPDATE ten_risk_acceptance SET justification = 'changed' WHERE id = %s", [acceptance_id])
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only and never deleted"):
            c.execute("DELETE FROM ten_risk_acceptance WHERE id = %s", [acceptance_id])
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="never truncated"):
            c.execute("TRUNCATE ten_risk_acceptance")


def test_ngrc_app_has_no_update_privilege_on_risk_acceptance(tenant_a):
    with role_connect("ngrc_app") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE ten_risk_acceptance SET justification = 'x' WHERE id = gen_random_uuid()")


def test_a_tenant_cannot_see_another_tenants_risk_data(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = _assessment()
        scenario = _scenario(assessment)
        uow.flush()
        assessment_id, scenario_id = assessment.id, scenario.id
    with tenant_context(tenant_b.id):
        assert not RiskAssessment.objects.filter(id=assessment_id).exists()
        assert not RiskScenario.objects.filter(id=scenario_id).exists()
