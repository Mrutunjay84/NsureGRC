"""D-P4-003: incidents - the strictly-linear detect-through-close transition graph (no stage skipping),
resolved_at/closed_at stamping, optional risk-scenario/implementation-control links, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.risk import services as risk_services
from ngrc.risk.models import Incident

pytestmark = pytest.mark.security


def _incident(**kw):
    return risk_services.raise_incident("Unauthorized access attempt", severity=Incident.Severity.HIGH,
                                         created_by=uuid.uuid4(), **kw)


def test_raise_incident(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
    assert incident.status == Incident.Status.DETECTED
    assert incident.severity == Incident.Severity.HIGH
    assert incident.detected_at is not None
    assert incident.risk_scenario_id is None
    assert incident.implementation_control_id is None


def test_incident_transition_graph_happy_path(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
        incident = risk_services.transition_incident(incident, Incident.Status.INVESTIGATING, actor_id=uuid.uuid4())
        assert incident.status == Incident.Status.INVESTIGATING
        incident = risk_services.transition_incident(incident, Incident.Status.CONTAINED, actor_id=uuid.uuid4())
        assert incident.status == Incident.Status.CONTAINED
        incident = risk_services.transition_incident(incident, Incident.Status.RESOLVED, actor_id=uuid.uuid4())
        assert incident.status == Incident.Status.RESOLVED
        assert incident.resolved_at is not None
        incident = risk_services.transition_incident(incident, Incident.Status.CLOSED, actor_id=uuid.uuid4())
        assert incident.status == Incident.Status.CLOSED
        assert incident.closed_at is not None


@pytest.mark.parametrize("skip_to", [Incident.Status.CONTAINED, Incident.Status.RESOLVED, Incident.Status.CLOSED])
def test_incident_cannot_skip_stages_from_detected(tenant_a, skip_to):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
        with pytest.raises(risk_services.RiskError, match="invalid_transition"):
            risk_services.transition_incident(incident, skip_to, actor_id=uuid.uuid4())


def test_incident_cannot_skip_investigating_to_resolved(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
        incident = risk_services.transition_incident(incident, Incident.Status.INVESTIGATING, actor_id=uuid.uuid4())
        with pytest.raises(risk_services.RiskError, match="invalid_transition"):
            risk_services.transition_incident(incident, Incident.Status.RESOLVED, actor_id=uuid.uuid4())


def test_closed_incident_can_be_reopened_and_clears_resolution_fields(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
        incident = risk_services.transition_incident(incident, Incident.Status.INVESTIGATING, actor_id=uuid.uuid4())
        incident = risk_services.transition_incident(incident, Incident.Status.CONTAINED, actor_id=uuid.uuid4())
        incident = risk_services.transition_incident(incident, Incident.Status.RESOLVED, actor_id=uuid.uuid4())
        incident = risk_services.transition_incident(incident, Incident.Status.CLOSED, actor_id=uuid.uuid4())
        incident = risk_services.transition_incident(incident, Incident.Status.DETECTED, actor_id=uuid.uuid4())
    assert incident.status == Incident.Status.DETECTED
    assert incident.resolved_at is None
    assert incident.closed_at is None


def test_incident_may_optionally_link_a_risk_scenario(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assessment = risk_services.create_risk_assessment("2027 Annual", created_by=uuid.uuid4())
        scenario = risk_services.create_risk_scenario(assessment, "Unpatched legacy server", likelihood=4, impact=4,
                                                       created_by=uuid.uuid4())
        incident = _incident(risk_scenario=scenario)
        uow.flush()
    assert incident.risk_scenario_id == scenario.id


def test_a_tenant_cannot_see_another_tenants_incident(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        incident = _incident()
        uow.flush()
        incident_id = incident.id
    with tenant_context(tenant_b.id):
        assert not Incident.objects.filter(id=incident_id).exists()
