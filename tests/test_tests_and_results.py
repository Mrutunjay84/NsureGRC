"""D-P3-003: tests and test results - the transition graph (only a failed result continues into
remediation), executed_at stamping, and tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import Test as ControlTest
from ngrc.controls.models import TestResult as ControlTestResult
from ngrc.core.context import tenant_context

pytestmark = pytest.mark.security
# pytest would otherwise try (and warn that it cannot) to collect the imported `Test` model class itself,
# since it matches pytest's own "Test*" class-collection convention - aliased on import to avoid the noise.


def _make_test(tenant_a) -> ControlTest:
    cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
    impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
    return control_services.create_test(impl, "Quarterly access review", created_by=uuid.uuid4(),
                                        test_type="manual", frequency="quarterly")


def test_create_test(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        uow.flush()
    assert t.frequency == "quarterly"
    assert t.test_type == "manual"


def test_schedule_test_result_starts_at_scheduled(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
        uow.flush()
    assert result.status == ControlTestResult.Status.SCHEDULED
    assert result.executed_at is None


def test_transition_graph_happy_path_running_to_passed(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
        uow.flush()
        result = control_services.transition_test_result(result, ControlTestResult.Status.RUNNING, actor_id=uuid.uuid4())
        assert result.status == ControlTestResult.Status.RUNNING
        assert result.executed_at is not None
        result = control_services.transition_test_result(result, ControlTestResult.Status.PASSED, actor_id=uuid.uuid4(),
                                                           detail="all checks green")
        assert result.status == ControlTestResult.Status.PASSED
        assert result.detail == "all checks green"


def test_failed_result_can_continue_into_remediation_and_verified(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
        uow.flush()
        result = control_services.transition_test_result(result, ControlTestResult.Status.RUNNING, actor_id=uuid.uuid4())
        result = control_services.transition_test_result(result, ControlTestResult.Status.FAILED, actor_id=uuid.uuid4(),
                                                           deadline="2026-12-01")
        assert result.status == ControlTestResult.Status.FAILED
        assert str(result.deadline) == "2026-12-01"
        result = control_services.transition_test_result(result, ControlTestResult.Status.REMEDIATING, actor_id=uuid.uuid4())
        assert result.status == ControlTestResult.Status.REMEDIATING
        result = control_services.transition_test_result(result, ControlTestResult.Status.VERIFIED, actor_id=uuid.uuid4())
        assert result.status == ControlTestResult.Status.VERIFIED


@pytest.mark.parametrize("terminal_status", [ControlTestResult.Status.PASSED, ControlTestResult.Status.UNKNOWN,
                                              ControlTestResult.Status.VERIFIED])
def test_terminal_statuses_cannot_continue_into_remediation(tenant_a, terminal_status):
    """Deliberate departure from the spec's literal single-arrow-chain reading (D-P3-003 ADR): only a
    failed result has anything to remediate."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
        uow.flush()
        result.status = terminal_status
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.transition_test_result(result, ControlTestResult.Status.REMEDIATING, actor_id=uuid.uuid4())


def test_scheduled_cannot_skip_straight_to_passed(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.transition_test_result(result, ControlTestResult.Status.PASSED, actor_id=uuid.uuid4())


def test_a_tenant_cannot_see_another_tenants_test(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        t = _make_test(tenant_a)
        uow.flush()
        test_id = t.id
    with tenant_context(tenant_b.id):
        assert not ControlTest.objects.filter(id=test_id).exists()
