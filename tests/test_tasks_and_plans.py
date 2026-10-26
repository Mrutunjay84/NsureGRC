"""D-P3-005: tasks and control plans - the task transition graph (including the done -> open reopen edge),
completed_at/completed_by stamping, optional control_plan linkage, and that none of this touches
ControlAssertion.satisfaction_state."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import ControlAssertion, ControlPlan, SatisfactionState
from ngrc.controls.models import Task as ControlTask
from ngrc.core.context import tenant_context
from ngrc.framework import services as framework_services

pytestmark = pytest.mark.security


def _framework_with_requirement(urn_suffix: str | None = None):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-task-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Tasks",
    )
    version = framework_services.draft_version(fw, "v1", created_by=uuid.uuid4())
    framework_services.add_requirement(version, "req-a", "A.1", "Control A")
    framework_services.publish_version(version, published_by=uuid.uuid4())
    return fw


def _published_version(fw):
    from ngrc.framework.models import FrameworkVersion

    return FrameworkVersion.objects.using("default").get(framework=fw, version_label="v1")


def _activate(tenant, fw):
    version = _published_version(fw)
    with tenant_context(tenant.id), audit_service.unit_of_work(tenant.id) as uow:
        framework_services.activate_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()


def _impl_and_assertion(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
    impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
    assertion = control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())
    return impl, assertion


def test_create_control_plan(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        plan = control_services.create_control_plan("Q1 2027 SOC 2 readiness", created_by=uuid.uuid4(),
                                                      owner=uuid.uuid4())
        uow.flush()
    assert plan.name == "Q1 2027 SOC 2 readiness"
    assert plan.lifecycle == "draft"


def test_create_task_without_a_control_plan(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
    assert task.control_plan_id is None
    assert task.status == ControlTask.Status.OPEN


def test_create_task_under_a_control_plan(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        plan = control_services.create_control_plan("Q1 2027 SOC 2 readiness", created_by=uuid.uuid4())
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4(), control_plan=plan)
        uow.flush()
    assert task.control_plan_id == plan.id


def test_task_transition_graph_happy_path(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
        task = control_services.transition_task(task, ControlTask.Status.IN_PROGRESS, actor_id=uuid.uuid4())
        assert task.status == ControlTask.Status.IN_PROGRESS
        assert task.completed_at is None
        actor = uuid.uuid4()
        task = control_services.transition_task(task, ControlTask.Status.DONE, actor_id=actor)
        assert task.status == ControlTask.Status.DONE
        assert task.completed_at is not None
        assert task.completed_by == actor


def test_task_can_skip_in_progress_straight_to_done(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
        task = control_services.transition_task(task, ControlTask.Status.DONE, actor_id=uuid.uuid4())
    assert task.status == ControlTask.Status.DONE


def test_done_task_can_be_reopened_and_clears_completion_fields(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
        task = control_services.transition_task(task, ControlTask.Status.DONE, actor_id=uuid.uuid4())
        assert task.completed_at is not None
        task = control_services.transition_task(task, ControlTask.Status.OPEN, actor_id=uuid.uuid4())
        assert task.status == ControlTask.Status.OPEN
        assert task.completed_at is None
        assert task.completed_by is None


def test_task_transition_rejects_an_edge_outside_the_graph(tenant_a):
    """done only allows -> open (reopen), never straight to in_progress."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
        task = control_services.transition_task(task, ControlTask.Status.DONE, actor_id=uuid.uuid4())
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.transition_task(task, ControlTask.Status.IN_PROGRESS, actor_id=uuid.uuid4())


def test_task_activity_does_not_touch_satisfaction_state(tenant_a):
    """07_CONTROL_EVIDENCE.md: supporting operations must not create duplicate control/evidence state."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _impl_and_assertion(tenant_a)
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4())
        uow.flush()
        control_services.transition_task(task, ControlTask.Status.IN_PROGRESS, actor_id=uuid.uuid4())
        control_services.transition_task(task, ControlTask.Status.DONE, actor_id=uuid.uuid4())
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.NOT_ASSESSED


def test_a_tenant_cannot_see_another_tenants_task_or_control_plan(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, _assertion = _impl_and_assertion(tenant_a)
        plan = control_services.create_control_plan("Q1 2027 SOC 2 readiness", created_by=uuid.uuid4())
        task = control_services.create_task(impl, "Rotate access review", created_by=uuid.uuid4(), control_plan=plan)
        uow.flush()
        task_id, plan_id = task.id, plan.id
    with tenant_context(tenant_b.id):
        assert not ControlTask.objects.filter(id=task_id).exists()
        assert not ControlPlan.objects.filter(id=plan_id).exists()
        assert not ControlAssertion.objects.filter(implementation_control_id=impl.id).exists()
