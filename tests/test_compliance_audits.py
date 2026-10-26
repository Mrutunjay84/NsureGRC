"""D-P4-005: compliance audits and audit items - creation fails closed on an unresolved framework, the
eight-plus-fork transition graph (including the changes_requested rework loop and no edge leaving locked),
result is never auto-derived from a linked ControlAssertion, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.compliance_audit import services as ca_services
from ngrc.compliance_audit.models import Audit, AuditItem
from ngrc.controls import services as control_services
from ngrc.controls.models import SatisfactionState
from ngrc.core.context import tenant_context
from ngrc.framework import services as framework_services

pytestmark = pytest.mark.security


def _framework_with_requirement(urn_suffix: str | None = None):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-audit-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Audits",
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


def test_create_audit_fails_closed_without_an_activation(tenant_a):
    fw = _framework_with_requirement()
    # deliberately NOT activated
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        uow.flush()
        with pytest.raises(ca_services.ComplianceAuditError, match="framework_not_resolved"):
            ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())


def test_create_audit_and_add_item(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        item = ca_services.add_audit_item(audit_obj, "req-a", created_by=uuid.uuid4())
        uow.flush()
    assert audit_obj.status == Audit.Status.DRAFT
    assert item.result == AuditItem.Result.NOT_ASSESSED


def test_add_audit_item_fails_closed_for_an_unknown_requirement_urn(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(ca_services.ComplianceAuditError, match="requirement_not_resolved"):
            ca_services.add_audit_item(audit_obj, "does-not-exist", created_by=uuid.uuid4())


def test_audit_transition_graph_happy_path_to_locked(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        uow.flush()
        for target in (Audit.Status.ASSIGNED, Audit.Status.IN_PROGRESS, Audit.Status.SUBMITTED,
                       Audit.Status.REVIEW, Audit.Status.ACCEPTED, Audit.Status.SIGNOFF, Audit.Status.LOCKED):
            audit_obj = ca_services.transition_audit(audit_obj, target, actor_id=uuid.uuid4())
    assert audit_obj.status == Audit.Status.LOCKED
    assert audit_obj.locked_at is not None


def test_changes_requested_loops_back_to_in_progress(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        uow.flush()
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.ASSIGNED, actor_id=uuid.uuid4())
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.IN_PROGRESS, actor_id=uuid.uuid4())
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.SUBMITTED, actor_id=uuid.uuid4())
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.REVIEW, actor_id=uuid.uuid4())
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.CHANGES_REQUESTED, actor_id=uuid.uuid4())
        assert audit_obj.status == Audit.Status.CHANGES_REQUESTED
        audit_obj = ca_services.transition_audit(audit_obj, Audit.Status.IN_PROGRESS, actor_id=uuid.uuid4())
        assert audit_obj.status == Audit.Status.IN_PROGRESS


def test_no_edge_leaves_locked(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        uow.flush()
        for target in (Audit.Status.ASSIGNED, Audit.Status.IN_PROGRESS, Audit.Status.SUBMITTED,
                       Audit.Status.REVIEW, Audit.Status.ACCEPTED, Audit.Status.SIGNOFF, Audit.Status.LOCKED):
            audit_obj = ca_services.transition_audit(audit_obj, target, actor_id=uuid.uuid4())
        with pytest.raises(ca_services.ComplianceAuditError, match="invalid_transition"):
            ca_services.transition_audit(audit_obj, Audit.Status.DRAFT, actor_id=uuid.uuid4())


def test_audit_cannot_skip_review_straight_to_signoff(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(ca_services.ComplianceAuditError, match="invalid_transition"):
            ca_services.transition_audit(audit_obj, Audit.Status.SIGNOFF, actor_id=uuid.uuid4())


def test_audit_item_result_is_never_auto_derived_from_control_assertion(tenant_a):
    """D-P4-005: an auditor's verdict is an independent human judgment - linking a ControlAssertion never
    changes AuditItem.result automatically, even when its own satisfaction_state is EFFECTIVE."""
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        assertion = control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        item = ca_services.add_audit_item(audit_obj, "req-a", created_by=uuid.uuid4(), control_assertion=assertion)
        uow.flush()
        assert assertion.satisfaction_state == SatisfactionState.UNKNOWN
        assert item.result == AuditItem.Result.NOT_ASSESSED
        item = ca_services.set_audit_item_result(item, AuditItem.Result.NON_COMPLIANT, actor_id=uuid.uuid4(),
                                                  observation="no evidence on file despite the assertion")
    assert item.result == AuditItem.Result.NON_COMPLIANT


def test_audit_item_without_a_control_assertion_is_valid(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        item = ca_services.add_audit_item(audit_obj, "req-a", created_by=uuid.uuid4())
        uow.flush()
    assert item.control_assertion_id is None


def test_a_tenant_cannot_see_another_tenants_audit(tenant_a, tenant_b):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = ca_services.create_audit(fw.urn, "2027 Annual Audit", created_by=uuid.uuid4())
        item = ca_services.add_audit_item(audit_obj, "req-a", created_by=uuid.uuid4())
        uow.flush()
        audit_id, item_id = audit_obj.id, item.id
    with tenant_context(tenant_b.id):
        assert not Audit.objects.filter(id=audit_id).exists()
        assert not AuditItem.objects.filter(id=item_id).exists()
