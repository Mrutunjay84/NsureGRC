"""D-P3-001: Common/Implementation controls and control assertions - tenant isolation, and the
fail-closed requirement link that reuses the Framework Engine's own resolver."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import CommonControl, SatisfactionState
from ngrc.core.context import tenant_context
from ngrc.framework import services as framework_services

pytestmark = pytest.mark.security


def _framework_with_requirement(urn_suffix: str | None = None):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-ctrl-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Controls",
    )
    version = framework_services.draft_version(fw, "v1", created_by=uuid.uuid4())
    framework_services.add_requirement(version, "req-a", "A.1", "Control A")
    framework_services.publish_version(version, published_by=uuid.uuid4())
    return fw


def test_create_common_and_implementation_control(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("access-control", "Access Control", created_by=uuid.uuid4(),
                                                      objective="Restrict access to authorized users")
        impl = control_services.create_implementation_control(cc, "Okta SSO enforcement", created_by=uuid.uuid4())
        uow.flush()
    assert impl.common_control_id == cc.id
    assert cc.key == "access-control"


def _activate(tenant, fw):
    version = _published_version(fw)
    with tenant_context(tenant.id), audit_service.unit_of_work(tenant.id) as uow:
        framework_services.activate_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()


def _published_version(fw):
    from ngrc.framework.models import FrameworkVersion

    return FrameworkVersion.objects.using("default").get(framework=fw, version_label="v1")


def test_assert_control_against_a_resolved_requirement(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        assertion = control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())
        uow.flush()
    assert assertion.requirement_urn == "req-a"
    # 07_CONTROL_EVIDENCE.md: health is derived from tests/evidence/review state, none of which exist yet
    # (EvidenceLink/Test are later increments) - anything other than "unknown" here would be fiction.
    assert assertion.satisfaction_state == SatisfactionState.UNKNOWN


def test_assert_control_fails_closed_without_an_activation(tenant_a):
    fw = _framework_with_requirement()
    # deliberately NOT activated
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(control_services.ControlError, match="framework_not_resolved"):
            control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())


def test_assert_control_fails_closed_for_an_unknown_requirement_urn(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(control_services.ControlError, match="requirement_not_resolved"):
            control_services.assert_control(impl, fw.urn, "does-not-exist", created_by=uuid.uuid4())


def test_a_tenant_cannot_see_another_tenants_common_control(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        uow.flush()
        key = cc.key
    with tenant_context(tenant_b.id):
        assert not CommonControl.objects.filter(key=key).exists()
