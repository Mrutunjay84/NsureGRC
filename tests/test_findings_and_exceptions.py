"""D-P4-001: findings (the transition graph, "close requires verification" enforced structurally) and
security exceptions (append-only - DB rejects UPDATE/DELETE/TRUNCATE outright, required approver/expiry)."""
from __future__ import annotations

import uuid

import psycopg
import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import Finding, SecurityException
from ngrc.core.context import tenant_context

from .conftest import role_connect

pytestmark = pytest.mark.security


def _impl(tenant_a):
    cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
    return control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())


def _finding(impl):
    return control_services.raise_finding(impl, "Access review not performed", source="audit", severity="high",
                                           created_by=uuid.uuid4())


def test_raise_finding(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        uow.flush()
    assert finding.status == Finding.Status.OPEN
    assert finding.source == "audit"
    assert finding.severity == "high"


def test_finding_transition_graph_happy_path_through_verification(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        uow.flush()
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4(),
                                                        remediation_notes="assigned to IT")
        assert finding.remediation_notes == "assigned to IT"
        finding = control_services.transition_finding(finding, Finding.Status.PENDING_VERIFICATION, actor_id=uuid.uuid4())
        actor = uuid.uuid4()
        finding = control_services.transition_finding(finding, Finding.Status.CLOSED, actor_id=actor)
    assert finding.status == Finding.Status.CLOSED
    assert finding.verified_by == actor
    assert finding.verified_at is not None


def test_finding_cannot_close_without_verification(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        uow.flush()
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.transition_finding(finding, Finding.Status.CLOSED, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4())
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.transition_finding(finding, Finding.Status.CLOSED, actor_id=uuid.uuid4())


def test_failed_verification_sends_finding_back_to_remediation(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        uow.flush()
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.PENDING_VERIFICATION, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4(),
                                                        remediation_notes="fix was incomplete")
    assert finding.status == Finding.Status.IN_REMEDIATION
    assert finding.remediation_notes == "fix was incomplete"


def test_closed_finding_can_be_reopened_and_clears_verification_fields(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        uow.flush()
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.PENDING_VERIFICATION, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.CLOSED, actor_id=uuid.uuid4())
        assert finding.verified_at is not None
        finding = control_services.transition_finding(finding, Finding.Status.OPEN, actor_id=uuid.uuid4())
    assert finding.status == Finding.Status.OPEN
    assert finding.verified_by is None
    assert finding.verified_at is None


def test_record_security_exception_requires_approver_and_expiry(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        approver = uuid.uuid4()
        exc = control_services.record_exception(
            impl, "MFA not enforced for the legacy integration account", "vendor cannot support TOTP until Q2",
            approver=approver, expiry_date="2027-06-30", created_by=uuid.uuid4(),
            compensating_control="IP allow-list + daily login review", residual_risk="low, single account",
        )
        uow.flush()
    assert exc.approver == approver
    assert str(exc.expiry_date) == "2027-06-30"
    assert exc.auditor_visible is True


def test_security_exception_is_append_only_rejects_update_delete_truncate(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        exc = control_services.record_exception(
            impl, "scope", "reason", approver=uuid.uuid4(), expiry_date="2027-06-30", created_by=uuid.uuid4(),
        )
        uow.flush()
        exc_id = exc.id
    with role_connect("ngrc_owner") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only and immutable"):
            c.execute("UPDATE ten_security_exception SET residual_risk = 'changed' WHERE id = %s", [exc_id])
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only and never deleted"):
            c.execute("DELETE FROM ten_security_exception WHERE id = %s", [exc_id])
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="never truncated"):
            c.execute("TRUNCATE ten_security_exception")


def test_ngrc_app_has_no_update_privilege_on_security_exception(tenant_a):
    with role_connect("ngrc_app") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE ten_security_exception SET residual_risk = 'x' WHERE id = gen_random_uuid()")


def test_a_tenant_cannot_see_another_tenants_finding_or_exception(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl(tenant_a)
        finding = _finding(impl)
        exc = control_services.record_exception(
            impl, "scope", "reason", approver=uuid.uuid4(), expiry_date="2027-06-30", created_by=uuid.uuid4(),
        )
        uow.flush()
        finding_id, exc_id = finding.id, exc.id
    with tenant_context(tenant_b.id):
        assert not Finding.objects.filter(id=finding_id).exists()
        assert not SecurityException.objects.filter(id=exc_id).exists()
