"""D-P5-007: notification service core - notify() creates nothing for a None recipient, mark_read is
idempotent, raise_finding notifies the owner only at high/critical severity, transition_audit notifies the
reviewer entering submitted and the assignee entering changes_requested, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.compliance_audit import services as compliance_audit_services
from ngrc.compliance_audit.models import Audit
from ngrc.controls import services as control_services
from ngrc.controls.models import Finding
from ngrc.core.context import tenant_context
from ngrc.framework import services as framework_services
from ngrc.notifications import services as notification_services
from ngrc.notifications.models import Notification

pytestmark = pytest.mark.security


def _impl():
    cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control", created_by=uuid.uuid4())
    return control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())


def _framework():
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-notif-fw-{uuid.uuid4().hex[:8]}", name="Test Framework for Notifications",
    )
    version = framework_services.draft_version(fw, "v1", created_by=uuid.uuid4())
    framework_services.add_requirement(version, "req-a", "A.1", "Control A")
    framework_services.publish_version(version, published_by=uuid.uuid4())
    return fw


def _activate(tenant, fw):
    from ngrc.framework.models import FrameworkVersion

    version = FrameworkVersion.objects.using("default").get(framework=fw, version_label="v1")
    with tenant_context(tenant.id), audit_service.unit_of_work(tenant.id) as uow:
        framework_services.activate_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()


def _audit(fw, *, status=Audit.Status.DRAFT, assigned_to=None, reviewer=None):
    audit_obj = compliance_audit_services.create_audit(fw.urn, "Q4 review", created_by=uuid.uuid4(),
                                                        assigned_to=assigned_to, reviewer=reviewer)
    for target in (Audit.Status.ASSIGNED, Audit.Status.IN_PROGRESS, Audit.Status.SUBMITTED):
        if audit_obj.status == status:
            return audit_obj
        audit_obj = compliance_audit_services.transition_audit(audit_obj, target, actor_id=uuid.uuid4())
    return audit_obj


def test_notify_with_no_recipient_creates_nothing(tenant_a):
    with tenant_context(tenant_a.id):
        result = notification_services.notify(None, "test_category", "hello", object_type="finding",
                                               object_id=uuid.uuid4(), created_by=uuid.uuid4())
    assert result is None
    with tenant_context(tenant_a.id):
        assert Notification.objects.count() == 0


def test_notify_with_a_recipient_creates_a_notification(tenant_a):
    recipient = uuid.uuid4()
    object_id = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        notification = notification_services.notify(recipient, "test_category", "hello", object_type="finding",
                                                      object_id=object_id, created_by=uuid.uuid4())
        uow.flush()
    assert notification is not None
    assert notification.recipient == recipient
    assert notification.category == "test_category"
    assert notification.object_type == "finding"
    assert notification.object_id == object_id
    assert notification.read_at is None


def test_mark_read_stamps_read_at_and_is_idempotent(tenant_a):
    recipient = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        notification = notification_services.notify(recipient, "test_category", "hello", object_type="finding",
                                                      object_id=uuid.uuid4(), created_by=uuid.uuid4())
        uow.flush()
        notification = notification_services.mark_read(notification, actor_id=uuid.uuid4())
        first_read_at = notification.read_at
        notification = notification_services.mark_read(notification, actor_id=uuid.uuid4())
    assert first_read_at is not None
    assert notification.read_at is not None


def test_raise_finding_notifies_owner_at_high_severity(tenant_a):
    owner = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        finding = control_services.raise_finding(impl, "Stale firewall rule", source=Finding.Source.MANUAL,
                                                  severity=Finding.Severity.HIGH, created_by=uuid.uuid4(),
                                                  owner=owner)
        uow.flush()
        notes = Notification.objects.filter(recipient=owner, object_type="finding", object_id=finding.id)
        assert notes.count() == 1
        assert notes.first().category == "finding_raised"


def test_raise_finding_does_not_notify_at_medium_severity(tenant_a):
    owner = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        control_services.raise_finding(impl, "Minor config drift", source=Finding.Source.MANUAL,
                                        severity=Finding.Severity.MEDIUM, created_by=uuid.uuid4(), owner=owner)
        uow.flush()
        assert Notification.objects.filter(recipient=owner).count() == 0


def test_raise_finding_with_no_owner_notifies_nobody(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        control_services.raise_finding(impl, "Stale firewall rule", source=Finding.Source.MANUAL,
                                        severity=Finding.Severity.CRITICAL, created_by=uuid.uuid4())
        uow.flush()
        assert Notification.objects.count() == 0


def test_transition_audit_into_submitted_notifies_the_reviewer(tenant_a):
    reviewer = uuid.uuid4()
    fw = _framework()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = _audit(fw, status=Audit.Status.SUBMITTED, reviewer=reviewer)
        uow.flush()
        notes = Notification.objects.filter(recipient=reviewer, object_type="audit", object_id=audit_obj.id)
        assert notes.count() == 1
        assert notes.first().category == "audit_awaiting_review"


def test_transition_audit_into_changes_requested_notifies_the_assignee(tenant_a):
    assigned_to = uuid.uuid4()
    fw = _framework()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        audit_obj = _audit(fw, status=Audit.Status.SUBMITTED, assigned_to=assigned_to)
        audit_obj = compliance_audit_services.transition_audit(audit_obj, Audit.Status.REVIEW, actor_id=uuid.uuid4())
        audit_obj = compliance_audit_services.transition_audit(audit_obj, Audit.Status.CHANGES_REQUESTED,
                                                                 actor_id=uuid.uuid4())
        uow.flush()
        notes = Notification.objects.filter(recipient=assigned_to, object_type="audit", object_id=audit_obj.id)
        assert notes.count() == 1
        assert notes.first().category == "audit_changes_requested"


def test_transition_audit_into_other_states_notifies_nobody(tenant_a):
    fw = _framework()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        _audit(fw, status=Audit.Status.IN_PROGRESS, assigned_to=uuid.uuid4(), reviewer=uuid.uuid4())
        uow.flush()
        assert Notification.objects.count() == 0


def test_notification_tenant_isolation(tenant_a, tenant_b):
    recipient = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        notification_services.notify(recipient, "test_category", "hello", object_type="finding",
                                      object_id=uuid.uuid4(), created_by=uuid.uuid4())
        uow.flush()
    with tenant_context(tenant_b.id):
        assert Notification.objects.filter(recipient=recipient).count() == 0
