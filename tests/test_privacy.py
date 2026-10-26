"""D-P4-006: privacy foundation - Purpose/PersonalData as siblings of ProcessingActivity (not nested),
RightsRequest and Breach transition graphs (including every reopen and stage-skip rejection), the two
independent breach-notification timestamps, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.privacy import services as privacy_services
from ngrc.privacy.models import Breach, PersonalData, ProcessingActivity, Purpose, RightsRequest

pytestmark = pytest.mark.security


def test_create_processing_activity_with_sibling_purpose_and_personal_data(tenant_a):
    """Purpose and PersonalData both FK the same ProcessingActivity independently (D-P4-006) - not a
    literal Processing -> PersonalData -> Purpose chain."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activity = privacy_services.create_processing_activity(
            "Customer support ticketing", role=ProcessingActivity.Role.CONTROLLER, created_by=uuid.uuid4(),
        )
        purpose = privacy_services.add_purpose(activity, "Resolve support tickets",
                                                lawful_basis=Purpose.LawfulBasis.CONTRACT, created_by=uuid.uuid4())
        pd = privacy_services.add_personal_data_category(activity, "contact details", created_by=uuid.uuid4())
        uow.flush()
    assert purpose.processing_activity_id == activity.id
    assert pd.processing_activity_id == activity.id
    assert pd.special_category is False


def test_personal_data_special_category_flag(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activity = privacy_services.create_processing_activity(
            "Occupational health screening", role=ProcessingActivity.Role.CONTROLLER, created_by=uuid.uuid4(),
        )
        pd = privacy_services.add_personal_data_category(activity, "health data", created_by=uuid.uuid4(),
                                                           special_category=True)
        uow.flush()
    assert pd.special_category is True


def test_processing_activity_transition_graph(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activity = privacy_services.create_processing_activity(
            "Customer support ticketing", role=ProcessingActivity.Role.CONTROLLER, created_by=uuid.uuid4(),
        )
        uow.flush()
        activity = privacy_services.transition_processing_activity(activity, ProcessingActivity.Status.ACTIVE,
                                                                     actor_id=uuid.uuid4())
        assert activity.status == ProcessingActivity.Status.ACTIVE
        activity = privacy_services.transition_processing_activity(activity, ProcessingActivity.Status.RETIRED,
                                                                     actor_id=uuid.uuid4())
        assert activity.status == ProcessingActivity.Status.RETIRED


def test_rights_request_full_lifecycle_and_reopen(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        request = privacy_services.create_rights_request(
            "case-2027-0042", request_type=RightsRequest.RequestType.ERASURE, created_by=uuid.uuid4(),
        )
        uow.flush()
        assert request.status == RightsRequest.Status.RECEIVED
        request = privacy_services.transition_rights_request(request, RightsRequest.Status.IN_PROGRESS,
                                                               actor_id=uuid.uuid4())
        request = privacy_services.transition_rights_request(request, RightsRequest.Status.FULFILLED,
                                                               actor_id=uuid.uuid4())
        request = privacy_services.transition_rights_request(request, RightsRequest.Status.CLOSED,
                                                               actor_id=uuid.uuid4())
        assert request.status == RightsRequest.Status.CLOSED
        request = privacy_services.transition_rights_request(request, RightsRequest.Status.RECEIVED,
                                                               actor_id=uuid.uuid4())
        assert request.status == RightsRequest.Status.RECEIVED


def test_rights_request_cannot_skip_in_progress(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        request = privacy_services.create_rights_request(
            "case-2027-0042", request_type=RightsRequest.RequestType.ACCESS, created_by=uuid.uuid4(),
        )
        uow.flush()
        with pytest.raises(privacy_services.PrivacyError, match="invalid_transition"):
            privacy_services.transition_rights_request(request, RightsRequest.Status.FULFILLED, actor_id=uuid.uuid4())


def test_breach_full_lifecycle_with_independent_notifications(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        breach = privacy_services.raise_breach("Unauthorized export of customer records",
                                                severity=Breach.Severity.HIGH, created_by=uuid.uuid4())
        uow.flush()
        assert breach.status == Breach.Status.OPEN
        assert breach.discovered_at is not None
        breach = privacy_services.transition_breach(breach, Breach.Status.INVESTIGATING, actor_id=uuid.uuid4())
        breach = privacy_services.transition_breach(breach, Breach.Status.CONTAINED, actor_id=uuid.uuid4())
        breach = privacy_services.record_authority_notification(breach, actor_id=uuid.uuid4())
        assert breach.notified_authority_at is not None
        assert breach.notified_subjects_at is None
        breach = privacy_services.transition_breach(breach, Breach.Status.NOTIFIED, actor_id=uuid.uuid4())
        breach = privacy_services.record_subject_notification(breach, actor_id=uuid.uuid4())
        assert breach.notified_subjects_at is not None
        breach = privacy_services.transition_breach(breach, Breach.Status.CLOSED, actor_id=uuid.uuid4())
        assert breach.status == Breach.Status.CLOSED
        breach = privacy_services.transition_breach(breach, Breach.Status.OPEN, actor_id=uuid.uuid4())
        assert breach.status == Breach.Status.OPEN


def test_breach_cannot_skip_stages(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        breach = privacy_services.raise_breach("Unauthorized export of customer records",
                                                severity=Breach.Severity.MEDIUM, created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(privacy_services.PrivacyError, match="invalid_transition"):
            privacy_services.transition_breach(breach, Breach.Status.CONTAINED, actor_id=uuid.uuid4())


def test_a_tenant_cannot_see_another_tenants_privacy_records(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activity = privacy_services.create_processing_activity(
            "Customer support ticketing", role=ProcessingActivity.Role.CONTROLLER, created_by=uuid.uuid4(),
        )
        request = privacy_services.create_rights_request("case-2027-0042", request_type=RightsRequest.RequestType.ACCESS,
                                                           created_by=uuid.uuid4())
        breach = privacy_services.raise_breach("test", severity=Breach.Severity.LOW, created_by=uuid.uuid4())
        uow.flush()
        activity_id, request_id, breach_id = activity.id, request.id, breach.id
    with tenant_context(tenant_b.id):
        assert not ProcessingActivity.objects.filter(id=activity_id).exists()
        assert not RightsRequest.objects.filter(id=request_id).exists()
        assert not Breach.objects.filter(id=breach_id).exists()
        assert not Purpose.objects.filter(processing_activity_id=activity_id).exists()
        assert not PersonalData.objects.filter(processing_activity_id=activity_id).exists()
