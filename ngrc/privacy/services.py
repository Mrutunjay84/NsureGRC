"""Privacy foundation (D-P4-006).

All plain TEN writes (no new DB role). Callers must already be inside the target tenant's
`tenant_context()` and have checked `privacy.manage` - services trust an already-authorized caller, same
convention as every other domain app in this codebase.
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.core import clock

from .models import Breach, PersonalData, ProcessingActivity, Purpose, RightsRequest


class PrivacyError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_processing_activity(name: str, *, role: str, created_by, description: str = "",
                                owner=None) -> ProcessingActivity:
    activity = ProcessingActivity.objects.create(name=name, description=description, owner=owner, role=role,
                                                  created_by=created_by)
    audit.record("privacy.processing_activity.created", actor_id=created_by, object_type="processing_activity",
                 object_id=str(activity.id), details={"role": role})
    return activity


_ALLOWED_ACTIVITY_TRANSITIONS: dict[str, set[str]] = {
    ProcessingActivity.Status.DRAFT: {ProcessingActivity.Status.ACTIVE},
    ProcessingActivity.Status.ACTIVE: {ProcessingActivity.Status.RETIRED},
    ProcessingActivity.Status.RETIRED: {ProcessingActivity.Status.ACTIVE},
}


def transition_processing_activity(activity: ProcessingActivity, new_status: str, *, actor_id) -> ProcessingActivity:
    allowed = _ALLOWED_ACTIVITY_TRANSITIONS.get(activity.status, set())
    if new_status not in allowed:
        raise PrivacyError(f"invalid_transition:{activity.status}->{new_status}")
    from_status = activity.status
    activity.status = new_status
    activity.save(update_fields=["status"])
    audit.record("privacy.processing_activity.transitioned", actor_id=actor_id, object_type="processing_activity",
                 object_id=str(activity.id), details={"from_status": from_status, "to_status": new_status})
    return activity


def add_purpose(activity: ProcessingActivity, description: str, *, lawful_basis: str, created_by) -> Purpose:
    purpose = Purpose.objects.create(processing_activity=activity, description=description,
                                      lawful_basis=lawful_basis, created_by=created_by)
    audit.record("privacy.purpose.added", actor_id=created_by, object_type="purpose", object_id=str(purpose.id),
                 details={"lawful_basis": lawful_basis})
    return purpose


def add_personal_data_category(activity: ProcessingActivity, category: str, *, created_by,
                                special_category: bool = False, retention_period: str = "") -> PersonalData:
    pd = PersonalData.objects.create(processing_activity=activity, category=category,
                                      special_category=special_category, retention_period=retention_period,
                                      created_by=created_by)
    audit.record("privacy.personal_data.added", actor_id=created_by, object_type="personal_data",
                 object_id=str(pd.id), details={"special_category": special_category})
    return pd


def create_rights_request(requester_reference: str, *, request_type: str, created_by, owner=None,
                           due_date=None) -> RightsRequest:
    request = RightsRequest.objects.create(requester_reference=requester_reference, request_type=request_type,
                                            owner=owner, due_date=due_date, created_by=created_by)
    audit.record("privacy.rights_request.created", actor_id=created_by, object_type="rights_request",
                 object_id=str(request.id), details={"request_type": request_type})
    return request


_ALLOWED_REQUEST_TRANSITIONS: dict[str, set[str]] = {
    RightsRequest.Status.RECEIVED: {RightsRequest.Status.IN_PROGRESS},
    RightsRequest.Status.IN_PROGRESS: {RightsRequest.Status.FULFILLED, RightsRequest.Status.REJECTED},
    RightsRequest.Status.FULFILLED: {RightsRequest.Status.CLOSED},
    RightsRequest.Status.REJECTED: {RightsRequest.Status.CLOSED},
    RightsRequest.Status.CLOSED: {RightsRequest.Status.RECEIVED},
}


def transition_rights_request(request: RightsRequest, new_status: str, *, actor_id) -> RightsRequest:
    allowed = _ALLOWED_REQUEST_TRANSITIONS.get(request.status, set())
    if new_status not in allowed:
        raise PrivacyError(f"invalid_transition:{request.status}->{new_status}")
    from_status = request.status
    request.status = new_status
    request.save(update_fields=["status"])
    audit.record("privacy.rights_request.transitioned", actor_id=actor_id, object_type="rights_request",
                 object_id=str(request.id), details={"from_status": from_status, "to_status": new_status})
    return request


def raise_breach(title: str, *, severity: str, created_by, description: str = "", owner=None,
                  discovered_at=None, affected_data_subjects_estimate=None) -> Breach:
    breach = Breach.objects.create(
        title=title, description=description, severity=severity, owner=owner,
        discovered_at=discovered_at or clock.now(),
        affected_data_subjects_estimate=affected_data_subjects_estimate, created_by=created_by,
    )
    audit.record("privacy.breach.raised", actor_id=created_by, object_type="breach", object_id=str(breach.id),
                 details={"severity": severity})
    return breach


_ALLOWED_BREACH_TRANSITIONS: dict[str, set[str]] = {
    Breach.Status.OPEN: {Breach.Status.INVESTIGATING},
    Breach.Status.INVESTIGATING: {Breach.Status.CONTAINED},
    Breach.Status.CONTAINED: {Breach.Status.NOTIFIED},
    Breach.Status.NOTIFIED: {Breach.Status.CLOSED},
    Breach.Status.CLOSED: {Breach.Status.OPEN},
}


def transition_breach(breach: Breach, new_status: str, *, actor_id) -> Breach:
    """Fails closed: strictly linear forward, same reasoning as Incident (D-P4-003). No stage skipping."""
    allowed = _ALLOWED_BREACH_TRANSITIONS.get(breach.status, set())
    if new_status not in allowed:
        raise PrivacyError(f"invalid_transition:{breach.status}->{new_status}")
    from_status = breach.status
    breach.status = new_status
    breach.save(update_fields=["status"])
    audit.record("privacy.breach.transitioned", actor_id=actor_id, object_type="breach", object_id=str(breach.id),
                 details={"from_status": from_status, "to_status": new_status})
    return breach


def record_authority_notification(breach: Breach, *, actor_id) -> Breach:
    """Independent of the `notified` status transition and of notifying data subjects (D-P4-006) - GDPR
    Art. 33/34 are two distinct duties."""
    breach.notified_authority_at = clock.now()
    breach.save(update_fields=["notified_authority_at"])
    audit.record("privacy.breach.authority_notified", actor_id=actor_id, object_type="breach",
                 object_id=str(breach.id), details={})
    return breach


def record_subject_notification(breach: Breach, *, actor_id) -> Breach:
    breach.notified_subjects_at = clock.now()
    breach.save(update_fields=["notified_subjects_at"])
    audit.record("privacy.breach.subjects_notified", actor_id=actor_id, object_type="breach",
                 object_id=str(breach.id), details={})
    return breach
