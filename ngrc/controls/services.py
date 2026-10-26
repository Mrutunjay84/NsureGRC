"""Common/Implementation controls and control assertions (D-P3-001).

All plain TEN writes (no new DB role, unlike the Framework Engine - D-P0-009's control/evidence/test
domain has no CAT/PLT content). Callers must already be inside the target tenant's `tenant_context()` and
have checked `control.manage` - services trust an already-authorized caller, same convention as
`ngrc.framework.services` (no HTTP layer exists yet for this app either).
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.core import clock
from ngrc.evidence.models import EvidenceRevision
from ngrc.framework import services as framework_services

from .models import (
    CommonControl,
    ControlAssertion,
    EvidenceLink,
    EvidenceRequirement,
    Frequency,
    ImplementationControl,
    Test,
    TestResult,
)


class ControlError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_common_control(key: str, name: str, *, created_by, objective: str = "", category: str = "",
                           owner=None) -> CommonControl:
    control = CommonControl.objects.create(
        key=key, name=name, objective=objective, category=category, owner=owner, created_by=created_by,
    )
    audit.record("control.common_control.created", actor_id=created_by, object_type="common_control",
                 object_id=str(control.id), details={"key": key})
    return control


def create_implementation_control(common_control: CommonControl, name: str, *, created_by,
                                   description: str = "", owner=None, reviewer=None, due_date=None) -> ImplementationControl:
    impl = ImplementationControl.objects.create(
        common_control=common_control, name=name, description=description, owner=owner, reviewer=reviewer,
        due_date=due_date, created_by=created_by,
    )
    audit.record("control.implementation_control.created", actor_id=created_by, object_type="implementation_control",
                 object_id=str(impl.id), details={"common_control_key": common_control.key})
    return impl


def assert_control(implementation_control: ImplementationControl, framework_urn: str, requirement_urn: str, *,
                    created_by, coverage: int | None = None) -> ControlAssertion:
    """Fails closed: the requirement must actually resolve (the tenant has `framework_urn` activated and
    `requirement_urn` exists in the pinned version) - reuses the Framework Engine's own resolver rather
    than re-implementing requirement lookup (D-P2-001/003)."""
    try:
        resolved_urns = {r.urn for r in framework_services.resolve_requirements(framework_urn)}
    except framework_services.FrameworkError as exc:
        raise ControlError(f"framework_not_resolved:{exc.code}") from exc
    if requirement_urn not in resolved_urns:
        raise ControlError("requirement_not_resolved")
    assertion = ControlAssertion.objects.create(
        implementation_control=implementation_control, framework_urn=framework_urn, requirement_urn=requirement_urn,
        coverage=coverage, created_by=created_by,
    )
    audit.record("control.assertion.created", actor_id=created_by, object_type="control_assertion",
                 object_id=str(assertion.id), details={"framework_urn": framework_urn, "requirement_urn": requirement_urn})
    return assertion


def create_evidence_requirement(implementation_control: ImplementationControl, evidence_type: str, *, created_by,
                                 source_system: str = "", frequency: str = Frequency.ON_DEMAND,
                                 freshness_days: int | None = None, acceptance_criteria: str = "",
                                 owner=None, reviewer=None) -> EvidenceRequirement:
    req = EvidenceRequirement.objects.create(
        implementation_control=implementation_control, evidence_type=evidence_type, source_system=source_system,
        frequency=frequency, freshness_days=freshness_days, acceptance_criteria=acceptance_criteria, owner=owner,
        reviewer=reviewer, created_by=created_by,
    )
    audit.record("control.evidence_requirement.created", actor_id=created_by, object_type="evidence_requirement",
                 object_id=str(req.id), details={"evidence_type": evidence_type})
    return req


def link_evidence(control_assertion: ControlAssertion, evidence_revision: EvidenceRevision, *, created_by,
                   evidence_requirement: EvidenceRequirement | None = None) -> EvidenceLink:
    """Fails closed: the revision must already be `collected` (clean scan) - scan_pending or quarantined
    evidence can never be attached to a control assertion. If an EvidenceRequirement is given, it must
    belong to the same ImplementationControl as the assertion being linked (D-P3-002)."""
    if evidence_revision.state != EvidenceRevision.State.COLLECTED:
        raise ControlError(f"evidence_not_collected:{evidence_revision.state}")
    if evidence_requirement is not None and (
        evidence_requirement.implementation_control_id != control_assertion.implementation_control_id
    ):
        raise ControlError("evidence_requirement_mismatch")
    link = EvidenceLink.objects.create(
        control_assertion=control_assertion, evidence_requirement=evidence_requirement,
        evidence_revision_id=evidence_revision.id, created_by=created_by,
    )
    audit.record("control.evidence_link.created", actor_id=created_by, object_type="evidence_link",
                 object_id=str(link.id), details={"review_state": link.review_state})
    return link


_ALLOWED_REVIEW_TRANSITIONS: dict[str, set[str]] = {
    EvidenceLink.ReviewState.COLLECTED: {EvidenceLink.ReviewState.IN_REVIEW},
    EvidenceLink.ReviewState.IN_REVIEW: {EvidenceLink.ReviewState.ACCEPTED, EvidenceLink.ReviewState.REJECTED},
    EvidenceLink.ReviewState.ACCEPTED: {EvidenceLink.ReviewState.EXPIRED, EvidenceLink.ReviewState.SUPERSEDED},
    EvidenceLink.ReviewState.REJECTED: {EvidenceLink.ReviewState.EXPIRED},
}


def review_evidence_link(link: EvidenceLink, new_state: str, *, reviewed_by) -> EvidenceLink:
    """Fails closed: only transitions in `_ALLOWED_REVIEW_TRANSITIONS` are accepted (D-P3-002)."""
    allowed = _ALLOWED_REVIEW_TRANSITIONS.get(link.review_state, set())
    if new_state not in allowed:
        raise ControlError(f"invalid_transition:{link.review_state}->{new_state}")
    from_state = link.review_state
    link.review_state, link.reviewed_by, link.reviewed_at = new_state, reviewed_by, clock.now()
    link.save(update_fields=["review_state", "reviewed_by", "reviewed_at"])
    audit.record("control.evidence_link.reviewed", actor_id=reviewed_by, object_type="evidence_link",
                 object_id=str(link.id), details={"from_state": from_state, "to_state": new_state})
    return link


def create_test(implementation_control: ImplementationControl, name: str, *, created_by,
                 description: str = "", test_type: str = "", frequency: str = Frequency.ON_DEMAND,
                 owner=None, reviewer=None) -> Test:
    test = Test.objects.create(
        implementation_control=implementation_control, name=name, description=description, test_type=test_type,
        frequency=frequency, owner=owner, reviewer=reviewer, created_by=created_by,
    )
    audit.record("control.test.created", actor_id=created_by, object_type="test", object_id=str(test.id),
                 details={"test_type": test_type})
    return test


def schedule_test_result(test: Test, *, created_by) -> TestResult:
    result = TestResult.objects.create(test=test, created_by=created_by)
    audit.record("control.test_result.scheduled", actor_id=created_by, object_type="test_result",
                 object_id=str(result.id), details={})
    return result


_ALLOWED_TEST_TRANSITIONS: dict[str, set[str]] = {
    TestResult.Status.SCHEDULED: {TestResult.Status.RUNNING},
    TestResult.Status.RUNNING: {TestResult.Status.PASSED, TestResult.Status.FAILED, TestResult.Status.UNKNOWN},
    TestResult.Status.FAILED: {TestResult.Status.REMEDIATING},
    TestResult.Status.REMEDIATING: {TestResult.Status.VERIFIED},
}


def transition_test_result(result: TestResult, new_status: str, *, actor_id, detail: str = "",
                            deadline=None) -> TestResult:
    """Fails closed: only transitions in `_ALLOWED_TEST_TRANSITIONS` are accepted (D-P3-003). `executed_at`
    is stamped the moment the result leaves `scheduled` and enters `running`. `deadline` is optional and
    caller-supplied (never auto-computed - not every tenant's process uses a fixed SLA offset)."""
    allowed = _ALLOWED_TEST_TRANSITIONS.get(result.status, set())
    if new_status not in allowed:
        raise ControlError(f"invalid_transition:{result.status}->{new_status}")
    from_status = result.status
    update_fields = ["status"]
    result.status = new_status
    if new_status == TestResult.Status.RUNNING:
        result.executed_at = clock.now()
        update_fields.append("executed_at")
    if detail:
        result.detail = detail
        update_fields.append("detail")
    if deadline is not None:
        result.deadline = deadline
        update_fields.append("deadline")
    result.save(update_fields=update_fields)
    audit.record("control.test_result.transitioned", actor_id=actor_id, object_type="test_result",
                 object_id=str(result.id), details={"from_status": from_status, "to_status": new_status})
    return result
