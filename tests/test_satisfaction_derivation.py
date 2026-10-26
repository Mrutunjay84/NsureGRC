"""D-P3-004: real satisfaction_state derivation from EvidenceLink + TestResult signals - every rung of the
ladder reachable and distinguishable, automatic recompute on the three trigger points, and the freshness
check against EvidenceRequirement.freshness_days."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import ControlAssertion, EvidenceLink, SatisfactionState
from ngrc.controls.models import Test as ControlTest
from ngrc.controls.models import TestResult as ControlTestResult
from ngrc.core.context import tenant_context
from ngrc.evidence.models import Evidence, EvidenceRevision
from ngrc.framework import services as framework_services

pytestmark = pytest.mark.security


def _framework_with_requirement(urn_suffix: str | None = None):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-sat-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Satisfaction",
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


def _revision() -> EvidenceRevision:
    ev = Evidence.objects.create(title="Access review export", created_by=uuid.uuid4())
    return EvidenceRevision.objects.create(
        evidence_id=ev.id, revision_no=1, filename="export.pdf", declared_type="application/pdf",
        detected_type="application/pdf", size_bytes=1024, sha256="0" * 64, storage_key=f"k-{uuid.uuid4().hex}",
        state=EvidenceRevision.State.COLLECTED, created_by=uuid.uuid4(),
    )


def _setup(tenant_a):
    """Common_control -> implementation_control -> assertion, all freshly created with no evidence/tests."""
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
    impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
    assertion = control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())
    return impl, assertion


def _accept_evidence(assertion, *, evidence_requirement=None, clock_ctl=None, advance_days=None):
    """`clock_ctl`/`advance_days` simulate staleness: EvidenceRevision.created_at uses Django's own
    auto_now_add (real wall clock, DB-immutable - see ten_evidence_revision_guard), never ngrc.core.clock -
    so instead of backdating the (immutable) row, the derivation's own clock.now() is moved forward past it,
    which the ladder reads identically."""
    rev = _revision()
    link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4(), evidence_requirement=evidence_requirement)
    link = control_services.review_evidence_link(link, EvidenceLink.ReviewState.IN_REVIEW, reviewed_by=uuid.uuid4())
    if clock_ctl is not None and advance_days is not None:
        clock_ctl.advance(days=advance_days)
    return control_services.review_evidence_link(link, EvidenceLink.ReviewState.ACCEPTED, reviewed_by=uuid.uuid4())


def _passing_test(impl):
    t = control_services.create_test(impl, "Quarterly review", created_by=uuid.uuid4())
    result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
    result = control_services.transition_test_result(result, ControlTestResult.Status.RUNNING, actor_id=uuid.uuid4())
    return control_services.transition_test_result(result, ControlTestResult.Status.PASSED, actor_id=uuid.uuid4())


def _failed_test(impl):
    t = control_services.create_test(impl, "Quarterly review", created_by=uuid.uuid4())
    result = control_services.schedule_test_result(t, created_by=uuid.uuid4())
    result = control_services.transition_test_result(result, ControlTestResult.Status.RUNNING, actor_id=uuid.uuid4())
    return control_services.transition_test_result(result, ControlTestResult.Status.FAILED, actor_id=uuid.uuid4())


def test_no_inputs_stays_not_assessed(tenant_a):
    """DEF-22: "unknown" is reserved for data-unavailability; "nothing built yet" is not_assessed."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        _impl, assertion = _setup(tenant_a)
        uow.flush()
        control_services.recompute_satisfaction_state(assertion, actor_id=uuid.uuid4())
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.NOT_ASSESSED


def test_evidence_link_with_nothing_positive_is_needs_attention(tenant_a):
    """link_evidence's own default review_state (collected, not accepted) already triggers this via the
    automatic recompute - no explicit recompute call needed."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        _impl, assertion = _setup(tenant_a)
        uow.flush()
        rev = _revision()
        control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.NEEDS_ATTENTION


def test_failed_test_is_needs_attention_even_with_accepted_evidence(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        uow.flush()
        _accept_evidence(assertion)
        _failed_test(impl)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.NEEDS_ATTENTION


def test_accepted_evidence_alone_is_partially_effective(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        _impl, assertion = _setup(tenant_a)
        uow.flush()
        _accept_evidence(assertion)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.PARTIALLY_EFFECTIVE


def test_passing_test_alone_is_partially_effective(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        uow.flush()
        _passing_test(impl)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.PARTIALLY_EFFECTIVE


def test_stale_accepted_evidence_with_passing_test_is_partially_effective_not_effective(tenant_a, clock_ctl):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4(),
                                                             freshness_days=30)
        uow.flush()
        _accept_evidence(assertion, evidence_requirement=req, clock_ctl=clock_ctl, advance_days=45)
        _passing_test(impl)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.PARTIALLY_EFFECTIVE


def test_fresh_accepted_evidence_and_passing_test_is_effective_when_unreviewed(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4(),
                                                             freshness_days=30)
        uow.flush()
        _accept_evidence(assertion, evidence_requirement=req)
        _passing_test(impl)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.EFFECTIVE


def test_evidence_with_no_requirement_is_never_stale(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        uow.flush()
        _accept_evidence(assertion)  # no evidence_requirement at all
        _passing_test(impl)
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.EFFECTIVE


def test_effective_becomes_verified_once_the_assertion_is_reviewed(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        uow.flush()
        _accept_evidence(assertion)
        _passing_test(impl)
        assertion.refresh_from_db()
        assert assertion.satisfaction_state == SatisfactionState.EFFECTIVE
        assertion = control_services.mark_assertion_reviewed(assertion, reviewed_by=uuid.uuid4())
    assert assertion.satisfaction_state == SatisfactionState.VERIFIED


def test_mark_assertion_reviewed_fails_closed_against_double_review(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        _impl, assertion = _setup(tenant_a)
        uow.flush()
        control_services.mark_assertion_reviewed(assertion, reviewed_by=uuid.uuid4())
        with pytest.raises(control_services.ControlError, match="already_reviewed"):
            control_services.mark_assertion_reviewed(assertion, reviewed_by=uuid.uuid4())


def test_transition_test_result_recomputes_every_sibling_assertion(tenant_a):
    """A Test belongs to the ImplementationControl, not to one assertion - several assertions can share it."""
    fw_a, fw_b = _framework_with_requirement("a"), _framework_with_requirement("b")
    _activate(tenant_a, fw_a)
    _activate(tenant_a, fw_b)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        assertion_a = control_services.assert_control(impl, fw_a.urn, "req-a", created_by=uuid.uuid4())
        assertion_b = control_services.assert_control(impl, fw_b.urn, "req-a", created_by=uuid.uuid4())
        uow.flush()
        _failed_test(impl)
        assertion_a.refresh_from_db()
        assertion_b.refresh_from_db()
    assert assertion_a.satisfaction_state == SatisfactionState.NEEDS_ATTENTION
    assert assertion_b.satisfaction_state == SatisfactionState.NEEDS_ATTENTION


def test_a_tenant_cannot_see_another_tenants_test_or_assertion_state_leak(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl, assertion = _setup(tenant_a)
        uow.flush()
        _failed_test(impl)
        assertion_id = assertion.id
    with tenant_context(tenant_b.id):
        assert not ControlAssertion.objects.filter(id=assertion_id).exists()
        assert not ControlTest.objects.filter(implementation_control_id=impl.id).exists()
