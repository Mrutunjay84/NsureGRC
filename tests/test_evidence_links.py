"""D-P3-002: evidence requirements and evidence links - fail-closed linking against the revision's scan
state, requirement/assertion consistency, the review-state transition graph, and tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import ControlAssertion, EvidenceLink, SatisfactionState
from ngrc.core.context import tenant_context
from ngrc.evidence.models import Evidence, EvidenceRevision
from ngrc.framework import services as framework_services

pytestmark = pytest.mark.security


def _framework_with_requirement(urn_suffix: str | None = None):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-evlink-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Evidence Links",
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


def _revision(*, state=EvidenceRevision.State.COLLECTED) -> EvidenceRevision:
    """Builds an Evidence + EvidenceRevision pair directly via the ORM - this suite tests the control-layer
    linking logic, not evidence upload/scanning itself (already covered by test_evidence_lifecycle.py)."""
    ev = Evidence.objects.create(title="Access review export", created_by=uuid.uuid4())
    return EvidenceRevision.objects.create(
        evidence_id=ev.id, revision_no=1, filename="export.pdf", declared_type="application/pdf",
        detected_type="application/pdf", size_bytes=1024, sha256="0" * 64, storage_key=f"k-{uuid.uuid4().hex}",
        state=state, created_by=uuid.uuid4(),
    )


def _assertion(tenant_a, fw) -> ControlAssertion:
    cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
    impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
    return control_services.assert_control(impl, fw.urn, "req-a", created_by=uuid.uuid4())


def test_create_evidence_requirement(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control("ac", "Access Control", created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        req = control_services.create_evidence_requirement(
            impl, "access_review_export", created_by=uuid.uuid4(), source_system="Okta",
            frequency="quarterly", freshness_days=90, acceptance_criteria="Exported within the quarter",
        )
        uow.flush()
    assert req.implementation_control_id == impl.id
    assert req.frequency == "quarterly"


def test_link_evidence_to_control_assertion(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision()
        link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())
        uow.flush()
    assert link.control_assertion_id == assertion.id
    assert link.evidence_revision_id == rev.id
    assert link.review_state == EvidenceLink.ReviewState.COLLECTED
    # health derivation is a later increment (D-P3-00x): linking evidence must not silently change this
    with tenant_context(tenant_a.id):
        assertion.refresh_from_db()
    assert assertion.satisfaction_state == SatisfactionState.UNKNOWN


def test_link_evidence_fails_closed_for_scan_pending_revision(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision(state=EvidenceRevision.State.SCAN_PENDING)
        uow.flush()
        with pytest.raises(control_services.ControlError, match="evidence_not_collected"):
            control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())


def test_link_evidence_fails_closed_for_quarantined_revision(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision(state=EvidenceRevision.State.QUARANTINED)
        uow.flush()
        with pytest.raises(control_services.ControlError, match="evidence_not_collected"):
            control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())


def test_link_evidence_fails_closed_when_requirement_belongs_to_a_different_implementation_control(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        other_cc = control_services.create_common_control("other", "Other Control", created_by=uuid.uuid4())
        other_impl = control_services.create_implementation_control(other_cc, "Other Impl", created_by=uuid.uuid4())
        other_req = control_services.create_evidence_requirement(other_impl, "log_extract", created_by=uuid.uuid4())
        rev = _revision()
        uow.flush()
        with pytest.raises(control_services.ControlError, match="evidence_requirement_mismatch"):
            control_services.link_evidence(assertion, rev, created_by=uuid.uuid4(), evidence_requirement=other_req)


def test_review_evidence_link_follows_the_allowed_transition_graph(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision()
        link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())
        uow.flush()
        link = control_services.review_evidence_link(link, EvidenceLink.ReviewState.IN_REVIEW, reviewed_by=uuid.uuid4())
        assert link.review_state == EvidenceLink.ReviewState.IN_REVIEW
        link = control_services.review_evidence_link(link, EvidenceLink.ReviewState.ACCEPTED, reviewed_by=uuid.uuid4())
        assert link.review_state == EvidenceLink.ReviewState.ACCEPTED
        assert link.reviewed_at is not None
        link = control_services.review_evidence_link(link, EvidenceLink.ReviewState.SUPERSEDED, reviewed_by=uuid.uuid4())
        assert link.review_state == EvidenceLink.ReviewState.SUPERSEDED


def test_review_evidence_link_rejects_a_transition_outside_the_graph(tenant_a):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision()
        link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())
        uow.flush()
        with pytest.raises(control_services.ControlError, match="invalid_transition"):
            control_services.review_evidence_link(link, EvidenceLink.ReviewState.ACCEPTED, reviewed_by=uuid.uuid4())


def test_a_tenant_cannot_see_another_tenants_evidence_link(tenant_a, tenant_b):
    fw = _framework_with_requirement()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        assertion = _assertion(tenant_a, fw)
        rev = _revision()
        link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4())
        uow.flush()
        link_id = link.id
    with tenant_context(tenant_b.id):
        assert not EvidenceLink.objects.filter(id=link_id).exists()
