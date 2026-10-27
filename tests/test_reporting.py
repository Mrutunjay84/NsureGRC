"""D-P5-001/D-P5-002/D-P5-003/D-P5-004: posture, control health, framework coverage, evidence coverage and
high-finding-ageing metrics - unknown/not_assessed excluded from the posture ratio, weighting by coverage,
control_health's worst-assertion rollup, framework_coverage's mapped-not-effective definition,
evidence_coverage's freshness-reuse and no-lifecycle-gate, high_finding_ageing's severity/status filtering
and oldest-first ordering, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.controls.models import EvidenceLink, Finding, SatisfactionState
from ngrc.core.context import tenant_context
from ngrc.evidence.models import Evidence, EvidenceRevision
from ngrc.framework import services as framework_services
from ngrc.reporting import services as reporting_services

pytestmark = pytest.mark.security


def _framework_with_requirements(urn_suffix: str | None = None, n: int = 1):
    from ngrc.framework.models import Framework

    fw = Framework.objects.using("catalog").create(
        urn=f"test-reporting-fw-{urn_suffix or uuid.uuid4().hex[:8]}", name="Test Framework for Reporting",
    )
    version = framework_services.draft_version(fw, "v1", created_by=uuid.uuid4())
    for i in range(n):
        framework_services.add_requirement(version, f"req-{i}", f"A.{i}", f"Control {i}")
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


def _impl():
    cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control", created_by=uuid.uuid4())
    return control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())


def test_tenant_posture_is_none_with_no_assertions_at_all(tenant_a):
    with tenant_context(tenant_a.id):
        result = reporting_services.tenant_posture()
    assert result["posture_pct"] is None
    assert result["scored_count"] == 0


def test_tenant_posture_excludes_not_assessed_assertions(tenant_a):
    """DEF-22/D-P5-001: a freshly-asserted control defaults to not_assessed - excluded from the ratio
    entirely, not counted as 0%."""
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        uow.flush()
        result = reporting_services.tenant_posture()
    assert result["posture_pct"] is None
    assert result["scored_count"] == 0
    assert result["excluded_count"] == 1


def test_tenant_posture_weighted_by_coverage(tenant_a):
    fw = _framework_with_requirements(n=2)
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        a1 = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4(), coverage=80)
        a2 = control_services.assert_control(impl, fw.urn, "req-1", created_by=uuid.uuid4(), coverage=20)
        uow.flush()
        # force known states directly (bypassing the real derivation, which needs evidence/tests) to test
        # the weighting arithmetic in isolation
        a1.satisfaction_state, a2.satisfaction_state = SatisfactionState.EFFECTIVE, SatisfactionState.NEEDS_ATTENTION
        a1.save(update_fields=["satisfaction_state"])
        a2.save(update_fields=["satisfaction_state"])
        result = reporting_services.tenant_posture()
    # (80*1.0 + 20*0.0) / (80+20) = 0.80 -> 80%
    assert result["posture_pct"] == pytest.approx(80.0)
    assert result["scored_count"] == 2


def test_control_health_with_no_assertions_is_not_assessed(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        uow.flush()
        result = reporting_services.control_health(impl)
    assert result["health"] == SatisfactionState.NOT_ASSESSED
    assert result["assertion_count"] == 0


def test_control_health_is_the_worst_assertion(tenant_a):
    fw = _framework_with_requirements(n=2)
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        a1 = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        a2 = control_services.assert_control(impl, fw.urn, "req-1", created_by=uuid.uuid4())
        uow.flush()
        a1.satisfaction_state = SatisfactionState.EFFECTIVE
        a1.save(update_fields=["satisfaction_state"])
        a2.satisfaction_state = SatisfactionState.NEEDS_ATTENTION
        a2.save(update_fields=["satisfaction_state"])
        result = reporting_services.control_health(impl)
    assert result["health"] == SatisfactionState.NEEDS_ATTENTION
    assert result["worst_assertion_id"] == a2.id
    assert result["assertion_count"] == 2


def test_a_tenant_cannot_see_another_tenants_posture(tenant_a, tenant_b):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        assertion.satisfaction_state = SatisfactionState.EFFECTIVE
        assertion.save(update_fields=["satisfaction_state"])
        uow.flush()
    with tenant_context(tenant_b.id):
        result = reporting_services.tenant_posture()
    assert result["posture_pct"] is None
    assert result["scored_count"] == 0


def test_framework_coverage_fails_closed_without_an_activation(tenant_a):
    fw = _framework_with_requirements()
    with tenant_context(tenant_a.id):
        with pytest.raises(framework_services.FrameworkError):
            reporting_services.framework_coverage(fw.urn)


def test_framework_coverage_zero_percent_is_a_real_measurement_not_none(tenant_a):
    """D-P5-002: unlike tenant_posture, a framework with known requirements and zero assertions reports
    0.0%, not None - the requirement count itself is known, so this is a real measurement."""
    fw = _framework_with_requirements(n=2)
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id):
        result = reporting_services.framework_coverage(fw.urn)
    assert result["total_requirements"] == 2
    assert result["covered_count"] == 0
    assert result["coverage_pct"] == 0.0
    assert sorted(result["uncovered_requirement_urns"]) == ["req-0", "req-1"]


def test_framework_coverage_partial(tenant_a):
    fw = _framework_with_requirements(n=2)
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        uow.flush()
        result = reporting_services.framework_coverage(fw.urn)
    assert result["covered_count"] == 1
    assert result["coverage_pct"] == pytest.approx(50.0)
    assert result["uncovered_requirement_urns"] == ["req-1"]


def test_framework_coverage_mapped_not_effective(tenant_a):
    """D-P5-002: an assertion counts toward coverage regardless of its satisfaction_state - coverage means
    "mapped", not "effective" (that question belongs to control_health/tenant_posture instead)."""
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        assertion.satisfaction_state = SatisfactionState.NEEDS_ATTENTION
        assertion.save(update_fields=["satisfaction_state"])
        uow.flush()
        result = reporting_services.framework_coverage(fw.urn)
    assert result["coverage_pct"] == pytest.approx(100.0)


def test_framework_coverage_tenant_isolation(tenant_a, tenant_b):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    _activate(tenant_b, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        uow.flush()
    with tenant_context(tenant_b.id):
        result = reporting_services.framework_coverage(fw.urn)
    assert result["covered_count"] == 0
    assert result["coverage_pct"] == 0.0


def _revision() -> EvidenceRevision:
    ev = Evidence.objects.create(title="Access review export", created_by=uuid.uuid4())
    return EvidenceRevision.objects.create(
        evidence_id=ev.id, revision_no=1, filename="export.pdf", declared_type="application/pdf",
        detected_type="application/pdf", size_bytes=1024, sha256="0" * 64, storage_key=f"k-{uuid.uuid4().hex}",
        state=EvidenceRevision.State.COLLECTED, created_by=uuid.uuid4(),
    )


def _accept_evidence(assertion, *, evidence_requirement=None, clock_ctl=None, advance_days=None):
    rev = _revision()
    link = control_services.link_evidence(assertion, rev, created_by=uuid.uuid4(), evidence_requirement=evidence_requirement)
    link = control_services.review_evidence_link(link, EvidenceLink.ReviewState.IN_REVIEW, reviewed_by=uuid.uuid4())
    if clock_ctl is not None and advance_days is not None:
        clock_ctl.advance(days=advance_days)
    return control_services.review_evidence_link(link, EvidenceLink.ReviewState.ACCEPTED, reviewed_by=uuid.uuid4())


def test_evidence_coverage_is_none_with_no_requirements_at_all(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        uow.flush()
        result = reporting_services.evidence_coverage(impl)
    assert result["coverage_pct"] is None
    assert result["total_requirements"] == 0


def test_evidence_coverage_zero_percent_is_a_real_measurement_not_none(tenant_a):
    """D-P5-003: like framework_coverage, a control with known requirements and zero fresh accepted links
    reports 0.0%, not None."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4())
        uow.flush()
        result = reporting_services.evidence_coverage(impl)
    assert result["total_requirements"] == 1
    assert result["covered_count"] == 0
    assert result["coverage_pct"] == 0.0
    assert result["uncovered_requirement_ids"] == [req.id]


def test_evidence_coverage_counts_a_draft_requirement(tenant_a):
    """D-P5-003: no lifecycle gate - a requirement left at its draft default (no activation workflow exists
    anywhere in ngrc.controls) still counts, both in the denominator and once satisfied."""
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4())
        uow.flush()
        assert req.lifecycle == "draft"
        _accept_evidence(assertion, evidence_requirement=req)
        result = reporting_services.evidence_coverage(impl)
    assert result["coverage_pct"] == pytest.approx(100.0)
    assert result["covered_count"] == 1


def test_evidence_coverage_excludes_stale_links(tenant_a, clock_ctl):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4(),
                                                             freshness_days=30)
        uow.flush()
        _accept_evidence(assertion, evidence_requirement=req, clock_ctl=clock_ctl, advance_days=45)
        result = reporting_services.evidence_coverage(impl)
    assert result["coverage_pct"] == 0.0
    assert result["uncovered_requirement_ids"] == [req.id]


def test_evidence_coverage_excludes_unaccepted_links(tenant_a):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4())
        uow.flush()
        rev = _revision()
        control_services.link_evidence(assertion, rev, created_by=uuid.uuid4(), evidence_requirement=req)
        result = reporting_services.evidence_coverage(impl)
    assert result["coverage_pct"] == 0.0


def test_evidence_coverage_partial_across_two_requirements(tenant_a):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        req1 = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4())
        req2 = control_services.create_evidence_requirement(impl, "firewall_config", created_by=uuid.uuid4())
        uow.flush()
        _accept_evidence(assertion, evidence_requirement=req1)
        result = reporting_services.evidence_coverage(impl)
    assert result["total_requirements"] == 2
    assert result["covered_count"] == 1
    assert result["coverage_pct"] == pytest.approx(50.0)
    assert result["uncovered_requirement_ids"] == [req2.id]


def test_evidence_coverage_tenant_isolation(tenant_a, tenant_b):
    fw = _framework_with_requirements()
    _activate(tenant_a, fw)
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        assertion = control_services.assert_control(impl, fw.urn, "req-0", created_by=uuid.uuid4())
        req = control_services.create_evidence_requirement(impl, "access_review_export", created_by=uuid.uuid4())
        uow.flush()
        _accept_evidence(assertion, evidence_requirement=req)
    with tenant_context(tenant_b.id):
        result = reporting_services.evidence_coverage(impl)
    assert result["total_requirements"] == 0
    assert result["coverage_pct"] is None


def _finding(impl, *, severity=Finding.Severity.HIGH):
    return control_services.raise_finding(impl, "Stale firewall rule", source=Finding.Source.MANUAL,
                                           severity=severity, created_by=uuid.uuid4())


def test_high_finding_ageing_is_empty_with_no_findings(tenant_a):
    with tenant_context(tenant_a.id):
        result = reporting_services.high_finding_ageing()
    assert result == {"count": 0, "oldest_age_days": None, "findings": []}


def test_high_finding_ageing_excludes_low_and_medium_severity(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        _finding(impl, severity=Finding.Severity.LOW)
        _finding(impl, severity=Finding.Severity.MEDIUM)
        uow.flush()
        result = reporting_services.high_finding_ageing()
    assert result["count"] == 0


def test_high_finding_ageing_excludes_closed_findings(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        finding = _finding(impl)
        uow.flush()
        finding = control_services.transition_finding(finding, Finding.Status.IN_REMEDIATION, actor_id=uuid.uuid4())
        finding = control_services.transition_finding(finding, Finding.Status.PENDING_VERIFICATION, actor_id=uuid.uuid4())
        control_services.transition_finding(finding, Finding.Status.CLOSED, actor_id=uuid.uuid4())
        result = reporting_services.high_finding_ageing()
    assert result["count"] == 0


def test_high_finding_ageing_sorts_oldest_first_and_reports_age(tenant_a):
    """Finding has no append-only guard (unlike EvidenceRevision) - created_at is backdated directly rather
    than via clock_ctl, which only shifts clock.now() forward and would age both findings identically since
    Django's auto_now_add is real wall-clock, not ngrc.core.clock."""
    from datetime import timedelta

    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        older = _finding(impl, severity=Finding.Severity.CRITICAL)
        newer = _finding(impl, severity=Finding.Severity.HIGH)
        uow.flush()
        older.created_at -= timedelta(days=10)
        older.save(update_fields=["created_at"])
        result = reporting_services.high_finding_ageing()
    assert result["count"] == 2
    assert [row["id"] for row in result["findings"]] == [older.id, newer.id]
    assert result["findings"][0]["age_days"] == 10
    assert result["findings"][1]["age_days"] == 0
    assert result["oldest_age_days"] == 10
    assert result["findings"][0]["severity"] == Finding.Severity.CRITICAL
    assert result["findings"][0]["implementation_control_id"] == impl.id


def test_high_finding_ageing_tenant_isolation(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        impl = _impl()
        _finding(impl)
        uow.flush()
    with tenant_context(tenant_b.id):
        result = reporting_services.high_finding_ageing()
    assert result["count"] == 0
