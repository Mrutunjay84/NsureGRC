"""D-P2-002: NIST CSF 2.0 parsing and the fetch-check-draft orchestration, against the real (trimmed)
CPRT payload captured during design - never a hand-written toy fixture. No test here hits the network:
`check_csf_source`'s own `fetch_csf_payload` is monkeypatched, and parsing is pure."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from ngrc.framework import nist_csf, services
from ngrc.framework.models import Framework, FrameworkVersion

pytestmark = pytest.mark.security

FIXTURE = Path(__file__).parent / "fixtures" / "nist_csf_2_0_0_sample.json"


@pytest.fixture
def raw_payload() -> bytes:
    return FIXTURE.read_bytes()


def _framework() -> Framework:
    return Framework.objects.using("catalog").create(
        urn=f"test-nist-csf-{uuid.uuid4().hex[:8]}", name="NIST CSF (test)", authority="NIST",
    )


def test_parse_builds_the_function_category_subcategory_hierarchy(raw_payload):
    parsed = nist_csf.parse_csf_payload(raw_payload)
    by_urn = {r.urn: r for r in parsed.requirements}

    fn = by_urn["nist-csf-2.0:RS"]
    assert fn.parent_urn is None
    assert fn.title == "RESPOND"

    cat = by_urn["nist-csf-2.0:RS.MA"]
    assert cat.parent_urn == "nist-csf-2.0:RS"

    sub = by_urn["nist-csf-2.0:RS.MA-01"]
    assert sub.parent_urn == "nist-csf-2.0:RS.MA"
    assert sub.ref_id == "RS.MA-01"


def test_parse_extracts_implementation_examples_and_external_references_as_reference_controls(raw_payload):
    parsed = nist_csf.parse_csf_payload(raw_payload)
    sub = next(r for r in parsed.requirements if r.urn == "nist-csf-2.0:RS.MA-01")
    sources = {g["catalog"] for g in sub.reference_controls}
    assert "NIST CSF 2.0 implementation example" in sources
    assert "SP_800_53_5_1_1" in sources
    impl = next(g for g in sub.reference_controls if g["catalog"] == "NIST CSF 2.0 implementation example")
    assert impl["note"]  # the real guidance text, not empty


def test_parse_drops_sort_and_withdraw_reason_elements(raw_payload):
    parsed = nist_csf.parse_csf_payload(raw_payload)
    urns = {r.urn for r in parsed.requirements}
    assert not any("WR-" in u or u.startswith("nist-csf-2.0:S-") for u in urns)


def test_build_draft_version_creates_the_full_requirement_tree(raw_payload):
    parsed = nist_csf.parse_csf_payload(raw_payload)
    fw = _framework()
    version = nist_csf.build_draft_version(parsed, fw, "v-test", created_by=uuid.uuid4(), checksum="abc123")
    assert version.status == FrameworkVersion.Status.DRAFT
    assert version.checksum == "abc123"
    assert version.requirements.using("default").count() == len(parsed.requirements)

    sub = version.requirements.using("default").get(urn="nist-csf-2.0:RS.MA-01")
    assert sub.parent.urn == "nist-csf-2.0:RS.MA"
    assert sub.reference_controls  # round-tripped through add_requirement


def test_check_csf_source_drafts_once_then_skips_when_unchanged(monkeypatch, raw_payload):
    monkeypatch.setattr(nist_csf, "fetch_csf_payload", lambda: raw_payload)
    fw = _framework()

    version = nist_csf.check_csf_source(fw, created_by=uuid.uuid4())
    assert version is not None
    assert version.status == FrameworkVersion.Status.DRAFT  # never auto-published
    first_count = version.requirements.using("default").count()
    assert first_count == len(nist_csf.parse_csf_payload(raw_payload).requirements)

    again = nist_csf.check_csf_source(fw, created_by=uuid.uuid4())
    assert again is None  # unchanged payload -> no second draft
    assert FrameworkVersion.objects.using("default").filter(framework=fw).count() == 1


def test_check_csf_source_drafts_again_when_payload_changes(monkeypatch, raw_payload):
    calls = {"n": 0}

    def fake_fetch():
        calls["n"] += 1
        return raw_payload if calls["n"] == 1 else raw_payload + b" "  # different bytes -> different hash

    monkeypatch.setattr(nist_csf, "fetch_csf_payload", fake_fetch)
    fw = _framework()

    v1 = nist_csf.check_csf_source(fw, created_by=uuid.uuid4())
    v2 = nist_csf.check_csf_source(fw, created_by=uuid.uuid4())
    assert v1 is not None and v2 is not None
    assert v1.id != v2.id
    assert FrameworkVersion.objects.using("default").filter(framework=fw).count() == 2


def test_check_csf_source_never_calls_publish(monkeypatch, raw_payload):
    monkeypatch.setattr(nist_csf, "fetch_csf_payload", lambda: raw_payload)
    calls = []
    monkeypatch.setattr(services, "publish_version", lambda *a, **kw: calls.append((a, kw)))
    fw = _framework()
    nist_csf.check_csf_source(fw, created_by=uuid.uuid4())
    assert calls == []
