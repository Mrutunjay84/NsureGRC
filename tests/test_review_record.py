"""P2-2 process control: the independent-review record cannot be satisfied by self-approval, by an AI tool, by an undated/unsigned review,
or by a review of different code. These tests exercise the CHECKER with synthetic records; they prove nothing about the real review, which is
BLOCKED (docs/review/REVIEW_RECORD.yaml contains no review). Pure Python, no database.
"""
import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_review_record as crr  # noqa: E402

pytestmark = pytest.mark.security

SCOPES = [s["id"] for s in yaml.safe_load((ROOT / "docs" / "review" / "review_scope.yaml").read_text(encoding="utf-8"))["scopes"]]
MANIFEST = "a" * 64
IMPLEMENTERS = ["Claude Code (AI assistant)", "Project Engineer One"]


def entry(**over):
    e = {"scopes": list(SCOPES), "reviewer": {"name": "Dr. Jane External", "organisation": "Example Security Ltd",
         "independent_of_implementers": True, "independence_statement": "No involvement in design or implementation."},
         "report_date": "2026-11-01", "report_sha256": "b" * 64, "reviewed_manifest_sha256": MANIFEST,
         "disposition": "approved", "no_findings_confirmed": True, "findings": []}
    e.update(over)
    return e


def rec(*entries, **over):
    return {"implementers": IMPLEMENTERS, "reviews": list(entries), **over}


def overall(record, manifest=MANIFEST):
    return crr.evaluate(record, SCOPES, manifest)


def test_the_real_record_is_blocked_because_no_independent_review_exists():
    real = yaml.safe_load((ROOT / "docs" / "review" / "REVIEW_RECORD.yaml").read_text(encoding="utf-8"))
    res = crr.evaluate(real, SCOPES, None)
    assert real["reviews"] == [] and res["overall"] == "BLOCKED"
    assert {v["state"] for v in res["scopes"].values()} == {"BLOCKED"}
    assert set(real["required_scopes"]) == set(SCOPES)


def test_an_empty_record_never_reads_as_reviewed():
    assert overall(rec())["overall"] == "BLOCKED"


@pytest.mark.parametrize("name", ["Claude Code (AI assistant)", "Project Engineer One", "claude", "Anthropic Claude", "ChatGPT", "Copilot", "some LLM"])
def test_implementers_and_ai_tools_cannot_review_their_own_work(name):
    e = entry(reviewer={**entry()["reviewer"], "name": name})
    res = overall(rec(e))
    assert res["overall"] == "NOT_ACCEPTED" and all(v["state"] == "REJECTED" for v in res["scopes"].values())


def test_reviewer_must_state_independence_themselves():
    e = entry(reviewer={**entry()["reviewer"], "independent_of_implementers": False})
    assert overall(rec(e))["overall"] == "NOT_ACCEPTED"
    e = entry(reviewer={**entry()["reviewer"], "independence_statement": ""})
    assert overall(rec(e))["overall"] == "NOT_ACCEPTED"


@pytest.mark.parametrize("missing", ["report_sha256", "report_date", "reviewed_manifest_sha256", "disposition"])
def test_a_review_without_report_digest_date_package_digest_or_disposition_is_incomplete(missing):
    e = entry()
    e[missing] = ""
    res = overall(rec(e))
    assert res["overall"] == "NOT_ACCEPTED" and {v["state"] for v in res["scopes"].values()} == {"INCOMPLETE"}


def test_a_review_of_different_code_is_stale():
    res = overall(rec(entry()), manifest="c" * 64)
    assert {v["state"] for v in res["scopes"].values()} == {"STALE"} and res["overall"] == "NOT_ACCEPTED"


def test_empty_findings_need_the_reviewers_explicit_confirmation():
    assert overall(rec(entry(no_findings_confirmed=False, findings=[])))["overall"] == "NOT_ACCEPTED"
    assert overall(rec(entry(findings=None)))["overall"] == "NOT_ACCEPTED"


def test_open_critical_or_high_findings_block_completion_and_lower_ones_leave_it_conditional():
    f = {"id": "R-1", "severity": "high", "status": "open", "remediation": "fix it"}
    assert overall(rec(entry(no_findings_confirmed=False, findings=[f])))["overall"] == "NOT_ACCEPTED"
    low = {**f, "severity": "low"}
    assert overall(rec(entry(no_findings_confirmed=False, findings=[low])))["overall"] == "CONDITIONAL"
    assert overall(rec(entry(disposition="approved_with_conditions")))["overall"] == "CONDITIONAL"
    assert overall(rec(entry(disposition="rejected")))["overall"] == "NOT_ACCEPTED"


def test_remediated_and_accepted_findings_need_evidence():
    base = {"id": "R-2", "severity": "medium", "remediation": "done"}
    assert overall(rec(entry(no_findings_confirmed=False, findings=[{**base, "status": "remediated"}])))["overall"] == "NOT_ACCEPTED"
    ok = {**base, "status": "remediated", "retest_evidence": "commit abc; tests pass"}
    assert overall(rec(entry(no_findings_confirmed=False, findings=[ok])))["overall"] == "COMPLETE"
    assert overall(rec(entry(no_findings_confirmed=False, findings=[{**base, "status": "accepted_risk"}])))["overall"] == "NOT_ACCEPTED"


def test_a_complete_record_requires_every_scope_to_be_covered():
    partial = entry(scopes=SCOPES[:2])
    res = overall(rec(partial))
    assert res["overall"] == "PARTIAL" and res["scopes"][SCOPES[0]]["state"] == "COMPLETE" and res["scopes"][SCOPES[3]]["state"] == "BLOCKED"
    assert overall(rec(entry()))["overall"] == "COMPLETE"  # synthetic record, test data only


def test_the_checker_does_not_mutate_its_input():
    r = rec(entry())
    before = copy.deepcopy(r)
    overall(r)
    assert r == before
