"""P2-1 process control: CI cannot be recorded as passed without a real run, all five jobs (including a Docker-capable container job), and an
unchanged workflow. These tests exercise the CHECKER with synthetic records; the real record is NOT_RUN (no CI service has executed the workflow).
Pure Python, no database.
"""
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_ci_record as ccr  # noqa: E402

pytestmark = pytest.mark.security

WF = "d" * 64


def good_run(**over):
    jobs = {j: {"conclusion": "success", "evidence": "artifact"} for j in ccr.REQUIRED_JOBS}
    jobs["container"]["docker_available"] = True
    run = {"service": "CI", "url": "https://ci.example/run/1", "commit_sha": "e" * 40, "workflow_sha256": WF, "completed_at": "2026-11-01T10:00:00Z",
           "jobs": jobs}
    run.update(over)
    return {"run": run}


def test_the_real_record_says_ci_has_not_run():
    real = yaml.safe_load((ROOT / "docs" / "ci" / "CI_RUN_RECORD.yaml").read_text(encoding="utf-8"))
    assert real["run"] is None and ccr.evaluate(real, ccr.workflow_digest())["state"] == "NOT_RUN"


def test_the_workflow_file_existing_is_not_a_result():
    assert ccr.WORKFLOW.exists() and ccr.evaluate({}, ccr.workflow_digest())["state"] == "NOT_RUN"


def test_all_jobs_green_on_an_unchanged_workflow_is_the_only_pass():
    assert ccr.evaluate(good_run(), WF)["state"] == "PASSED"


@pytest.mark.parametrize("job", ccr.REQUIRED_JOBS)
def test_a_missing_skipped_or_failed_job_is_never_a_pass(job):
    for bad in ({"conclusion": "failure"}, {"conclusion": "skipped"}, {"conclusion": "cancelled"}, None):
        rec = good_run()
        if bad is None:
            del rec["run"]["jobs"][job]
        else:
            rec["run"]["jobs"][job] = bad
        assert ccr.evaluate(rec, WF)["state"] in {"FAILED", "INCOMPLETE"}


def test_the_container_job_without_docker_does_not_count():
    rec = good_run()
    rec["run"]["jobs"]["container"]["docker_available"] = False
    res = ccr.evaluate(rec, WF)
    assert res["state"] == "INCOMPLETE" and res["jobs"]["container"] == "NO_DOCKER"


def test_a_success_without_evidence_is_not_accepted():
    rec = good_run()
    rec["run"]["jobs"]["tests"]["evidence"] = ""
    assert ccr.evaluate(rec, WF)["state"] == "INCOMPLETE"


def test_a_changed_workflow_makes_the_recorded_run_stale():
    assert ccr.evaluate(good_run(), "f" * 64)["state"] == "STALE"


@pytest.mark.parametrize("over", [{"url": "file:///tmp/run"}, {"url": ""}, {"commit_sha": "abc"}, {"workflow_sha256": ""}, {"service": ""}])
def test_run_metadata_must_be_present_and_well_formed(over):
    assert ccr.evaluate(good_run(**over), WF)["state"] == "INCOMPLETE"
