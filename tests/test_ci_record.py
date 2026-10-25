"""P2-1 process control: CI cannot be recorded as passed without a real run of the PRIVATE repository's workflow, with the right commit and workflow identity, all
five jobs (tests incl. PostgreSQL/RLS results, the security scans, a Docker-capable container job with a clean image scan) and an unchanged workflow.
These tests exercise the CHECKER (and the importer's pure functions) with synthetic records; the real record is NOT_RUN - no CI service has executed the workflow.
Pure Python, no database."""
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_ci_record as ccr  # noqa: E402
import import_ci_run as icr  # noqa: E402

pytestmark = pytest.mark.security

WF = "d" * 64
SHA = "e" * 40


def good_run(**over):
    jobs = {j: {"conclusion": "success", "evidence": "artifact"} for j in ccr.REQUIRED_JOBS}
    jobs["tests"].update({"tests_passed": 600, "tests_failed": 0, "rls_tests_passed": 70})
    jobs["container"].update({"docker_available": True, "image_scan": "clean"})
    jobs["secrets"].update({"history_scanned": True})
    run = {"service": "GitHub Actions", "url": "https://github.com/o/r/actions/runs/1", "commit_sha": SHA, "workflow_sha256": WF,
           "workflow_path": ".github/workflows/ci.yml", "workflow_name": "ci", "repository_private": True,
           "completed_at": "2026-11-01T10:00:00Z", "jobs": jobs}
    run.update(over)
    return {"run": run}


def evaluate(rec, current=WF, at_commit=WF):
    return ccr.evaluate(rec, current, commit_workflow_sha=lambda _sha: at_commit)


def test_the_real_record_reflects_a_genuinely_passed_run():
    """P2-1 closed 2026-10-26 (run 40232416860): this asserts the checker's own verdict on the real record, not a
    hardcoded belief about it - if the record is ever hand-edited into something the checker would not accept, this
    fails. Before that date this test asserted the opposite (`real["run"] is None`, state "NOT_RUN") - CI had never
    actually run; that assumption is now stale by design, not weakened."""
    real = yaml.safe_load((ROOT / "docs" / "ci" / "CI_RUN_RECORD.yaml").read_text(encoding="utf-8"))
    assert real["run"] is not None
    result = ccr.evaluate(real, ccr.workflow_digest())  # same call main() makes; commit_workflow_sha defaults to the real git lookup
    assert result["state"] == "PASSED", result


def test_the_workflow_file_existing_is_not_a_result():
    assert ccr.WORKFLOW.exists() and ccr.evaluate({}, ccr.workflow_digest())["state"] == "NOT_RUN"


def test_all_jobs_green_for_the_right_commit_and_an_unchanged_workflow_is_the_only_pass():
    assert evaluate(good_run())["state"] == "PASSED"


@pytest.mark.parametrize("job", ccr.REQUIRED_JOBS)
def test_a_missing_skipped_or_failed_job_is_never_a_pass(job):
    for bad in ({"conclusion": "failure"}, {"conclusion": "skipped"}, {"conclusion": "cancelled"}, None):
        rec = good_run()
        if bad is None:
            del rec["run"]["jobs"][job]
        else:
            rec["run"]["jobs"][job] = bad
        assert evaluate(rec)["state"] in {"FAILED", "INCOMPLETE"}


def test_the_container_job_needs_docker_and_a_clean_image_scan():
    for patch, expect in (({"docker_available": False}, "NO_DOCKER"), ({"image_scan": "findings"}, "IMAGE_SCAN_NOT_CLEAN"), ({"image_scan": None}, "IMAGE_SCAN_NOT_CLEAN")):
        rec = good_run()
        rec["run"]["jobs"]["container"].update(patch)
        res = evaluate(rec)
        assert res["state"] == "INCOMPLETE" and res["jobs"]["container"] == expect


@pytest.mark.parametrize("patch", [{"tests_passed": 0}, {"tests_failed": 1}, {"rls_tests_passed": 0}, {"tests_passed": "600"}, {"rls_tests_passed": None}])
def test_the_tests_job_must_report_passes_no_failures_and_postgresql_rls_results(patch):
    rec = good_run()
    rec["run"]["jobs"]["tests"].update(patch)
    res = evaluate(rec)
    assert res["state"] == "INCOMPLETE" and res["jobs"]["tests"] == "NO_TEST_RESULTS"


def test_the_secret_scan_must_have_seen_the_full_history():
    rec = good_run()
    rec["run"]["jobs"]["secrets"]["history_scanned"] = False
    assert evaluate(rec)["jobs"]["secrets"] == "HISTORY_NOT_SCANNED"


def test_a_success_without_evidence_is_not_accepted():
    rec = good_run()
    rec["run"]["jobs"]["sast"]["evidence"] = ""
    assert evaluate(rec)["state"] == "INCOMPLETE"


def test_a_changed_workflow_makes_the_recorded_run_stale():
    assert evaluate(good_run(), current="f" * 64)["state"] == "STALE"


def test_the_run_must_have_executed_the_workflow_that_the_commit_contains():
    assert evaluate(good_run(), at_commit="0" * 64)["state"] == "INCOMPLETE"
    res = evaluate(good_run(), at_commit=None)
    assert res["state"] == "INCOMPLETE" and "not in the local repository" in res["problems"][0]


@pytest.mark.parametrize("over", [{"url": "file:///tmp/run"}, {"url": ""}, {"commit_sha": "abc"}, {"workflow_sha256": ""}, {"service": ""},
                                  {"repository_private": False}, {"repository_private": None}, {"workflow_path": ".github/workflows/other.yml"},
                                  {"workflow_name": "release"}])
def test_run_metadata_must_be_present_well_formed_private_and_for_the_right_workflow(over):
    assert evaluate(good_run(**over))["state"] == "INCOMPLETE"


# ------------------------------------------------------------------------------------------------ importer (pure functions only)
def test_the_importer_derives_job_results_from_api_shaped_data_and_never_invents_the_rest():
    keys = icr.job_key_by_display_name()
    assert set(keys.values()) == set(ccr.REQUIRED_JOBS)
    name = {v: k for k, v in keys.items()}
    run = {"html_url": "https://github.com/o/r/actions/runs/9", "head_sha": SHA, "updated_at": "2026-11-01T10:00:00Z", "path": ".github/workflows/ci.yml",
           "name": "ci", "repository": {"private": True}}
    jobs = [{"name": name[k], "conclusion": "success", "html_url": "https://github.com/o/r/actions/runs/9/job/1", "steps": [{"name": "Build", "conclusion": "success"}]}
            for k in ccr.REQUIRED_JOBS]
    arts = [{"name": n, "id": i, "digest": "sha256:abc"} for i, n in enumerate(("test-evidence", "sast-evidence", "sca-evidence", "container-evidence"))]
    junit = ('<testsuite><testcase classname="tests.test_rls_x" name="a"/><testcase classname="tests.test_other" name="b"/>'
             '<testcase classname="tests.test_rls_y" name="c"><skipped type="pytest.xfail"/></testcase></testsuite>')
    rec = icr.build_record(run, jobs, arts, junit, trivy_clean=None, history_scanned=None)
    assert rec["jobs"]["tests"]["tests_passed"] == 2 and rec["jobs"]["tests"]["rls_tests_passed"] == 1 and rec["jobs"]["tests"]["tests_failed"] == 0
    assert "image_scan" not in rec["jobs"]["container"] and "history_scanned" not in rec["jobs"]["secrets"]    # not derivable => left out, checker says INCOMPLETE
    assert rec["repository_private"] is True and rec["workflow_path"] == ".github/workflows/ci.yml"
    full = {"run": {**rec, "workflow_sha256": WF, "service": "GitHub Actions"}}
    assert evaluate(full)["state"] == "INCOMPLETE"
