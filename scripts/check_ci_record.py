#!/usr/bin/env python3
"""Evaluate the CI run record (docs/ci/CI_RUN_RECORD.yaml) - P2-1.

A passing CI result can only be recorded from a REAL run on the project's CI service (decision 2026-10-21: a private GitHub repository with
GitHub Actions). The record must prove, field by field:

* WHICH CODE ran: `run.commit_sha` (40 hex) that exists in the local repository, and the workflow file AT THAT COMMIT hashes to `run.workflow_sha256`
  (so the run executed the workflow we have, and a later edit makes the record STALE);
* WHICH WORKFLOW ran: `workflow_path == .github/workflows/ci.yml` and `workflow_name == ci`, in a repository recorded as private, with an https run URL;
* ALL required jobs ran and succeeded - tests, sast, sca, secrets, container - each with named evidence;
* the TEST RESULTS: the `tests` job reports N passed, 0 failed, and at least one PostgreSQL/RLS test passed;
* the SECURITY SCANS: sast, sca and secrets (gitleaks full history) succeeded;
* the CONTAINER gate: built on a Docker-capable runner and the image scan clean.

It never fills anything in. Local rehearsals (docs/ci/LOCAL_REHEARSAL.md) are not CI runs and cannot satisfy it.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess  # noqa: S404
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs" / "ci" / "CI_RUN_RECORD.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW_PATH = ".github/workflows/ci.yml"
WORKFLOW_NAME = "ci"
REQUIRED_JOBS = ("tests", "sast", "sca", "secrets", "container")
_SHA = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def workflow_digest() -> str:
    return hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()


def workflow_digest_at(commit: str) -> str | None:
    """sha256 of the workflow file as committed at `commit` in the local repository; None if the commit is unknown here."""
    try:
        p = subprocess.run(["git", "show", f"{commit}:{WORKFLOW_PATH}"], cwd=ROOT, capture_output=True, timeout=30)  # noqa: S603,S607
    except (OSError, subprocess.SubprocessError):
        return None
    return hashlib.sha256(p.stdout).hexdigest() if p.returncode == 0 else None


def evaluate(rec: dict, current_workflow_sha: str, commit_workflow_sha=workflow_digest_at) -> dict:
    run = rec.get("run")
    if not run:
        return {"state": "NOT_RUN", "problems": ["no CI run has been recorded; the workflow file existing is not a result"], "jobs": {}}
    problems: list[str] = []
    if not str(run.get("url") or "").startswith("https://"):
        problems.append("run.url (https link to the CI run) is required")
    if not _SHA.fullmatch(str(run.get("commit_sha") or "")):
        problems.append("run.commit_sha (40 hex) is required")
    if not _HEX64.fullmatch(str(run.get("workflow_sha256") or "")):
        problems.append("run.workflow_sha256 is required")
    if run.get("workflow_path") != WORKFLOW_PATH or run.get("workflow_name") != WORKFLOW_NAME:
        problems.append(f"workflow identity must be path {WORKFLOW_PATH} and name {WORKFLOW_NAME}")
    if run.get("repository_private") is not True:
        problems.append("run.repository_private must be true (the approved CI setup is a PRIVATE repository)")
    if not str(run.get("service") or "").strip() or not str(run.get("completed_at") or "").strip():
        problems.append("run.service and run.completed_at are required")
    jobs = run.get("jobs") or {}
    states: dict[str, str] = {}
    for j in REQUIRED_JOBS:
        got = jobs.get(j) or {}
        c = got.get("conclusion")
        if c is None:
            states[j] = "MISSING"
        elif c != "success":
            states[j] = str(c).upper()
        elif not str(got.get("evidence") or "").strip():
            states[j] = "NO_EVIDENCE"
        elif j == "tests" and not (isinstance(got.get("tests_passed"), int) and got["tests_passed"] > 0 and got.get("tests_failed") == 0
                                   and isinstance(got.get("rls_tests_passed"), int) and got["rls_tests_passed"] > 0):
            states[j] = "NO_TEST_RESULTS"          # needs N passed, 0 failed and PostgreSQL/RLS tests among them
        elif j == "container" and (got.get("docker_available") is not True or got.get("image_scan") != "clean"):
            states[j] = "NO_DOCKER" if got.get("docker_available") is not True else "IMAGE_SCAN_NOT_CLEAN"
        elif j == "secrets" and got.get("history_scanned") is not True:
            states[j] = "HISTORY_NOT_SCANNED"      # gitleaks must have seen the full history (fetch-depth: 0)
        else:
            states[j] = "SUCCESS"
    if problems:
        return {"state": "INCOMPLETE", "problems": problems, "jobs": states}
    if any(s != "SUCCESS" for s in states.values()):
        bad = {j: s for j, s in states.items() if s != "SUCCESS"}
        return {"state": "FAILED" if any(s in {"FAILURE", "CANCELLED", "TIMED_OUT"} for s in bad.values()) else "INCOMPLETE",
                "problems": [f"{j}: {s}" for j, s in bad.items()], "jobs": states}
    at_commit = commit_workflow_sha(run["commit_sha"])
    if at_commit is None:
        return {"state": "INCOMPLETE", "problems": ["the recorded commit is not in the local repository (fetch it): the code that ran cannot be checked"], "jobs": states}
    if at_commit != run["workflow_sha256"]:
        return {"state": "INCOMPLETE", "problems": ["the recorded workflow digest does not match the workflow at the recorded commit"], "jobs": states}
    if run["workflow_sha256"] != current_workflow_sha:
        return {"state": "STALE", "problems": ["the workflow changed after the recorded run"], "jobs": states}
    return {"state": "PASSED", "problems": [], "jobs": states}


def main() -> int:
    rec = yaml.safe_load(RECORD.read_text(encoding="utf-8")) or {}
    res = evaluate(rec, workflow_digest())
    print(json.dumps(res, indent=2))
    return 0 if res["state"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
