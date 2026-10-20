#!/usr/bin/env python3
"""Evaluate the CI run record (docs/ci/CI_RUN_RECORD.yaml) - P2-1.

A passing CI result can only be recorded from a REAL run on a CI service. The record must carry the run URL, the commit that ran, the digest of
the workflow file that ran, and a conclusion per job. This script refuses to call CI "passed" when:
* there is no run (state NOT_RUN),
* any required job is missing, skipped, cancelled or failed,
* the `container` job did not run on a Docker-capable runner (image build + image scan is part of the requirement),
* the workflow file has changed since the recorded run (STALE),
* the record claims a service/URL that is not an https URL.
It never fills anything in. Local rehearsals (docs/ci/LOCAL_REHEARSAL.md) are not CI runs and cannot satisfy it.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs" / "ci" / "CI_RUN_RECORD.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
REQUIRED_JOBS = ("tests", "sast", "sca", "secrets", "container")
_SHA = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def workflow_digest() -> str:
    return hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()


def evaluate(rec: dict, current_workflow_sha: str) -> dict:
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
        elif j == "container" and got.get("docker_available") is not True:
            states[j] = "NO_DOCKER"
        elif not str(got.get("evidence") or "").strip():
            states[j] = "NO_EVIDENCE"
        else:
            states[j] = "SUCCESS"
    if problems:
        return {"state": "INCOMPLETE", "problems": problems, "jobs": states}
    if any(s != "SUCCESS" for s in states.values()):
        bad = {j: s for j, s in states.items() if s != "SUCCESS"}
        return {"state": "FAILED" if any(s in {"FAILURE", "CANCELLED", "TIMED_OUT"} for s in bad.values()) else "INCOMPLETE",
                "problems": [f"{j}: {s}" for j, s in bad.items()], "jobs": states}
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
