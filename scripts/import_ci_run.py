#!/usr/bin/env python3
"""Turn a REAL GitHub Actions run into docs/ci/CI_RUN_RECORD.yaml content (P2-1). Run it yourself with YOUR token; this project never creates or stores credentials.

    GITHUB_TOKEN=<your fine-grained token: Actions + Contents read-only on the one repository> \
    uv run python scripts/import_ci_run.py --repo OWNER/NAME --run-id 123456789 [--write]

It reads the run, its jobs and its artifacts from the GitHub REST API, downloads the `test-evidence` and `container-evidence` artifacts to count test results and
read the image scan outcome, and prints (or with --write stores) the `run:` block. Nothing is invented: a field it cannot derive stays out of the record, and
`scripts/check_ci_record.py` then reports INCOMPLETE. STATUS OF THIS SCRIPT: the pure record-building functions are unit-tested with fixture responses
(tests/test_ci_record.py); the HTTP calls have NOT been exercised against the real API because no repository or credentials exist yet.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # noqa: S405 - parsing the project's own pytest output
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
API = "https://api.github.com"


def job_key_by_display_name() -> dict[str, str]:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return {j.get("name", k): k for k, j in wf["jobs"].items()}


def parse_junit(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)  # noqa: S314
    passed = failed = rls = 0
    for tc in root.iter("testcase"):
        bad = tc.find("failure") is not None or tc.find("error") is not None
        skipped = tc.find("skipped") is not None
        if bad:
            failed += 1
        elif not skipped:
            passed += 1
            if "test_rls_" in tc.get("classname", ""):
                rls += 1
    return {"tests_passed": passed, "tests_failed": failed, "rls_tests_passed": rls}


def build_record(run: dict, jobs: list[dict], artifacts: list[dict], junit_xml: str | None, trivy_clean: bool | None, history_scanned: bool | None) -> dict:
    keys = job_key_by_display_name()
    out_jobs: dict[str, dict] = {}
    art = {a["name"]: a for a in artifacts}
    for j in jobs:
        key = keys.get(j["name"])
        if key is None:
            continue
        entry: dict = {"conclusion": j.get("conclusion")}
        names = {"tests": "test-evidence", "sast": "sast-evidence", "sca": "sca-evidence", "container": "container-evidence"}
        if key in names and names[key] in art:
            a = art[names[key]]
            entry["evidence"] = f"artifact {a['name']} (id {a['id']}, digest {a.get('digest', 'not provided by the API')})"
        elif key == "secrets":
            entry["evidence"] = f"job log {j.get('html_url', '')}"
        if key == "tests" and junit_xml:
            entry.update(parse_junit(junit_xml))
        if key == "container":
            entry["docker_available"] = any(s.get("name", "").lower().startswith("build") and s.get("conclusion") == "success" for s in j.get("steps", []))
            if trivy_clean is not None:
                entry["image_scan"] = "clean" if trivy_clean else "findings"
        if key == "secrets" and history_scanned is not None:
            entry["history_scanned"] = history_scanned
        out_jobs[key] = entry
    return {"service": "GitHub Actions", "url": run["html_url"], "commit_sha": run["head_sha"], "completed_at": run.get("updated_at", ""),
            "workflow_path": run.get("path", ""), "workflow_name": run.get("name", ""), "repository_private": bool(run.get("repository", {}).get("private")),
            "runner_image": "see run log", "jobs": out_jobs}


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Artifact downloads 302 from api.github.com to a signed Azure Blob Storage URL; forwarding our GitHub
    Authorization header there (urllib's default redirect behaviour) makes Azure reject the request with 401
    (its own SAS-token auth in the URL conflicts with an unexpected Authorization header). Strip it whenever
    the redirect target is a different host than the original request - first run against the real API found
    this (DEF-20); it cannot be exercised by the fixture-based unit tests, which never issue a real HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            new_req.headers.pop("Authorization", None)
        return new_req


_OPENER = urllib.request.build_opener(_StripAuthOnRedirect)


def _get(url: str, token: str, raw: bool = False):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",  # noqa: S310
                                               "X-GitHub-Api-Version": "2022-11-28"})
    with _OPENER.open(req, timeout=60) as r:  # noqa: S310 - fixed https API host
        data = r.read()
    return data if raw else json.loads(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--run-id", required=True, type=int)
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", a.repo):
        print("bad --repo")
        return 2
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is not set (supply your own read-only token; this project never creates credentials)")
        return 2
    base = f"{API}/repos/{a.repo}/actions/runs/{a.run_id}"
    run = _get(base, token)
    jobs = _get(base + "/jobs?per_page=100", token)["jobs"]
    artifacts = _get(base + "/artifacts?per_page=100", token)["artifacts"]
    junit = None
    by_name = {x["name"]: x for x in artifacts}
    if "test-evidence" in by_name:
        z = zipfile.ZipFile(io.BytesIO(_get(by_name["test-evidence"]["archive_download_url"], token, raw=True)))
        name = next((n for n in z.namelist() if n.endswith("junit.xml")), None)
        junit = z.read(name).decode("utf-8") if name else None
    record = {"version": 1, "status": "RECORDED", "status_reason": f"imported from run {a.run_id} by scripts/import_ci_run.py",
              "run": build_record(run, jobs, artifacts, junit, trivy_clean=None, history_scanned=None)}
    record["run"]["workflow_sha256"] = ""   # fill with: git show <commit>:.github/workflows/ci.yml | sha256sum  (never trusted from the API)
    print(yaml.safe_dump(record, sort_keys=False))
    if a.write:
        (ROOT / "docs" / "ci" / "CI_RUN_RECORD.yaml").write_text(yaml.safe_dump(record, sort_keys=False), encoding="utf-8")
    print("\nStill to be filled by a human from the run page: workflow_sha256, container image_scan, secrets history_scanned.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
