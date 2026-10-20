#!/usr/bin/env python3
"""Evaluate the independent-review record (docs/review/REVIEW_RECORD.yaml) - P2-2.

The record is HUMAN INPUT: reviewer identity, scope, findings, severity, remediation and disposition come from an independent reviewer's
signed report. This module only decides what the record is allowed to *mean*:

* no review entry for a scope            -> that scope is BLOCKED (never "passed by default");
* a reviewer who is (or may be) an implementer, or who does not state independence -> the entry is REJECTED (no self-approval);
* an entry without the reviewer's report digest, date, or the digest of the package that was reviewed -> INCOMPLETE;
* a review of an OLDER package than the current one -> STALE (the code changed after review);
* open Critical/High findings -> the scope cannot be COMPLETE.

Exit code 0 only when every scope is COMPLETE. Nothing here can mark a review as done on the reviewer's behalf.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs" / "review" / "REVIEW_RECORD.yaml"
SCOPE = ROOT / "docs" / "review" / "review_scope.yaml"
MANIFEST = ROOT / "evidence" / "review_package" / "review_package_manifest.json"

SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STATUS = ("open", "remediated", "accepted_risk", "not_applicable")
DISPOSITIONS = ("approved", "approved_with_conditions", "rejected")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def evaluate_entry(entry: dict, implementers: list[str], current_manifest: str | None) -> tuple[str, list[str]]:
    """Return (state, problems) for one review entry. States: COMPLETE | CONDITIONAL | REJECTED | INCOMPLETE | STALE."""
    problems: list[str] = []
    rv = entry.get("reviewer") or {}
    name = str(rv.get("name") or "").strip()
    if not name or not str(rv.get("organisation") or "").strip():
        problems.append("reviewer name and organisation are required")
    if rv.get("independent_of_implementers") is not True or not str(rv.get("independence_statement") or "").strip():
        problems.append("reviewer must state independence from the implementers (independent_of_implementers: true + statement)")
    low = " ".join(name.lower().split())
    for imp in (" ".join(i.lower().split()) for i in implementers if i):
        if low and (low == imp or (len(low) >= 5 and (low in imp or imp in low))):
            return "REJECTED", [f"reviewer '{name}' matches an implementer - self-approval is not accepted"]
    if re.search(r"\b(claude|anthropic|assistant|copilot|chatgpt|gpt-?\d*|llm)\b", low):
        return "REJECTED", [f"reviewer '{name}' is an AI assistant or tool - tool output is not an independent review"]
    if problems:
        return "REJECTED", problems
    if not _HEX64.fullmatch(str(entry.get("report_sha256") or "")):
        problems.append("report_sha256 (digest of the reviewer's signed report) is required")
    if not str(entry.get("report_date") or "").strip():
        problems.append("report_date is required")
    reviewed = str(entry.get("reviewed_manifest_sha256") or "")
    if not _HEX64.fullmatch(reviewed):
        problems.append("reviewed_manifest_sha256 (digest of the package that was reviewed) is required")
    if entry.get("disposition") not in DISPOSITIONS:
        problems.append(f"disposition must be one of {DISPOSITIONS}")
    findings = entry.get("findings")
    if findings is None or (findings == [] and entry.get("no_findings_confirmed") is not True):
        problems.append("findings must be listed; an empty list needs no_findings_confirmed: true from the reviewer")
    open_blocking = False
    for f in findings or []:
        if f.get("severity") not in SEVERITIES or f.get("status") not in FINDING_STATUS or not f.get("id"):
            problems.append(f"finding {f.get('id', '?')}: id, severity and status are required and must be from the allowed sets")
            continue
        if f["severity"] != "info" and not str(f.get("remediation") or "").strip():
            problems.append(f"finding {f['id']}: remediation text is required")
        if f["status"] == "remediated" and not str(f.get("retest_evidence") or "").strip():
            problems.append(f"finding {f['id']}: a remediated finding needs retest evidence")
        if f["status"] == "accepted_risk" and not str(f.get("risk_acceptance_ref") or "").strip():
            problems.append(f"finding {f['id']}: accepted risk needs a risk-acceptance reference")
        if f["status"] == "open" and f["severity"] in ("critical", "high"):
            open_blocking = True
    if problems:
        return "INCOMPLETE", problems
    if current_manifest and reviewed != current_manifest:
        return "STALE", ["the reviewed package digest differs from the current code/doc package; the changed material was not reviewed"]
    if entry["disposition"] == "rejected" or open_blocking:
        return "REJECTED", ["reviewer rejected the design or open Critical/High findings remain"]
    open_any = any(f.get("status") == "open" for f in findings or [])
    if entry["disposition"] == "approved_with_conditions" or open_any:
        return "CONDITIONAL", ["conditions or open lower-severity findings remain"]
    return "COMPLETE", []


def evaluate(record: dict, scope_ids: list[str], current_manifest: str | None = None) -> dict:
    implementers = [str(x) for x in (record.get("implementers") or []) + (record.get("implementer_humans") or [])]
    entries = record.get("reviews") or []
    out: dict[str, dict] = {}
    for sid in scope_ids:
        mine = [e for e in entries if sid in (e.get("scopes") or [])]
        if not mine:
            out[sid] = {"state": "BLOCKED", "problems": ["no independent reviewer has reviewed this scope"], "reviewers": []}
            continue
        results = [evaluate_entry(e, implementers, current_manifest) for e in mine]
        order = ["REJECTED", "INCOMPLETE", "STALE", "CONDITIONAL", "COMPLETE"]
        worst = min(results, key=lambda r: order.index(r[0]))
        out[sid] = {"state": worst[0], "problems": worst[1], "reviewers": [(e.get("reviewer") or {}).get("name", "") for e in mine]}
    states = {v["state"] for v in out.values()}
    if states == {"COMPLETE"}:
        overall = "COMPLETE"
    elif "BLOCKED" in states and states <= {"BLOCKED"}:
        overall = "BLOCKED"
    elif states & {"REJECTED", "INCOMPLETE", "STALE"}:
        overall = "NOT_ACCEPTED"
    elif "BLOCKED" in states:
        overall = "PARTIAL"
    else:
        overall = "CONDITIONAL"
    return {"overall": overall, "scopes": out}


def current_manifest_digest() -> str | None:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8")).get("package_sha256")
    return None


def main() -> int:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8")) or {}
    scope_ids = [s["id"] for s in yaml.safe_load(SCOPE.read_text(encoding="utf-8"))["scopes"]]
    res = evaluate(record, scope_ids, current_manifest_digest())
    print(json.dumps(res, indent=2))
    return 0 if res["overall"] == "COMPLETE" else 1


if __name__ == "__main__":
    sys.exit(main())
