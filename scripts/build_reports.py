#!/usr/bin/env python3
"""Generate the Phase 1 reports from REAL run output. Nothing here invents a result.

Inputs : docs/control_map.yaml (hand-maintained mapping, no results), docs/defects_found.yaml, docs/accepted_risks.yaml,
         evidence/junit.xml (pytest), evidence/gate_summary.json + raw scanner output (scripts/security_gate.py)
Outputs: docs/SECURITY_CONTROL_MATRIX.md, docs/SECURITY_TEST_REPORT.md, docs/SECURITY_SCAN_REPORT.md, docs/BLOCKED_TESTS.md,
         and the traceability register 00_CONTROL/TRACEABILITY/feature_control_map.csv

A control reads "TESTED - PASS" only if every mapped test is present in the JUnit file and passed. A mapped test that does not
exist, or a control whose mapped tests failed, makes this script exit non-zero.
"""
from __future__ import annotations

import ast
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own pytest output
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling record checkers (check_review_record, check_ci_record)
DOCS, EV = ROOT / "docs", ROOT / "evidence"
TRACE = ROOT.parent.parent / "00_CONTROL" / "TRACEABILITY" / "feature_control_map.csv"
NOW = datetime.now(UTC).strftime("%Y-%m-%d")


def load_yaml(p: Path):
    return yaml.safe_load(p.read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------------ JUnit
def read_junit() -> list[dict]:
    root = ET.parse(EV / "junit.xml").getroot()  # noqa: S314
    cases = []
    for tc in root.iter("testcase"):
        file = tc.get("classname", "").replace(".", "/") + ".py"
        name = tc.get("name", "")
        res, detail = "passed", ""
        for tag, label in (("failure", "failed"), ("error", "error"), ("skipped", "skipped")):
            node = tc.find(tag)
            if node is not None:
                res, detail = label, (node.get("message") or "")[:300]
                if tag == "skipped" and node.get("type") == "pytest.xfail":
                    res = "xfail"  # expected failure of a pending spec / gap demo: NEVER counted as a pass
        cases.append({"file": file, "name": name, "base": name.split("[")[0], "result": res, "detail": detail,
                      "time": float(tc.get("time", 0))})
    return cases


def docstrings() -> dict[tuple[str, str], str]:
    out = {}
    for p in (ROOT / "tests").glob("test_*.py"):
        mod = ast.parse(p.read_text(encoding="utf-8"))
        for node in mod.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                out[(f"tests/{p.name}", node.name)] = (ast.get_docstring(node) or "").strip().split("\n")[0]
        mdoc = (ast.get_docstring(mod) or "").strip().split("\n")[0]
        out[(f"tests/{p.name}", "__module__")] = mdoc
    return out


def humanize(name: str) -> str:
    return re.sub(r"\s+", " ", name.removeprefix("test_").replace("_", " ")).strip().capitalize()


def select(cases: list[dict], spec: dict) -> list[dict]:
    hits = [c for c in cases if c["file"] == spec["file"] and (not spec.get("match") or any(m in c["base"] for m in spec["match"]))]
    return hits


# ------------------------------------------------------------------------------------------------ control evaluation
def evaluate(controls: list[dict], cases: list[dict]) -> tuple[list[dict], list[str]]:
    errors, out = [], []
    for c in controls:
        sel, missing = [], []
        for spec in c.get("tests") or []:
            hits = select(cases, spec)
            if spec.get("match"):
                for m in spec["match"]:
                    if not any(m in h["base"] and h["file"] == spec["file"] for h in cases):
                        missing.append(f"{spec['file']}::*{m}*")
            elif not hits:
                missing.append(spec["file"])
            sel.extend(hits)
        uniq = {(h["file"], h["name"]): h for h in sel}
        sel = list(uniq.values())
        passed = sum(1 for h in sel if h["result"] == "passed")
        bad = [h for h in sel if h["result"] != "passed"]
        # executable specifications / gap demos: reported separately, NEVER counted as passing tests
        psel, pmissing = [], []
        for spec in c.get("pending_specs") or []:
            hits = select(cases, spec)
            for m in spec.get("match") or []:
                if not any(m in h["base"] and h["file"] == spec["file"] for h in cases):
                    pmissing.append(f"{spec['file']}::*{m}*")
            psel.extend(hits)
        psel = list({(h["file"], h["name"]): h for h in psel}.values())
        pbad = [h for h in psel if h["result"] != "xfail"]  # a pending spec that PASSES or errors means the control map is stale
        if missing or pmissing:
            errors.append(f"{c['id']}: mapped tests not found in the run: {missing + pmissing}")
        if pbad:
            errors.append(f"{c['id']}: pending specs not in XFAIL state (implemented? update control_map.yaml): "
                          f"{[h['name'] for h in pbad][:5]}")
        dynamic = c.get("dynamic")
        if dynamic:
            state, bad_dyn = dynamic_state(dynamic, bad or missing)
            status = state
        elif c.get("not_implemented"):
            status = "NOT IMPLEMENTED"
        elif not sel:
            status = "IMPLEMENTED — UNTESTED" if c.get("implementation") else "NOT IMPLEMENTED"
        elif bad or missing:
            status = "FAIL" if bad else "FAIL (mapped test missing)"
        else:
            status = "TESTED — PASS"
        flags = []
        if c.get("dev_only") and status.startswith("TESTED"):
            flags.append("DEV-ONLY component")
        if c.get("gaps") and not c.get("not_implemented"):
            flags.append(f"{len(c['gaps'])} documented gap(s)")
        if c.get("blocked"):
            flags.append(f"BLOCKED: {len(c['blocked'])}")
        if psel:
            flags.append(f"{len(psel)} pending spec/gap-demo case(s) XFAIL")
        out.append({**c, "selected": sel, "passed": passed, "total": len(sel), "bad": bad, "status": status, "flags": flags,
                    "pending": psel})
    return out, errors


def dynamic_state(kind: str, failing) -> tuple[str, bool]:
    """Status of controls whose truth lives in a human-supplied record (independent review, CI run). Never PASS by default."""
    if failing:
        return "FAIL", True
    if kind == "review":
        import check_review_record as crr

        scope_ids = [s["id"] for s in load_yaml(DOCS / "review" / "review_scope.yaml")["scopes"]]
        res = crr.evaluate(load_yaml(DOCS / "review" / "REVIEW_RECORD.yaml") or {}, scope_ids, crr.current_manifest_digest())
        return ("BLOCKED" if res["overall"] == "BLOCKED" else f"REVIEW {res['overall']}"), False
    import check_ci_record as ccr

    res = ccr.evaluate(load_yaml(DOCS / "ci" / "CI_RUN_RECORD.yaml") or {}, ccr.workflow_digest())
    return ("BLOCKED" if res["state"] == "NOT_RUN" else f"CI {res['state']}"), False


# ------------------------------------------------------------------------------------------------ writers
def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def short_tests(c: dict) -> str:
    files = defaultdict(int)
    for h in c["selected"]:
        files[h["file"].removeprefix("tests/")] += 1
    if not files:
        return "—"
    return "<br>".join(f"`{f}` ({n} case{'s' if n != 1 else ''})" for f, n in sorted(files.items()))


def write_matrix(evald: list[dict], meta: dict) -> None:
    lines = ["# NsureGRC — Security Control Matrix (Phase 1 / v1.3-alpha)", "",
             f"*Generated {meta['generated']} by `scripts/build_reports.py` from `docs/control_map.yaml` and the real pytest run "
             f"(`evidence/junit.xml`: {meta['passed']} passed, {meta['xfailed']} XFAIL, {meta['failed']} failed, {meta['skipped']} skipped, "
             f"{meta['total']} test cases).* **Do not edit by hand — regenerate.**", "",
             "**Reading this table.** `TESTED — PASS` means every mapped automated test ran in the recorded run and passed; it does **not** "
             "mean the control is production-ready, audited, certified or sufficient for any standard. `NOT IMPLEMENTED` means no code exists; "
             "an executable specification (reported as **XFAIL**, never as a pass) may exist for it. `BLOCKED` means the control depends on a "
             "human-supplied record (independent review, CI run) that does not exist. Standards references are "
             "*indicative mappings only*. Gaps, dev-only components and blocked tests are shown against each control and summarised below.", ""]
    counts = defaultdict(int)
    for c in evald:
        counts[c["status"]] += 1
    lines += ["## Summary", "", "| Status | Controls |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(counts.items())]
    lines += ["", "## Owner-decided groups (decision 2026-10-21)", "",
              "**Required before Phase 2 can be called security-ready** (implement AND test):", "", "| Control | Status | Result |", "|---|---|---|"]
    for c in evald:
        if c.get("phase2_required"):
            lines.append(f"| {c['id']} {md_escape(c['feature'])} | **{c['status']}** | {c['passed']}/{c['total']} passed |")
    lines += ["", "**Production-security gates** (NOT Phase 2 development blockers; no production-readiness claim while any is open):", "",
              "| Control | Status |", "|---|---|"]
    for c in evald:
        if c.get("production_gate"):
            lines.append(f"| {c['id']} {md_escape(c['feature'])} | **{c['status']}** |")
    lines += ["", "## Matrix", "",
              "| Control | Implementation | Test | Result | Audit event(s) | Evidence | Status |", "|---|---|---|---|---|---|---|"]
    for c in evald:
        impl = "<br>".join(f"`{i}`" for i in c.get("implementation") or []) or "—"
        ae = ", ".join(f"`{a}`" for a in c.get("audit_events") or []) or "—"
        ev = "<br>".join(f"`{e}`" for e in c.get("evidence") or []) or "—"
        res = f"{c['passed']}/{c['total']} passed" if c["total"] else "no passing tests"
        if c.get("pending"):
            res += f" · {len(c['pending'])} XFAIL (not a pass)"
        flag = (" · " + "; ".join(c["flags"])) if c["flags"] else ""
        lines.append(f"| **{c['id']}** {md_escape(c['feature'])} | {impl} | {short_tests(c)} | {res} | {ae} | {ev} | **{c['status']}**{flag} |")
    lines += ["", "## Documented gaps, dev-only components and blocked tests (per control)", ""]
    for c in evald:
        if c.get("gaps") or c.get("blocked") or c.get("dev_only"):
            lines.append(f"### {c['id']} — {c['feature']}")
            if c.get("dev_only"):
                lines.append("- **DEV-ONLY:** the only implementation is a development stand-in and must never be treated as a production control.")
            for g in c.get("gaps") or []:
                lines.append(f"- {g}")
            for b in c.get("blocked") or []:
                lines.append(f"- **BLOCKED test:** {b}")
            lines.append("")
    lines += ["## Chain of evidence", "",
              "For each row: *Implementation* (code/DB object) → *Test* (named automated tests, listed per case in `SECURITY_TEST_REPORT.md`) → "
              "*Result* (from `evidence/junit.xml`) → *Audit event* (the registered `audit.action_registry` actions the control emits; the tests "
              "assert they are written where noted) → *Evidence* (machine-generated files under `evidence/`, digests in `evidence/MANIFEST.json`)."]
    (DOCS / "SECURITY_CONTROL_MATRIX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_test_report(cases: list[dict], evald: list[dict], defects: list[dict], meta: dict) -> None:
    docs = docstrings()
    by_fn: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for c in cases:
        by_fn[(c["file"], c["base"])].append(c)
    dmap = defaultdict(list)
    for d in defects:
        for t in d.get("tests", []):
            f, _, fn = t.partition("::")
            dmap[(f, fn)].append(d["id"])
            dmap[(f, "*")].append(d["id"])
    lines = ["# NsureGRC — Security Test Report (Phase 1 / v1.3-alpha)", "",
             f"*Generated {meta['generated']} from `evidence/junit.xml`. Environment: {meta['env']}.*", "",
             f"**Execution result: {meta['passed']} passed, {meta['failed']} failed, {meta['xfailed']} XFAIL, {meta['skipped']} skipped, "
             f"{meta['total']} total (pytest, {meta['duration']:.0f} s).** Tests run against a throw-away PostgreSQL database built by the real migrations, "
             "connecting as the real least-privilege runtime roles (never a superuser).", "",
             "**XFAIL is not a pass.** An XFAIL case is an executable specification of a NOT IMPLEMENTED control, or a *gap demo* that runs today "
             "against a dev-only stand-in and fails an assertion stating the production property. They are listed separately below and never "
             "counted in the passed column; if one unexpectedly passes the run fails (strict xfail).", "",
             "## Scope and limits", "",
             "- These are **automated regression tests written by the same team that built the controls**. They are not a penetration test, "
             "not an independent security assessment and not a certification. No penetration test has been performed.",
             "- WebAuthn is exercised with a software authenticator only. Time-dependent behaviour uses a controllable clock.",
             f"- CI: **{meta['ci']}** The suite was also run on a clean-room local PostgreSQL cluster (`docs/ci/LOCAL_REHEARSAL.md`), which is not CI.",
             f"- Independent security review: **{meta['review']}**",
             "- Tests marked BLOCKED in `BLOCKED_TESTS.md` could not be run and are **not** counted above.", ""]
    lines += ["## Defects found while verifying, and their remediation", "",
              "| ID | Defect | Severity | Found by | Remediation | Regression test(s) | Final status |", "|---|---|---|---|---|---|---|"]
    for d in defects:
        tests = "<br>".join(f"`{t}`" for t in d.get("tests", []))
        lines.append(f"| {d['id']} | {md_escape(d['title'])} | {md_escape(str(d['severity']))} | {md_escape(d['found_by'])} | "
                     f"{md_escape(d.get('fix', ''))} | {tests} | {d['status']}{' — ' + md_escape(d['note']) if d.get('note') else ''} |")
    lines += ["", "## Results by test", "",
              "Each row is one test function (parametrised cases are aggregated). *Remediation* names the defect, if any, that this test "
              "found or now guards. A test is `PASS` only if every case passed.", "",
              "| Test | Purpose | Cases | Result | Failure details | Remediation | Final status |", "|---|---|---|---|---|---|---|"]
    for (f, fn), cs in sorted(by_fn.items()):
        passed = sum(1 for x in cs if x["result"] == "passed")
        xf = [x for x in cs if x["result"] == "xfail"]
        fails = [x for x in cs if x["result"] not in {"passed", "xfail"}]
        purpose = docs.get((f, fn)) or humanize(fn)
        rem = ", ".join(sorted(set(dmap.get((f, fn), []))))
        if fails:
            status = "FAIL"
        elif xf and len(xf) == len(cs):
            status = "XFAIL — not a pass"
        elif xf:
            status = f"PARTIAL ({passed} pass, {len(xf)} XFAIL)"
        else:
            status = "PASS"
        det = md_escape("; ".join(f"{x['name']}: {x['detail']}" for x in fails)) if fails else "—"
        res = f"{passed}/{len(cs)} passed" + (f", {len(xf)} XFAIL" if xf else "")
        lines.append(f"| `{f.removeprefix('tests/')}::{fn}` | {md_escape(purpose)} | {len(cs)} | {res} | {det} | {rem or '—'} | **{status}** |")
    lines += ["", "## Pending specifications and gap demonstrations (XFAIL — NOT passes)", "",
              "| Control | Status | XFAIL cases | What exists | Plan |", "|---|---|---|---|---|"]
    for c in evald:
        if c.get("pending"):
            kinds = sorted({"gap demo (runs today, fails its assertion)" if "gap_demo" in h["base"] else "spec (stops at the absent interface)"
                            for h in c["pending"]})
            lines.append(f"| **{c['id']}** {md_escape(c['feature'])} | {c['status']} | {len(c['pending'])} | {'; '.join(kinds)} | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |")
    lines += ["", "A control changes from NOT IMPLEMENTED to implemented only when its code exists, its specs pass with only the `@pending` marker removed, and "
              "`docs/control_map.yaml` is updated; the generator exits non-zero while a mapped pending spec is not in the XFAIL state.", "",
              "## Coverage by required test category", "",
              "| Required category (Phase 1 brief) | Automated tests | Status |", "|---|---|---|"]
    cats = [
        ("cross-tenant read / write / delete", "tests/test_rls_tenant_isolation.py", ["cross_tenant"], "PASS"),
        ("cross-tenant search", "tests/test_cross_tenant_search.py", [""], "PASS"),
        ("cross-tenant download", "tests/test_evidence_download.py", ["cross_tenant", "database_row_pointing", "restricted", "support_sessions"], "PASS"),
        ("cross-tenant export / report / job / notification", None, [], "BLOCKED — those features do not exist (see BLOCKED_TESTS.md)"),
        ("BOLA / IDOR", "tests/test_authorization_api.py", ["idor", "tenant_identifier", "selecting_a_tenant"], "PASS"),
        ("missing tenant context", "tests/test_rls_tenant_isolation.py", ["no_context", "orm_guard"], "PASS"),
        ("invalid tenant context", "tests/test_authorization_api.py", ["tampered_session_tenant", "no_tenant_selected", "suspended_tenant"], "PASS"),
        ("RLS bypass attempts", "tests/test_rls_bypass_attempts.py", [""], "PASS"),
        ("unauthorized role changes / privilege escalation", "tests/test_authorization_api.py", ["admin_cannot", "nobody_can_modify", "system_roles", "platform_permissions"], "PASS"),
        ("MFA bypass", "tests/test_authentication.py", ["password_only_session", "pending_mfa", "mfa_endpoints_require", "wrong_totp"], "PASS"),
        ("MFA factor removal / lost-factor recovery abuse", "tests/test_lost_factor_recovery.py", [""], "PASS"),
        ("account lock-out / brute force (temporary baseline)", "tests/test_auth_backoff_policy.py", [""], "PASS"),
        ("session revocation", "tests/test_authentication.py", ["logout_revokes", "password_change_revokes", "membership_suspension", "idle_timeout", "absolute_timeout"], "PASS"),
        ("authorization default-deny", "tests/test_authorization_api.py", ["every_route", "every_non_public", "view_without_policy", "drf_defaults"], "PASS"),
        ("audit tampering", "tests/test_audit_integrity.py", ["tampered", "deleted", "reordered", "truncated", "full_chain", "forged_checkpoint"], "PASS"),
        ("audit checkpoint completeness / continuity (H-11)", "tests/test_audit_completeness.py", [""], "PASS"),
        ("audit UPDATE / DELETE / TRUNCATE attempts", "tests/test_audit_integrity.py", ["runtime_roles_cannot_mutate", "triggers_block", "chain_head"], "PASS"),
        ("audit-write failure", "tests/test_authorization_api.py", ["audit_append_fails", "denial_stays_a_denial"], "PASS"),
        ("SQL injection", "tests/test_input_and_exposure.py", ["sql_injection", "operator_api_inputs", "no_string_built_sql"], "PASS"),
        ("file upload abuse (type confusion, archive bombs, traversal)", "tests/test_evidence_lifecycle.py", [""], "PASS"),
        ("CSRF", "tests/test_authentication.py", ["csrf"], "PASS"),
        ("XSS (where applicable)", "tests/test_input_and_exposure.py", ["html_payloads", "reflected_input", "all_responses_are_json"], "PASS (API/header level; no UI exists)"),
        ("secret exposure", "tests/test_input_and_exposure.py", ["no_secret_ever", "secrets_are_not_logged", "api_responses_never", "repository_contains_no"], "PASS"),
        ("insecure configuration", "tests/test_config_security.py", [""], "PASS"),
    ]
    for label, f, match, note in cats:
        if f is None:
            lines.append(f"| {label} | 0 | **{note}** |")
            continue
        hits = [c for c in cases if c["file"] == f and any(m in c["base"] for m in match)]
        ok = hits and all(h["result"] == "passed" for h in hits)
        lines.append(f"| {label} | {len(hits)} | **{note if ok else 'FAIL'}** |")
    (DOCS / "SECURITY_TEST_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_blocked(evald: list[dict], gate: dict | None) -> None:
    lines = ["# Blocked and not-implemented tests (Phase 1)", "",
             f"*Generated {NOW}.* A BLOCKED test is one that **cannot run** until infrastructure or a feature exists. It is not counted as a pass.", "",
             "## BLOCKED — infrastructure or feature missing", "", "| ID | Test that cannot run | Blocked by | Related control | Becomes runnable when |", "|---|---|---|---|---|"]
    rows = [
        ("B-02", "cross-tenant EXPORT / REPORT / JOB / NOTIFICATION isolation (search and download are now tested: F-AUZ-005, F-DAT-004)", "no export, reporting, job or notification features exist", "F-AUZ-002", "those features are added (the endpoint-inventory test fails the build until the suite is extended)"),
        ("B-03", "context isolation behind a transaction-mode connection pooler", "no PgBouncer/pooler in the environment", "F-TEN-002", "a pooler is deployed in the test environment"),
        ("B-04", "throttling behaviour when Redis is down", "no Redis/cache infrastructure; throttling is DB-backed only", "F-ATH-002", "Redis is introduced (ADR requires degradation to DB counters, never to unthrottled)"),
        ("B-05", "DELIVERY of audit/security alerts to a real channel (pager, SIEM, e-mail); scheduling on real infrastructure; a separate-host watchdog", "hosting / monitoring stack not selected (O-4); alerts reach the log pipeline only", "F-AUD-007, F-ATH-002", "alert routing exists and is tested end to end"),
        ("B-06", "production audit anchoring (KMS signature, WORM sink) and key rotation (7 specs + 3 gap demos, all XFAIL)", "hosting / KMS / immutable storage not selected (open item O-4)", "F-AUD-006, F-DAT-006", "O-4 is decided and implemented"),
        ("B-07", "container image build and image vulnerability scan", "no container runtime on the Phase 1 workstation (Docker/Podman absent)", "F-GOV-005", "CI container job runs (defined in .github/workflows/ci.yml)"),
        ("B-08", "execution of the CI workflow on a runner", "no repository/CI service connected to this project yet; pushing project code externally needs the owner's decision", "F-GOV-005", "repository is pushed, Actions enabled, and docs/ci/CI_RUN_RECORD.yaml filled from the real run"),
        ("B-09", "network-restricted operator hostname / VPN allow-list", "hosting not selected (O-4)", "F-PLT-001", "deployment topology exists"),
        ("B-10", "Restricted-class content consent enforcement during support sessions", "no Restricted-class content endpoints exist", "F-PLT-002", "evidence / privacy modules exist"),
        ("B-11", "hardware-authenticator and cross-browser WebAuthn interoperability", "only a software authenticator is available", "F-ATH-006", "manual/hardware test pass is scheduled"),
        ("B-15", "real-mailbox delivery of recovery / factor-removal notifications", "no e-mail provider (O-7)", "F-ATH-015, F-ATH-014", "provider configured; delivery and authentication (SPF/DKIM/DMARC) tested"),
        ("B-16", "real private object store and malware-scanning engine for evidence", "hosting not selected (O-4); no engine selected (O-11)", "F-DAT-004, F-DAT-005", "store and engine chosen; the same tests run against them"),
        ("B-12", "dynamic application security testing (DAST) and penetration test", "not performed; requires a deployed environment and independent testers", "all", "environment + testers available"),
        ("B-13", "independent cryptographic / AppSec review of audit hash, checkpoints, AEAD helper, authentication/session/MFA", "no independent reviewer engaged; package prepared (docs/review/)", "F-GOV-004", "a reviewer's signed report is recorded in docs/review/REVIEW_RECORD.yaml and scripts/check_review_record.py reports COMPLETE"),
        ("B-14", "tests that need the real KMS/WORM provider (IAM key separation, non-exportability, retention lock, account separation)", "provider not selected (O-4)", "F-DAT-006, F-AUD-006", "provider chosen; interface conformance suite extended with integration tests"),
    ]
    lines += [f"| {a} | {b} | {c} | {d} | {e} |" for a, b, c, d, e in rows]
    lines += ["", "## NOT IMPLEMENTED — no code exists, so no test exists", "", "| Control | What is missing | Why |", "|---|---|---|"]
    for c in evald:
        if c["status"] == "NOT IMPLEMENTED":
            lines.append(f"| {c['id']} {md_escape(c['feature'])} | whole control | {md_escape('; '.join(c.get('gaps') or ['planned for a later phase']))} |")
    lines += ["", "## BLOCKED controls — the evidence is a human-supplied record that does not exist", "", "| Control | Status | What is missing |", "|---|---|---|"]
    for c in evald:
        if c.get("dynamic"):
            lines.append(f"| {c['id']} {md_escape(c['feature'])} | **{c['status']}** | {md_escape('; '.join(c.get('blocked') or []))} |")
    lines += ["", "## Partially implemented — gaps inside implemented controls", "", "| Control | Gap |", "|---|---|"]
    for c in evald:
        if c["status"] != "NOT IMPLEMENTED":
            for g in c.get("gaps") or []:
                lines.append(f"| {c['id']} | {md_escape(g)} |")
    if gate:
        lines += ["", "## Gate steps reported BLOCKED by `scripts/security_gate.py`", ""]
        lines += [f"- **{g['gate']}** — {g['detail']}" for g in gate["gates"] if g["status"] == "BLOCKED"] or ["- none"]
    (DOCS / "BLOCKED_TESTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def record_status_text() -> tuple[str, str]:
    import check_ci_record as ccr
    import check_review_record as crr

    ci = ccr.evaluate(load_yaml(DOCS / "ci" / "CI_RUN_RECORD.yaml") or {}, ccr.workflow_digest())
    scope_ids = [s["id"] for s in load_yaml(DOCS / "review" / "review_scope.yaml")["scopes"]]
    rv = crr.evaluate(load_yaml(DOCS / "review" / "REVIEW_RECORD.yaml") or {}, scope_ids, crr.current_manifest_digest())
    ci_txt = ("NOT RUN — the workflow has never executed on a CI runner (`docs/ci/CI_RUN_RECORD.yaml`)." if ci["state"] == "NOT_RUN"
              else f"{ci['state']} — {'; '.join(ci['problems']) or 'all required jobs green'} (`docs/ci/CI_RUN_RECORD.yaml`).")
    rv_txt = ("BLOCKED — no independent reviewer has reviewed any scope; the review package is prepared (`docs/review/`)." if rv["overall"] == "BLOCKED"
              else f"{rv['overall']} (`docs/review/REVIEW_RECORD.yaml`; per scope: "
                   + ", ".join(f"{k}={v['state']}" for k, v in rv["scopes"].items()) + ").")
    return ci_txt, rv_txt


def _gitleaks_paragraph() -> str:
    rep, meta = EV / "gitleaks_history.json", EV / "gitleaks_meta.json"
    if not rep.exists() or not meta.exists():
        return ("No secret scan of **git history** is recorded (`evidence/gitleaks_history.json` missing). CI runs `gitleaks` with full history "
                "once a repository exists; that CI job has not run.")
    findings = json.loads(rep.read_text(encoding="utf-8") or "[]")
    m = json.loads(meta.read_text(encoding="utf-8"))
    return (f"**Git history (local run, not CI):** `gitleaks {m['version']}` (release SHA-256 verified) scanned {m['commits']} commit(s) of the local repository "
            f"(HEAD `{m['head'][:12]}`) and the working tree: **{len(findings)} finding(s)**. The CI `secrets` job (full history on the runner) has **not** run.")


def write_scan_report(gate: dict | None, risks: dict) -> None:
    lines = ["# NsureGRC — Dependency & Security Scan Report (Phase 1)", "", f"*Generated {NOW} from `evidence/gate_summary.json` and the raw tool output in `evidence/`.*", ""]
    if not gate:
        lines.append("**No gate run is recorded (`evidence/gate_summary.json` missing). Run `uv run python scripts/security_gate.py`.**")
    else:
        lines += [f"Gate run: {gate['generated_at']} on {gate['platform']} (Python {gate['python']}). Totals: "
                  f"**{gate['totals']['PASS']} PASS · {gate['totals']['FAIL']} FAIL · {gate['totals']['BLOCKED']} BLOCKED**.", "",
                  "| Gate | Status | Detail | Raw evidence |", "|---|---|---|---|"]
        for g in gate["gates"]:
            lines.append(f"| {md_escape(g['gate'])} | **{g['status']}** | {md_escape(g['detail'])} | {', '.join(f'`{a}`' for a in g['artifacts']) or '—'} |")
    lines += ["", "## 1. Dependency vulnerabilities (SCA)", ""]
    for art, label in (("pip_audit_runtime.json", "Runtime (production) dependencies"), ("pip_audit.json", "All dependencies including dev tooling")):
        p = EV / art
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            v = [(x["name"], x["version"], y["id"], y.get("fix_versions"), (y.get("description") or "")[:140].replace("\n", " ")) for x in d["dependencies"] for y in x.get("vulns", [])]
            lines += [f"**{label}:** {len(d['dependencies'])} packages scanned with `pip-audit` (OSV/PyPI advisory data at run time); **{len(v)} known vulnerabilit{'y' if len(v) == 1 else 'ies'}**.", ""]
            for n, ver, i, fixes, desc in v:
                acc = risks.get(i)
                lines.append(f"- `{n} {ver}` — {i}; fixed in {fixes}. {desc}…  " + (f"**ACCEPTED RISK** ({acc['scope']}; review: {acc['review_by']})" if acc else "**UNRESOLVED**"))
            lines.append("")
    lines += ["## 2. Static analysis (SAST)", ""]
    bp = EV / "bandit.json"
    if bp.exists():
        d = json.loads(bp.read_text(encoding="utf-8"))
        t = d["metrics"]["_totals"]
        lines += [f"**Bandit:** {int(t['loc'])} lines of application code; {len(d['results'])} findings (HIGH {t.get('SEVERITY.HIGH', 0)}, MEDIUM {t.get('SEVERITY.MEDIUM', 0)}, LOW {t.get('SEVERITY.LOW', 0)}).",
                  "", "Triage of the findings raised during Phase 1 (all resolved before the final run):", "",
                  "| Finding | Count | Triage | Action |", "|---|---|---|---|",
                  "| B608 string-built SQL in migrations | 10 | False positive: f-strings interpolate module-level constants (search_path clause, signature lists); migrations are reviewed static SQL run only by `ngrc_owner` | Migrations excluded from bandit with written justification in `pyproject.toml`; still scanned by Semgrep and ruff `S608`; runtime code guarded by `test_no_string_built_sql_outside_the_reviewed_set` |",
                  "| B105 hard-coded password | 3 | False positive: enum/purpose names (`password_ok`, `password_reset`) and a DRF setting `None` | `# nosec B105` on the exact lines |",
                  "| B101 assert in production code | 2 | Valid: asserts vanish under `python -O` | Replaced with explicit `RuntimeError` (DEF-13) |", ""]
    sp = EV / "semgrep.json"
    if sp.exists():
        d = json.loads(sp.read_text(encoding="utf-8"))
        lines += [f"**Semgrep** (registry rule packs `p/python`, `p/django`, `p/security-audit`): {len(d.get('results', []))} findings over {len(d.get('paths', {}).get('scanned', []))} files.", ""]
    lines += ["Ruff with security-lint rules (`S`, `B`, `E`, `F`, `W`, `UP`, `I`): see `evidence/ruff.txt`. Rule `E501` (line length) is deliberately ignored as a formatting preference.", "",
              "## 3. Secret scanning", "",
              "`detect-secrets` with an audited baseline (`.secrets.baseline`). Sixteen candidates have been raised across local and CI runs and each was inspected by hand; **all sixteen are false positives**:", "",
              "| Location | Type | Triage |", "|---|---|---|",
              "| `ngrc/audit/service.py:9` | keyword | the word \"secrets\" in a docstring |",
              "| `ngrc/authn/abstract.py:37`, `ngrc/iam/models.py:101` | keyword | enum names `password_ok` / `password_reset` |",
              "| `tests/conftest.py:27` | keyword | deliberately fake test-only password (not in any real system) |",
              "| `tests/test_input_and_exposure.py:183,213,231,242` | keyword / entropy | fake strings used to prove redaction and non-disclosure |",
              "| `tests/test_support_access.py:353` | keyword | a settings key name (`operator_account_free_failures`) |",
              "| `tests/test_evidence_artifacts.py:121` | keyword | a dictionary key containing the word PASSWORD in an explanatory note |",
              "| `tests/test_pending_controls.py` / `tests/test_auth_backoff_policy.py` | keyword | deliberately wrong passwords used to provoke failures |",
              "| `tests/test_authentication.py:67,317,360,361` | keyword | deliberately wrong/throwaway passwords exercising the password-change and -reset API flows (`\"wrong-password-xyz\"`, `\"wrong-one-xxxxxx\"`, `\"An0ther-Long-Passphrase-77!\"`, `\"short\"`, `\"Brand-New-Passphrase-4242!\"`); flagged by the real GitHub Actions `secret scanning` job (run `40227089460`), not reproducible on this Windows workstation — the `detect-secrets` \"Secret Keyword\" plugin does not raise them locally for the same byte-identical file (confirmed with a line-ending-normalized clone at the same commit); triaged from the CI run's own reported hashes, not fabricated |", "",
              _gitleaks_paragraph(), "",
              "## 4. Container and IaC scanning", ""]
    for g in (gate or {"gates": []})["gates"]:
        if "trivy" in g["gate"] or "container" in g["gate"]:
            lines.append(f"- **{g['gate']}** — **{g['status']}**: {g['detail']}")
    lines += ["", "The Dockerfile (multi-stage, pinned tags, non-root uid 10001, no secrets, dev group excluded, locked install) was written but "
              "**the image has not been built**; image scanning is therefore **BLOCKED** locally and is performed by the CI `container` job. "
              "Trivy was obtained from the official release page and its SHA-256 matched the release's checksum file (this protects against corruption, "
              "not against a compromised release).", "",
              "## 5. Unresolved issues (honest list)", "",
              "1. `mcp 1.29.0` CVE-2026-59951 in dev tooling only — accepted risk, see `docs/accepted_risks.yaml`.",
              "2. Container image build/scan, **CI execution on a runner**, DAST and penetration testing have **not** been performed (BLOCKED / not done). "
              "The independent cryptographic/AppSec review is also **BLOCKED** (no reviewer).",
              "3. Actions are pinned by tag, and the base image by tag, not by commit SHA / digest.",
              "4. Open items (hosting/KMS/immutable storage, retention, RPO/RTO, legal review, framework licensing, crypto review, AppSec review) remain open — see `docs/OPEN_ITEMS.md`.",
              "5. Defect DEF-15 (failure-triggered lock-out) is **mitigated-temporary** by owner decision D-P1-001 (progressive back-off + detection, stricter operator parameters); it closes only when the lost-factor recovery mechanism (F-ATH-015) has been independently reviewed — see `docs/defects_found.yaml`.",
              "", "## 6. CI and independent-review status (records, not claims)", ""]
    ci_txt, review_txt = record_status_text()
    lines += [f"- **CI:** {ci_txt}", f"- **Independent review:** {review_txt}",
              "- `actionlint` (checksum-verified binary) lint of `.github/workflows/ci.yml`: see `evidence/ci_rehearsal/actionlint.txt` — a syntax/semantic check of the workflow file, **not** a run.",
              "- Local clean-room rehearsal of the CI command lines: `docs/ci/LOCAL_REHEARSAL.md` — **not** CI."]
    (DOCS / "SECURITY_SCAN_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------------------------------------ traceability CSV
def update_traceability(evald: list[dict]) -> None:
    meta_ci = record_status_text()[0]
    rows = list(csv.DictReader(TRACE.open(encoding="utf-8")))
    cols = list(rows[0].keys())
    for extra in ("open_gaps", "result_ref", "pending_specs"):
        if extra not in cols:
            cols.append(extra)
    byid = {r["feature_id"]: r for r in rows}
    for c in evald:
        r = byid.get(c["id"])
        if r is None:
            r = {k: "" for k in cols}
            r.update({"feature_id": c["id"], "feature": c["feature"], "phase": "P0-Ph1", "security_requirement": c["requirement"],
                      "source": c.get("source", ""), "owner": "Platform Security"})
            rows.append(r)
            byid[c["id"]] = r
        tests = sorted({f"{h['file'].removeprefix('tests/')}::{h['base']}" for h in c["selected"]})
        r["implementation"] = "; ".join(c.get("implementation") or []) or "—"
        r["test_ids"] = "; ".join(tests) if tests else "—"
        r["audit_events"] = ", ".join(c.get("audit_events") or []) or "—"
        r["evidence"] = "; ".join(c.get("evidence") or []) or "—"
        r["standards_indicative"] = (c.get("standards") or r.get("standards_indicative", "")) + " (indicative mapping, not a compliance claim)" if c.get("standards") else r.get("standards_indicative", "")
        r["status"] = {"TESTED — PASS": "Tested", "IMPLEMENTED — UNTESTED": "Implemented", "NOT IMPLEMENTED": "Designed",
                       "BLOCKED": "Blocked"}.get(c["status"], "Implemented")
        r["last_reviewed"] = NOW
        gaps = list(c.get("gaps") or [])
        if c.get("dev_only"):
            gaps.insert(0, "DEV-ONLY stand-in")
        r["open_gaps"] = " | ".join(gaps) or "—"
        ci_note = "local run; CI not executed" if "NOT RUN" in meta_ci else "see CI record"
        r["result_ref"] = (f"{c['passed']}/{c['total']} cases passed in evidence/junit.xml ({NOW}); {ci_note}" if c["total"]
                           else "no passing tests (NOT IMPLEMENTED / BLOCKED)")
        r["pending_specs"] = "; ".join(sorted({f"{h['file'].removeprefix('tests/')}::{h['base']}" for h in c.get("pending") or []})) or "—"
    with TRACE.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})


def main() -> int:
    cmap = load_yaml(DOCS / "control_map.yaml")["controls"]
    cases = read_junit()
    defects = load_yaml(DOCS / "defects_found.yaml")["defects"]
    risks = {r["id"]: r for r in (load_yaml(DOCS / "accepted_risks.yaml") or {}).get("accepted", [])}
    gate = json.loads((EV / "gate_summary.json").read_text(encoding="utf-8")) if (EV / "gate_summary.json").exists() else None
    root = ET.parse(EV / "junit.xml").getroot()  # noqa: S314
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    ci_txt, review_txt = record_status_text()
    meta = {"generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "total": len(cases),
            "passed": sum(1 for c in cases if c["result"] == "passed"), "failed": sum(1 for c in cases if c["result"] in {"failed", "error"}),
            "xfailed": sum(1 for c in cases if c["result"] == "xfail"),
            "skipped": sum(1 for c in cases if c["result"] == "skipped"), "duration": float(suite.get("time", 0)) if suite is not None else 0.0,
            "env": "Windows 11 workstation, Python 3.12 (uv), PostgreSQL 16 in WSL2 Ubuntu", "ci": ci_txt, "review": review_txt}
    evald, errors = evaluate(cmap, cases)
    mapped = {(h["file"], h["name"]) for c in evald for h in [*c["selected"], *c.get("pending", [])]}
    unmapped = [c for c in cases if (c["file"], c["name"]) not in mapped]
    write_matrix(evald, meta)
    write_test_report(cases, evald, defects, meta)
    write_blocked(evald, gate)
    write_scan_report(gate, risks)
    update_traceability(evald)
    print(f"controls: {len(evald)}; tests: {meta['total']} (passed {meta['passed']}, failed {meta['failed']}); "
          f"tests not mapped to any control: {len(unmapped)}")
    for e in errors:
        print("ERROR:", e)
    return 1 if errors or meta["failed"] or any(c["status"].startswith("FAIL") for c in evald) else 0


if __name__ == "__main__":
    sys.exit(main())
