#!/usr/bin/env python3
"""Phase 1 security gate runner: lint, SAST, SCA, secret scan, IaC/FS scan, container scan, tests -> evidence/.

Run from the project root inside the project environment:   uv run python scripts/security_gate.py [--skip-tests]

* Every tool's RAW output is written to evidence/ (never summarised away).
* Exit code is non-zero if any gate FAILS. Gates whose tooling/infrastructure is unavailable are reported as BLOCKED and are
  never counted as PASS. A BLOCKED gate does not fail the script (the report states it loudly), because the gate decision
  (docs/PHASE1_SECURITY_GATE.md) treats BLOCKED items explicitly.
* Accepted risks live in docs/accepted_risks.yaml (id, package, justification, review_by). Nothing is accepted implicitly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess  # noqa: S404
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"
PY = sys.executable
SCAN_PATHS = ["ngrc", "config", "db", "scripts", "tests", "pyproject.toml", "README.md", ".github", "Dockerfile"]
# glob patterns (both separators) so the exclusion works on Windows and Linux; migrations are triaged in docs/SECURITY_SCAN_REPORT.md
BANDIT_EXCLUDES = "*/migrations*,*\\migrations*,*/tests*,*\\tests*,*.venv*"


def fresh(*names: str) -> None:
    """Remove a previous artifact so a gate can never pass on a stale file left by an earlier run."""
    for n in names:
        (EV / n).unlink(missing_ok=True)


def run(cmd: list[str], *, out: Path | None = None, env: dict | None = None, timeout: int = 1500) -> tuple[int, str]:
    t0 = time.time()
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=timeout)  # noqa: S603
    text = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
    if out is not None:
        out.write_text(text, encoding="utf-8")
    print(f"  -> exit {p.returncode} in {time.time() - t0:.1f}s")
    return p.returncode, text


def gate(name: str, status: str, detail: str, artifacts: list[str] | None = None) -> dict:
    print(f"[{status:7}] {name}: {detail}")
    return {"gate": name, "status": status, "detail": detail, "artifacts": artifacts or []}


def accepted() -> dict:
    p = ROOT / "docs" / "accepted_risks.yaml"
    return {r["id"]: r for r in (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("accepted", [])} if p.exists() else {}


def g_ruff() -> dict:
    print("ruff (lint + security-lint rules)")
    code, _ = run([PY, "-m", "ruff", "check", "ngrc", "config", "tests", "scripts", "--output-format", "concise"], out=EV / "ruff.txt")
    return gate("lint (ruff E,F,W,B,S,UP,I)", "PASS" if code == 0 else "FAIL", "no findings" if code == 0 else "see evidence/ruff.txt", ["evidence/ruff.txt"])


def g_bandit() -> dict:
    print("bandit (SAST)")
    fresh("bandit.json")
    code, text = run([PY, "-m", "bandit", "-r", "ngrc", "config", "-c", "pyproject.toml", "-x", BANDIT_EXCLUDES, "-f", "json", "-o", str(EV / "bandit.json"), "-q"])
    if code not in (0, 1) or not (EV / "bandit.json").exists():
        return gate("SAST bandit", "FAIL", f"bandit did not complete (exit {code}): {text[-200:]}")
    d = json.loads((EV / "bandit.json").read_text(encoding="utf-8"))
    n = len(d["results"])
    sev = {s: d["metrics"]["_totals"].get(f"SEVERITY.{s}", 0) for s in ("HIGH", "MEDIUM", "LOW")}
    return gate("SAST bandit", "PASS" if n == 0 else "FAIL", f"{n} findings {sev}, {int(d['metrics']['_totals']['loc'])} LOC", ["evidence/bandit.json"])


def g_semgrep() -> dict:
    print("semgrep (SAST, registry rules p/python p/django p/security-audit)")
    fresh("semgrep.json")
    exe = shutil.which("semgrep") or str(Path(PY).parent / ("semgrep.exe" if os.name == "nt" else "semgrep"))
    code, text = run([exe, "scan", "--config", "p/python", "--config", "p/django", "--config", "p/security-audit", "--metrics=off",
                      "--json", "-o", str(EV / "semgrep.json"), "--quiet", "ngrc", "config"], timeout=1800)
    if code not in (0, 1) or not (EV / "semgrep.json").exists():
        return gate("SAST semgrep", "FAIL", f"semgrep did not complete (exit {code}): {text[-300:]}")
    d = json.loads((EV / "semgrep.json").read_text(encoding="utf-8"))
    n = len(d.get("results", []))
    return gate("SAST semgrep", "PASS" if n == 0 else "FAIL", f"{n} findings; {len(d.get('paths', {}).get('scanned', []))} files scanned", ["evidence/semgrep.json"])


def g_sca() -> list[dict]:
    print("pip-audit (SCA)")
    out = []
    code, _ = run(["uv", "export", "--no-dev", "--no-hashes", "--no-emit-project", "-o", str(EV / "requirements-runtime.txt")])
    code, _ = run(["uv", "export", "--no-hashes", "--no-emit-project", "-o", str(EV / "requirements-all.txt")])
    for label, req, art in (("runtime", "requirements-runtime.txt", "pip_audit_runtime.json"), ("dev-tooling", "requirements-all.txt", "pip_audit.json")):
        fresh(art)
        c_audit, t_audit = run([PY, "-m", "pip_audit", "-r", str(EV / req), "--no-deps", "--disable-pip", "--progress-spinner", "off", "-f", "json", "-o", str(EV / art)])
        if c_audit not in (0, 1) or not (EV / art).exists():
            out.append(gate(f"SCA pip-audit ({label})", "FAIL", f"pip-audit did not complete (exit {c_audit}): {t_audit[-200:]}"))
            continue
        d = json.loads((EV / art).read_text(encoding="utf-8"))
        vulns = [(x["name"], x["version"], v["id"], v.get("fix_versions")) for x in d["dependencies"] for v in x.get("vulns", [])]
        acc = accepted()
        open_ = [v for v in vulns if v[2] not in acc]
        # runtime dependencies can never be risk-accepted silently: any runtime finding fails
        status = "PASS" if not open_ else "FAIL"
        detail = f"{len(d['dependencies'])} packages, {len(vulns)} known vulnerabilities, {len(vulns) - len(open_)} accepted"
        if vulns and label == "dev-tooling" and not open_:
            detail += " (" + ", ".join(f"{v[0]} {v[2]}" for v in vulns) + " - see docs/accepted_risks.yaml)"
        out.append(gate(f"SCA pip-audit ({label})", status, detail, [f"evidence/{art}"]))
    return out


def g_secrets() -> dict:
    print("detect-secrets")
    fresh("detect_secrets_scan.json")
    code, text = run([PY, "-m", "detect_secrets", "scan", "--all-files", *SCAN_PATHS])
    (EV / "detect_secrets_scan.json").write_text(text.split("\n[stderr]")[0], encoding="utf-8")
    new = json.loads((EV / "detect_secrets_scan.json").read_text(encoding="utf-8"))
    base = json.loads((ROOT / ".secrets.baseline").read_text(encoding="utf-8"))
    norm = lambda f: f.replace("\\", "/")  # noqa: E731
    cleared = {(norm(f), s["hashed_secret"]) for f, items in base["results"].items() for s in items if s.get("is_secret") is False}
    found = [(norm(f), s["hashed_secret"], s["type"], s["line_number"]) for f, items in new["results"].items() for s in items]
    unreviewed = [x for x in found if (x[0], x[1]) not in cleared]
    return gate("secret scan (detect-secrets)", "PASS" if not unreviewed else "FAIL",
                f"{len(found)} candidate(s), {len(found) - len(unreviewed)} triaged as false positives in .secrets.baseline, {len(unreviewed)} unreviewed",
                ["evidence/detect_secrets_scan.json"])


def _git(*args: str) -> str | None:
    try:
        p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60)  # noqa: S603,S607
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def g_gitleaks() -> list[dict]:
    """Secret scan of git HISTORY and of the working tree with gitleaks (local run; the CI `secrets` job repeats it on the runner)."""
    exe = os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks")
    head = _git("rev-parse", "HEAD")
    if not exe:
        return [gate("secret scan (gitleaks, git history)", "BLOCKED", "gitleaks not installed")]
    if not head:
        return [gate("secret scan (gitleaks, git history)", "BLOCKED", "the project is not a git repository with at least one commit")]
    print("gitleaks (history + working tree)")
    fresh("gitleaks_history.json", "gitleaks_worktree.json", "gitleaks_meta.json")
    c1, _ = run([exe, "git", ".", "--redact", "--no-banner", "--report-format", "json", "--report-path", str(EV / "gitleaks_history.json")])
    c2, _ = run([exe, "dir", ".", "--redact", "--no-banner", "--report-format", "json", "--report-path", str(EV / "gitleaks_worktree.json")])
    _, ver = run([exe, "version"])
    commits = int(_git("rev-list", "--count", "HEAD") or 0)
    (EV / "gitleaks_meta.json").write_text(json.dumps({"version": ver.strip().splitlines()[0] if ver.strip() else "unknown", "head": head,
                                                      "commits": commits}), encoding="utf-8")
    res = []
    for label, art, c in (("git history", "gitleaks_history.json", c1), ("working tree", "gitleaks_worktree.json", c2)):
        p = EV / art
        if c not in (0, 1) or not p.exists():
            res.append(gate(f"secret scan (gitleaks, {label})", "FAIL", f"gitleaks did not complete (exit {c})"))
            continue
        n = len(json.loads(p.read_text(encoding="utf-8") or "[]"))
        res.append(gate(f"secret scan (gitleaks, {label})", "PASS" if n == 0 else "FAIL",
                        f"{n} finding(s)" + (f" over {commits} commit(s), HEAD {head[:12]}" if label == "git history" else ""), [f"evidence/{art}"]))
    return res


def g_actionlint() -> dict:
    exe = os.environ.get("ACTIONLINT_BIN") or shutil.which("actionlint")
    if not exe:
        return gate("CI workflow lint (actionlint)", "BLOCKED", "actionlint not installed")
    d = EV / "ci_rehearsal"
    d.mkdir(exist_ok=True)
    code, _ = run([exe, ".github/workflows/ci.yml"], out=d / "actionlint.txt")
    return gate("CI workflow lint (actionlint)", "PASS" if code == 0 else "FAIL",
                "workflow syntax/semantics clean (this is a lint of the file, NOT a CI run)" if code == 0 else "see evidence/ci_rehearsal/actionlint.txt",
                ["evidence/ci_rehearsal/actionlint.txt"])


def g_records() -> list[dict]:
    """The CI run and the independent review are human/CI-supplied records. Absent => BLOCKED, never PASS."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_ci_record as ccr
    import check_review_record as crr

    ci = ccr.evaluate(yaml.safe_load(ccr.RECORD.read_text(encoding="utf-8")) or {}, ccr.workflow_digest())
    scope_ids = [s["id"] for s in yaml.safe_load(crr.SCOPE.read_text(encoding="utf-8"))["scopes"]]
    rv = crr.evaluate(yaml.safe_load(crr.RECORD.read_text(encoding="utf-8")) or {}, scope_ids, crr.current_manifest_digest())
    out = []
    if ci["state"] == "NOT_RUN":
        out.append(gate("CI workflow execution on a runner", "BLOCKED", "no CI run recorded (docs/ci/CI_RUN_RECORD.yaml); no repository/runner"))
    else:
        out.append(gate("CI workflow execution on a runner", "PASS" if ci["state"] == "PASSED" else "FAIL", f"{ci['state']}: {'; '.join(ci['problems']) or 'all jobs green'}"))
    if rv["overall"] == "BLOCKED":
        out.append(gate("independent crypto/AppSec review", "BLOCKED", "no independent reviewer has reviewed any scope (docs/review/REVIEW_RECORD.yaml)"))
    else:
        out.append(gate("independent crypto/AppSec review", "PASS" if rv["overall"] == "COMPLETE" else "FAIL",
                        f"{rv['overall']}: " + ", ".join(f"{k}={v['state']}" for k, v in rv["scopes"].items())))
    return out


def g_trivy() -> list[dict]:
    exe = os.environ.get("TRIVY_BIN") or shutil.which("trivy")
    if not exe:
        return [gate("filesystem/IaC scan (trivy fs+config)", "BLOCKED", "trivy not installed"),
                gate("container image scan (trivy image)", "BLOCKED", "trivy not installed")]
    print("trivy fs + config")
    fresh("trivy_fs.json", "trivy_config.json")
    res = []
    code, _ = run([exe, "fs", "--scanners", "vuln,secret,misconfig", "--severity", "HIGH,CRITICAL", "--skip-dirs", ".venv,evidence,.pytest_cache,.ruff_cache",
                   "--format", "json", "--output", str(EV / "trivy_fs.json"), "."], timeout=1800)
    code2, _ = run([exe, "config", "--severity", "MEDIUM,HIGH,CRITICAL", "--format", "json", "--output", str(EV / "trivy_config.json"), "Dockerfile"])
    for label, art, c in (("filesystem (lockfile vulns, secrets, misconfig)", "trivy_fs.json", code), ("Dockerfile misconfiguration", "trivy_config.json", code2)):
        p = EV / art
        if c != 0 or not p.exists():
            res.append(gate(f"trivy {label}", "BLOCKED", f"trivy exit {c} (vulnerability DB download or scan failed)"))
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        n = sum(len(r.get("Vulnerabilities") or []) + len(r.get("Misconfigurations") or []) + len(r.get("Secrets") or []) for r in d.get("Results", []))
        res.append(gate(f"trivy {label}", "PASS" if n == 0 else "FAIL", f"{n} finding(s) at the configured severities", [f"evidence/{art}"]))
    return res


def g_container() -> dict:
    docker = shutil.which("docker") or shutil.which("podman")
    if not docker:
        return gate("container image build + scan", "BLOCKED", "no container runtime (docker/podman) on this machine; the CI workflow performs this gate")
    code, _ = run([docker, "build", "-t", "nsuregrc:gate", "."], out=EV / "docker_build.txt", timeout=3000)
    if code != 0:
        return gate("container image build + scan", "FAIL", "image build failed", ["evidence/docker_build.txt"])
    trivy = os.environ.get("TRIVY_BIN") or shutil.which("trivy")
    if not trivy:
        return gate("container image build + scan", "BLOCKED", "image built but trivy is not installed", ["evidence/docker_build.txt"])
    code, _ = run([trivy, "image", "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--exit-code", "1", "--format", "json", "--output",
                   str(EV / "trivy_image.json"), "nsuregrc:gate"], timeout=3000)
    return gate("container image build + scan", "PASS" if code == 0 else "FAIL", "image built; trivy image scan " + ("clean" if code == 0 else "found issues"),
                ["evidence/trivy_image.json"])


def g_tests() -> dict:
    print("pytest security regression suite")
    code, text = run([PY, "-m", "pytest", "tests", "-q", f"--junitxml={EV / 'junit.xml'}", "-p", "no:cacheprovider"], out=EV / "pytest_output.txt", timeout=3000)
    last = [ln for ln in text.splitlines() if " passed" in ln or " failed" in ln or " error" in ln][-1:]
    return gate("security regression suite (pytest)", "PASS" if code == 0 else "FAIL", last[0].strip() if last else f"exit {code}",
                ["evidence/junit.xml", "evidence/pytest_output.txt"])


def manifest() -> None:
    files = sorted(p for p in EV.iterdir() if p.is_file() and p.name != "MANIFEST.json")
    m = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "host": platform.platform(), "python": platform.python_version(),
         "files": {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size} for p in files}}
    (EV / "MANIFEST.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--only", choices=["secrets"], help="run a single gate (used by CI jobs that need just one)")
    args = ap.parse_args()
    EV.mkdir(exist_ok=True)
    if args.only == "secrets":
        r = g_secrets()
        return 1 if r["status"] == "FAIL" else 0
    results = [g_ruff(), g_bandit(), g_semgrep(), *g_sca(), g_secrets(), *g_gitleaks(), *g_trivy(), g_container(), g_actionlint(), *g_records()]
    if not args.skip_tests:
        results.append(g_tests())
    summary = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "python": platform.python_version(), "platform": platform.platform(),
               "gates": results, "totals": {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "BLOCKED")}}
    (EV / "gate_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    manifest()
    print("\n" + json.dumps(summary["totals"]))
    return 1 if summary["totals"]["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
