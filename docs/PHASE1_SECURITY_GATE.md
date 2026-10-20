# NsureGRC — Phase 1 Security Gate (v1.3-alpha, Secure Foundation)

**Date:** 2026-10-20 · **Scope:** Phase 1 steps 1–29 of the approved brief (C-1…C-6 approved) · **Status of the code:** development alpha, not for production.

## DECISION: **CONDITIONAL PASS**

### Why not PASS
The Phase 0 exit gate (`00_CONTROL/PHASE0/00_INDEX.md` §5) requires two things that are **not satisfied**:
1. *"all Phase 0 testing requirements … pass **in CI**"* — the suite passes locally (370/370), but the CI workflow has **never run on a runner** and the container image has **never been built or scanned** (no container runtime here; `BLOCKED_TESTS.md` B-07/B-08).
2. *"crypto/AppSec review (O-10) complete"* — **not done.** The audit hash construction, the AEAD helper and the authentication flows were written and tested by the same engineers; no independent review has occurred.

In addition, several Phase 0 testing requirements are for features that do not exist yet (e.g. email-change flow, lost-factor cooling-off, personal access tokens, purge procedure, restore drill) — they are listed as NOT IMPLEMENTED, not skipped silently.

### Why not FAIL
- Every automated gate that can run on this machine passed on the final run, with no failing test and no unresolved scanner finding at the configured severities (details below).
- The verification itself found **13 real defects** (5 rated high by the engineers' own assessment, including an audit-forgery path for the migration identity, an unenforced step-up and an MFA-downgrade path) — all fixed with regression tests (`defects_found.yaml`). A suite that finds and pins defects is evidence the tests have teeth.
- Nothing in the foundation is presented as more than it is: dev-only stand-ins are labelled, blocked from production start-up, and listed; gaps are shown on the control rows.

### What a CONDITIONAL PASS permits and does not permit
- **Permits:** the team may review this report and decide to proceed to Phase 2 planning **once the Phase-2 conditions below are cleared or explicitly waived by the approver.**
- **Does not permit:** production use, real customer data, or any statement of audit-readiness, certification or standards compliance. Standards columns in the matrix are *indicative mappings*, not claims.
- **Phase 2 has not been started.**

## Evidence (final run, 2026-10-20, Windows 11 workstation, Python 3.12.13, PostgreSQL 16.15)

| Gate | Result | Source |
|---|---|---|
| Security regression suite | **370 passed, 0 failed, 0 skipped** (real PostgreSQL, real runtime roles, throw-away DB) | `evidence/junit.xml` |
| Lint with security rules (ruff) | PASS, 0 findings | `evidence/ruff.txt` |
| SAST — bandit | PASS, 0 findings (3,968 LOC; migration B608 false positives excluded with written justification) | `evidence/bandit.json` |
| SAST — semgrep (p/python, p/django, p/security-audit) | PASS, 0 findings, 168 files | `evidence/semgrep.json` |
| SCA — runtime dependencies (20 pkgs) | PASS, **0** known vulnerabilities | `evidence/pip_audit_runtime.json` |
| SCA — dev tooling (109 pkgs) | 1 advisory (`mcp` via `semgrep`), **accepted risk**, not in runtime | `docs/accepted_risks.yaml` |
| Secret scan (detect-secrets + audited baseline) | PASS; 11 candidates, all inspected, all false positives | `evidence/detect_secrets_scan.json` |
| Trivy filesystem (lockfile vulns/secrets/misconfig) + Dockerfile config | PASS, 0 findings at HIGH/CRITICAL (fs) and MEDIUM+ (config) | `evidence/trivy_*.json` |
| **Container image build + scan** | **BLOCKED** (no Docker/Podman) | `gate_summary.json` |
| **CI workflow execution** | **NOT RUN** (no repository/runner) | `.github/workflows/ci.yml` |
| Controls | 42 in the matrix: **35 TESTED — PASS** (10 with no recorded gap; 25 carry documented gaps, dev-only flags or blocked tests), **7 NOT IMPLEMENTED** | `SECURITY_CONTROL_MATRIX.md` |

Evidence integrity: `evidence/MANIFEST.json` lists SHA-256 digests of the artifacts. It protects against accidental change, **not** against a malicious rewrite (it is not signed or held off-host).

## Phase 1 steps — actual status

| # | Step | Status |
|---|---|---|
| 1 | Repository / project structure | Done |
| 2 | Secure development configuration | Done, tested (`test_config_security.py`); prod start refuses dev-only components |
| 3 | CI/CD security gates | **Defined, not executed on a runner.** Equivalent gates executed locally by `scripts/security_gate.py` |
| 4 | Dependency / SCA | Executed locally (pip-audit, Trivy fs) — PASS |
| 5 | SAST | Executed locally (bandit, semgrep, ruff-S) — PASS |
| 6 | Secret scanning | Executed locally on the working tree — PASS. **Git-history scan not possible** (not a git repo yet) |
| 7 | Container scanning | **BLOCKED** for the image; Dockerfile/IaC scan executed — PASS |
| 8 | Secure Docker configuration | Written (multi-stage, non-root, locked, no dev group, no secrets). **Never built; hadolint not run** |
| 9 | Django/DRF security baseline | Done, tested |
| 10 | PostgreSQL setup | Done (roles, grants, bootstrap SQL), tested |
| 11 | `ngrc_app` / `ngrc_auth` separation (C-5) | Done, tested (exact privilege matrix) |
| 12 | Table classification | Done: manifest + pg_catalog checks |
| 13 | Tenant model | Done (registry, provisioning). Suspend/offboard API NOT IMPLEMENTED |
| 14 | PostgreSQL RLS | Done, tested incl. hostile-SQL bypass attempts |
| 15 | Transaction-scoped tenant context | Done, tested. Behind a pooler: BLOCKED |
| 16 | Fail-closed tenant behaviour | Done, tested |
| 17 | Authorization policy resolver | Done, tested |
| 18 | Default-deny route registry | Done, tested (every route, every method, anonymous) |
| 19 | Authentication | Done, tested. E-mail change, factor removal, lost-factor recovery NOT IMPLEMENTED |
| 20 | MFA (C-1) | Done, tested with a software authenticator only |
| 21 | Session management | Done, tested. Self-service session listing/revocation NOT IMPLEMENTED |
| 22 | Platform roles (C-2) | Done, tested |
| 23 | Tenant roles | Done, tested (no-escalation rules) |
| 24 | Support / break-glass (C-3) | Done, tested. Owner e-mail notification and post-incident review record NOT IMPLEMENTED |
| 25 | Audit event service | Done, tested |
| 26 | Append-only audit enforcement | Done, tested (grants + triggers + role separation) |
| 27 | Hash chaining / checkpoints (C-4) | Done, tested. **Signer and sink are DEV-ONLY**; production anchoring NOT IMPLEMENTED (O-4) |
| 28 | Security event model | Done: registered actions, writer-role and detail-key allow-list enforced in the DB |
| 29 | Security regression tests | 370 tests passing |

## Conditions

### Before Phase 2 starts (recommended gate to clear or explicitly waive)
| # | Condition | Why it matters |
|---|---|---|
| P2-1 | Push the repository and **run the CI workflow green**, including the container build, Trivy image scan, Dockerfile lint and the gitleaks history scan | Closes BLOCKED B-07/B-08/history-scan; the Phase 0 exit gate says "in CI" |
| P2-2 | **Independent crypto/AppSec review** (O-10) of: audit hash/chain/checkpoint construction, envelope-encryption helper, authentication & session design, support-grant state machine | Home-written constructions on standard primitives are the highest residual risk; tests cannot replace review |
| P2-3 | Decide whether Phase 2 depends on the NOT IMPLEMENTED items H-03 (scheduled audit verification), H-05 (factor removal / recovery / session self-service), H-06 (tenant lifecycle) and schedule them | These are gaps in Phase 1 scope, not hidden |
| P2-4 | Tighten the support-grant trigger to match the application rule (H-01) via a new migration | DB should be as strict as the app (defence in depth) |

### Before any production use or real data
Resolve or decide, **without invented values**: O-2 retention, O-3 RPO/RTO, **O-4 hosting/KMS/WORM + production audit anchoring + key rotation**, O-5 staffing for two-person rules, O-7 e-mail authentication, O-8 legal review + framework licensing, O-12 breach-corpus blocklist; plus H-02 (re-apply the audit-owner grant on any existing cluster), H-04 (supply-chain pinning, SBOM, signing), H-07 (Python series), H-09 (DAST + independent penetration test).
`config.settings.prod` **cannot start** today by design (dev-only key provider and audit signer are the only ones available).

## Limits of this verification (read before relying on it)
- Tests are automated regression tests written by the implementers. **No penetration test, DAST, or independent assessment has been performed.**
- Everything ran on one workstation; the CI workflow is unproven. The container image is unbuilt.
- WebAuthn was exercised with a software authenticator only; time-based behaviour uses a controllable clock.
- XSS was assessed at the API/header level only (no UI exists).
- Hash-chain and checkpoint verification were demonstrated against an attacker with schema-owner rights; a database **superuser** can still alter data, and detection then depends on the externally exported checkpoints — whose production sink does not exist yet.
- Standards mappings (ISO 27001:2022, SOC 2, OWASP ASVS/API Top 10, NIST 800-63B) are indicative and unvalidated.

## Deliverables (all under `03_APP/nsuregrc/docs/` unless stated)
1. Architecture summary — `ARCHITECTURE_SUMMARY.md`
2. Security control matrix — `SECURITY_CONTROL_MATRIX.md` (generated from the real run)
3. Security test report — `SECURITY_TEST_REPORT.md` (every test, result, defects and remediation)
4. Dependency / security report — `SECURITY_SCAN_REPORT.md`, `DEPENDENCIES.md`, `accepted_risks.yaml`
5. Traceability update — `00_CONTROL/TRACEABILITY/feature_control_map.csv` (regenerated; previous version archived in `99_ARCHIVE/`)
6. This gate report; supporting: `BLOCKED_TESTS.md`, `OPEN_ITEMS.md`, `OPERATIONS_NOTES.md`, `defects_found.yaml`

## Reproduce
```
uv run python scripts/security_gate.py     # all gates -> evidence/ (needs PostgreSQL roles; see OPERATIONS_NOTES.md)
uv run python scripts/build_reports.py     # regenerates the matrix, reports and traceability CSV from that run
```
