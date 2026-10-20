# NsureGRC — Phase 1 Security Gate (v1.3-alpha, Secure Foundation) — revision after the P2 conditions

**Date:** 2026-10-21 · **Scope:** Phase 1 steps 1–29 + the four conditions P2-1…P2-4 set by the project owner · **Code status:** development alpha, not for production.
**Phase 2 has NOT been started and is not authorised by this report.**

## DECISION: **CONDITIONAL PASS** (unchanged)

The result does not become PASS: two of the four conditions cannot be satisfied from this workstation and are **BLOCKED**, and the controls that P2-3 asked to be planned and specified are still **not implemented**.
It does not become FAIL: every gate that can run here is green, nothing regressed, and the one condition that could be fully closed (P2-4) is closed with proof.

### The four conditions

| # | Condition | Status | What exists | What is still missing |
|---|---|---|---|---|
| **P2-1** | Run the real CI workflow on a real runner | **BLOCKED** | Workflow `ci.yml` lint-clean (actionlint); local git repo (2+ local commits, **nothing pushed**); clean-room rehearsal of the CI command lines on a fresh PostgreSQL cluster using the real `ci_bootstrap.sh` (`ci/LOCAL_REHEARSAL.md`); runbook (`ci/CI_RUNBOOK.md`); run record `ci/CI_RUN_RECORD.yaml` = **NOT_RUN** and a checker that refuses to call CI passed without a real run, all five jobs (incl. Docker-capable `container`), and an unchanged workflow | A repository and runner. No `gh`, remote or credentials exist here, and pushing project code externally is the owner's decision. The container image has still never been built or scanned. **The rehearsal is not CI** |
| **P2-2** | Independent review of audit hash, audit integrity/checkpoints, AEAD helper, authentication/session/MFA | **BLOCKED** | Review package (`review/INDEPENDENT_REVIEW_PACKAGE.md`, `review_scope.yaml`, 44 files with SHA-256 manifest and zip), review record `review/REVIEW_RECORD.yaml` with **no reviewer, no findings, no disposition** (none exist) and a checker that rejects implementers, AI tools, undated/unsigned reviews and reviews of different code | **An independent human reviewer.** Reviewer, scope, findings, severity, remediation and disposition are all blank by design. Nothing was self-approved |
| **P2-3** | Plans and tests for the NOT IMPLEMENTED / BLOCKED controls | **Plans + executable specs DONE; controls NOT IMPLEMENTED** | `plans/P2-3_IMPLEMENTATION_PLANS.md`; `tests/test_pending_controls.py`: 53 XFAIL cases covering evidence download, cross-tenant search, scheduled audit verification, factor removal, lost-factor recovery/lock-out exit, production KMS, immutable audit storage — of which 4 *gap demos* execute today against the dev stand-ins and fail their stated production assertion | The functionality. Every one of the seven controls is still NOT IMPLEMENTED or BLOCKED (KMS and WORM additionally need the O-4 provider). XFAIL is **not** counted as a pass anywhere |
| **P2-4** | Tighten the trigger weakness; regression test for the audit-integrity property | **CLOSED** | Migration `control_plane/0004` (DEF-14); `tests/test_support_grant_db_guard.py` — 26 tests, **25 of which fail against the Phase 1 trigger** (`evidence/p2_4_mutation_check_phase1_trigger.txt`); reverse and re-apply of the migration verified | Nothing for this condition. Independent review of the state machine is requested within P2-2 scope |

**P2-4 in detail.** The identified weakness (H-01) was that `platform_admin` could be inserted as requester. Re-review found the real hole was larger: the trigger's "same state" branch skipped all checks, so a holder of the `ngrc_ops` credential
could, *without a state change*, **extend `expires_at` of an active grant**, rewrite approval/activation times, or plant approvers. That matters for audit integrity because `audit.append_tenant_event` accepts operator `support.action` events only while the grant is
`active` and `expires_at > now()`: an extended expiry widened the window in which the tenant audit stream accepts operator actions. Now: decision/time columns are write-once and set only with their matching transition, expiry can only be **shortened**, requester must be an active
Platform Support operator (re-checked at activation), approvers must be active, consent columns change only on the consent transition. `test_expiry_may_be_cut_short_but_never_extended_and_audit_follows_the_real_expiry` proves the audit function refuses events after the real expiry and that no database path reopens the window.
Limits: the path required the operator database credential (or SQL injection into the operator plane); the application did not expose it.

## Evidence (final run, 2026-10-21, fresh PostgreSQL 16.15 cluster bootstrapped by `scripts/ci_bootstrap.sh`; Windows 11; Python 3.12.13)

| Gate | Result | Source |
|---|---|---|
| Security regression suite | **433 passed, 0 failed**, 53 XFAIL (pending specs / gap demos — not passes), 486 cases; real roles, throw-away DB | `evidence/junit.xml` |
| Lint (ruff E,F,W,B,S,UP,I) | PASS | `evidence/ruff.txt` |
| SAST bandit / semgrep | PASS, 0 findings (3,968 LOC) / 0 findings, 86 files (all of `ngrc` + `config`; the earlier "168" counted `__pycache__` before the tree was a git repo) | `evidence/bandit.json`, `semgrep.json` |
| SCA runtime (20 pkgs) / dev tooling (109) | PASS, 0 vulns / 1 accepted advisory (`mcp` via `semgrep`, not in runtime) | `evidence/pip_audit*.json`, `docs/accepted_risks.yaml` |
| Secret scan — detect-secrets | PASS (12 candidates, all triaged false positives) | `evidence/detect_secrets_scan.json` |
| Secret scan — gitleaks 8.30.1 git history + working tree | PASS, 0 findings over 2 local commits (first run raised 23 + 235: SHA-1 digests in the baseline files and 211 third-party `.venv` files; resolved by a narrow documented allow-list `.gitleaks.toml`; a planted canary token was detected) | `evidence/gitleaks_*.json` |
| Trivy filesystem + Dockerfile config | PASS, 0 findings | `evidence/trivy_*.json` |
| CI workflow lint (actionlint 1.7.12) | PASS (a lint of the file, **not a run**) | `evidence/ci_rehearsal/actionlint.txt` |
| **Container image build + scan** | **BLOCKED** (no Docker/Podman) | `gate_summary.json` |
| **CI workflow execution** | **BLOCKED** — record NOT_RUN | `docs/ci/CI_RUN_RECORD.yaml` |
| **Independent crypto/AppSec review** | **BLOCKED** — no reviewer | `docs/review/REVIEW_RECORD.yaml` |
| Gate totals | **12 PASS · 0 FAIL · 3 BLOCKED** | `evidence/gate_summary.json` |
| Controls | **50** in the matrix: 35 TESTED — PASS (with documented gaps/dev-only flags), **13 NOT IMPLEMENTED**, **2 BLOCKED** (F-GOV-004 review, F-GOV-005 CI) | `SECURITY_CONTROL_MATRIX.md` |

Evidence integrity: `evidence/MANIFEST.json` lists SHA-256 digests; it guards against accidental change only (not signed, not held off-host).

## Findings opened or closed by this round
* **DEF-14 (fixed):** support-grant trigger weaknesses (above).
* **DEF-15 (OPEN, high — decision needed from the project owner):** 20 failed logins for an e-mail address (10 for operators; 10 MFA failures) set the account to `recovery_required`, but the ADR's verified-e-mail unlock is not implemented, so a stranger who knows an address can lock that account until a DBA intervenes. Either keep the hard stop and accept the availability risk until F-ATH-015 exists, or remove the hard stop (back-off only) as an interim. I did **not** change it: both options alter a security control. Tracked in `OPEN_ITEMS.md` H-10 and by an XFAIL spec.
* **H-11 (open, demonstrated):** the audit verifier ignores database checkpoints with no external copy, so dropping the newest export record is not detected (gap demo runs today; plan item W-3).
* One lint defect in new test code was caught by the CI-rehearsal and fixed.

## Phase 1 steps — status (unchanged except where noted)
Steps 1–2, 8–29 as in the previous revision (Done, tested; dev-only components and missing parts listed per control). Step 3 CI/CD gates: **defined and linted, not executed on a runner**. Step 6 secret scanning: working tree and **local** git history now scanned (gitleaks); CI history scan pending.
Step 7 container scanning: Dockerfile scanned; **image build/scan BLOCKED**. Step 26 append-only audit enforcement and step 24 support/break-glass: strengthened by DEF-14. Step 27 hash chaining/checkpoints: dev signer and sink only; production anchoring NOT IMPLEMENTED (plans F-DAT-006, F-AUD-006).

## What a CONDITIONAL PASS permits and does not permit
* **Permits:** continued planning, and work that clears the remaining conditions. It does **not** authorise Phase 2 feature development.
* **Does not permit:** production use, real customer data, or any statement of audit-readiness, certification or standards compliance. Standards columns are indicative mappings only. `config.settings.prod` cannot start by design.

## To reach PASS (all required; nothing here may be waived by the implementers)
1. **P2-1:** repository + runner; all five CI jobs green incl. container build, hadolint and Trivy image scan, gitleaks full-history; run recorded in `CI_RUN_RECORD.yaml`; `scripts/check_ci_record.py` prints PASSED.
2. **P2-2:** independent reviewer(s) report on all four scopes; findings remediated or risk-accepted by name; `scripts/check_review_record.py` prints COMPLETE for the current package digest.
3. **P2-3:** decide which of the seven controls Phase 2 depends on (and the open decisions D-EV-1, D-SR-1, O-4 provider); implement them with their specs passing with only the marker removed — or have the approver explicitly re-scope the Phase 1 exit criteria in writing.
4. Decide **DEF-15**.
5. Phase 0 exit gate wording "all Phase 0 testing requirements pass in CI" then becomes checkable; requirements for unimplemented features (email change, PATs, purge, restore drill, …) must be implemented or formally re-scoped.

## Limits of this verification (read before relying on it)
* Tests are implementer-authored regression tests; **no penetration test, DAST or independent assessment** has been performed. WebAuthn uses a software authenticator; XSS only at API/header level.
* Everything ran on one workstation. The CI workflow is unproven on a runner; the container image is unbuilt; hadolint never ran.
* The bodies of the pending specs after their first `require_*` call have never executed against an implementation.
* A database superuser can still alter audit data; detection depends on externally held checkpoints whose production sink does not exist.
* Environment: Windows Python + WSL PostgreSQL is accepted for now; WSL networking is recorded as technical debt TD-001 (`TECH_DEBT.md`), not a gate blocker.

## Deliverables (under `03_APP/nsuregrc/docs/` unless stated)
`PHASE1_SECURITY_GATE.md` (this) · `SECURITY_CONTROL_MATRIX.md` and `control_map.yaml` · `SECURITY_TEST_REPORT.md` · `SECURITY_SCAN_REPORT.md` · `BLOCKED_TESTS.md` · `OPEN_ITEMS.md` · `defects_found.yaml` ·
`plans/P2-3_IMPLEMENTATION_PLANS.md` · `review/` · `ci/` · `TECH_DEBT.md` · traceability register `00_CONTROL/TRACEABILITY/feature_control_map.csv` · `00_CONTROL/CHANGELOG.md`.

## Reproduce
```
uv run python scripts/security_gate.py     # all gates -> evidence/ (needs PostgreSQL roles; optional TRIVY_BIN / GITLEAKS_BIN / ACTIONLINT_BIN)
uv run python scripts/build_reports.py     # regenerates matrix, reports and traceability CSV (statuses of review/CI come from their records)
uv run python scripts/build_review_package.py ; uv run python scripts/check_review_record.py ; uv run python scripts/check_ci_record.py
```
