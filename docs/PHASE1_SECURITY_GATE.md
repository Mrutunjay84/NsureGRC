# NsureGRC — Phase 1 Security Gate (v1.3-alpha, Secure Foundation) — reassessment after the owner's decisions of 2026-10-21

**Date:** 2026-10-21 · **Scope:** Phase 1 steps 1–29, the four conditions P2-1…P2-4, and the owner's six decisions (CI approach, independent review, DEF-15, the P2-3 dependency split, H-11, Phase 2 authorisation) · **Code status:** development alpha, not for production.
**Phase 2 has NOT been started and is not authorised by this report.**

> **Update 2026-10-26 — P2-1 CLOSED, overall decision unchanged.** The owner created the private repository ([`Mrutunjay84/NsureGRC`](https://github.com/Mrutunjay84/NsureGRC)) and pushed; the workflow has now run repeatedly on real GitHub Actions hardware. `scripts/check_ci_record.py` against the real run prints `"state": "PASSED"` (`docs/ci/CI_RUN_RECORD.yaml`): commit `5cd872e`, workflow digest verified from git, all five jobs green, 615 tests passed / 0 failed with 63 PostgreSQL/RLS tests, clean Trivy image scan, full-history secret scan. This also clears the separate **container image build + scan** BLOCKED gate (this workstation has no Docker; the GitHub runner does). Three real defects were found and fixed along the way, not waived: **DEF-18** (checkpoint-sealer concurrency race, real CI hardware only), **DEF-19** (`.gitleaks.toml`'s allowlist used an invalid TOML key and had never actually applied since it was written — no secret was ever exposed by this, the allow-listed paths hold digests/public-key material by design), **DEF-20** (`import_ci_run.py`'s artifact download forwarded the GitHub auth header across a redirect to Azure Blob Storage, which rejected it — the script's HTTP path had never been run against the real API before). Full detail in `docs/defects_found.yaml` and `03_APP/nsuregrc/docs/GATE_CLEARING_CHECKLIST.md`.
> **P2-2 (independent review) is still BLOCKED — no reviewer has been engaged.** `implementer_humans` is now recorded and a review package + outreach draft are ready to send, but sourcing prep is not a review. **The overall decision below stays CONDITIONAL PASS**, DEF-15 and H-11 are unaffected by this update, and this gate reassessment covers only P2-1; gate totals, control counts and the rest of this document are **not** regenerated and still reflect the 2026-10-21 run.

## DECISION: **CONDITIONAL PASS** (unchanged — kept by owner instruction and confirmed by the evidence)

Why it is not PASS: two of the owner's pre-Phase-2 requirements need things this workstation cannot provide and are **BLOCKED** (a real CI run; an independent reviewer), DEF-15 is only *mitigated-temporary* by design, and H-11 is *deliberately still open*.
Why it is not FAIL: every gate that can run here is green, nothing regressed, and the five controls the owner made Phase-2-required are now implemented with passing tests (plus mutation checks showing the tests detect the removal of the protecting code).
**Nothing was waived and no status was converted by assertion.**

### Exit-criteria checklist (the owner's list from 2026-10-21)

| # | Requirement | Status | Evidence / what is missing |
|---|---|---|---|
| 1 | **P2-4** trigger weakness closed | **CLOSED** (earlier) | migration `control_plane/0004`, 26 tests, 25 fail against the old trigger (DEF-14) |
| 2 | **P2-1** real CI execution (private GitHub repo + Actions, real run URL; gate checks commit SHA, workflow identity, all jobs, unchanged workflow, test results, scans, PostgreSQL/RLS tests, image scan) | **BLOCKED** | Everything that can be prepared locally exists: workflow (actionlint-clean), local git history (6 commits, no remote), `docs/ci/GITHUB_SETUP_REQUIREMENTS.md` (the human steps), a CI checker that accepts nothing but a real run (`scripts/check_ci_record.py`, 28 tests), an importer for the run (`scripts/import_ci_run.py`, pure parts unit-tested; **its HTTP calls have never run against GitHub**). **Missing:** a human must create the private repository, set the secrets and push; no run exists; record is `NOT_RUN`. I did not push or create credentials. |
| 3 | **P2-2** independent review (audit hash, checkpoint/signing, AEAD helper, authentication, session management, MFA/WebAuthn) | **BLOCKED** | Package re-issued because the mechanisms changed (63 reviewed files + 9 context documents, digest in `evidence/review_package/review_package_manifest.json`; supersedes the 44-file package) with 25 known concerns listed for the reviewer. **No independent reviewer exists**; record is BLOCKED; the checker refuses self-review, AI/tool review, undocumented or unsigned reviews. Nothing in this report is a review. |
| 4 | **DEF-15** resolved with the approved temporary policy | **RE-CONFIRMED 2026-10-27 — status "mitigated-temporary", still NOT closed** | Hard stop removed; progressive back-off, rate limiting, failed-login counting, audit events, suspicious-login detection, alert interface, stricter operator parameters (ADR D-P1-001; `tests/test_auth_backoff_policy.py`, 11 tests plus the exit-path test). Permanent recovery mechanism is the F-ATH-015 below. The earlier correction (customer accounts have a password-reset exit; operator accounts and the stranger-triggered-reset/no-notification gaps do not) left the residual risks in D-P1-001 unchanged in substance, only narrower in customer-account severity. Owner re-confirmed under standing delegation (docs/defects_found.yaml DEF-15 note) rather than a fresh ad-hoc approval — this is a risk-acceptance call on the owner's own project, a different kind of decision from P2-2 below, which no delegation can substitute for. |
| 5 | **P2-3 required (1)** evidence download | **IMPLEMENTED + TESTED** (dev-only store) | F-DAT-004: 13 tests; F-DAT-005 lifecycle 46 tests; mutation run 17/20 killed (3 documented equivalent mutants). Object store and EICAR scanner are **DEV-ONLY**: no malware detection, no real object store. |
| 6 | **P2-3 required (2)** cross-tenant search | **IMPLEMENTED + TESTED** | F-AUZ-005: 29 tests (metadata only; PostgreSQL FTS under RLS). Every future searchable resource needs the same tests (the inventory test fails the build otherwise). |
| 7 | **P2-3 required (3)** scheduled audit verification | **IMPLEMENTED + TESTED** | F-AUD-007: 16 tests. **Alert delivery to a real channel is BLOCKED (O-4)**; alerts reach the log pipeline. Where the schedule and a separate-host watchdog run is a deployment decision. |
| 8 | **P2-3 required (4)** MFA factor removal | **IMPLEMENTED + TESTED** | F-ATH-014: 13 tests; mutation 8/8 killed; DB trigger prevents the last factor being removed even by direct SQL. |
| 9 | **P2-3 required (5)** lost-factor recovery | **IMPLEMENTED + TESTED** | F-ATH-015: 23 tests; mutation 14/14 killed; database-enforced state machine. Open: real mail delivery (O-7), Platform Security identity-verification procedure (O-5/O-8), operator-realm recovery, trust model of tenant-plane approval (`app.principal_id`) and the time-limited enrolment reservation — all listed for the reviewer. |
| 10 | **Production gate** production KMS (F-DAT-006) | **NOT IMPLEMENTED — production gate, not a Phase 2 development blocker** | 4 executable specs + 2 gap demos, all XFAIL (not passes). Dev stand-ins are marked and refused by `config.settings.prod`. |
| 11 | **Production gate** immutable/WORM audit storage (F-AUD-006) | **NOT IMPLEMENTED — production gate** | 4 specs + 1 gap demo, XFAIL. **No production-readiness claim may be made while 10 and 11 are open.** |
| 12 | **H-11** analysed, mechanism designed, regression tests | **MECHANISM DONE; H-11 REMAINS OPEN by instruction** | ADR D-P1-003 states the threat model and the two properties the verifier must distinguish — (A) the supplied checkpoint chain is internally valid, (B) the sequence is complete and no latest checkpoint silently disappeared. Implemented: chained format-2 checkpoints with a database continuity trigger, heartbeat checkpoints, two-way external-copy comparison, previous-run high-water mark, freshness check, verdicts `internally_valid` + `completeness ∈ {violated, not_established, consistent, established}`. 16 regression tests; verifier mutation 7/7 killed. **Honest ceiling:** `completeness` can reach `consistent` but not `established` until an immutable sink exists (item 11); the high-water mark lives in the database it protects; events after the newest honest checkpoint are covered by chain consistency only (window = checkpoint interval). Not independently reviewed. |

### Control counts (generated, `SECURITY_CONTROL_MATRIX.md`)
50 controls: **41 TESTED — PASS** (each with its documented gaps/dev-only flags), **7 NOT IMPLEMENTED** (F-AUD-004 retention/purge, F-AUD-006 WORM, F-ATH-011 PATs, F-DAT-006 KMS, F-DR-001, F-DR-002, F-FWK-001), **2 BLOCKED** (F-GOV-004 independent review, F-GOV-005 CI run). A control is "TESTED — PASS" only because its mapped tests ran in the recorded run and passed — not because it is reviewed, production-grade or compliant.

## Evidence (final run, 2026-10-21; fresh PostgreSQL 16.15 cluster bootstrapped by `scripts/ci_bootstrap.sh`; Windows 11; Python 3.12.13; HEAD `5200e96`)

| Gate | Result | Source |
|---|---|---|
| Security regression suite | **615 passed, 0 failed**, 11 XFAIL (KMS/WORM specs and gap demos — not passes), 626 cases; real roles, throw-away DB | `evidence/junit.xml` |
| Lint (ruff E,F,W,B,S,UP,I) | PASS | `evidence/ruff.txt` |
| SAST bandit / semgrep | PASS, 0 findings (5,381 LOC) / 0 findings, 109 files | `evidence/bandit.json`, `semgrep.json` |
| SCA runtime (20 pkgs) / dev tooling (109) | PASS, 0 vulns / 1 accepted advisory (`mcp` via `semgrep`, not in runtime) | `evidence/pip_audit*.json`, `docs/accepted_risks.yaml` |
| Secret scan — detect-secrets | PASS (12 candidates, all triaged false positives; the new one is a test dictionary key named `"secrets"`) | `evidence/detect_secrets_scan.json` |
| Secret scan — gitleaks 8.30.1 history + working tree | PASS, 0 findings over 6 local commits | `evidence/gitleaks_history.json`, `gitleaks_worktree.json` |
| Trivy filesystem + Dockerfile config | PASS, 0 findings | `evidence/trivy_*.json` |
| CI workflow lint (actionlint 1.7.12) | PASS (a lint of the file, **not a run**) | `evidence/ci_rehearsal/actionlint.txt` |
| **Container image build + scan** | **BLOCKED** (no Docker/Podman) | `gate_summary.json` |
| **CI workflow execution** | **BLOCKED** — record NOT_RUN | `docs/ci/CI_RUN_RECORD.yaml` |
| **Independent crypto/AppSec review** | **BLOCKED** — no reviewer | `docs/review/REVIEW_RECORD.yaml` |
| Gate totals | **12 PASS · 0 FAIL · 3 BLOCKED** | `evidence/gate_summary.json` |
| Mutation checks (security-critical lines disabled one at a time; tests must fail) | H-11 verifier 7/7; recovery 14/14; factor removal 8/8; evidence 17/20 | `evidence/h11_mutation_check.txt`, `p2_*_mutation_check.txt` |

The mutation checks are an implementer-run measure of test strength, not independent assurance. Evidence integrity: `evidence/MANIFEST.json` lists SHA-256 digests; it guards against accidental change only (not signed, not held off-host).

## Defects and findings found while doing this work
* **DEF-15** — see table above (mitigated-temporary; **earlier "no exit path" claim corrected**).
* **DEF-16 (fixed)** — dev signer key-creation race on first concurrent use (found by the H-11 concurrency test).
* **DEF-17 (fixed)** — a malformed client address caused an audit-append error and HTTP 500 on the login path; addresses are now normalised (residual: unparseable values share one throttle bucket).
* **H-12/H-13/H-14 (new open items)** — evidence below-the-API components are dev-only and two interim decisions (D-EV-1, D-SR-1) await approval; numeric BASELINE values await approval; the tenant-plane recovery approval trusts a runtime-settable session variable.
* **Surviving mutants (documented):** E9/E10 (security headers are also set by global middleware) and E15 (the allow-list is re-checked in `sniff.inspect`) are equivalent mutants — a second layer enforces the same property.

## What a CONDITIONAL PASS permits and does not permit
* **Permits:** continued planning, and work that clears the remaining conditions. It does **not** authorise Phase 2 feature development.
* **Does not permit:** production use, real customer data, or any statement of audit-readiness, certification or standards compliance. Standards columns are indicative mappings only. `config.settings.prod` cannot start by design.

## To reach PASS (nothing here may be waived by the implementers)
1. **P2-1 (human):** create the private GitHub repository, set `CI_PG_SUPERUSER_PASSWORD` (and `GITLEAKS_LICENSE` only for an organisation), push `main`, let the workflow run to completion; all five jobs green including container build, hadolint and Trivy image scan; record the run (`scripts/import_ci_run.py` with your own token, then `scripts/check_ci_record.py` must print PASSED). Expect red first runs in the never-executed container job.
2. **P2-2 (human):** engage a reviewer independent of the implementer; they report on all four scopes (audit hash; checkpoint/integrity; AEAD helper; authentication, session management and MFA/WebAuthn) against the current package digest; findings remediated or risk-accepted by name; `scripts/check_review_record.py` prints COMPLETE.
3. **DEF-15:** the owner re-confirms (or amends) D-P1-001 after reading the correction; it closes only when F-ATH-015 is independently reviewed.
4. **H-11:** closes with the WORM sink (F-AUD-006) and review; the owner decides whether the interval-sized residual window is acceptable.
5. **Production gates** (KMS, WORM, plus O-4/O-7/O-11 providers) before any production-readiness claim.
6. Phase 0 exit wording "all Phase 0 testing requirements pass in CI" becomes checkable after item 1; requirements for still-unimplemented features (e-mail change, PATs, purge, restore drill, …) must be implemented or formally re-scoped by the owner.

## Limits of this verification (read before relying on it)
* Tests are implementer-authored regression tests; **no penetration test, DAST or independent assessment** has been performed. WebAuthn uses a software authenticator; XSS only at API/header level.
* Everything ran on one workstation. The CI workflow is unproven on a runner; the container image is unbuilt; hadolint never ran; the GitHub-import script's HTTP path never ran.
* Pending specs (KMS/WORM) bodies after their first `require_*` call have never executed against an implementation.
* A database superuser can still alter audit data; detection depends on externally held anchors whose production sink does not exist.
* Evidence storage, malware scanning, alert delivery, e-mail delivery and key management are dev stand-ins or absent.
* Environment: Windows Python + WSL PostgreSQL is accepted for now; WSL networking is technical debt TD-001 (`TECH_DEBT.md`), not a gate blocker.

## Deliverables (under `03_APP/nsuregrc/docs/` unless stated)
`PHASE1_SECURITY_GATE.md` (this) · `SECURITY_CONTROL_MATRIX.md` and `control_map.yaml` · `SECURITY_TEST_REPORT.md` · `SECURITY_SCAN_REPORT.md` · `BLOCKED_TESTS.md` · `OPEN_ITEMS.md` · `defects_found.yaml` ·
`plans/P2-3_IMPLEMENTATION_PLANS.md` · `review/` · `ci/` (incl. `GITHUB_SETUP_REQUIREMENTS.md`) · `TECH_DEBT.md` · decision records `00_CONTROL/PHASE1/D-P1-001…004` · traceability register `00_CONTROL/TRACEABILITY/feature_control_map.csv` · `00_CONTROL/CHANGELOG.md`.

## Reproduce
```
uv run python scripts/security_gate.py     # all gates -> evidence/ (needs PostgreSQL roles; optional TRIVY_BIN / GITLEAKS_BIN / ACTIONLINT_BIN)
uv run python scripts/build_reports.py     # regenerates matrix, reports and traceability CSV (statuses of review/CI come from their records)
uv run python scripts/build_review_package.py ; uv run python scripts/check_review_record.py ; uv run python scripts/check_ci_record.py
```
