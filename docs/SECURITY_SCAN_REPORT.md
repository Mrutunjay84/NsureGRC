# NsureGRC — Dependency & Security Scan Report (Phase 1)

*Generated 2026-10-20 from `evidence/gate_summary.json` and the raw tool output in `evidence/`.*

Gate run: 2026-10-20T21:28:49+00:00 on Windows-11-10.0.26200-SP0 (Python 3.12.13). Totals: **12 PASS · 0 FAIL · 3 BLOCKED**.

| Gate | Status | Detail | Raw evidence |
|---|---|---|---|
| lint (ruff E,F,W,B,S,UP,I) | **PASS** | no findings | `evidence/ruff.txt` |
| SAST bandit | **PASS** | 0 findings {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}, 5381 LOC | `evidence/bandit.json` |
| SAST semgrep | **PASS** | 0 findings; 109 files scanned | `evidence/semgrep.json` |
| SCA pip-audit (runtime) | **PASS** | 20 packages, 0 known vulnerabilities, 0 accepted | `evidence/pip_audit_runtime.json` |
| SCA pip-audit (dev-tooling) | **PASS** | 109 packages, 1 known vulnerabilities, 1 accepted (mcp CVE-2026-59951 - see docs/accepted_risks.yaml) | `evidence/pip_audit.json` |
| secret scan (detect-secrets) | **PASS** | 12 candidate(s), 12 triaged as false positives in .secrets.baseline, 0 unreviewed | `evidence/detect_secrets_scan.json` |
| secret scan (gitleaks, git history) | **PASS** | 0 finding(s) over 6 commit(s), HEAD 5200e966c784 | `evidence/gitleaks_history.json` |
| secret scan (gitleaks, working tree) | **PASS** | 0 finding(s) | `evidence/gitleaks_worktree.json` |
| trivy filesystem (lockfile vulns, secrets, misconfig) | **PASS** | 0 finding(s) at the configured severities | `evidence/trivy_fs.json` |
| trivy Dockerfile misconfiguration | **PASS** | 0 finding(s) at the configured severities | `evidence/trivy_config.json` |
| container image build + scan | **BLOCKED** | no container runtime (docker/podman) on this machine; the CI workflow performs this gate | — |
| CI workflow lint (actionlint) | **PASS** | workflow syntax/semantics clean (this is a lint of the file, NOT a CI run) | `evidence/ci_rehearsal/actionlint.txt` |
| CI workflow execution on a runner | **BLOCKED** | no CI run recorded (docs/ci/CI_RUN_RECORD.yaml); no repository/runner | — |
| independent crypto/AppSec review | **BLOCKED** | no independent reviewer has reviewed any scope (docs/review/REVIEW_RECORD.yaml) | — |
| security regression suite (pytest) | **PASS** | 615 passed, 11 xfailed in 100.30s (0:01:40) | `evidence/junit.xml`, `evidence/pytest_output.txt` |

## 1. Dependency vulnerabilities (SCA)

**Runtime (production) dependencies:** 20 packages scanned with `pip-audit` (OSV/PyPI advisory data at run time); **0 known vulnerabilities**.


**All dependencies including dev tooling:** 109 packages scanned with `pip-audit` (OSV/PyPI advisory data at run time); **1 known vulnerability**.

- `mcp 1.29.0` — CVE-2026-59951; fixed in ['1.30.0', '2.2.0']. ### Summary In affected versions, a Streamable HTTP server in stateful mode (the default) never reclaimed session state:  - sessions did not…  **ACCEPTED RISK** (dev-tooling only (transitive dependency of semgrep, dependency group `dev`); review: at the next semgrep upgrade and before the Phase 2 security gate)

## 2. Static analysis (SAST)

**Bandit:** 5381 lines of application code; 0 findings (HIGH 0, MEDIUM 0, LOW 0).

Triage of the findings raised during Phase 1 (all resolved before the final run):

| Finding | Count | Triage | Action |
|---|---|---|---|
| B608 string-built SQL in migrations | 10 | False positive: f-strings interpolate module-level constants (search_path clause, signature lists); migrations are reviewed static SQL run only by `ngrc_owner` | Migrations excluded from bandit with written justification in `pyproject.toml`; still scanned by Semgrep and ruff `S608`; runtime code guarded by `test_no_string_built_sql_outside_the_reviewed_set` |
| B105 hard-coded password | 3 | False positive: enum/purpose names (`password_ok`, `password_reset`) and a DRF setting `None` | `# nosec B105` on the exact lines |
| B101 assert in production code | 2 | Valid: asserts vanish under `python -O` | Replaced with explicit `RuntimeError` (DEF-13) |

**Semgrep** (registry rule packs `p/python`, `p/django`, `p/security-audit`): 0 findings over 109 files.

Ruff with security-lint rules (`S`, `B`, `E`, `F`, `W`, `UP`, `I`): see `evidence/ruff.txt`. Rule `E501` (line length) is deliberately ignored as a formatting preference.

## 3. Secret scanning

`detect-secrets` with an audited baseline (`.secrets.baseline`). Twelve candidates were raised and each was inspected by hand; **all twelve are false positives**:

| Location | Type | Triage |
|---|---|---|
| `ngrc/audit/service.py:9` | keyword | the word "secrets" in a docstring |
| `ngrc/authn/abstract.py:37`, `ngrc/iam/models.py:101` | keyword | enum names `password_ok` / `password_reset` |
| `tests/conftest.py:27` | keyword | deliberately fake test-only password (not in any real system) |
| `tests/test_input_and_exposure.py:183,213,231,242` | keyword / entropy | fake strings used to prove redaction and non-disclosure |
| `tests/test_support_access.py:353` | keyword | a settings key name (`operator_account_free_failures`) |
| `tests/test_evidence_artifacts.py:121` | keyword | a dictionary key containing the word PASSWORD in an explanatory note |
| `tests/test_pending_controls.py` / `tests/test_auth_backoff_policy.py` | keyword | deliberately wrong passwords used to provoke failures |

**Git history (local run, not CI):** `gitleaks 8.30.1` (release SHA-256 verified) scanned 6 commit(s) of the local repository (HEAD `5200e966c784`) and the working tree: **0 finding(s)**. The CI `secrets` job (full history on the runner) has **not** run.

## 4. Container and IaC scanning

- **trivy filesystem (lockfile vulns, secrets, misconfig)** — **PASS**: 0 finding(s) at the configured severities
- **trivy Dockerfile misconfiguration** — **PASS**: 0 finding(s) at the configured severities
- **container image build + scan** — **BLOCKED**: no container runtime (docker/podman) on this machine; the CI workflow performs this gate

The Dockerfile (multi-stage, pinned tags, non-root uid 10001, no secrets, dev group excluded, locked install) was written but **the image has not been built**; image scanning is therefore **BLOCKED** locally and is performed by the CI `container` job. Trivy was obtained from the official release page and its SHA-256 matched the release's checksum file (this protects against corruption, not against a compromised release).

## 5. Unresolved issues (honest list)

1. `mcp 1.29.0` CVE-2026-59951 in dev tooling only — accepted risk, see `docs/accepted_risks.yaml`.
2. Container image build/scan, **CI execution on a runner**, DAST and penetration testing have **not** been performed (BLOCKED / not done). The independent cryptographic/AppSec review is also **BLOCKED** (no reviewer).
3. Actions are pinned by tag, and the base image by tag, not by commit SHA / digest.
4. Open items (hosting/KMS/immutable storage, retention, RPO/RTO, legal review, framework licensing, crypto review, AppSec review) remain open — see `docs/OPEN_ITEMS.md`.
5. Defect DEF-15 (failure-triggered lock-out) is **mitigated-temporary** by owner decision D-P1-001 (progressive back-off + detection, stricter operator parameters); it closes only when the lost-factor recovery mechanism (F-ATH-015) has been independently reviewed — see `docs/defects_found.yaml`.

## 6. CI and independent-review status (records, not claims)

- **CI:** NOT RUN — the workflow has never executed on a CI runner (`docs/ci/CI_RUN_RECORD.yaml`).
- **Independent review:** BLOCKED — no independent reviewer has reviewed any scope; the review package is prepared (`docs/review/`).
- `actionlint` (checksum-verified binary) lint of `.github/workflows/ci.yml`: see `evidence/ci_rehearsal/actionlint.txt` — a syntax/semantic check of the workflow file, **not** a run.
- Local clean-room rehearsal of the CI command lines: `docs/ci/LOCAL_REHEARSAL.md` — **not** CI.
