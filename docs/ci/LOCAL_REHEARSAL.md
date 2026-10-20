# Local clean-room rehearsal of the CI workflow — NOT a CI run

**This is not CI evidence and must not be cited as such.** It records what was run on the developer workstation to find problems before the first real CI run,
and exactly how it differs from a runner. CI status is whatever `CI_RUN_RECORD.yaml` says (today: **NOT_RUN**).

## What was run (2026-10-21)
| Step | How | Result |
|---|---|---|
| Workflow lint | `actionlint 1.7.12` (release SHA-256 verified against the published checksums) on `.github/workflows/ci.yml` | exit 0, no findings (`evidence/ci_rehearsal/actionlint.txt`). actionlint's optional shellcheck/pyflakes integrations were not installed, so embedded shell snippets were not shell-linted |
| Fresh database | new PostgreSQL 16.15 cluster (`initdb`, SCRAM, random superuser password in a mode-600 file, port 5544, inside WSL) | created |
| Role bootstrap | the **real** `scripts/ci_bootstrap.sh` with `PGHOST/PGPORT/PGUSER/PGPASSWORD` and `RUNNER_TEMP/GITHUB_ENV` set like a runner | all roles created; env file written with random passwords, not printed |
| `tests` job | `uv sync --frozen`; `ruff check ngrc config tests scripts --output-format github`; `makemigrations --check --dry-run`; `pytest tests` | see below |
| `sast` job | the workflow's own bandit and semgrep command lines | both exit 0 (`evidence/ci_rehearsal/`) |
| `sca` job | `uv export` + `pip-audit` (runtime blocking; dev tolerated) + `check_accepted_risks.py` | runtime exit 0; dev exit 1 as tolerated; accepted-risk check: no unaccepted vulnerabilities |
| `secrets` job | `detect-secrets` gate; `gitleaks 8.30.1` CLI (checksum verified) on git history and working tree | see `SECURITY_SCAN_REPORT.md` |
| Full gate | `scripts/security_gate.py` against the same fresh cluster | `evidence/gate_summary.json` |

## What the rehearsal found
* **A real defect, fixed:** the first lint run failed on the new `tests/test_support_grant_db_guard.py` (ruff UP017) — it would have failed the CI `tests` job. Fixed and re-run clean.
* `makemigrations --check` exits 0 ("No changes detected") but prints a `RuntimeWarning` because the test database does not exist at that point (TD-002).
* The suite passes on a freshly bootstrapped cluster (it does not depend on state left on the long-lived dev cluster, including the H-02 grant): 396 passed before the pending specs were added; **433 passed, 53 XFAIL** in the final gate run.
* The secret scans initially failed on baseline/evidence files holding SHA-1 digests of triaged false positives and on 211 third-party files in `.venv`; resolved with a documented, narrow allow-list (`.gitleaks.toml`) and one detect-secrets triage entry. A planted canary token was detected, so the scanner still has teeth.

## How this differs from a CI run (why it proves less)
* Windows host + uv-managed Python 3.12 against a PostgreSQL 16.15 Ubuntu package, not `ubuntu-24.04` with the `postgres:16` service container.
* No GitHub Actions context: repository secrets, `services:`, `actions/checkout`/`upload-artifact`, `GITHUB_ENV` semantics (simulated with a file), concurrency, permissions.
* `gitleaks` CLI instead of `gitleaks-action`; **hadolint was not run**; **no container image was built or scanned** (no container runtime) — the `container` job has never executed in any form.
* The repository history is two local commits, not the real project history.

## What would still need a real run
All five jobs on a runner, including the container job, from a clean checkout — see `CI_RUNBOOK.md`.
