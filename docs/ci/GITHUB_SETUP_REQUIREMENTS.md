# GitHub Actions setup requirements (approved approach, 2026-10-21)

**Decision (project owner):** a **private GitHub repository** with **GitHub Actions** is the CI service. CI is "passed" only when the actual workflow has executed against that
repository and produced a real run URL. **This workstation did not and will not create the repository, push code, or create any credential.** Everything below needs a human with
access to the GitHub account. When these steps are done, hand the run id (and nothing secret) back and the CI record is completed from the real run.

## 1. What you create (human steps)
| # | Step | Notes |
|---|---|---|
| 1 | Create a **private** repository (personal account or organisation) | Visibility must be *private*: the checker rejects a record that does not say so |
| 2 | Settings → Actions → General | Allow Actions; **Workflow permissions: read repository contents only** (the workflow also declares `permissions: contents: read`); do not allow Actions to create/approve pull requests; *Actions permissions*: allow GitHub-authored actions plus exactly these third-party actions — `astral-sh/setup-uv`, `hadolint/hadolint-action`, `aquasecurity/trivy-action`, `gitleaks/gitleaks-action` |
| 3 | Settings → Secrets and variables → Actions → **Repository secrets** | `CI_PG_SUPERUSER_PASSWORD` = a long random value (it only protects the *ephemeral* PostgreSQL service container; every application role password is generated randomly per run). `GITLEAKS_LICENSE` **only** if the repository belongs to an organisation (gitleaks-action requires it there) |
| 4 | Settings → Code security | Enable *secret scanning* and *push protection* where your plan offers them; enable dependency alerts. These are additional to, not replacements for, the workflow's gates |
| 5 | Branch protection on `main` | Require a pull request, require the five status checks listed in §3, require branches to be up to date, block force-pushes and deletions |
| 6 | Runners | Use GitHub-hosted `ubuntu-24.04` (Docker is available, which the `container` job needs). **No self-hosted runner** unless it is separately reviewed |
| 7 | Push `main` from `03_APP/nsuregrc` | `git remote add origin <url>` then `git push -u origin main`. Before pushing run `git ls-files` and `git log --stat` once: no secrets are tracked, the history is 5+ local commits, `.gitattributes` forces LF |

## 2. What the first run will exercise
`tests` (lint, migration-drift check, the whole security regression suite on a fresh PostgreSQL 16 service container with the real least-privilege roles — including every PostgreSQL/RLS test) · `sast` (bandit, semgrep) · `sca` (pip-audit runtime + dev) · `secrets` (detect-secrets baseline, gitleaks over the **full history**) · `container` (hadolint, `docker build`, Trivy image scan, non-root check, Trivy config scan).
Expect red first runs: the container job has never executed in any form (hadolint findings and base-image CVEs are plausible). The right response is to fix the image or pin a newer base — **never** to lower thresholds or add ignores without a recorded risk acceptance.

## 3. Required status checks (exact job names from `.github/workflows/ci.yml`)
`lint + migration check + security regression suite` · `SAST (bandit + semgrep)` · `dependency vulnerabilities (pip-audit)` · `secret scanning` · `container build + image scan + Dockerfile lint`

## 4. Recording the result (after a run exists)
1. Compute the workflow digest **from git, not from the API**: `git show <run commit sha>:.github/workflows/ci.yml | sha256sum` (or Get-FileHash on the extracted file).
2. Import the run with *your own* read-only token (never shared with this project):
   `GITHUB_TOKEN=… uv run python scripts/import_ci_run.py --repo OWNER/NAME --run-id <id> --write` — then fill the fields it cannot derive from the run page: `workflow_sha256`, the container job's `image_scan: clean` (only if the Trivy step passed), the secrets job's `history_scanned: true` (only if the gitleaks step ran with `fetch-depth: 0` and passed). The importer is unit-tested against fixture data only; the HTTP calls have not run against the real API.
3. `uv run python scripts/check_ci_record.py` must print `PASSED`. It verifies: the commit exists in this repository and the workflow *at that commit* matches the recorded digest; the workflow path/name; the repository is private; all five jobs succeeded with evidence; the tests job reports N passed, 0 failed and PostgreSQL/RLS tests among them; the full-history secret scan; the container build on Docker with a clean image scan; the workflow is unchanged since.
4. Then regenerate the reports (`security_gate.py`, `build_reports.py`) and reassess the gate.

## 5. What "stop" means here
Until a real run is recorded, **P2-1 stays BLOCKED** in every generated report. Nothing in this repository can turn it green: not a local rehearsal, not the existence of the workflow file, not a hand-typed record that fails the checker.
