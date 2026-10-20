# P2-1 — Running the CI workflow for real (runbook)

**Status: BLOCKED — the workflow has never run on a CI runner.** This machine has no remote repository, no CI-service credentials and no `gh` CLI, and pushing
project code to an external service is an outward-facing action that needs the project owner's decision (which service/account, private or not). Nothing was pushed.
The CI result is recorded only in `CI_RUN_RECORD.yaml` and judged by `scripts/check_ci_record.py`; the existence of `.github/workflows/ci.yml` is not a result.

## What has been prepared (local only)
* The project directory is a local git repository on branch `main` (no remote, nothing pushed); `.gitattributes` pins LF line endings so shell scripts and the Dockerfile are safe on Linux runners; `.gitignore` excludes env files, keys and local state.
* `actionlint 1.7.12` (SHA-256 verified against the release checksums) reports the workflow clean.
* A **clean-room rehearsal** ran the real `scripts/ci_bootstrap.sh` against a fresh PostgreSQL 16 cluster and then the CI `tests`, `sast`, `sca` and `secrets` command lines — see `LOCAL_REHEARSAL.md` for exactly what ran and what it cannot show. It found and fixed one real problem (a lint error in a new test file).

## What the project owner needs to do (cannot be done from this workstation)
1. **Choose the CI service/account.** The workflow targets GitHub Actions (`ubuntu-24.04`, Docker available on hosted runners). Create a **private** repository.
2. **Push `main`** from `03_APP/nsuregrc` (`git remote add origin <url>`; `git push -u origin main`). Review the staged file list first (`git ls-files`); no secrets are tracked.
3. **Repository secret:** `CI_PG_SUPERUSER_PASSWORD` — any strong random string; it only protects the ephemeral PostgreSQL *service container* on the runner. (Every application role password is generated randomly per run by `scripts/ci_bootstrap.sh`.)
4. **Secrets job:** `gitleaks/gitleaks-action@v2` needs a `GITLEAKS_LICENSE` secret when the repository belongs to a GitHub *organisation* (not for personal accounts). If that is not wanted, replace it with the gitleaks CLI (a downloaded, checksum-verified binary) — do not delete the history scan.
5. **Run** the workflow (push or pull request). All five jobs must be green: `tests`, `sast`, `sca`, `secrets`, `container`.
6. **Record the result:** download the artifacts (`test-evidence`, `sast-evidence`, `sca-evidence`, `container-evidence`), copy run URL, commit SHA, workflow digest (`sha256sum .github/workflows/ci.yml` at that commit), job conclusions and evidence references into `CI_RUN_RECORD.yaml` (template inside), then `uv run python scripts/check_ci_record.py` must print `PASSED`.

## What to expect (so a red first run is not mistaken for a broken process)
* **`container` job:** image build, `hadolint` (failure threshold *warning*) and the Trivy **image** scan have never run. Findings on `python:3.12-slim` OS packages are plausible; the response is to update the base image (and pin by digest — H-04), **not** to lower the threshold or add ignores without a recorded risk acceptance.
* **`tests` job:** `makemigrations --check` prints a harmless `RuntimeWarning` (the test database does not exist yet at that step); it exits 0. If it ever exits non-zero, the models and migrations have drifted.
* **`secrets` job:** a full-history scan (`fetch-depth: 0`) also reads the first commit; the project's audited `.secrets.baseline` covers `detect-secrets` only, so a gitleaks hit is a *new* finding to triage, not to allow-list reflexively.
* Actions are pinned by version tag, not commit SHA (H-04, tracked).

## What a green run would and would not prove
It would prove: the suite, lint, SAST, dependency audit, secret scan and container build/scan pass on a clean, independent runner from a clean checkout.
It would **not** prove: absence of vulnerabilities, production readiness, standards compliance, or anything about the dev-only components (local key provider, file signer, local export). It does not replace the independent review (P2-2) or a penetration test.
