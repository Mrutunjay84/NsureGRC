# P2-1 — Running the CI workflow for real (runbook)

**Status: BLOCKED — the workflow has never run on a CI runner.** Approved approach (owner, 2026-10-21): a **private GitHub repository** with **GitHub Actions**. This workstation has no remote and no credentials, and
will not create any; the human steps are in **`GITHUB_SETUP_REQUIREMENTS.md`**. The CI result is recorded only in `CI_RUN_RECORD.yaml` and judged by `scripts/check_ci_record.py`; the existence of `.github/workflows/ci.yml` is not a result.

## What has been prepared (local only)
* A local git repository on `main` (several local commits; **no remote, nothing pushed**); `.gitattributes` pins LF; `.gitignore` excludes env files, keys, the local evidence store and local state.
* `actionlint 1.7.12` (SHA-256 verified) reports the workflow clean.
* A **clean-room rehearsal** ran the real `scripts/ci_bootstrap.sh` against a fresh PostgreSQL 16 cluster and the CI command lines — `LOCAL_REHEARSAL.md` (what ran, what it cannot show). It is **not** CI.
* A CI gate that cannot be satisfied by anything but a real run: commit SHA present in this repository, workflow digest at that commit, workflow path/name, private repository, all five jobs, test results with PostgreSQL/RLS tests, full-history secret scan, container build + clean image scan, workflow unchanged since. `scripts/import_ci_run.py` (your own token) builds the record from the run.

## What to expect (so a red first run is not mistaken for a broken process)
* **`container` job:** image build, `hadolint` (failure threshold *warning*) and the Trivy **image** scan have never run. Findings on `python:3.12-slim` OS packages are plausible; the response is to update the base image (and pin by digest — H-04), **not** to lower the threshold or add ignores without a recorded risk acceptance.
* **`tests` job:** `makemigrations --check` prints a harmless `RuntimeWarning` (the test database does not exist yet at that step); it exits 0. If it ever exits non-zero, the models and migrations have drifted.
* **`secrets` job:** a full-history scan also reads the first commit; a gitleaks hit is a *new* finding to triage, not to allow-list reflexively (the local `.gitleaks.toml` allow-lists three tool-output files and `.venv` with reasons).
* Actions are pinned by version tag, not commit SHA (H-04, tracked).

## What a green run would and would not prove
It would prove: the suite (including every PostgreSQL/RLS test), lint, SAST, dependency audit, secret scan and container build/scan pass on a clean, independent runner from a clean checkout.
It would **not** prove: absence of vulnerabilities, production readiness, standards compliance, or anything about the dev-only components (local key provider, file signer, local export, local evidence store, EICAR scanner). It does not replace the independent review (P2-2) or a penetration test.
