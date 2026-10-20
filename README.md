# NsureGRC — v1.3-alpha (Phase 1: Secure Foundation)

Secure application foundation only. **No GRC feature modules.** Design baseline: `../../00_CONTROL/PHASE0/` (D-P0-001…009).

Nothing here is production-ready, certified or independently reviewed. Start with:

| Document | What it tells you |
|---|---|
| [`docs/PHASE1_SECURITY_GATE.md`](docs/PHASE1_SECURITY_GATE.md) | **The gate decision** and the reasons |
| [`docs/ARCHITECTURE_SUMMARY.md`](docs/ARCHITECTURE_SUMMARY.md) | What was built and how the parts interact |
| [`docs/SECURITY_CONTROL_MATRIX.md`](docs/SECURITY_CONTROL_MATRIX.md) | Control → implementation → test → result → audit event → evidence → status (generated from the real run) |
| [`docs/SECURITY_TEST_REPORT.md`](docs/SECURITY_TEST_REPORT.md) | Every test, its result, defects found and remediated |
| [`docs/SECURITY_SCAN_REPORT.md`](docs/SECURITY_SCAN_REPORT.md) | Dependency, SAST, secret, container findings and unresolved issues |
| [`docs/BLOCKED_TESTS.md`](docs/BLOCKED_TESTS.md) | What could not run, and what does not exist yet |
| [`docs/OPEN_ITEMS.md`](docs/OPEN_ITEMS.md) | Phase 0 open items (O-x) and hardening follow-ups (H-x) — none silently resolved |
| [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md), [`docs/OPERATIONS_NOTES.md`](docs/OPERATIONS_NOTES.md) | Versions; how to run and operate the dev environment |
| [`docs/plans/P2-3_IMPLEMENTATION_PLANS.md`](docs/plans/P2-3_IMPLEMENTATION_PLANS.md) | Plans + executable specs (reported XFAIL) for the NOT IMPLEMENTED / BLOCKED controls |
| [`docs/review/`](docs/review/INDEPENDENT_REVIEW_PACKAGE.md) | Independent-review package, scope and record (review is **BLOCKED**: no reviewer) |
| [`docs/ci/`](docs/ci/CI_RUNBOOK.md) | How to run CI for real, the CI run record (**NOT_RUN**) and the local rehearsal |
| [`docs/TECH_DEBT.md`](docs/TECH_DEBT.md) | Technical debt (WSL networking, etc.) — not gate blockers |

## Layout
| Path | Purpose |
|---|---|
| `config/` | Django project, split settings (`base`, `dev`, `test`, `prod`); `validators.py` is the production-start gate |
| `ngrc/core/` | tenant context, DB router, base models, SQL generators for RLS/grants, strict JSON parser, crypto helpers, logging redaction |
| `ngrc/authn/` | realm-generic authentication: passwords, throttling, TOTP, WebAuthn, recovery codes, sessions |
| `ngrc/authz/` | permission catalogue, policy resolver, default-deny DRF base view |
| `ngrc/iam/` | customer identity (IDN) models + auth/MFA/session API |
| `ngrc/tenancy/` | tenant-owned (TEN) roles/memberships + tenant administration API |
| `ngrc/control_plane/` | platform (PLT) data + operator realm API: provisioning, support grants, break-glass, platform audit |
| `ngrc/audit/` | audit schema (raw SQL migration), service, chain, sealer, signer (dev-only), verifier |
| `db/bootstrap/` | role/database bootstrap SQL (run once by a DBA, never by the app); `table_classification.yaml` |
| `tests/` | the security regression suite (pytest, real PostgreSQL, real runtime roles) |
| `scripts/` | `security_gate.py` (all gates), `build_reports.py`, dev/CI bootstrap |
| `evidence/` | **generated**: raw scanner output, JUnit, machine-generated control evidence, `MANIFEST.json` (SHA-256) |
| `docs/` | reports, `control_map.yaml` (mapping input), `defects_found.yaml`, `accepted_risks.yaml` |

## Quick start
Linux/WSL with PostgreSQL 16:
```bash
sudo bash scripts/dev_bootstrap.sh          # roles + db; random passwords in ~/.config/nsuregrc/dev.env (never in the repo)
uv sync
uv run python manage.py migrate --database=owner
uv run pytest
```
Windows + WSL database: see [`docs/OPERATIONS_NOTES.md`](docs/OPERATIONS_NOTES.md) (set `NGRC_ENV_FILE`; keep a WSL session open).

Full gate and reports:
```bash
uv run python scripts/security_gate.py      # writes evidence/, exits non-zero on any FAIL
uv run python scripts/build_reports.py      # regenerates docs/SECURITY_*.md, BLOCKED_TESTS.md, traceability CSV
```
