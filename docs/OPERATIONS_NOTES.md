# Operations notes (development / verification environment)

## Running the verification on the Phase 1 workstation (Windows 11 + WSL2)

PostgreSQL 16 runs in WSL2 (Ubuntu). Python runs natively on Windows through `uv` because the WSL network was too slow to install packages.
Windows reaches the WSL database through localhost forwarding, which **only works while at least one WSL session is open** — keep one running
(e.g. `wsl -d Ubuntu -u root -- sleep 14400`). If every connection is "refused", that is the cause.

```powershell
# one-time (WSL, as root): roles + database. Writes random passwords to ~flash/.config/nsuregrc/dev.env (mode 600, outside the repo)
wsl -d Ubuntu -u root -- bash /mnt/e/NsureGRC-Precode/03_APP/nsuregrc/scripts/dev_bootstrap.sh

# every session (PowerShell, project root)
$env:NGRC_ENV_FILE = "\\wsl$\Ubuntu\home\flash\.config\nsuregrc\dev.env"   # secrets stay outside the repository
uv sync
uv run pytest tests -q --junitxml=evidence/junit.xml        # builds a throw-away database `ngrc_test` and runs the whole suite
uv run python scripts/security_gate.py                      # lint, SAST, SCA, secrets, trivy, tests -> evidence/
uv run python scripts/build_reports.py                      # regenerates docs/SECURITY_*.md + the traceability register from real results
```

`scripts/dev_bootstrap.sh` / `dev_reset_db.sh` are **dev only**. Production roles and credentials must come from infrastructure automation and
a secrets manager (open item O-4).

## Existing clusters: re-apply the audit-owner grant (DEF-03 / H-02)
A cluster bootstrapped before this fix still lets the migration identity *inherit* the audit owner's privileges. As a superuser:
```sql
GRANT ngrc_audit_owner TO ngrc_owner WITH INHERIT FALSE, SET TRUE;
```
and verify with `tests/test_audit_integrity.py::test_migration_identity_cannot_write_audit_without_set_role`.
The tests build their database from scratch, so a stale development cluster does not affect test results, but a stale **shared** environment would
be exposed.

## Process planes
`NGRC_PLANE` selects what a process may do and which database roles it receives: `customer` (default, auth + tenant API), `operator`
(platform API; own hostname/process), `migrate` (owner role only; run `manage.py migrate --database=owner`), `all` (tests only; refused by the
production validator). A customer process is started **without** the operator/owner/audit passwords and still boots — that is tested.

## Bootstrapping a platform operator
No self-registration exists. `NGRC_PLANE=operator uv run python manage.py create_operator --email … --name … --role platform_security --password-env VAR`
(the password is read from the named environment variable or prompted; never from the command line). The operator enrols a WebAuthn
authenticator (user verification required) at first sign-in.

## Production start-up
`DJANGO_SETTINGS_MODULE=config.settings.prod` **refuses to start** while the only key provider / audit signer available are the dev-only ones
(`ImproperlyConfigured: Insecure production configuration …`). That is the intended state until open item O-4 is resolved.

## Scheduled audit sealing and verification (F-AUD-007; dev usage)
* `uv run python manage.py audit_seal` — seals every stream (heartbeat if idle); runs as plane `audit_seal` (role `ngrc_audit_sealer`).
* `uv run python manage.py audit_verify --mode incremental|full [--loop] [--check-freshness]` — plane `audit_verify` (role `ngrc_audit_verifier`). Run a **full** pass on a schedule (incremental passes do not recompute old events). `--check-freshness` is the watchdog and should run on a separate schedule/host in production (O-4).
* Alerts reach the log pipeline only (`ALERT_SINKS`); delivery to a pager/SIEM is NOT IMPLEMENTED. Thresholds: `AUDIT_CHECKPOINT_INTERVAL_S`, `AUDIT_CHECKPOINT_MAX_AGE_S`, `AUDIT_EXPORT_GRACE_S`, `AUDIT_VERIFY_MAX_AGE_HOURS` (BASELINE, H-13).
* Production refuses to start without `AUDIT_REQUIRE_EXTERNAL_COPY`, `AUDIT_REQUIRE_COMPLETENESS`, `AUDIT_SINK_IMMUTABLE` — the last cannot be honestly true until a WORM sink exists.

## Evidence store (dev only)
Objects live under `EVIDENCE_STORE_DIR` (git-ignored `var/`); keys are server-generated. This is not an object store: production refuses `EVIDENCE_STORE_BACKEND=local_dev` and `EVIDENCE_SCANNER_BACKEND=dev_eicar`.

## Migrations added since the first gate
`audit/0003_registry_p2`, `audit/0004_checkpoint_continuity`, `iam/0005_recovery_request`, `iam/0006_recovery_security`, `evidence/0001_initial`, `evidence/0002_security`, `control_plane/0004_harden_support_grant_guard`. Run `migrate --database=owner` on every existing cluster.
