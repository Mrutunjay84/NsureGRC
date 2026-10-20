# NsureGRC — Dependency Record (open item O-1)

*Recorded 2026-10-20. Versions come from `uv.lock` (110 locked packages; 20 are runtime dependencies). Support-lifecycle data was read from
the public aggregator <https://endoflife.date> on the same day — **a third-party source; confirm against the vendor pages before relying on
it** (Django, Python and PostgreSQL project sites).*

## Platform components

| Component | Version in use | Lifecycle (endoflife.date, 2026-10-20) | Note |
|---|---|---|---|
| Python | 3.12 (`>=3.12,<3.13`) | security fixes until 2028-10-31; **bug-fix support already ended 2025-04-02** | 3.13 and 3.14 are available; a move is advisable before production. Not changed in Phase 1 to keep the verified baseline stable. |
| Django | 5.2.18 (`>=5.2.18,<5.3`) | 5.2 is an LTS: security support until 2028-04-30; 5.2.18 is the latest 5.2 release | D-P0-002 said "migrate to the next LTS when released"; 6.1 is not an LTS. Re-check at the Phase 2 gate. |
| PostgreSQL | 16.15 (WSL2 Ubuntu 24.04 package) | 16.x supported until 2028-11-09; 16.15 is the latest 16.x | Production version/hosting is open item O-4. |
| Django REST framework | 3.18.3 | — | |
| psycopg | 3.3.6 (binary wheel) | — | `psycopg[binary]` is convenient for development; production images should consider building psycopg against the distro libpq. |

## Direct runtime dependencies

`Django 5.2.18`, `djangorestframework 3.18.3`, `psycopg[binary] 3.3.6`, `argon2-cffi 25.1.0`, `cryptography 50.0.2`, `pyotp 2.10.0`,
`webauthn 2.8.0` (py_webauthn), `gunicorn 26.2.0`. Full list: `evidence/requirements-runtime.txt` (20 packages incl. transitive).
`pip-audit` result for these 20 packages: **0 known vulnerabilities** (`evidence/pip_audit_runtime.json`).

## Development / verification tooling (not in the runtime image)

`pytest 9.1.1`, `pytest-django 4.14.0`, `ruff 0.17.1`, `bandit 1.9.4`, `pip-audit 2.10.1`, `semgrep 1.181.0`, `detect-secrets 1.5.0`,
`cbor2 5.9.0` (software WebAuthn authenticator), `pyyaml 6.0.3`. Trivy 0.76.0 was used locally (official release; SHA-256 matched the
release checksum file).

## Supply-chain controls and what is NOT yet done

- Installs are reproducible from `uv.lock` (`uv sync --frozen`); the Docker build and CI use `--frozen` and exclude the `dev` group.
- **Not done:** hash-pinned requirements (`--require-hashes`), SBOM generation/attestation, signed images, GitHub Actions pinned by commit SHA,
  base image pinned by digest. These are tracked in `docs/OPEN_ITEMS.md` (H-04).
- One advisory exists in dev tooling only (`mcp` via `semgrep`): see `docs/accepted_risks.yaml`.

## Upgrade rule
Any dependency change requires: `uv lock` diff review, `pip-audit` on the runtime export, the full security suite, and a line in `CHANGELOG.md`.
