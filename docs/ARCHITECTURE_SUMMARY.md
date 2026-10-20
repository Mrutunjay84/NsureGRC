# NsureGRC v1.3-alpha — Phase 1 Architecture Summary

Phase 1 delivers the **secure application foundation only** — no GRC feature modules. Everything below is implemented in this repository and
exercised by the automated suite unless a line says otherwise. Control status and gaps: `SECURITY_CONTROL_MATRIX.md`. Nothing here is
production-ready, certified or independently reviewed.

## 1. Shape of the system

```
                     customer hostname                                platform hostname (separate process)
   browser/API ──► NGRC_PLANE=customer  (/api/v1/…)               operator ──► NGRC_PLANE=operator (/ops/api/v1/…)
                    │  iam: login, MFA, sessions, invitations                    │  control_plane: operator login (WebAuthn),
                    │  tenancy: roles, members, invitations,                     │  tenants, support grants, break-glass,
                    │           support consent, audit read/export               │  platform audit, support-session reads
                    ▼                                                            ▼
   Django + DRF  ─ every view = NgrcAPIView + declared Policy ─ default-deny ─ CSRF on every unsafe method ─ strict JSON parser
                    │ tenant_context(): ONE transaction, set_config('app.tenant_id', …, is_local=true), audit unit-of-work flushed last
   ┌────────────────┴───────────── PostgreSQL 16, one database, one connection alias per least-privilege role ─────────────────────┐
   │ ngrc_app (tenant data, RLS)   ngrc_auth (identity/credentials)   ngrc_ops (platform)   ngrc_audit_reader_platform             │
   │ ngrc_audit_sealer (checkpoints)   ngrc_audit_verifier (read-only verify)   ngrc_owner (migrations only)   ngrc_audit_owner*   │
   │ * NOLOGIN; ngrc_owner may SET ROLE to it inside reviewed audit migrations but does NOT inherit its privileges (DEF-03)          │
   └────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

A process receives **only** the database credentials of its plane (`config/settings/base.py`); a customer-plane process boots without the
operator, owner or audit passwords (tested).

## 2. Data classes (D-P0-009) — `db/table_classification.yaml`
`TEN` (tenant-owned: roles, memberships — ENABLE+FORCE RLS, NOT NULL immutable `tenant_id`, composite same-tenant FKs), `PLT` (tenant registry,
operator realm, support grants), `IDN` (customer identity, credentials, sessions, tokens — reachable only by `ngrc_auth`), `AUD` (audit schema),
`SYS`, plus `CAT` (reserved; no tables yet). Pytest compares the manifest with `pg_catalog` (equality, class shape, exact per-role privilege
matrix, no FK from non-TEN into TEN, no views without `security_invoker`).

## 3. Tenant isolation (D-P0-003)
1. Authority is PostgreSQL RLS, not the ORM: policy `tenant_id = ngrc_current_tenant()` on every TEN table (and a context-bound `owner_context` policy, so even FORCE-subject owners honour it).
2. Context is **transaction-scoped** (`set_config(..., true)`), set only by `ngrc.core.context.tenant_context()` from the *server-side session* (or a verified support grant) — never from request data. A malformed value is a cast error (fail closed); switching tenants inside an open context raises.
3. ORM guard layer (`TenantOwnedModel`/`TenantManager`) raises without an active context + open transaction; RLS still enforces if the guard were bypassed.
4. Tenant plane sees `plt_tenant` only as its own row, `idn_account` only as a 4-column projection of members (column grant + RLS), and has **no** privileges on credentials, sessions, tokens or operator tables; invitations and support-consent go through reviewed `SECURITY DEFINER` functions with a pinned `search_path`.

## 4. Authentication & sessions (D-P0-008, C-1)
Argon2id (OWASP-floor enforced by the production validator; rehash on login; dummy-hash timing equalisation; bounded hashing concurrency), NFC + length + blocklist policy,
progressive per-account/per-IP throttling evaluated *before* hashing, uniform errors. **MFA is mandatory for every account**: password → `password_ok`/`enroll_mfa` session
that can reach only MFA endpoints → TOTP (RFC 6238, replay-protected, secret sealed with AES-256-GCM) or WebAuthn (py_webauthn; single-use bound challenges; counter-regression
flags the credential; user verification required for platform operators and privileged tenant roles) or recovery code (customer realm only, HMAC-stored, single use).
Sessions are server-side: opaque 256-bit id (only SHA-256 stored), `__Host-` HttpOnly Secure SameSite=Lax cookies, id rotation on MFA and tenant selection, idle + absolute timeouts, immediate revocation on logout/password change/reset/membership suspension/role-permission reduction.
Step-up: T1 (recent second factor, 10 min) for tenant mutations; T2 (per-action WebAuthn assertion whose challenge is bound to the grant id) for support-grant approval.

## 5. Authorization (default-deny)
`ngrc.authz.drf.NgrcAPIView` + `Policy(scope, permission, stages, step_up, reason)`. DRF defaults are `DenyAll`/JSON-only. A route without a policy is denied; the test-suite fails if
any route lacks one, if an unreviewed public route appears, or if an endpoint inventory changes. The central resolver (`ngrc.authz.policy.authorize`) checks realm, authentication stage,
tenant membership/role (loaded under RLS), expiry, tenant status and step-up; tenant roles can never contain `platform.*` (catalogue partition **and** a DB CHECK); no one may grant
what they do not hold, modify themselves or outrank-modify; system roles and the last Owner are protected by triggers. Every denial is audited on an *independent* connection.

## 6. Platform plane, support access and break-glass (D-P0-005, C-2, C-3)
Separate identity store (`plt_operator_*`), separate cookie, WebAuthn-only. Roles: Admin, Security, Curator, Support Engineer. **No standing access to tenant data.** Support flow:
Support Engineer requests (ticket + reason + profile + duration) → Platform Security approves with a grant-bound T2 assertion → tenant **Owner** consents (step-up) → Engineer activates and starts a session
bound to the grant → every request re-validates the grant (active, unexpired, same tenant) and is double-audited (tenant stream `support.action` + platform stream) → tenant can revoke instantly.
The state machine and separation of duties are enforced **in the database** (trigger `plt_support_grant_guard`; consent columns writable only via `SECURITY DEFINER` functions). The trigger was re-reviewed and tightened in the P2 gate work (migration `control_plane/0004`, DEF-14): only an active Platform Support operator can be the requester; decision/time columns are write-once and set only with their matching transition; an active grant's expiry can be shortened but never extended (the audit stream accepts operator `support.action` events only while the grant is active and unexpired); consent columns change only on the consent transition.
Break-glass: requester ≠ approvers; Security then a *different* Platform Admin; ≤120 min; no tenant consent; flagged events.

## 7. Audit (D-P0-006, C-4)
Schema `audit` owned by a NOLOGIN role; tables have no INSERT/UPDATE/DELETE/TRUNCATE grants for anyone; events enter only through `SECURITY DEFINER` `audit.append_*` which validate the registered action,
the *writing DB role*, tenant binding and an **allow-list of detail keys** (so secrets cannot be recorded), then chain SHA-256 under a row lock. Triggers reject mutation even by the schema owner.
Business change and audit events commit **together or not at all**; denials persist on an independent transaction. An independent Python verifier recomputes every hash; a sealer signs checkpoints (Ed25519) and exports them.
**DEV-ONLY:** the signing key is a file on the DB host and the export sink is a local directory; production KMS/WORM anchoring is NOT IMPLEMENTED (O-4).

## 8. Secure development & delivery
`scripts/security_gate.py` (ruff+security rules, bandit, semgrep, pip-audit runtime & dev, detect-secrets with audited baseline, trivy fs/config, container build+scan, pytest) writes raw output + `MANIFEST.json` digests
to `evidence/`; `.github/workflows/ci.yml` defines the same gates (**not yet run on a runner** - `docs/ci/CI_RUN_RECORD.yaml` says NOT_RUN; a local clean-room rehearsal is documented in `docs/ci/LOCAL_REHEARSAL.md` and is not CI); `Dockerfile` is multi-stage, non-root, locked, dev-free (**not yet built**). `scripts/build_reports.py` regenerates the matrix, test
report, scan report, blocked-test list and the traceability register from real results.

## 9. What is explicitly NOT in Phase 1
GRC feature modules; evidence handling/download (C-6 is an approved *design*, no code); search; personal access tokens; DR/restore; framework ingestion; audit retention/purge; scheduled audit verification;
KMS/WORM; container image build; CI execution; penetration test. See `OPEN_ITEMS.md` and `BLOCKED_TESTS.md`.

## 10. P2 gate work (2026-10-21) - what exists beside the foundation
Executable specifications and gap demos for the NOT IMPLEMENTED controls (`tests/test_pending_controls.py`, reported XFAIL) with plans in `docs/plans/`; an independent-review package, scope and record with a checker that refuses self-approval (`docs/review/`, review BLOCKED); a CI runbook, run record and checker (`docs/ci/`, CI NOT_RUN); a technical-debt register (`docs/TECH_DEBT.md`).
