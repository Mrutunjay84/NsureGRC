# NsureGRC — Security Control Matrix (Phase 1 / v1.3-alpha)

*Generated 2026-10-20 21:28 UTC by `scripts/build_reports.py` from `docs/control_map.yaml` and the real pytest run (`evidence/junit.xml`: 615 passed, 11 XFAIL, 0 failed, 0 skipped, 626 test cases).* **Do not edit by hand — regenerate.**

**Reading this table.** `TESTED — PASS` means every mapped automated test ran in the recorded run and passed; it does **not** mean the control is production-ready, audited, certified or sufficient for any standard. `NOT IMPLEMENTED` means no code exists; an executable specification (reported as **XFAIL**, never as a pass) may exist for it. `BLOCKED` means the control depends on a human-supplied record (independent review, CI run) that does not exist. Standards references are *indicative mappings only*. Gaps, dev-only components and blocked tests are shown against each control and summarised below.

## Summary

| Status | Controls |
|---|---|
| BLOCKED | 2 |
| NOT IMPLEMENTED | 7 |
| TESTED — PASS | 41 |

## Owner-decided groups (decision 2026-10-21)

**Required before Phase 2 can be called security-ready** (implement AND test):

| Control | Status | Result |
|---|---|---|
| F-AUD-007 Scheduled continuous audit verification with alerting and watchdog | **TESTED — PASS** | 16/16 passed |
| F-DAT-004 Authorization-checked evidence download (C-6) | **TESTED — PASS** | 13/13 passed |
| F-AUZ-005 Cross-tenant search isolation (PostgreSQL full-text search under RLS) | **TESTED — PASS** | 29/29 passed |
| F-ATH-014 MFA factor removal | **TESTED — PASS** | 13/13 passed |
| F-ATH-015 Lost-factor recovery (admin-assisted, last-Owner via Platform Security, cooling-off, cancel) | **TESTED — PASS** | 23/23 passed |

**Production-security gates** (NOT Phase 2 development blockers; no production-readiness claim while any is open):

| Control | Status |
|---|---|
| F-AUD-006 Immutable (WORM) audit checkpoint storage and external anchoring | **NOT IMPLEMENTED** |
| F-DAT-006 Production key management (KMS) for data encryption and audit signing | **NOT IMPLEMENTED** |

## Matrix

| Control | Implementation | Test | Result | Audit event(s) | Evidence | Status |
|---|---|---|---|---|---|---|
| **F-TEN-001** Tenant isolation via PostgreSQL RLS | `ngrc/core/sqlgen.py`<br>`ngrc/tenancy/migrations/0002_security.py`<br>`ngrc/control_plane/migrations/0002_security.py`<br>`db/bootstrap/00_roles.sql` | `test_rls_bypass_attempts.py` (44 cases)<br>`test_rls_tenant_isolation.py` (19 cases)<br>`test_table_classification.py` (2 cases) | 65/65 passed | `authz.denied` | `evidence/junit.xml`<br>`evidence/rls_coverage.json`<br>`evidence/privilege_matrix.json` | **TESTED — PASS** |
| **F-TEN-002** Fail-closed transaction-scoped tenant context | `ngrc/core/context.py`<br>`ngrc/core/models.py`<br>`ngrc/authz/drf.py` | `test_authorization_api.py` (6 cases)<br>`test_rls_tenant_isolation.py` (6 cases) | 12/12 passed | `authz.denied` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s); BLOCKED: 1 |
| **F-TEN-003** Composite tenant FKs and tenant-scoped uniques | `ngrc/tenancy/migrations/0002_security.py` | `test_rls_tenant_isolation.py` (3 cases)<br>`test_table_classification.py` (2 cases) | 5/5 passed | — | `evidence/junit.xml` | **TESTED — PASS** |
| **F-TEN-004** Table classification manifest with automated enforcement | `db/table_classification.yaml`<br>`tests/test_table_classification.py` | `test_table_classification.py` (38 cases) | 38/38 passed | — | `evidence/junit.xml`<br>`evidence/rls_coverage.json`<br>`evidence/privilege_matrix.json` | **TESTED — PASS** · 2 documented gap(s) |
| **F-AUZ-001** Central policy resolver and default-deny route registry | `ngrc/authz/policy.py`<br>`ngrc/authz/drf.py`<br>`ngrc/authz/drf_defaults.py`<br>`ngrc/authz/permissions.py` | `test_authorization_api.py` (7 cases) | 7/7 passed | `authz.denied` | `evidence/junit.xml`<br>`evidence/route_policy_inventory.json` | **TESTED — PASS** |
| **F-AUZ-002** BOLA/IDOR regression suite | `ngrc/authz/drf.py`<br>`ngrc/tenancy/views.py`<br>`RLS policies` | `test_audit_integrity.py` (1 case)<br>`test_authorization_api.py` (5 cases)<br>`test_support_access.py` (1 case) | 7/7 passed | `authz.denied` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s); BLOCKED: 1 |
| **F-AUZ-003** Privilege-escalation prevention in tenant role management | `ngrc/tenancy/views.py`<br>`ngrc/tenancy/roles.py`<br>`ngrc/tenancy/migrations/0002_security.py` | `test_authorization_api.py` (10 cases)<br>`test_rls_tenant_isolation.py` (3 cases) | 13/13 passed | `authz.denied`, `tenant.role.created`, `tenant.role.updated`, `tenant.member.role_changed`, `tenant.invitation.created` | `evidence/junit.xml` | **TESTED — PASS** |
| **F-AUZ-004** Audit-write failure is fail-closed (C-4) | `ngrc/audit/service.py`<br>`ngrc/authz/drf.py` | `test_audit_integrity.py` (3 cases)<br>`test_authorization_api.py` (3 cases) | 6/6 passed | `authz.denied` | `evidence/junit.xml` | **TESTED — PASS** |
| **F-PLT-001** Customer vs platform identity realms | `ngrc/authn/realms.py`<br>`ngrc/control_plane/models.py`<br>`ngrc/control_plane/views.py`<br>`config/settings/base.py` | `test_authentication.py` (3 cases)<br>`test_config_security.py` (5 cases)<br>`test_support_access.py` (9 cases) | 17/17 passed | `platform.operator.login.success`, `platform.operator.login.failure`, `platform.operator.mfa.verified`, `platform.operator.webauthn.registered`, `platform.operator.throttle.triggered` | `evidence/junit.xml`<br>`evidence/config_snapshot.json` | **TESTED — PASS** · 2 documented gap(s); BLOCKED: 1 |
| **F-PLT-002** Support access grant (time-bound, ticketed, approved, tenant-consented) | `ngrc/control_plane/views.py`<br>`ngrc/control_plane/support.py`<br>`ngrc/control_plane/migrations/0002_security.py`<br>`ngrc/tenancy/views.py` | `test_support_access.py` (18 cases)<br>`test_support_grant_db_guard.py` (26 cases) | 44/44 passed | `support.grant.requested`, `support.grant.approved`, `tenant.support.consented`, `tenant.support.revoked`, `support.session.started`, `support.action`, `support.session.ended`, `platform.support.requested`, `platform.support.approved`, `platform.support.consented`, `platform.support.activated`, `platform.support.action`, `platform.support.ended`, `platform.operator.stepup.success` | `evidence/junit.xml` | **TESTED — PASS** · 3 documented gap(s) |
| **F-PLT-003** Break-glass emergency access | `ngrc/control_plane/views.py`<br>`ngrc/control_plane/migrations/0002_security.py` | `test_support_access.py` (4 cases)<br>`test_support_grant_db_guard.py` (2 cases) | 6/6 passed | `platform.breakglass.requested`, `platform.breakglass.approved`, `support.session.started` | `evidence/junit.xml` | **TESTED — PASS** · 2 documented gap(s) |
| **F-PLT-004** Platform audit stream access control | `ngrc/audit/migrations/0001_audit_schema.py`<br>`ngrc/control_plane/views.py` | `test_audit_integrity.py` (4 cases)<br>`test_support_access.py` (1 case) | 5/5 passed | `platform.audit.read` | `evidence/junit.xml`<br>`evidence/privilege_matrix.json` | **TESTED — PASS** |
| **F-PLT-005** Tenant provisioning by Platform Administrator | `ngrc/control_plane/views.py`<br>`ngrc/control_plane/migrations/0002_security.py`<br>`ngrc/control_plane/migrations/0003_provision_invitation_kind.py` | `test_support_access.py` (2 cases) | 2/2 passed | `platform.tenant.provisioned` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-AUD-001** Enforced append-only audit tables | `ngrc/audit/migrations/0001_audit_schema.py`<br>`db/bootstrap/00_roles.sql` | `test_audit_integrity.py` (32 cases)<br>`test_support_grant_db_guard.py` (1 case)<br>`test_table_classification.py` (2 cases) | 35/35 passed | `audit.integrity_violation` | `evidence/junit.xml`<br>`evidence/privilege_matrix.json` | **TESTED — PASS** · 1 documented gap(s) |
| **F-AUD-002** Hash chain with signed, externally exported checkpoints | `ngrc/audit/chain.py`<br>`ngrc/audit/sealer.py`<br>`ngrc/audit/signer.py`<br>`ngrc/audit/verifier.py` | `test_audit_completeness.py` (16 cases)<br>`test_audit_integrity.py` (10 cases)<br>`test_evidence_artifacts.py` (1 case) | 27/27 passed | `audit.integrity_violation` | `evidence/junit.xml`<br>`evidence/audit_chain_verification.json`<br>`evidence/h11_mutation_check.txt` | **TESTED — PASS** · DEV-ONLY component; 5 documented gap(s) |
| **F-AUD-003** Audit verification library (on demand; independent recomputation) | `ngrc/audit/verifier.py` | `test_audit_integrity.py` (1 case) | 1/1 passed | `audit.integrity_violation` | `evidence/junit.xml` | **TESTED — PASS** · 2 documented gap(s) |
| **F-AUD-007** Scheduled continuous audit verification with alerting and watchdog | `ngrc/audit/scheduler.py`<br>`ngrc/audit/alerts.py`<br>`ngrc/audit/management/commands/audit_verify.py`<br>`ngrc/audit/management/commands/audit_seal.py`<br>`config/settings/base.py`<br>`config/settings/prod.py` | `test_scheduled_verification.py` (16 cases) | 16/16 passed | `audit.verification.completed`, `audit.verification.overdue`, `audit.integrity_violation` | `evidence/junit.xml`<br>`evidence/h11_mutation_check.txt` | **TESTED — PASS** · 5 documented gap(s); BLOCKED: 1 |
| **F-AUD-006** Immutable (WORM) audit checkpoint storage and external anchoring | — | — | no passing tests · 5 XFAIL (not a pass) | — | — | **NOT IMPLEMENTED** · BLOCKED: 1; 5 pending spec/gap-demo case(s) XFAIL |
| **F-AUD-004** Audit retention and purge procedure | — | — | no passing tests | — | — | **NOT IMPLEMENTED** |
| **F-AUD-005** Audit read and export controls | `ngrc/tenancy/views.py` | `test_authorization_api.py` (2 cases)<br>`test_support_access.py` (1 case) | 3/3 passed | `audit.read`, `audit.export` | `evidence/junit.xml` | **TESTED — PASS** |
| **F-DAT-001** Data classification and handling rules | `db/table_classification.yaml`<br>`ngrc/core/logging.py`<br>`ngrc/audit/actions.py` | `test_input_and_exposure.py` (6 cases)<br>`test_table_classification.py` (2 cases) | 8/8 passed | — | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-DAT-002** Envelope AEAD encryption for reversible secrets | `ngrc/core/crypto.py` | `test_authentication.py` (1 case)<br>`test_crypto.py` (10 cases) | 11/11 passed | — | `evidence/junit.xml` | **TESTED — PASS** · DEV-ONLY component; 2 documented gap(s) |
| **F-DAT-003** Hash-only storage of tokens and recovery codes | `ngrc/core/crypto.py`<br>`ngrc/authn/sessions.py`<br>`ngrc/authn/recovery.py`<br>`ngrc/iam/services.py` | `test_authentication.py` (3 cases)<br>`test_crypto.py` (2 cases) | 5/5 passed | — | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-DAT-004** Authorization-checked evidence download (C-6) | `ngrc/evidence/views.py`<br>`ngrc/evidence/storage.py`<br>`ngrc/evidence/models.py`<br>`ngrc/evidence/migrations/0002_security.py` | `test_evidence_download.py` (13 cases) | 13/13 passed | `evidence.downloaded`, `evidence.hash_mismatch`, `authz.denied` | `evidence/junit.xml`<br>`evidence/p2_evidence_mutation_check.txt` | **TESTED — PASS** · DEV-ONLY component; 5 documented gap(s) |
| **F-DAT-005** Evidence upload validation, scan lifecycle and immutable revisions | `ngrc/evidence/service.py`<br>`ngrc/evidence/sniff.py`<br>`ngrc/evidence/scanner.py`<br>`ngrc/evidence/storage.py`<br>`ngrc/evidence/migrations/0002_security.py` | `test_evidence_lifecycle.py` (45 cases) | 45/45 passed | `evidence.created`, `evidence.revision.added`, `evidence.scan.clean`, `evidence.scan.quarantined`, `evidence.scan.error`, `evidence.upload_rejected` | `evidence/junit.xml`<br>`evidence/p2_evidence_mutation_check.txt` | **TESTED — PASS** · DEV-ONLY component; 3 documented gap(s) |
| **F-ATH-001** Password policy and Argon2id hashing | `ngrc/authn/passwords.py`<br>`config/settings/validators.py` | `test_authentication.py` (5 cases)<br>`test_config_security.py` (28 cases) | 33/33 passed | `auth.password.blocklist_rejected` | `evidence/junit.xml` | **TESTED — PASS** · 2 documented gap(s) |
| **F-ATH-002** Login and second-factor throttling (progressive back-off, suspicious-login detection) - TEMPORARY baseline D-P1-001 | `ngrc/authn/throttle.py`<br>`ngrc/authn/flow.py`<br>`ngrc/audit/alerts.py`<br>`ngrc/core/net.py` | `test_auth_backoff_policy.py` (10 cases)<br>`test_authentication.py` (5 cases)<br>`test_support_access.py` (2 cases) | 17/17 passed | `auth.login.failure`, `auth.throttle.triggered`, `auth.login.suspicious`, `platform.operator.login.suspicious`, `platform.operator.throttle.triggered` | `evidence/junit.xml` | **TESTED — PASS** · 3 documented gap(s); BLOCKED: 1 |
| **F-ATH-003** Password reset | `ngrc/iam/views.py`<br>`ngrc/iam/services.py` | `test_authentication.py` (7 cases) | 7/7 passed | `auth.password.reset_requested`, `auth.password.reset_completed` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-ATH-004** Email verification and invitations | `ngrc/iam/views.py`<br>`ngrc/iam/services.py`<br>`ngrc/iam/migrations/0002_security.py` | `test_authentication.py` (1 case)<br>`test_authorization_api.py` (2 cases) | 3/3 passed | `auth.email.verified`, `auth.invitation.accepted`, `tenant.invitation.created`, `tenant.invitation.revoked` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-ATH-005** TOTP MFA | `ngrc/authn/totp.py` | `test_authentication.py` (6 cases)<br>`test_input_and_exposure.py` (3 cases) | 9/9 passed | `auth.mfa.enrolled`, `auth.mfa.verified`, `auth.mfa.failed`, `auth.totp.replay_rejected` | `evidence/junit.xml` | **TESTED — PASS** |
| **F-ATH-006** WebAuthn MFA / step-up | `ngrc/authn/webauthn_.py`<br>`ngrc/iam/views.py`<br>`ngrc/control_plane/views.py` | `test_authentication.py` (9 cases)<br>`test_support_access.py` (3 cases) | 12/12 passed | `auth.webauthn.registered`, `auth.webauthn.counter_regression`, `auth.mfa.verified`, `platform.operator.webauthn.registered` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-ATH-007** Recovery codes and lost-factor recovery | `ngrc/authn/recovery.py` | `test_authentication.py` (3 cases) | 3/3 passed | `auth.recovery_codes.generated`, `auth.recovery_codes.used`, `auth.recovery_codes.failed` | `evidence/junit.xml` | **TESTED — PASS** · 2 documented gap(s) |
| **F-ATH-008** Server-side sessions | `ngrc/authn/sessions.py`<br>`ngrc/authn/middleware.py` | `test_authentication.py` (11 cases)<br>`test_authorization_api.py` (1 case)<br>`test_support_access.py` (2 cases) | 14/14 passed | `auth.logout`, `auth.session.revoked`, `auth.session.expired` | `evidence/junit.xml` | **TESTED — PASS** · 2 documented gap(s) |
| **F-ATH-009** CSRF and CORS protections | `ngrc/authz/drf.py`<br>`config/settings/base.py`<br>`ngrc/core/parsers.py` | `test_authentication.py` (5 cases)<br>`test_input_and_exposure.py` (3 cases) | 8/8 passed | `authz.denied` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-ATH-010** Universal MFA, privileged roles and step-up tiers (C-1) | `ngrc/authn/flow.py`<br>`ngrc/authz/policy.py`<br>`ngrc/authz/drf.py`<br>`ngrc/control_plane/views.py` | `test_authentication.py` (5 cases)<br>`test_authorization_api.py` (1 case)<br>`test_smoke_flows.py` (2 cases)<br>`test_support_access.py` (3 cases) | 11/11 passed | `auth.stepup.success`, `auth.stepup.failure`, `platform.operator.stepup.success`, `platform.operator.stepup.failure` | `evidence/junit.xml` | **TESTED — PASS** · 1 documented gap(s) |
| **F-ATH-011** Personal access tokens | — | — | no passing tests | — | — | **NOT IMPLEMENTED** |
| **F-ATH-012** Authentication audit events (correct stream, no secrets) | `ngrc/audit/actions.py`<br>`ngrc/audit/service.py`<br>`ngrc/authn/flow.py` | `test_audit_integrity.py` (3 cases)<br>`test_authentication.py` (1 case)<br>`test_input_and_exposure.py` (1 case) | 5/5 passed | `auth.login.success`, `auth.login.failure`, `auth.mfa.verified`, `auth.mfa.failed`, `auth.logout`, `auth.password.changed` | `evidence/junit.xml` | **TESTED — PASS** |
| **F-ATH-013** Input hardening (SQL injection, XSS, hostile payloads) | `ngrc/core/parsers.py`<br>`ngrc/core/middleware.py`<br>`ngrc/core/views.py`<br>`config/settings/base.py` | `test_input_and_exposure.py` (32 cases) | 32/32 passed | — | `evidence/junit.xml`<br>`evidence/semgrep.json`<br>`evidence/bandit.json` | **TESTED — PASS** · 2 documented gap(s) |
| **F-AUZ-005** Cross-tenant search isolation (PostgreSQL full-text search under RLS) | `ngrc/evidence/views.py`<br>`ngrc/evidence/migrations/0002_security.py` | `test_cross_tenant_search.py` (29 cases) | 29/29 passed | `search.executed`, `authz.denied` | `evidence/junit.xml`<br>`evidence/p2_evidence_mutation_check.txt` | **TESTED — PASS** · 3 documented gap(s) |
| **F-DAT-006** Production key management (KMS) for data encryption and audit signing | — | — | no passing tests · 6 XFAIL (not a pass) | — | — | **NOT IMPLEMENTED** · BLOCKED: 1; 6 pending spec/gap-demo case(s) XFAIL |
| **F-ATH-014** MFA factor removal | `ngrc/iam/views.py`<br>`ngrc/iam/migrations/0006_recovery_security.py` | `test_factor_removal.py` (13 cases) | 13/13 passed | `auth.mfa.removed`, `authz.denied` | `evidence/junit.xml`<br>`evidence/p2_factor_mutation_check.txt` | **TESTED — PASS** · 3 documented gap(s) |
| **F-ATH-015** Lost-factor recovery (admin-assisted, last-Owner via Platform Security, cooling-off, cancel) | `ngrc/iam/recovery_service.py`<br>`ngrc/iam/views.py`<br>`ngrc/iam/models.py`<br>`ngrc/iam/migrations/0005_recovery_request.py`<br>`ngrc/iam/migrations/0006_recovery_security.py`<br>`ngrc/tenancy/views.py`<br>`ngrc/control_plane/views.py`<br>`ngrc/authn/sessions.py` | `test_auth_backoff_policy.py` (1 case)<br>`test_lost_factor_recovery.py` (22 cases) | 23/23 passed | `auth.recovery.requested`, `auth.recovery.approved`, `auth.recovery.denied`, `auth.recovery.cancelled`, `auth.recovery.completed` | `evidence/junit.xml`<br>`evidence/p2_recovery_mutation_check.txt` | **TESTED — PASS** · 6 documented gap(s) |
| **F-GOV-004** Independent cryptographic / AppSec review (audit hash, checkpoints, AEAD helper, authentication/session/MFA) | `docs/review/INDEPENDENT_REVIEW_PACKAGE.md`<br>`docs/review/review_scope.yaml`<br>`docs/review/REVIEW_RECORD.yaml`<br>`scripts/build_review_package.py`<br>`scripts/check_review_record.py` | `test_review_record.py` (20 cases) | 20/20 passed | — | `evidence/review_package/review_package_manifest.json` | **BLOCKED** · 2 documented gap(s); BLOCKED: 1 |
| **F-GOV-005** CI workflow executed on an independent runner | `.github/workflows/ci.yml`<br>`docs/ci/CI_RUNBOOK.md`<br>`docs/ci/CI_RUN_RECORD.yaml`<br>`scripts/check_ci_record.py` | `test_ci_record.py` (28 cases) | 28/28 passed | — | `docs/ci/LOCAL_REHEARSAL.md` | **BLOCKED** · 2 documented gap(s); BLOCKED: 3 |
| **F-DR-001** Platform-level DR restore | — | — | no passing tests | — | — | **NOT IMPLEMENTED** |
| **F-DR-002** Erasure ledger replay after restore | — | — | no passing tests | — | — | **NOT IMPLEMENTED** |
| **F-FWK-001** Framework ingestion sandboxing (SSRF/XXE/archive limits) | — | — | no passing tests | — | — | **NOT IMPLEMENTED** |
| **F-GOV-001** Secure SDLC pipeline (SAST, SCA, secrets, container, IaC, security tests) | `.github/workflows/ci.yml`<br>`scripts/security_gate.py`<br>`scripts/ci_bootstrap.sh`<br>`Dockerfile`<br>`pyproject.toml`<br>`.secrets.baseline` | `test_config_security.py` (1 case)<br>`test_evidence_artifacts.py` (5 cases)<br>`test_input_and_exposure.py` (1 case)<br>`test_pending_controls.py` (1 case) | 8/8 passed | — | `evidence/gate_summary.json`<br>`evidence/bandit.json`<br>`evidence/semgrep.json`<br>`evidence/pip_audit.json`<br>`evidence/ruff.txt`<br>`evidence/MANIFEST.json` | **TESTED — PASS** · 4 documented gap(s); BLOCKED: 3 |
| **F-GOV-002** Secure configuration and startup validation | `config/settings/base.py`<br>`config/settings/prod.py`<br>`config/settings/validators.py` | `test_config_security.py` (47 cases) | 47/47 passed | — | `evidence/junit.xml`<br>`evidence/config_snapshot.json` | **TESTED — PASS** · 1 documented gap(s) |
| **F-GOV-003** Honest labelling of dev-only stand-ins | `ngrc/core/crypto.py`<br>`ngrc/audit/signer.py`<br>`config/settings/prod.py` | `test_config_security.py` (3 cases)<br>`test_crypto.py` (1 case) | 4/4 passed | — | `evidence/junit.xml` | **TESTED — PASS** |

## Documented gaps, dev-only components and blocked tests (per control)

### F-TEN-002 — Fail-closed transaction-scoped tenant context
- Connection-pooler (PgBouncer transaction mode) behaviour is BLOCKED: no pooler in the Phase 1 environment; the transaction-local set_config design is tested on a direct connection
- **BLOCKED test:** pooling test against a real transaction pooler

### F-TEN-004 — Table classification manifest with automated enforcement
- No CAT-class tables exist yet (framework catalogue is Phase 2); the CAT shape rules are implemented but unexercised
- Enforced by pytest; the CI job that runs it has not been executed on a CI runner

### F-AUZ-002 — BOLA/IDOR regression suite
- Cross-tenant SEARCH (F-AUZ-005) and DOWNLOAD (F-DAT-004) are now tested; REPORT, EXPORT, NOTIFICATION and JOB tests remain BLOCKED: those features do not exist (test_endpoint_inventory_is_reviewed fails the build if such an endpoint appears without extending the suite)
- **BLOCKED test:** cross-tenant report/export/job/notification

### F-PLT-001 — Customer vs platform identity realms
- Separate hostname / network restriction (VPN or IP allow-list) is a deployment control: BLOCKED (hosting not selected, O-4)
- Platform-admin recovery process is organisational (O-5)
- **BLOCKED test:** network-restricted operator hostname

### F-PLT-002 — Support access grant (time-bound, ticketed, approved, tenant-consented)
- Restricted-class consent is stored but unexercised (no Restricted-class content endpoints exist)
- write_limited profile has no write operations
- Module scope is stored but not enforced (no modules exist)

### F-PLT-003 — Break-glass emergency access
- Immediate e-mail/pager notification to tenant Owners NOT IMPLEMENTED (events appear in the tenant audit stream only)
- Post-incident review record/timer NOT IMPLEMENTED (process control; period is open item O-5)

### F-PLT-005 — Tenant provisioning by Platform Administrator
- Tenant suspend/offboard lifecycle API NOT IMPLEMENTED (audit action exists; DB column and denial path are tested)

### F-AUD-001 — Enforced append-only audit tables
- A database SUPERUSER can still alter audit data; detection (not prevention) relies on external checkpoints - see F-AUD-002

### F-AUD-002 — Hash chain with signed, externally exported checkpoints
- **DEV-ONLY:** the only implementation is a development stand-in and must never be treated as a production control.
- H-11 (D-P1-003): checkpoints are chained, heartbeat-sealed and verified against anchors, but COMPLETENESS cannot exceed 'consistent' until an immutable sink exists - every anchor is currently rewritable by a schema-owner attacker; events after the newest honest checkpoint are covered by chain consistency only
- Signing key is a DEV-ONLY file on the database host: NOT a production control
- Checkpoint export sink is a local directory, NOT WORM/immutable storage (see F-AUD-006)
- Production KMS signer is NOT IMPLEMENTED (F-DAT-006, open item O-4)
- Cryptographic construction has NOT had an independent review: BLOCKED, no reviewer (F-GOV-004)

### F-AUD-003 — Audit verification library (on demand; independent recomputation)
- The scheduled job, watchdog and incremental mode are the separate control F-AUD-007
- Completeness against anchors is covered by F-AUD-002 (D-P1-003)

### F-AUD-007 — Scheduled continuous audit verification with alerting and watchdog
- Alert DELIVERY (pager/SIEM/e-mail) is NOT IMPLEMENTED: alerts reach the log pipeline only (O-4)
- The scheduler is a command / worker loop; WHERE it runs (cron, CronJob, a separate host for the watchdog) is a deployment decision (O-4)
- Incremental runs do not recompute already-verified events; a periodic FULL run is required (tested, documented)
- Thresholds are BASELINE pending approval
- Not independently reviewed (F-GOV-004 BLOCKED)
- **BLOCKED test:** alert delivery to a real channel

### F-AUD-006 — Immutable (WORM) audit checkpoint storage and external anchoring
- Hosting/KMS/WORM provider not selected (open item O-4); retention lock periods depend on O-2
- The verifier's two-way external-copy comparison and the `AUDIT_SINK_IMMUTABLE` gate EXIST (F-AUD-002) but the sink itself is a rewritable dev file: completeness cannot exceed 'consistent' until a WORM sink exists
- A gap demo runs today and is expected to fail its assertion (XFAIL): the dev export file is rewritable by the application process
- **BLOCKED test:** WORM semantics, account separation and retention lock need the real provider

### F-AUD-004 — Audit retention and purge procedure
- Retention periods are open item O-2 (no values invented); purge procedure is Phase 2

### F-DAT-001 — Data classification and handling rules
- Handling rules for Confidential tenant content (export, retention, AI use) have no content to apply to yet (Phase 2+)

### F-DAT-002 — Envelope AEAD encryption for reversible secrets
- **DEV-ONLY:** the only implementation is a development stand-in and must never be treated as a production control.
- Master key comes from the environment (DEV-ONLY local provider); KMS/HSM provider and key rotation are NOT IMPLEMENTED (F-DAT-006, open item O-4)
- Cryptographic review NOT done: BLOCKED, no independent reviewer (F-GOV-004)

### F-DAT-003 — Hash-only storage of tokens and recovery codes
- The recovery-code pepper is an environment value (production: KMS-held, O-4)

### F-DAT-004 — Authorization-checked evidence download (C-6)
- **DEV-ONLY:** the only implementation is a development stand-in and must never be treated as a production control.
- The object store is a DEV-ONLY local directory: no private object store exists (open item O-4); production start-up refuses it
- D-EV-1 (pre-verification into a bounded spool) is an INTERIM decision awaiting owner approval
- Orphaned objects (stored, request failed before COMMIT) need a sweep: NOT IMPLEMENTED
- Bulk/Restricted export, retention, legal hold and deletion do not exist
- Not independently reviewed

### F-DAT-005 — Evidence upload validation, scan lifecycle and immutable revisions
- **DEV-ONLY:** the only implementation is a development stand-in and must never be treated as a production control.
- The scanner is a DEV-ONLY EICAR stand-in: MALWARE DETECTION IS NOT PROVIDED, only the quarantine mechanics (open item O-11); production start-up refuses it
- Nested archives inside OOXML packages are not inspected
- Legal hold / retention / purge are later workflows (O-2, O-8)

### F-ATH-001 — Password policy and Argon2id hashing
- Blocklist is a SEED file, not a breach corpus (open item O-12)
- Production Argon2 parameters must be benchmarked on production hardware

### F-ATH-002 — Login and second-factor throttling (progressive back-off, suspicious-login detection) - TEMPORARY baseline D-P1-001
- TEMPORARY (DEF-15 mitigated-temporary): the D-P0-008 hard stop is suspended; an attacker can still keep a victim waiting up to the delay cap; no cross-account distributed-attack detection; alert delivery beyond the log pipeline is NOT IMPLEMENTED (O-4)
- Counters are DB-backed only; Redis / distributed throttling and its failure-mode test are NOT IMPLEMENTED (no cache infrastructure)
- Numeric values are BASELINE pending approval
- **BLOCKED test:** Redis-down throttling behaviour

### F-ATH-003 — Password reset
- E-mail delivery domain authentication (SPF/DKIM/DMARC) is open item O-7

### F-ATH-004 — Email verification and invitations
- Email-change flow NOT IMPLEMENTED

### F-ATH-006 — WebAuthn MFA / step-up
- Exercised with a SOFTWARE authenticator only; no hardware-authenticator or browser interoperability testing

### F-ATH-007 — Recovery codes and lost-factor recovery
- Factor removal (F-ATH-014) and lost-factor recovery (F-ATH-015) are implemented as separate controls; the recovery-code REGENERATION endpoint is still missing
- A credential flagged as cloned leaves the user to recovery codes or the F-ATH-015 workflow

### F-ATH-008 — Server-side sessions
- Timeout values are NsureGRC baseline numbers, not standard-derived
- A user-facing 'list / revoke my sessions' API is NOT IMPLEMENTED

### F-ATH-009 — CSRF and CORS protections
- PAT-vs-cookie separation tests are N/A until PATs exist (F-ATH-011)

### F-ATH-010 — Universal MFA, privileged roles and step-up tiers (C-1)
- T2 actions for tenant deletion, privacy erasure, DR restore and platform role change are NOT IMPLEMENTED (the features do not exist); T2 is implemented for support-grant approval only

### F-ATH-011 — Personal access tokens
- Phase 2

### F-ATH-013 — Input hardening (SQL injection, XSS, hostile payloads)
- No browser-rendered UI exists yet: XSS is tested at the API/response-header level only (output encoding for a future UI is out of scope)
- No dynamic scanner (DAST) has been run

### F-AUZ-005 — Cross-tenant search isolation (PostgreSQL full-text search under RLS)
- Searches evidence METADATA only (title, description) with the 'simple' configuration; no content indexing, no language handling
- Applies only to the one searchable resource that exists; every future searchable resource needs the same tests (the endpoint inventory test fails the build for new search routes)
- Not independently reviewed

### F-DAT-006 — Production key management (KMS) for data encryption and audit signing
- Provider not selected (open item O-4); independent cryptographic review is mandatory before use (F-GOV-004)
- Two gap demos run today against the dev stand-ins and are expected to fail their assertions (XFAIL): no key versions/rotation; dev signing key readable by the signing process
- IAM separation, non-exportability, KMS audit trail and rotation under load can only be tested with the real provider account
- **BLOCKED test:** any test requiring the real KMS account

### F-ATH-014 — MFA factor removal
- Tenant-Owner 'WebAuthn-only' tightening needs a tenant policy feature that does not exist
- E-mail change flow NOT IMPLEMENTED
- Not independently reviewed (F-GOV-004 BLOCKED)

### F-ATH-015 — Lost-factor recovery (admin-assisted, last-Owner via Platform Security, cooling-off, cancel)
- Real notification delivery needs an e-mail provider (O-7); notifications are only as good as the user's mailbox
- Platform Security's identity verification of a sole Owner is an organisational procedure that does not exist (O-5, O-8)
- Operator-realm MFA recovery is NOT IMPLEMENTED (organisational procedure)
- Tenant-plane approval trusts app.principal_id (runtime-role-settable): see review concern 19
- Post-recovery enrolment is protected only by a short window (see D-P1-004)
- Not independently reviewed (F-GOV-004 BLOCKED)

### F-GOV-004 — Independent cryptographic / AppSec review (audit hash, checkpoints, AEAD helper, authentication/session/MFA)
- The tests prove the RECORD CHECKER refuses self-approval, AI/tool reviewers, undated or unsigned reviews and reviews of different code; they say nothing about the design under review
- Package prepared; no reviewer has been engaged: status BLOCKED
- **BLOCKED test:** the review itself

### F-GOV-005 — CI workflow executed on an independent runner
- The tests prove the RECORD CHECKER refuses to call CI passed without a real run; they are not a CI run
- No repository/runner exists; pushing code to an external service needs the project owner's decision: status BLOCKED
- **BLOCKED test:** CI runner execution
- **BLOCKED test:** container image build and scan
- **BLOCKED test:** full-history secret scan

### F-DR-001 — Platform-level DR restore
- Phase 2; RPO/RTO are open item O-3 (no values asserted)

### F-DR-002 — Erasure ledger replay after restore
- Phase 2; legal review of erasure vs backups/audit retention is open item O-8

### F-FWK-001 — Framework ingestion sandboxing (SSRF/XXE/archive limits)
- Phase 2; framework content licensing is an open item (O-8)

### F-GOV-001 — Secure SDLC pipeline (SAST, SCA, secrets, container, IaC, security tests)
- The GitHub Actions workflow is DEFINED and lint-checked (actionlint) but has NOT been executed on a CI runner (F-GOV-005, BLOCKED); a local clean-room rehearsal ran the same command lines (docs/ci/LOCAL_REHEARSAL.md) and is NOT CI
- Container IMAGE build and image scan are BLOCKED: no container runtime on the workstation
- Actions are pinned by tag, not commit SHA; base image by tag, not digest (to be pinned by CI)
- No DAST / penetration test has been performed
- **BLOCKED test:** container image build
- **BLOCKED test:** container image vulnerability scan
- **BLOCKED test:** CI runner execution

### F-GOV-002 — Secure configuration and startup validation
- Production start-up is intentionally IMPOSSIBLE until the KMS key provider and audit signer/WORM sink exist (O-4)

## Chain of evidence

For each row: *Implementation* (code/DB object) → *Test* (named automated tests, listed per case in `SECURITY_TEST_REPORT.md`) → *Result* (from `evidence/junit.xml`) → *Audit event* (the registered `audit.action_registry` actions the control emits; the tests assert they are written where noted) → *Evidence* (machine-generated files under `evidence/`, digests in `evidence/MANIFEST.json`).
