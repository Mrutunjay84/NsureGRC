# Blocked and not-implemented tests (Phase 1)

*Generated 2026-10-20.* A BLOCKED test is one that **cannot run** until infrastructure or a feature exists. It is not counted as a pass.

## BLOCKED — infrastructure or feature missing

| ID | Test that cannot run | Blocked by | Related control | Becomes runnable when |
|---|---|---|---|---|
| B-01 | cross-tenant SEARCH isolation | no search feature/index exists (Phase 2+) | F-AUZ-002 | a search endpoint or index is added (the endpoint-inventory test fails the build until this suite is extended) |
| B-02 | cross-tenant DOWNLOAD / export / report / job / notification isolation | no evidence storage, reporting or job features (Phase 3) | F-AUZ-002, F-DAT-004 | evidence download (C-6) and reporting exist |
| B-03 | context isolation behind a transaction-mode connection pooler | no PgBouncer/pooler in the environment | F-TEN-002 | a pooler is deployed in the test environment |
| B-04 | throttling behaviour when Redis is down | no Redis/cache infrastructure; throttling is DB-backed only | F-ATH-002 | Redis is introduced (ADR requires degradation to DB counters, never to unthrottled) |
| B-05 | scheduled audit verification and alert delivery | no worker/scheduler/monitoring stack | F-AUD-003 | scheduler and alert routing exist |
| B-06 | production audit anchoring (KMS signature, WORM sink) and key rotation | hosting / KMS / immutable storage not selected (open item O-4) | F-AUD-002, F-DAT-002 | O-4 is decided and implemented |
| B-07 | container image build and image vulnerability scan | no container runtime on the Phase 1 workstation (Docker/Podman absent) | F-GOV-001 | CI container job runs (defined in .github/workflows/ci.yml) |
| B-08 | execution of the CI workflow on a runner | no repository/CI service connected to this project yet | F-GOV-001 | repository is pushed and Actions enabled |
| B-09 | network-restricted operator hostname / VPN allow-list | hosting not selected (O-4) | F-PLT-001 | deployment topology exists |
| B-10 | Restricted-class content consent enforcement during support sessions | no Restricted-class content endpoints exist | F-PLT-002 | evidence / privacy modules exist |
| B-11 | hardware-authenticator and cross-browser WebAuthn interoperability | only a software authenticator is available | F-ATH-006 | manual/hardware test pass is scheduled |
| B-12 | dynamic application security testing (DAST) and penetration test | not performed; requires a deployed environment and independent testers | all | environment + testers available |

## NOT IMPLEMENTED — no code exists, so no test exists

| Control | What is missing | Why |
|---|---|---|
| F-AUD-004 Audit retention and purge procedure | whole control | Retention periods are open item O-2 (no values invented); purge procedure is Phase 2 |
| F-DAT-004 Authorization-checked evidence download (C-6) | whole control | Evidence handling is Phase 3. Cross-tenant download tests are BLOCKED until it exists |
| F-DAT-005 Evidence scan lifecycle and immutable revisions | whole control | Phase 3; malware engine choice is open item O-11 |
| F-ATH-011 Personal access tokens | whole control | Phase 2 |
| F-DR-001 Platform-level DR restore | whole control | Phase 2; RPO/RTO are open item O-3 (no values asserted) |
| F-DR-002 Erasure ledger replay after restore | whole control | Phase 2; legal review of erasure vs backups/audit retention is open item O-8 |
| F-FWK-001 Framework ingestion sandboxing (SSRF/XXE/archive limits) | whole control | Phase 2; framework content licensing is an open item (O-8) |

## Partially implemented — gaps inside implemented controls

| Control | Gap |
|---|---|
| F-TEN-002 | Connection-pooler (PgBouncer transaction mode) behaviour is BLOCKED: no pooler in the Phase 1 environment; the transaction-local set_config design is tested on a direct connection |
| F-TEN-004 | No CAT-class tables exist yet (framework catalogue is Phase 2); the CAT shape rules are implemented but unexercised |
| F-TEN-004 | Enforced by pytest; the CI job that runs it has not been executed on a CI runner |
| F-AUZ-002 | Cross-tenant SEARCH, DOWNLOAD, REPORT, NOTIFICATION and JOB tests are BLOCKED: those features do not exist in Phase 1 (test_endpoint_inventory_is_reviewed fails the build if such an endpoint appears without extending the suite) |
| F-PLT-001 | Separate hostname / network restriction (VPN or IP allow-list) is a deployment control: BLOCKED (hosting not selected, O-4) |
| F-PLT-001 | Platform-admin recovery process is organisational (O-5) |
| F-PLT-002 | Restricted-class consent is stored but unexercised (no Restricted-class content endpoints exist) |
| F-PLT-002 | write_limited profile has no write operations |
| F-PLT-002 | Module scope is stored but not enforced (no modules exist) |
| F-PLT-003 | Immediate e-mail/pager notification to tenant Owners NOT IMPLEMENTED (events appear in the tenant audit stream only) |
| F-PLT-003 | Post-incident review record/timer NOT IMPLEMENTED (process control; period is open item O-5) |
| F-PLT-005 | Tenant suspend/offboard lifecycle API NOT IMPLEMENTED (audit action exists; DB column and denial path are tested) |
| F-AUD-001 | A database SUPERUSER can still alter audit data; detection (not prevention) relies on external checkpoints - see F-AUD-002 |
| F-AUD-002 | Signing key is a DEV-ONLY file on the database host: NOT a production control |
| F-AUD-002 | Checkpoint export sink is a local directory, NOT WORM/immutable storage |
| F-AUD-002 | Production KMS signer, immutable storage and anchoring are NOT IMPLEMENTED (open item O-4) |
| F-AUD-002 | Cryptographic construction has not had an independent review (O-10) |
| F-AUD-003 | The verifier library runs on demand and records violations; a SCHEDULED job and alert routing are NOT IMPLEMENTED (needs worker/monitoring infrastructure) |
| F-DAT-001 | Handling rules for Confidential tenant content (export, retention, AI use) have no content to apply to yet (Phase 2+) |
| F-DAT-002 | Master key comes from the environment (DEV-ONLY local provider); KMS/HSM provider and key rotation are NOT IMPLEMENTED (open item O-4) |
| F-DAT-002 | Cryptographic review not done (O-10) |
| F-DAT-003 | The recovery-code pepper is an environment value (production: KMS-held, O-4) |
| F-ATH-001 | Blocklist is a SEED file, not a breach corpus (open item O-12) |
| F-ATH-001 | Production Argon2 parameters must be benchmarked on production hardware |
| F-ATH-002 | Counters are DB-backed only; Redis / distributed throttling and its failure-mode test are NOT IMPLEMENTED (no cache infrastructure) |
| F-ATH-003 | E-mail delivery domain authentication (SPF/DKIM/DMARC) is open item O-7 |
| F-ATH-004 | Email-change flow NOT IMPLEMENTED |
| F-ATH-006 | Exercised with a SOFTWARE authenticator only; no hardware-authenticator or browser interoperability testing |
| F-ATH-007 | Factor removal, recovery-code regeneration endpoint, admin-assisted recovery and the lost-factor cooling-off are NOT IMPLEMENTED |
| F-ATH-007 | A credential flagged as cloned currently leaves the user to recovery codes / out-of-band recovery (no workflow) |
| F-ATH-008 | Timeout values are NsureGRC baseline numbers, not standard-derived |
| F-ATH-008 | A user-facing 'list / revoke my sessions' API is NOT IMPLEMENTED |
| F-ATH-009 | PAT-vs-cookie separation tests are N/A until PATs exist (F-ATH-011) |
| F-ATH-010 | T2 actions for tenant deletion, privacy erasure, DR restore and platform role change are NOT IMPLEMENTED (the features do not exist); T2 is implemented for support-grant approval only |
| F-ATH-013 | No browser-rendered UI exists yet: XSS is tested at the API/response-header level only (output encoding for a future UI is out of scope) |
| F-ATH-013 | No dynamic scanner (DAST) has been run |
| F-GOV-001 | The GitHub Actions workflow is DEFINED but has NOT been executed on a CI runner (no repository/runner in this environment) |
| F-GOV-001 | Container IMAGE build and image scan are BLOCKED: no container runtime on the workstation |
| F-GOV-001 | Actions are pinned by tag, not commit SHA; base image by tag, not digest (to be pinned by CI) |
| F-GOV-001 | No DAST / penetration test has been performed |
| F-GOV-002 | Production start-up is intentionally IMPOSSIBLE until the KMS key provider and audit signer/WORM sink exist (O-4) |

## Gate steps reported BLOCKED by `scripts/security_gate.py`

- **container image build + scan** — no container runtime (docker/podman) on this machine; the CI workflow performs this gate
