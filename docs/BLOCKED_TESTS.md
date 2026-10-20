# Blocked and not-implemented tests (Phase 1)

*Generated 2026-10-20.* A BLOCKED test is one that **cannot run** until infrastructure or a feature exists. It is not counted as a pass.

## BLOCKED — infrastructure or feature missing

| ID | Test that cannot run | Blocked by | Related control | Becomes runnable when |
|---|---|---|---|---|
| B-01 | cross-tenant SEARCH isolation (5 executable specs, XFAIL) | no search feature/index exists (Phase 2+) | F-AUZ-005 | a search endpoint or index is added (the endpoint-inventory test fails the build until this suite is extended) |
| B-02 | cross-tenant DOWNLOAD / export / report / job / notification isolation (download: 10 specs, XFAIL) | no evidence storage, reporting or job features (Phase 3) | F-AUZ-002, F-DAT-004 | evidence download (C-6) and reporting exist |
| B-03 | context isolation behind a transaction-mode connection pooler | no PgBouncer/pooler in the environment | F-TEN-002 | a pooler is deployed in the test environment |
| B-04 | throttling behaviour when Redis is down | no Redis/cache infrastructure; throttling is DB-backed only | F-ATH-002 | Redis is introduced (ADR requires degradation to DB counters, never to unthrottled) |
| B-05 | scheduled audit verification and alert delivery (6 executable specs, XFAIL) | no worker/scheduler/monitoring stack | F-AUD-007 | scheduler and alert routing exist |
| B-06 | production audit anchoring (KMS signature, WORM sink) and key rotation (8 specs + 4 gap demos, all XFAIL) | hosting / KMS / immutable storage not selected (open item O-4) | F-AUD-006, F-DAT-006 | O-4 is decided and implemented |
| B-07 | container image build and image vulnerability scan | no container runtime on the Phase 1 workstation (Docker/Podman absent) | F-GOV-005 | CI container job runs (defined in .github/workflows/ci.yml) |
| B-08 | execution of the CI workflow on a runner | no repository/CI service connected to this project yet; pushing project code externally needs the owner's decision | F-GOV-005 | repository is pushed, Actions enabled, and docs/ci/CI_RUN_RECORD.yaml filled from the real run |
| B-09 | network-restricted operator hostname / VPN allow-list | hosting not selected (O-4) | F-PLT-001 | deployment topology exists |
| B-10 | Restricted-class content consent enforcement during support sessions | no Restricted-class content endpoints exist | F-PLT-002 | evidence / privacy modules exist |
| B-11 | hardware-authenticator and cross-browser WebAuthn interoperability | only a software authenticator is available | F-ATH-006 | manual/hardware test pass is scheduled |
| B-12 | dynamic application security testing (DAST) and penetration test | not performed; requires a deployed environment and independent testers | all | environment + testers available |
| B-13 | independent cryptographic / AppSec review of audit hash, checkpoints, AEAD helper, authentication/session/MFA | no independent reviewer engaged; package prepared (docs/review/) | F-GOV-004 | a reviewer's signed report is recorded in docs/review/REVIEW_RECORD.yaml and scripts/check_review_record.py reports COMPLETE |
| B-14 | tests that need the real KMS/WORM provider (IAM key separation, non-exportability, retention lock, account separation) | provider not selected (O-4) | F-DAT-006, F-AUD-006 | provider chosen; interface conformance suite extended with integration tests |

## NOT IMPLEMENTED — no code exists, so no test exists

| Control | What is missing | Why |
|---|---|---|
| F-AUD-007 Scheduled continuous audit verification with alerting | whole control | Plan: docs/plans/P2-3_IMPLEMENTATION_PLANS.md s3. Needs a scheduler (deployment choice, O-4) and an alert channel (SIEM/pager, O-4) |
| F-AUD-006 Immutable (WORM) audit checkpoint storage and external anchoring | whole control | Hosting/KMS/WORM provider not selected (open item O-4); retention lock periods depend on O-2; Two gap demos run today against the dev sink and are expected to fail their assertions (XFAIL): the dev export is a rewritable plain file, and removing the newest exported checkpoint goes undetected |
| F-AUD-004 Audit retention and purge procedure | whole control | Retention periods are open item O-2 (no values invented); purge procedure is Phase 2 |
| F-DAT-004 Authorization-checked evidence download (C-6) | whole control | Evidence handling is Phase 3. Cross-tenant download tests are BLOCKED until it exists; Plan: docs/plans/P2-3_IMPLEMENTATION_PLANS.md s1; decision D-EV-1 (integrity verification mode) and the object store (O-4) are open |
| F-DAT-005 Evidence scan lifecycle and immutable revisions | whole control | Phase 3; malware engine choice is open item O-11 |
| F-ATH-011 Personal access tokens | whole control | Phase 2 |
| F-AUZ-005 Cross-tenant search isolation | whole control | No search feature exists (B-01). Plan: docs/plans/P2-3_IMPLEMENTATION_PLANS.md s2; decision D-SR-1 (PostgreSQL FTS under RLS vs external index) is open |
| F-DAT-006 Production key management (KMS) for data encryption and audit signing | whole control | Provider not selected (open item O-4); independent cryptographic review is mandatory before use (F-GOV-004); Two gap demos run today against the dev stand-ins and are expected to fail their assertions (XFAIL): no key versions/rotation; dev signing key readable by the signing process; IAM separation, non-exportability, KMS audit trail and rotation under load can only be tested with the real provider account |
| F-ATH-014 MFA factor removal | whole control | No factor listing or removal endpoint exists. Plan: docs/plans/P2-3_IMPLEMENTATION_PLANS.md s4 |
| F-ATH-015 Lost-factor recovery and lock-out exit | whole control | OPEN DEFECT DEF-15: accounts reach recovery_required after repeated failures but have no unlock path (lock-out DoS) - decision needed from the project owner; Needs real e-mail delivery (O-7) for notifications; platform-approver staffing (O-5). Plan: docs/plans/P2-3_IMPLEMENTATION_PLANS.md s5 |
| F-DR-001 Platform-level DR restore | whole control | Phase 2; RPO/RTO are open item O-3 (no values asserted) |
| F-DR-002 Erasure ledger replay after restore | whole control | Phase 2; legal review of erasure vs backups/audit retention is open item O-8 |
| F-FWK-001 Framework ingestion sandboxing (SSRF/XXE/archive limits) | whole control | Phase 2; framework content licensing is an open item (O-8) |

## BLOCKED controls — the evidence is a human-supplied record that does not exist

| Control | Status | What is missing |
|---|---|---|
| F-GOV-004 Independent cryptographic / AppSec review (audit hash, checkpoints, AEAD helper, authentication/session/MFA) | **BLOCKED** | the review itself |
| F-GOV-005 CI workflow executed on an independent runner | **BLOCKED** | CI runner execution; container image build and scan; full-history secret scan |

## Partially implemented — gaps inside implemented controls

| Control | Gap |
|---|---|
| F-TEN-002 | Connection-pooler (PgBouncer transaction mode) behaviour is BLOCKED: no pooler in the Phase 1 environment; the transaction-local set_config design is tested on a direct connection |
| F-TEN-004 | No CAT-class tables exist yet (framework catalogue is Phase 2); the CAT shape rules are implemented but unexercised |
| F-TEN-004 | Enforced by pytest; the CI job that runs it has not been executed on a CI runner |
| F-AUZ-002 | Cross-tenant SEARCH (F-AUZ-005), DOWNLOAD (F-DAT-004), REPORT, NOTIFICATION and JOB tests are BLOCKED: those features do not exist in Phase 1 (test_endpoint_inventory_is_reviewed fails the build if such an endpoint appears without extending the suite) |
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
| F-AUD-002 | Checkpoint export sink is a local directory, NOT WORM/immutable storage (see F-AUD-006) |
| F-AUD-002 | Production KMS signer is NOT IMPLEMENTED (F-DAT-006, open item O-4) |
| F-AUD-002 | Cryptographic construction has NOT had an independent review: BLOCKED, no reviewer (F-GOV-004) |
| F-AUD-003 | On-demand only: the SCHEDULED job, alert routing, freshness alert and incremental mode are a separate, NOT IMPLEMENTED control - F-AUD-007 |
| F-AUD-003 | Does not require every database checkpoint to have an external copy (demonstrated by a gap demo; plan item W-3, see F-AUD-006) |
| F-DAT-001 | Handling rules for Confidential tenant content (export, retention, AI use) have no content to apply to yet (Phase 2+) |
| F-DAT-002 | Master key comes from the environment (DEV-ONLY local provider); KMS/HSM provider and key rotation are NOT IMPLEMENTED (F-DAT-006, open item O-4) |
| F-DAT-002 | Cryptographic review NOT done: BLOCKED, no independent reviewer (F-GOV-004) |
| F-DAT-003 | The recovery-code pepper is an environment value (production: KMS-held, O-4) |
| F-ATH-001 | Blocklist is a SEED file, not a breach corpus (open item O-12) |
| F-ATH-001 | Production Argon2 parameters must be benchmarked on production hardware |
| F-ATH-002 | Counters are DB-backed only; Redis / distributed throttling and its failure-mode test are NOT IMPLEMENTED (no cache infrastructure) |
| F-ATH-003 | E-mail delivery domain authentication (SPF/DKIM/DMARC) is open item O-7 |
| F-ATH-004 | Email-change flow NOT IMPLEMENTED |
| F-ATH-006 | Exercised with a SOFTWARE authenticator only; no hardware-authenticator or browser interoperability testing |
| F-ATH-007 | Factor removal (F-ATH-014), admin-assisted recovery, the lost-factor cooling-off and the lock-out exit (F-ATH-015) are NOT IMPLEMENTED; the recovery-code regeneration endpoint is also missing |
| F-ATH-007 | A credential flagged as cloned currently leaves the user to recovery codes / out-of-band recovery (no workflow) |
| F-ATH-008 | Timeout values are NsureGRC baseline numbers, not standard-derived |
| F-ATH-008 | A user-facing 'list / revoke my sessions' API is NOT IMPLEMENTED |
| F-ATH-009 | PAT-vs-cookie separation tests are N/A until PATs exist (F-ATH-011) |
| F-ATH-010 | T2 actions for tenant deletion, privacy erasure, DR restore and platform role change are NOT IMPLEMENTED (the features do not exist); T2 is implemented for support-grant approval only |
| F-ATH-013 | No browser-rendered UI exists yet: XSS is tested at the API/response-header level only (output encoding for a future UI is out of scope) |
| F-ATH-013 | No dynamic scanner (DAST) has been run |
| F-GOV-004 | The tests prove the RECORD CHECKER refuses self-approval, AI/tool reviewers, undated or unsigned reviews and reviews of different code; they say nothing about the design under review |
| F-GOV-004 | Package prepared; no reviewer has been engaged: status BLOCKED |
| F-GOV-005 | The tests prove the RECORD CHECKER refuses to call CI passed without a real run; they are not a CI run |
| F-GOV-005 | No repository/runner exists; pushing code to an external service needs the project owner's decision: status BLOCKED |
| F-GOV-001 | The GitHub Actions workflow is DEFINED and lint-checked (actionlint) but has NOT been executed on a CI runner (F-GOV-005, BLOCKED); a local clean-room rehearsal ran the same command lines (docs/ci/LOCAL_REHEARSAL.md) and is NOT CI |
| F-GOV-001 | Container IMAGE build and image scan are BLOCKED: no container runtime on the workstation |
| F-GOV-001 | Actions are pinned by tag, not commit SHA; base image by tag, not digest (to be pinned by CI) |
| F-GOV-001 | No DAST / penetration test has been performed |
| F-GOV-002 | Production start-up is intentionally IMPOSSIBLE until the KMS key provider and audit signer/WORM sink exist (O-4) |

## Gate steps reported BLOCKED by `scripts/security_gate.py`

- **container image build + scan** — no container runtime (docker/podman) on this machine; the CI workflow performs this gate
- **CI workflow execution on a runner** — no CI run recorded (docs/ci/CI_RUN_RECORD.yaml); no repository/runner
- **independent crypto/AppSec review** — no independent reviewer has reviewed any scope (docs/review/REVIEW_RECORD.yaml)
