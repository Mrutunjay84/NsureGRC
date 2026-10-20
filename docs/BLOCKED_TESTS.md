# Blocked and not-implemented tests (Phase 1)

*Generated 2026-10-20.* A BLOCKED test is one that **cannot run** until infrastructure or a feature exists. It is not counted as a pass.

## BLOCKED — infrastructure or feature missing

| ID | Test that cannot run | Blocked by | Related control | Becomes runnable when |
|---|---|---|---|---|
| B-02 | cross-tenant EXPORT / REPORT / JOB / NOTIFICATION isolation (search and download are now tested: F-AUZ-005, F-DAT-004) | no export, reporting, job or notification features exist | F-AUZ-002 | those features are added (the endpoint-inventory test fails the build until the suite is extended) |
| B-03 | context isolation behind a transaction-mode connection pooler | no PgBouncer/pooler in the environment | F-TEN-002 | a pooler is deployed in the test environment |
| B-04 | throttling behaviour when Redis is down | no Redis/cache infrastructure; throttling is DB-backed only | F-ATH-002 | Redis is introduced (ADR requires degradation to DB counters, never to unthrottled) |
| B-05 | DELIVERY of audit/security alerts to a real channel (pager, SIEM, e-mail); scheduling on real infrastructure; a separate-host watchdog | hosting / monitoring stack not selected (O-4); alerts reach the log pipeline only | F-AUD-007, F-ATH-002 | alert routing exists and is tested end to end |
| B-06 | production audit anchoring (KMS signature, WORM sink) and key rotation (7 specs + 3 gap demos, all XFAIL) | hosting / KMS / immutable storage not selected (open item O-4) | F-AUD-006, F-DAT-006 | O-4 is decided and implemented |
| B-07 | container image build and image vulnerability scan | no container runtime on the Phase 1 workstation (Docker/Podman absent) | F-GOV-005 | CI container job runs (defined in .github/workflows/ci.yml) |
| B-08 | execution of the CI workflow on a runner | no repository/CI service connected to this project yet; pushing project code externally needs the owner's decision | F-GOV-005 | repository is pushed, Actions enabled, and docs/ci/CI_RUN_RECORD.yaml filled from the real run |
| B-09 | network-restricted operator hostname / VPN allow-list | hosting not selected (O-4) | F-PLT-001 | deployment topology exists |
| B-10 | Restricted-class content consent enforcement during support sessions | no Restricted-class content endpoints exist | F-PLT-002 | evidence / privacy modules exist |
| B-11 | hardware-authenticator and cross-browser WebAuthn interoperability | only a software authenticator is available | F-ATH-006 | manual/hardware test pass is scheduled |
| B-15 | real-mailbox delivery of recovery / factor-removal notifications | no e-mail provider (O-7) | F-ATH-015, F-ATH-014 | provider configured; delivery and authentication (SPF/DKIM/DMARC) tested |
| B-16 | real private object store and malware-scanning engine for evidence | hosting not selected (O-4); no engine selected (O-11) | F-DAT-004, F-DAT-005 | store and engine chosen; the same tests run against them |
| B-12 | dynamic application security testing (DAST) and penetration test | not performed; requires a deployed environment and independent testers | all | environment + testers available |
| B-13 | independent cryptographic / AppSec review of audit hash, checkpoints, AEAD helper, authentication/session/MFA | no independent reviewer engaged; package prepared (docs/review/) | F-GOV-004 | a reviewer's signed report is recorded in docs/review/REVIEW_RECORD.yaml and scripts/check_review_record.py reports COMPLETE |
| B-14 | tests that need the real KMS/WORM provider (IAM key separation, non-exportability, retention lock, account separation) | provider not selected (O-4) | F-DAT-006, F-AUD-006 | provider chosen; interface conformance suite extended with integration tests |

## NOT IMPLEMENTED — no code exists, so no test exists

| Control | What is missing | Why |
|---|---|---|
| F-AUD-006 Immutable (WORM) audit checkpoint storage and external anchoring | whole control | Hosting/KMS/WORM provider not selected (open item O-4); retention lock periods depend on O-2; The verifier's two-way external-copy comparison and the `AUDIT_SINK_IMMUTABLE` gate EXIST (F-AUD-002) but the sink itself is a rewritable dev file: completeness cannot exceed 'consistent' until a WORM sink exists; A gap demo runs today and is expected to fail its assertion (XFAIL): the dev export file is rewritable by the application process |
| F-AUD-004 Audit retention and purge procedure | whole control | Retention periods are open item O-2 (no values invented); purge procedure is Phase 2 |
| F-ATH-011 Personal access tokens | whole control | Phase 2 |
| F-DAT-006 Production key management (KMS) for data encryption and audit signing | whole control | Provider not selected (open item O-4); independent cryptographic review is mandatory before use (F-GOV-004); Two gap demos run today against the dev stand-ins and are expected to fail their assertions (XFAIL): no key versions/rotation; dev signing key readable by the signing process; IAM separation, non-exportability, KMS audit trail and rotation under load can only be tested with the real provider account |
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
| F-AUZ-002 | Cross-tenant SEARCH (F-AUZ-005) and DOWNLOAD (F-DAT-004) are now tested; REPORT, EXPORT, NOTIFICATION and JOB tests remain BLOCKED: those features do not exist (test_endpoint_inventory_is_reviewed fails the build if such an endpoint appears without extending the suite) |
| F-PLT-001 | Separate hostname / network restriction (VPN or IP allow-list) is a deployment control: BLOCKED (hosting not selected, O-4) |
| F-PLT-001 | Platform-admin recovery process is organisational (O-5) |
| F-PLT-002 | Restricted-class consent is stored but unexercised (no Restricted-class content endpoints exist) |
| F-PLT-002 | write_limited profile has no write operations |
| F-PLT-002 | Module scope is stored but not enforced (no modules exist) |
| F-PLT-003 | Immediate e-mail/pager notification to tenant Owners NOT IMPLEMENTED (events appear in the tenant audit stream only) |
| F-PLT-003 | Post-incident review record/timer NOT IMPLEMENTED (process control; period is open item O-5) |
| F-PLT-005 | Tenant suspend/offboard lifecycle API NOT IMPLEMENTED (audit action exists; DB column and denial path are tested) |
| F-AUD-001 | A database SUPERUSER can still alter audit data; detection (not prevention) relies on external checkpoints - see F-AUD-002 |
| F-AUD-002 | H-11 (D-P1-003): checkpoints are chained, heartbeat-sealed and verified against anchors, but COMPLETENESS cannot exceed 'consistent' until an immutable sink exists - every anchor is currently rewritable by a schema-owner attacker; events after the newest honest checkpoint are covered by chain consistency only |
| F-AUD-002 | Signing key is a DEV-ONLY file on the database host: NOT a production control |
| F-AUD-002 | Checkpoint export sink is a local directory, NOT WORM/immutable storage (see F-AUD-006) |
| F-AUD-002 | Production KMS signer is NOT IMPLEMENTED (F-DAT-006, open item O-4) |
| F-AUD-002 | Cryptographic construction has NOT had an independent review: BLOCKED, no reviewer (F-GOV-004) |
| F-AUD-003 | The scheduled job, watchdog and incremental mode are the separate control F-AUD-007 |
| F-AUD-003 | Completeness against anchors is covered by F-AUD-002 (D-P1-003) |
| F-AUD-007 | Alert DELIVERY (pager/SIEM/e-mail) is NOT IMPLEMENTED: alerts reach the log pipeline only (O-4) |
| F-AUD-007 | The scheduler is a command / worker loop; WHERE it runs (cron, CronJob, a separate host for the watchdog) is a deployment decision (O-4) |
| F-AUD-007 | Incremental runs do not recompute already-verified events; a periodic FULL run is required (tested, documented) |
| F-AUD-007 | Thresholds are BASELINE pending approval |
| F-AUD-007 | Not independently reviewed (F-GOV-004 BLOCKED) |
| F-DAT-001 | Handling rules for Confidential tenant content (export, retention, AI use) have no content to apply to yet (Phase 2+) |
| F-DAT-002 | Master key comes from the environment (DEV-ONLY local provider); KMS/HSM provider and key rotation are NOT IMPLEMENTED (F-DAT-006, open item O-4) |
| F-DAT-002 | Cryptographic review NOT done: BLOCKED, no independent reviewer (F-GOV-004) |
| F-DAT-003 | The recovery-code pepper is an environment value (production: KMS-held, O-4) |
| F-DAT-004 | The object store is a DEV-ONLY local directory: no private object store exists (open item O-4); production start-up refuses it |
| F-DAT-004 | D-EV-1 (pre-verification into a bounded spool) is an INTERIM decision awaiting owner approval |
| F-DAT-004 | Orphaned objects (stored, request failed before COMMIT) need a sweep: NOT IMPLEMENTED |
| F-DAT-004 | Bulk/Restricted export, retention, legal hold and deletion do not exist |
| F-DAT-004 | Not independently reviewed |
| F-DAT-005 | The scanner is a DEV-ONLY EICAR stand-in: MALWARE DETECTION IS NOT PROVIDED, only the quarantine mechanics (open item O-11); production start-up refuses it |
| F-DAT-005 | Nested archives inside OOXML packages are not inspected |
| F-DAT-005 | Legal hold / retention / purge are later workflows (O-2, O-8) |
| F-ATH-001 | Blocklist is a SEED file, not a breach corpus (open item O-12) |
| F-ATH-001 | Production Argon2 parameters must be benchmarked on production hardware |
| F-ATH-002 | TEMPORARY (DEF-15 mitigated-temporary): the D-P0-008 hard stop is suspended; an attacker can still keep a victim waiting up to the delay cap; no cross-account distributed-attack detection; alert delivery beyond the log pipeline is NOT IMPLEMENTED (O-4) |
| F-ATH-002 | Counters are DB-backed only; Redis / distributed throttling and its failure-mode test are NOT IMPLEMENTED (no cache infrastructure) |
| F-ATH-002 | Numeric values are BASELINE pending approval |
| F-ATH-003 | E-mail delivery domain authentication (SPF/DKIM/DMARC) is open item O-7 |
| F-ATH-004 | Email-change flow NOT IMPLEMENTED |
| F-ATH-006 | Exercised with a SOFTWARE authenticator only; no hardware-authenticator or browser interoperability testing |
| F-ATH-007 | Factor removal (F-ATH-014) and lost-factor recovery (F-ATH-015) are implemented as separate controls; the recovery-code REGENERATION endpoint is still missing |
| F-ATH-007 | A credential flagged as cloned leaves the user to recovery codes or the F-ATH-015 workflow |
| F-ATH-008 | Timeout values are NsureGRC baseline numbers, not standard-derived |
| F-ATH-008 | A user-facing 'list / revoke my sessions' API is NOT IMPLEMENTED |
| F-ATH-009 | PAT-vs-cookie separation tests are N/A until PATs exist (F-ATH-011) |
| F-ATH-010 | T2 actions for tenant deletion, privacy erasure, DR restore and platform role change are NOT IMPLEMENTED (the features do not exist); T2 is implemented for support-grant approval only |
| F-ATH-013 | No browser-rendered UI exists yet: XSS is tested at the API/response-header level only (output encoding for a future UI is out of scope) |
| F-ATH-013 | No dynamic scanner (DAST) has been run |
| F-AUZ-005 | Searches evidence METADATA only (title, description) with the 'simple' configuration; no content indexing, no language handling |
| F-AUZ-005 | Applies only to the one searchable resource that exists; every future searchable resource needs the same tests (the endpoint inventory test fails the build for new search routes) |
| F-AUZ-005 | Not independently reviewed |
| F-ATH-014 | Tenant-Owner 'WebAuthn-only' tightening needs a tenant policy feature that does not exist |
| F-ATH-014 | E-mail change flow NOT IMPLEMENTED |
| F-ATH-014 | Not independently reviewed (F-GOV-004 BLOCKED) |
| F-ATH-015 | Real notification delivery needs an e-mail provider (O-7); notifications are only as good as the user's mailbox |
| F-ATH-015 | Platform Security's identity verification of a sole Owner is an organisational procedure that does not exist (O-5, O-8) |
| F-ATH-015 | Operator-realm MFA recovery is NOT IMPLEMENTED (organisational procedure) |
| F-ATH-015 | Tenant-plane approval trusts app.principal_id (runtime-role-settable): see review concern 19 |
| F-ATH-015 | Post-recovery enrolment is protected only by a short window (see D-P1-004) |
| F-ATH-015 | Not independently reviewed (F-GOV-004 BLOCKED) |
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
