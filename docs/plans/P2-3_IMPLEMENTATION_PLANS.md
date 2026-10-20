# P2-3 — Required controls (implemented) and production-security gates (still plans)

**Update 2026-10-21 (owner decision):** five controls are REQUIRED before Phase 2 can be considered security-ready and were implemented and tested; two remain **production-security gates** (not Phase 2 development blockers).
Status here is a pointer; the authoritative status is the generated `SECURITY_CONTROL_MATRIX.md`, and a control counts as implemented only because its tests exist and passed in the recorded run.

| # | Control | Class | Status | Where |
|---|---|---|---|---|
| 1 | Evidence download (F-DAT-004, F-DAT-005) | Phase-2 required | **Implemented + tested** (dev-only store and scanner) | ADR `00_CONTROL/PHASE1/D-P1-002`; `test_evidence_download.py`, `test_evidence_lifecycle.py` |
| 2 | Cross-tenant search (F-AUZ-005) | Phase-2 required | **Implemented + tested** (evidence metadata only) | ADR D-P1-002; `test_cross_tenant_search.py` |
| 3 | Scheduled audit verification (F-AUD-007) | Phase-2 required | **Implemented + tested** (alert delivery blocked on O-4) | ADR `D-P1-003`; `test_scheduled_verification.py`, `test_audit_completeness.py` |
| 4 | MFA factor removal (F-ATH-014) | Phase-2 required | **Implemented + tested** | ADR `D-P1-004`; `test_factor_removal.py` |
| 5 | Lost-factor recovery (F-ATH-015) | Phase-2 required | **Implemented + tested** (mail delivery, procedures open) | ADR D-P1-004; `test_lost_factor_recovery.py` |
| 6 | Production KMS (F-DAT-006) | **Production gate** | **NOT IMPLEMENTED / BLOCKED on O-4** | section 6 below |
| 7 | Immutable (WORM) audit storage (F-AUD-006) | **Production gate** | **NOT IMPLEMENTED / BLOCKED on O-4** | section 7 below |

"Implemented and tested" is **not** "independently reviewed" (P2-2 is BLOCKED) and not "production-ready": every dev-only stand-in (local object store, EICAR scanner, local key provider, file signer, rewritable export file, log-only alerts) is labelled in code, in the reports and by a refusal in `config.settings.prod`.
No production-readiness claim may be made while items 6 and 7 are open. Development stand-ins are acceptable only while they stay clearly marked and cannot start in production.

**Mutation evidence:** for the implemented controls, security-critical lines were disabled one at a time and the named tests had to fail (`evidence/p2_*_mutation_check.txt`, `evidence/h11_mutation_check.txt`); survivors were either strengthened with new tests or documented as equivalent mutants (a second layer enforces the same property).

---

## 6. Production key management (KMS) — F-DAT-006 (D-P0-006 §5, D-P0-007 §3; open item O-4)  ·  BLOCKED

**Requirement.** Envelope encryption with a KMS-held key; audit-checkpoint signing with a **sign-only, non-exportable** KMS/HSM key the application
roles cannot read; key versions stored beside ciphertext so rotation keeps old data readable; KMS use audited; separate keys for data, audit signing
and backups; production refuses to start with dev providers.

**Current state.** `ngrc.core.crypto` implements real AES-256-GCM envelope encryption but the master key comes from the environment (single key, no
versions, rotation would orphan data) and `DevFileSigner` keeps an Ed25519 private key in a file. `config.settings.prod` refuses both by design.
These are **DEV-ONLY** and are labelled so in code, reports and every exported record.

**Planned interface (provider-neutral).** `ngrc/core/keys.py`: `KeyProvider` protocol (`seal`, `open`, `rotate`, `key_id`) with `LocalKeyProvider`
(the existing code, dev-only) and `KmsKeyProvider`; `ngrc.audit.signer.KmsSigner` (`sign`, `verify`, no private-key attribute);
`config/settings/prod_check.validate()` asserting KMS backends and no key material in settings. A **provider conformance suite** is the main
deliverable that can be built now — the same tests run against any provider. **No provider is selected here (O-4).**

**What runs today:** two *gap demos* — old ciphertext is unreadable after a master-key change; the dev signing key is readable by the signing
process. **Specs:** 4 (`test_kms_provider_envelope_round_trip…`, `…keeps_old_ciphertext_readable_after_rotation`, `…signer_is_sign_only…`,
`…production_settings_start_only_with_kms_backends…`). **Review:** crypto design → P2-2, **mandatory** before any provider goes live.
**Cannot be tested without infrastructure (stays BLOCKED even after the code exists):** IAM separation of key roles, non-exportability, KMS audit trail,
rotation under load — these need the real provider account.

## 7. Immutable (WORM) audit storage and external anchoring — F-AUD-006 (D-P0-006 §5; open item O-4)  ·  BLOCKED

**Requirement.** Signed checkpoints are exported to write-once storage in a **separate account/failure domain** and to the SIEM; the verifier compares
the database checkpoints with the external copy; sink outage degrades the *detection window*, not event capture.

**Current state (after H-11, D-P1-003).** The sealer publishes chained, heartbeat-sealed checkpoints to a local JSON-lines file labelled `NOT WORM`; the verifier compares database and export in **both** directions (W-3 is DONE and tested), reports `consistent` at best, and `config.settings.prod` refuses to start unless `AUDIT_SINK_IMMUTABLE` is true.
What is missing is the sink itself: an attacker who can write the export file can still hide the newest checkpoint if no earlier verification run remembers it.

**Plan items.**
* **W-1** `ngrc/audit/sinks.py`: `Sink` protocol (`append` → receipt, `read`, `list`, no delete/overwrite) with `LocalFileSink` (dev) and `WormSink`.
* **W-2** Sealer marks a checkpoint *published* only after the sink acknowledges it; sink failure raises a lag alert but never blocks business transactions.
* ~~W-3~~ **DONE (H-11):** every database checkpoint older than the grace window must have a sink copy, and every sink record must exist in the database unchanged (`test_removing_the_newest_external_copy_is_caught` and friends).
* **W-4** The WORM provider (object lock/compliance-mode retention, separate account, write-only credentials for the sealer, read-only for the verifier) — **blocked on O-4**; lock/retention durations depend on O-2. Only this item allows `completeness = established`.
* **W-5** Checkpoint-lag and sink-failure alert DELIVERY (the alert interface exists; delivery is blocked on O-4).
* **W-6** Restore drill using sink checkpoints (D-P0-004) — blocked on a hosting/backup design (O-3, O-4).

**What runs today:** one gap demo ("dev export file is rewritable by the application process"). **Specs:** 4 (`test_worm_sink_refuses_overwrite_delete_and_truncate…`, `…credentials_the_application…do_not_hold`, `…does_not_report_a_checkpoint_published_until…`,
`…verifier_compares_database_checkpoints_with_the_sink_copy`). Real WORM semantics (retention lock, account separation) **cannot be tested without the provider** and stay BLOCKED after the interface exists. **Review:** P2-2 scope.

---

## 8. Counts (from the last real run — see `SECURITY_TEST_REPORT.md`)
Pending specs and demos: **11** test cases in `tests/test_pending_controls.py` (+1 harness self-test that passes), all XFAIL, all for the two production gates (KMS, WORM). Three are *gap demos* that execute against dev stand-ins. **None of these numbers is evidence that a control works.**
