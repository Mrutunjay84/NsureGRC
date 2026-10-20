# P2-3 — Implementation plans and executable specifications for the missing controls

**Status of every control in this document: NOT IMPLEMENTED or BLOCKED.** Nothing here is built. What exists is (a) this plan and
(b) `tests/test_pending_controls.py`, which holds the executable specifications. They run in every test run and are reported as
**XFAIL** (not implemented) — never as passed. Phase 2 feature development has not started and these plans do not authorise it.

## 0. How to read this, and the rules every item follows

* **Source of requirements:** the approved Phase 0 ADRs (D-P0-004, -006, -007, -008, -009) and approvals C-1…C-6. Where an ADR gives a
  `[BASELINE]` value (for example the 24 h cooling-off) the plan uses it as a *configurable default pending approval*, not as a standard.
* **No invented decisions.** Anything that is an open item (O-1…O-12) is named as a dependency and left open. In particular this plan does
  **not** choose a cloud/KMS/WORM provider (O-4), retention periods (O-2), RPO/RTO (O-3) or e-mail infrastructure (O-7).
* **Specs vs. gap demos.** `FeatureAbsent` specs stop at their first `require_route`/`require_symbol` call; the lines after it have **never
  executed against an implementation** and may need correction when the feature exists. *Gap demos* run today against the dev-only
  stand-ins and fail an assertion that states the production property — they demonstrate that the stand-in does not provide it.
* **Definition of done (applies to every section):**
  1. Implementation merged with the interfaces below (or a documented, reviewed deviation).
  2. The control's spec tests pass **with only the `@pending` marker removed** (fixtures/factories named in the spec supplied by the
     feature); strict xfail makes an unexpected pass fail the run, so removing the marker is a deliberate, reviewed act.
  3. Full suite green in CI (P2-1) including the RLS/IDOR/default-deny inventory tests, which fail the build if a new route lacks a policy.
  4. `docs/control_map.yaml` updated (remove `not_implemented`, map the tests), reports regenerated from the real run.
  5. Audit actions registered in a new audit-registry migration; the audit/event assertions in the specs pass.
  6. Independent review where a cryptographic or authentication design is involved (sections 4–7; see P2-2).
* **Order and dependencies**

| # | Control | Depends on | Can start before O-4? |
|---|---|---|---|
| 3 | Scheduled audit verification | alert channel (interface now; real routing with O-4/SIEM) | Yes (library + CLI + dev alert log) |
| 4 | Factor removal | none new | Yes |
| 5 | Lost-factor recovery | 4; e-mail delivery (O-7) for real notifications | Yes, with the dev mail backend labelled as such |
| 7 | Immutable audit storage | O-4 for the real sink; W-1…W-3 do not need it | Interface + verifier rule: yes; WORM sink: **no** |
| 6 | Production KMS | O-4; independent crypto review | Interface + conformance suite: yes; provider: **no** |
| 1 | Evidence download | evidence module, storage (O-4), scan pipeline | No (module does not exist) |
| 2 | Cross-tenant search | a search feature (not scheduled) | No |

---

## 1. Evidence download — F-DAT-004 / F-DAT-005 (decision C-6; D-P0-007 §5)  ·  NOT IMPLEMENTED

**Requirement.** Evidence is downloaded only through an authorization-checked **application endpoint** that streams from private storage;
no signed storage URLs in P0. Files are downloadable only after a clean scan (A5). Every download is audited with object, revision hash,
actor and result. Restricted-class evidence is not bulk-exportable.

**Current state.** No evidence module, storage adapter, scan pipeline or download route exists. Isolation of future tenant tables is
already enforced by RLS, and `test_endpoint_inventory_is_reviewed` fails the build if a new route lacks a policy.

**Planned interface.** `GET /api/v1/tenant/evidence/{evidence_id}/revisions/{revision_id}/download/` (`ngrc.evidence`).
Policy `("tenant", "evidence.read")`; Restricted class needs the elevated permission. Order of operations (fail-closed):
authorize (RLS-scoped lookup → 404 on miss) → check scan state (`collected`/`in_review` only) → **write `evidence.downloaded` (fail-closed, C-4)**
→ open object stream → integrity check → stream with `Content-Disposition: attachment` (server-generated name), `X-Content-Type-Options: nosniff`,
`Cache-Control: no-store`, no redirect. Object key `tenants/{tenant_id}/…` is generated server-side from UUIDs only. New audit actions:
`evidence.downloaded`, `evidence.hash_mismatch` (registered in a new audit migration). Test-support factory `ngrc.evidence.testing.make_evidence`.

**Decision needed (not made here).** *D-EV-1:* integrity verification mode — verify the stored SHA-256 before releasing any byte (buffering/temp
file, bounded size) versus verify while streaming and abort + alert on mismatch (bytes already released). Needs Platform Security + product approval.

**Threats the specs cover:** cross-tenant read via guessed ids (404 + denial audit, identical body for unknown revision); IDOR on revision ids;
path traversal in names/keys; serving unscanned/quarantined files; object tampered behind its hash; audit outage releasing data; support sessions
reaching content under a metadata-only grant; Restricted data in bulk export; content-type sniffing / inline execution.

**Specs:** `test_download_streams_exact_bytes…`, `…requires_authentication_and_the_evidence_read_permission`, `…cross_tenant_download…`,
`…download_event_records…`, `…unscanned_or_quarantined…` (2 cases), `…no_longer_matches_its_recorded_hash…`, `…fails_closed_when_the_audit_event…`,
`…support_session_cannot_download…`, `…restricted_class_evidence_is_excluded_from_bulk_export`, `…object_keys_are_tenant_prefixed…` (10 specs, 11 cases).
**Blocked tests this unblocks:** B-02 (download part). **Open items:** O-4 (private object store), O-2 (retention/legal hold).

## 2. Cross-tenant search — F-AUZ-005 (D-P0-003 testing requirement 5)  ·  BLOCKED (no search feature exists)

**Requirement.** Search results, snippets, facets, counts and suggestions never contain another tenant's data; hits are re-authorised before use;
every index document and query carries `tenant_id`.

**Current state.** No search feature. The route-inventory test would fail the build if one appeared without this suite being extended.

**Planned approach (two options, decision needed *D-SR-1*, not made here).** (A) PostgreSQL full-text search over tenant tables so RLS applies
unchanged and there is no derived store (smaller attack surface); (B) an external index (class EPH in D-P0-009) with `tenant_id` mandatory in every
document, a server-side filter the client cannot influence, and per-hit re-authorisation. The specs are written to pass for either; option (B)
additionally needs `ngrc.search.index.all_documents` (checked by the "every document carries tenant_id" spec).

**Specs:** `test_search_returns_only_the_callers_tenant`, `…without_valid_tenant_context_fails_closed`, `…hits_are_reauthorised_per_item…`,
`…every_indexed_document_and_query_carries_the_tenant_id`, `…query_syntax_cannot_widen_the_tenant_filter` (6 hostile queries) — 5 specs, 10 cases.
**Unblocks:** B-01. **Open items:** none beyond choosing A/B.

## 3. Scheduled audit verification — F-AUD-007 (D-P0-006 §6; open item H-03)  ·  NOT IMPLEMENTED

**Requirement.** An `audit-verify` job under the separate `ngrc_audit_verifier` identity runs continuously/incrementally and on demand: gapless
sequence, hash linkage, checkpoint signatures, comparison with the external copy; a violation writes `audit.integrity_violation`, alerts Platform
Security, and the absence of a recent run is itself an alert.

**Current state.** The library (`ngrc.audit.verifier`) is implemented and tested (tamper, reorder, truncate, forged checkpoint, full-chain rewrite).
There is no scheduler, no alert routing, no freshness check, and no incremental mode.

**Planned interface.** `ngrc/audit/scheduler.py`: `run_scheduled_verification(mode="full"|"incremental") -> Summary(streams_checked,
violations, recorded_runs, exit_code)`, `check_verification_freshness()`, `database_identity()`; `ngrc/audit/alerts.py`: `notify(Alert)` with
pluggable sinks (log in dev; SIEM/pager when O-4 is decided) and a `recorder` test double; management command `audit_verify` (non-zero exit on any
violation). Runner-agnostic: how it is *scheduled* (cron, Kubernetes CronJob, systemd timer) is a deployment decision under O-4. Settings:
`AUDIT_VERIFY_MAX_AGE_HOURS` and `AUDIT_REQUIRE_EXTERNAL_COPY` (forced on in `prod`); **the age threshold value is not proposed here — Platform Security decides.**

**Threats the specs cover:** tampering that nobody looks for (silence ≠ health); a verifier running with a stronger identity than intended;
tenant admins disabling verification; production running without an external checkpoint copy.
**Specs:** 6 (`test_scheduled_run_…` ×2, `…overdue_verification…`, `…incremental…`, `…verifier_identity…`, `…missing_external_checkpoint_copy…`).
**Unblocks:** B-05. **Open items:** O-4 (alert routing/SIEM). **Related:** section 7 item W-3 (verifier rule) lands with this control.

## 4. MFA factor removal — F-ATH-014 (D-P0-008 §7; open item H-05)  ·  NOT IMPLEMENTED

**Requirement.** Factor add/remove requires step-up; removing the **last** factor is refused; after removal the account still has two recovery
options (two factors, or one factor + recovery codes); removal revokes other sessions and is audited. Platform-realm credentials are not
self-removable (recovery is out of band with a second approver).

**Current state.** Enrolment (TOTP, WebAuthn) exists; there is no removal endpoint and no factor listing.

**Planned interface.** `GET /api/v1/auth/mfa/factors/` (own factors only), `DELETE /api/v1/auth/mfa/factors/{id}/`; service `iam.services.remove_factor`;
registered action `auth.mfa.removed` already exists. **Defence in depth:** a database guard that refuses deleting an account's last active factor
(same pattern as the support-grant guard: tested directly as `ngrc_app`/`ngrc_auth`). Tenant-Owner "WebAuthn-only" policy depends on a tenant
policy feature that does not exist; the spec for it is deferred until that feature is planned.

**Threats:** account lock-out/takeover by removing factors; removal with a stolen session; IDOR on factor ids; leaving a downgrade path.
**Specs:** 6 (`…requires_step_up`, `…last_factor_cannot_be_removed`, `…two_recovery_options`, `…revokes_other_sessions_and_is_audited`,
`…belonging_to_someone_else_is_not_found`, `…operator_cannot_remove_their_own_webauthn_credential`). **Review:** authentication design → P2-2 scope.

## 5. Lost-factor recovery and lock-out exit — F-ATH-015 (D-P0-008 §7.4; open item H-05)  ·  NOT IMPLEMENTED

**Requirement.** Self-service via recovery codes; otherwise **admin-assisted** reset approved by a *different* tenant Owner/Admin with step-up, target
notified on all channels, a **cooling-off** (BASELINE 24 h) before the new factor completes with a cancel link for the legitimate user, all sessions
revoked on completion. The last Owner goes through a documented platform identity-verification procedure requiring Platform Security approval and
the same cooling-off. **Platform support can never reset MFA unilaterally.** Platform-realm recovery is out of band (Platform Security + second approver).

**Current state.** Recovery codes can be generated and used at the MFA step (tested). There is no recovery request model, approval flow, cooling-off,
cancel link, notification or last-Owner procedure.

**Planned interface.** New table `idn_recovery_request` (IDN class) with a DB state-machine trigger modelled on `plt_support_grant_guard`
(approver ≠ target, approver role, step-up evidenced, cooling-off not shortened, write-once decision columns, no delete); endpoints under
`/auth/recovery/…`, approval under `/tenant/recovery/…`, last-Owner approval on the operator plane under a new platform permission; single-use
hashed cancel token; uniform responses (no account enumeration) and throttling. Notifications use the e-mail backend — **real delivery and
authentication of that mail depends on O-7**; until then only the labelled dev backend exists. The 24 h value is a configurable BASELINE awaiting approval.

**Threats:** social-engineered admin approval; attacker approving own request; shortening the cooling-off; recovery as an MFA bypass for support staff;
account enumeration; cancel-link replay.
**Specs:** 8 (`…locked_by_failed_logins_has_an_email_unlock_path…` (DEF-15), `…recovery_code_flow…`, `…different_approver_with_step_up`, `…cooling_off_period`, `…cancel…and_all_sessions_are_revoked`,
`…platform_support_can_never_reset…`, `…last_owner_requires_platform_security…`, `…throttled_and_do_not_reveal…`). **Review:** P2-2 scope.
**Open items:** O-7 (e-mail), O-5 (staffing for platform approvers), O-8 (legal wording of the identity-verification procedure).

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

**Current state.** The sealer appends signed checkpoints to a local JSON-lines file labelled `NOT WORM`. A DB-level attacker is detected by the
checkpoint/export comparison (tested), but an attacker who can write the export can also hide it — see W-3.

**Plan items.**
* **W-1** `ngrc/audit/sinks.py`: `Sink` protocol (`append` → receipt, `read`, `list`, no delete/overwrite) with `LocalFileSink` (dev) and `WormSink`.
* **W-2** Sealer marks a checkpoint *published* only after the sink acknowledges it; sink failure raises a lag alert but never blocks business transactions.
* **W-3** *Verifier rule found while writing the gap demos:* when an external copy is required, **every database checkpoint older than a configurable grace window
  must have a sink copy**; today the verifier checks only the exported records that remain, so dropping the newest export line is not detected
  (`test_gap_demo_dropping_the_latest_exported_checkpoint_goes_unnoticed`, runs now). The grace window value is a Platform Security decision, not proposed here.
* **W-4** The WORM provider (object lock/compliance-mode retention, separate account, write-only credentials for the sealer, read-only for the verifier) — **blocked on O-4**;
  lock/retention durations depend on O-2.
* **W-5** Checkpoint-lag and sink-failure alerts (shares `ngrc.audit.alerts` with section 3).
* **W-6** Restore drill using sink checkpoints (D-P0-004) — blocked on a hosting/backup design (O-3, O-4).

**What runs today:** gap demos for W-3 and for "dev export file is rewritable by the application process". **Specs:** 4
(`test_worm_sink_refuses_overwrite_delete_and_truncate…`, `…credentials_the_application…do_not_hold`, `…does_not_report_a_checkpoint_published_until…`,
`…verifier_compares_database_checkpoints_with_the_sink_copy`). Real WORM semantics (retention lock, account separation) **cannot be tested without the provider**
and stay BLOCKED after the interface exists. **Review:** P2-2 scope (checkpoint construction and anchoring).

---

## 8. Counts (from the last real run — see `SECURITY_TEST_REPORT.md`)
Pending specs and demos: **53** test cases in `tests/test_pending_controls.py` (+1 harness self-test that passes). All are reported as XFAIL. Four are *gap demos*
that execute against dev stand-ins. **None of these numbers is evidence that a control works.**
