# NsureGRC — Security Test Report (Phase 1 / v1.3-alpha)

*Generated 2026-10-20 21:28 UTC from `evidence/junit.xml`. Environment: Windows 11 workstation, Python 3.12 (uv), PostgreSQL 16 in WSL2 Ubuntu.*

**Execution result: 615 passed, 0 failed, 11 XFAIL, 0 skipped, 626 total (pytest, 100 s).** Tests run against a throw-away PostgreSQL database built by the real migrations, connecting as the real least-privilege runtime roles (never a superuser).

**XFAIL is not a pass.** An XFAIL case is an executable specification of a NOT IMPLEMENTED control, or a *gap demo* that runs today against a dev-only stand-in and fails an assertion stating the production property. They are listed separately below and never counted in the passed column; if one unexpectedly passes the run fails (strict xfail).

## Scope and limits

- These are **automated regression tests written by the same team that built the controls**. They are not a penetration test, not an independent security assessment and not a certification. No penetration test has been performed.
- WebAuthn is exercised with a software authenticator only. Time-dependent behaviour uses a controllable clock.
- CI: **NOT RUN — the workflow has never executed on a CI runner (`docs/ci/CI_RUN_RECORD.yaml`).** The suite was also run on a clean-room local PostgreSQL cluster (`docs/ci/LOCAL_REHEARSAL.md`), which is not CI.
- Independent security review: **BLOCKED — no independent reviewer has reviewed any scope; the review package is prepared (`docs/review/`).**
- Tests marked BLOCKED in `BLOCKED_TESTS.md` could not be run and are **not** counted above.

## Defects found while verifying, and their remediation

| ID | Defect | Severity | Found by | Remediation | Regression test(s) | Final status |
|---|---|---|---|---|---|---|
| DEF-01 | Application could not start - circular import between DRF settings and ngrc.authz.drf | high (availability; blocked every other control) | django system check (first run) | classes moved to ngrc/authz/drf_defaults.py (no rest_framework.views import); drf.py re-exports them. | `tests/test_authorization_api.py::test_drf_defaults_fail_closed`<br>`tests/test_smoke_flows.py` | fixed |
| DEF-02 | Tenant provisioning always failed - plt_provision_tenant omitted the NOT NULL column idn_invitation.kind | high (functional; no tenant could be created) | tests/test_rls_tenant_isolation.py fixtures | migration control_plane/0003_provision_invitation_kind.py (CREATE OR REPLACE FUNCTION) | `tests/test_support_access.py::test_only_platform_admin_can_provision_and_it_needs_step_up`<br>`tests/test_rls_tenant_isolation.py` | fixed |
| DEF-03 | The migration identity (ngrc_owner) inherited the audit owner's privileges and could forge audit rows | high (audit integrity; contradicts D-P0-006 duty separation) | manual probe while writing the audit tamper tests | GRANT ... WITH INHERIT FALSE, SET TRUE in db/bootstrap/00_roles.sql; audit migration 0001 now executes SET LOCAL ROLE before touching audit-owned objects. | `tests/test_audit_integrity.py::test_migration_identity_cannot_write_audit_without_set_role`<br>`tests/test_table_classification.py::test_migration_identity_has_no_privileges_on_audit` | fixed — Existing clusters must re-run the GRANT (documented in docs/OPERATIONS_NOTES.md). A database SUPERUSER remains outside this control (see F-AUD-001 gaps). |
| DEF-04 | Non-ASCII digits in the TOTP code caused HTTP 500 (and "$" tolerated a trailing newline) | medium (remotely triggerable server error on an authentication endpoint) | tests/test_authentication.py::test_totp_code_format_is_enforced | ASCII-only fullmatch regex and an isinstance check in ngrc/authn/totp.py. | `tests/test_authentication.py::test_totp_code_format_is_enforced` | fixed |
| DEF-05 | Policy step-up was not enforced for session-scope routes (password change skipped its declared T1 step-up) | high (authorization; documented control silently inactive) | tests/test_authentication.py::test_password_change_requires_current_password_and_step_up | PolicyPermission now calls require_recent_step_up when a policy declares step_up without a catalogue permission. | `tests/test_authentication.py::test_password_change_requires_current_password_and_step_up` | fixed |
| DEF-06 | MFA downgrade - a credential flagged as cloned made the account look factor-less, so a password-only login could enrol a new factor | high (authentication bypass path) | tests/test_authentication.py::test_webauthn_counter_regression_flags_the_credential | flagged credentials still count as an enrolled factor (ngrc/authn/flow.py::_has_factor); the user must recover instead of re-enrolling with only a password. | `tests/test_authentication.py::test_webauthn_counter_regression_flags_the_credential`<br>`tests/test_support_access.py::test_operator_counter_regression_blocks_the_credential` | fixed — The recovery workflow itself (factor removal, cooling-off) is NOT IMPLEMENTED - see F-ATH-007. |
| DEF-07 | Break-glass could not be completed - permissions were assigned to the wrong platform roles and the approval route excluded the second approver | medium (functional/design conformance with D-P0-005 s2/s4) | tests/test_support_access.py (break-glass flow) | platform_support requests break-glass (requester is never an approver); platform_admin no longer holds support.request/breakglass.request; approval routes admit both approver roles and each step requires its own permission. | `tests/test_support_access.py::test_break_glass_needs_two_distinct_approvers_and_skips_consent`<br>`tests/test_support_access.py::test_approvers_cannot_request_break_glass`<br>`tests/test_support_access.py::test_break_glass_second_approver_must_be_a_different_platform_admin` | fixed — The DB guard trigger still allows platform_admin as a requester role (superset of the application rule). Tightening it is tracked in docs/OPEN_ITEMS.md (H-01). |
| DEF-08 | userVerification was not required for privileged customer accounts | medium (ADR conformance) | review against D-P0-008 s7.2 | ngrc/iam/views.py::_uv() requires UV when the account holds any privileged tenant role; operator realm always requires UV. | `tests/test_authentication.py::test_privileged_roles_require_user_verification`<br>`tests/test_support_access.py::test_operator_requires_webauthn_with_user_verification` | fixed |
| DEF-09 | NUL characters, lone surrogates and deeply nested JSON produced HTTP 500 | medium (robustness / DoS-adjacent; remotely triggerable) | tests/test_input_and_exposure.py | ngrc/core/parsers.py::StrictJSONParser (rejects NUL / unencodable strings, depth limit 32, RecursionError -> 400) set as the only parser. | `tests/test_input_and_exposure.py::test_nul_and_invalid_unicode_never_cause_a_server_error`<br>`tests/test_input_and_exposure.py::test_malformed_and_oversized_bodies_are_rejected_cleanly` | fixed |
| DEF-10 | X-Frame-Options header was never sent (setting present, middleware absent) | low (CSP frame-ancestors already denied framing in modern browsers) | tests/test_input_and_exposure.py::test_all_responses_are_json_with_hardening_headers | XFrameOptionsMiddleware added. | `tests/test_input_and_exposure.py::test_all_responses_are_json_with_hardening_headers` | fixed |
| DEF-11 | Role-key validation regex used "$" (tolerates a trailing newline) | low (defence in depth; DRF already trims whitespace) | review after DEF-04 | fullmatch in ngrc/tenancy/roles.py / views.py. | `tests/test_authorization_api.py::test_role_creation_validation_and_mass_assignment` | fixed |
| DEF-12 | idn_session carried a column literally named tenant_id, contradicting D-P0-009 s2.2 (IDN tables carry no plain tenant_id) | low (classification rule; made the automated shape check unable to be exact) | writing tests/test_table_classification.py | renamed to active_tenant_id (migration iam/0004_session_active_tenant.py); the SQL function that referenced it was redefined. | `tests/test_table_classification.py::test_non_tenant_classes_have_no_plain_tenant_id` | fixed |
| DEF-13 | Import-time validation used assert (removed under python -O) | low | bandit B101 | explicit RuntimeError in ngrc/audit/actions.py. | `tests/test_audit_integrity.py::test_action_registry_matches_code` | fixed |
| GAP-01 | Phase 1 steps with no implementation at the start of this verification (operator-plane API, classification manifest, CI workflow, Dockerfile, test suite, evidence generation, reports) | process | gap analysis against the Phase 1 brief | built in this session; see docs/PHASE1_SECURITY_GATE.md for the resulting status of each step. | `tests/test_support_access.py`<br>`tests/test_table_classification.py`<br>`tests/test_evidence_artifacts.py` | fixed |
| DEF-14 | Support-grant guard trigger weaknesses - platform_admin accepted as requester (H-01); decision/time columns editable without a state change (an ACTIVE grant's expiry could be extended, approvers planted, activation/approval times rewritten); consent columns writable on any transition by the owner role; pre-set decision fields accepted on insert; role-only (not account-status) checks | high (the audit stream accepts operator `support.action` events while a grant is active and `expires_at > now()`, so an extended expiry widened the window in which operator actions were accepted; also weakened separation of duties at the database layer) | P2-4 re-review of plt_support_grant_guard (H-01 plus the same-state branch) | migration control_plane/0004_harden_support_grant_guard.py - requester must hold platform_support and be active; decision/time columns are write-once and set only with the matching transition; expiry can only be SHORTENED while active; the single remaining same-state write is the fully validated first break-glass approval; consent columns change only on approved -> tenant_consented; insert rejects pre-set fields and inconsistent scope; approvers/requester must be active accounts and the requester must still hold platform_support at activation. | `tests/test_support_grant_db_guard.py::test_only_platform_support_can_be_the_requester_even_by_direct_insert`<br>`tests/test_support_grant_db_guard.py::test_an_active_grant_cannot_be_widened_or_rewritten_without_a_state_transition`<br>`tests/test_support_grant_db_guard.py::test_expiry_may_be_cut_short_but_never_extended_and_audit_follows_the_real_expiry`<br>`tests/test_support_grant_db_guard.py::test_break_glass_first_approval_is_validated_in_full`<br>`tests/test_support_grant_db_guard.py::test_activation_requires_the_requester_to_still_hold_platform_support` | fixed — 25 of the 26 new tests fail against the Phase 1 trigger (evidence/p2_4_mutation_check_phase1_trigger.txt); the 26th guards a rule that already existed. |
| DEF-15 | Failure-triggered lock-out was exploitable by a stranger: repeated failed logins (20; operators 10) or second-factor failures (10) set the account to recovery_required, and the ADR's dedicated unlock flow and owner/admin notification did not exist | medium-high (availability: repeatable lock-out denial of service; operator accounts had no self-service exit). First recorded as 'high, no exit path' - CORRECTED: customer accounts could leave the state via password reset | preparing the P2-2 review package (reading throttle.py against the ADR); corrected while building F-ATH-015 | TEMPORARY, by project-owner decision 2026-10-21 (ADR 00_CONTROL/PHASE1/D-P1-001): the automatic transition to recovery_required was removed for the customer and operator realms and for second-factor failures; replaced by counted, progressive, pre-hash delays, per-IP limiting, audit events, suspicious-login detection (many sources against one account; success after a failure burst) with alerts (log sink only; delivery is open item O-4), and STRICTER operator parameters (free 3, 120 s doubling to 3600 s). Found and fixed on the way: a malformed client address made the audit append fail (HTTP 500) - addresses are now normalised (ngrc/core/net.py). | `tests/test_auth_backoff_policy.py::test_no_number_of_failures_ever_locks_the_account`<br>`tests/test_auth_backoff_policy.py::test_delays_grow_progressively_to_the_cap_and_are_enforced_before_the_password_check`<br>`tests/test_auth_backoff_policy.py::test_attempts_from_several_sources_against_one_account_raise_one_alert`<br>`tests/test_auth_backoff_policy.py::test_operator_accounts_are_throttled_harder_and_alert_at_critical_severity`<br>`tests/test_auth_backoff_policy.py::test_hostile_source_addresses_cannot_break_the_counters`<br>`tests/test_auth_backoff_policy.py::test_a_recovery_required_account_still_has_an_exit_through_password_reset_with_mailbox_proof` | mitigated-temporary — NOT closed. Residual risks are written into D-P1-001 (an attacker can keep a victim waiting up to the delay cap; no cross-account distributed-attack detection; alert delivery missing). Closes only when the permanent recovery mechanism F-ATH-015 is implemented, tested and reviewed. The owner is asked to re-confirm the decision given the correction. |
| DEF-16 | DevFileSigner key-creation race - two processes (sealer and verifier/scheduler) using the dev signer for the first time concurrently could each create a different key file, one signing with a key the other then overwrote or failed to load | low (DEV-ONLY signer; would produce spurious verification failures, not a bypass) | writing the concurrent-sealer test for H-11 (tests/test_audit_completeness.py) | ngrc/audit/signer.py creates the key file exclusively and, on FileExistsError, loads the key that won the race. | `tests/test_audit_completeness.py::test_concurrent_sealers_publish_each_checkpoint_exactly_once` | fixed |
| DEF-17 | Malformed REMOTE_ADDR / X-forwarded values reached the audit append as an ip column value and raised DataError, turning a login attempt into HTTP 500 | low-medium (availability / error handling on an unauthenticated path) | writing tests/test_auth_backoff_policy.py | ngrc/core/net.py normalize_ip(); unparseable values share one throttle bucket ('unknown') and are stored as NULL. | `tests/test_auth_backoff_policy.py::test_hostile_source_addresses_cannot_break_the_counters` | fixed — residual - one shared bucket can be filled by an attacker controlling REMOTE_ADDR; production gets the address from a trusted proxy configuration that does not yet exist (review concern 23). |

## Results by test

Each row is one test function (parametrised cases are aggregated). *Remediation* names the defect, if any, that this test found or now guards. A test is `PASS` only if every case passed.

| Test | Purpose | Cases | Result | Failure details | Remediation | Final status |
|---|---|---|---|---|---|---|
| `test_audit_completeness.py::test_a_changed_checkpoint_is_not_accepted_as_the_one_verified_earlier` | A changed checkpoint is not accepted as the one verified earlier | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_a_forged_checkpoint_with_a_wrong_previous_digest_is_rejected` | A forged checkpoint with a wrong previous digest is rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_a_valid_chain_alone_never_proves_completeness` | B cannot be derived from the data: deleting the NEWEST checkpoint leaves a perfectly valid shorter chain. | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_an_immutable_sink_is_the_only_way_to_reach_established` | An immutable sink is the only way to reach established | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_checkpoints_are_chained_and_a_heartbeat_extends_the_chain_without_new_events` | Checkpoints are chained and a heartbeat extends the chain without new events | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_concurrent_sealers_publish_each_checkpoint_exactly_once` | Concurrent sealers publish each checkpoint exactly once | 1 | 1/1 passed | — | DEF-16 | **PASS** |
| `test_audit_completeness.py::test_deleting_the_newest_checkpoint_everywhere_is_caught_by_the_high_water_mark` | Deleting the newest checkpoint everywhere is caught by the high water mark | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_deleting_the_newest_checkpoint_is_caught_by_the_external_copy` | Deleting the newest checkpoint is caught by the external copy | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_deleting_the_newest_checkpoints_and_silencing_the_sealer_is_caught_by_staleness` | Deleting the newest checkpoints and silencing the sealer is caught by staleness | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_legacy_checkpoints_still_verify_and_are_reported_as_legacy` | Legacy checkpoints still verify and are reported as legacy | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_middle_checkpoint_deletion_and_insertion_are_detected_without_any_anchor` | Middle checkpoint deletion and insertion are detected without any anchor | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_removing_the_newest_external_copy_is_caught` | The Phase 1 gap demo (H-11): dropping the newest exported record used to leave the stream 'healthy'. | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_resealing_over_a_deleted_checkpoint_cannot_replace_it_silently` | Delete checkpoint 2 and let the sealer issue a new checkpoint 2: the sink still holds the original, so the replacement is exposed. | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_the_sealer_role_cannot_skip_repeat_rewind_or_downgrade_checkpoints` | The sealer role cannot skip repeat rewind or downgrade checkpoints | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_verdicts_are_recorded_and_only_successful_runs_move_the_high_water_mark` | Verdicts are recorded and only successful runs move the high water mark | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_completeness.py::test_without_a_stale_check_the_residual_window_is_the_checkpoint_interval` | Documented limit: events written after the newest honest checkpoint are covered by chain consistency only until the next checkpoint. | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_action_registry_matches_code` | Action registry matches code | 1 | 1/1 passed | — | DEF-13 | **PASS** |
| `test_audit_integrity.py::test_app_cannot_write_to_another_tenants_stream` | App cannot write to another tenants stream | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_append_chains_events_and_verifier_accepts` | Append chains events and verifier accepts | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_business_change_and_audit_commit_together` | Business change and audit commit together | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_business_transaction_fails_if_audit_append_fails` | Business transaction fails if audit append fails | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_chain_head_may_only_advance_by_one` | Chain head may only advance by one | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_checkpoint_by_unknown_key_rejected` | Checkpoint by unknown key rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_deleted_row_detected` | Deleted row detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_denial_event_persists_after_request_rollback` | Denial event persists after request rollback | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_detail_size_and_shape_limits` | Detail size and shape limits | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_forged_checkpoint_signature_rejected` | Forged checkpoint signature rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_full_chain_recompute_rewrite_is_caught_by_checkpoint_and_export` | Attacker with DB-write access recomputes every later hash so the DB chain is internally consistent - the signed | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_integrity_violation_is_recorded_and_alerted` | Integrity violation is recorded and alerted | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_migration_identity_cannot_write_audit_without_set_role` | ngrc_owner may SET ROLE to the audit owner inside reviewed audit migrations, but must NOT inherit its privileges: | 1 | 1/1 passed | — | DEF-03 | **PASS** |
| `test_audit_integrity.py::test_ops_needs_a_support_grant_to_write_tenant_stream` | Ops needs a support grant to write tenant stream | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_platform_reader_can_read_platform_stream_only` | Platform reader can read platform stream only | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_platform_stream_unreadable_by_runtime_roles` | Platform stream unreadable by runtime roles | 3 | 3/3 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_reordered_rows_detected` | Reordered rows detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_runtime_roles_cannot_mutate_audit_tables` | Runtime roles cannot mutate audit tables | 18 | 18/18 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_sealer_checkpoints_are_signed_and_exported` | Sealer checkpoints are signed and exported | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_secret_like_detail_keys_rejected` | Secret like detail keys rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_signed_checkpoint_accepted_then_rewrite_after_checkpoint_detected` | Signed checkpoint accepted then rewrite after checkpoint detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_tampered_row_detected` | Tampered row detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_tenant_cannot_read_other_tenants_audit` | Tenant cannot read other tenants audit | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_triggers_block_even_the_schema_owner` | Defence in depth: with every GRANT ignored (owner role), the triggers still reject UPDATE/DELETE/TRUNCATE. | 5 | 5/5 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_truncated_tail_detected` | Truncated tail detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_unregistered_action_rejected` | Unregistered action rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_audit_integrity.py::test_writer_role_must_be_registered_for_action` | ngrc_app may not emit an auth-service action; ngrc_auth may not emit tenant administration events. | 1 | 1/1 passed | — | — | **PASS** |
| `test_auth_backoff_policy.py::test_a_recovery_required_account_still_has_an_exit_through_password_reset_with_mailbox_proof` | CORRECTION (found while building F-ATH-015): the DEF-15 write-up said accounts in `recovery_required` had NO exit. They do: the password-reset | 1 | 1/1 passed | — | DEF-15 | **PASS** |
| `test_auth_backoff_policy.py::test_attempts_from_several_sources_against_one_account_raise_one_alert` | Attempts from several sources against one account raise one alert | 1 | 1/1 passed | — | DEF-15 | **PASS** |
| `test_auth_backoff_policy.py::test_delays_grow_progressively_to_the_cap_and_are_enforced_before_the_password_check` | Delays grow progressively to the cap and are enforced before the password check | 1 | 1/1 passed | — | DEF-15 | **PASS** |
| `test_auth_backoff_policy.py::test_hostile_source_addresses_cannot_break_the_counters` | Hostile source addresses cannot break the counters | 1 | 1/1 passed | — | DEF-15, DEF-17 | **PASS** |
| `test_auth_backoff_policy.py::test_no_number_of_failures_ever_locks_the_account` | No number of failures ever locks the account | 1 | 1/1 passed | — | DEF-15 | **PASS** |
| `test_auth_backoff_policy.py::test_operator_accounts_are_never_moved_to_a_lock_state_by_failures` | Operator accounts are never moved to a lock state by failures | 1 | 1/1 passed | — | — | **PASS** |
| `test_auth_backoff_policy.py::test_operator_accounts_are_throttled_harder_and_alert_at_critical_severity` | Operator accounts are throttled harder and alert at critical severity | 1 | 1/1 passed | — | DEF-15 | **PASS** |
| `test_auth_backoff_policy.py::test_second_factor_failures_back_off_but_never_lock_the_account` | Second factor failures back off but never lock the account | 1 | 1/1 passed | — | — | **PASS** |
| `test_auth_backoff_policy.py::test_success_after_a_burst_of_failures_is_audited_and_alerted` | Success after a burst of failures is audited and alerted | 1 | 1/1 passed | — | — | **PASS** |
| `test_auth_backoff_policy.py::test_the_temporary_policy_is_visible_in_configuration_and_has_no_hard_stop` | The temporary policy is visible in configuration and has no hard stop | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_absolute_timeout_even_with_continuous_activity` | Absolute timeout even with continuous activity | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_argon2id_is_used_with_floor_parameters` | Argon2id is used with floor parameters | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_concurrent_token_consumption_has_exactly_one_winner` | Concurrent token consumption has exactly one winner | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_csrf_cookie_attributes` | Csrf cookie attributes | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_csrf_enforced_on_every_authenticated_unsafe_route` | Csrf enforced on every authenticated unsafe route | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_csrf_is_enforced_on_unsafe_methods_including_login` | Csrf is enforced on unsafe methods including login | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_csrf_rejects_foreign_origin_even_with_a_valid_token` | Csrf rejects foreign origin even with a valid token | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_customer_webauthn_assertion_attacks` | Customer webauthn assertion attacks | 5 | 5/5 passed | — | — | **PASS** |
| `test_authentication.py::test_customer_webauthn_challenge_is_consumed_by_a_failed_attempt` | Customer webauthn challenge is consumed by a failed attempt | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_customer_webauthn_registration_and_login` | Customer webauthn registration and login | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_forged_or_foreign_session_cookies_are_rejected` | Forged or foreign session cookies are rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_idle_timeout` | Idle timeout | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_ip_throttling_blocks_distributed_account_guessing` | Ip throttling blocks distributed account guessing | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_login_errors_do_not_reveal_whether_account_exists` | Login errors do not reveal whether account exists | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_login_failure_audit_has_no_password_or_raw_email` | Login failure audit has no password or raw email | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_login_unknown_and_wrong_password_run_the_same_hashing_work` | Dummy-hash timing parity (ADR s3): an unknown account still performs a full Argon2 verification. | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_logout_revokes_server_side` | Logout revokes server side | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_membership_suspension_ends_that_users_sessions_immediately` | Membership suspension ends that users sessions immediately | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_mfa_endpoints_require_a_password_session` | Mfa endpoints require a password session | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_only_a_hash_of_the_session_id_is_stored` | Only a hash of the session id is stored | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_change_requires_current_password_and_step_up` | Password change requires current password and step up | 1 | 1/1 passed | — | DEF-05 | **PASS** |
| `test_authentication.py::test_password_change_revokes_other_sessions_and_notifies` | Password change revokes other sessions and notifies | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_hash_never_leaves_the_server` | Password hash never leaves the server | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_only_session_cannot_reach_anything_protected` | Password only session cannot reach anything protected | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_policy` | Password policy | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_reset_is_single_use_expires_and_revokes_sessions` | Password reset is single use expires and revokes sessions | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_reset_request_is_uniform` | Password reset request is uniform | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_reset_token_expires` | Password reset token expires | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_password_session_expires_quickly` | Password session expires quickly | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_pending_mfa_session_with_enrolled_factor_cannot_reach_protected_routes` | Pending mfa session with enrolled factor cannot reach protected routes | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_platform_credentials_are_rejected_on_the_customer_surface` | Platform credentials are rejected on the customer surface | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_privileged_roles_require_user_verification` | Privileged roles require user verification | 1 | 1/1 passed | — | DEF-08 | **PASS** |
| `test_authentication.py::test_progressive_throttling_applies_before_password_check` | Progressive throttling applies before password check | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_recovery_code_is_single_use` | Recovery code is single use | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_recovery_codes_are_stored_hashed` | Recovery codes are stored hashed | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_recovery_codes_not_accepted_for_operators` | Recovery codes not accepted for operators | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_reset_link_ignores_host_header_injection` | Reset link ignores host header injection | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_reset_token_is_stored_hashed` | Reset token is stored hashed | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_safe_methods_do_not_require_csrf` | Safe methods do not require csrf | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_session_cookie_attributes` | Session cookie attributes | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_session_id_rotates_on_mfa_and_on_tenant_selection` | Session id rotates on mfa and on tenant selection | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_totp_clock_drift_one_step_back_is_accepted` | Totp clock drift one step back is accepted | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_totp_code_format_is_enforced` | Totp code format is enforced | 1 | 1/1 passed | — | DEF-04 | **PASS** |
| `test_authentication.py::test_totp_replay_and_window` | Totp replay and window | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_totp_secret_is_stored_encrypted` | Totp secret is stored encrypted | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_verify_email_token_single_use` | Verify email token single use | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_weak_hash_is_upgraded_on_login` | Weak hash is upgraded on login | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_weak_password_does_not_burn_the_reset_token` | Weak password does not burn the reset token | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_webauthn_counter_regression_flags_the_credential` | Webauthn counter regression flags the credential | 1 | 1/1 passed | — | DEF-06 | **PASS** |
| `test_authentication.py::test_wrong_totp_never_promotes_the_session` | Wrong totp never promotes the session | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_a_denial_stays_a_denial_when_the_audit_service_is_down` | A denial stays a denial when the audit service is down | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_admin_cannot_create_a_role_with_permissions_it_does_not_hold` | Admin cannot create a role with permissions it does not hold | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_admin_cannot_promote_anyone_to_owner_or_modify_owners` | Admin cannot promote anyone to owner or modify owners | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_audit_trail_and_export_never_cross_tenants` | Audit trail and export never cross tenants | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_business_change_is_rolled_back_when_the_audit_append_fails` | Business change is rolled back when the audit append fails | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_cannot_delete_role_in_use_and_last_owner_is_protected` | Cannot delete role in use and last owner is protected | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_drf_defaults_fail_closed` | Drf defaults fail closed | 1 | 1/1 passed | — | DEF-01 | **PASS** |
| `test_authorization_api.py::test_endpoint_inventory_is_reviewed` | Any new route fails this test until the inventory (and therefore its authz/IDOR tests) is consciously extended. | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_every_non_public_route_rejects_anonymous_callers_on_every_method` | Every non public route rejects anonymous callers on every method | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_every_route_is_an_ngrc_view_with_a_declared_policy` | Every route is an ngrc view with a declared policy | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_expired_membership_denies_access` | Expired membership denies access | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_external_auditor_invitation_requires_expiry` | External auditor invitation requires expiry | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_failed_requests_leave_no_partial_state` | Failed requests leave no partial state | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_idor_attempts_do_not_leak_existence` | Idor attempts do not leak existence | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_idor_roles_members_invitations_across_tenants` | Idor roles members invitations across tenants | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_invitation_flow_enforces_no_escalation_and_hides_token` | Invitation flow enforces no escalation and hides token | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_member_has_no_tenant_admin_rights` | Member has no tenant admin rights | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_mutations_require_recent_step_up` | Mutations require recent step up | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_no_tenant_selected_blocks_tenant_routes` | No tenant selected blocks tenant routes | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_nobody_can_modify_their_own_membership` | Nobody can modify their own membership | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_platform_permissions_can_never_be_put_in_a_tenant_role` | Platform permissions can never be put in a tenant role | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_public_routes_match_the_reviewed_allow_list_and_state_a_reason` | Public routes match the reviewed allow list and state a reason | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_removing_membership_takes_effect_on_the_next_request` | Removing membership takes effect on the next request | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_role_creation_validation_and_mass_assignment` | Role creation validation and mass assignment | 1 | 1/1 passed | — | DEF-11 | **PASS** |
| `test_authorization_api.py::test_role_permission_reduction_revokes_holders_sessions` | Role permission reduction revokes holders sessions | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_selecting_a_tenant_without_membership_is_denied_and_audited` | Selecting a tenant without membership is denied and audited | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_suspended_tenant_denies_access` | Suspended tenant denies access | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_system_roles_are_immutable_through_the_api` | System roles are immutable through the api | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_tampered_session_tenant_is_not_honoured` | Tampered session tenant is not honoured | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_tenant_identifier_in_requests_is_never_trusted` | Tenant identifier in requests is never trusted | 1 | 1/1 passed | — | — | **PASS** |
| `test_authorization_api.py::test_view_without_policy_is_denied` | View without policy is denied | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_a_changed_workflow_makes_the_recorded_run_stale` | A changed workflow makes the recorded run stale | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_a_missing_skipped_or_failed_job_is_never_a_pass` | A missing skipped or failed job is never a pass | 5 | 5/5 passed | — | — | **PASS** |
| `test_ci_record.py::test_a_success_without_evidence_is_not_accepted` | A success without evidence is not accepted | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_all_jobs_green_for_the_right_commit_and_an_unchanged_workflow_is_the_only_pass` | All jobs green for the right commit and an unchanged workflow is the only pass | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_run_metadata_must_be_present_well_formed_private_and_for_the_right_workflow` | Run metadata must be present well formed private and for the right workflow | 9 | 9/9 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_container_job_needs_docker_and_a_clean_image_scan` | The container job needs docker and a clean image scan | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_importer_derives_job_results_from_api_shaped_data_and_never_invents_the_rest` | The importer derives job results from api shaped data and never invents the rest | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_real_record_says_ci_has_not_run` | The real record says ci has not run | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_run_must_have_executed_the_workflow_that_the_commit_contains` | The run must have executed the workflow that the commit contains | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_secret_scan_must_have_seen_the_full_history` | The secret scan must have seen the full history | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_tests_job_must_report_passes_no_failures_and_postgresql_rls_results` | The tests job must report passes no failures and postgresql rls results | 5 | 5/5 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_workflow_file_existing_is_not_a_result` | The workflow file existing is not a result | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_a_fully_secure_configuration_passes` | A fully secure configuration passes | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_dev_only_markers_are_explicit` | Dev-only stand-ins must announce themselves so nobody mistakes them for production controls. | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_django_baseline_features_are_not_installed` | Django baseline features are not installed | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_each_insecure_setting_is_detected` | Each insecure setting is detected | 28 | 28/28 passed | — | — | **PASS** |
| `test_config_security.py::test_each_process_plane_receives_only_its_own_database_roles` | Each process plane receives only its own database roles | 5 | 5/5 passed | — | — | **PASS** |
| `test_config_security.py::test_http_security_settings_are_secure_by_default` | Http security settings are secure by default | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_insecure_database_settings_are_detected` | Insecure database settings are detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_missing_required_secrets_stop_startup_and_nothing_has_a_default` | Missing required secrets stop startup and nothing has a default | 4 | 4/4 passed | — | — | **PASS** |
| `test_config_security.py::test_no_test_only_code_ships_in_the_application_package` | No test only code ships in the application package | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_production_settings_refuse_to_start_while_dev_only_components_are_the_only_ones_available` | Production settings refuse to start while dev only components are the only ones available | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_runtime_roles_in_database_settings_are_not_privileged` | Runtime roles in database settings are not privileged | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_signing_key_and_env_files_are_gitignored` | Signing key and env files are gitignored | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_weak_secret_key_and_wildcard_hosts_stop_startup` | Weak secret key and wildcard hosts stop startup | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_a_term_that_exists_only_in_another_tenant_finds_nothing_and_looks_like_any_empty_search` | A term that exists only in another tenant finds nothing and looks like any empty search | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_every_searchable_row_carries_its_tenant_and_the_vector_is_derived_by_the_database` | Every searchable row carries its tenant and the vector is derived by the database | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_invalid_queries_are_rejected_cleanly` | Invalid queries are rejected cleanly | 7 | 7/7 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_query_syntax_cannot_widen_the_tenant_filter_or_break_the_server` | Query syntax cannot widen the tenant filter or break the server | 13 | 13/13 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_restricted_hits_are_reauthorised_per_item` | Restricted hits are reauthorised per item | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_results_are_capped_and_ranked` | Results are capped and ranked | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_results_come_only_from_the_callers_tenant` | Results come only from the callers tenant | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_row_level_security_alone_confines_the_search_sql` | Row level security alone confines the search sql | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_search_needs_authentication_a_tenant_context_and_the_permission` | Search needs authentication a tenant context and the permission | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_snippets_are_plain_text_without_markup` | Snippets are plain text without markup | 1 | 1/1 passed | — | — | **PASS** |
| `test_cross_tenant_search.py::test_the_query_text_is_never_audited_only_its_length_and_the_result_count` | The query text is never audited only its length and the result count | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_any_bit_flip_is_detected` | Any bit flip is detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_ciphertext_is_bound_to_tenant_record_and_field` | Ciphertext is bound to tenant record and field | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_constant_time_comparison` | Constant time comparison | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_keyed_hashes_depend_on_the_server_pepper` | Keyed hashes depend on the server pepper | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_no_custom_cryptographic_primitives_in_the_codebase` | Only stdlib hashlib/hmac/secrets and the `cryptography` AEAD/Ed25519 APIs are used (no hand-rolled ciphers or RNG). | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_only_the_dev_key_provider_exists_and_production_one_is_not_implemented` | Only the dev key provider exists and production one is not implemented | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_seal_open_round_trip_and_randomisation` | Seal open round trip and randomisation | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_short_master_key_is_refused` | Short master key is refused | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_tokens_are_high_entropy_and_hashed_not_encrypted` | Tokens are high entropy and hashed not encrypted | 1 | 1/1 passed | — | — | **PASS** |
| `test_crypto.py::test_wrong_master_key_cannot_open` | Wrong master key cannot open | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_artifacts.py::test_audit_chain_verification_report` | Audit chain verification report | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_artifacts.py::test_privilege_matrix_report` | Privilege matrix report | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_artifacts.py::test_rls_coverage_report` | Rls coverage report | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_artifacts.py::test_route_policy_inventory` | Route policy inventory | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_artifacts.py::test_security_configuration_snapshot` | Security configuration snapshot | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_a_database_row_pointing_at_another_tenants_object_is_never_opened` | A database row pointing at another tenants object is never opened | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_a_missing_or_truncated_object_is_an_integrity_failure_not_a_partial_download` | A missing or truncated object is an integrity failure not a partial download | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_a_revision_whose_scan_has_not_completed_is_never_served` | A revision whose scan has not completed is never served | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_an_object_that_no_longer_matches_its_recorded_hash_is_refused_and_alerted` | An object that no longer matches its recorded hash is refused and alerted | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_api_responses_never_expose_storage_keys_paths_or_urls` | Api responses never expose storage keys paths or urls | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_authentication_and_the_evidence_read_permission_are_required` | Authentication and the evidence read permission are required | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_cross_tenant_download_is_an_identical_audited_404` | Cross tenant download is an identical audited 404 | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_download_streams_the_exact_bytes_with_hardened_headers_and_no_redirect` | Download streams the exact bytes with hardened headers and no redirect | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_no_byte_is_released_when_the_download_event_cannot_be_written` | No byte is released when the download event cannot be written | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_quarantined_evidence_is_retained_but_never_served` | Quarantined evidence is retained but never served | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_restricted_evidence_is_invisible_without_the_restricted_permission` | Restricted evidence is invisible without the restricted permission | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_support_sessions_and_operators_have_no_path_to_evidence` | Support sessions and operators have no path to evidence | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_download.py::test_the_event_records_object_revision_hash_actor_and_result` | The event records object revision hash actor and result | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_a_pending_revision_can_receive_exactly_one_outcome` | A pending revision can receive exactly one outcome | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_a_reader_without_the_upload_permission_can_read_but_not_create_or_upload` | The upload permission is checked on its own: a role with evidence.read only passes the route policy but not the mutation. | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_content_must_be_what_it_claims_to_be` | Content must be what it claims to be | 8 | 8/8 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_eicar_is_quarantined_at_upload_with_a_critical_event` | Eicar is quarantined at upload with a critical event | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_hostile_storage_keys_are_refused` | Hostile storage keys are refused | 10 | 10/10 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_member_cannot_upload_and_validation_errors_are_clean` | Member cannot upload and validation errors are clean | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_nothing_can_delete_or_truncate_evidence_and_restricted_cannot_be_downgraded` | Nothing can delete or truncate evidence and restricted cannot be downgraded | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_office_packages_are_checked_for_bombs_path_escapes_and_real_structure` | Office packages are checked for bombs path escapes and real structure | 6 | 6/6 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_revision_content_is_immutable_and_the_scan_outcome_final` | Revision content is immutable and the scan outcome final | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_revisions_are_numbered_listed_and_each_one_is_independently_downloadable` | Revisions are numbered listed and each one is independently downloadable | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_rls_composite_fk_and_with_check_keep_evidence_inside_its_tenant` | Rls composite fk and with check keep evidence inside its tenant | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_size_limit_is_enforced_before_and_while_storing` | Size limit is enforced before and while storing | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_ten_evidence_and_ten_evidence_revision_follow_the_tenant_table_template` | Ten evidence and ten evidence revision follow the tenant table template | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_the_original_filename_is_metadata_only_and_sanitised` | The original filename is metadata only and sanitised | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_the_sniffer_is_pure_and_rejects_the_unknown` | The sniffer is pure and rejects the unknown | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_the_store_never_overwrites_and_keys_are_server_generated` | The store never overwrites and keys are server generated | 1 | 1/1 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_types_outside_the_allow_list_are_refused_and_nothing_is_stored` | Types outside the allow list are refused and nothing is stored | 7 | 7/7 passed | — | — | **PASS** |
| `test_evidence_lifecycle.py::test_valid_documents_are_accepted_and_scanned_clean` | Valid documents are accepted and scanned clean | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_a_cloned_credential_is_not_a_usable_factor_and_may_always_be_removed` | A cloned credential is not a usable factor and may always be removed | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_a_factor_of_someone_else_is_not_found_and_stays_untouched` | A factor of someone else is not found and stays untouched | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_an_unfinished_enrolment_is_not_a_factor_and_can_be_replaced` | An unfinished enrolment is not a factor and can be replaced | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_concurrent_removals_cannot_both_succeed` | Two requests, two connections, an account with exactly two factors: the guard serialises on the account row, so one of them must fail. | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_operators_have_no_self_service_removal_and_the_database_protects_their_last_credential` | Operators have no self service removal and the database protects their last credential | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_removal_must_leave_two_recovery_options` | After removal: two usable factors, or one factor plus recovery codes (D-P0-008 s7). | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_removal_requires_a_recent_step_up` | Removal requires a recent step up | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_removal_revokes_other_sessions_rotates_mine_notifies_and_is_audited` | Removal revokes other sessions rotates mine notifies and is audited | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_someone_elses_totp_factor_is_not_found_and_stays_untouched` | Someone elses totp factor is not found and stays untouched | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_the_database_refuses_to_delete_the_last_usable_factor_even_without_the_application` | The database refuses to delete the last usable factor even without the application | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_the_factor_list_shows_only_my_factors_and_the_recovery_code_count` | The factor list shows only my factors and the recovery code count | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_the_last_usable_factor_cannot_be_removed` | The last usable factor cannot be removed | 1 | 1/1 passed | — | — | **PASS** |
| `test_factor_removal.py::test_the_owner_role_is_the_only_exception_and_is_used_by_the_recovery_function` | Documented trust boundary: the schema owner (migrations, SECURITY DEFINER recovery completion) bypasses the guard. | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_all_responses_are_json_with_hardening_headers` | All responses are json with hardening headers | 1 | 1/1 passed | — | DEF-10 | **PASS** |
| `test_input_and_exposure.py::test_api_responses_never_contain_credentials_or_hashes` | Api responses never contain credentials or hashes | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_cors_is_default_deny` | Cors is default deny | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_emails_carry_tokens_only_in_the_url_fragment` | Emails carry tokens only in the url fragment | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_error_pages_do_not_disclose_framework_details` | Error pages do not disclose framework details | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_html_payloads_are_stored_as_inert_json_text` | Html payloads are stored as inert json text | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_http_method_override_is_not_honoured` | Http method override is not honoured | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_malformed_and_oversized_bodies_are_rejected_cleanly` | Malformed and oversized bodies are rejected cleanly | 1 | 1/1 passed | — | DEF-09 | **PASS** |
| `test_input_and_exposure.py::test_no_secret_ever_reaches_the_audit_trail` | No secret ever reaches the audit trail | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_no_string_built_sql_outside_the_reviewed_set` | Static guard: every `execute(f"...")` must be in this reviewed list (identifiers validated or constants only). | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_nul_and_invalid_unicode_never_cause_a_server_error` | Nul and invalid unicode never cause a server error | 3 | 3/3 passed | — | DEF-09 | **PASS** |
| `test_input_and_exposure.py::test_operator_api_inputs_are_parameterised` | Operator api inputs are parameterised | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_redaction_filter_and_formatter` | Redaction filter and formatter | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_reflected_input_in_errors_is_not_echoed_back` | Reflected input in errors is not echoed back | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_repository_contains_no_hardcoded_secrets` | Repository contains no hardcoded secrets | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_secrets_are_not_logged` | Secrets are not logged | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_sql_injection_cannot_reach_other_tenants_or_credentials` | Sql injection cannot reach other tenants or credentials | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_sql_injection_in_login_fields` | Sql injection in login fields | 10 | 10/10 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_sql_injection_in_tenant_api_inputs` | Sql injection in tenant api inputs | 10 | 10/10 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_totp_secret_is_shown_exactly_once` | Totp secret is shown exactly once | 1 | 1/1 passed | — | — | **PASS** |
| `test_input_and_exposure.py::test_unhandled_exceptions_return_a_generic_body` | Unhandled exceptions return a generic body | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_a_denied_request_ends_and_the_user_is_told` | A denied request ends and the user is told | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_a_pending_password_session_is_required_to_ask_for_recovery` | A pending password session is required to ask for recovery | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_a_sole_owner_needs_platform_security_and_the_same_cooling_off` | A sole owner needs platform security and the same cooling off | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_admin_assisted_recovery_end_to_end` | Admin assisted recovery end to end | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_after_a_completed_recovery_only_the_completing_session_may_enrol_for_a_short_window` | After a completed recovery only the completing session may enrol for a short window | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_another_tenants_admin_cannot_see_or_approve` | Another tenants admin cannot see or approve | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_cancelling_during_the_cooling_off_stops_the_completion` | Cancelling during the cooling off stops the completion | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_expired_requests_cannot_be_approved_and_are_replaced_by_a_new_one` | Expired requests cannot be approved and are replaced by a new one | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_neither_the_audit_trail_nor_the_database_holds_a_usable_cancel_token` | Neither the audit trail nor the database holds a usable cancel token | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_no_runtime_role_can_write_or_read_the_request_table_directly` | No runtime role can write or read the request table directly | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_no_support_session_route_can_touch_recovery` | No support session route can touch recovery | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_nobody_can_approve_their_own_recovery` | Nobody can approve their own recovery | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_only_one_request_is_open_and_requests_are_throttled` | Only one request is open and requests are throttled | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_only_tenant_owners_and_admins_see_or_decide_and_a_fresh_step_up_is_required` | Only tenant owners and admins see or decide and a fresh step up is required | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_recovery_events_are_registered_and_stay_in_their_streams` | Recovery events are registered and stay in their streams | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_tenant_selection_rules_for_the_request` | Tenant selection rules for the request | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_terminal_states_cannot_be_reopened_even_by_the_owner_role` | Terminal states cannot be reopened even by the owner role | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_the_cancel_endpoint_is_throttled_and_does_not_reveal_anything` | The cancel endpoint is throttled and does not reveal anything | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_the_cooling_off_and_the_state_machine_hold_even_against_the_owner_role` | The cooling off and the state machine hold even against the owner role | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_the_emailed_link_cancels_once_and_nothing_can_follow` | The emailed link cancels once and nothing can follow | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_the_platform_approval_assertion_is_bound_to_that_one_request` | The platform approval assertion is bound to that one request | 1 | 1/1 passed | — | — | **PASS** |
| `test_lost_factor_recovery.py::test_the_trigger_rejects_forged_approvals_even_from_the_owner_role` | Defence in depth: the functions never produce these rows, so each rule is exercised by a forged UPDATE as the schema owner. | 1 | 1/1 passed | — | — | **PASS** |
| `test_pending_controls.py::test_gap_demo_ciphertext_cannot_be_read_after_a_master_key_change` | GAP DEMO (runs now): the dev provider has a single master key and ignores the key id stored beside the ciphertext, so rotation | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_dev_signing_key_is_readable_by_the_process_that_signs` | GAP DEMO (runs now): the dev signer's private key is a file the application process can read, so a host-level attacker (or an | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_the_dev_export_file_can_be_rewritten_by_the_application_process` | GAP DEMO (runs now): the dev sink is an ordinary file opened for append by the same process that writes the database, so it is not | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_harness_separates_absent_features_from_broken_specs` | Self-test of the harness (RUNS and must PASS): an absent module/route is FeatureAbsent; an existing one resolves. Any other error | 1 | 1/1 passed | — | — | **PASS** |
| `test_pending_controls.py::test_kms_provider_envelope_round_trip_and_aad_binding` | Kms provider envelope round trip and aad binding | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_kms_provider_keeps_old_ciphertext_readable_after_rotation` | Kms provider keeps old ciphertext readable after rotation | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_kms_signer_is_sign_only_and_the_private_key_is_not_exportable` | Kms signer is sign only and the private key is not exportable | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_production_settings_start_only_with_kms_backends_and_hold_no_key_material` | Production settings start only with kms backends and hold no key material | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_sealer_does_not_report_a_checkpoint_published_until_the_sink_acknowledges_it` | Sealer does not report a checkpoint published until the sink acknowledges it | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_sink_uses_credentials_the_application_database_and_runtime_roles_do_not_hold` | Sink uses credentials the application database and runtime roles do not hold | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_verifier_compares_database_checkpoints_with_the_sink_copy` | Verifier compares database checkpoints with the sink copy | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_worm_sink_refuses_overwrite_delete_and_truncate_of_a_published_checkpoint` | Worm sink refuses overwrite delete and truncate of a published checkpoint | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_review_record.py::test_a_complete_record_requires_every_scope_to_be_covered` | A complete record requires every scope to be covered | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_a_review_of_different_code_is_stale` | A review of different code is stale | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_a_review_without_report_digest_date_package_digest_or_disposition_is_incomplete` | A review without report digest date package digest or disposition is incomplete | 4 | 4/4 passed | — | — | **PASS** |
| `test_review_record.py::test_an_empty_record_never_reads_as_reviewed` | An empty record never reads as reviewed | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_empty_findings_need_the_reviewers_explicit_confirmation` | Empty findings need the reviewers explicit confirmation | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_implementers_and_ai_tools_cannot_review_their_own_work` | Implementers and ai tools cannot review their own work | 7 | 7/7 passed | — | — | **PASS** |
| `test_review_record.py::test_open_critical_or_high_findings_block_completion_and_lower_ones_leave_it_conditional` | Open critical or high findings block completion and lower ones leave it conditional | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_remediated_and_accepted_findings_need_evidence` | Remediated and accepted findings need evidence | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_reviewer_must_state_independence_themselves` | Reviewer must state independence themselves | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_the_checker_does_not_mutate_its_input` | The checker does not mutate its input | 1 | 1/1 passed | — | — | **PASS** |
| `test_review_record.py::test_the_real_record_is_blocked_because_no_independent_review_exists` | The real record is blocked because no independent review exists | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_a_hijacked_search_path_cannot_change_definer_behaviour` | A hostile session creates nothing (no CREATE), and even a changed search_path does not alter pinned definer functions. | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_a_non_owner_cannot_grant_itself_or_public_more_access` | GRANT by a non-owner is a silent no-op WARNING in PostgreSQL (not an error), so assert the EFFECT. | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_audit_append_binds_the_events_to_the_callers_own_tenant` | Audit append binds the events to the callers own tenant | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_connection_and_statement_limits_are_applied_to_runtime_roles` | Connection and statement limits are applied to runtime roles | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_ddl_and_privilege_changes_are_denied` | Ddl and privilege changes are denied | 18 | 18/18 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_definer_functions_enforce_the_callers_own_tenant` | Definer functions enforce the callers own tenant | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_disabling_row_security_makes_queries_fail_not_leak` | Disabling row security makes queries fail not leak | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_every_security_definer_function_pins_search_path_and_is_not_public` | Search-path hijack and PUBLIC-EXECUTE audit over the real catalogue. | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_role_switching_is_impossible` | Role switching is impossible | 5 | 5/5 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_runtime_roles_cannot_read_other_roles_secrets_via_settings` | Runtime roles cannot read other roles secrets via settings | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_runtime_roles_cannot_terminate_other_sessions` | Runtime roles cannot terminate other sessions | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_server_side_file_program_and_catalogue_secrets_are_unreachable` | Server side file program and catalogue secrets are unreachable | 11 | 11/11 passed | — | — | **PASS** |
| `test_rls_bypass_attempts.py::test_unrelated_account_cannot_be_enumerated_through_the_profile_projection` | Unrelated account cannot be enumerated through the profile projection | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_composite_fk_rejects_cross_tenant_parent` | Composite fk rejects cross tenant parent | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_context_cannot_be_switched_inside_open_context` | Context cannot be switched inside open context | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_context_does_not_leak_across_transactions` | Pooling test: same physical connection, next transaction sees no tenant (is_local = true). | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_cross_tenant_insert_denied` | Cross tenant insert denied | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_cross_tenant_read_denied` | Cross tenant read denied | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_cross_tenant_update_and_delete_affect_zero_rows` | Cross tenant update and delete affect zero rows | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_invalid_tenant_identifier_rejected` | Invalid tenant identifier rejected | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_last_owner_cannot_be_removed` | Last owner cannot be removed | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_malformed_context_fails_closed` | Malformed context fails closed | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_no_context_reads_nothing_and_writes_fail` | No context reads nothing and writes fail | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_orm_cannot_see_other_tenants_rows` | Orm cannot see other tenants rows | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_orm_guard_requires_context` | Orm guard requires context | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_own_tenant_row_only_in_registry` | Own tenant row only in registry | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_runtime_roles_have_no_dangerous_attributes` | Runtime roles have no dangerous attributes | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_runtime_roles_own_nothing` | Runtime roles own nothing | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_system_roles_immutable_for_tenant_plane` | System roles immutable for tenant plane | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_tenant_id_is_immutable` | Tenant id is immutable | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_tenant_roles_cannot_carry_platform_permissions` | Tenant roles cannot carry platform permissions | 1 | 1/1 passed | — | — | **PASS** |
| `test_rls_tenant_isolation.py::test_unique_constraints_are_tenant_scoped` | Both tenants own a role keyed 'member' (system role) - uniqueness is per tenant, not global. | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_a_scheduled_run_detects_tampering_records_it_alerts_and_exits_non_zero` | A scheduled run detects tampering records it alerts and exits non zero | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_a_scheduled_run_verifies_each_stream_records_each_result_and_writes_a_summary_event` | A scheduled run verifies each stream records each result and writes a summary event | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_alert_details_may_not_carry_secrets_and_a_failing_sink_never_breaks_the_caller` | Alert details may not carry secrets and a failing sink never breaks the caller | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_documented_limit_an_in_place_edit_of_an_old_event_needs_a_full_run` | Documented limit an in place edit of an old event needs a full run | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_incremental_runs_agree_with_full_runs_on_clean_data_and_catch_new_tampering` | Incremental runs agree with full runs on clean data and catch new tampering | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_no_tenant_route_can_configure_pause_or_disable_verification` | No tenant route can configure pause or disable verification | 4 | 4/4 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_production_mode_requires_the_external_copy_and_an_independent_anchor` | Production mode requires the external copy and an independent anchor | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_public_keys_come_from_configuration_so_the_verifier_needs_no_private_key` | Public keys come from configuration so the verifier needs no private key | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_silence_is_an_alert_the_watchdog_raises_when_no_run_is_recorded` | Silence is an alert the watchdog raises when no run is recorded | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_the_job_only_runs_as_the_verifier_identity` | The job only runs as the verifier identity | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_the_seal_command_issues_checkpoints_and_a_heartbeat` | The seal command issues checkpoints and a heartbeat | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_the_watchdog_is_a_separate_entry_point_and_the_command_maps_it_to_the_exit_code` | The watchdog is a separate entry point and the command maps it to the exit code | 1 | 1/1 passed | — | — | **PASS** |
| `test_scheduled_verification.py::test_verified_clock_used_by_the_scheduler_is_the_shared_one` | Verified clock used by the scheduler is the shared one | 1 | 1/1 passed | — | — | **PASS** |
| `test_smoke_flows.py::test_customer_full_login_flow` | Customer full login flow | 1 | 1/1 passed | — | — | **PASS** |
| `test_smoke_flows.py::test_operator_login_flow` | Operator login flow | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_activation_is_impossible_without_tenant_consent` | Activation is impossible without tenant consent | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_another_tenants_owner_cannot_see_or_decide_the_grant` | Another tenants owner cannot see or decide the grant | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_approval_requires_an_assertion_bound_to_that_exact_grant` | Approval requires an assertion bound to that exact grant | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_approvers_cannot_request_break_glass` | Approvers cannot request break glass | 1 | 1/1 passed | — | DEF-07 | **PASS** |
| `test_support_access.py::test_break_glass_duration_is_capped_lower` | Break glass duration is capped lower | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_break_glass_needs_two_distinct_approvers_and_skips_consent` | Break glass needs two distinct approvers and skips consent | 1 | 1/1 passed | — | DEF-07 | **PASS** |
| `test_support_access.py::test_break_glass_second_approver_must_be_a_different_platform_admin` | Break glass second approver must be a different platform admin | 1 | 1/1 passed | — | DEF-07 | **PASS** |
| `test_support_access.py::test_consent_before_approval_is_refused` | Consent before approval is refused | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_expired_grant_stops_working_immediately` | Expired grant stops working immediately | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_grant_duration_is_capped` | Grant duration is capped | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_only_a_tenant_owner_can_consent` | Only a tenant owner can consent | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_only_platform_admin_can_provision_and_it_needs_step_up` | Only platform admin can provision and it needs step up | 1 | 1/1 passed | — | DEF-02 | **PASS** |
| `test_support_access.py::test_only_platform_security_can_approve` | Only platform security can approve | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_only_support_engineers_may_request` | Approvers (security, admin) and curators cannot request: the requester is never one of the approvers. | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_cookie_attributes` | Operator cookie attributes | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_counter_regression_blocks_the_credential` | Operator counter regression blocks the credential | 1 | 1/1 passed | — | DEF-06 | **PASS** |
| `test_support_access.py::test_operator_login_does_not_enumerate` | Operator login does not enumerate | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_login_is_throttled_harder_than_customer_login` | Operator login is throttled harder than customer login | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_password_alone_grants_nothing` | Operator password alone grants nothing | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_requires_webauthn_with_user_verification` | Operator requires webauthn with user verification | 1 | 1/1 passed | — | DEF-08 | **PASS** |
| `test_support_access.py::test_operator_session_is_short_lived` | Operator session is short lived | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_operator_session_never_works_on_the_customer_api` | Operator session never works on the customer api | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_platform_audit_stream_is_for_platform_security_only` | Platform audit stream is for platform security only | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_provisioning_needs_a_fresh_step_up` | Provisioning needs a fresh step up | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_request_needs_ticket_reason_and_valid_profile` | Request needs ticket reason and valid profile | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_request_requires_recent_step_up` | Request requires recent step up | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_requester_cannot_approve_their_own_request` | Requester cannot approve their own request | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_state_machine_trigger_rejects_illegal_transitions_even_for_the_owner_role` | Skipping states or forging consent directly in SQL is refused by plt_support_grant_guard. | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_support_access_end_to_end_with_mirrored_audit` | Support access end to end with mirrored audit | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_support_session_cannot_be_used_on_the_platform_side_or_by_others` | Support session cannot be used on the platform side or by others | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_tenant_has_no_write_path_to_approval_columns` | Tenant has no write path to approval columns | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_tenant_owner_revocation_is_immediate` | Tenant owner revocation is immediate | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_tenant_owner_sees_the_grant_and_its_actions` | Tenant owner sees the grant and its actions | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_access.py::test_tenant_users_cannot_use_platform_apis` | Tenant users cannot use platform apis | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_a_disabled_support_operator_cannot_open_a_request_and_the_positive_control_works` | A disabled support operator cannot open a request and the positive control works | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_a_requester_who_is_also_security_cannot_be_recorded_as_their_own_approver` | A requester who is also security cannot be recorded as their own approver | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_activation_requires_the_requester_to_still_hold_platform_support` | Activation requires the requester to still hold platform support | 1 | 1/1 passed | — | DEF-14 | **PASS** |
| `test_support_grant_db_guard.py::test_an_active_grant_cannot_be_widened_or_rewritten_without_a_state_transition` | An active grant cannot be widened or rewritten without a state transition | 8 | 8/8 passed | — | DEF-14 | **PASS** |
| `test_support_grant_db_guard.py::test_an_approver_cannot_be_planted_without_the_approval_transition` | An approver cannot be planted without the approval transition | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_break_glass_first_approval_is_validated_in_full` | Break glass first approval is validated in full | 1 | 1/1 passed | — | DEF-14 | **PASS** |
| `test_support_grant_db_guard.py::test_consent_columns_cannot_be_written_outside_the_consent_transition_even_by_the_owner_role` | Consent columns cannot be written outside the consent transition even by the owner role | 1 | 1/1 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_expiry_may_be_cut_short_but_never_extended_and_audit_follows_the_real_expiry` | The audit-integrity property: operator actions are accepted into the tenant audit stream only inside the approved window, | 1 | 1/1 passed | — | DEF-14 | **PASS** |
| `test_support_grant_db_guard.py::test_insert_cannot_preload_decision_fields_or_an_inconsistent_scope` | Insert cannot preload decision fields or an inconsistent scope | 6 | 6/6 passed | — | — | **PASS** |
| `test_support_grant_db_guard.py::test_only_platform_support_can_be_the_requester_even_by_direct_insert` | Only platform support can be the requester even by direct insert | 4 | 4/4 passed | — | DEF-14 | **PASS** |
| `test_support_grant_db_guard.py::test_state_transitions_cannot_smuggle_changes_to_other_columns` | Ending a grant must not also rewrite the activation window or approvers in the same statement. | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_audit_tables_have_mutation_guards` | Audit tables have mutation guards | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_idn_account_column_level_grants` | ngrc_app sees only the four profile columns of idn_account - never password_hash or any credential material. | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_manifest_entries_are_well_formed` | Manifest entries are well formed | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_manifest_equals_catalogue` | Manifest equals catalogue | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_membership_self_listing_through_auth_role` | Membership self listing through auth role | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_migration_identity_has_no_privileges_on_audit` | Migration identity has no privileges on audit | 1 | 1/1 passed | — | DEF-03 | **PASS** |
| `test_table_classification.py::test_no_foreign_key_from_non_ten_classes_into_ten` | No foreign key from non ten classes into ten | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_non_tenant_classes_have_no_plain_tenant_id` | Non tenant classes have no plain tenant id | 1 | 1/1 passed | — | DEF-12 | **PASS** |
| `test_table_classification.py::test_operator_plane_has_no_access_to_tenant_data` | Operator plane has no access to tenant data | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_ops_can_only_update_operator_side_grant_columns` | Ops can only update operator side grant columns | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_ops_cannot_read_customer_identity` | Ops cannot read customer identity | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_privilege_matrix_is_exact` | Privilege matrix is exact | 6 | 6/6 passed | — | — | **PASS** |
| `test_table_classification.py::test_profile_visibility_only_for_members_or_self` | Profile visibility only for members or self | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_public_has_no_table_privileges` | Public has no table privileges | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_rls_flag_matches_manifest` | Rls flag matches manifest | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_ten_tables_shape` | Ten tables shape | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_ten_unique_constraints_are_tenant_scoped` | Ten unique constraints are tenant scoped | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_tenant_plane_cannot_read_password_hash` | Tenant plane cannot read password hash | 1 | 1/1 passed | — | — | **PASS** |
| `test_table_classification.py::test_tenant_plane_cannot_touch_credential_or_platform_tables` | Tenant plane cannot touch credential or platform tables | 14 | 14/14 passed | — | — | **PASS** |
| `test_table_classification.py::test_views_over_tenant_data_would_need_security_invoker` | Views over tenant data would need security invoker | 1 | 1/1 passed | — | — | **PASS** |

## Pending specifications and gap demonstrations (XFAIL — NOT passes)

| Control | Status | XFAIL cases | What exists | Plan |
|---|---|---|---|---|
| **F-AUD-006** Immutable (WORM) audit checkpoint storage and external anchoring | NOT IMPLEMENTED | 5 | gap demo (runs today, fails its assertion); spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-DAT-006** Production key management (KMS) for data encryption and audit signing | NOT IMPLEMENTED | 6 | gap demo (runs today, fails its assertion); spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |

A control changes from NOT IMPLEMENTED to implemented only when its code exists, its specs pass with only the `@pending` marker removed, and `docs/control_map.yaml` is updated; the generator exits non-zero while a mapped pending spec is not in the XFAIL state.

## Coverage by required test category

| Required category (Phase 1 brief) | Automated tests | Status |
|---|---|---|
| cross-tenant read / write / delete | 4 | **PASS** |
| cross-tenant search | 29 | **PASS** |
| cross-tenant download | 4 | **PASS** |
| cross-tenant export / report / job / notification | 0 | **BLOCKED — those features do not exist (see BLOCKED_TESTS.md)** |
| BOLA / IDOR | 4 | **PASS** |
| missing tenant context | 2 | **PASS** |
| invalid tenant context | 3 | **PASS** |
| RLS bypass attempts | 44 | **PASS** |
| unauthorized role changes / privilege escalation | 5 | **PASS** |
| MFA bypass | 4 | **PASS** |
| MFA factor removal / lost-factor recovery abuse | 22 | **PASS** |
| account lock-out / brute force (temporary baseline) | 10 | **PASS** |
| session revocation | 5 | **PASS** |
| authorization default-deny | 4 | **PASS** |
| audit tampering | 6 | **PASS** |
| audit checkpoint completeness / continuity (H-11) | 16 | **PASS** |
| audit UPDATE / DELETE / TRUNCATE attempts | 24 | **PASS** |
| audit-write failure | 2 | **PASS** |
| SQL injection | 23 | **PASS** |
| file upload abuse (type confusion, archive bombs, traversal) | 45 | **PASS** |
| CSRF | 5 | **PASS** |
| XSS (where applicable) | 3 | **PASS (API/header level; no UI exists)** |
| secret exposure | 4 | **PASS** |
| insecure configuration | 47 | **PASS** |
