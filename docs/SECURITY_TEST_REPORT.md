# NsureGRC — Security Test Report (Phase 1 / v1.3-alpha)

*Generated 2026-10-20 19:51 UTC from `evidence/junit.xml`. Environment: Windows 11 workstation, Python 3.12 (uv), PostgreSQL 16 in WSL2 Ubuntu.*

**Execution result: 433 passed, 0 failed, 53 XFAIL, 0 skipped, 486 total (pytest, 62 s).** Tests run against a throw-away PostgreSQL database built by the real migrations, connecting as the real least-privilege runtime roles (never a superuser).

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
| DEF-15 | Account lock-out without an exit path - 20 failed logins for an e-mail address (10 for operators; 10 MFA failures for customers) set the account to recovery_required, but the ADR's "verified-email unlock + MFA, owner/admin notified, never a silent permanent lock" is not implemented | high (availability / lock-out denial of service by anyone who knows an e-mail address; contradicts D-P0-008 s4) | preparing the P2-2 review package (reading throttle.py against the ADR) | NOT FIXED. Decision needed from the project owner (keep the hard stop and accept the availability risk until F-ATH-008 exists, or remove the hard stop - back-off only - as an interim). Not changed unilaterally because either choice alters a security control. Tracked by the pending spec below and by plan section 5. | `tests/test_pending_controls.py::test_an_account_locked_by_failed_logins_has_an_email_unlock_path_and_the_owner_is_notified` | open |

## Results by test

Each row is one test function (parametrised cases are aggregated). *Remediation* names the defect, if any, that this test found or now guards. A test is `PASS` only if every case passed.

| Test | Purpose | Cases | Result | Failure details | Remediation | Final status |
|---|---|---|---|---|---|---|
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
| `test_authentication.py::test_absolute_timeout_even_with_continuous_activity` | Absolute timeout even with continuous activity | 1 | 1/1 passed | — | — | **PASS** |
| `test_authentication.py::test_account_recovery_required_after_many_failures` | Account recovery required after many failures | 1 | 1/1 passed | — | — | **PASS** |
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
| `test_ci_record.py::test_all_jobs_green_on_an_unchanged_workflow_is_the_only_pass` | All jobs green on an unchanged workflow is the only pass | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_run_metadata_must_be_present_and_well_formed` | Run metadata must be present and well formed | 5 | 5/5 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_container_job_without_docker_does_not_count` | The container job without docker does not count | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_real_record_says_ci_has_not_run` | The real record says ci has not run | 1 | 1/1 passed | — | — | **PASS** |
| `test_ci_record.py::test_the_workflow_file_existing_is_not_a_result` | The workflow file existing is not a result | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_a_fully_secure_configuration_passes` | A fully secure configuration passes | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_dev_only_markers_are_explicit` | Dev-only stand-ins must announce themselves so nobody mistakes them for production controls. | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_django_baseline_features_are_not_installed` | Django baseline features are not installed | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_each_insecure_setting_is_detected` | Each insecure setting is detected | 23 | 23/23 passed | — | — | **PASS** |
| `test_config_security.py::test_each_process_plane_receives_only_its_own_database_roles` | Each process plane receives only its own database roles | 3 | 3/3 passed | — | — | **PASS** |
| `test_config_security.py::test_http_security_settings_are_secure_by_default` | Http security settings are secure by default | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_insecure_database_settings_are_detected` | Insecure database settings are detected | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_missing_required_secrets_stop_startup_and_nothing_has_a_default` | Missing required secrets stop startup and nothing has a default | 4 | 4/4 passed | — | — | **PASS** |
| `test_config_security.py::test_no_test_only_code_ships_in_the_application_package` | No test only code ships in the application package | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_production_settings_refuse_to_start_while_dev_only_components_are_the_only_ones_available` | Production settings refuse to start while dev only components are the only ones available | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_runtime_roles_in_database_settings_are_not_privileged` | Runtime roles in database settings are not privileged | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_signing_key_and_env_files_are_gitignored` | Signing key and env files are gitignored | 1 | 1/1 passed | — | — | **PASS** |
| `test_config_security.py::test_weak_secret_key_and_wildcard_hosts_stop_startup` | Weak secret key and wildcard hosts stop startup | 1 | 1/1 passed | — | — | **PASS** |
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
| `test_pending_controls.py::test_a_factor_belonging_to_someone_else_is_not_found` | A factor belonging to someone else is not found | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_a_support_session_cannot_download_evidence_under_a_metadata_only_grant` | A support session cannot download evidence under a metadata only grant | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_admin_assisted_reset_needs_a_different_approver_with_step_up` | Admin assisted reset needs a different approver with step up | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_an_account_locked_by_failed_logins_has_an_email_unlock_path_and_the_owner_is_notified` | DEF-15: the hard stop sets `recovery_required`; the ADR requires 'verified-email unlock + MFA, owner/admin notified, never a silent | 1 | 0/1 passed, 1 XFAIL | — | DEF-15 | **XFAIL — not a pass** |
| `test_pending_controls.py::test_an_operator_cannot_remove_their_own_webauthn_credential` | An operator cannot remove their own webauthn credential | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_an_overdue_verification_raises_its_own_alert` | An overdue verification raises its own alert | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_cross_tenant_download_is_not_found_leaks_nothing_and_is_audited` | Cross tenant download is not found leaks nothing and is audited | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_download_event_records_object_revision_hash_actor_and_result` | Download event records object revision hash actor and result | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_download_fails_closed_when_the_audit_event_cannot_be_written` | Download fails closed when the audit event cannot be written | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_download_requires_authentication_and_the_evidence_read_permission` | Download requires authentication and the evidence read permission | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_download_streams_exact_bytes_through_an_authorization_checked_endpoint` | Download streams exact bytes through an authorization checked endpoint | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_every_indexed_document_and_query_carries_the_tenant_id` | Every indexed document and query carries the tenant id | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_factor_removal_requires_step_up` | Factor removal requires step up | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_ciphertext_cannot_be_read_after_a_master_key_change` | GAP DEMO (runs now): the dev provider has a single master key and ignores the key id stored beside the ciphertext, so rotation | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_dev_signing_key_is_readable_by_the_process_that_signs` | GAP DEMO (runs now): the dev signer's private key is a file the application process can read, so a host-level attacker (or an | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_dropping_the_latest_exported_checkpoint_goes_unnoticed` | GAP DEMO (runs now): with a plain-file export, the newest checkpoint copy can be removed and the verifier - which only checks the | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_gap_demo_the_dev_export_file_can_be_rewritten_by_the_application_process` | GAP DEMO (runs now): the dev sink is an ordinary file opened for append by the same process that writes the database, so it is not | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_harness_separates_absent_features_from_broken_specs` | Self-test of the harness (RUNS and must PASS): an absent module/route is FeatureAbsent; an existing one resolves. Any other error | 1 | 1/1 passed | — | — | **PASS** |
| `test_pending_controls.py::test_incremental_verification_reaches_the_same_verdict_as_a_full_run` | Incremental verification reaches the same verdict as a full run | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_kms_provider_envelope_round_trip_and_aad_binding` | Kms provider envelope round trip and aad binding | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_kms_provider_keeps_old_ciphertext_readable_after_rotation` | Kms provider keeps old ciphertext readable after rotation | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_kms_signer_is_sign_only_and_the_private_key_is_not_exportable` | Kms signer is sign only and the private key is not exportable | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_missing_external_checkpoint_copy_is_a_violation_in_production_mode` | Missing external checkpoint copy is a violation in production mode | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_object_keys_are_tenant_prefixed_and_cannot_be_chosen_by_the_client` | Object keys are tenant prefixed and cannot be chosen by the client | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_platform_support_can_never_reset_a_customers_mfa` | Platform support can never reset a customers mfa | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_production_settings_start_only_with_kms_backends_and_hold_no_key_material` | Production settings start only with kms backends and hold no key material | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_recovery_code_flow_restores_access_notifies_and_audits` | Recovery code flow restores access notifies and audits | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_recovery_endpoints_are_throttled_and_do_not_reveal_whether_an_account_exists` | Recovery endpoints are throttled and do not reveal whether an account exists | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_removal_must_leave_two_recovery_options` | ADR D-P0-008 s7: after removal the account keeps two factors, or one factor plus recovery codes. | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_removal_revokes_other_sessions_and_is_audited` | Removal revokes other sessions and is audited | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_restricted_class_evidence_is_excluded_from_bulk_export` | Restricted class evidence is excluded from bulk export | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_scheduled_run_detects_tampering_records_a_violation_and_raises_the_alert` | Scheduled run detects tampering records a violation and raises the alert | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_scheduled_run_verifies_every_stream_and_records_each_result` | Scheduled run verifies every stream and records each result | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_sealer_does_not_report_a_checkpoint_published_until_the_sink_acknowledges_it` | Sealer does not report a checkpoint published until the sink acknowledges it | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_search_hits_are_reauthorised_per_item_before_return` | Search hits are reauthorised per item before return | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_search_query_syntax_cannot_widen_the_tenant_filter` | Search query syntax cannot widen the tenant filter | 6 | 0/6 passed, 6 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_search_returns_only_the_callers_tenant` | Search returns only the callers tenant | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_search_without_valid_tenant_context_fails_closed` | Search without valid tenant context fails closed | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_sink_uses_credentials_the_application_database_and_runtime_roles_do_not_hold` | Sink uses credentials the application database and runtime roles do not hold | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_stored_object_that_no_longer_matches_its_recorded_hash_is_refused` | Stored object that no longer matches its recorded hash is refused | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_the_last_factor_cannot_be_removed` | The last factor cannot be removed | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_the_last_owner_requires_platform_security_approval_and_the_same_cooling_off` | The last owner requires platform security approval and the same cooling off | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_the_legitimate_user_can_cancel_during_cooling_off_and_all_sessions_are_revoked_on_completion` | The legitimate user can cancel during cooling off and all sessions are revoked on completion | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_the_new_factor_cannot_complete_before_the_cooling_off_period` | The new factor cannot complete before the cooling off period | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_the_verification_job_runs_only_as_the_verifier_identity_and_cannot_be_disabled_by_a_tenant` | The verification job runs only as the verifier identity and cannot be disabled by a tenant | 1 | 0/1 passed, 1 XFAIL | — | — | **XFAIL — not a pass** |
| `test_pending_controls.py::test_unscanned_or_quarantined_evidence_is_never_served` | Unscanned or quarantined evidence is never served | 2 | 0/2 passed, 2 XFAIL | — | — | **XFAIL — not a pass** |
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
| **F-AUD-007** Scheduled continuous audit verification with alerting | NOT IMPLEMENTED | 6 | spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-AUD-006** Immutable (WORM) audit checkpoint storage and external anchoring | NOT IMPLEMENTED | 6 | gap demo (runs today, fails its assertion); spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-DAT-004** Authorization-checked evidence download (C-6) | NOT IMPLEMENTED | 11 | spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-AUZ-005** Cross-tenant search isolation | NOT IMPLEMENTED | 10 | spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-DAT-006** Production key management (KMS) for data encryption and audit signing | NOT IMPLEMENTED | 6 | gap demo (runs today, fails its assertion); spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-ATH-014** MFA factor removal | NOT IMPLEMENTED | 6 | spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |
| **F-ATH-015** Lost-factor recovery and lock-out exit | NOT IMPLEMENTED | 8 | spec (stops at the absent interface) | `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` |

A control changes from NOT IMPLEMENTED to implemented only when its code exists, its specs pass with only the `@pending` marker removed, and `docs/control_map.yaml` is updated; the generator exits non-zero while a mapped pending spec is not in the XFAIL state.

## Coverage by required test category

| Required category (Phase 1 brief) | Automated tests | Status |
|---|---|---|
| cross-tenant read / write / delete | 4 | **PASS** |
| cross-tenant search / download | 0 | **BLOCKED — no search/download features exist yet; executable specs are XFAIL (see BLOCKED_TESTS.md)** |
| BOLA / IDOR | 4 | **PASS** |
| missing tenant context | 2 | **PASS** |
| invalid tenant context | 3 | **PASS** |
| RLS bypass attempts | 44 | **PASS** |
| unauthorized role changes / privilege escalation | 5 | **PASS** |
| MFA bypass | 4 | **PASS** |
| session revocation | 5 | **PASS** |
| authorization default-deny | 4 | **PASS** |
| audit tampering | 6 | **PASS** |
| audit UPDATE / DELETE / TRUNCATE attempts | 24 | **PASS** |
| audit-write failure | 2 | **PASS** |
| SQL injection | 23 | **PASS** |
| CSRF | 5 | **PASS** |
| XSS (where applicable) | 3 | **PASS (API/header level; no UI exists)** |
| secret exposure | 4 | **PASS** |
| insecure configuration | 40 | **PASS** |
