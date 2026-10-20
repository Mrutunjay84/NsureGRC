# NsureGRC — Independent security review package (P2-2)

**Review status: BLOCKED — no independent reviewer has been engaged, and nothing in this package has been reviewed.**
This document prepares the material a reviewer needs. It is **not** a review, it contains **no** approval, and nothing in it may be cited as
cryptographic or AppSec sign-off. The authors of the mechanisms (see `REVIEW_RECORD.yaml` → `implementers`) are not permitted to approve them.

## 1. Purpose, independence and what counts as a review
* **Purpose:** satisfy Phase 0 exit gate item "crypto/AppSec review (O-10) complete" for four areas: (1) audit hash construction, (2) audit integrity /
  checkpoint mechanism, (3) AEAD / encryption helper, (4) authentication, session and MFA implementation.
* **Independence (all required):** the reviewer did not design, implement, test or approve any of the code under review; is not employed to deliver it;
  states this in writing; and is competent in applied cryptography (areas 1–3) and application security / authentication (area 4). Both competences
  may be two people. **Output of an AI assistant, a scanner or a test suite is not an independent review** (the checker rejects such reviewers).
* **What the project must record** (all in `REVIEW_RECORD.yaml`, taken from the reviewer's own signed report): reviewer, scope, findings, severity,
  remediation, final disposition, report digest, and the digest of the package they reviewed.
* **Not claimed anywhere:** that this review would constitute certification, a penetration test, or standards compliance.

## 2. How to obtain the material
```
uv run python scripts/build_review_package.py     # -> evidence/review_package/nsuregrc_review_package_<digest12>.zip + review_package_manifest.json
uv run python scripts/check_review_record.py      # shows what the current record is allowed to mean (BLOCKED today)
```
The manifest lists every file with its SHA-256 and line count and a `package_sha256` over the *reviewed material* (source, tests, Phase 0 ADRs). If any
reviewed file changes after a review, the checker marks that review **STALE**. The digest is not signed; it protects against accidental change only.

## 3. Scope (files per area are listed in `review_scope.yaml`)

| Area | Question for the reviewer | Primary files |
|---|---|---|
| 1. Audit hash construction | Is the canonical encoding unambiguous and collision-safe; are DB and Python implementations byte-identical for all inputs; are the domain-separation tags, versioning and NULL handling sound? | `ngrc/audit/chain.py`, `audit._lp/_t/_event_hash` in `ngrc/audit/migrations/0001_audit_schema.py` |
| 2. Audit integrity / checkpoints | Does chain + signed checkpoint + external copy detect the attacker classes in §5; are the role separation and append-only enforcement adequate; is the sealer/verifier protocol sound (replay, ordering, key handling, failure modes)? | `ngrc/audit/{sealer,signer,verifier,service}.py`, audit migration 0001/0002, `db/bootstrap/00_roles.sql` |
| 3. AEAD / encryption helper | Is the envelope construction correct (nonces, AAD binding, wrapping, versioning, error handling, key-use limits); are hashing/HMAC uses of tokens, recovery codes and the pepper correct? | `ngrc/core/crypto.py` + consumers `authn/totp.py`, `authn/recovery.py` |
| 4. Authentication / session / MFA | Do password, TOTP, WebAuthn, recovery codes, throttling, step-up, sessions, CSRF, and the operator realm resist the threats in §5; are the state machines and fail-closed paths complete? | `ngrc/authn/*`, `ngrc/iam/{services,views}.py`, `ngrc/control_plane/{views,support}.py` and its migrations, `ngrc/authz/*` |

## 4. What the implementation claims (to be tested by the reviewer, not accepted)

### 4.1 Audit event hash (`NGRC-AUDIT-v1`)
* One hash chain per tenant (`stream_key` = tenant UUID text) and one `platform` chain. Genesis = `SHA-256("NGRC-AUDIT-v1-genesis|" || stream_key)`.
* `hash = SHA-256( T("NGRC-AUDIT-v1") ‖ T(stream) ‖ T(seq) ‖ LP(prev_hash) ‖ T(event_id) ‖ T(occurred_at UTC, microsecond ISO-8601 "Z") ‖ T(tenant) ‖
  T(actor_type) ‖ T(actor_id) ‖ T(grant) ‖ T(action) ‖ T(object_type) ‖ T(object_id) ‖ T(result) ‖ T(reason) ‖ T(host(source_ip)) ‖ T(user_agent) ‖
  T(session_ref) ‖ T(request_id) ‖ T(details::text) ‖ T(data_class) ‖ T(schema_version) )`; `LP(b)` = 4-byte big-endian length ‖ b, NULL = `0xFFFFFFFF`; `T(s)` = `LP(UTF-8(s))`.
* Computed inside the append transaction under a row lock on `audit.chain_head` (serialises appenders per stream). Recomputed independently in Python by the verifier
  from stored column values (`details::text`, `host(ip)` as PostgreSQL emits them).

### 4.2 Checkpoints, sealing, verification
* Sealer (`ngrc_audit_sealer`: SELECT chain_head, INSERT checkpoint) signs `"NGRC-CHECKPOINT-v1|stream|seq|head_hash_hex|issued_at|key_id"` with **Ed25519**
  and stores it in `audit.checkpoint`; the same record is appended to an export file. **DEV-ONLY:** the signing key is a local file and the export is a plain file
  (not WORM). No KMS signer, no production sink, no scheduler exist (plans: `docs/plans/P2-3_IMPLEMENTATION_PLANS.md` §3, §6, §7).
* Verifier (`ngrc_audit_verifier`, read-only + INSERT run record) checks gapless `seq`, linkage, recomputed hashes, head vs last event, DB checkpoint vs chain,
  checkpoint signature against supplied public keys, and exported records vs chain. A violation writes `audit.integrity_violation`.
* Append-only enforcement: no runtime role holds INSERT/UPDATE/DELETE/TRUNCATE on event tables; `SECURITY DEFINER` append functions (owner `ngrc_audit_owner`,
  pinned `search_path`) validate action registry, writer role, tenant binding and a detail-key allow-list; `BEFORE UPDATE/DELETE/TRUNCATE` triggers refuse mutation
  even for the owner; `ngrc_owner` has `SET` but not `INHERIT` on the audit owner (found and fixed in Phase 1: DEF-03).
* Stated limit (ADR §4): an actor with schema-owner or superuser rights can alter rows and recompute the in-DB chain **back to the most recent externally held checkpoint**;
  detection beyond the last anchor is the claim, prevention at superuser level is not.

### 4.3 AEAD / envelope helper (`ngrc/core/crypto.py`)
* Per record: random 256-bit data key; payload encrypted with AES-256-GCM (random 96-bit nonce) under AAD `"{scope}|{record_id}|{field}"`; the data key is wrapped with
  AES-256-GCM under a 256-bit master key (random nonce, same AAD). Blob = version ‖ key-id ‖ nonce₁ ‖ wrapped key ‖ nonce₂ ‖ ciphertext.
* Master key = `NGRC_FIELD_ENCRYPTION_KEY` from the environment (**DEV-ONLY** local provider; production start-up refuses it). Key id is written but not used on read.
* Token hashing: session ids / reset tokens `SHA-256` of 256-bit CSPRNG values; recovery codes (80-bit) `HMAC-SHA-256` with `NGRC_TOKEN_PEPPER` (env var in P1; the ADR
  calls for a KMS-held pepper); failed-login identifiers keyed-hashed with the same pepper.

### 4.4 Authentication, sessions, MFA
* Passwords: Argon2id (`t=3, m=64 MiB, p=4` as shipped defaults, to be benchmarked), NFC normalisation, 12–128 code points, local blocklist, bounded concurrent hashing, timing
  equalisation for unknown accounts.
* TOTP: RFC 6238, SHA-1/6 digits/30 s, ±1 step, replay prevention via per-factor highest-accepted step (atomic compare-and-set), secret sealed with the helper above.
* WebAuthn: maintained `webauthn` library; attestation none; origin allow-list; single-use 5-minute challenges bound to the session and to a purpose/binding string; UV required for
  operators and privileged roles; signature-counter regression flags the credential. Operator realm: WebAuthn only, no recovery codes, T2 per-action assertions bound to a grant id.
* Sessions: opaque 256-bit ids, only SHA-256 stored, `__Host-` cookies, rotation on login/MFA/tenant switch/step-up, idle and absolute timeouts, immediate server-side revocation.
* Throttling: DB-backed per-account progressive back-off (free 5, 60 s doubling to 900 s) and per-IP window; hard stop → `recovery_required` (20 failures; operator realm 10).
* Separate customer and operator realms (own tables, cookies, URL planes, process planes).

## 5. Threat model summary and non-goals
Attacker classes considered: (A) unauthenticated internet attacker; (B) authenticated tenant user attacking other tenants or higher roles; (C) stolen session/cookie;
(D) attacker with SQL injection as the runtime role; (E) attacker with read access to the database or backups; (F) attacker with write access to audit tables (schema-owner
level); (G) malicious or compromised platform operator; (H) host-level attacker on the application server (can read env/keys).
**Non-goals / not protected:** a database superuser who also controls the external checkpoint copy; a compromised KMS/HSM; physical attacks; nation-state endpoint compromise; the
dev-only components when used in production (production start-up refuses them).

## 6. Evidence available to the reviewer
* `docs/SECURITY_TEST_REPORT.md`, `evidence/junit.xml` — every test, with purpose and result (**implementer-authored tests**; not independent evidence).
* Tests per area are listed in `review_scope.yaml`. Notable: hostile-SQL bypass attempts, tamper/rewrite/truncate/forged-checkpoint tests, MFA-bypass and fixation tests,
  step-up binding tests, the support-grant guard regression suite, and the *gap demos* in `tests/test_pending_controls.py`.
* `docs/defects_found.yaml` — defects found while verifying (DEF-01…): the reviewer should treat each as evidence that the design needed correction and look for siblings.
* Static analysis and dependency results: `docs/SECURITY_SCAN_REPORT.md`. No penetration test or DAST has been performed.

## 7. Concerns the implementers already know about (NOT findings, NOT reviewed — listed so the reviewer need not rediscover them)
**Audit**
1. `details::text` and `host(ip)` hash inputs depend on PostgreSQL's text output formats; a major-version change could change them for old rows (a verification failure, not a bypass).
2. Checkpoint message uses `|`-joined text, not the length-prefixed encoding used for events. Fields are constrained today (`platform`/UUID, hex, ISO time, `dev-<hex>` key id); a future KMS key id containing `|` would be ambiguous.
3. The platform stream is a single serialised writer (row lock). Anonymous failed logins write to it, so write contention is an availability risk under attack.
4. `ngrc_owner` may `SET ROLE ngrc_audit_owner` (needed by migrations). A holder of that credential can disable triggers and rewrite history; detection then depends on checkpoints and the external copy.
5. **The verifier only checks exported records that exist** — removing the newest export record is not detected (`test_gap_demo_dropping_the_latest_exported_checkpoint_goes_unnoticed`, runs today; plan item W-3).
6. Sealing is invoked manually; there is no schedule, no checkpoint-lag alert, no incremental verification (plans §3, §7). `seal_all` appends the export record even when `ON CONFLICT DO NOTHING` discarded the database row (concurrent sealers could leave duplicate export lines).
7. Signing key (dev) is a readable file; no KMS signer; no key rotation procedure (`test_gap_demo_dev_signing_key_is_readable_by_the_process_that_signs`).

**AEAD / hashing**
8. Random 96-bit nonces under a single long-lived master key with no rotation: no mechanism bounds the number of wrap operations per key.
9. The key id in the blob is ignored on read; changing the master key orphans all ciphertext (`test_gap_demo_ciphertext_cannot_be_read_after_a_master_key_change`).
10. `open_sealed` slices a binary format without bounds checks; malformed blobs raise `IndexError`/`ValueError`/`InvalidTag` rather than one error type. Callers read blobs only from the database.
11. AAD is a `|`-joined string (not length-prefixed); the three components are internal (UUID/field name) today.
12. `_master_key` silently truncates a longer decoded key to 32 bytes; no KDF (the key is used directly).
13. One pepper (`TOKEN_PEPPER`) keys both recovery-code digests and failed-login identifier hashes (message prefix differs for one only). The pepper is an environment variable, not KMS-held.

**Authentication / sessions**
14. **Lock-out DoS without an exit path (DEF-14, OPEN):** 20 failed logins for an e-mail address (10 for operators) set the account to `recovery_required`, but the ADR's "verified-email unlock + MFA, owner/admin notified, never a silent permanent lock" is **not implemented**. A stranger who knows an address can lock that account out until a database administrator intervenes. Needs a decision (§8).
15. WebAuthn counter-regression detection depends on matching the substring `"sign count"` in the library's exception message; a library upgrade could silently disable it (a test exists but only protects when it is run after the upgrade). Authenticators that always report counter 0 are never flagged.
16. Idle timeout is updated at most every 60 s (`TOUCH_INTERVAL_S`), so effective idle granularity is a minute.
17. A WebAuthn challenge is consumed by any attempt (success or failure) — intended; it also means a failed attempt requires a new `begin` call.
18. TOTP accepts a ±1 step window; two distinct valid codes inside a window cannot both be accepted (replay guard), by design.
19. Customer-realm MFA lock-out after 10 failures also has no unlock path today (same root cause as 14).
20. Factor removal, lost-factor recovery, e-mail change, and self-service session revocation are not implemented (`docs/plans/P2-3_IMPLEMENTATION_PLANS.md` §4–5).

## 8. Questions the project wants answered
1. Is the length-prefixed event encoding sufficient, and should checkpoints and AAD adopt the same? Is `NGRC-AUDIT-v1` adequately domain-separated for future versions?
2. Is the chain + checkpoint + external copy design sound against attacker class F, and what is the minimum viable verifier rule set (see concern 5)?
3. Is envelope encryption with a single wrap key acceptable until a KMS exists; what usage limits and rotation design do you require before any real secret is stored?
4. Review the support-grant state machine and its database guard (migration 0004) for remaining bypass paths.
5. For concern 14, which interim behaviour do you recommend: keep the hard stop (security-conservative, availability risk) or remove it until the unlock flow exists (back-off only)?
6. Which parts of the authentication design need testing with hardware authenticators or in a deployed environment before you would sign off?

## 9. What the reviewer should deliver (so the record can be completed)
A signed report stating: reviewer(s) and organisation; independence statement; the package digest reviewed; scope covered and not covered; each finding with
severity (critical/high/medium/low/info), evidence and recommended remediation; and an overall disposition per scope (approved / approved with conditions / rejected).
The project then records remediation and retest evidence per finding in `REVIEW_RECORD.yaml`. A scope is complete only when `scripts/check_review_record.py` says so.
