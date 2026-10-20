# NsureGRC — Open Items Register (carried from Phase 0; nothing silently resolved)

Items **O-x** are the Phase 0 open items. No value has been invented for any of them. Items **H-x** are hardening/engineering follow-ups found
during Phase 1 verification. "Dev-only stand-in" means a clearly labelled development substitute exists; it is **not** a production control.

| ID | Item | Phase 1 treatment | Needed by |
|---|---|---|---|
| O-1 | Exact Django/Python/PostgreSQL versions | Recorded in `DEPENDENCIES.md` (lifecycle from a third-party aggregator; vendor confirmation outstanding) | done (confirm) |
| O-2 | Retention periods (audit, evidence, backups, logs, sessions) and legal hold | **No value set.** Purge procedure NOT IMPLEMENTED (F-AUD-004) | before retention jobs / production |
| O-3 | RPO / RTO and restore-test frequency | **No value set.** DR NOT IMPLEMENTED (F-DR-001) | before production |
| O-4 | Hosting / cloud / **KMS** / **immutable (WORM) storage** / managed Postgres | **Not selected.** Dev-only stand-ins: `KEY_PROVIDER=local` (AES-256-GCM, master key from the environment) and `AUDIT_SIGNER_BACKEND=dev_file` (Ed25519 key file on the DB host) with a local export directory. `config.settings.prod` **refuses to start** while these are the only options | before audit anchoring & key management go live |
| O-5 | Staffing for two-person rules; post-incident review period | Two-person rules are technically enforced (approver ≠ requester; break-glass needs Security + Admin). **Organisational capacity and review period undefined** | before production |
| O-6 | Frontend technology / BFF shape | Not started; API is JSON-only with CSRF tokens delivered by `GET …/auth/csrf/` | before UI work |
| O-7 | E-mail provider and SPF/DKIM/DMARC | Django locmem backend in tests; no provider configured | before auth e-mail goes live |
| O-8 | **Legal/privacy review** (erasure vs backups/audit retention, DPDP/GDPR processor duties) and **framework content licensing** (ISO etc.) | **Not done; no legal conclusion asserted anywhere.** Framework ingestion NOT IMPLEMENTED | before production data / catalogue ingestion |
| O-9 | Tenant data-portability export in P0? | Not decided | Phase 3 planning |
| O-10 | **Independent crypto / AppSec review** of the audit hash construction and AEAD helper | **NOT DONE.** Primitives are standard (SHA-256, AES-256-GCM, Ed25519, HMAC-SHA-256, Argon2id); the *constructions* are home-written and unreviewed | **Phase 1 exit (see gate report)** |
| O-11 | Malware-scanning engine | Not started | Phase 3 |
| O-12 | Breach-corpus source for the password blocklist | A small SEED list ships (`ngrc/authn/data/blocklist_seed.txt`); **not** a breach corpus | Phase 1 auth → before production |
| H-01 | DB guard trigger `plt_support_grant_guard` still lets `platform_admin` be a *requester*; the application layer forbids it (DEF-07) | Tighten the trigger via a new migration | next migration window |
| H-02 | Operations: clusters created before DEF-03 must re-run `GRANT ngrc_audit_owner TO ngrc_owner WITH INHERIT FALSE, SET TRUE` | Documented in `OPERATIONS_NOTES.md` | before any shared environment |
| H-03 | Scheduled audit verification + alert routing | Library exists and is tested; scheduler NOT IMPLEMENTED (F-AUD-003) | Phase 2 |
| H-04 | Supply chain: hash-pinned requirements, SBOM, signed images, Actions pinned by SHA, base image by digest | Not done | before first release |
| H-05 | Session self-service (list/revoke my sessions), factor removal, lost-factor recovery, e-mail change | NOT IMPLEMENTED (F-ATH-007, F-ATH-008) | Phase 2 |
| H-06 | Tenant suspend / offboard lifecycle API | NOT IMPLEMENTED (DB column and denial path tested) | Phase 2 |
| H-07 | Move Python from 3.12 (security-only) to a currently supported series | Not changed | before production |
| H-08 | CI has never run; container image never built | BLOCKED (`BLOCKED_TESTS.md` B-07, B-08) | first push |
| H-09 | No penetration test / DAST | Not performed | before production |
