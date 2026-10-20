# NsureGRC — Open Items Register (carried from Phase 0; nothing silently resolved)

Items **O-x** are the Phase 0 open items. No value has been invented for any of them. Items **H-x** are hardening/engineering follow-ups found
during Phase 1 verification. "Dev-only stand-in" means a clearly labelled development substitute exists; it is **not** a production control.
Updated for the P2 gate work (2026-10-21).

| ID | Item | Treatment / status | Needed by |
|---|---|---|---|
| O-1 | Exact Django/Python/PostgreSQL versions | Recorded in `DEPENDENCIES.md` (lifecycle from a third-party aggregator; vendor confirmation outstanding) | done (confirm) |
| O-2 | Retention periods (audit, evidence, backups, logs, sessions) and legal hold | **No value set.** Purge procedure NOT IMPLEMENTED (F-AUD-004) | before retention jobs / production |
| O-3 | RPO / RTO and restore-test frequency | **No value set.** DR NOT IMPLEMENTED (F-DR-001) | before production |
| O-4 | Hosting / cloud / **KMS** / **immutable (WORM) storage** / managed Postgres | **Not selected.** Dev-only stand-ins: `KEY_PROVIDER=local` and `AUDIT_SIGNER_BACKEND=dev_file` with a local export directory; `config.settings.prod` **refuses to start** while these are the only options. Provider-neutral plans and specs exist: `plans/P2-3_IMPLEMENTATION_PLANS.md` s6, s7 (F-DAT-006, F-AUD-006) | before audit anchoring & key management go live |
| O-5 | Staffing for two-person rules; post-incident review period | Two-person rules are technically enforced. **Organisational capacity and review period undefined** | before production |
| O-6 | Frontend technology / BFF shape | Not started | before UI work |
| O-7 | E-mail provider and SPF/DKIM/DMARC | Django locmem backend in tests; no provider. Needed by recovery/unlock notifications (F-ATH-015) | before auth e-mail goes live |
| O-8 | **Legal/privacy review** and **framework content licensing** | **Not done; no legal conclusion asserted anywhere.** | before production data / catalogue ingestion |
| O-9 | Tenant data-portability export in P0? | Not decided | Phase 3 planning |
| O-10 | **Independent crypto / AppSec review** | **BLOCKED — no independent reviewer.** Review package, scope, record and checker are prepared (`review/`); nothing has been reviewed. A reviewer matching an implementer, or an AI tool, is rejected by `scripts/check_review_record.py` | **Phase 1 exit** |
| O-11 | Malware-scanning engine | Not started | Phase 3 |
| O-12 | Breach-corpus source for the password blocklist | A small SEED list ships; **not** a breach corpus | before production |
| H-01 | `plt_support_grant_guard` accepted `platform_admin` as requester (and had a same-state hole) | **CLOSED 2026-10-21** — migration `control_plane/0004`, 26 regression tests (`tests/test_support_grant_db_guard.py`), 25 of which fail against the Phase 1 trigger (DEF-14) | done |
| H-02 | Clusters created before DEF-03 must re-run `GRANT ngrc_audit_owner TO ngrc_owner WITH INHERIT FALSE, SET TRUE` | Documented in `OPERATIONS_NOTES.md`; a freshly bootstrapped cluster (`ci_bootstrap.sh`) has it | before any shared environment |
| H-03 | Scheduled audit verification + alert routing | NOT IMPLEMENTED — plan s3, 6 executable specs (F-AUD-007) | Phase 2 |
| H-04 | Supply chain: hash-pinned requirements, SBOM, signed images, Actions pinned by SHA, base image by digest | Not done | before first release |
| H-05 | Session self-service, factor removal, lost-factor recovery, e-mail change | NOT IMPLEMENTED — plans s4, s5; specs for factor removal (F-ATH-014) and recovery/unlock (F-ATH-015). Session self-service and e-mail change still have no spec | Phase 2 |
| H-06 | Tenant suspend / offboard lifecycle API | NOT IMPLEMENTED (DB column and denial path tested). No plan or spec written yet | Phase 2 |
| H-07 | Move Python from 3.12 (security-only) to a currently supported series | Not changed | before production |
| H-08 | CI has never run; container image never built | **BLOCKED** — needs the project owner to create a repository and push (`ci/CI_RUNBOOK.md`); record `ci/CI_RUN_RECORD.yaml` says NOT_RUN | first push |
| H-09 | No penetration test / DAST | Not performed | before production |
| H-10 | **DEF-15 — lock-out without an exit path.** 20 failed logins (10 for operators; 10 MFA failures) set `recovery_required`, but the ADR's verified-e-mail unlock is not implemented, so a stranger who knows an e-mail address can lock that account until a DBA intervenes | **OPEN — decision needed from the project owner:** (a) keep the hard stop and accept the availability risk until F-ATH-015 exists, or (b) remove the hard stop (back-off only) as an interim. Not changed unilaterally: either alters a security control. Spec: `test_an_account_locked_by_failed_logins_has_an_email_unlock_path…` | before any real user |
| H-11 | Verifier does not require a sink copy of every database checkpoint (newest export record can be removed unnoticed) | Demonstrated by a gap demo; plan item W-3 (F-AUD-006) | with the WORM sink |
| TD-001 | WSL2 networking is extremely slow on the dev workstation | Technical debt, **not** a gate blocker — `TECH_DEBT.md` | when convenient |
