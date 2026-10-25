# Draft outreach message for P2-2 reviewer candidates

Send this (edited to taste) to a candidate reviewer or firm. Two versions below: a short first-contact
message for an initial feeler, and a fuller scoping email once they've expressed interest.

---

## Short version (first contact / DM / forum post)

> Subject: Paid code review — applied crypto + auth, ~63 files, Python/Django
>
> I'm looking for a short, scoped independent security code review of a Django/PostgreSQL application —
> not a penetration test, a source-level review of four specific areas:
>
> 1. An audit-log hash chain (canonical encoding, domain separation, SQL/Python byte-equivalence)
> 2. Ed25519-signed checkpoints over that chain (replay, ordering, key handling)
> 3. An AEAD envelope-encryption helper (nonces, AAD binding, HMAC uses)
> 4. Authentication / session / MFA (password, TOTP, WebAuthn, recovery codes, step-up)
>
> ~63 source + test files, a written brief with 25 known concerns already identified for you to adjudicate,
> and a manifest with SHA-256 digests of everything in scope. I need a signed written report: findings with
> your own severity ratings, a disposition per area, and a written independence statement (you'd need no
> prior involvement in this project's design or implementation).
>
> Is this something you take on, and could you give me a rough quote/timeline?

---

## Fuller scoping email (once they're interested)

> Subject: NsureGRC independent security review — scope and package
>
> Thanks for your interest. Here's the full scope.
>
> **What this is:** a focused source-code security review, not a penetration test and not a compliance
> audit. The codebase is a Django/DRF/PostgreSQL application (NsureGRC — a GRC/compliance platform, still
> pre-feature-development, Phase 1 "secure foundation" only: tenant isolation, auth, audit, evidence
> handling). All code was written by an AI coding assistant (Claude Code) under my direction; this review is
> the independent check on the security-critical parts before I build product features on top of it.
>
> **Four scopes** (yours to pick some or all of — crypto-focused scopes 1–3 and the AppSec-focused scope 4
> can go to different reviewers if that's a better fit):
>
> 1. **Audit hash construction** — `ngrc/audit/chain.py` + the SQL hash function. Is the canonical encoding
>    collision-safe, are the DB and Python implementations byte-identical, are domain separation and NULL
>    handling sound?
> 2. **Audit integrity / checkpoints** — `ngrc/audit/{sealer,signer,verifier,service}.py`. Ed25519-signed
>    checkpoints, chain + external-copy comparison, role separation, sealer/verifier protocol (replay,
>    ordering, key handling, failure modes).
> 3. **AEAD encryption helper** — `ngrc/core/crypto.py` + consumers (`authn/totp.py`, `authn/recovery.py`).
>    Envelope construction (nonces, AAD binding, wrapping, versioning), HMAC uses for tokens/recovery
>    codes/pepper.
> 4. **Authentication / session / MFA** — `ngrc/authn/*`, `ngrc/iam/*`, `ngrc/control_plane/*`,
>    `ngrc/authz/*`. Password/TOTP/WebAuthn/recovery-code/throttling/step-up state machines, session
>    handling, CSRF, the platform-operator realm.
>
> **What you'll receive:**
> - A zip of all in-scope source, tests, and design ADRs (~63 files + 9 context documents, ~320 KB),
>   digest `package_sha256 = 33bd252cec84155912301fd36e9a7a066dfedce0d7092c711412cea999ca0d9b`
> - A written brief (`INDEPENDENT_REVIEW_PACKAGE.md`) covering what the implementation claims to do in each
>   area, the threat model, and **25 concerns already identified** for you to confirm, refute, or expand on
> - Design decision records (Phase 0/1 ADRs) giving the "why" behind each mechanism
>
> **What I need back**, as a signed written report:
> - Your name, organisation, and relevant qualifications
> - A written independence statement (no prior involvement in this project's design, implementation, or
>   testing — true by construction here, since everything was AI-authored, but I still need it in writing)
> - A disposition per scope: approved / approved with conditions / rejected
> - Findings with your own severity ratings (critical/high/medium/low/info), each with a clear description
>   and suggested remediation
> - Explicit confirmation of the `package_sha256` above, so the review is tied to the exact code you looked at
>
> This becomes part of a permanent, append-only review record for the project (nothing is marked "passed"
> without your findings in your own words — no AI or automated review is accepted in this slot).
>
> **Not required:** a penetration test, infrastructure review, or any compliance framework mapping — purely
> the source-level crypto/AppSec review described above.
>
> Could you give me a quote and estimated turnaround based on the above? Happy to send the package as soon
> as you're ready to start.

---

## Notes for yourself before sending

- **Get 2–3 quotes** before committing — the price and turnaround for "63 files, 4 scopes, 25 pre-identified
  concerns" varies a lot by reviewer experience and availability.
- **Confirm no conflict before engaging**: whoever you pick must have had zero prior involvement with this
  project. Since only you (Rushi) directed/accepted the implementation (recorded in `REVIEW_RECORD.yaml`),
  anyone else genuinely qualifies on that count — just don't pick someone who already saw this code informally.
- **If the package goes stale** (any scoped file changes after you send it — check `generated_at` in
  `evidence/review_package/review_package_manifest.json` against your own commits), regenerate before
  sending: `uv run python scripts/build_review_package.py`.
- **When their report arrives**, don't transcribe it into `REVIEW_RECORD.yaml` yourself from a summary —
  use their own words/ratings for findings, severity, and disposition, per the file's own instructions.
