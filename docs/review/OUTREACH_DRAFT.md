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

---

## Upwork-specific posts

Two separate job posts, not one — Upwork freelancers self-select heavily by title and skill tags, and
"cryptography reviewer" and "Django security reviewer" are different pools of people. A combined post
reads as unfocused to both. Post both; whoever's strongest across all four scopes will say so in their
proposal, and you can always merge the engagement later.

### Post 1 — the crypto scopes (1–3)

**Title:** `Independent security code review: audit hash chain, signed checkpoints, AEAD crypto (Python)`

**Category:** Web, Mobile & Software Dev → Cybersecurity & Data Protection → Pen Testing & Security Analysis
*(or Cybersecurity & Compliance → Application Security, depending on what your Upwork account shows —
pick whichever lists cryptography-adjacent skill tags)*

**Skills to tag:** `Cryptography`, `Python`, `Code Review`, `Application Security`, `PostgreSQL`,
`Vulnerability Assessment` — do **not** tag generic `Django`/`Web Development` here, that's what pulls in
AppSec generalists without crypto depth; this post wants to filter them out.

**Description** (paste the "Fuller scoping email" above, scopes 1–3 only, trimmed to this intro):

> I need a focused, scoped independent security code review of three specific cryptographic/integrity
> mechanisms in a Django/PostgreSQL application — not a penetration test, not a full-app audit.
>
> [paste scopes 1–3 from the fuller email above verbatim]
>
> This is a **source-level review of ~45–50 files** (the crypto-relevant subset of a ~63-file package),
> with a written brief and 25 pre-identified concerns for you to confirm, refute, or expand on. I need a
> **signed written report**: your own severity ratings per finding, a disposition per scope, and a written
> independence statement. All code was written by an AI coding assistant under my direction — this review
> is the independent check before I build on it.
>
> Full package (digest, manifest, brief) sent after we agree scope and price.

**Budget:** Fixed-price. Don't guess a number from me — post it as a range once you've seen 2–3 proposals
land, or use Upwork's "I'll finalize budget with freelancers" option if your account offers it. A tight,
pre-scoped review like this (known file count, known concerns list, no discovery phase) is exactly the
shape Upwork fixed-price does well.

**Screening questions** (Upwork lets you attach these to the post):
1. "Have you done a paid independent review of Ed25519 signing or AEAD/envelope encryption before? Briefly describe one (client names can stay anonymous)."
2. "Can you provide a redacted writing sample from a past security review report?"
3. "Do you have any prior involvement — design, implementation, informal review — with this project? (Expected answer: no; this is a hard requirement, not a formality.)"

### Post 2 — the AppSec scope (4)

**Title:** `Independent security review: Django authentication, sessions & MFA (TOTP/WebAuthn)`

**Category:** Web, Mobile & Software Dev → Cybersecurity & Data Protection → Pen Testing & Security Analysis

**Skills to tag:** `Django`, `Python`, `Application Security`, `Authentication`, `Code Review`, `OWASP`

**Description:**

> Independent source-code security review of authentication, session management and MFA in a Django/DRF
> application — not a penetration test.
>
> [paste scope 4 from the fuller email above verbatim: password/TOTP/WebAuthn/recovery-code/throttling/
> step-up state machines, session handling, CSRF, the platform-operator realm]
>
> ~15–18 files, a written brief with pre-identified concerns, same deliverable requirements as above
> (signed report, your own severity ratings, written independence statement, confirmation of the package
> digest you reviewed).

**Budget:** Fixed-price, same approach as Post 1 — this scope is smaller, so expect (not a promise) a
lower range than the crypto post.

**Screening questions:**
1. "Have you reviewed a Django or similar framework's custom authentication/session code before (not just run an automated scanner)? Briefly describe one."
2. "Can you provide a redacted writing sample from a past security review report?"
3. "Do you have any prior involvement with this project? (Expected answer: no.)"

### Before you post either one

- Don't attach the review package zip to the public post — it's a private repo's source code. Mention the
  package exists (digest + file count, as above) and send it only after a contract starts or an NDA is in
  place, whichever Upwork flow you use.
- Upwork lets you invite specific freelancers directly instead of (or alongside) a public post — if you'd
  rather not have this publicly listed at all, search `cryptography` + `security review` in Upwork's
  freelancer directory and send invites instead of posting.

---

## Going invite-only (chosen approach)

Upwork's mechanics: you still create the two job posts above, but set each one's **visibility to
"Invite-only"** at creation (not "Public") — the post exists as the container the contract attaches to,
but it never appears in search or the public job feed. You find and invite candidates yourself from
Upwork's freelancer directory; nobody else can apply. Send multiple invites per post — most won't respond
or won't be a fit, and you want 2–3 real quotes, not your first reply.

### Finding candidates to invite

**For the crypto post**, search Upwork's freelancer directory (not the job-post search) for:
- `cryptography security review`, `applied cryptography consultant`, `cryptographic code audit`
- Filter: "Expert" experience level; sort by Job Success Score and "Rising Talent"/Top Rated badges, not
  just hourly rate
- Check their portfolio/work history for anything naming cryptographic primitives, key management, or
  protocol review specifically — generic "penetration tester" profiles usually aren't the right fit here,
  same reasoning as the skill-tag filtering above

**For the Django/AppSec post**, search:
- `django security audit`, `web application security review`, `python application security`
- The two Django-specific firms from the earlier search ([Imagescape](https://www.imagescape.com/django-security-review/), [Djangsters](https://www.djangsters.de/en/technology/django/django-security-audit/)) aren't Upwork profiles — if you want to loop them in, contact them directly outside Upwork rather than searching for them there

**Shortlisting before you invite:** look past the star rating — check whether their work history shows
actual security review deliverables (not just "fixed a bug" gigs), read 1–2 of their client reviews in
full for specifics, and confirm they're not already flagged in their own profile as unavailable/booked out.
Inviting 5–8 well-matched people per post and expecting 2–3 real responses is a reasonable rate to plan for.

### Short invite message (send with the invite, not the full job post text)

Upwork invites carry a short personal note alongside the job post link — keep it to a few sentences, not
the full description (they'll read that from the post itself):

> Subject line is auto-filled from the job post title.
>
> Hi [name] — I'm looking for a short, scoped independent security code review (not a pentest) of
> [the audit-log hash chain, signed checkpoints and AEAD crypto in a Django/PostgreSQL app / the
> authentication, session and MFA code in a Django/PostgreSQL app], and your profile looks like a strong
> match. Full scope is in the job post. ~[45–50 / 15–18] files, a written brief with concerns already
> identified for you to confirm or expand on, and I need a signed report in your own words — not an
> automated scan. Would this be something you're available for, and could you give me a rough quote and
> timeline?

Swap the bracketed scope description per post. Keep both invites this short — the job post carries the
real detail, and a long invite note reads as generic/copy-pasted even when it isn't.
