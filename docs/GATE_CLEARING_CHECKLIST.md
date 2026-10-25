# Owner action list — getting the Phase 1 gate from CONDITIONAL PASS to PASS

**Created:** 2026-10-25 · **Decision it serves:** owner chose (2026-10-25) to clear the gate *before* Phase 2 feature development starts.
**State at creation:** gate `CONDITIONAL PASS`, 12 PASS / 0 FAIL / 3 BLOCKED. HEAD `54e6826`, working tree clean, 7 local commits, no git remote.

**Update 2026-10-25 (same day):** repo created and pushed — [`Mrutunjay84/NsureGRC`](https://github.com/Mrutunjay84/NsureGRC) (private).
Section A's setup steps 1–4 and 7–8 are now done; see "Current state" under A. Owner declined GitHub Pro / Advanced Security
(step 5's secret scanning + step 6's branch protection cannot run on this plan) — recorded as `ACCEPT-GH-FREE-TIER-001` in
`accepted_risks.yaml`, not silently dropped. Step 1 of the CI run itself (triggering a workflow) has not happened yet.

This file consolidates what only a human can do. It adds no new requirement — it collects the ones already recorded in
[`PHASE1_SECURITY_GATE.md`](PHASE1_SECURITY_GATE.md), [`ci/GITHUB_SETUP_REQUIREMENTS.md`](ci/GITHUB_SETUP_REQUIREMENTS.md),
[`review/`](review/INDEPENDENT_REVIEW_PACKAGE.md) and [`OPEN_ITEMS.md`](OPEN_ITEMS.md) into one list, with the digests you will need.

**Nothing here may be waived by the implementer, and no item becomes green by assertion.**

---

## A — Gate item P2-1: a real CI run (clears 2 of the 3 BLOCKED gates)

A green run also clears the **container image build + scan** gate, which is blocked here only because this workstation has no
Docker/Podman. So A is worth doing first: two of three blockers, and it needs nobody but you.

Full steps: [`ci/GITHUB_SETUP_REQUIREMENTS.md`](ci/GITHUB_SETUP_REQUIREMENTS.md). Condensed:

| # | Action | Gotcha |
|---|---|---|
| 1 | Create a **private** GitHub repo | The checker rejects a record that does not say `private` |
| 2 | Actions → General: workflow permissions **read contents only**; allow only `astral-sh/setup-uv`, `hadolint/hadolint-action`, `aquasecurity/trivy-action`, `gitleaks/gitleaks-action` | Do not allow Actions to create/approve PRs |
| 3 | Repo secret `CI_PG_SUPERUSER_PASSWORD` = long random value | Protects only the ephemeral PostgreSQL service container |
| 4 | Repo secret `GITLEAKS_LICENSE` — **only if the repo is under an organisation** | gitleaks-action requires it for orgs, not personal accounts |
| 5 | Enable secret scanning + push protection + dependency alerts | Additional to the workflow gates, not a replacement |
| 6 | Branch protection on `main`: require PR, require the five checks in §3 of the setup doc, block force-push and deletion | |
| 7 | Runners: GitHub-hosted `ubuntu-24.04` | The `container` job needs Docker. No self-hosted runner unless separately reviewed |
| 8 | `git remote add origin <url>` then `git push -u origin main` from `03_APP/nsuregrc` | |

### Current state (verified against the live GitHub API, 2026-10-25)

| Step | Status |
|---|---|
| 1. Private repo created | ✅ `Mrutunjay84/NsureGRC`, `visibility: PRIVATE` |
| 2. Actions restricted to the named third parties + GitHub-owned | ✅ `allowed_actions=selected`; `patterns_allowed` = `astral-sh/setup-uv@*`, `hadolint/hadolint-action@*`, `aquasecurity/trivy-action@*`, `aquasecurity/setup-trivy@*` (trivy-action v0.33.1's own dependency — the first real container-job run failed until this was added), `gitleaks/gitleaks-action@*`. Workflow perms `default_workflow_permissions=read`, `can_approve_pull_request_reviews=false` |
| 3. `CI_PG_SUPERUSER_PASSWORD` secret | ✅ set (random, never displayed) |
| 4. `GITLEAKS_LICENSE` | n/a — personal account, not an organisation |
| 5. Secret scanning + push protection | ❌ **Cannot enable on this plan.** `PATCH security_and_analysis` for both is silently ignored (stays `disabled`) — this is GitHub Advanced Security, gated on private repos without a paid licence. Dependabot vulnerability alerts + automated security fixes **are** enabled (free). Accepted risk `ACCEPT-GH-FREE-TIER-001`. |
| 6. Branch protection on `main` | ❌ **Cannot enable on this plan.** Both the classic branch-protection API and the newer rulesets API return `403 Upgrade to GitHub Pro or make this repository public`. Same accepted-risk entry; mitigated by the Actions lockdown in step 2 (a compromised workflow still can't write to the repo) — but nothing stops a direct push to `main` bypassing CI. Revisit before any second collaborator joins. |
| 7. Runner | n/a until a workflow actually runs — `ubuntu-24.04` is specified in `ci.yml` already |
| 8. Push `main` | ✅ merged with GitHub's placeholder commit (kept this repo's real README) and pushed; remote `main` now has the full history |

**Not yet done:** no workflow run exists (`gh run list` is empty) — nothing has triggered `ci.yml` on GitHub yet. That's section A's actual remaining step; everything above it is setup, not the test itself.

### Pre-push checks — already run for you (2026-10-25, HEAD `54e6826`)

| Check | Result |
|---|---|
| Working tree clean | yes |
| Local history | 7 commits on `main`, no remote, nothing pushed |
| Tracked files | 224; no `.env`, key, PEM, credential, venv or cache paths tracked |
| Only secret-shaped hits | `.secrets.baseline` and `evidence/detect_secrets_scan.json` — detect-secrets' own baseline and output (hashed candidates, not secrets) |
| `.gitattributes` | forces `eol=lf` globally and on `*.sh` / `Dockerfile` |
| Large tracked files | none over 200 KB |
| `.github/workflows/ci.yml` present at HEAD | yes — **sha256 `95f3b0eaa84ba26ac569a691aaba87814a43cc2aad4b73703f1570d98fe54354`** |

Keep that workflow digest. Step 4 below needs it, and `check_ci_record.py` re-derives it from git at the run's commit —
if the workflow changed after the run, the record fails.

### Expect the first runs to be red

The `container` job has **never executed in any form** — not locally, not in CI. Hadolint findings and base-image CVEs are
likely. The correct response is to fix the Dockerfile or pin a newer base image. **Never lower a threshold or add an ignore
without a recorded risk acceptance** in `docs/accepted_risks.yaml`.

### Recording the run

1. `git show <run-commit-sha>:.github/workflows/ci.yml | sha256sum`
2. `GITHUB_TOKEN=… uv run python scripts/import_ci_run.py --repo OWNER/NAME --run-id <id> --write`
   — use **your own** read-only token; never share it with this project. The importer's pure logic is unit-tested, but
   **its HTTP calls have never run against the real GitHub API** — expect to debug it once.
3. Fill what the API cannot give: `workflow_sha256`, the container job's `image_scan: clean` (only if Trivy actually passed),
   the secrets job's `history_scanned: true` (only if gitleaks ran with `fetch-depth: 0` and passed).
4. `uv run python scripts/check_ci_record.py` must print `PASSED`.
5. Then `uv run python scripts/security_gate.py` and `uv run python scripts/build_reports.py`, and the gate is reassessed.

Hand me the run id and I will do steps 1–5 and the reassessment. **Do not give me the token.**

---

## B — Gate item P2-2: an independent security review (the long pole)

This is the item with real calendar time and cost, so start sourcing a reviewer **in parallel with A**, not after it.

### What the reviewer receives

| | |
|---|---|
| Package | `evidence/review_package/nsuregrc_review_package_fe008f356068.zip` (317 KB) |
| `package_sha256` | `fe008f35606831692394aefd16507eb4aba25b7fc17ec68fdb495535540bccfa` |
| Contents | 63 reviewed source files + 9 context documents, generated 2026-10-20 |
| Brief | [`review/INDEPENDENT_REVIEW_PACKAGE.md`](review/INDEPENDENT_REVIEW_PACKAGE.md) — includes **25 known concerns** written up for them |

This package **supersedes** the earlier 44-file one; a review of that digest will be rejected as stale.

### The four scopes they must cover ([`review/review_scope.yaml`](review/review_scope.yaml))

1. **`audit_hash`** — canonical encoding, domain separation, SQL/Python hash equivalence
2. **`audit_integrity_checkpoint`** — hash chain, signed checkpoints, sealer, verifier (incl. the H-11 validity-vs-completeness verdicts), scheduler, role separation
3. **`aead_helper`** — AEAD / envelope encryption, token and pepper hashing, TOTP secret sealing, recovery-code HMAC
4. **`authn_session_mfa`** — passwords, TOTP, WebAuthn, recovery codes, throttling, step-up, sessions, operator realm

This is a **focused cryptography / application-security code review**, not a penetration test and not a certification
audit. Scope it to quote as: ~63 files, four named scopes, 25 pre-written concerns to adjudicate, a signed written report.
Get quotes rather than assuming a price — the useful shortlist is independent AppSec consultancies or individual
applied-cryptography reviewers, *not* a compliance-audit firm, which is a different service.

### What you must get back, or the record stays BLOCKED

`scripts/check_review_record.py` refuses: self-review, AI/tool review, unsigned or undated reports, and reviews of a
different package digest. The reviewer's report must supply, **in their own words and ratings**:

- Name, organisation, relevant qualifications
- An **independence statement** — only the reviewer can assert this; no involvement in design, implementation or testing
- `reviewed_manifest_sha256` matching `fe008f35…bccfa`
- A disposition per scope: `approved` / `approved_with_conditions` / `rejected`
- Findings with the reviewer's own severity ratings, each later marked `remediated` (with retest evidence) or
  `accepted_risk` (with a named approver)

### One thing you must supply before independence can be checked

`review/REVIEW_RECORD.yaml` has `implementer_humans: []`. Fill in the names of any humans who directed, edited or accepted
the Phase 1 implementation — otherwise independence cannot be verified. The recorded implementer is
`Claude Code (AI assistant)`.

---

## C — Owner decisions waiting on you (no cost, no third party)

These are free to clear and some of them block the review's conclusions.

| Item | What is needed |
|---|---|
| **DEF-15 / H-10** | **Re-confirm or amend** decision `D-P1-001`. I had reported locked accounts had "no exit path"; that was overstated — customer accounts could leave `recovery_required` via password reset. The real defects were stranger-triggered repeatable forced resets, no notification, no unlock flow, and no exit at all for operators. You were asked to re-confirm in light of that correction and have not yet. |
| **H-13** | Approve the numeric **BASELINE values**: throttling delays/thresholds, recovery cooling-off 24 h, request TTL 7 d, enrolment window 30 min, checkpoint interval 300 s, max age 900 s, export grace 120 s, skew 300 s, verification watchdog 6 h, evidence limit 25 MiB. None is standard-derived; all are configurable. |
| **H-12** | Approve or amend interim decisions **D-EV-1** (evidence pre-verification) and **D-SR-1** (full-text search under RLS). |
| **O-6** | **Frontend technology / BFF shape** — undecided since Phase 0. Needed before any UI work, and it shapes the API, so decide it before the Phase 2 specs harden. |
| **PRD §8** | Confirm the scope cut implied by "no auto-capture": the `Integration → Connection → Resource → Test → Result` chain comes out of P0, evidence becomes human-uploaded with manual freshness/expiry. Confirm separately whether the read-only **AI Advisor** (`08_AI_ADVISOR.md`, P1) stays or goes. |

---

## D — Not gate blockers, but no production claim until they are done

Recorded so they are not quietly forgotten. These are **production** gates, explicitly *not* Phase 2 development blockers
(owner decision 2026-10-21).

| | |
|---|---|
| **F-DAT-006** production KMS | NOT IMPLEMENTED — 4 executable specs + 2 gap demos, all XFAIL |
| **F-AUD-006** WORM audit storage | NOT IMPLEMENTED — 4 specs + 1 gap demo, XFAIL. **H-11 completeness cannot reach `established` without it** |
| **O-4** hosting / cloud / managed Postgres / private object store | Not selected |
| **O-7** e-mail provider + SPF/DKIM/DMARC | None. Recovery and factor-removal notifications are only as strong as real delivery |
| **O-11** malware-scanning engine | Not selected; the EICAR stand-in provides **no malware detection** |
| **O-2 / O-3** retention + RPO/RTO values | No values set; purge (F-AUD-004) and DR (F-DR-001/002) not implemented |
| **O-8** legal/privacy review + framework content licensing | Not done. Relevant before ingesting any framework catalogue |

`config.settings.prod` refuses to start against any dev-only stand-in, by design. That is the mechanism keeping D honest.

---

## Order I recommend

1. **C** now — it is free, and DEF-15 plus H-13 feed the reviewer's context.
2. **A** now — two of three blocked gates, needs only you, and the red container job is better found early.
3. **B** sourcing in parallel — it has the longest lead time.
4. Gate reassessed when A and B land. Phase 2 feature work starts then.
