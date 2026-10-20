"""Scheduled audit verification (F-AUD-007, D-P0-006 s6).

* `run_scheduled_verification(mode)` verifies every stream as the `ngrc_audit_verifier` identity, records one `audit.verification_run` per stream,
  raises an alert + `audit.integrity_violation` for each violation, and writes one `audit.verification.completed` summary event.
  Production settings require an external checkpoint copy and an established-completeness anchor (AUDIT_REQUIRE_EXTERNAL_COPY /
  AUDIT_REQUIRE_COMPLETENESS) and freshness (the sealer's heartbeat).
* `check_verification_freshness()` is the WATCHDOG: silence must not look like health. If no verification run was recorded within
  AUDIT_VERIFY_MAX_AGE_HOURS it raises `audit.verification.overdue` + an alert. A watchdog that lives in the same process as the verifier cannot
  report that process dying, so deployments run it from a SEPARATE scheduler entry (and ideally a separate host) - how that is arranged depends
  on the hosting decision (open item O-4). The scheduling itself (cron / CronJob / systemd timer / the `audit_verify --loop` worker) is a
  deployment choice; this module is runner-agnostic.
* Public keys come from AUDIT_PUBLIC_KEYS (key id -> hex of the raw public key). The verifier never needs a private key. Only in development
  (dev_file signer) do the keys fall back to the local key file.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import connections

from ngrc.core import clock

from . import alerts, service, verifier
from .signer import get_signer

log = logging.getLogger("ngrc.audit")
DB = verifier.DB
EXPECTED_IDENTITY = "ngrc_audit_verifier"


class WrongIdentity(RuntimeError):
    """The verification job is connected as a role other than the verifier (a stronger role would hide privilege mistakes)."""


@dataclass
class Summary:
    mode: str
    streams_checked: int = 0
    violations: int = 0             # number of STREAMS with at least one violation
    recorded_runs: int = 0
    exit_code: int = 0
    completeness: dict = field(default_factory=dict)
    results: list = field(default_factory=list)


def database_identity() -> str:
    with connections[DB].cursor() as cur:
        cur.execute("SELECT session_user")
        return cur.fetchone()[0]


def published_public_keys() -> dict[str, bytes]:
    keys = {k: bytes.fromhex(v) for k, v in (getattr(settings, "AUDIT_PUBLIC_KEYS", None) or {}).items()}
    if not keys and getattr(settings, "AUDIT_SIGNER_BACKEND", "") == "dev_file":   # DEV ONLY: share the local key file
        s = get_signer()
        keys[s.key_id] = s.public_key_raw()
    if not keys:
        raise RuntimeError("no audit public keys configured (AUDIT_PUBLIC_KEYS)")
    return keys


def run_scheduled_verification(mode: str = "full", *, tenant_ids: list[str] | None = None) -> Summary:
    if mode not in {"full", "incremental"}:
        raise ValueError("mode must be 'full' or 'incremental'")
    ident = database_identity()
    if ident != EXPECTED_IDENTITY:
        raise WrongIdentity(f"verification must run as {EXPECTED_IDENTITY}, not {ident}")
    results = verifier.verify_all(
        published_public_keys(), tenant_ids=tenant_ids, mode=mode, record=True,
        require_export=bool(getattr(settings, "AUDIT_REQUIRE_EXTERNAL_COPY", False)), require_fresh=True,
        require_completeness=bool(getattr(settings, "AUDIT_REQUIRE_COMPLETENESS", False)))
    bad = [r for r in results if not r.ok]
    counts: dict[str, int] = {}
    for r in results:
        counts[r.completeness] = counts.get(r.completeness, 0) + 1
    summary = Summary(mode=mode, streams_checked=len(results), violations=len(bad), recorded_runs=len(results),
                      exit_code=1 if bad else 0, completeness=counts, results=results)
    service.emit_platform(DB, "audit.verification.completed", actor_type="service", result="failure" if bad else "success",
                          details={"mode": mode, "streams": len(results), "violations": len(bad)})
    return summary


def check_verification_freshness(*, now=None) -> bool:
    """True if a verification run was recorded recently enough. Otherwise raises the overdue alert and audit event and returns False."""
    now = now or clock.now()
    max_h = int(getattr(settings, "AUDIT_VERIFY_MAX_AGE_HOURS", 6))
    with connections[DB].cursor() as cur:
        cur.execute("SELECT max(finished_at) FROM audit.verification_run")
        last = cur.fetchone()[0]
    if last is not None and now - last <= timedelta(hours=max_h):
        return True
    service.emit_platform(DB, "audit.verification.overdue", actor_type="service", result="failure",
                          details={"max_age_h": max_h, "last_run": last.isoformat() if last else "never"})
    alerts.notify(alerts.Alert(kind="verification_overdue", severity="critical", stream="platform",
                               message=f"no audit verification recorded within {max_h} h",
                               details={"max_age_h": max_h, "last_run": last.isoformat() if last else "never"}))
    return False
