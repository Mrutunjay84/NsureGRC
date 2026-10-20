"""Login / second-factor throttling (D-P0-008 s4, amended by D-P1-001 for DEF-15). DB-backed counters (Redis arrives with infrastructure;
ADR requires degrading to DB counters, never to "unthrottled"). Progressive back-off - there is deliberately NO hard stop to a
`recovery_required` state while no unlock/recovery workflow exists (D-P1-001): a stranger who knows an address must not be able to lock
the real user out for good. Operator accounts get stricter parameters. Failures are counted, delayed, rate-limited, audited and
(DEF-15 decision) scanned for suspicious patterns. Thresholds are NsureGRC baseline values (settings.AUTH_THROTTLE), not standard-mandated numbers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import transaction

from ngrc.core import clock
from ngrc.core.crypto import keyed_identifier_hash, sha256_hex

from .realms import Realm


@dataclass(frozen=True)
class FailureOutcome:
    failures: int
    locked_for_s: int
    suspicious: str | None = None  # None | "distributed_sources" (several distinct source addresses against one account)
    distinct_sources: int = 1


@dataclass(frozen=True)
class SuccessOutcome:
    prior_failures: int
    suspicious: str | None = None  # None | "success_after_failures"


def _acct_key(scope: str, identifier: str) -> str:
    return f"{scope}:{keyed_identifier_hash(identifier)}"


def _src_prefix(scope: str, identifier: str) -> str:
    return f"src:{_acct_key(scope, identifier)}:"


def _ip_key(ip: str | None) -> str:
    return f"ip:{(ip or 'unknown')[:100]}"


def _cfg(realm: Realm, name: str):
    k = f"{realm.throttle_prefix}{name}"
    return settings.AUTH_THROTTLE[k] if k in settings.AUTH_THROTTLE else settings.AUTH_THROTTLE[name]


def retry_after(realm: Realm, identifier: str, ip: str | None, scope: str = "acct") -> int:
    """Seconds the caller must wait (0 = allowed). Evaluated BEFORE any password hashing."""
    now = clock.now()
    T = realm.Throttle.objects.using(realm.db)
    wait = 0
    row = T.filter(key=_acct_key(scope, identifier)).first()
    if row and row.locked_until and row.locked_until > now:
        wait = max(wait, int((row.locked_until - now).total_seconds()) + 1)
    ip_row = T.filter(key=_ip_key(ip)).first()
    if ip_row and (now - ip_row.window_started).total_seconds() <= settings.AUTH_THROTTLE["ip_window_s"] \
            and ip_row.failures >= settings.AUTH_THROTTLE["ip_max_attempts"]:
        wait = max(wait, int(settings.AUTH_THROTTLE["ip_window_s"] - (now - ip_row.window_started).total_seconds()) + 1)
    return wait


def record_failure(realm: Realm, identifier: str, ip: str | None, scope: str = "acct") -> FailureOutcome:
    now = clock.now()
    cfg = settings.AUTH_THROTTLE
    free = _cfg(realm, "account_free_failures")
    base, cap = _cfg(realm, "account_base_delay_s"), _cfg(realm, "account_max_delay_s")
    window = timedelta(seconds=_cfg(realm, "suspicious_window_s"))
    with transaction.atomic(using=realm.db):
        T = realm.Throttle.objects.using(realm.db).select_for_update()
        row, _ = T.get_or_create(key=_acct_key(scope, identifier),
                                 defaults={"failures": 0, "window_started": now, "updated_at": now})
        row.failures += 1
        row.updated_at = now
        locked_for = 0
        if row.failures >= free:
            locked_for = min(base * 2 ** min(row.failures - free, 20), cap)  # exponent bounded: no huge intermediate integers
            row.locked_until = now + timedelta(seconds=locked_for)
        row.save()
        ip_row, _ = T.get_or_create(key=_ip_key(ip), defaults={"failures": 0, "window_started": now, "updated_at": now})
        if (now - ip_row.window_started).total_seconds() > cfg["ip_window_s"]:
            ip_row.window_started, ip_row.failures = now, 0
        ip_row.failures += 1
        ip_row.updated_at = now
        ip_row.save()
        # suspicious-pattern detection: how many DISTINCT source addresses failed against this account recently?
        src, created = T.get_or_create(key=_src_prefix(scope, identifier) + sha256_hex(ip or "unknown")[:24],  # <= 128 chars
                                       defaults={"failures": 0, "window_started": now, "updated_at": now})
        src.failures += 1
        src.updated_at = now
        src.save()
        sources = T.filter(key__startswith=_src_prefix(scope, identifier), updated_at__gte=now - window).count()
    flagged = None
    if sources == _cfg(realm, "suspicious_distinct_sources") and created:  # raised once, when the threshold is first crossed
        flagged = "distributed_sources"
    return FailureOutcome(row.failures, locked_for, flagged, sources)


def record_success(realm: Realm, identifier: str, scope: str = "acct") -> SuccessOutcome:
    """Clear the counters; report whether this success followed a burst of failures (a possible guessed credential)."""
    T = realm.Throttle.objects.using(realm.db)
    row = T.filter(key=_acct_key(scope, identifier)).first()
    prior = row.failures if row else 0
    T.filter(key=_acct_key(scope, identifier)).delete()
    T.filter(key__startswith=_src_prefix(scope, identifier)).delete()
    return SuccessOutcome(prior, "success_after_failures" if prior >= _cfg(realm, "account_free_failures") else None)
