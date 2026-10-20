"""Login / second-factor throttling (D-P0-008 s4). DB-backed counters (Redis arrives with infrastructure; ADR requires
degrading to DB counters, never to "unthrottled"). Progressive back-off rather than hard lockout to avoid lockout-DoS.
Thresholds are NsureGRC baseline values (settings.AUTH_THROTTLE), not standard-mandated numbers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import transaction

from ngrc.core import clock
from ngrc.core.crypto import keyed_identifier_hash

from .realms import Realm


@dataclass(frozen=True)
class FailureOutcome:
    failures: int
    locked_for_s: int
    recovery_required: bool


def _acct_key(scope: str, identifier: str) -> str:
    return f"{scope}:{keyed_identifier_hash(identifier)}"


def _ip_key(ip: str | None) -> str:
    return f"ip:{(ip or 'unknown')[:100]}"


def _cfg(realm: Realm, name: str):
    return settings.AUTH_THROTTLE[f"{realm.throttle_prefix}{name}"] if f"{realm.throttle_prefix}{name}" in settings.AUTH_THROTTLE \
        else settings.AUTH_THROTTLE[name]


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
    hard = _cfg(realm, "account_recovery_required_at")
    with transaction.atomic(using=realm.db):
        T = realm.Throttle.objects.using(realm.db).select_for_update()
        row, _ = T.get_or_create(key=_acct_key(scope, identifier),
                                 defaults={"failures": 0, "window_started": now, "updated_at": now})
        row.failures += 1
        row.updated_at = now
        locked_for = 0
        if row.failures >= free:
            locked_for = min(cfg["account_base_delay_s"] * 2 ** (row.failures - free), cfg["account_max_delay_s"])
            row.locked_until = now + timedelta(seconds=locked_for)
        row.save()
        ip_row, _ = T.get_or_create(key=_ip_key(ip), defaults={"failures": 0, "window_started": now, "updated_at": now})
        if (now - ip_row.window_started).total_seconds() > cfg["ip_window_s"]:
            ip_row.window_started, ip_row.failures = now, 0
        ip_row.failures += 1
        ip_row.updated_at = now
        ip_row.save()
    return FailureOutcome(row.failures, locked_for, row.failures >= hard)


def record_success(realm: Realm, identifier: str, scope: str = "acct") -> None:
    realm.Throttle.objects.using(realm.db).filter(key=_acct_key(scope, identifier)).delete()
