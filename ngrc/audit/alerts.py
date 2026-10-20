"""Security alerting (interface + DEV sinks).

`notify(Alert)` hands an alert to every sink named in `settings.ALERT_SINKS`:
* `log`    - one structured ERROR/WARNING record on logger `ngrc.alerts` (always on; what a log shipper / SIEM can pick up);
* `memory` - an in-process buffer used by the test suite (`recorder`).
Delivery to a pager / SIEM / e-mail list is NOT IMPLEMENTED: it depends on the hosting decision (open item O-4). An alert is therefore only as
visible as the log pipeline behind logger `ngrc.alerts`; the audit events that accompany alerts remain the system of record.
Alert details must never contain secrets or personal data (same discipline as audit details): identifiers are keyed hashes.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

from django.conf import settings

log = logging.getLogger("ngrc.alerts")
_FORBIDDEN = ("password", "secret", "token", "cookie", "otp", "recovery", "private", "authorization", "email")


@dataclass(frozen=True)
class Alert:
    kind: str          # e.g. suspicious_login, integrity_violation, verification_overdue
    severity: str      # info | warning | critical
    message: str
    stream: str = ""   # audit stream the alert concerns, when any
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        for k in self.details:
            if any(f in k.lower() for f in _FORBIDDEN):
                raise ValueError(f"secret-like or personal key {k!r} in alert details")


class _Recorder:
    """In-memory sink for tests."""

    def __init__(self):
        self.sent: deque[Alert] = deque(maxlen=1000)

    def reset(self) -> None:
        self.sent.clear()


recorder = _Recorder()


def _log_sink(alert: Alert) -> None:
    level = logging.ERROR if alert.severity == "critical" else logging.WARNING if alert.severity == "warning" else logging.INFO
    log.log(level, "ALERT kind=%s severity=%s stream=%s msg=%s details=%s", alert.kind, alert.severity, alert.stream, alert.message, alert.details)


_SINKS = {"log": _log_sink, "memory": recorder.sent.append}


def notify(alert: Alert) -> None:
    """Never raises: an alerting failure must not break authentication or verification; it is logged instead."""
    for name in getattr(settings, "ALERT_SINKS", ["log"]):
        try:
            _SINKS[name](alert)
        except Exception:  # noqa: BLE001 - alerting is best-effort by design; the audit event is the record
            log.exception("alert sink %s failed", name)
