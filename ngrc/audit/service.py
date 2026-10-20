"""Audit event service (Phase 1 steps 25-28).

Write paths:
* `record()`  - tenant-stream events queued in the request's UnitOfWork and appended as the LAST statements of the
                business transaction (atomic with the action; failure => the whole transaction fails: C-4).
* `emit_platform()` / `emit_tenant()` - immediate append on a given connection alias (auth service, operator plane).
* `emit_denied()` - authorisation denials on the `autonomous` connection: an independent transaction, so rolling back
                the request cannot erase the evidence of the denial (D-P0-006 s3).
Nothing here ever receives secrets: `details` keys are allow-listed per action by the database.
"""
from __future__ import annotations

import contextvars
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from django.db import connections, transaction

from ngrc.core.context import _bind
from ngrc.core.errors import AuditWriteFailed
from ngrc.core.net import normalize_ip

log = logging.getLogger("ngrc.audit")


@dataclass(frozen=True)
class RequestMeta:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    session_ref: str | None = None


# RequestMeta is a frozen dataclass: the shared default instance is immutable, so B039 does not apply
_meta: contextvars.ContextVar[RequestMeta] = contextvars.ContextVar("ngrc_meta", default=RequestMeta())  # noqa: B039
_uow: contextvars.ContextVar[UnitOfWork | None] = contextvars.ContextVar("ngrc_uow", default=None)


def set_meta(meta: RequestMeta):
    return _meta.set(meta)


def get_meta() -> RequestMeta:
    return _meta.get()


@dataclass
class Event:
    action: str
    result: str = "success"
    actor_type: str = "user"
    actor_id: uuid.UUID | None = None
    grant_id: uuid.UUID | None = None
    object_type: str | None = None
    object_id: str | None = None
    reason_code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    data_class: str = "C"
    tenant_id: uuid.UUID | None = None
    meta: RequestMeta | None = None
    platform: bool = False  # True => append to the platform stream (still inside the same transaction)


_SQL_ARGS = "%s::text,%s::uuid,%s::uuid,%s::text,%s::text,%s::text,%s::text,%s::text,%s::inet,%s::text,%s::text,%s::text,%s::jsonb,%s::text"


def _params(ev: Event) -> list:
    m = ev.meta or get_meta()
    return [
        ev.actor_type, str(ev.actor_id) if ev.actor_id else None, str(ev.grant_id) if ev.grant_id else None,
        ev.action, ev.object_type, ev.object_id, ev.result, ev.reason_code, normalize_ip(m.ip), (m.user_agent or "")[:256] or None,
        m.session_ref, m.request_id, json.dumps(ev.details, separators=(",", ":"), sort_keys=True), ev.data_class,
    ]


def append_tenant(using: str, ev: Event) -> int:
    if ev.tenant_id is None:
        raise AuditWriteFailed("tenant event without tenant")
    try:
        with connections[using].cursor() as cur:
            cur.execute(f"SELECT audit.append_tenant_event(%s::uuid,{_SQL_ARGS})", [str(ev.tenant_id), *_params(ev)])
            return cur.fetchone()[0]
    except Exception as exc:  # noqa: BLE001 - any failure must fail closed; never leak driver text
        log.error("audit append failed (tenant stream): %s", type(exc).__name__)
        raise AuditWriteFailed("audit append failed") from exc


def append_platform(using: str, ev: Event) -> int:
    try:
        with connections[using].cursor() as cur:
            cur.execute(f"SELECT audit.append_platform_event(%s::uuid,{_SQL_ARGS})",
                        [str(ev.tenant_id) if ev.tenant_id else None, *_params(ev)])
            return cur.fetchone()[0]
    except Exception as exc:  # noqa: BLE001
        log.error("audit append failed (platform stream): %s", type(exc).__name__)
        raise AuditWriteFailed("audit append failed") from exc


class UnitOfWork:
    """Collects tenant-stream events for one request; flushed as the last step before COMMIT."""

    def __init__(self, tenant_id: uuid.UUID, using: str = "default"):
        self.tenant_id, self.using, self.events = tenant_id, using, []

    def record(self, action: str, **kw) -> None:
        self.events.append(Event(action=action, tenant_id=self.tenant_id, meta=get_meta(), **kw))

    def record_platform(self, action: str, **kw) -> None:
        self.events.append(Event(action=action, tenant_id=self.tenant_id, meta=get_meta(), platform=True, **kw))

    def flush(self) -> int:
        n = 0
        for ev in self.events:
            (append_platform if ev.platform else append_tenant)(self.using, ev)
            n += 1
        self.events.clear()
        return n


class unit_of_work:  # noqa: N801 - context manager used like a function
    def __init__(self, tenant_id, using: str = "default"):
        self.uow = UnitOfWork(tenant_id, using)

    def __enter__(self) -> UnitOfWork:
        self._tok = _uow.set(self.uow)
        return self.uow

    def __exit__(self, *exc):
        _uow.reset(self._tok)


def record_platform(action: str, **kw) -> None:
    uow = _uow.get()
    if uow is None:
        raise AuditWriteFailed("no audit unit of work is active")
    uow.record_platform(action, **kw)


def record(action: str, **kw) -> None:
    """Queue a tenant-stream event on the current request's unit of work (programming error if none)."""
    uow = _uow.get()
    if uow is None:
        raise AuditWriteFailed("no audit unit of work is active")
    uow.record(action, **kw)


def emit_platform(using: str, action: str, **kw) -> int:
    """Immediate platform-stream append on connection alias `using` (auth: 'auth', operator plane: 'ops')."""
    return append_platform(using, Event(action=action, meta=kw.pop("meta", None), **kw))


def emit_tenant(using: str, action: str, tenant_id, **kw) -> int:
    return append_tenant(using, Event(action=action, tenant_id=tenant_id, meta=kw.pop("meta", None), **kw))


def emit_independent(action: str, tenant_id, *, actor_id=None, actor_type: str = "user", result: str = "success", reason_code: str | None = None,
                     details: dict | None = None, object_type: str | None = None, object_id: str | None = None, using: str = "autonomous") -> None:
    """Record a TENANT-stream event in its own transaction so it survives the rollback of a failing request (e.g. an integrity failure or a
    rejected upload). Never raises: the failure is logged; callers must not rely on this for the primary business record."""
    ev = Event(action=action, result=result, actor_type=actor_type, actor_id=actor_id, reason_code=reason_code, details=details or {},
               object_type=object_type, object_id=object_id, tenant_id=tenant_id)
    try:
        with transaction.atomic(using=using):
            _bind(using, tenant_id, actor_id)
            append_tenant(using, ev)
    except Exception as exc:  # noqa: BLE001
        log.error("independent audit event %s could not be recorded: %s", action, type(exc).__name__)


def emit_denied(*, permission: str, route: str, reason: str, tenant_id=None, actor_id=None, actor_type: str = "user",
                grant_id=None, using: str = "autonomous") -> None:
    """Record an authorisation denial in an independent transaction. Never raises: a denial stays a denial even if the
    audit write fails (never fail open); the failure is logged and alerts operationally."""
    ev = Event(action="authz.denied", result="denied", actor_type=actor_type, actor_id=actor_id, grant_id=grant_id,
               reason_code=reason, details={"permission": permission, "route": route[:120]}, tenant_id=tenant_id)
    try:
        with transaction.atomic(using=using):
            if tenant_id is not None:
                _bind(using, tenant_id, actor_id)
                append_tenant(using, ev)
            else:
                append_platform(using, ev)
    except Exception as exc:  # noqa: BLE001
        log.error("audit denial could not be recorded: %s", type(exc).__name__)
