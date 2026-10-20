"""Transaction-scoped tenant context (D-P0-003 s3).

The tenant id is bound to PostgreSQL with `set_config('app.tenant_id', <uuid>, true)` (is_local = true), i.e. it lives
and dies with the current transaction. It is therefore safe with transaction-pooling and cannot leak between requests.
The Python-side contextvar only powers the ORM guard; the database RLS policies are the authority.
"""
from __future__ import annotations

import contextvars
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from django.db import connections, transaction

from .errors import InvalidTenantContext, TenantContextMissing, TenantContextSwitch

_tenant: contextvars.ContextVar[uuid.UUID | None] = contextvars.ContextVar("ngrc_tenant", default=None)
_principal: contextvars.ContextVar[uuid.UUID | None] = contextvars.ContextVar("ngrc_principal", default=None)


def parse_uuid(value, *, what: str = "tenant") -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidTenantContext(f"invalid {what} identifier") from exc


def current_tenant_id() -> uuid.UUID | None:
    return _tenant.get()


def assert_tenant_context(using: str = "default") -> uuid.UUID:
    """ORM guard: raise unless a tenant context is active AND we are inside its transaction."""
    tid = _tenant.get()
    if tid is None or not connections[using].in_atomic_block:
        raise TenantContextMissing("tenant-owned data accessed without an active tenant context")
    return tid


def _bind(using: str, tenant_id: uuid.UUID | None, principal_id: uuid.UUID | None) -> None:
    with connections[using].cursor() as cur:
        cur.execute(
            "SELECT set_config('app.tenant_id', %s, true), set_config('app.principal_id', %s, true)",
            [str(tenant_id) if tenant_id else "", str(principal_id) if principal_id else ""],
        )


@contextmanager
def tenant_context(tenant_id, principal_id=None, *, using: str = "default") -> Iterator[uuid.UUID]:
    """Open a transaction bound to `tenant_id`. Switching tenant inside an open context is refused."""
    tid = parse_uuid(tenant_id)
    pid = parse_uuid(principal_id, what="principal") if principal_id else None
    active = _tenant.get()
    if active is not None:
        if active != tid:
            raise TenantContextSwitch("tenant context cannot be switched inside an open context")
        with transaction.atomic(using=using):  # same tenant: savepoint, same transaction
            yield tid
        return
    with transaction.atomic(using=using):
        _bind(using, tid, pid)
        t_token = _tenant.set(tid)
        p_token = _principal.set(pid)
        try:
            yield tid
        finally:
            _tenant.reset(t_token)
            _principal.reset(p_token)


@contextmanager
def principal_context(principal_id, *, using: str = "auth") -> Iterator[uuid.UUID]:
    """Transaction bound to a principal only (no tenant), e.g. to list the caller's own memberships at login."""
    pid = parse_uuid(principal_id, what="principal")
    with transaction.atomic(using=using):
        _bind(using, None, pid)
        yield pid
