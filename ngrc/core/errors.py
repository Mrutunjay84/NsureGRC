"""Exceptions for fail-closed behaviour. None of these messages may contain secrets or SQL."""


class TenantContextError(Exception):
    """Base class: tenant context is missing, invalid or being switched."""


class TenantContextMissing(TenantContextError):
    pass


class InvalidTenantContext(TenantContextError):
    pass


class TenantContextSwitch(TenantContextError):
    pass


class AuditWriteFailed(Exception):
    """An audit event could not be appended; the business transaction MUST fail (C-4, D-P0-006 s3)."""
