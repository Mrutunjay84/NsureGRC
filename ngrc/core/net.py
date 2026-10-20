"""Client-address normalisation. REMOTE_ADDR is set by the WSGI server, but an unparseable value must never reach a typed `inet` column
(the audit append would fail -> HTTP 500) or become a distinct throttle bucket per garbage string."""
from __future__ import annotations

import ipaddress


def normalize_ip(value: str | None) -> str | None:
    """Canonical text form of a valid IPv4/IPv6 address, else None (callers treat None as 'unknown')."""
    if not value or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None
