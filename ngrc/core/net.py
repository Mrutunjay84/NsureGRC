"""Client-address normalisation, and the one SSRF-safe outbound fetch helper (P0 checklist #12).

`normalize_ip`: REMOTE_ADDR is set by the WSGI server, but an unparseable value must never reach a typed
`inet` column (the audit append would fail -> HTTP 500) or become a distinct throttle bucket per garbage
string.

`safe_fetch`: this codebase's first outbound call to a third party (D-P2-002). Every prior domain is
DB-only or handles inbound requests. Per-call `allowed_hosts` (never a global allowlist) resolves DNS
itself, rejects any private/loopback/link-local/reserved/metadata-range address, and connects to the
resolved IP directly with the real hostname pinned for TLS SNI/hostname verification and the Host header -
the standard mitigation for a DNS-rebinding TOCTOU (resolve once, validate, use that exact address).
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


def normalize_ip(value: str | None) -> str | None:
    """Canonical text form of a valid IPv4/IPv6 address, else None (callers treat None as 'unknown')."""
    if not value or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


class FetchError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_UNSAFE_IP_ATTRS = ("is_private", "is_loopback", "is_link_local", "is_multicast", "is_reserved", "is_unspecified")


def _is_unsafe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable is not safe either - fail closed
    return any(getattr(ip, attr) for attr in _UNSAFE_IP_ATTRS)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to `pinned_ip`, but keeps `host` as the real hostname for TLS SNI, certificate hostname
    verification, and the default Host header - so a second, uncontrolled DNS lookup never happens at
    connect time (the resolve-validate-connect sequence uses one address throughout)."""

    def __init__(self, host: str, pinned_ip: str, port: int, *, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def safe_fetch(url: str, *, allowed_hosts: frozenset[str], timeout_s: float = 10, max_bytes: int = 8_000_000,
               resolver=socket.getaddrinfo, require_https: bool = True, _skip_destination_check: bool = False) -> bytes:
    """GET `url`. Raises `FetchError` for anything outside the explicit contract - never returns a partial
    or best-effort result.

    `require_https=False` and `_skip_destination_check` exist ONLY for tests (D-P2-002). Every real caller
    uses the secure defaults. `_skip_destination_check` is deliberately private and separate from
    `require_https`: a loopback test server is itself a loopback address, so an end-to-end "it really
    connects and streams" test can only run with the destination check bypassed - that check's own
    correctness (rejecting loopback/private/link-local/metadata addresses) is proven independently and
    exhaustively by the pure `_is_unsafe_ip` unit tests, never by this bypass.
    """
    parts = urlsplit(url)
    if require_https and parts.scheme != "https":
        raise FetchError("scheme_not_https")
    if parts.scheme not in {"http", "https"}:
        raise FetchError("scheme_not_https")
    host = parts.hostname
    if not host or host not in allowed_hosts:
        raise FetchError("host_not_allowed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addrs = resolver(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError("dns_resolution_failed") from exc
    if not addrs:
        raise FetchError("dns_resolution_failed")
    ip = addrs[0][4][0]
    if not _skip_destination_check and _is_unsafe_ip(ip):
        raise FetchError("destination_not_allowed")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        conn = _PinnedHTTPSConnection(host, ip, port, timeout=timeout_s, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout_s)
    try:
        conn.request("GET", path, headers={"Host": host, "User-Agent": "NsureGRC-SourceRegistry/1.0"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise FetchError(f"http_status_{resp.status}")
        data = bytearray()
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise FetchError("response_too_large")
        return bytes(data)
    except TimeoutError as exc:
        raise FetchError("timeout") from exc
    except OSError as exc:
        raise FetchError("connection_failed") from exc
    finally:
        conn.close()
