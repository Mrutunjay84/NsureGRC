"""D-P2-002: the SSRF-safe outbound fetch helper. `_is_unsafe_ip` is the security-critical piece (pure,
no network); the loopback integration tests exercise the real resolve-validate-connect path end to end."""
from __future__ import annotations

import http.server
import threading

import pytest

from ngrc.core.net import FetchError, _is_unsafe_ip, safe_fetch

pytestmark = pytest.mark.security


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.0.0.53",            # loopback
    "10.0.0.1", "172.16.0.1", "192.168.1.1",  # RFC1918 private
    "169.254.169.254", "169.254.1.1",     # link-local / cloud metadata
    "224.0.0.1", "239.255.255.250",       # multicast
    "0.0.0.0",                             # unspecified - not a bind target here, just an address we expect to reject  # noqa: S104
    "::1", "fe80::1", "fc00::1",           # IPv6 loopback / link-local / unique-local (is_private)
    "not-an-ip",                           # unparseable -> fail closed
])
def test_unsafe_ips_are_rejected(ip):
    assert _is_unsafe_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_are_accepted(ip):
    assert _is_unsafe_ip(ip) is False


def test_non_https_scheme_rejected_by_default():
    with pytest.raises(FetchError, match="scheme_not_https"):
        safe_fetch("http://example.test/x", allowed_hosts=frozenset({"example.test"}))


def test_host_not_in_allowlist_rejected():
    with pytest.raises(FetchError, match="host_not_allowed"):
        safe_fetch("https://evil.test/x", allowed_hosts=frozenset({"good.test"}))


def _fake_resolver_for(ip: str):
    def resolver(host, port, proto=None):
        return [(2, 1, 6, "", (ip, port))]
    return resolver


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b"hello from test server"

    def do_GET(self):  # noqa: N802 - stdlib method name
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):  # silence
        pass


class _BigHandler(_Handler):
    body = b"x" * 1000


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()


@pytest.fixture
def big_local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _BigHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()


def test_happy_path_against_a_local_loopback_server(local_server):
    """require_https=False and _skip_destination_check are test-only (D-P2-002): a loopback test server IS
    a loopback address, so this proves the connect/stream/response-cap logic, not the destination guard -
    that guard is proven separately and exhaustively by the _is_unsafe_ip unit tests above, never bypassed
    by a real caller."""
    data = safe_fetch(
        f"http://ngrc-test-source.local:{local_server}/csf",
        allowed_hosts=frozenset({"ngrc-test-source.local"}),
        require_https=False,
        resolver=_fake_resolver_for("127.0.0.1"),
        _skip_destination_check=True,
    )
    assert data == b"hello from test server"


def test_response_over_the_byte_cap_is_rejected(big_local_server):
    with pytest.raises(FetchError, match="response_too_large"):
        safe_fetch(
            f"http://ngrc-test-source.local:{big_local_server}/csf",
            allowed_hosts=frozenset({"ngrc-test-source.local"}),
            require_https=False,
            resolver=_fake_resolver_for("127.0.0.1"),
            _skip_destination_check=True,
            max_bytes=100,
        )


def test_resolver_returning_a_private_ip_is_rejected_even_with_require_https_false(local_server):
    """The private-IP rejection is never bypassed, even in the test-only http path - only the scheme check is."""
    with pytest.raises(FetchError, match="destination_not_allowed"):
        safe_fetch(
            f"http://ngrc-test-source.local:{local_server}/csf",
            allowed_hosts=frozenset({"ngrc-test-source.local"}),
            require_https=False,
            resolver=_fake_resolver_for("10.1.2.3"),  # pretend DNS returned a private address
        )
