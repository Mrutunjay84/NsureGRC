"""DEV ONLY (D-P6-001). Serves the Django customer plane over HTTPS on 127.0.0.1:8443 using a self-signed
cert from .dev-certs/ (generate with `scripts/gen_dev_cert.sh`), so the frontend dev proxy and the browser
both see a secure cookie-compatible origin, matching this project's CSRF_COOKIE_SECURE/SESSION_COOKIE_SECURE
settings unchanged. `gunicorn` (the real production server) does not run on Windows (imports `fcntl`).

Uses the stdlib `wsgiref.simple_server`, not uvicorn: Django's own `WSGIHandler.__call__` builds every
Set-Cookie header via `cookie_morsel.output(header="")` (django/core/handlers/wsgi.py), and
`http.cookies.Morsel.output()` always prefixes its output with a space when `header=""` - so Django itself
hands the WSGI server a Set-Cookie value with a leading space on every response that sets a cookie. h11
(uvicorn's strict HTTP/1.1 layer) rejects that as an "Illegal header value" and drops the connection -
confirmed by testing directly against this app, not a hypothetical. Real browsers and `wsgiref`'s own
unvalidated header writer both tolerate the leading space (HTTP's OWS allowance), so this is a dev-server
choice to route around a strict-parser incompatibility, not a change to the application's own response
code - worth a closer look if this app is ever fronted by something as strict as h11 in production."""
import os
import ssl
import sys
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

REPO = Path(__file__).resolve().parent.parent
CERT, KEY = REPO / ".dev-certs" / "localhost.crt", REPO / ".dev-certs" / "localhost.key"

if not CERT.exists() or not KEY.exists():
    sys.exit(f"missing dev cert - run: bash scripts/gen_dev_cert.sh (expected {CERT} and {KEY})")

sys.path.insert(0, str(REPO))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
os.environ.setdefault("NGRC_PLANE", "customer")

import django  # noqa: E402

django.setup()

from config.wsgi import application  # noqa: E402


class ThreadingHTTPSServer(WSGIServer):
    allow_reuse_address = True


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
    with make_server("127.0.0.1", 8443, application, server_class=ThreadingHTTPSServer,
                     handler_class=WSGIRequestHandler) as httpd:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print("Serving https://127.0.0.1:8443 (Ctrl+C to quit)")
        httpd.serve_forever()
