"""Request id + security headers."""
from __future__ import annotations

import re
import uuid

_RID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class RequestIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        inbound = request.META.get("HTTP_X_REQUEST_ID", "")
        request.request_id = inbound if _RID.match(inbound) else str(uuid.uuid4())
        response = self.get_response(request)
        response["X-Request-ID"] = request.request_id
        return response


class SecurityHeadersMiddleware:
    """API-only service: lock down every response. Auth/API responses are never cacheable."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        response.setdefault("Cache-Control", "no-store")
        response.setdefault("Pragma", "no-cache")
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "no-referrer")
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response
