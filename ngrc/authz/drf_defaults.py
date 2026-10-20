"""DRF defaults referenced from settings.REST_FRAMEWORK.

Kept separate from `ngrc.authz.drf` on purpose: DRF resolves these dotted paths while `rest_framework.views` is still
being imported, so this module must not import `rest_framework.views` (directly or via `ngrc.authz.drf`).
"""
from __future__ import annotations

from rest_framework import exceptions, permissions, status
from rest_framework.authentication import BaseAuthentication
from rest_framework.response import Response


class DenyAll(permissions.BasePermission):
    def has_permission(self, request, view):
        return False


class NgrcSessionAuthentication(BaseAuthentication):
    """Principal comes from SessionAuthMiddleware (server-side session). No other auth mechanism exists in Phase 1."""

    def authenticate(self, request):
        principal = getattr(request._request, "ngrc_principal", None)
        return (principal, None) if principal is not None else None

    def authenticate_header(self, request):
        return "Session"


def exception_handler(exc, context):
    """Uniform, non-revealing error bodies. Unknown exceptions return None => Django 500 (generic JSON, see handler500)."""
    if isinstance(exc, exceptions.NotAuthenticated):
        return Response({"error": "not_authenticated"}, status=status.HTTP_401_UNAUTHORIZED)
    if isinstance(exc, exceptions.PermissionDenied):
        return Response({"error": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
    if isinstance(exc, exceptions.Throttled):
        resp = Response({"error": "throttled", "retry_after": exc.wait}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        if exc.wait:
            resp["Retry-After"] = str(int(exc.wait))
        return resp
    if isinstance(exc, exceptions.NotFound) or exc.__class__.__name__ == "Http404":
        return Response({"error": "not_found"}, status=status.HTTP_404_NOT_FOUND)
    if isinstance(exc, exceptions.ValidationError):
        return Response({"error": "invalid_request", "fields": _flatten(exc.detail)}, status=status.HTTP_400_BAD_REQUEST)
    if isinstance(exc, exceptions.ParseError | exceptions.UnsupportedMediaType | exceptions.NotAcceptable):
        return Response({"error": "invalid_request"}, status=exc.status_code)
    if isinstance(exc, exceptions.MethodNotAllowed):
        return Response({"error": "method_not_allowed"}, status=405)
    if isinstance(exc, exceptions.APIException):
        return Response({"error": "error"}, status=exc.status_code)
    return None


def _flatten(detail):
    if isinstance(detail, dict):
        return {k: _flatten(v) for k, v in detail.items()}
    if isinstance(detail, list):
        return [_flatten(v) if isinstance(v, dict | list) else str(v) for v in detail]
    return str(detail)
