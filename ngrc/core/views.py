from django.http import JsonResponse
from django.views import View


class HealthView(View):
    """Liveness only. PUBLIC by design (allow-listed in the route registry); touches no data, reveals no version."""

    ngrc_public_reason = "liveness probe; no data access, no information disclosure"

    def get(self, request):
        return JsonResponse({"status": "ok"})


def server_error(request, *args, **kwargs):
    """Generic JSON 500: no stack trace, no internals (D-P0-008 s16)."""
    return JsonResponse({"error": "server_error"}, status=500)


def not_found(request, *args, **kwargs):
    return JsonResponse({"error": "not_found"}, status=404)
