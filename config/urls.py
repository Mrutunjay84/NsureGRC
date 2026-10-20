"""Root URLconf. Planes (customer / operator) are mounted according to NGRC_PLANE (D-P0-005 s1).

In production each plane runs as its own process on its own hostname; `all` exists only for the test settings.
"""
from django.conf import settings
from django.urls import include, path

from ngrc.core.views import HealthView

urlpatterns = [path("healthz", HealthView.as_view(), name="healthz")]

if settings.NGRC_PLANE in {"customer", "all"}:
    urlpatterns += [
        path("api/v1/auth/", include("ngrc.iam.urls")),
        path("api/v1/tenant/", include("ngrc.tenancy.urls")),
        path("api/v1/tenant/", include("ngrc.evidence.urls")),
    ]
if settings.NGRC_PLANE in {"operator", "all"}:
    urlpatterns += [path("ops/api/v1/", include("ngrc.control_plane.urls"))]

handler500 = "ngrc.core.views.server_error"
handler404 = "ngrc.core.views.not_found"
