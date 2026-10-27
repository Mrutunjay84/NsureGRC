"""Reporting HTTP surface (Phase 6 increment 1 - UI dashboard). Read-only: wraps the already-built,
already-tested `tenant_report()` aggregator (D-P5-008) behind the standard tenant-session policy. Gated on
`tenant.view` - the same baseline permission `ngrc.tenancy.views.MeView` uses - not a new catalogue
permission: a tenant-wide metrics overview is exactly what every member of a tenant already sees, matching
the UI/UX spec's "Overview > Analytics" nav item having no extra access gate."""
from __future__ import annotations

from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services


class DashboardView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "tenant.view")

    def get(self, request):
        return Response(services.tenant_report())
