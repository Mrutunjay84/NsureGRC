"""Compliance Audits HTTP surface (Phase 6): Audit, AuditItem. Gated on the existing
compliance_audit.read/compliance_audit.manage permissions (D-P4-005) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.framework import services as framework_services

from . import services
from .models import Audit, AuditItem


def _audit_json(a: Audit) -> dict:
    return {"id": str(a.id), "framework_urn": a.framework_urn, "name": a.name, "description": a.description,
            "status": a.status, "assigned_to": str(a.assigned_to) if a.assigned_to else None,
            "reviewer": str(a.reviewer) if a.reviewer else None, "locked_at": a.locked_at, "created_at": a.created_at}


def _item_json(i: AuditItem) -> dict:
    return {"id": str(i.id), "audit_id": str(i.audit_id), "requirement_urn": i.requirement_urn,
            "control_assertion_id": str(i.control_assertion_id) if i.control_assertion_id else None,
            "result": i.result, "observation": i.observation, "created_at": i.created_at}


class AuditCreateSerializer(serializers.Serializer):
    framework_urn = serializers.SlugField(max_length=200)
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    assigned_to = serializers.UUIDField(required=False, allow_null=True)
    reviewer = serializers.UUIDField(required=False, allow_null=True)


class AuditTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Audit.Status.choices)


class AuditListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "compliance_audit.read")

    def get(self, request):
        return Response({"results": [_audit_json(a) for a in Audit.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "compliance_audit.manage")
        d = AuditCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            a = services.create_audit(
                d.validated_data["framework_urn"], d.validated_data["name"], created_by=request.user.account_id,
                description=d.validated_data.get("description", ""), assigned_to=d.validated_data.get("assigned_to"),
                reviewer=d.validated_data.get("reviewer"),
            )
        except (services.ComplianceAuditError, framework_services.FrameworkError) as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_audit_json(a), status=201)


class AuditDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "compliance_audit.read")

    def get(self, request, pk):
        try:
            a = Audit.objects.get(id=pk)
        except Audit.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        items = [_item_json(i) for i in AuditItem.objects.filter(audit=a).order_by("requirement_urn")]
        return Response({**_audit_json(a), "items": items})


class AuditTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "compliance_audit.manage")

    def post(self, request, pk):
        try:
            a = Audit.objects.get(id=pk)
        except Audit.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = AuditTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            a = services.transition_audit(a, d.validated_data["status"], actor_id=request.user.account_id)
        except services.ComplianceAuditError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_audit_json(a))


class AuditItemCreateSerializer(serializers.Serializer):
    requirement_urn = serializers.SlugField(max_length=250)


class AuditItemListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "compliance_audit.read")

    def post(self, request, pk):
        self.require(request, "compliance_audit.manage")
        try:
            a = Audit.objects.get(id=pk)
        except Audit.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = AuditItemCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            item = services.add_audit_item(a, d.validated_data["requirement_urn"], created_by=request.user.account_id)
        except services.ComplianceAuditError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_item_json(item), status=201)
