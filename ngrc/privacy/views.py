"""Privacy HTTP surface (Phase 6): ProcessingActivity, RightsRequest, Breach. Gated on the existing
privacy.read/privacy.manage permissions (D-P4-006) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services
from .models import Breach, ProcessingActivity, RightsRequest


def _activity_json(a: ProcessingActivity) -> dict:
    return {"id": str(a.id), "name": a.name, "description": a.description, "role": a.role, "status": a.status,
            "owner": str(a.owner) if a.owner else None, "created_at": a.created_at}


def _request_json(r: RightsRequest) -> dict:
    return {"id": str(r.id), "requester_reference": r.requester_reference, "request_type": r.request_type,
            "status": r.status, "due_date": r.due_date, "owner": str(r.owner) if r.owner else None,
            "created_at": r.created_at}


def _breach_json(b: Breach) -> dict:
    return {"id": str(b.id), "title": b.title, "description": b.description, "severity": b.severity,
            "status": b.status, "discovered_at": b.discovered_at, "notified_authority_at": b.notified_authority_at,
            "notified_subjects_at": b.notified_subjects_at,
            "affected_data_subjects_estimate": b.affected_data_subjects_estimate,
            "owner": str(b.owner) if b.owner else None, "created_at": b.created_at}


class ActivityCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    role = serializers.ChoiceField(choices=ProcessingActivity.Role.choices)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class ProcessingActivityListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "privacy.read")

    def get(self, request):
        return Response({"results": [_activity_json(a) for a in ProcessingActivity.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "privacy.manage")
        d = ActivityCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        a = services.create_processing_activity(d.validated_data["name"], role=d.validated_data["role"],
                                                created_by=request.user.account_id,
                                                description=d.validated_data.get("description", ""),
                                                owner=d.validated_data.get("owner"))
        return Response(_activity_json(a), status=201)


class RightsRequestCreateSerializer(serializers.Serializer):
    requester_reference = serializers.CharField(max_length=200)
    request_type = serializers.ChoiceField(choices=RightsRequest.RequestType.choices)
    owner = serializers.UUIDField(required=False, allow_null=True)
    due_date = serializers.DateField(required=False, allow_null=True)


class RightsRequestTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=RightsRequest.Status.choices)


class RightsRequestListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "privacy.read")

    def get(self, request):
        return Response({"results": [_request_json(r) for r in RightsRequest.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "privacy.manage")
        d = RightsRequestCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        r = services.create_rights_request(d.validated_data["requester_reference"],
                                           request_type=d.validated_data["request_type"],
                                           created_by=request.user.account_id, owner=d.validated_data.get("owner"),
                                           due_date=d.validated_data.get("due_date"))
        return Response(_request_json(r), status=201)


class RightsRequestTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "privacy.manage")

    def post(self, request, pk):
        try:
            r = RightsRequest.objects.get(id=pk)
        except RightsRequest.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = RightsRequestTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            r = services.transition_rights_request(r, d.validated_data["status"], actor_id=request.user.account_id)
        except services.PrivacyError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_request_json(r))


class BreachCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    severity = serializers.ChoiceField(choices=Breach.Severity.choices)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)
    affected_data_subjects_estimate = serializers.IntegerField(required=False, allow_null=True, min_value=0)


class BreachTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Breach.Status.choices)


class BreachListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "privacy.read")

    def get(self, request):
        return Response({"results": [_breach_json(b) for b in Breach.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "privacy.manage")
        d = BreachCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        b = services.raise_breach(d.validated_data["title"], severity=d.validated_data["severity"],
                                  created_by=request.user.account_id, description=d.validated_data.get("description", ""),
                                  owner=d.validated_data.get("owner"),
                                  affected_data_subjects_estimate=d.validated_data.get("affected_data_subjects_estimate"))
        return Response(_breach_json(b), status=201)


class BreachTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "privacy.manage")

    def post(self, request, pk):
        try:
            b = Breach.objects.get(id=pk)
        except Breach.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = BreachTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            b = services.transition_breach(b, d.validated_data["status"], actor_id=request.user.account_id)
        except services.PrivacyError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_breach_json(b))
