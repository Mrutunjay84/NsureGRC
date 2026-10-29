"""Risk HTTP surface (Phase 6): RiskAssessment, RiskScenario. Gated on the existing risk.read/risk.manage
permissions (D-P4-002) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services
from .models import RiskAssessment, RiskScenario


def _assessment_json(a: RiskAssessment) -> dict:
    return {"id": str(a.id), "name": a.name, "description": a.description, "status": a.status,
            "owner": str(a.owner) if a.owner else None, "created_at": a.created_at}


def _scenario_json(s: RiskScenario) -> dict:
    return {"id": str(s.id), "risk_assessment_id": str(s.risk_assessment_id), "name": s.name,
            "description": s.description, "threat": s.threat, "vulnerability": s.vulnerability,
            "likelihood": s.likelihood, "impact": s.impact, "risk_level": services.risk_level(s.likelihood, s.impact),
            "treatment": s.treatment, "status": s.status, "owner": str(s.owner) if s.owner else None,
            "created_at": s.created_at}


class AssessmentCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class RiskAssessmentListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "risk.read")

    def get(self, request):
        return Response({"results": [_assessment_json(a) for a in RiskAssessment.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "risk.manage")
        d = AssessmentCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        a = services.create_risk_assessment(d.validated_data["name"], created_by=request.user.account_id,
                                            description=d.validated_data.get("description", ""),
                                            owner=d.validated_data.get("owner"))
        return Response(_assessment_json(a), status=201)


class ScenarioCreateSerializer(serializers.Serializer):
    risk_assessment = serializers.UUIDField()
    name = serializers.CharField(max_length=200)
    likelihood = serializers.IntegerField(min_value=1, max_value=5)
    impact = serializers.IntegerField(min_value=1, max_value=5)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    threat = serializers.CharField(max_length=1000, required=False, allow_blank=True)
    vulnerability = serializers.CharField(max_length=1000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class ScenarioTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=RiskScenario.Status.choices)


class RiskScenarioListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "risk.read")

    def get(self, request):
        return Response({"results": [_scenario_json(s) for s in RiskScenario.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "risk.manage")
        d = ScenarioCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            ra = RiskAssessment.objects.get(id=d.validated_data["risk_assessment"])
        except RiskAssessment.DoesNotExist:
            return Response({"error": "risk_assessment_not_found"}, status=400)
        try:
            s = services.create_risk_scenario(
                ra, d.validated_data["name"], likelihood=d.validated_data["likelihood"],
                impact=d.validated_data["impact"], created_by=request.user.account_id,
                description=d.validated_data.get("description", ""), threat=d.validated_data.get("threat", ""),
                vulnerability=d.validated_data.get("vulnerability", ""), owner=d.validated_data.get("owner"),
            )
        except services.RiskError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_scenario_json(s), status=201)


class RiskScenarioTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "risk.manage")

    def post(self, request, pk):
        try:
            s = RiskScenario.objects.get(id=pk)
        except RiskScenario.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = ScenarioTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            s = services.transition_scenario(s, d.validated_data["status"], actor_id=request.user.account_id)
        except services.RiskError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_scenario_json(s))
