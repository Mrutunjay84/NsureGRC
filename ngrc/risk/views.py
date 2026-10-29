"""Risk HTTP surface (Phase 6): RiskAssessment, RiskScenario. Gated on the existing risk.read/risk.manage
permissions (D-P4-002) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services
from .models import CRITICALITY_CHOICES, Asset, AssetBIA, Incident, RiskAssessment, RiskScenario


def _assessment_json(a: RiskAssessment) -> dict:
    return {"id": str(a.id), "name": a.name, "description": a.description, "status": a.status,
            "owner": str(a.owner) if a.owner else None, "created_at": a.created_at}


def _scenario_json(s: RiskScenario) -> dict:
    return {"id": str(s.id), "risk_assessment_id": str(s.risk_assessment_id), "name": s.name,
            "description": s.description, "threat": s.threat, "vulnerability": s.vulnerability,
            "likelihood": s.likelihood, "impact": s.impact, "risk_level": services.risk_level(s.likelihood, s.impact),
            "treatment": s.treatment, "status": s.status, "owner": str(s.owner) if s.owner else None,
            "asset_id": str(s.asset_id) if s.asset_id else None, "created_at": s.created_at}


def _asset_json(a: Asset) -> dict:
    return {"id": str(a.id), "name": a.name, "asset_type": a.asset_type, "criticality": a.criticality,
            "owner": str(a.owner) if a.owner else None, "description": a.description, "created_at": a.created_at}


def _bia_json(b: AssetBIA) -> dict:
    return {"id": str(b.id), "asset_id": str(b.asset_id), "recovery_time_objective_hours": b.recovery_time_objective_hours,
            "recovery_point_objective_hours": b.recovery_point_objective_hours, "impact_rating": b.impact_rating,
            "notes": b.notes, "assessor": str(b.assessor) if b.assessor else None, "assessed_at": b.assessed_at,
            "created_at": b.created_at}


def _incident_json(i: Incident) -> dict:
    return {"id": str(i.id), "title": i.title, "description": i.description, "severity": i.severity,
            "status": i.status, "detected_at": i.detected_at, "resolved_at": i.resolved_at, "closed_at": i.closed_at,
            "owner": str(i.owner) if i.owner else None,
            "risk_scenario_id": str(i.risk_scenario_id) if i.risk_scenario_id else None,
            "implementation_control_id": str(i.implementation_control_id) if i.implementation_control_id else None,
            "asset_id": str(i.asset_id) if i.asset_id else None, "created_at": i.created_at}


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
    asset_id = serializers.UUIDField(required=False, allow_null=True)


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
        asset = None
        if d.validated_data.get("asset_id"):
            try:
                asset = Asset.objects.get(id=d.validated_data["asset_id"])
            except Asset.DoesNotExist:
                return Response({"error": "asset_not_found"}, status=404)
        try:
            s = services.create_risk_scenario(
                ra, d.validated_data["name"], likelihood=d.validated_data["likelihood"],
                impact=d.validated_data["impact"], created_by=request.user.account_id,
                description=d.validated_data.get("description", ""), threat=d.validated_data.get("threat", ""),
                vulnerability=d.validated_data.get("vulnerability", ""), owner=d.validated_data.get("owner"),
                asset=asset,
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


# ------------------------------------------------------------------------------------------------- D-P7-002: assets + BIA
class AssetCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    asset_type = serializers.ChoiceField(choices=Asset.AssetType.choices)
    criticality = serializers.ChoiceField(choices=[c[0] for c in CRITICALITY_CHOICES])
    owner = serializers.UUIDField(required=False, allow_null=True)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)


class BiaCreateSerializer(serializers.Serializer):
    asset_id = serializers.UUIDField()
    impact_rating = serializers.ChoiceField(choices=[c[0] for c in CRITICALITY_CHOICES])
    recovery_time_objective_hours = serializers.FloatField(required=False, allow_null=True)
    recovery_point_objective_hours = serializers.FloatField(required=False, allow_null=True)
    notes = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    assessor = serializers.UUIDField(required=False, allow_null=True)
    assessed_at = serializers.DateField(required=False, allow_null=True)


class AssetListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "asset.read")

    def get(self, request):
        return Response({"results": [_asset_json(a) for a in Asset.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "asset.manage")
        d = AssetCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        a = services.create_asset(d.validated_data["name"], asset_type=d.validated_data["asset_type"],
                                  criticality=d.validated_data["criticality"], owner=d.validated_data.get("owner"),
                                  description=d.validated_data.get("description", ""),
                                  created_by=request.user.account_id)
        return Response(_asset_json(a), status=201)


class AssetDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "asset.read")

    def get(self, request, pk):
        try:
            a = Asset.objects.get(id=pk)
        except Asset.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        return Response({**_asset_json(a), "bias": [_bia_json(b) for b in a.bias.order_by("-created_at")],
                         "risk_scenarios": [_scenario_json(s) for s in a.risk_scenarios.order_by("-created_at")],
                         "incidents": [_incident_json(i) for i in a.incidents.order_by("-created_at")]})


class AssetBiaListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "asset.read")

    def get(self, request):
        return Response({"results": [_bia_json(b) for b in AssetBIA.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "asset.manage")
        d = BiaCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            asset = Asset.objects.get(id=d.validated_data["asset_id"])
        except Asset.DoesNotExist:
            return Response({"error": "asset_not_found"}, status=404)
        b = services.record_bia(asset, impact_rating=d.validated_data["impact_rating"],
                                recovery_time_objective_hours=d.validated_data.get("recovery_time_objective_hours"),
                                recovery_point_objective_hours=d.validated_data.get("recovery_point_objective_hours"),
                                notes=d.validated_data.get("notes", ""), assessor=d.validated_data.get("assessor"),
                                assessed_at=d.validated_data.get("assessed_at"), created_by=request.user.account_id)
        return Response(_bia_json(b), status=201)


# ------------------------------------------------------------------------------------------------- incidents (D-P4-003 model, first HTTP exposure here as part of D-P7-002's asset link)
class IncidentCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    severity = serializers.ChoiceField(choices=Incident.Severity.choices)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)
    detected_at = serializers.DateTimeField(required=False, allow_null=True)
    risk_scenario_id = serializers.UUIDField(required=False, allow_null=True)
    asset_id = serializers.UUIDField(required=False, allow_null=True)


class IncidentTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Incident.Status.choices)


class IncidentListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "risk.read")

    def get(self, request):
        return Response({"results": [_incident_json(i) for i in Incident.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "risk.manage")
        d = IncidentCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        risk_scenario = None
        if d.validated_data.get("risk_scenario_id"):
            try:
                risk_scenario = RiskScenario.objects.get(id=d.validated_data["risk_scenario_id"])
            except RiskScenario.DoesNotExist:
                return Response({"error": "risk_scenario_not_found"}, status=404)
        asset = None
        if d.validated_data.get("asset_id"):
            try:
                asset = Asset.objects.get(id=d.validated_data["asset_id"])
            except Asset.DoesNotExist:
                return Response({"error": "asset_not_found"}, status=404)
        i = services.raise_incident(d.validated_data["title"], severity=d.validated_data["severity"],
                                    created_by=request.user.account_id,
                                    description=d.validated_data.get("description", ""),
                                    owner=d.validated_data.get("owner"), detected_at=d.validated_data.get("detected_at"),
                                    risk_scenario=risk_scenario, asset=asset)
        return Response(_incident_json(i), status=201)


class IncidentTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "risk.manage")

    def post(self, request, pk):
        try:
            i = Incident.objects.get(id=pk)
        except Incident.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = IncidentTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            i = services.transition_incident(i, d.validated_data["status"], actor_id=request.user.account_id)
        except services.RiskError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_incident_json(i))
