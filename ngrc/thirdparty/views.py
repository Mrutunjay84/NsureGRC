"""Third Parties HTTP surface (D-P7-001): Entity, Representative, Solution, Assessment. Gated on the new
third_party.read/third_party.manage permissions - not privileged, same tier as governance/risk."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services
from .models import (
    CRITICALITY_CHOICES,
    ThirdPartyAssessment,
    ThirdPartyEntity,
    ThirdPartyRepresentative,
    ThirdPartySolution,
)


def _entity_json(e: ThirdPartyEntity) -> dict:
    return {"id": str(e.id), "name": e.name, "category": e.category, "criticality": e.criticality,
            "status": e.status, "description": e.description, "created_at": e.created_at}


def _rep_json(r: ThirdPartyRepresentative) -> dict:
    return {"id": str(r.id), "entity_id": str(r.entity_id), "name": r.name, "email": r.email,
            "role": r.role, "phone": r.phone, "created_at": r.created_at}


def _solution_json(s: ThirdPartySolution) -> dict:
    return {"id": str(s.id), "entity_id": str(s.entity_id), "name": s.name, "description": s.description,
            "data_classification_note": s.data_classification_note, "created_at": s.created_at}


def _assessment_json(a: ThirdPartyAssessment) -> dict:
    return {"id": str(a.id), "entity_id": str(a.entity_id), "solution_id": str(a.solution_id) if a.solution_id else None,
            "scope": a.scope, "risk_rating": a.risk_rating, "status": a.status,
            "assessor": str(a.assessor) if a.assessor else None, "started_at": a.started_at,
            "completed_at": a.completed_at, "created_at": a.created_at}


class EntityCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    category = serializers.ChoiceField(choices=ThirdPartyEntity.Category.choices)
    criticality = serializers.ChoiceField(choices=[c[0] for c in CRITICALITY_CHOICES])
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)


class EntityListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.read")

    def get(self, request):
        return Response({"results": [_entity_json(e) for e in ThirdPartyEntity.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "third_party.manage")
        d = EntityCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        e = services.create_entity(d.validated_data["name"], category=d.validated_data["category"],
                                   criticality=d.validated_data["criticality"],
                                   description=d.validated_data.get("description", ""),
                                   created_by=request.user.account_id)
        return Response(_entity_json(e), status=201)


class EntityDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.read")

    def get(self, request, pk):
        try:
            e = ThirdPartyEntity.objects.get(id=pk)
        except ThirdPartyEntity.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        return Response({
            **_entity_json(e),
            "representatives": [_rep_json(r) for r in e.representatives.order_by("-created_at")],
            "solutions": [_solution_json(s) for s in e.solutions.order_by("-created_at")],
            "assessments": [_assessment_json(a) for a in e.assessments.order_by("-created_at")],
        })


class RepresentativeCreateSerializer(serializers.Serializer):
    entity_id = serializers.UUIDField()
    name = serializers.CharField(max_length=200)
    email = serializers.EmailField(max_length=254)
    role = serializers.CharField(max_length=200, required=False, allow_blank=True)
    phone = serializers.CharField(max_length=32, required=False, allow_blank=True)


class RepresentativeListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.read")

    def get(self, request):
        return Response({"results": [_rep_json(r) for r in ThirdPartyRepresentative.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "third_party.manage")
        d = RepresentativeCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            entity = ThirdPartyEntity.objects.get(id=d.validated_data["entity_id"])
        except ThirdPartyEntity.DoesNotExist:
            return Response({"error": "entity_not_found"}, status=404)
        r = services.create_representative(entity, d.validated_data["name"], d.validated_data["email"],
                                           role=d.validated_data.get("role", ""), phone=d.validated_data.get("phone", ""),
                                           created_by=request.user.account_id)
        return Response(_rep_json(r), status=201)


class SolutionCreateSerializer(serializers.Serializer):
    entity_id = serializers.UUIDField()
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    data_classification_note = serializers.CharField(max_length=500, required=False, allow_blank=True)


class SolutionListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.read")

    def get(self, request):
        return Response({"results": [_solution_json(s) for s in ThirdPartySolution.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "third_party.manage")
        d = SolutionCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            entity = ThirdPartyEntity.objects.get(id=d.validated_data["entity_id"])
        except ThirdPartyEntity.DoesNotExist:
            return Response({"error": "entity_not_found"}, status=404)
        s = services.create_solution(entity, d.validated_data["name"],
                                     description=d.validated_data.get("description", ""),
                                     data_classification_note=d.validated_data.get("data_classification_note", ""),
                                     created_by=request.user.account_id)
        return Response(_solution_json(s), status=201)


class AssessmentCreateSerializer(serializers.Serializer):
    entity_id = serializers.UUIDField()
    solution_id = serializers.UUIDField(required=False, allow_null=True)
    scope = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    risk_rating = serializers.ChoiceField(choices=[c[0] for c in CRITICALITY_CHOICES], required=False, allow_blank=True)
    started_at = serializers.DateField(required=False, allow_null=True)


class AssessmentTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=ThirdPartyAssessment.Status.choices)
    completed_at = serializers.DateField(required=False, allow_null=True)


class AssessmentListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.read")

    def get(self, request):
        return Response({"results": [_assessment_json(a) for a in ThirdPartyAssessment.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "third_party.manage")
        d = AssessmentCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            entity = ThirdPartyEntity.objects.get(id=d.validated_data["entity_id"])
        except ThirdPartyEntity.DoesNotExist:
            return Response({"error": "entity_not_found"}, status=404)
        solution = None
        if d.validated_data.get("solution_id"):
            try:
                solution = ThirdPartySolution.objects.get(id=d.validated_data["solution_id"])
            except ThirdPartySolution.DoesNotExist:
                return Response({"error": "solution_not_found"}, status=404)
        try:
            a = services.create_assessment(entity, solution=solution, scope=d.validated_data.get("scope", ""),
                                           risk_rating=d.validated_data.get("risk_rating", ""),
                                           started_at=d.validated_data.get("started_at"),
                                           created_by=request.user.account_id)
        except services.ThirdPartyError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_assessment_json(a), status=201)


class AssessmentTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "third_party.manage")

    def post(self, request, pk):
        try:
            a = ThirdPartyAssessment.objects.get(id=pk)
        except ThirdPartyAssessment.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = AssessmentTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            a = services.transition_assessment(a, d.validated_data["status"], actor_id=request.user.account_id,
                                               completed_at=d.validated_data.get("completed_at"))
        except services.ThirdPartyError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_assessment_json(a))
