"""Governance HTTP surface (Phase 6): Policy, Objective, Issue. Gated on the existing
governance.read/governance.manage permissions (D-P4-004) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy

from . import services
from .models import Issue, Objective
from .models import Policy as PolicyModel


def _policy_json(p: PolicyModel) -> dict:
    return {"id": str(p.id), "title": p.title, "description": p.description, "status": p.status,
            "owner": str(p.owner) if p.owner else None, "effective_date": p.effective_date,
            "next_review_date": p.next_review_date, "created_at": p.created_at}


def _objective_json(o: Objective) -> dict:
    return {"id": str(o.id), "title": o.title, "description": o.description, "status": o.status,
            "owner": str(o.owner) if o.owner else None, "target_date": o.target_date, "created_at": o.created_at}


def _issue_json(i: Issue) -> dict:
    return {"id": str(i.id), "title": i.title, "description": i.description, "severity": i.severity,
            "status": i.status, "owner": str(i.owner) if i.owner else None, "due_date": i.due_date,
            "created_at": i.created_at}


class PolicyCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class PolicyListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "governance.read")

    def get(self, request):
        return Response({"results": [_policy_json(p) for p in PolicyModel.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "governance.manage")
        d = PolicyCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        p = services.create_policy(d.validated_data["title"], created_by=request.user.account_id,
                                   description=d.validated_data.get("description", ""), owner=d.validated_data.get("owner"))
        return Response(_policy_json(p), status=201)


class ObjectiveCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)
    target_date = serializers.DateField(required=False, allow_null=True)


class ObjectiveListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "governance.read")

    def get(self, request):
        return Response({"results": [_objective_json(o) for o in Objective.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "governance.manage")
        d = ObjectiveCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        o = services.create_objective(d.validated_data["title"], created_by=request.user.account_id,
                                      description=d.validated_data.get("description", ""),
                                      owner=d.validated_data.get("owner"), target_date=d.validated_data.get("target_date"))
        return Response(_objective_json(o), status=201)


class IssueCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    severity = serializers.ChoiceField(choices=Issue.Severity.choices)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)
    due_date = serializers.DateField(required=False, allow_null=True)


class IssueTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Issue.Status.choices)


class IssueListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "governance.read")

    def get(self, request):
        return Response({"results": [_issue_json(i) for i in Issue.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "governance.manage")
        d = IssueCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        i = services.raise_issue(d.validated_data["title"], severity=d.validated_data["severity"],
                                 created_by=request.user.account_id, description=d.validated_data.get("description", ""),
                                 owner=d.validated_data.get("owner"), due_date=d.validated_data.get("due_date"))
        return Response(_issue_json(i), status=201)


class IssueTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "governance.manage")

    def post(self, request, pk):
        try:
            i = Issue.objects.get(id=pk)
        except Issue.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = IssueTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            i = services.transition_issue(i, d.validated_data["status"], actor_id=request.user.account_id)
        except services.GovernanceError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_issue_json(i))
