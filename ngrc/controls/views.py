"""Controls HTTP surface (Phase 6): CommonControl/ImplementationControl, ControlAssertion, Finding, Task.
Every handler runs inside a tenant-bound transaction + audit unit of work via NgrcAPIView, same convention
as every other domain's API layer. Gated on the existing control.read/control.manage permissions
(D-P3-001) - no new catalogue permissions."""
from __future__ import annotations

from rest_framework import serializers
from rest_framework.response import Response

from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.framework import services as framework_services

from . import services
from .models import CommonControl, Finding, ImplementationControl, Task


def _common_control_json(c: CommonControl) -> dict:
    return {"id": str(c.id), "key": c.key, "name": c.name, "objective": c.objective, "category": c.category,
            "lifecycle": c.lifecycle, "owner": str(c.owner) if c.owner else None, "created_at": c.created_at}


def _implementation_control_json(c: ImplementationControl) -> dict:
    return {"id": str(c.id), "common_control_id": str(c.common_control_id),
            "common_control_name": c.common_control.name, "name": c.name, "description": c.description,
            "owner": str(c.owner) if c.owner else None, "reviewer": str(c.reviewer) if c.reviewer else None,
            "due_date": c.due_date, "lifecycle": c.lifecycle, "created_at": c.created_at}


def _finding_json(f: Finding) -> dict:
    return {"id": str(f.id), "implementation_control_id": str(f.implementation_control_id),
            "title": f.title, "description": f.description, "source": f.source, "severity": f.severity,
            "status": f.status, "remediation_notes": f.remediation_notes,
            "owner": str(f.owner) if f.owner else None, "created_at": f.created_at}


def _task_json(t: Task) -> dict:
    return {"id": str(t.id), "implementation_control_id": str(t.implementation_control_id), "title": t.title,
            "description": t.description, "assigned_to": str(t.assigned_to) if t.assigned_to else None,
            "due_date": t.due_date, "status": t.status, "created_at": t.created_at}


class CommonControlSerializer(serializers.Serializer):
    key = serializers.SlugField(max_length=100)
    name = serializers.CharField(max_length=200)
    objective = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    category = serializers.CharField(max_length=100, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class CommonControlListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.read")

    def get(self, request):
        return Response({"results": [_common_control_json(c) for c in CommonControl.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "control.manage")
        d = CommonControlSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            c = services.create_common_control(
                d.validated_data["key"], d.validated_data["name"], created_by=request.user.account_id,
                objective=d.validated_data.get("objective", ""), category=d.validated_data.get("category", ""),
                owner=d.validated_data.get("owner"),
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a client-facing validation error
            return Response({"error": str(exc)}, status=400)
        return Response(_common_control_json(c), status=201)


class ImplementationControlSerializer(serializers.Serializer):
    common_control = serializers.UUIDField()
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=4000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)
    reviewer = serializers.UUIDField(required=False, allow_null=True)
    due_date = serializers.DateField(required=False, allow_null=True)


class ImplementationControlListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.read")

    def get(self, request):
        qs = ImplementationControl.objects.select_related("common_control").order_by("-created_at")
        return Response({"results": [_implementation_control_json(c) for c in qs]})

    def post(self, request):
        self.require(request, "control.manage")
        d = ImplementationControlSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            common = CommonControl.objects.get(id=d.validated_data["common_control"])
        except CommonControl.DoesNotExist:
            return Response({"error": "common_control_not_found"}, status=400)
        c = services.create_implementation_control(
            common, d.validated_data["name"], created_by=request.user.account_id,
            description=d.validated_data.get("description", ""), owner=d.validated_data.get("owner"),
            reviewer=d.validated_data.get("reviewer"), due_date=d.validated_data.get("due_date"),
        )
        return Response(_implementation_control_json(c), status=201)


class AssertControlSerializer(serializers.Serializer):
    framework_urn = serializers.SlugField(max_length=200)
    requirement_urn = serializers.SlugField(max_length=250)
    coverage = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=100)


class ImplementationControlDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.read")

    def get(self, request, pk):
        try:
            c = ImplementationControl.objects.select_related("common_control").get(id=pk)
        except ImplementationControl.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        assertions = [
            {"id": str(a.id), "framework_urn": a.framework_urn, "requirement_urn": a.requirement_urn,
             "coverage": a.coverage, "satisfaction_state": a.satisfaction_state, "review_state": a.review_state}
            for a in c.assertions.order_by("-created_at")
        ]
        findings = [_finding_json(f) for f in c.findings.order_by("-created_at")]
        tasks = [_task_json(t) for t in c.tasks.order_by("-created_at")]
        return Response({**_implementation_control_json(c), "assertions": assertions, "findings": findings, "tasks": tasks})


class ImplementationControlAssertView(NgrcAPIView):
    """Assert a control against a framework requirement (fails closed if the framework isn't activated for
    this tenant - same resolver every other caller of assert_control uses)."""
    ngrc_policy = Policy("tenant", "control.manage")

    def post(self, request, pk):
        try:
            c = ImplementationControl.objects.get(id=pk)
        except ImplementationControl.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = AssertControlSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            a = services.assert_control(
                c, d.validated_data["framework_urn"], d.validated_data["requirement_urn"],
                created_by=request.user.account_id, coverage=d.validated_data.get("coverage"),
            )
        except (services.ControlError, framework_services.FrameworkError) as exc:
            return Response({"error": str(exc)}, status=400)
        return Response({"id": str(a.id), "framework_urn": a.framework_urn, "requirement_urn": a.requirement_urn,
                         "satisfaction_state": a.satisfaction_state}, status=201)


class FindingCreateSerializer(serializers.Serializer):
    implementation_control = serializers.UUIDField()
    title = serializers.CharField(max_length=200)
    source = serializers.ChoiceField(choices=Finding.Source.choices)
    severity = serializers.ChoiceField(choices=Finding.Severity.choices)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    owner = serializers.UUIDField(required=False, allow_null=True)


class FindingTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Finding.Status.choices)
    remediation_notes = serializers.CharField(max_length=2000, required=False, allow_blank=True)


class FindingListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.read")

    def get(self, request):
        return Response({"results": [_finding_json(f) for f in Finding.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "control.manage")
        d = FindingCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            c = ImplementationControl.objects.get(id=d.validated_data["implementation_control"])
        except ImplementationControl.DoesNotExist:
            return Response({"error": "implementation_control_not_found"}, status=400)
        f = services.raise_finding(
            c, d.validated_data["title"], source=d.validated_data["source"], severity=d.validated_data["severity"],
            created_by=request.user.account_id, description=d.validated_data.get("description", ""),
            owner=d.validated_data.get("owner"),
        )
        return Response(_finding_json(f), status=201)


class FindingTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.manage")

    def post(self, request, pk):
        try:
            f = Finding.objects.get(id=pk)
        except Finding.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = FindingTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            f = services.transition_finding(
                f, d.validated_data["status"], actor_id=request.user.account_id,
                remediation_notes=d.validated_data.get("remediation_notes", ""),
            )
        except services.ControlError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_finding_json(f))


class TaskCreateSerializer(serializers.Serializer):
    implementation_control = serializers.UUIDField()
    title = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True)
    assigned_to = serializers.UUIDField(required=False, allow_null=True)
    due_date = serializers.DateField(required=False, allow_null=True)


class TaskTransitionSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Task.Status.choices)


class TaskListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.read")

    def get(self, request):
        return Response({"results": [_task_json(t) for t in Task.objects.order_by("-created_at")]})

    def post(self, request):
        self.require(request, "control.manage")
        d = TaskCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            c = ImplementationControl.objects.get(id=d.validated_data["implementation_control"])
        except ImplementationControl.DoesNotExist:
            return Response({"error": "implementation_control_not_found"}, status=400)
        t = services.create_task(
            c, d.validated_data["title"], created_by=request.user.account_id,
            description=d.validated_data.get("description", ""), assigned_to=d.validated_data.get("assigned_to"),
            due_date=d.validated_data.get("due_date"),
        )
        return Response(_task_json(t), status=201)


class TaskTransitionView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "control.manage")

    def post(self, request, pk):
        try:
            t = Task.objects.get(id=pk)
        except Task.DoesNotExist:
            return Response({"error": "not_found"}, status=404)
        d = TaskTransitionSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        try:
            t = services.transition_task(t, d.validated_data["status"], actor_id=request.user.account_id)
        except services.ControlError as exc:
            return Response({"error": str(exc)}, status=400)
        return Response(_task_json(t))
