"""Common/Implementation controls and control assertions (D-P3-001).

All plain TEN writes (no new DB role, unlike the Framework Engine - D-P0-009's control/evidence/test
domain has no CAT/PLT content). Callers must already be inside the target tenant's `tenant_context()` and
have checked `control.manage` - services trust an already-authorized caller, same convention as
`ngrc.framework.services` (no HTTP layer exists yet for this app either).
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.framework import services as framework_services

from .models import CommonControl, ControlAssertion, ImplementationControl


class ControlError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def create_common_control(key: str, name: str, *, created_by, objective: str = "", category: str = "",
                           owner=None) -> CommonControl:
    control = CommonControl.objects.create(
        key=key, name=name, objective=objective, category=category, owner=owner, created_by=created_by,
    )
    audit.record("control.common_control.created", actor_id=created_by, object_type="common_control",
                 object_id=str(control.id), details={"key": key})
    return control


def create_implementation_control(common_control: CommonControl, name: str, *, created_by,
                                   description: str = "", owner=None, reviewer=None, due_date=None) -> ImplementationControl:
    impl = ImplementationControl.objects.create(
        common_control=common_control, name=name, description=description, owner=owner, reviewer=reviewer,
        due_date=due_date, created_by=created_by,
    )
    audit.record("control.implementation_control.created", actor_id=created_by, object_type="implementation_control",
                 object_id=str(impl.id), details={"common_control_key": common_control.key})
    return impl


def assert_control(implementation_control: ImplementationControl, framework_urn: str, requirement_urn: str, *,
                    created_by, coverage: int | None = None) -> ControlAssertion:
    """Fails closed: the requirement must actually resolve (the tenant has `framework_urn` activated and
    `requirement_urn` exists in the pinned version) - reuses the Framework Engine's own resolver rather
    than re-implementing requirement lookup (D-P2-001/003)."""
    try:
        resolved_urns = {r.urn for r in framework_services.resolve_requirements(framework_urn)}
    except framework_services.FrameworkError as exc:
        raise ControlError(f"framework_not_resolved:{exc.code}") from exc
    if requirement_urn not in resolved_urns:
        raise ControlError("requirement_not_resolved")
    assertion = ControlAssertion.objects.create(
        implementation_control=implementation_control, framework_urn=framework_urn, requirement_urn=requirement_urn,
        coverage=coverage, created_by=created_by,
    )
    audit.record("control.assertion.created", actor_id=created_by, object_type="control_assertion",
                 object_id=str(assertion.id), details={"framework_urn": framework_urn, "requirement_urn": requirement_urn})
    return assertion
