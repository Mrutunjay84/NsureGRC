"""D-P6-001: the reporting dashboard HTTP endpoint - gated on tenant.view (every member, no new permission),
anonymous rejected (covered generically by test_authorization_api.py), response shape matches calling
tenant_report() directly, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.core.context import tenant_context
from ngrc.reporting import services as reporting_services

pytestmark = pytest.mark.security


def test_dashboard_accessible_to_a_plain_member(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.get("/tenant/reporting/dashboard/")
    assert r.status_code == 200, r.content
    body = r.json()
    assert body["posture"]["posture_pct"] is None
    assert body["high_finding_ageing"]["count"] == 0
    assert body["control_health"] == {}


def test_dashboard_response_matches_tenant_report_directly(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control",
                                                      created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        uow.flush()
        direct = reporting_services.tenant_report()
    r = u.api.get("/tenant/reporting/dashboard/")
    assert r.status_code == 200, r.content
    body = r.json()
    assert set(body["control_health"].keys()) == set(direct["control_health"].keys()) == {str(impl.id)}
    assert body["control_health"][str(impl.id)]["health"] == direct["control_health"][str(impl.id)]["health"]


def test_dashboard_tenant_isolation(tenant_a, tenant_b, make_user):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control",
                                                      created_by=uuid.uuid4())
        control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        uow.flush()
    u = make_user(tenant_b, "owner")
    r = u.api.get("/tenant/reporting/dashboard/")
    assert r.status_code == 200, r.content
    assert r.json()["control_health"] == {}
