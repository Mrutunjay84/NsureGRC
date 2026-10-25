"""D-P6-001: the reporting dashboard HTTP endpoint - gated on tenant.view (every member, no new permission),
anonymous rejected (covered generically by test_authorization_api.py), response shape matches calling
tenant_report() directly, tenant isolation.

D-P7-003: the calendar HTTP endpoint - same tenant.view gate, window_days query param (default/clamping,
rejects non-integers), response shape matches calling calendar_deadlines() directly, tenant isolation."""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from ngrc.audit import service as audit_service
from ngrc.controls import services as control_services
from ngrc.core import clock
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


# -------------------------------------------------------------------------------------------- D-P7-003 calendar
def test_calendar_accessible_to_a_plain_member(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.get("/tenant/reporting/calendar/")
    assert r.status_code == 200, r.content
    assert r.json() == {"deadlines": []}


def test_calendar_response_matches_service_directly(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control",
                                                      created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        control_services.create_task(impl, "Rotate keys", created_by=uuid.uuid4(),
                                      due_date=clock.now().date() + timedelta(days=5))
        uow.flush()
        direct = reporting_services.calendar_deadlines()
    r = u.api.get("/tenant/reporting/calendar/")
    assert r.status_code == 200, r.content
    direct_serialized = [{**d, "date": d["date"].isoformat()} for d in direct]
    assert r.json()["deadlines"] == direct_serialized


def test_calendar_window_days_excludes_dates_beyond_it(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control",
                                                      created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        control_services.create_task(impl, "Far future", created_by=uuid.uuid4(),
                                      due_date=clock.now().date() + timedelta(days=200))
        uow.flush()
    assert u.api.get("/tenant/reporting/calendar/?window_days=90").json() == {"deadlines": []}
    assert len(u.api.get("/tenant/reporting/calendar/?window_days=365").json()["deadlines"]) == 1


def test_calendar_rejects_a_non_integer_window_days(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.get("/tenant/reporting/calendar/?window_days=not-a-number")
    assert r.status_code == 400, r.content


def test_calendar_tenant_isolation(tenant_a, tenant_b, make_user):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        cc = control_services.create_common_control(f"cc-{uuid.uuid4().hex[:8]}", "Access Control",
                                                      created_by=uuid.uuid4())
        impl = control_services.create_implementation_control(cc, "Impl", created_by=uuid.uuid4())
        control_services.create_task(impl, "Rotate keys", created_by=uuid.uuid4(),
                                      due_date=clock.now().date() + timedelta(days=5))
        uow.flush()
    u = make_user(tenant_b, "owner")
    r = u.api.get("/tenant/reporting/calendar/")
    assert r.status_code == 200, r.content
    assert r.json() == {"deadlines": []}
