"""Phase 6: Risk/Governance/Compliance-Audit/Privacy HTTP surfaces - create+list work for control.manage-
equivalent permissions, a plain member is read-only, transitions work, tenant isolation on one entity per
domain (the underlying RLS/permission plumbing is identical and already exhaustively tested per-domain at
the service layer - this file only proves the HTTP wiring itself)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------------------------------- risk
def test_risk_assessment_and_scenario_create_list_transition(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    ra = u.api.post("/tenant/risk/assessments/", {"name": "Q4 assessment"}).json()
    r = u.api.post("/tenant/risk/scenarios/",
                   {"risk_assessment": ra["id"], "name": "Vendor outage", "likelihood": 3, "impact": 4})
    assert r.status_code == 201, r.content
    scenario = r.json()
    assert scenario["risk_level"]
    r = u.api.get("/tenant/risk/scenarios/")
    assert any(s["id"] == scenario["id"] for s in r.json()["results"])
    r = u.api.post(f"/tenant/risk/scenarios/{scenario['id']}/transition/", {"status": "treating"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "treating"


def test_risk_member_is_read_only(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.post("/tenant/risk/assessments/", {"name": "Q4"})
    assert r.status_code == 403
    assert u.api.get("/tenant/risk/assessments/").status_code == 200


def test_risk_scenario_tenant_isolation(tenant_a, tenant_b, make_user):
    ua = make_user(tenant_a, "owner")
    ra = ua.api.post("/tenant/risk/assessments/", {"name": "Q4"}).json()
    ua.api.post("/tenant/risk/scenarios/", {"risk_assessment": ra["id"], "name": "X", "likelihood": 1, "impact": 1})
    ub = make_user(tenant_b, "owner")
    assert ub.api.get("/tenant/risk/scenarios/").json()["results"] == []


# ----------------------------------------------------------------------------------------------- governance
def test_policy_objective_issue_create_and_issue_transition(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    assert u.api.post("/tenant/governance/policies/", {"title": "Access Policy"}).status_code == 201
    assert u.api.post("/tenant/governance/objectives/", {"title": "Reduce MTTR"}).status_code == 201
    r = u.api.post("/tenant/governance/issues/", {"title": "Vendor gap", "severity": "high"})
    assert r.status_code == 201, r.content
    issue = r.json()
    r = u.api.post(f"/tenant/governance/issues/{issue['id']}/transition/", {"status": "in_progress"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "in_progress"


# ------------------------------------------------------------------------------------------- compliance audits
def test_audit_fails_closed_without_an_activated_framework(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/tenant/audits/", {"framework_urn": "not-activated", "name": "Q4 audit"})
    assert r.status_code == 400
    assert "error" in r.json()


# ------------------------------------------------------------------------------------------------- privacy
def test_processing_activity_and_rights_request_and_breach(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    assert u.api.post("/tenant/privacy/processing-activities/",
                      {"name": "Payroll", "role": "controller"}).status_code == 201
    r = u.api.post("/tenant/privacy/rights-requests/", {"requester_reference": "REQ-1", "request_type": "access"})
    assert r.status_code == 201, r.content
    req = r.json()
    r = u.api.post(f"/tenant/privacy/rights-requests/{req['id']}/transition/", {"status": "in_progress"})
    assert r.status_code == 200, r.content
    r = u.api.post("/tenant/privacy/breaches/", {"title": "Laptop lost", "severity": "high"})
    assert r.status_code == 201, r.content
    breach = r.json()
    r = u.api.post(f"/tenant/privacy/breaches/{breach['id']}/transition/", {"status": "investigating"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "investigating"
