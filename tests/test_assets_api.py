"""Phase 7: Assets + BIA HTTP surface (D-P7-002) - asset/BIA create+list, the cross-reference 02_PRD.md s13
asks for (RiskScenario.asset, Incident.asset - both optional), Incident's first-ever HTTP exposure (built in
D-P4-003, never wired to the web until this increment needed it to test the asset link), member read-only,
tenant isolation. Same scope as tests/test_risk_governance_privacy_audits_api.py: the underlying service-
layer logic (risk_level, transition graphs) is already exhaustively tested elsewhere - this file only
proves the HTTP wiring and the new cross-references."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_asset_create_list_and_bia_record(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/tenant/assets/", {"name": "Primary DB cluster", "asset_type": "data", "criticality": "critical"})
    assert r.status_code == 201, r.content
    asset = r.json()

    r = u.api.post("/tenant/assets/bia/", {"asset_id": asset["id"], "impact_rating": "high",
                                           "recovery_time_objective_hours": 4, "recovery_point_objective_hours": 1})
    assert r.status_code == 201, r.content

    r = u.api.get(f"/tenant/assets/{asset['id']}/")
    assert r.status_code == 200, r.content
    detail = r.json()
    assert len(detail["bias"]) == 1
    assert detail["bias"][0]["impact_rating"] == "high"


def test_risk_scenario_and_incident_can_reference_an_asset(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    asset = u.api.post("/tenant/assets/", {"name": "Payment service", "asset_type": "service", "criticality": "high"}).json()
    ra = u.api.post("/tenant/risk/assessments/", {"name": "Q1"}).json()

    r = u.api.post("/tenant/risk/scenarios/",
                   {"risk_assessment": ra["id"], "name": "Outage", "likelihood": 3, "impact": 4, "asset_id": asset["id"]})
    assert r.status_code == 201, r.content
    assert r.json()["asset_id"] == asset["id"]

    r = u.api.post("/tenant/risk/incidents/",
                   {"title": "Payment outage", "severity": "high", "asset_id": asset["id"]})
    assert r.status_code == 201, r.content
    incident = r.json()
    assert incident["asset_id"] == asset["id"]
    assert incident["status"] == "detected"

    r = u.api.get(f"/tenant/assets/{asset['id']}/")
    detail = r.json()
    assert len(detail["risk_scenarios"]) == 1 and len(detail["incidents"]) == 1


def test_incident_transition_and_invalid_transition_rejected(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/tenant/risk/incidents/", {"title": "Phishing attempt", "severity": "medium"})
    assert r.status_code == 201, r.content
    incident = r.json()

    r = u.api.post(f"/tenant/risk/incidents/{incident['id']}/transition/", {"status": "investigating"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "investigating"

    # investigating -> resolved directly is not allowed (must pass through contained)
    r = u.api.post(f"/tenant/risk/incidents/{incident['id']}/transition/", {"status": "resolved"})
    assert r.status_code == 400, r.content


def test_asset_and_bia_member_is_read_only(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.post("/tenant/assets/", {"name": "X", "asset_type": "hardware", "criticality": "low"})
    assert r.status_code == 403
    assert u.api.get("/tenant/assets/").status_code == 200


def test_asset_tenant_isolation(tenant_a, tenant_b, make_user):
    ua = make_user(tenant_a, "owner")
    ua.api.post("/tenant/assets/", {"name": "A-only", "asset_type": "data", "criticality": "low"})
    ub = make_user(tenant_b, "owner")
    assert ub.api.get("/tenant/assets/").json()["results"] == []
