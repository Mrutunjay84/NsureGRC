"""Phase 7: Third Parties HTTP surface (D-P7-001) - entity/representative/solution/assessment create+list
work for third_party.manage, a plain member is read-only, assessment transitions work, solution/entity
mismatch is rejected, tenant isolation on one entity (the underlying RLS/permission plumbing is identical
and already exhaustively tested per-domain at the service layer - this file only proves the HTTP wiring
itself, same scope as tests/test_risk_governance_privacy_audits_api.py)."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_entity_representative_solution_assessment_create_and_list(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/tenant/third-parties/entities/",
                   {"name": "Acme Cloud", "category": "vendor", "criticality": "high"})
    assert r.status_code == 201, r.content
    entity = r.json()

    r = u.api.post("/tenant/third-parties/representatives/",
                   {"entity_id": entity["id"], "name": "Jane Doe", "email": "jane@acme.example"})
    assert r.status_code == 201, r.content

    r = u.api.post("/tenant/third-parties/solutions/", {"entity_id": entity["id"], "name": "Acme Storage"})
    assert r.status_code == 201, r.content
    solution = r.json()

    r = u.api.post("/tenant/third-parties/assessments/",
                   {"entity_id": entity["id"], "solution_id": solution["id"], "risk_rating": "medium"})
    assert r.status_code == 201, r.content
    assessment = r.json()
    assert assessment["status"] == "draft"

    r = u.api.get(f"/tenant/third-parties/entities/{entity['id']}/")
    assert r.status_code == 200, r.content
    detail = r.json()
    assert len(detail["representatives"]) == 1 and len(detail["solutions"]) == 1 and len(detail["assessments"]) == 1


def test_assessment_transition_and_invalid_transition_rejected(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    entity = u.api.post("/tenant/third-parties/entities/",
                        {"name": "Beta Corp", "category": "processor", "criticality": "low"}).json()
    a = u.api.post("/tenant/third-parties/assessments/", {"entity_id": entity["id"]}).json()

    r = u.api.post(f"/tenant/third-parties/assessments/{a['id']}/transition/", {"status": "in_progress"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "in_progress"

    r = u.api.post(f"/tenant/third-parties/assessments/{a['id']}/transition/", {"status": "completed"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "completed"

    # completed -> in_progress is not an allowed edge (only completed -> draft, the reopen)
    r = u.api.post(f"/tenant/third-parties/assessments/{a['id']}/transition/", {"status": "in_progress"})
    assert r.status_code == 400, r.content

    r = u.api.post(f"/tenant/third-parties/assessments/{a['id']}/transition/", {"status": "draft"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "draft"


def test_assessment_rejects_a_solution_from_a_different_entity(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    entity_a = u.api.post("/tenant/third-parties/entities/",
                          {"name": "Entity A", "category": "vendor", "criticality": "low"}).json()
    entity_b = u.api.post("/tenant/third-parties/entities/",
                          {"name": "Entity B", "category": "vendor", "criticality": "low"}).json()
    solution_b = u.api.post("/tenant/third-parties/solutions/",
                            {"entity_id": entity_b["id"], "name": "B's product"}).json()
    r = u.api.post("/tenant/third-parties/assessments/",
                   {"entity_id": entity_a["id"], "solution_id": solution_b["id"]})
    assert r.status_code == 400, r.content
    assert r.json()["error"] == "solution_entity_mismatch"


def test_third_party_member_is_read_only(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.post("/tenant/third-parties/entities/", {"name": "X", "category": "vendor", "criticality": "low"})
    assert r.status_code == 403
    assert u.api.get("/tenant/third-parties/entities/").status_code == 200


def test_third_party_entity_tenant_isolation(tenant_a, tenant_b, make_user):
    ua = make_user(tenant_a, "owner")
    ua.api.post("/tenant/third-parties/entities/", {"name": "A-only", "category": "vendor", "criticality": "low"})
    ub = make_user(tenant_b, "owner")
    assert ub.api.get("/tenant/third-parties/entities/").json()["results"] == []
