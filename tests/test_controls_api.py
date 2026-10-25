"""Phase 6: Controls/Findings/Tasks HTTP surface - list/create work for a member with control.manage,
a plain member can read but not write, assert_control fails closed without an activated framework,
finding/task transitions work, tenant isolation."""
from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.security


def test_member_can_create_and_list_common_controls(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.post("/tenant/controls/common/", {"key": "ac-1", "name": "Access Control"})
    assert r.status_code == 201, r.content
    cc_id = r.json()["id"]
    r = u.api.get("/tenant/controls/common/")
    assert r.status_code == 200
    assert any(c["id"] == cc_id for c in r.json()["results"])


def test_plain_member_cannot_create_but_can_read(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    r = u.api.post("/tenant/controls/common/", {"key": "ac-1", "name": "Access Control"})
    assert r.status_code == 403
    r = u.api.get("/tenant/controls/common/")
    assert r.status_code == 200


def _common_and_impl(u):
    cc = u.api.post("/tenant/controls/common/", {"key": f"cc-{uuid.uuid4().hex[:8]}", "name": "Access Control"}).json()
    impl = u.api.post("/tenant/controls/implementation/",
                      {"common_control": cc["id"], "name": "Impl"}).json()
    return cc, impl


def test_create_implementation_control_and_detail_view(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    _cc, impl = _common_and_impl(u)
    r = u.api.get(f"/tenant/controls/implementation/{impl['id']}/")
    assert r.status_code == 200, r.content
    body = r.json()
    assert body["id"] == impl["id"]
    assert body["assertions"] == []
    assert body["findings"] == []
    assert body["tasks"] == []


def test_assert_control_fails_closed_without_an_activated_framework(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    _cc, impl = _common_and_impl(u)
    r = u.api.post(f"/tenant/controls/implementation/{impl['id']}/assert/",
                   {"framework_urn": "not-activated", "requirement_urn": "req-1"})
    assert r.status_code == 400
    assert "error" in r.json()


def test_raise_finding_and_transition(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    _cc, impl = _common_and_impl(u)
    r = u.api.post("/tenant/findings/", {"implementation_control": impl["id"], "title": "Stale rule",
                                         "source": "manual", "severity": "high"})
    assert r.status_code == 201, r.content
    finding = r.json()
    assert finding["status"] == "open"
    r = u.api.get("/tenant/findings/")
    assert any(f["id"] == finding["id"] for f in r.json()["results"])
    r = u.api.post(f"/tenant/findings/{finding['id']}/transition/", {"status": "in_remediation"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "in_remediation"


def test_create_task_and_transition(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    _cc, impl = _common_and_impl(u)
    r = u.api.post("/tenant/tasks/", {"implementation_control": impl["id"], "title": "Rotate keys"})
    assert r.status_code == 201, r.content
    task = r.json()
    assert task["status"] == "open"
    r = u.api.post(f"/tenant/tasks/{task['id']}/transition/", {"status": "done"})
    assert r.status_code == 200, r.content
    assert r.json()["status"] == "done"


def test_tenant_isolation_on_implementation_control_detail(tenant_a, tenant_b, make_user):
    ua = make_user(tenant_a, "owner")
    _cc, impl = _common_and_impl(ua)
    ub = make_user(tenant_b, "owner")
    r = ub.api.get(f"/tenant/controls/implementation/{impl['id']}/")
    assert r.status_code == 404
