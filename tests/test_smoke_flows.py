import pytest

pytestmark = pytest.mark.security


def test_customer_full_login_flow(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    r = u.api.get("/tenant/me/")
    assert r.status_code == 200, r.content
    assert r.json()["role"] == "owner"


def test_operator_login_flow(login_operator):
    op = login_operator("platform_admin")
    r = op.api.get("/auth/session/")
    assert r.status_code == 200, r.content
    assert r.json()["stage"] == "active"
