"""F-DAT-004 / decision C-6 (D-P0-007 s5): evidence is downloaded ONLY through an authorization-checked application endpoint - no signed storage URLs -
and only after a clean scan; every download is audited (object, revision hash, actor, result) before any byte is released; the stored object is
verified against its recorded SHA-256 first; foreign / unknown / unreadable-Restricted ids are an identical 404; support sessions have no path."""
import pytest
from django.urls import Resolver404, resolve

from ngrc.audit import alerts, service
from ngrc.authz import permissions as perm
from ngrc.core.errors import AuditWriteFailed
from ngrc.evidence import scanner

from .conftest import role_connect
from .evidence_factory import EICAR_FILE, PDF, PNG, Made, download_url, make_evidence, stored_path
from .helpers import Api, audit_events

pytestmark = pytest.mark.security


def get(user, m: Made):
    return user.api.get(download_url(m))


def body(resp) -> bytes:
    return b"".join(resp.streaming_content)


# ------------------------------------------------------------------------------------------------ the happy path and its headers
def test_download_streams_the_exact_bytes_with_hardened_headers_and_no_redirect(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, content=PDF + b"payload", filename="../../etc/passwd.pdf")
    assert m.state == "collected"
    r = get(owner, m)
    assert r.status_code == 200 and body(r) == m.content and r["Content-Length"] == str(len(m.content))
    assert r["Content-Type"] == "application/octet-stream"                                       # never the declared type: no sniffing / inline rendering
    disp = r["Content-Disposition"]
    assert disp.startswith("attachment;") and "/" not in disp.split("filename*=")[0] and ".." not in disp and "passwd.pdf" in disp
    assert r["X-Content-Type-Options"] == "nosniff" and r["Cache-Control"] == "no-store"
    assert r.status_code < 300 and not r.has_header("Location")                                 # C-6: no redirect to a storage URL
    assert str(stored_path(tenant_a.id, m.rev)) not in repr(r.headers) and "tenants/" not in repr(r.headers)


def test_the_event_records_object_revision_hash_actor_and_result(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner)
    assert get(owner, m).status_code == 200
    (e,) = audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")
    assert e["actor_id"] == str(owner.account.id) and e["result"] == "success" and e["object_id"] == m.rev
    assert f'"revision_sha256":"{m.sha256}"' in e["details"].replace(" ", "") and '"revision_no":1' in e["details"].replace(" ", "")


def test_authentication_and_the_evidence_read_permission_are_required(tenant_a, make_user):
    owner, member, admin = make_user(tenant_a, "owner"), make_user(tenant_a, "member"), make_user(tenant_a, "admin")
    m = make_evidence(owner)
    assert Api().get(download_url(m)).status_code == 401
    assert get(member, m).status_code == 403                                                     # the default member role has no evidence.read
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", actor_id=member.account.id)
    assert get(admin, m).status_code == 200                                                      # control: admins hold evidence.read
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded", actor_id=member.account.id)


# ------------------------------------------------------------------------------------------------ BOLA / IDOR
def test_cross_tenant_download_is_an_identical_audited_404(tenant_a, tenant_b, make_user):
    a_owner, b_owner = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    secret = make_evidence(a_owner, content=PDF + b"tenant A secret")
    own = make_evidence(b_owner)
    foreign = get(b_owner, secret)
    unknown = b_owner.api.get(f"/tenant/evidence/{secret.id}/revisions/00000000-0000-0000-0000-000000000000/download/")
    wrong_pair = b_owner.api.get(f"/tenant/evidence/{own.id}/revisions/{secret.rev}/download/")   # B's evidence id + A's revision id
    assert foreign.status_code == unknown.status_code == wrong_pair.status_code == 404
    assert foreign.content == unknown.content == wrong_pair.content == b'{"error":"not_found"}'
    assert b"tenant A secret" not in foreign.content
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")
    assert audit_events(tenant_id=tenant_b.id, action="authz.denied", reason_code="object_not_found", actor_id=b_owner.account.id)


def test_a_database_row_pointing_at_another_tenants_object_is_never_opened(tenant_a, tenant_b, make_user):
    a_owner, b_owner = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    a_doc = make_evidence(a_owner, content=PDF + b"A only")
    b_doc = make_evidence(b_owner)
    with role_connect("ngrc_owner") as c:       # simulate a corrupted / malicious key (schema-owner action; RLS context set as the policy requires)
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_b.id)])
        c.execute("ALTER TABLE ten_evidence_revision DISABLE TRIGGER USER")   # the immutability trigger refuses even the owner role: lift it for the probe
        c.execute("UPDATE ten_evidence_revision SET storage_key = %s WHERE id = %s", [f"tenants/{tenant_a.id}/evidence/{a_doc.rev}", b_doc.rev])
        c.execute("ALTER TABLE ten_evidence_revision ENABLE TRIGGER USER")
        c.commit()
    r = get(b_owner, b_doc)
    assert r.status_code == 404 and b"A only" not in r.content


# ------------------------------------------------------------------------------------------------ scan lifecycle
def test_quarantined_evidence_is_retained_but_never_served(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, content=EICAR_FILE, filename="invoice.txt", content_type="text/plain")
    assert m.state == "quarantined" and stored_path(tenant_a.id, m.rev).exists()               # kept for investigation
    r = get(owner, m)
    assert r.status_code == 409 and r.json() == {"error": "not_available"} and b"EICAR" not in r.content
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")
    assert audit_events(tenant_id=tenant_a.id, action="evidence.scan.quarantined")


def test_a_revision_whose_scan_has_not_completed_is_never_served(tenant_a, make_user, monkeypatch):
    owner = make_user(tenant_a, "owner")

    def broken():
        raise RuntimeError("scanner unavailable")

    monkeypatch.setattr(scanner, "get_scanner", broken)
    m = make_evidence(owner, content=PDF + b"unscanned")
    assert m.state == "scan_pending"
    r = get(owner, m)
    assert r.status_code == 409 and b"unscanned" not in r.content
    assert audit_events(tenant_id=tenant_a.id, action="evidence.scan.error")


# ------------------------------------------------------------------------------------------------ integrity
def test_an_object_that_no_longer_matches_its_recorded_hash_is_refused_and_alerted(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, content=PDF + b"original")
    alerts.recorder.reset()
    stored_path(tenant_a.id, m.rev).write_bytes(PDF + b"TAMPERED")
    r = get(owner, m)
    assert r.status_code == 500 and r.json() == {"error": "integrity_check_failed"} and b"TAMPERED" not in r.content
    ev = audit_events(tenant_id=tenant_a.id, action="evidence.hash_mismatch")             # persisted although the request failed (independent transaction)
    assert ev and m.sha256 in ev[-1]["details"] and ev[-1]["result"] == "failure"
    assert any(a.kind == "evidence_integrity_failure" and a.severity == "critical" for a in alerts.recorder.sent)
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")


def test_a_missing_or_truncated_object_is_an_integrity_failure_not_a_partial_download(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m1, m2 = make_evidence(owner, content=PDF + b"x" * 100), make_evidence(owner, content=PNG, filename="pic.png", content_type="image/png")
    stored_path(tenant_a.id, m1.rev).write_bytes(PDF + b"x" * 10)      # truncated
    stored_path(tenant_a.id, m2.rev).unlink()                          # missing
    for m in (m1, m2):
        r = get(owner, m)
        assert r.status_code == 500 and r.json() == {"error": "integrity_check_failed"}
    assert len(audit_events(tenant_id=tenant_a.id, action="evidence.hash_mismatch")) >= 2


# ------------------------------------------------------------------------------------------------ fail-closed audit (C-4)
def test_no_byte_is_released_when_the_download_event_cannot_be_written(tenant_a, make_user, monkeypatch):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, content=PDF + b"must not leak")
    real = service.append_tenant

    def failing(using, ev):
        if ev.action == "evidence.downloaded":
            raise AuditWriteFailed("simulated audit outage")
        return real(using, ev)

    monkeypatch.setattr(service, "append_tenant", failing)
    r = get(owner, m)
    assert r.status_code == 500 and not r.streaming and b"must not leak" not in r.content
    monkeypatch.setattr(service, "append_tenant", real)
    assert get(owner, m).status_code == 200                                                         # control: works again once audit works


# ------------------------------------------------------------------------------------------------ Restricted class and support access
def test_restricted_evidence_is_invisible_without_the_restricted_permission(tenant_a, make_user):
    owner, admin = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    m = make_evidence(owner, content=PDF + b"R-class", data_class="R", title="Board minutes")
    assert get(admin, m).status_code == 404                                                          # indistinguishable from "does not exist"
    assert admin.api.get(f"/tenant/evidence/{m.id}/").status_code == 404
    assert m.id not in str(admin.api.get("/tenant/evidence/").json())
    assert admin.api.post("/tenant/evidence/", {"title": "x", "data_class": "R"}).status_code == 403   # cannot create what it cannot read
    assert body(get(owner, m)).endswith(b"R-class")
    assert m.id in str(owner.api.get("/tenant/evidence/").json())


def test_support_sessions_and_operators_have_no_path_to_evidence(tenant_a, make_user, login_operator):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner)
    for path in ("/ops/api/v1/support/tenant/evidence/", f"/ops/api/v1/support/tenant/evidence/{m.id}/", "/ops/api/v1/evidence/"):
        with pytest.raises(Resolver404):
            resolve(path)
    assert not [k for p in perm.SUPPORT_PROFILE_PERMISSIONS.values() for k in p if k.startswith("evidence")]
    assert not [k for r in perm.PLATFORM_ROLES.values() for k in r if "evidence" in k]
    op = login_operator("platform_support")
    cust = Api()
    cust.set_cookie("__Host-ngrc-sid", op.api.cookie("__Host-ngrc-ops-sid"))                       # an operator cookie on the customer API is not a session
    assert cust.get(download_url(m)).status_code == 401


# ------------------------------------------------------------------------------------------------ no storage URLs, no leaked keys
def test_api_responses_never_expose_storage_keys_paths_or_urls(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner)
    texts = [owner.api.get(f"/tenant/evidence/{m.id}/").content.decode(), owner.api.get("/tenant/evidence/").content.decode(),
             owner.api.get("/tenant/search/?q=review").content.decode()]
    for t in texts:
        assert "storage" not in t.lower() and "tenants/" not in t and str(tenant_a.id) not in t and "http" not in t
