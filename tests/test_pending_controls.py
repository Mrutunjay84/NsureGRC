"""P2-3: executable specifications for controls that are NOT IMPLEMENTED or BLOCKED, plus runnable demonstrations of dev-only gaps.

Nothing in this file is evidence that a control works. Every test is `xfail(strict=True)`; the outcome is reported as XFAIL, which the
reports count as "not implemented / gap demonstrated", never as a pass. See tests/pending.py for the guard rails and
docs/plans/P2-3_IMPLEMENTATION_PLANS.md for the interface each spec commits to and the definition of done.

Two kinds of test live here:
* SPEC - written against a not-yet-existing interface; stops at `require_route` / `require_symbol` with FeatureAbsent.
* GAP DEMO - runs today against the dev-only stand-in and fails an assertion that states the production property
  (xfail(raises=AssertionError)); it is real execution that proves the stand-in does NOT provide that property.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from django.conf import settings
from django.core import mail

from ngrc.audit import sealer, service, verifier
from ngrc.audit.signer import get_signer
from ngrc.core import crypto
from ngrc.core.context import tenant_context

from .helpers import Api, audit_events, last_mail_token
from .pending import pending, require_route, require_symbol

pytestmark = pytest.mark.security

PLAN = "docs/plans/P2-3_IMPLEMENTATION_PLANS.md"


# ================================================================================================ 1. evidence download (F-DAT-004/005, C-6)
EV = "F-DAT-004"


def _evidence(tenant, **kw):
    make = require_symbol("ngrc.evidence.testing:make_evidence")  # test-support factory delivered with the evidence module
    return make(tenant, **kw)


def _dl(ev):
    return f"/tenant/evidence/{ev.id}/revisions/{ev.revision_id}/download/"


@pending(EV, f"{PLAN} section 1")
def test_download_streams_exact_bytes_through_an_authorization_checked_endpoint(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    ev = _evidence(tenant_a, content=b"%PDF-1.7 spec body", filename="../../etc/passwd.pdf")
    require_route(_dl(ev))
    r = owner.api.get(_dl(ev))
    assert r.status_code == 200 and b"".join(r.streaming_content) == b"%PDF-1.7 spec body"
    disp = r["Content-Disposition"]
    assert disp.startswith("attachment") and "/" not in disp and ".." not in disp  # original name is metadata only, never a path
    assert r["X-Content-Type-Options"] == "nosniff" and "no-store" in r["Cache-Control"]
    assert r.has_header("Location") is False  # C-6: no redirect to a storage URL


@pending(EV, f"{PLAN} section 1")
def test_download_requires_authentication_and_the_evidence_read_permission(tenant_a, make_user):
    ev = _evidence(tenant_a, content=b"x")
    require_route(_dl(ev))
    assert Api().get(_dl(ev)).status_code == 401
    assert make_user(tenant_a, "member").api.get(_dl(ev)).status_code == 403  # default member role lacks evidence.read
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied")


@pending(EV, f"{PLAN} section 1")
def test_cross_tenant_download_is_not_found_leaks_nothing_and_is_audited(tenant_a, tenant_b, make_user):
    ev = _evidence(tenant_a, content=b"tenant A secret")
    require_route(_dl(ev))
    intruder = make_user(tenant_b, "owner")
    r = intruder.api.get(_dl(ev))
    assert r.status_code == 404 and b"tenant A secret" not in r.content
    assert r.content == intruder.api.get(_dl(type("E", (), {"id": ev.id, "revision_id": "00000000-0000-0000-0000-000000000000"}))).content
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")
    assert audit_events(tenant_id=tenant_b.id, action="authz.denied")


@pending(EV, f"{PLAN} section 1")
def test_download_event_records_object_revision_hash_actor_and_result(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    ev = _evidence(tenant_a, content=b"abc")
    require_route(_dl(ev))
    assert owner.api.get(_dl(ev)).status_code == 200
    (e,) = audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")
    assert e["actor_id"] == owner.account.id and e["result"] == "success"
    assert e["details"]["revision_sha256"] == ev.sha256 and e["object_id"] == str(ev.id)


@pending(EV, f"{PLAN} section 1")
@pytest.mark.parametrize("state", ["scan_pending", "quarantined"])
def test_unscanned_or_quarantined_evidence_is_never_served(state, tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    ev = _evidence(tenant_a, content=b"EICAR-like marker", state=state)
    require_route(_dl(ev))
    r = owner.api.get(_dl(ev))
    assert r.status_code in (403, 409) and b"EICAR" not in r.content
    assert not audit_events(tenant_id=tenant_a.id, action="evidence.downloaded")


@pending(EV, f"{PLAN} section 1")
def test_stored_object_that_no_longer_matches_its_recorded_hash_is_refused(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    ev = _evidence(tenant_a, content=b"original")
    require_route(_dl(ev))
    ev.corrupt_stored_object(b"tampered")  # supplied by the testing factory: rewrites the bytes behind the recorded hash
    r = owner.api.get(_dl(ev))
    assert r.status_code in (409, 422, 500) and b"tampered" not in r.content
    assert audit_events(tenant_id=tenant_a.id, action="evidence.hash_mismatch")


@pending(EV, f"{PLAN} section 1")
def test_download_fails_closed_when_the_audit_event_cannot_be_written(tenant_a, make_user, monkeypatch):
    owner = make_user(tenant_a, "owner")
    ev = _evidence(tenant_a, content=b"must not leak")
    require_route(_dl(ev))
    from ngrc.core.errors import AuditWriteFailed

    def boom(*a, **k):
        raise AuditWriteFailed("simulated outage")

    monkeypatch.setattr(service, "emit_tenant", boom)
    r = owner.api.get(_dl(ev))
    assert r.status_code >= 500 and b"must not leak" not in r.content  # bytes are never released before the audit event commits


@pending(EV, f"{PLAN} section 1")
def test_a_support_session_cannot_download_evidence_under_a_metadata_only_grant(tenant_a, login_operator):
    ev = _evidence(tenant_a, content=b"customer content")
    require_route(_dl(ev))
    # an operator holding an ACTIVE diagnostic_metadata grant on tenant A must still be refused (profile has no content access)
    sup = login_operator("platform_support")
    assert sup.api.get(f"/support/tenant/evidence/{ev.id}/").status_code in (403, 404)


@pending(EV, f"{PLAN} section 1")
def test_restricted_class_evidence_is_excluded_from_bulk_export(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    _evidence(tenant_a, content=b"R-class", data_class="R")
    require_route("/tenant/evidence/export/")
    r = owner.api.post("/tenant/evidence/export/", {"scope": "all"})
    assert r.status_code in (200, 202) and b"R-class" not in r.content


@pending(EV, f"{PLAN} section 1")
def test_object_keys_are_tenant_prefixed_and_cannot_be_chosen_by_the_client(tenant_a):
    ev = _evidence(tenant_a, content=b"x", filename="../../tenants/other/evil")
    assert ev.storage_key.startswith(f"tenants/{tenant_a.id}/") and ".." not in ev.storage_key


# ================================================================================================ 2. cross-tenant search (F-AUZ-005, B-01)
SR = "F-AUZ-005"


@pending(SR, f"{PLAN} section 2")
def test_search_returns_only_the_callers_tenant(tenant_a, tenant_b, make_user):
    seed = require_symbol("ngrc.search.testing:index_document")  # test-support: add a document to the index for a tenant
    a = make_user(tenant_a, "owner")
    seed(tenant_a, title="Quarterly access review ZEBRA-A")
    seed(tenant_b, title="Quarterly access review ZEBRA-B")
    require_route("/tenant/search/")
    ra = a.api.get("/tenant/search/?q=ZEBRA").json()
    assert [h["title"] for h in ra["results"]] == ["Quarterly access review ZEBRA-A"]
    assert "ZEBRA-B" not in json.dumps(ra)  # not in results, snippets, facets, counts or suggestions


@pending(SR, f"{PLAN} section 2")
def test_search_without_valid_tenant_context_fails_closed(tenant_a, make_user):
    require_route("/tenant/search/")
    assert Api().get("/tenant/search/?q=x").status_code == 401
    u = make_user(tenant_a, "owner", select_tenant=False)
    assert u.api.get("/tenant/search/?q=x").status_code in (400, 403)


@pending(SR, f"{PLAN} section 2")
def test_search_hits_are_reauthorised_per_item_before_return(tenant_a, make_user):
    seed = require_symbol("ngrc.search.testing:index_document")
    member = make_user(tenant_a, "member")
    seed(tenant_a, title="Restricted board paper", required_permission="evidence.read_restricted")
    require_route("/tenant/search/")
    assert "Restricted board paper" not in json.dumps(member.api.get("/tenant/search/?q=board").json())  # stale index never widens access


@pending(SR, f"{PLAN} section 2")
def test_every_indexed_document_and_query_carries_the_tenant_id(tenant_a):
    index = require_symbol("ngrc.search.index:all_documents")
    assert all(d.get("tenant_id") for d in index()), "an index document without tenant_id would be searchable across tenants"


@pending(SR, f"{PLAN} section 2")
@pytest.mark.parametrize("q", ["' OR 1=1 --", "tenant_id:*", "*", "{{7*7}}", "\\u0000", "a" * 10_000])
def test_search_query_syntax_cannot_widen_the_tenant_filter(q, tenant_a, tenant_b, make_user):
    seed = require_symbol("ngrc.search.testing:index_document")
    seed(tenant_b, title="OTHER-TENANT-DOC")
    require_route("/tenant/search/")
    r = make_user(tenant_a, "owner").api.get("/tenant/search/", **{"QUERY_STRING": f"q={q}"})
    assert r.status_code in (200, 400, 422) and b"OTHER-TENANT-DOC" not in r.content


# ================================================================================================ 3. scheduled audit verification (F-AUD-007, H-03)
AV = "F-AUD-007"


@pending(AV, f"{PLAN} section 3")
def test_scheduled_run_verifies_every_stream_and_records_each_result(tenant_a):
    run = require_symbol("ngrc.audit.scheduler:run_scheduled_verification")
    summary = run()
    assert summary.streams_checked >= 1 and summary.violations == 0
    assert summary.recorded_runs == summary.streams_checked  # one audit.verification_run row per stream


@pending(AV, f"{PLAN} section 3")
def test_scheduled_run_detects_tampering_records_a_violation_and_raises_the_alert(tenant_a):
    run = require_symbol("ngrc.audit.scheduler:run_scheduled_verification")
    alerts = require_symbol("ngrc.audit.alerts:recorder")  # test double that captures notifications
    with tenant_context(tenant_a.id):
        service.emit_tenant("default", "tenant.role.created", tenant_a.id, object_type="role", object_id="r1",
                            details={"role_key": "k", "permissions": 1})
    sealer.seal_all()
    from .test_audit_integrity import attacker

    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'x' WHERE tenant_id = %s", [str(tenant_a.id)])
    summary = run()
    assert summary.violations >= 1 and summary.exit_code != 0
    assert audit_events(platform=True, action="audit.integrity_violation")
    assert any(a.severity == "critical" and str(tenant_a.id) in a.stream for a in alerts.sent)


@pending(AV, f"{PLAN} section 3")
def test_an_overdue_verification_raises_its_own_alert(clock_ctl):
    check = require_symbol("ngrc.audit.scheduler:check_verification_freshness")
    alerts = require_symbol("ngrc.audit.alerts:recorder")
    clock_ctl.advance(hours=settings.AUDIT_VERIFY_MAX_AGE_HOURS + 1)  # setting introduced by the feature
    check()
    assert any(a.kind == "verification_overdue" for a in alerts.sent)  # silence must not look like health


@pending(AV, f"{PLAN} section 3")
def test_incremental_verification_reaches_the_same_verdict_as_a_full_run(tenant_a):
    run = require_symbol("ngrc.audit.scheduler:run_scheduled_verification")
    assert run(mode="incremental").violations == run(mode="full").violations == 0


@pending(AV, f"{PLAN} section 3")
def test_the_verification_job_runs_only_as_the_verifier_identity_and_cannot_be_disabled_by_a_tenant(tenant_a, make_user):
    ident = require_symbol("ngrc.audit.scheduler:database_identity")
    assert ident() == "ngrc_audit_verifier"
    owner = make_user(tenant_a, "owner")
    assert owner.api.post("/tenant/audit/verification/disable/", {}).status_code in (403, 404, 405)


@pending(AV, f"{PLAN} section 3")
def test_missing_external_checkpoint_copy_is_a_violation_in_production_mode(tenant_a, settings):
    run = require_symbol("ngrc.audit.scheduler:run_scheduled_verification")
    settings.AUDIT_REQUIRE_EXTERNAL_COPY = True  # always on in prod settings
    settings.AUDIT_CHECKPOINT_EXPORT_DIR = ""
    assert run().violations >= 1


# ================================================================================================ 4. MFA factor removal (F-ATH-014)
FR = "F-ATH-014"


def _factors(user):
    return user.api.get("/auth/mfa/factors/").json()["factors"]


@pending(FR, f"{PLAN} section 4")
def test_factor_removal_requires_step_up(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    require_route("/auth/mfa/factors/")
    fid = _factors(u)[0]["id"]
    u.clock.advance(minutes=11)  # step-up window lapsed
    assert u.api.delete(f"/auth/mfa/factors/{fid}/").status_code in (401, 403)
    assert len(_factors(u)) >= 1


@pending(FR, f"{PLAN} section 4")
def test_the_last_factor_cannot_be_removed(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    require_route("/auth/mfa/factors/")
    (only,) = _factors(u)
    u.stepup()
    assert u.api.delete(f"/auth/mfa/factors/{only['id']}/").status_code == 409
    assert len(_factors(u)) == 1


@pending(FR, f"{PLAN} section 4")
def test_removal_must_leave_two_recovery_options(tenant_a, make_user):
    """ADR D-P0-008 s7: after removal the account keeps two factors, or one factor plus recovery codes."""
    u = make_user(tenant_a, "owner")
    require_route("/auth/mfa/factors/")
    u.stepup()
    assert u.api.post("/auth/mfa/totp/enroll/begin/", {}).status_code == 200  # second factor path exists in Phase 1
    u.recovery_codes.clear()  # simulate: codes consumed or regenerated away
    (f,) = [x for x in _factors(u) if x["method"] == "totp"][:1]
    assert u.api.delete(f"/auth/mfa/factors/{f['id']}/").status_code == 409


@pending(FR, f"{PLAN} section 4")
def test_removal_revokes_other_sessions_and_is_audited(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    other = u.relogin()
    require_route("/auth/mfa/factors/")
    u.stepup()
    extra = u.api.post("/auth/mfa/webauthn/register/begin/", {})
    assert extra.status_code == 200
    fid = _factors(u)[0]["id"]
    assert u.api.delete(f"/auth/mfa/factors/{fid}/").status_code == 200
    assert other.get("/tenant/me/").status_code == 401  # every OTHER session is revoked
    assert audit_events(tenant_id=tenant_a.id, action="auth.mfa.removed")


@pending(FR, f"{PLAN} section 4")
def test_a_factor_belonging_to_someone_else_is_not_found(tenant_a, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    require_route("/auth/mfa/factors/")
    victim_factor = _factors(b)[0]["id"]
    a.stepup()
    assert a.api.delete(f"/auth/mfa/factors/{victim_factor}/").status_code == 404
    assert len(_factors(b)) >= 1


@pending(FR, f"{PLAN} section 4")
def test_an_operator_cannot_remove_their_own_webauthn_credential(login_operator):
    op = login_operator("platform_security")
    op.stepup()
    require_route("/auth/mfa/factors/", prefix="/ops/api/v1")
    cid = op.api.get("/auth/mfa/factors/").json()["factors"][0]["id"]
    assert op.api.delete(f"/auth/mfa/factors/{cid}/").status_code in (403, 405)  # platform recovery is out-of-band + second approver


# ================================================================================================ 5. lost-factor recovery and lock-out exit (F-ATH-015)
LR = "F-ATH-015"
COOL = 24  # ADR D-P0-008 s7.4 BASELINE (hours)


@pending(LR, f"{PLAN} section 5")
def test_recovery_code_flow_restores_access_notifies_and_audits(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    require_route("/auth/recovery/start/")
    code = u.recovery_codes[0]
    api = Api()
    r = api.post("/auth/recovery/start/", {"email": u.email, "password": u.password, "recovery_code": code})
    assert r.status_code == 200 and mail.outbox  # user is notified of use
    assert Api().post("/auth/recovery/start/", {"email": u.email, "password": u.password, "recovery_code": code}).status_code in (400, 401)  # single use
    assert audit_events(tenant_id=tenant_a.id, action="auth.recovery_codes.used")


@pending(LR, f"{PLAN} section 5 (DEF-15)")
def test_an_account_locked_by_failed_logins_has_an_email_unlock_path_and_the_owner_is_notified(tenant_a, make_user, clock_ctl):
    """DEF-15: the hard stop sets `recovery_required`; the ADR requires 'verified-email unlock + MFA, owner/admin notified, never a silent
    permanent lock'. A stranger who only knows the address must not be able to deny the real user access for good."""
    victim = make_user(tenant_a, "member")
    require_route("/auth/unlock/request/")
    stranger = Api()
    for _ in range(settings.AUTH_THROTTLE["account_recovery_required_at"]):
        clock_ctl.advance(minutes=16)  # step over the progressive back-off between attempts
        stranger.post("/auth/login/", {"email": victim.email, "password": "definitely-the-wrong-password-1"})
    assert Api().post("/auth/login/", {"email": victim.email, "password": victim.password}).status_code == 401  # locked
    mail.outbox.clear()
    assert Api().post("/auth/unlock/request/", {"email": victim.email}).status_code in (200, 202)
    token = last_mail_token(mail.outbox, victim.email)
    assert Api().post("/auth/unlock/confirm/", {"email": victim.email, "token": token}).status_code == 200
    api = Api()
    r = api.post("/auth/login/", {"email": victim.email, "password": victim.password})
    assert r.status_code == 200 and r.json().get("stage") == "password_ok"  # unlocked, but MFA is still required
    assert any(m for m in mail.outbox if "owner@" in ",".join(m.to))  # owner/admin notified of the lock and the unlock


@pending(LR, f"{PLAN} section 5")
def test_admin_assisted_reset_needs_a_different_approver_with_step_up(tenant_a, make_user):
    victim, admin = make_user(tenant_a, "member"), make_user(tenant_a, "admin")
    require_route("/auth/recovery/admin-assisted/request/")
    rid = Api().post("/auth/recovery/admin-assisted/request/", {"email": victim.email}).json()["request_id"]
    assert victim.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code == 403  # cannot approve own request
    assert admin.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code in (401, 403)  # approver needs fresh step-up
    admin.stepup()
    assert admin.api.post(f"/tenant/recovery/{rid}/approve/", {}).status_code == 200
    assert mail.outbox and victim.email in [t for m in mail.outbox for t in m.to]  # target notified


@pending(LR, f"{PLAN} section 5")
def test_the_new_factor_cannot_complete_before_the_cooling_off_period(tenant_a, make_user, clock_ctl):
    victim, admin = make_user(tenant_a, "member"), make_user(tenant_a, "admin")
    require_route("/auth/recovery/admin-assisted/request/")
    rid = Api().post("/auth/recovery/admin-assisted/request/", {"email": victim.email}).json()["request_id"]
    admin.stepup()
    admin.api.post(f"/tenant/recovery/{rid}/approve/", {})
    clock_ctl.advance(hours=COOL - 1, minutes=59)
    assert Api().post(f"/auth/recovery/{rid}/complete/", {"email": victim.email, "password": victim.password}).status_code == 409
    clock_ctl.advance(minutes=2)
    assert Api().post(f"/auth/recovery/{rid}/complete/", {"email": victim.email, "password": victim.password}).status_code == 200


@pending(LR, f"{PLAN} section 5")
def test_the_legitimate_user_can_cancel_during_cooling_off_and_all_sessions_are_revoked_on_completion(tenant_a, make_user, clock_ctl):
    victim, admin = make_user(tenant_a, "member"), make_user(tenant_a, "admin")
    require_route("/auth/recovery/admin-assisted/request/")
    rid = Api().post("/auth/recovery/admin-assisted/request/", {"email": victim.email}).json()["request_id"]
    admin.stepup()
    admin.api.post(f"/tenant/recovery/{rid}/approve/", {})
    cancel_token = mail.outbox[-1].body.split("cancel=")[1].split()[0]
    assert Api().post("/auth/recovery/cancel/", {"token": cancel_token}).status_code == 200
    clock_ctl.advance(hours=COOL + 1)
    assert Api().post(f"/auth/recovery/{rid}/complete/", {"email": victim.email, "password": victim.password}).status_code in (404, 409)
    assert victim.api.get("/tenant/me/").status_code == 200  # a cancelled request changes nothing for the real user


@pending(LR, f"{PLAN} section 5")
def test_platform_support_can_never_reset_a_customers_mfa(tenant_a, make_user, login_operator):
    victim = make_user(tenant_a, "member")
    sup = login_operator("platform_support")
    require_route("/auth/recovery/admin-assisted/request/")
    for path in (f"/support/tenant/users/{victim.account.id}/reset-mfa/", f"/support/recovery/{victim.account.id}/"):
        assert sup.api.post(path, {}).status_code in (403, 404, 405)


@pending(LR, f"{PLAN} section 5")
def test_the_last_owner_requires_platform_security_approval_and_the_same_cooling_off(tenant_a, make_user, login_operator):
    owner = make_user(tenant_a, "owner")  # sole Owner: no peer can approve
    require_route("/auth/recovery/admin-assisted/request/")
    rid = Api().post("/auth/recovery/admin-assisted/request/", {"email": owner.email}).json()["request_id"]
    assert Api().post(f"/auth/recovery/{rid}/complete/", {"email": owner.email, "password": owner.password}).status_code == 409
    sec = login_operator("platform_security")
    sec.stepup()
    assert sec.api.post(f"/recovery/{rid}/approve/", {}).status_code == 200
    assert Api().post(f"/auth/recovery/{rid}/complete/", {"email": owner.email, "password": owner.password}).status_code == 409  # still cooling off


@pending(LR, f"{PLAN} section 5")
def test_recovery_endpoints_are_throttled_and_do_not_reveal_whether_an_account_exists(tenant_a, make_user):
    u = make_user(tenant_a, "member")
    require_route("/auth/recovery/admin-assisted/request/")
    known = Api().post("/auth/recovery/admin-assisted/request/", {"email": u.email})
    unknown = Api().post("/auth/recovery/admin-assisted/request/", {"email": "nobody-here@example.test"})
    assert known.status_code == unknown.status_code and set(known.json()) == set(unknown.json())
    api = Api()
    codes = [api.post("/auth/recovery/admin-assisted/request/", {"email": u.email}).status_code for _ in range(30)]
    assert 429 in codes


# ================================================================================================ 6. production KMS (F-DAT-006, O-4, BLOCKED)
KM = "F-DAT-006"


def _kms_provider():
    return require_symbol("ngrc.core.keys:KmsKeyProvider")  # selected with hosting (O-4); interface per plan section 6


@pending(KM, f"{PLAN} section 6")
def test_kms_provider_envelope_round_trip_and_aad_binding():
    p = _kms_provider()()
    blob = p.seal(b"payload", b"tenant|record|field")
    assert p.open(blob, b"tenant|record|field") == b"payload"
    with pytest.raises(Exception):  # noqa: B017,PT011 - any authentication failure; exact type is provider specific
        p.open(blob, b"other-tenant|record|field")


@pending(KM, f"{PLAN} section 6")
def test_kms_provider_keeps_old_ciphertext_readable_after_rotation():
    p = _kms_provider()()
    old = p.seal(b"before", b"aad")
    p.rotate()  # new key version becomes current; the old one stays available for decryption
    assert p.open(old, b"aad") == b"before" and p.key_id(p.seal(b"after", b"aad")) != p.key_id(old)


@pending(KM, f"{PLAN} section 6")
def test_kms_signer_is_sign_only_and_the_private_key_is_not_exportable():
    signer = require_symbol("ngrc.audit.signer:KmsSigner")()
    sig = signer.sign(b"message")
    assert signer.verify(sig, b"message") and not hasattr(signer, "_key")
    assert not hasattr(signer, "private_bytes") and not hasattr(signer, "export_private_key")


@pending(KM, f"{PLAN} section 6")
def test_production_settings_start_only_with_kms_backends_and_hold_no_key_material(monkeypatch):
    load = require_symbol("config.settings.prod_check:validate")
    monkeypatch.setenv("NGRC_KEY_PROVIDER", "kms")
    monkeypatch.setenv("NGRC_AUDIT_SIGNER_BACKEND", "kms")
    assert load().ok and "FIELD_ENCRYPTION_KEY" not in load().loaded_secret_names


@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - dev-only local key provider has no key versions/rotation (F-DAT-006, O-4)")
def test_gap_demo_ciphertext_cannot_be_read_after_a_master_key_change():
    """GAP DEMO (runs now): the dev provider has a single master key and ignores the key id stored beside the ciphertext, so rotation
    would orphan existing data. This is why rotation is a plan item and why the local provider is DEV-ONLY."""
    blob = crypto.seal(b"x", b"aad")
    original = settings.FIELD_ENCRYPTION_KEY
    try:
        settings.FIELD_ENCRYPTION_KEY = base64.b64encode(os.urandom(32)).decode()
        try:
            opened = crypto.open_sealed(blob, b"aad")
        except Exception:  # noqa: BLE001 - InvalidTag: the property being demonstrated is "this fails"
            opened = None
    finally:
        settings.FIELD_ENCRYPTION_KEY = original
    assert opened == b"x", "old ciphertext must stay readable after rotation (not provided by the DEV-ONLY local provider)"




@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - DevFileSigner key is a plain file (DEV-ONLY); KMS signer NOT IMPLEMENTED (O-4)")
def test_gap_demo_dev_signing_key_is_readable_by_the_process_that_signs():
    """GAP DEMO (runs now): the dev signer's private key is a file the application process can read, so a host-level attacker (or an
    application RCE) could mint valid checkpoints. A KMS/HSM sign-only key must not be readable by the application at all."""
    get_signer()
    assert not os.access(settings.AUDIT_SIGNER_KEY_PATH, os.R_OK), "signing key must not be readable by the application"




# ================================================================================================ 7. immutable audit storage (F-AUD-006, O-4, BLOCKED)
WM = "F-AUD-006"


def _sink():
    return require_symbol("ngrc.audit.sinks:WormSink")  # object-lock bucket in a separate account (selected with O-4)


@pending(WM, f"{PLAN} section 7")
def test_worm_sink_refuses_overwrite_delete_and_truncate_of_a_published_checkpoint():
    s = _sink()()
    receipt = s.append({"stream_key": "platform", "seq": 1, "head_hash": "00" * 32})
    for attempt in (lambda: s.append({"stream_key": "platform", "seq": 1, "head_hash": "11" * 32}),  # same key, different content
                    lambda: s.delete(receipt), lambda: s.truncate("platform")):
        with pytest.raises(Exception):  # noqa: B017,PT011 - provider-specific refusal
            attempt()
    assert s.read(receipt)["head_hash"] == "00" * 32


@pending(WM, f"{PLAN} section 7")
def test_sink_uses_credentials_the_application_database_and_runtime_roles_do_not_hold():
    s = _sink()()
    assert s.writer_identity != s.reader_identity and s.writer_identity not in {"ngrc_app", "ngrc_ops", "ngrc_owner"}
    assert s.account_id != s.application_account_id  # separate failure domain (D-P0-004 / D-P0-006)


@pending(WM, f"{PLAN} section 7")
def test_sealer_does_not_report_a_checkpoint_published_until_the_sink_acknowledges_it(tenant_a, monkeypatch):
    sinks = require_symbol("ngrc.audit.sinks:get_sink")
    monkeypatch.setattr(sinks(), "append", lambda *a, **k: (_ for _ in ()).throw(OSError("sink unavailable")))
    with tenant_context(tenant_a.id):
        service.emit_tenant("default", "tenant.role.created", tenant_a.id, object_type="role", object_id="r",
                            details={"role_key": "k", "permissions": 1})
    result = sealer.seal_all()
    assert all(not r.get("published") for r in result)  # lag alert, but event capture (the business transaction) is unaffected
    assert audit_events(tenant_id=tenant_a.id, action="tenant.role.created")


@pending(WM, f"{PLAN} section 7")
def test_verifier_compares_database_checkpoints_with_the_sink_copy(tenant_a):
    verify = require_symbol("ngrc.audit.sinks:verify_against_sink")
    assert verify(str(tenant_a.id)).ok


def _two_sealed_checkpoints(tenant, tmp_path):
    settings.AUDIT_CHECKPOINT_EXPORT_DIR = str(tmp_path)
    for i in range(2):
        with tenant_context(tenant.id):
            for n in range(2):
                service.emit_tenant("default", "tenant.role.created", tenant.id, object_type="role", object_id=f"r{i}{n}",
                                    details={"role_key": f"k{i}{n}", "permissions": 1})
        sealer.seal_all()
    return Path(tmp_path) / "checkpoints.jsonl"


@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - verifier ignores database checkpoints that have no exported copy (plan section 7, item W-3)")
def test_gap_demo_dropping_the_latest_exported_checkpoint_goes_unnoticed(tenant_a, tmp_path):
    """GAP DEMO (runs now): with a plain-file export, the newest checkpoint copy can be removed and the verifier - which only checks the
    exported records that REMAIN - still reports the stream healthy. The newest copy is exactly the one that would expose a rewrite of
    recent events. Production needs a write-once sink AND a verifier rule that every database checkpoint has a sink copy."""
    original = settings.AUDIT_CHECKPOINT_EXPORT_DIR
    try:
        path = _two_sealed_checkpoints(tenant_a, tmp_path)
        mine = [ln for ln in path.read_text().splitlines() if json.loads(ln)["stream_key"] == str(tenant_a.id)]
        assert len(mine) == 2  # precondition: the demo really produced two exported checkpoints
        path.write_text("\n".join(ln for ln in path.read_text().splitlines() if ln != mine[-1]) + "\n")
        keys = {get_signer().key_id: get_signer().public_key_raw()}
        res = verifier.verify_stream(str(tenant_a.id), keys, require_export=True)
    finally:
        settings.AUDIT_CHECKPOINT_EXPORT_DIR = original
    assert not res.ok, "a missing sink copy of the newest checkpoint must be reported"




@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - dev sink is a plain local file, not WORM (F-AUD-006, O-4)")
def test_gap_demo_the_dev_export_file_can_be_rewritten_by_the_application_process(tenant_a, tmp_path):
    """GAP DEMO (runs now): the dev sink is an ordinary file opened for append by the same process that writes the database, so it is not
    write-once. It is explicitly labelled `NOT WORM` in every exported record."""
    original = settings.AUDIT_CHECKPOINT_EXPORT_DIR
    try:
        path = _two_sealed_checkpoints(tenant_a, tmp_path)
        try:
            with open(path, "r+b") as fh:
                fh.write(b"#")
            rewritten = True
        except OSError:
            rewritten = False
    finally:
        settings.AUDIT_CHECKPOINT_EXPORT_DIR = original
    assert not rewritten, "a published checkpoint must be impossible to modify (object lock / retention)"




def test_harness_separates_absent_features_from_broken_specs():
    """Self-test of the harness (RUNS and must PASS): an absent module/route is FeatureAbsent; an existing one resolves. Any other error
    inside a spec therefore shows up as a real failure, not as a silent xfail."""
    from .pending import FeatureAbsent

    with pytest.raises(FeatureAbsent):
        require_symbol("ngrc.this_module_does_not_exist:thing")
    with pytest.raises(FeatureAbsent):
        require_symbol("ngrc.audit.sealer:no_such_function")
    with pytest.raises(FeatureAbsent):
        require_route("/definitely/not/a/route/", prefix="")
    assert callable(require_symbol("ngrc.audit.sealer:seal_all"))
    require_route("/healthz", prefix="")  # an existing route does not raise
