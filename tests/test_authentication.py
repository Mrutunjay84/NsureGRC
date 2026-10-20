"""D-P0-008 testing requirements: authentication, MFA, sessions, password reset, CSRF. All through the real HTTP stack."""
import json
import threading
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from django.conf import settings
from django.core import mail

from ngrc.authn import passwords
from ngrc.iam import services
from ngrc.iam.models import Account, Session, WebAuthnCredential

from .conftest import TEST_PASSWORD, add_member, make_account
from .helpers import (
    Api,
    Authenticator,
    Totp,
    audit_events,
    enroll_totp_and_login,
    last_mail_token,
    login_with_totp,
)

pytestmark = pytest.mark.security
SID = settings.CUSTOMER_COOKIE_NAME


def _login(email, password, api=None):
    api = api or Api()
    return api, api.post("/auth/login/", {"email": email, "password": password})


# ------------------------------------------------------------------------------------------------ enumeration / throttling
def test_login_errors_do_not_reveal_whether_account_exists(account):
    _, wrong_pw = _login(account.email, "definitely-the-wrong-password")
    _, unknown = _login("nobody-here@example.test", "definitely-the-wrong-password")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json() == {"error": "invalid_credentials"}


def test_login_unknown_and_wrong_password_run_the_same_hashing_work(account, monkeypatch):
    """Dummy-hash timing parity (ADR s3): an unknown account still performs a full Argon2 verification."""
    calls = []
    real = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password", lambda h, p: calls.append("verify") or real(h, p))
    burn = []
    real_burn = passwords.burn_verification
    monkeypatch.setattr(passwords, "burn_verification", lambda: burn.append(1) or real_burn())
    _login(account.email, "wrong-password-xyz")
    _login("ghost@example.test", "wrong-password-xyz")
    assert calls.count("verify") >= 2 and len(burn) == 1  # known: verify; unknown: burn (which itself verifies)


def test_password_reset_request_is_uniform(account):
    api = Api()
    known = api.post("/auth/password/reset/request/", {"email": account.email})
    unknown = api.post("/auth/password/reset/request/", {"email": "ghost@example.test"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert len(mail.outbox) >= 1 and all("ghost@example.test" not in m.to for m in mail.outbox)


def test_progressive_throttling_applies_before_password_check(account):
    api = Api()
    codes = [api.post("/auth/login/", {"email": account.email, "password": "wrong-password-xyz"}).status_code for _ in range(5)]
    assert codes == [401] * 5
    locked = api.post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD})  # CORRECT password, still locked out
    assert locked.status_code == 429 and int(locked["Retry-After"]) > 0
    assert audit_events(platform=True, action="auth.throttle.triggered")


def test_ip_throttling_blocks_distributed_account_guessing():
    api = Api()
    seen = [api.post("/auth/login/", {"email": f"victim{i}@example.test", "password": "wrong-password-xyz"}).status_code
            for i in range(settings.AUTH_THROTTLE["ip_max_attempts"] + 2)]
    assert seen[-1] == 429


def test_login_failure_audit_has_no_password_or_raw_email(account):
    _login(account.email, "hunter2-secret-attempt")
    for e in audit_events(platform=True, action="auth.login.failure"):
        assert "hunter2" not in e["details"] and account.email not in e["details"]


# ------------------------------------------------------------------------------------------------ cookies & headers
def test_session_cookie_attributes(account):
    api, r = _login(account.email, TEST_PASSWORD)
    morsel = api.c.cookies[SID]
    assert SID.startswith("__Host-")
    assert morsel["secure"] and morsel["httponly"] and morsel["samesite"] == "Lax" and morsel["path"] == "/"
    assert not morsel["domain"]
    assert len(morsel.value) >= 40  # 256-bit opaque id


def test_csrf_cookie_attributes():
    api = Api()
    api.post("/auth/login/", {"email": "x@example.test", "password": "y"})
    m = api.c.cookies[settings.CSRF_COOKIE_NAME]
    assert settings.CSRF_COOKIE_NAME.startswith("__Host-") and m["secure"] and m["httponly"] and m["samesite"] == "Lax"


def test_only_a_hash_of_the_session_id_is_stored(account):
    api, _ = _login(account.email, TEST_PASSWORD)
    raw = api.cookie(SID)
    s = Session.objects.using("auth").get(account=account)
    assert s.token_hash != raw and len(s.token_hash) == 64 and raw not in str(s.__dict__.values())


# ------------------------------------------------------------------------------------------------ MFA cannot be bypassed
def test_password_only_session_cannot_reach_anything_protected(tenant_a, make_member):
    acct = make_account()
    make_member(tenant_a, acct, "owner")
    api, r = _login(acct.email, TEST_PASSWORD)
    assert r.json()["stage"] == "enroll_mfa"
    for path in ("/auth/tenants/", "/auth/session/x", "/tenant/me/", "/tenant/roles/", "/tenant/members/", "/tenant/audit/events/"):
        resp = api.get(path)
        assert resp.status_code in (403, 404), (path, resp.status_code)
    assert api.post("/auth/tenants/select/", {"tenant_id": str(tenant_a.id)}).status_code == 403


def test_pending_mfa_session_with_enrolled_factor_cannot_reach_protected_routes(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    api = Api()
    r = api.post("/auth/login/", {"email": u.email, "password": u.password})
    assert r.json()["stage"] == "password_ok"
    assert api.get("/tenant/me/").status_code == 403
    assert api.post("/auth/mfa/totp/enroll/begin/").status_code == 403  # cannot add a factor while only password-authenticated
    assert api.post("/auth/stepup/", {"method": "totp", "code": "123456"}).status_code == 403
    assert api.post("/auth/tenants/select/", {"tenant_id": str(tenant_a.id)}).status_code == 403


def test_mfa_endpoints_require_a_password_session():
    api = Api()
    assert api.post("/auth/mfa/totp/verify/", {"code": "123456"}).status_code == 401
    assert api.post("/auth/mfa/recovery/verify/", {"code": "AAAA-AAAA-AAAA-AAAA"}).status_code == 401


def test_wrong_totp_never_promotes_the_session(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    api = Api()
    api.post("/auth/login/", {"email": u.email, "password": u.password})
    for _ in range(3):
        assert api.post("/auth/mfa/totp/verify/", {"code": "000000"}).status_code == 401
    assert api.get("/tenant/me/").status_code == 403
    assert audit_events(platform=True, action="auth.mfa.failed", actor_id=u.account.id)


def test_totp_code_format_is_enforced(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    api = Api()
    api.post("/auth/login/", {"email": u.email, "password": u.password})
    for bad in ("", "12345", "1234567", "abcdef", "12 345", "１２３４５６", "' OR '1'='1"):
        assert api.post("/auth/mfa/totp/verify/", {"code": bad}).status_code in (400, 401, 429)  # never 200, never 500


def test_forged_or_foreign_session_cookies_are_rejected(account, login_operator):
    api = Api()
    api.set_cookie(SID, "A" * 43)
    assert api.get("/auth/session/").status_code == 401
    op = login_operator("platform_admin")
    stolen = op.api.cookie(settings.OPERATOR_COOKIE_NAME)
    other = Api()
    other.set_cookie(SID, stolen)  # operator session id presented on the customer surface
    assert other.get("/auth/session/").status_code == 401
    cust_api, _ = _login(account.email, TEST_PASSWORD)
    ops_side = Api(prefix="/ops/api/v1")
    ops_side.set_cookie(settings.OPERATOR_COOKIE_NAME, cust_api.cookie(SID))  # customer id on the platform surface
    assert ops_side.get("/auth/session/").status_code == 401


def test_platform_credentials_are_rejected_on_the_customer_surface(make_operator):
    op = make_operator("platform_admin")
    _, r = _login(op.email, TEST_PASSWORD)
    assert r.status_code == 401
    ops_api = Api(prefix="/ops/api/v1")
    assert ops_api.post("/auth/login/", {"email": make_account().email, "password": TEST_PASSWORD}).status_code == 401


# ------------------------------------------------------------------------------------------------ TOTP / recovery codes
def test_totp_replay_and_window(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    api = Api()
    api.post("/auth/login/", {"email": u.email, "password": u.password})
    ts = clock_ctl.ts()
    far = u.totp.t.at(ts + 60)  # two steps ahead: outside the +/-1 window
    assert api.post("/auth/mfa/totp/verify/", {"code": far}).status_code == 401
    good = u.totp.code(ts)  # next step: accepted
    assert api.post("/auth/mfa/totp/verify/", {"code": good}).status_code == 200
    # the very same code on a brand-new password session is a replay
    api2 = Api()
    api2.post("/auth/login/", {"email": u.email, "password": u.password})
    assert api2.post("/auth/mfa/totp/verify/", {"code": good}).status_code == 401
    assert audit_events(platform=True, action="auth.totp.replay_rejected", actor_id=u.account.id)


def test_totp_clock_drift_one_step_back_is_accepted(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    api = Api()
    api.post("/auth/login/", {"email": u.email, "password": u.password})
    clock_ctl.advance(seconds=60)
    ts = clock_ctl.ts()
    code = u.totp.t.at(((ts // 30) - 1) * 30)  # one step in the past, but newer than the last accepted step
    assert api.post("/auth/mfa/totp/verify/", {"code": code}).status_code == 200


def test_totp_secret_is_stored_encrypted(tenant_a, make_user):
    from ngrc.iam.models import TotpFactor

    u = make_user(tenant_a, "owner")
    f = TotpFactor.objects.using("auth").get(account=u.account)
    assert u.totp.t.secret.encode() not in bytes(f.secret_sealed)


def test_recovery_code_is_single_use(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    assert len(u.recovery_codes) == 10
    code = u.recovery_codes[0]
    api = Api()
    api.post("/auth/login/", {"email": u.email, "password": u.password})
    r = api.post("/auth/mfa/recovery/verify/", {"code": code})
    assert r.status_code == 200 and r.json()["recovery_codes_remaining"] == 9
    assert any("recovery code was used" in m.subject for m in mail.outbox)
    api2 = Api()
    api2.post("/auth/login/", {"email": u.email, "password": u.password})
    assert api2.post("/auth/mfa/recovery/verify/", {"code": code}).status_code == 401
    assert audit_events(platform=True, action="auth.recovery_codes.used", actor_id=u.account.id)


def test_recovery_codes_are_stored_hashed(tenant_a, make_user):
    from ngrc.iam.models import RecoveryCode

    u = make_user(tenant_a, "owner")
    stored = {r.digest for r in RecoveryCode.objects.using("auth").filter(account=u.account)}
    assert len(stored) == 10 and not stored & {c.replace("-", "") for c in u.recovery_codes} and not stored & set(u.recovery_codes)


def test_recovery_codes_not_accepted_for_operators(login_operator):
    op = login_operator("platform_admin")
    assert op.api.post("/auth/mfa/recovery/verify/", {"code": "AAAA-AAAA-AAAA-AAAA"}).status_code in (404, 405)


# ------------------------------------------------------------------------------------------------ sessions
def test_session_id_rotates_on_mfa_and_on_tenant_selection(tenant_a):
    acct = make_account()
    add_member(tenant_a, acct, "owner")
    api = Api()
    api.post("/auth/login/", {"email": acct.email, "password": TEST_PASSWORD})
    pre = api.cookie(SID)
    b = api.post("/auth/mfa/totp/enroll/begin/")
    from .helpers import Totp  # noqa: PLC0415

    totp = Totp(b.json()["secret"])
    import time

    api.post("/auth/mfa/totp/enroll/confirm/", {"code": totp.code(int(time.time()))})
    post_mfa = api.cookie(SID)
    assert post_mfa != pre
    api.refresh_csrf()
    api.post("/auth/tenants/select/", {"tenant_id": str(tenant_a.id)})
    post_tenant = api.cookie(SID)
    assert post_tenant not in (pre, post_mfa)
    for dead in (pre, post_mfa):  # fixation: previous identifiers are useless
        stale = Api()
        stale.set_cookie(SID, dead)
        assert stale.get("/auth/session/").status_code == 401


def test_logout_revokes_server_side(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    cookie = u.api.cookie(SID)
    assert u.api.post("/auth/logout/").status_code == 200
    replay = Api()
    replay.set_cookie(SID, cookie)
    assert replay.get("/tenant/me/").status_code == 401
    assert audit_events(platform=True, action="auth.logout", actor_id=u.account.id)


def test_idle_timeout(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    assert u.api.get("/tenant/me/").status_code == 200
    clock_ctl.advance(minutes=16)  # privileged idle limit is 15 min
    assert u.api.get("/tenant/me/").status_code == 401


def test_absolute_timeout_even_with_continuous_activity(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    for _ in range(46):  # 7h40 of activity every 10 minutes (privileged absolute limit is 8 h)
        clock_ctl.advance(minutes=10)
        assert u.api.get("/tenant/me/").status_code == 200
    clock_ctl.advance(minutes=30)
    assert u.api.get("/tenant/me/").status_code == 401


def test_password_session_expires_quickly(account, clock_ctl):
    api, _ = _login(account.email, TEST_PASSWORD)
    clock_ctl.advance(minutes=11)
    assert api.get("/auth/session/").status_code == 401


def test_password_change_revokes_other_sessions_and_notifies(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    second = login_with_totp(u.email, u.password, u.totp, u.clock.ts())
    assert second.get("/tenant/me/").status_code in (200, 403)  # second session is live (no tenant selected => 403)
    new_pw = "An0ther-Long-Passphrase-77!"
    r = u.api.post("/auth/password/change/", {"current_password": u.password, "new_password": new_pw})
    assert r.status_code == 200, r.content
    assert second.get("/auth/session/").status_code == 401
    assert u.api.get("/tenant/me/").status_code == 200
    assert any("password was changed" in m.subject for m in mail.outbox)
    assert audit_events(platform=True, action="auth.password.changed", actor_id=u.account.id)


def test_password_change_requires_current_password_and_step_up(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    assert u.api.post("/auth/password/change/", {"current_password": "wrong-one-xxxxxx", "new_password": "An0ther-Long-Passphrase-77!"}
                      ).status_code == 401
    clock_ctl.advance(minutes=11)
    r = u.api.post("/auth/password/change/", {"current_password": u.password, "new_password": "An0ther-Long-Passphrase-77!"})
    assert r.status_code == 403  # step-up window (10 min) elapsed


def test_membership_suspension_ends_that_users_sessions_immediately(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    member = make_user(tenant_a, "member")
    assert member.api.get("/tenant/me/").status_code == 200
    mid = [m for m in owner.api.get("/tenant/members/").json()["members"] if m["principal_id"] == str(member.account.id)][0]["id"]
    owner.stepup()
    assert owner.api.patch(f"/tenant/members/{mid}/", {"status": "suspended"}).status_code == 200
    assert member.api.get("/tenant/me/").status_code == 401  # session revoked, not merely denied


# ------------------------------------------------------------------------------------------------ password reset
def test_password_reset_is_single_use_expires_and_revokes_sessions(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    Api().post("/auth/password/reset/request/", {"email": u.email})
    token = last_mail_token(mail.outbox, u.email)
    new_pw = "Brand-New-Passphrase-4242!"
    api = Api()
    assert api.post("/auth/password/reset/confirm/", {"token": token, "new_password": new_pw}).status_code == 200
    assert u.api.get("/auth/session/").status_code == 401  # existing sessions revoked
    assert api.post("/auth/password/reset/confirm/", {"token": token, "new_password": new_pw + "x"}).status_code == 400  # replay
    r = Api().post("/auth/login/", {"email": u.email, "password": new_pw})
    assert r.status_code == 200 and r.json()["stage"] == "password_ok"  # MFA is STILL required after a reset
    assert Api().post("/auth/login/", {"email": u.email, "password": u.password}).status_code == 401


def test_password_reset_token_expires(account, clock_ctl):
    Api().post("/auth/password/reset/request/", {"email": account.email})
    token = last_mail_token(mail.outbox, account.email)
    clock_ctl.advance(minutes=31)
    r = Api().post("/auth/password/reset/confirm/", {"token": token, "new_password": "Brand-New-Passphrase-4242!"})
    assert r.status_code == 400


def test_weak_password_does_not_burn_the_reset_token(account):
    Api().post("/auth/password/reset/request/", {"email": account.email})
    token = last_mail_token(mail.outbox, account.email)
    assert Api().post("/auth/password/reset/confirm/", {"token": token, "new_password": "short"}).status_code == 400
    assert Api().post("/auth/password/reset/confirm/", {"token": token, "new_password": "Brand-New-Passphrase-4242!"}).status_code == 200


def test_reset_token_is_stored_hashed(account):
    from ngrc.iam.models import AuthToken

    Api().post("/auth/password/reset/request/", {"email": account.email})
    token = last_mail_token(mail.outbox, account.email)
    assert not AuthToken.objects.using("auth").filter(token_hash=token).exists()
    assert AuthToken.objects.using("auth").filter(account=account, purpose="password_reset").exists()


def test_reset_link_ignores_host_header_injection(account):
    Api().c.post("/api/v1/auth/password/reset/request/", data=json.dumps({"email": account.email}), content_type="application/json",
                 secure=True, HTTP_HOST="localhost", HTTP_X_FORWARDED_HOST="evil.example", HTTP_ORIGIN="https://testserver",
                 HTTP_X_CSRFTOKEN="x")
    api = Api()
    api.post("/auth/password/reset/request/", {"email": account.email})
    body = [m for m in mail.outbox if account.email in m.to][-1].body
    assert body.count(settings.PUBLIC_BASE_URL) >= 1 and "evil.example" not in body
    assert "#token=" in body and "?token=" not in body  # token in the fragment: never in Referer/server logs


def test_concurrent_token_consumption_has_exactly_one_winner(account):
    from django.db import connections

    raw = services.issue_token(account, "password_reset", 600)
    wins = []

    def attempt():
        try:
            if services.consume_token(raw, "password_reset") is not None:
                wins.append(1)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(wins) == 1


def test_verify_email_token_single_use():
    acct = make_account(verified=False)
    services.send_verification_email(acct)
    token = last_mail_token(mail.outbox, acct.email)
    api = Api()
    assert api.post("/auth/email/verify/", {"token": token}).status_code == 200
    assert api.post("/auth/email/verify/", {"token": token}).status_code == 400
    assert Account.objects.using("auth").get(pk=acct.pk).status == "active"


# ------------------------------------------------------------------------------------------------ password policy / hashing
def _blocklisted():
    words = [w.strip() for w in Path(settings.PASSWORD_POLICY["blocklist_path"]).read_text(encoding="utf-8").splitlines()]
    return next(w for w in words if len(w) >= 12)


def test_password_policy():
    with pytest.raises(passwords.PolicyViolation) as e:
        passwords.check_policy("short")
    assert e.value.code == "too_short"
    with pytest.raises(passwords.PolicyViolation) as e:
        passwords.check_policy(_blocklisted())
    assert e.value.code == "blocklisted"
    with pytest.raises(passwords.PolicyViolation) as e:
        passwords.check_policy("x" * 129)
    assert e.value.code == "too_long"
    assert passwords.check_policy("p" * 100 + "Q9!")  # long passphrases accepted; no composition rules
    assert passwords.check_policy("alllowercasebutlongenough")
    with pytest.raises(passwords.PolicyViolation):
        passwords.check_policy("someone@example.test", context_terms=("someone@example.test",))
    assert passwords.normalize("é") == "é"  # NFC


def test_argon2id_is_used_with_floor_parameters():
    h = passwords.hash_password(TEST_PASSWORD)
    assert h.startswith("$argon2id$")
    p = settings.PASSWORD_HASHING
    from config.settings.validators import argon2_meets_floor

    assert argon2_meets_floor(p["memory_cost_kib"], p["time_cost"], p["parallelism"])
    assert not argon2_meets_floor(1024, 1, 1) and not argon2_meets_floor(65536, 0, 1)


def test_weak_hash_is_upgraded_on_login(account):
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(TEST_PASSWORD)
    Account.objects.using("auth").filter(pk=account.pk).update(password_hash=weak)
    _, r = _login(account.email, TEST_PASSWORD)
    assert r.status_code == 200
    new = Account.objects.using("auth").get(pk=account.pk).password_hash
    assert new != weak and not passwords.needs_rehash(new)


def test_password_hash_never_leaves_the_server(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    blobs = [u.api.get(p).content.decode() for p in ("/auth/session/", "/tenant/me/", "/tenant/members/", "/auth/tenants/")]
    assert all("argon2" not in b and "password_hash" not in b for b in blobs)


# ------------------------------------------------------------------------------------------------ WebAuthn (customer)
def _wa_register(api, auth):
    opts = api.post("/auth/mfa/webauthn/register/begin/").json()
    return api.post("/auth/mfa/webauthn/register/complete/", {"credential": auth.register(opts)})


def test_customer_webauthn_registration_and_login(account):
    api, r = _login(account.email, TEST_PASSWORD)
    auth = Authenticator()
    assert _wa_register(api, auth).status_code == 200
    api2, r = _login(account.email, TEST_PASSWORD)
    assert r.json()["stage"] == "password_ok"
    opts = api2.post("/auth/mfa/webauthn/authenticate/begin/").json()
    assert api2.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts)}).status_code == 200
    assert audit_events(platform=True, action="auth.mfa.verified", actor_id=account.id)


@pytest.mark.parametrize("attack", ["wrong_origin", "wrong_rp_id", "replayed_challenge", "foreign_credential", "bad_challenge"])
def test_customer_webauthn_assertion_attacks(account, attack):
    api, _ = _login(account.email, TEST_PASSWORD)
    auth = Authenticator()
    _wa_register(api, auth)
    api2, _ = _login(account.email, TEST_PASSWORD)
    opts = api2.post("/auth/mfa/webauthn/authenticate/begin/").json()
    if attack == "wrong_origin":
        cred = auth.assert_(opts, origin="https://evil.example")
    elif attack == "wrong_rp_id":
        cred = auth.assert_(opts, rp_id="evil.example")
    elif attack == "bad_challenge":
        cred = auth.assert_(opts, challenge="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    elif attack == "foreign_credential":
        cred = Authenticator().assert_(opts)
    else:  # replay: a valid assertion is submitted twice; the challenge is single-use
        cred = auth.assert_(opts)
        assert api2.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": cred}).status_code == 200
        api3, _ = _login(account.email, TEST_PASSWORD)
        api3.post("/auth/mfa/webauthn/authenticate/begin/")
        assert api3.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": cred}).status_code == 401
        return
    assert api2.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": cred}).status_code == 401
    assert api2.get("/auth/tenants/").status_code == 403  # still not authenticated


def test_customer_webauthn_challenge_is_consumed_by_a_failed_attempt(account):
    api, _ = _login(account.email, TEST_PASSWORD)
    auth = Authenticator()
    _wa_register(api, auth)
    api2, _ = _login(account.email, TEST_PASSWORD)
    opts = api2.post("/auth/mfa/webauthn/authenticate/begin/").json()
    assert api2.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts, origin="https://evil.example")}
                     ).status_code == 401
    assert api2.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts)}).status_code == 401  # no retry


def test_webauthn_counter_regression_flags_the_credential(account):
    api, _ = _login(account.email, TEST_PASSWORD)
    auth = Authenticator()
    _wa_register(api, auth)
    for i, ok in ((5, True), (3, False)):
        a, _ = _login(account.email, TEST_PASSWORD)
        opts = a.post("/auth/mfa/webauthn/authenticate/begin/").json()
        r = a.post("/auth/mfa/webauthn/authenticate/complete/", {"credential": auth.assert_(opts, counter=i)})
        assert (r.status_code == 200) is ok
    assert WebAuthnCredential.objects.using("auth").get(account=account).flagged_clone
    assert audit_events(platform=True, action="auth.webauthn.counter_regression", actor_id=account.id)
    a, _ = _login(account.email, TEST_PASSWORD)
    assert a.post("/auth/mfa/webauthn/authenticate/begin/").status_code == 400  # cloned credential no longer offered


def test_privileged_roles_require_user_verification(tenant_a):
    acct = make_account()
    add_member(tenant_a, acct, "owner")
    api, _ = _login(acct.email, TEST_PASSWORD)
    opts = api.post("/auth/mfa/webauthn/register/begin/").json()
    assert opts["authenticatorSelection"]["userVerification"] == "required"
    assert api.post("/auth/mfa/webauthn/register/complete/", {"credential": Authenticator(uv=False).register(opts)}).status_code == 400
    opts = api.post("/auth/mfa/webauthn/register/begin/").json()
    assert api.post("/auth/mfa/webauthn/register/complete/", {"credential": Authenticator(uv=True).register(opts)}).status_code == 200


# ------------------------------------------------------------------------------------------------ CSRF
def test_csrf_is_enforced_on_unsafe_methods_including_login(account):
    no_token = Api(csrf=False)
    assert no_token.post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD}).status_code == 403
    bad_token = Api(csrf=False)
    r = bad_token.c.post("/api/v1/auth/login/", data="{}", content_type="application/json", secure=True,
                         HTTP_ORIGIN="https://testserver", HTTP_X_CSRFTOKEN="not-a-valid-token")
    assert r.status_code == 403


def test_csrf_rejects_foreign_origin_even_with_a_valid_token(account):
    api = Api()
    api._csrf()  # obtain a legitimate token + cookie
    r = api.c.post("/api/v1/auth/login/", data="{}", content_type="application/json", secure=True,
                   HTTP_ORIGIN="https://evil.example", HTTP_X_CSRFTOKEN=api.token)
    assert r.status_code == 403


def test_csrf_enforced_on_every_authenticated_unsafe_route(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    nt = Api(csrf=False)
    nt.c.cookies = u.api.c.cookies  # same authenticated session, but no CSRF header
    nt.set_cookie(SID, u.api.cookie(SID))
    for method, path in (("post", "/auth/logout/"), ("post", "/auth/tenants/select/"), ("post", "/tenant/roles/"),
                         ("post", "/auth/password/change/"), ("post", "/tenant/invitations/"), ("post", "/auth/stepup/")):
        r = getattr(nt, method)(path, {})
        assert r.status_code == 403, (path, r.status_code)
    assert u.api.get("/tenant/me/").status_code == 200  # session untouched by the blocked attempts
    assert audit_events(platform=True, action="authz.denied", reason_code="csrf_failed", actor_id=u.account.id)


def test_safe_methods_do_not_require_csrf(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    assert Api(csrf=False).c.get("/api/v1/auth/csrf/", secure=True).status_code == 200
    assert u.api.get("/tenant/me/").status_code == 200


# silence unused import warnings for helpers kept for readability
_ = (Totp, enroll_totp_and_login)
