"""F-ATH-014 - MFA factor removal (D-P0-008 s7): step-up required, the last usable factor is never removable, two recovery options must remain,
other sessions are revoked, the user is notified, factors of other accounts are invisible - and the DATABASE refuses to delete the last usable
factor even when the application is bypassed (trigger idn_factor_guard), including under concurrent requests."""
import threading
import time

import psycopg
import pytest
from django.core import mail
from django.urls import Resolver404, resolve

from ngrc.core import clock
from ngrc.iam.models import RecoveryCode, TotpFactor, WebAuthnCredential

from .conftest import role_connect
from .helpers import Authenticator, audit_events

pytestmark = pytest.mark.security


def add_webauthn(u):
    u.stepup()
    opts = u.api.post("/auth/mfa/webauthn/register/begin/").json()
    auth = Authenticator()
    r = u.api.post("/auth/mfa/webauthn/register/complete/", {"credential": auth.register(opts), "nickname": "laptop key"})
    assert r.status_code == 200, r.content
    return auth


def factors(u):
    return u.api.get("/auth/mfa/factors/").json()


def factor_id(u, method):
    return next(f["id"] for f in factors(u)["factors"] if f["method"] == method)


# ------------------------------------------------------------------------------------------------ listing and ownership
def test_the_factor_list_shows_only_my_factors_and_the_recovery_code_count(tenant_a, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    add_webauthn(a)
    mine = factors(a)
    assert {f["method"] for f in mine["factors"]} == {"totp", "webauthn"} and mine["recovery_codes_remaining"] == 10
    assert all(set(f) == {"id", "method", "nickname", "created_at", "last_used_at", "usable"} for f in mine["factors"])  # no secret material
    assert {f["id"] for f in mine["factors"]}.isdisjoint({f["id"] for f in factors(b)["factors"]})


def test_someone_elses_totp_factor_is_not_found_and_stays_untouched(tenant_a, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    add_webauthn(a)                                   # a has two factors, so only ownership (not the last-factor rule) can refuse the request
    victim = factor_id(b, "totp")
    a.stepup()
    assert a.api.delete(f"/auth/mfa/factors/{victim}/").status_code == 404
    assert TotpFactor.objects.using("auth").filter(pk=victim, confirmed_at__isnull=False).exists()


def test_a_factor_of_someone_else_is_not_found_and_stays_untouched(tenant_a, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_a, "admin")
    add_webauthn(b)
    victim = factor_id(b, "webauthn")
    a.stepup()
    r = a.api.delete(f"/auth/mfa/factors/{victim}/")
    assert r.status_code == 404 and r.json() == {"error": "not_found"}
    assert audit_events(platform=True, action="authz.denied", reason_code="factor_not_found", actor_id=a.account.id)
    assert any(f["id"] == victim for f in factors(b)["factors"])


# ------------------------------------------------------------------------------------------------ the rules
def test_removal_requires_a_recent_step_up(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    add_webauthn(u)
    wid = factor_id(u, "webauthn")
    u.clock.advance(minutes=11)   # the step-up window lapses
    r = u.api.delete(f"/auth/mfa/factors/{wid}/")
    assert r.status_code in (401, 403) and any(f["id"] == wid for f in factors(u)["factors"])
    assert audit_events(platform=True, action="authz.denied", actor_id=u.account.id)   # session-scope denials land in the platform stream


def test_the_last_usable_factor_cannot_be_removed(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    only = factor_id(u, "totp")
    u.stepup()
    r = u.api.delete(f"/auth/mfa/factors/{only}/")
    assert r.status_code == 409 and r.json() == {"error": "last_factor"}
    assert len(factors(u)["factors"]) == 1


def test_removal_must_leave_two_recovery_options(tenant_a, make_user):
    """After removal: two usable factors, or one factor plus recovery codes (D-P0-008 s7)."""
    u = make_user(tenant_a, "owner")
    add_webauthn(u)
    RecoveryCode.objects.using("auth").filter(account=u.account).update(used_at=clock.now())   # codes used up
    u.stepup()
    r = u.api.delete(f"/auth/mfa/factors/{factor_id(u, 'webauthn')}/")
    assert r.status_code == 409 and r.json() == {"error": "recovery_options"} and len(factors(u)["factors"]) == 2
    RecoveryCode.objects.using("auth").filter(account=u.account).delete()
    from ngrc.authn import recovery
    recovery.generate(u.account)                                                                # fresh codes: one factor + codes is enough
    r = u.api.delete(f"/auth/mfa/factors/{factor_id(u, 'webauthn')}/")
    assert r.status_code == 200 and [f["method"] for f in factors(u)["factors"]] == ["totp"]


def test_a_cloned_credential_is_not_a_usable_factor_and_may_always_be_removed(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    add_webauthn(u)
    wid = factor_id(u, "webauthn")
    WebAuthnCredential.objects.using("auth").filter(pk=wid).update(flagged_clone=True)
    assert next(f for f in factors(u)["factors"] if f["id"] == wid)["usable"] is False
    u.stepup()
    assert u.api.delete(f"/auth/mfa/factors/{factor_id(u, 'totp')}/").status_code == 409   # the TOTP is now the ONLY usable factor
    RecoveryCode.objects.using("auth").filter(account=u.account).update(used_at=clock.now())   # no codes either: the two-options rule would block a USABLE removal
    assert u.api.delete(f"/auth/mfa/factors/{wid}/").status_code == 200                      # removing the unusable one hurts nobody
    assert [f["method"] for f in factors(u)["factors"]] == ["totp"]


def test_removal_revokes_other_sessions_rotates_mine_notifies_and_is_audited(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    add_webauthn(u)
    old = u.api
    u.relogin()
    assert u.api.post("/auth/tenants/select/", {"tenant_id": str(tenant_a.id)}).status_code == 200   # the tenant stream copy needs a selected tenant
    u.api.refresh_csrf()
    u.stepup()
    sid_before = u.api.cookie("__Host-ngrc-sid")
    mail.outbox.clear()
    assert u.api.delete(f"/auth/mfa/factors/{factor_id(u, 'webauthn')}/").status_code == 200
    assert old.get("/tenant/me/").status_code == 401                       # every OTHER session is gone
    assert u.api.get("/auth/session/").json()["stage"] == "active"          # mine survives ...
    assert u.api.cookie("__Host-ngrc-sid") != sid_before                    # ... under a rotated id
    assert any(u.email in m.to and "factor was removed" in m.subject for m in mail.outbox)
    ev = audit_events(platform=True, action="auth.mfa.removed", actor_id=u.account.id)
    assert ev and '"method":"webauthn"' in ev[-1]["details"].replace(" ", "")
    assert audit_events(tenant_id=tenant_a.id, action="auth.mfa.removed", actor_id=u.account.id)


# ------------------------------------------------------------------------------------------------ the database guard
def test_the_database_refuses_to_delete_the_last_usable_factor_even_without_the_application(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    with role_connect("ngrc_auth") as c, pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
        c.execute("DELETE FROM idn_totp_factor WHERE account_id = %s", [str(u.account.id)])
    assert "last usable authentication factor" in exc.value.diag.message_primary
    add_webauthn(u)
    with role_connect("ngrc_auth") as c:                                                       # control: with a second factor it is allowed
        c.execute("DELETE FROM idn_webauthn_credential WHERE account_id = %s", [str(u.account.id)])
        c.commit()
    assert TotpFactor.objects.using("auth").filter(account=u.account, confirmed_at__isnull=False).count() == 1


def test_an_unfinished_enrolment_is_not_a_factor_and_can_be_replaced(tenant_a, make_user):
    u = make_user(tenant_a, "owner")
    u.stepup()
    assert u.api.post("/auth/mfa/totp/enroll/begin/").status_code == 200       # creates an UNCONFIRMED factor
    assert u.api.post("/auth/mfa/totp/enroll/begin/").status_code == 200       # replacing it deletes the unconfirmed row: the guard allows it
    assert TotpFactor.objects.using("auth").filter(account=u.account, confirmed_at__isnull=True).count() == 1


def test_concurrent_removals_cannot_both_succeed(tenant_a, make_user):
    """Two requests, two connections, an account with exactly two factors: the guard serialises on the account row, so one of them must fail."""
    u = make_user(tenant_a, "owner")
    add_webauthn(u)
    acct, results, first_deleted = str(u.account.id), {}, threading.Event()

    def delete_totp():
        with role_connect("ngrc_auth") as c:
            c.execute("DELETE FROM idn_totp_factor WHERE account_id = %s", [acct])
            first_deleted.set()
            time.sleep(1.0)            # keep the transaction open: the other deletion has to wait for the account row lock
            c.commit()
            results["totp"] = "deleted"

    def delete_webauthn():
        first_deleted.wait(10)
        with role_connect("ngrc_auth") as c:
            try:
                c.execute("DELETE FROM idn_webauthn_credential WHERE account_id = %s", [acct])
                c.commit()
                results["webauthn"] = "deleted"
            except psycopg.errors.InsufficientPrivilege:
                results["webauthn"] = "refused"

    ts = [threading.Thread(target=delete_totp), threading.Thread(target=delete_webauthn)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert results == {"totp": "deleted", "webauthn": "refused"}, results
    assert WebAuthnCredential.objects.using("auth").filter(account=u.account).count() == 1


def test_the_owner_role_is_the_only_exception_and_is_used_by_the_recovery_function(tenant_a, make_user):
    """Documented trust boundary: the schema owner (migrations, SECURITY DEFINER recovery completion) bypasses the guard."""
    u = make_user(tenant_a, "owner")
    with role_connect("ngrc_owner") as c:
        c.execute("DELETE FROM idn_totp_factor WHERE account_id = %s", [str(u.account.id)])
        c.rollback()   # probe only: the point is that it is not refused


# ------------------------------------------------------------------------------------------------ operators
def test_operators_have_no_self_service_removal_and_the_database_protects_their_last_credential(login_operator):
    for path in ("/ops/api/v1/auth/mfa/factors/", "/ops/api/v1/auth/mfa/factors/00000000-0000-0000-0000-000000000000/"):
        with pytest.raises(Resolver404):
            resolve(path)
    op = login_operator("platform_security")
    with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
        c.execute("DELETE FROM plt_operator_webauthn_credential WHERE account_id = %s", [str(op.account.id)])
    assert "last usable operator credential" in exc.value.diag.message_primary
