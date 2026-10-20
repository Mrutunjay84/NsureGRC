"""DEF-15 / D-P1-001 - TEMPORARY authentication baseline while lost-factor recovery (F-ATH-015) does not exist.

The Phase 1 hard stop (account -> `recovery_required` after repeated failures) is gone: nobody could ever leave that state, so a stranger who knew an
address could lock the real user out for good. What replaces it, and what these tests pin: failed-login counting, progressive delays (checked
BEFORE password hashing, so a correct password during the delay is still refused), per-IP rate limiting, audit events, suspicious-pattern
detection with alerts, and stricter parameters for operator accounts. Residual risk, stated in the ADR: an attacker can still keep a victim waiting
up to the delay cap; that is the price of not having a permanent lock-out.
"""
import pytest
from django.conf import settings

from ngrc.audit import alerts
from ngrc.authn import flow
from ngrc.authn.realms import CUSTOMER
from ngrc.control_plane.models import OperatorAccount
from ngrc.iam.models import Account

from .conftest import TEST_PASSWORD
from .helpers import Api, audit_events

pytestmark = pytest.mark.security
CFG = settings.AUTH_THROTTLE
WRONG = "wrong-password-xyz"


@pytest.fixture(autouse=True)
def _fresh_alerts():
    alerts.recorder.reset()


def _fail(api, email):
    return api.post("/auth/login/", {"email": email, "password": WRONG})


def test_no_number_of_failures_ever_locks_the_account(account, clock_ctl):
    api = Api(ip="203.0.113.7")
    for _ in range(30):
        clock_ctl.advance(seconds=CFG["account_max_delay_s"] + 1)
        assert _fail(api, account.email).status_code == 401
    assert Account.objects.using("auth").get(pk=account.pk).status == "active"
    clock_ctl.advance(seconds=CFG["account_max_delay_s"] + 1)
    assert Api().post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD}).status_code == 200
    assert not audit_events(platform=True, action="auth.account.locked", actor_id=account.id)


def test_delays_grow_progressively_to_the_cap_and_are_enforced_before_the_password_check(account, clock_ctl):
    api = Api(ip="203.0.113.8")
    waits = []
    for _ in range(CFG["account_free_failures"] - 1):
        assert _fail(api, account.email).status_code == 401  # free failures: no delay yet
    for _ in range(8):
        assert _fail(api, account.email).status_code == 401
        blocked = api.post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD})  # CORRECT password, still refused
        assert blocked.status_code == 429
        waits.append(int(blocked["Retry-After"]))
        clock_ctl.advance(seconds=waits[-1] + 1)
    assert waits[0] >= CFG["account_base_delay_s"]
    assert all(b >= a for a, b in zip(waits, waits[1:], strict=False)), waits
    assert waits[1] >= 2 * CFG["account_base_delay_s"] - 3 and max(waits) <= CFG["account_max_delay_s"] + 1 and waits[-1] >= CFG["account_max_delay_s"]
    assert audit_events(platform=True, action="auth.throttle.triggered")


def test_success_after_a_burst_of_failures_is_audited_and_alerted(account, clock_ctl):
    api = Api(ip="203.0.113.9")
    for _ in range(CFG["account_free_failures"]):
        clock_ctl.advance(seconds=CFG["account_max_delay_s"] + 1)
        _fail(api, account.email)
    clock_ctl.advance(seconds=CFG["account_max_delay_s"] + 1)
    assert Api().post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD}).status_code == 200
    ev = audit_events(platform=True, action="auth.login.suspicious", actor_id=account.id)
    assert [e for e in ev if e["reason_code"] == "success_after_failures"]
    assert any(a.kind == "suspicious_login" and a.details["reason"] == "success_after_failures" for a in alerts.recorder.sent)
    # a clean login afterwards is not suspicious
    before = len(audit_events(platform=True, action="auth.login.suspicious", actor_id=account.id))
    Api().post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD})
    assert len(audit_events(platform=True, action="auth.login.suspicious", actor_id=account.id)) == before


def test_attempts_from_several_sources_against_one_account_raise_one_alert(account):
    n = CFG["suspicious_distinct_sources"]
    for i in range(n + 2):
        _fail(Api(ip=f"198.51.100.{i + 1}"), account.email)
    ev = [e for e in audit_events(platform=True, action="auth.login.suspicious", actor_id=account.id) if e["reason_code"] == "distributed_sources"]
    assert len(ev) == 1  # raised when the threshold is first crossed, not on every further source
    assert any(a.kind == "suspicious_login" and a.details["reason"] == "distributed_sources" and a.severity == "warning" for a in alerts.recorder.sent)
    assert account.email not in str(ev) and WRONG not in str(ev)


def test_second_factor_failures_back_off_but_never_lock_the_account(tenant_a, make_user, clock_ctl):
    u = make_user(tenant_a, "owner")
    api = Api(ip="203.0.113.10")
    assert api.post("/auth/login/", {"email": u.email, "password": u.password}).json()["stage"] == "password_ok"
    free = CFG["account_free_failures"]
    assert [api.post("/auth/mfa/totp/verify/", {"code": "000000"}).status_code for _ in range(free)] == [401] * free
    blocked = api.post("/auth/mfa/totp/verify/", {"code": u.totp.code(clock_ctl.ts())})  # a CORRECT code during the delay is refused
    assert blocked.status_code == 429 and int(blocked["Retry-After"]) > 0
    clock_ctl.advance(seconds=int(blocked["Retry-After"]) + 1)
    assert api.post("/auth/mfa/totp/verify/", {"code": u.totp.code(clock_ctl.ts())}).status_code == 200
    for _ in range(40):  # however many second-factor failures accumulate, the account stays usable
        flow.mfa_failed(CUSTOMER, u.account, "203.0.113.11", "totp")
    assert Account.objects.using("auth").get(pk=u.account.pk).status == "active"
    assert not audit_events(platform=True, action="auth.mfa.locked", actor_id=u.account.id)


def test_operator_accounts_are_throttled_harder_and_alert_at_critical_severity(make_operator, clock_ctl):
    op = make_operator("platform_security")
    api = Api(prefix="/ops/api/v1", ip="203.0.113.20")
    free = CFG["operator_account_free_failures"]
    assert free < CFG["account_free_failures"]
    for _ in range(free):
        assert api.post("/auth/login/", {"email": op.email, "password": WRONG}).status_code == 401
    blocked = api.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD})
    assert blocked.status_code == 429 and int(blocked["Retry-After"]) >= CFG["operator_account_base_delay_s"] > CFG["account_base_delay_s"]
    assert CFG["operator_account_max_delay_s"] > CFG["account_max_delay_s"]
    # a second source address already counts as suspicious for a privileged account
    clock_ctl.advance(seconds=CFG["operator_account_max_delay_s"] + 1)
    Api(prefix="/ops/api/v1", ip="203.0.113.21").post("/auth/login/", {"email": op.email, "password": WRONG})
    ev = audit_events(platform=True, action="platform.operator.login.suspicious", actor_id=op.id)
    assert [e for e in ev if e["reason_code"] == "distributed_sources"]
    assert any(a.severity == "critical" and a.details["realm"] == "operator" for a in alerts.recorder.sent)


def test_operator_accounts_are_never_moved_to_a_lock_state_by_failures(make_operator, clock_ctl):
    op = make_operator("platform_admin")
    api = Api(prefix="/ops/api/v1", ip="203.0.113.22")
    for _ in range(15):
        clock_ctl.advance(seconds=CFG["operator_account_max_delay_s"] + 1)
        assert api.post("/auth/login/", {"email": op.email, "password": WRONG}).status_code == 401
    assert OperatorAccount.objects.using("ops").get(pk=op.id).status == "active"
    clock_ctl.advance(seconds=CFG["operator_account_max_delay_s"] + 1)
    assert api.post("/auth/login/", {"email": op.email, "password": TEST_PASSWORD}).status_code == 200


def test_the_temporary_policy_is_visible_in_configuration_and_has_no_hard_stop():
    assert not [k for k in CFG if "recovery_required" in k], "the hard-stop thresholds must stay removed until F-ATH-015 exists"
    for k in ("account_free_failures", "account_base_delay_s", "account_max_delay_s", "suspicious_distinct_sources", "suspicious_window_s"):
        assert f"operator_{k}" in CFG, k
    assert CFG["operator_account_free_failures"] <= CFG["account_free_failures"]
    assert CFG["operator_account_base_delay_s"] >= CFG["account_base_delay_s"]
    assert CFG["operator_account_max_delay_s"] >= CFG["account_max_delay_s"]
    assert CFG["operator_suspicious_distinct_sources"] <= CFG["suspicious_distinct_sources"]


def test_hostile_source_addresses_cannot_break_the_counters(account):
    for ip in ("1" * 500, "::ffff:" + "9" * 200, "‮127.0.0.1", ""):
        assert _fail(Api(ip=ip), account.email).status_code in (401, 429)


def test_a_recovery_required_account_still_has_an_exit_through_password_reset_with_mailbox_proof(account):
    """CORRECTION (found while building F-ATH-015): the DEF-15 write-up said accounts in `recovery_required` had NO exit. They do: the password-reset
    confirmation proves mailbox control, returns the account to `active` and revokes sessions; MFA is still required afterwards. What was missing
    is the ADR's dedicated unlock flow and the owner/admin notification, and the hard stop still let a stranger force that disruptive reset."""
    from django.core import mail

    from .helpers import last_mail_token

    Account.objects.using("auth").filter(pk=account.pk).update(status="recovery_required")
    assert Api().post("/auth/login/", {"email": account.email, "password": TEST_PASSWORD}).status_code == 401
    api = Api()
    assert api.post("/auth/password/reset/request/", {"email": account.email}).status_code == 202
    token = last_mail_token(mail.outbox, account.email)
    new_pw = "Another-Strong-Passphrase-77!"
    assert api.post("/auth/password/reset/confirm/", {"token": token, "new_password": new_pw}).status_code == 200
    assert Account.objects.using("auth").get(pk=account.pk).status == "active"
    r = Api().post("/auth/login/", {"email": account.email, "password": new_pw})
    assert r.status_code == 200 and r.json()["stage"] in {"enroll_mfa", "password_ok"}   # signed in to the MFA stage only
