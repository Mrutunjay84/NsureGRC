"""Realm-generic authentication flow: password stage -> second factor stage -> active session (D-P0-008)."""
from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings
from django.db import transaction

from ngrc.audit import alerts
from ngrc.audit import service as audit
from ngrc.core import clock
from ngrc.core.crypto import keyed_identifier_hash

from . import passwords, sessions, throttle
from .realms import CUSTOMER, OPERATOR, Realm


def ev(realm: Realm, name: str) -> str:
    """Audit action name for this realm. Customer: auth.<x>; operator: platform.operator.<x>."""
    return f"auth.{name}" if realm is CUSTOMER else f"platform.operator.{name}"


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()[:254]


@dataclass
class LoginResult:
    status: str  # ok | invalid | throttled
    raw_token: str | None = None
    stage: str | None = None
    retry_after: int = 0
    account: object = None


def _suspicious(realm: Realm, account, reason: str, *, failures: int, sources: int, stage: str) -> None:
    """DEF-15 / D-P1-001: audit + alert a suspicious authentication pattern. Never raises into the login path."""
    name = "platform.operator.login.suspicious" if realm is OPERATOR else "auth.login.suspicious"
    audit.emit_platform(realm.db, name, actor_type="operator" if realm is OPERATOR else "user", actor_id=getattr(account, "id", None),
                        result="failure", reason_code=reason, details={"reason": reason, "failures": failures, "distinct_sources": sources})
    alerts.notify(alerts.Alert(kind="suspicious_login", severity="critical" if realm is OPERATOR else "warning",
                               message=f"{reason} during {stage}", stream="platform",
                               details={"realm": realm.name, "reason": reason, "failures": failures, "distinct_sources": sources,
                                        "account_id": str(getattr(account, "id", ""))}))


def _has_factor(realm: Realm, account) -> bool:
    # A credential flagged as cloned still COUNTS as an enrolled factor: otherwise the next password-only login would land in
    # `enroll_mfa` and let an attacker who knows the password enrol a factor of their own (MFA downgrade). The user must recover.
    if realm.WebAuthn.objects.using(realm.db).filter(account=account).exists():
        return True
    if realm is CUSTOMER:
        from . import totp

        return totp.has_factor(account)
    return False


def password_login(realm: Realm, email: str, password: str, *, ip: str | None, user_agent: str) -> LoginResult:
    email = normalize_email(email)
    ident_hash = keyed_identifier_hash(email)
    wait = throttle.retry_after(realm, email, ip)
    if wait:
        audit.emit_platform(realm.db, ev(realm, "throttle.triggered"), actor_type="anonymous", result="denied",
                            reason_code="throttled",
                            details={"scope": "login"} if realm is OPERATOR else {"scope": "login", "identifier_hash": ident_hash})
        return LoginResult("throttled", retry_after=wait)

    account = realm.Account.objects.using(realm.db).filter(email=email).first() if email else None
    usable = account is not None and bool(account.password_hash) and account.status == "active"
    if account is not None and account.password_hash:
        ok = passwords.verify_password(account.password_hash, password or "")
    else:
        passwords.burn_verification()  # equalise timing for unknown / credential-less accounts
        ok = False

    if not (ok and usable):
        outcome = throttle.record_failure(realm, email, ip)
        reason = "bad_credentials" if not ok else f"account_{account.status}"
        audit.emit_platform(realm.db, ev(realm, "login.failure"), actor_type="anonymous", result="denied", reason_code=reason,
                            details={"identifier_hash": ident_hash})
        # DEF-15 / D-P1-001: no status change here. The account stays usable; the progressive delay (throttle.record_failure) is the control.
        if outcome.suspicious and account is not None:
            _suspicious(realm, account, outcome.suspicious, failures=outcome.failures, sources=outcome.distinct_sources, stage="login")
        return LoginResult("invalid")

    done = throttle.record_success(realm, email)
    if done.suspicious:
        _suspicious(realm, account, done.suspicious, failures=done.prior_failures, sources=1, stage="login")
    if passwords.needs_rehash(account.password_hash):
        realm.Account.objects.using(realm.db).filter(pk=account.pk).update(password_hash=passwords.hash_password(password))
    if not getattr(settings, "NGRC_MFA_REQUIRED", True):
        # DEV-ONLY (D-P0-008): NGRC_MFA_REQUIRED=False skips enrolment/verification entirely, whether or not a
        # factor is already enrolled, and promotes straight to an active session. base.py/prod.py hard-code this
        # True; config/settings/validators.py refuses production startup with anything else. Audited honestly as
        # a skip, never blended into a real "mfa.verified" event, so this is never invisible in the audit trail
        # even though it is disabled.
        with transaction.atomic(using=realm.db):
            raw, s = sessions.create(realm, account, stage="password_ok", ip=ip, user_agent=user_agent,
                                     policy_key="pending_mfa", methods=["password"])
            policy_key = "operator" if realm is OPERATOR else "privileged"
            raw = sessions.promote_active(realm, s, methods=["password"], policy_key=policy_key)
            realm.Account.objects.using(realm.db).filter(pk=account.pk).update(last_login_at=clock.now())
        audit.emit_platform(realm.db, ev(realm, "login.success"), actor_id=account.id,
                            actor_type="operator" if realm is OPERATOR else "user", details={"stage": "active"})
        audit.emit_platform(realm.db, ev(realm, "mfa.skipped_dev_only"), actor_id=account.id,
                            actor_type="operator" if realm is OPERATOR else "user",
                            details={"reason": "NGRC_MFA_REQUIRED=False (dev-only)"})
        return LoginResult("ok", raw_token=raw, stage="active", account=account)

    stage = "password_ok" if _has_factor(realm, account) else "enroll_mfa"
    raw, _s = sessions.create(realm, account, stage=stage, ip=ip, user_agent=user_agent, policy_key="pending_mfa",
                              methods=["password"])
    audit.emit_platform(realm.db, ev(realm, "login.success"), actor_id=account.id,
                        actor_type="operator" if realm is OPERATOR else "user", details={"stage": stage})
    return LoginResult("ok", raw_token=raw, stage=stage, account=account)


def mfa_retry_after(realm: Realm, account, ip) -> int:
    return throttle.retry_after(realm, account.email, ip, scope="mfa")


def mfa_failed(realm: Realm, account, ip, method: str) -> None:
    out = throttle.record_failure(realm, account.email, ip, scope="mfa")
    audit.emit_platform(realm.db, ev(realm, "mfa.failed"), actor_id=account.id, result="denied",
                        actor_type="operator" if realm is OPERATOR else "user", reason_code="invalid_code",
                        details={"method": method})
    # DEF-15 / D-P1-001: no account lock-out after repeated second-factor failures; the progressive MFA back-off applies instead.
    if out.suspicious:
        _suspicious(realm, account, out.suspicious, failures=out.failures, sources=out.distinct_sources, stage="mfa")


def mfa_succeeded(realm: Realm, session, account, method: str) -> str:
    """Promote the session to ACTIVE (rotating the id) and return the new raw cookie value."""
    done = throttle.record_success(realm, account.email, scope="mfa")
    if done.suspicious:
        _suspicious(realm, account, done.suspicious, failures=done.prior_failures, sources=1, stage="mfa")
    policy_key = "operator" if realm is OPERATOR else "privileged"  # strict until a tenant (and its role) is selected
    with transaction.atomic(using=realm.db):
        raw = sessions.promote_active(realm, session, methods=["password", method], policy_key=policy_key)
        realm.Account.objects.using(realm.db).filter(pk=account.pk).update(last_login_at=clock.now())
    audit.emit_platform(realm.db, ev(realm, "mfa.verified"), actor_id=account.id,
                        actor_type="operator" if realm is OPERATOR else "user", details={"method": method})
    return raw
