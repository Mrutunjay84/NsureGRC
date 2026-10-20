"""Realm-generic authentication flow: password stage -> second factor stage -> active session (D-P0-008)."""
from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction

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
        if outcome.recovery_required and account is not None and account.status == "active":
            realm.Account.objects.using(realm.db).filter(pk=account.pk).update(status="recovery_required")
            if realm is CUSTOMER:
                audit.emit_platform(realm.db, "auth.account.locked", actor_type="system", actor_id=account.id,
                                    result="failure", reason_code="too_many_failures", details={"reason": "login_failures"})
        return LoginResult("invalid")

    throttle.record_success(realm, email)
    if passwords.needs_rehash(account.password_hash):
        realm.Account.objects.using(realm.db).filter(pk=account.pk).update(password_hash=passwords.hash_password(password))
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
    if out.failures >= 10 and realm is CUSTOMER:
        realm.Account.objects.using(realm.db).filter(pk=account.pk, status="active").update(status="recovery_required")
        audit.emit_platform(realm.db, "auth.mfa.locked", actor_id=account.id, result="failure",
                            reason_code="too_many_mfa_failures", details={"method": method})


def mfa_succeeded(realm: Realm, session, account, method: str) -> str:
    """Promote the session to ACTIVE (rotating the id) and return the new raw cookie value."""
    throttle.record_success(realm, account.email, scope="mfa")
    policy_key = "operator" if realm is OPERATOR else "privileged"  # strict until a tenant (and its role) is selected
    with transaction.atomic(using=realm.db):
        raw = sessions.promote_active(realm, session, methods=["password", method], policy_key=policy_key)
        realm.Account.objects.using(realm.db).filter(pk=account.pk).update(last_login_at=clock.now())
    audit.emit_platform(realm.db, ev(realm, "mfa.verified"), actor_id=account.id,
                        actor_type="operator" if realm is OPERATOR else "user", details={"method": method})
    return raw
