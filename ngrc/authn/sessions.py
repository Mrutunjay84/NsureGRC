"""Server-side sessions (D-P0-008 s8-9): opaque 256-bit ids, only SHA-256(id) stored, rotation, idle + absolute timeouts,
immediate revocation. Timeout values are NsureGRC baseline (settings.SESSION_POLICY), not NIST-derived."""
from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction

from ngrc.core import clock
from ngrc.core.crypto import hash_token, new_token

from .realms import Realm

TOUCH_INTERVAL_S = 60


def _policy(key: str) -> tuple[int, int]:
    return settings.SESSION_POLICY[key]


def create(realm: Realm, account, *, stage: str, ip: str | None, user_agent: str, policy_key: str, methods=(),
           tenant_id=None):
    raw = new_token()
    now = clock.now()
    idle, absolute = _policy(policy_key)
    kwargs = {"active_tenant_id": tenant_id} if realm.name == "customer" else {}
    s = realm.Session.objects.using(realm.db).create(
        token_hash=hash_token(raw), account=account, stage=stage, created_at=now, last_seen_at=now,
        expires_at=now + timedelta(seconds=absolute), idle_timeout_s=idle, auth_methods=list(methods), password_at=now,
        ip=ip, user_agent=(user_agent or "")[:256], **kwargs,
    )
    return raw, s


def lookup(realm: Realm, raw: str):
    """Return the live session for a cookie value or None. Expired/revoked/disabled-account sessions are rejected."""
    if not raw or len(raw) > 128:
        return None
    s = realm.Session.objects.using(realm.db).select_related("account").filter(token_hash=hash_token(raw)).first()
    if s is None or s.revoked_at is not None:
        return None
    now = clock.now()
    if now >= s.expires_at or (now - s.last_seen_at).total_seconds() > s.idle_timeout_s:
        revoke(realm, s, "expired")
        return None
    if s.account.status not in {"active"}:
        revoke(realm, s, "account_unavailable")
        return None
    if (now - s.last_seen_at).total_seconds() >= TOUCH_INTERVAL_S:
        realm.Session.objects.using(realm.db).filter(pk=s.pk).update(last_seen_at=now)
        s.last_seen_at = now
    return s


def rotate(realm: Realm, s) -> str:
    """New opaque id for the same server-side session (anti-fixation). The old cookie value stops working immediately."""
    raw = new_token()
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(token_hash=hash_token(raw))
    s.token_hash = hash_token(raw)
    return raw


def promote_active(realm: Realm, s, *, methods, policy_key: str) -> str:
    now = clock.now()
    idle, absolute = _policy(policy_key)
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(
        stage="active", mfa_at=now, auth_methods=list(methods), idle_timeout_s=idle, last_seen_at=now,
        expires_at=now + timedelta(seconds=absolute), step_up_at=now,
        step_up_method=methods[-1] if methods else "", webauthn_challenge=None,
    )
    s.stage = "active"
    return rotate(realm, s)


def apply_policy(realm: Realm, s, policy_key: str) -> None:
    """Re-apply timeouts (e.g. when a tenant is selected): absolute timeout stays anchored on the MFA time."""
    idle, absolute = _policy(policy_key)
    anchor = s.mfa_at or s.created_at
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(
        idle_timeout_s=idle, expires_at=min(s.expires_at, anchor + timedelta(seconds=absolute)))


def set_tenant(realm: Realm, s, tenant_id, privileged: bool) -> str:
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(active_tenant_id=tenant_id)
    s.active_tenant_id = tenant_id
    apply_policy(realm, s, "privileged" if privileged else "standard")
    return rotate(realm, s)


def mark_step_up(realm: Realm, s, method: str) -> None:
    realm.Session.objects.using(realm.db).filter(pk=s.pk).update(step_up_at=clock.now(), step_up_method=method)


def revoke(realm: Realm, s, reason: str) -> None:
    realm.Session.objects.using(realm.db).filter(pk=s.pk, revoked_at__isnull=True).update(
        revoked_at=clock.now(), revoked_reason=reason[:64])


def revoke_all(realm: Realm, account_id, *, except_id=None, reason: str) -> int:
    qs = realm.Session.objects.using(realm.db).filter(account_id=account_id, revoked_at__isnull=True)
    if except_id is not None:
        qs = qs.exclude(pk=except_id)
    with transaction.atomic(using=realm.db):
        return qs.update(revoked_at=clock.now(), revoked_reason=reason[:64])


def set_cookie(response, realm: Realm, raw: str) -> None:
    """`__Host-` prefix => Secure, Path=/, no Domain (enforced by browsers). HttpOnly + SameSite=Lax (ADR s8)."""
    response.set_cookie(realm.cookie_name, raw, secure=True, httponly=True, samesite="Lax", path="/")


def clear_cookie(response, realm: Realm) -> None:
    response.set_cookie(realm.cookie_name, "", max_age=0, secure=True, httponly=True, samesite="Lax", path="/")
