"""Lost-factor recovery orchestration (D-P0-008 s7.4, F-ATH-015). All authority lives in the database functions of migration 0006; this module
issues the cancel token, calls them and sends the notifications.

Flow (customer realm): the user passes the PASSWORD stage (so the requester is not anonymous and no account can be probed) -> `start` creates a
request: kind `admin_assisted` when another Owner/Admin exists in the chosen tenant, otherwise `last_owner` (Platform Security approves) ->
an Owner/Admin (never the requester) approves with step-up -> a COOLING-OFF period (BASELINE 24 h) in which the real user is notified and can
cancel with the emailed single-use link or from a signed-in session -> `complete` deletes the old factors and recovery codes, revokes every other
session and turns the completing session into an enrolment session. Platform support has no path into any of this.
"""
from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import DatabaseError, IntegrityError, connections, transaction

from ngrc.core import clock
from ngrc.core.crypto import hash_token, new_token
from ngrc.core.net import normalize_ip

from . import services
from .models import RecoveryRequest


class RecoveryError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def start(account, tenant_id, ip) -> dict:
    cooling = int(settings.RECOVERY_COOLING_OFF_S)
    raw = new_token()
    expires = clock.now() + timedelta(seconds=int(settings.RECOVERY_REQUEST_TTL_S))
    try:
        with transaction.atomic(using="auth"), connections["auth"].cursor() as cur:
            cur.execute("SELECT id, kind FROM idn_recovery_create(%s::uuid, %s::uuid, %s, %s, %s, %s::inet)",
                        [str(account.id), str(tenant_id), cooling, expires, hash_token(raw), normalize_ip(ip)])
            rid, kind = cur.fetchone()
    except IntegrityError as exc:
        raise RecoveryError("request_already_open") from exc
    except DatabaseError as exc:
        raise RecoveryError("not_allowed") from exc
    return {"id": rid, "kind": kind, "cancel_token": raw, "expires_at": expires}


def approver_emails(request_id) -> list[str]:
    with connections["auth"].cursor() as cur:
        cur.execute("SELECT email FROM idn_recovery_notify_targets(%s::uuid)", [str(request_id)])
        return [r[0] for r in cur.fetchall()]


def cancel_with_token(raw: str):
    """-> (account_id, tenant_id, kind) or None. The token is single-use by construction (the request leaves the open states)."""
    if not raw or len(raw) > 128:
        return None
    with transaction.atomic(using="auth"), connections["auth"].cursor() as cur:
        cur.execute("SELECT account_id, subject_tenant_id, kind FROM idn_recovery_cancel(%s)", [hash_token(raw)])
        return cur.fetchone()


def cancel_for_account(request_id, account_id):
    with transaction.atomic(using="auth"), connections["auth"].cursor() as cur:
        cur.execute("SELECT subject_tenant_id, kind FROM idn_recovery_cancel_for_account(%s::uuid, %s::uuid)", [str(request_id), str(account_id)])
        return cur.fetchone()


def complete(account, request_id) -> None:
    try:
        with transaction.atomic(using="auth"), connections["auth"].cursor() as cur:
            cur.execute("SELECT idn_recovery_complete(%s::uuid, %s::uuid)", [str(request_id), str(account.id)])
    except DatabaseError as exc:
        raise RecoveryError("not_ready") from exc


def latest(account) -> RecoveryRequest | None:
    return RecoveryRequest.objects.using("auth").filter(account=account).order_by("-created_at").first()


def can_complete(r: RecoveryRequest | None) -> bool:
    return bool(r and r.state == "approved" and r.cooling_until and r.cooling_until <= clock.now() < r.expires_at)


def cancel_link(raw: str) -> str:
    return services._link("recover/cancel", raw)  # noqa: SLF001 - same host-header-safe link builder as the other mail flows
