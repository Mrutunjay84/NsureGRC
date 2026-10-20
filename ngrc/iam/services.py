"""Customer identity services: accounts, one-time tokens (hash-only), invitations, tenant listing."""
from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import connections, transaction

from ngrc.audit import service as audit
from ngrc.authn import passwords, sessions
from ngrc.authn.flow import normalize_email
from ngrc.authn.realms import CUSTOMER
from ngrc.core import clock
from ngrc.core.context import principal_context
from ngrc.core.crypto import hash_token, keyed_identifier_hash, new_token

from .models import Account, AuthToken, Invitation


class ServiceError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def context_terms(email: str, display_name: str = "") -> tuple[str, ...]:
    return (email, email.split("@")[0], display_name)


def create_account(email: str, password: str, display_name: str = "", *, verified: bool) -> Account:
    email = normalize_email(email)
    try:
        pw = passwords.check_policy(password, context_terms=context_terms(email, display_name))
    except passwords.PolicyViolation as exc:
        audit.emit_platform("auth", "auth.password.blocklist_rejected", actor_type="anonymous", result="denied",
                            reason_code=exc.code) if exc.code == "blocklisted" else None
        raise ServiceError(f"password_{exc.code}") from exc
    now = clock.now()
    return Account.objects.using("auth").create(
        email=email, display_name=display_name[:200], password_hash=passwords.hash_password(pw), password_changed_at=now,
        email_verified_at=now if verified else None, status="active" if verified else "pending")


def issue_token(account: Account, purpose: str, ttl_s: int) -> str:
    """Create a single-use token; any outstanding token for the same purpose is invalidated. Returns the RAW token once."""
    raw = new_token()
    now = clock.now()
    with transaction.atomic(using="auth"):
        AuthToken.objects.using("auth").filter(account=account, purpose=purpose, used_at__isnull=True).update(used_at=now)
        AuthToken.objects.using("auth").create(account=account, purpose=purpose, token_hash=hash_token(raw), created_at=now,
                                               expires_at=now + timedelta(seconds=ttl_s))
    return raw


def consume_token(raw: str, purpose: str) -> Account | None:
    """Atomic single use: a replayed, expired or wrong-purpose token returns None."""
    if not raw or len(raw) > 128:
        return None
    now = clock.now()
    with transaction.atomic(using="auth"):
        tok = AuthToken.objects.using("auth").select_for_update().filter(
            token_hash=hash_token(raw), purpose=purpose, used_at__isnull=True, expires_at__gt=now).select_related("account").first()
        if tok is None:
            return None
        AuthToken.objects.using("auth").filter(pk=tok.pk).update(used_at=now)
        return tok.account


def peek_token(raw: str, purpose: str) -> Account | None:
    now = clock.now()
    tok = AuthToken.objects.using("auth").filter(token_hash=hash_token(raw or ""), purpose=purpose, used_at__isnull=True,
                                                 expires_at__gt=now).select_related("account").first()
    return tok.account if tok else None


def _link(path_fragment: str, token: str) -> str:
    # base URL is configuration, NEVER request.get_host() (host-header injection); token in the fragment keeps it out of
    # Referer headers and server logs.
    return f"{settings.PUBLIC_BASE_URL}/{path_fragment}#token={token}"


def send_verification_email(account: Account) -> None:
    raw = issue_token(account, "verify_email", settings.EMAIL_VERIFY_TTL_S)
    send_mail("Verify your NsureGRC email", f"Verify your email: {_link('verify-email', raw)}\nThis link expires in 24 hours.",
              None, [account.email], fail_silently=False)
    audit.emit_platform("auth", "auth.email.verification_sent", actor_id=account.id)


def send_reset_email(account: Account) -> None:
    raw = issue_token(account, "password_reset", settings.PASSWORD_RESET_TTL_S)
    send_mail("Reset your NsureGRC password", f"Reset your password: {_link('reset-password', raw)}\n"
              "This link is valid for 30 minutes and can be used once. If you did not request it, ignore this email.",
              None, [account.email], fail_silently=False)


def send_notice(account: Account, subject: str, body: str) -> None:
    send_mail(subject, body, None, [account.email], fail_silently=True)


def set_password(account: Account, new_password: str) -> None:
    pw = passwords.check_policy(new_password, context_terms=context_terms(account.email, account.display_name))
    Account.objects.using("auth").filter(pk=account.pk).update(
        password_hash=passwords.hash_password(pw), password_changed_at=clock.now())


# ------------------------------------------------------------------ tenant membership listing (auth connection)
_MEMBERSHIPS_SQL = """SELECT m.tenant_id, t.slug, t.name, r.key, r.permissions::text, m.kind
  FROM ten_membership m
  JOIN ten_role r ON r.id = m.role_id AND r.tenant_id = m.tenant_id
  JOIN plt_tenant t ON t.id = m.tenant_id
 WHERE m.principal_id = ngrc_current_principal() AND m.status = 'active'
   AND (m.expires_at IS NULL OR m.expires_at > now()) AND t.status = 'active'"""


def list_memberships(account_id) -> list[dict]:
    import json

    with principal_context(account_id, using="auth"), connections["auth"].cursor() as cur:
        cur.execute(_MEMBERSHIPS_SQL + " ORDER BY t.name")
        return [{"tenant_id": r[0], "slug": r[1], "name": r[2], "role": r[3], "permissions": json.loads(r[4]), "kind": r[5]}
                for r in cur.fetchall()]


def find_membership(account_id, tenant_id) -> dict | None:
    tid = uuid.UUID(str(tenant_id))
    return next((m for m in list_memberships(account_id) if m["tenant_id"] == tid), None)


# ------------------------------------------------------------------ invitations
def get_usable_invitation(raw: str) -> Invitation | None:
    inv = Invitation.objects.using("auth").filter(token_hash=hash_token(raw or "")).first()
    if inv is None or inv.accepted_at or inv.revoked_at or inv.expires_at <= clock.now():
        return None
    return inv


def accept_invitation(inv: Invitation, account: Account) -> uuid.UUID:
    with transaction.atomic(using="auth"), connections["auth"].cursor() as cur:
        cur.execute("SELECT ten_membership_from_invitation(%s::uuid, %s::uuid)", [str(inv.id), str(account.id)])
        return cur.fetchone()[0]


def identifier_hash(email: str) -> str:
    return keyed_identifier_hash(normalize_email(email))


__all__ = [n for n in dir() if not n.startswith("_")] + ["sessions", "CUSTOMER"]
