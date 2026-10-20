"""Platform operator accounts (platform realm). Operators exist only here; there is no self-registration."""
from __future__ import annotations

from django.db import transaction

from ngrc.audit import service as audit
from ngrc.authn import passwords
from ngrc.authn.flow import normalize_email
from ngrc.core import clock

from .models import OperatorAccount, OperatorRole


def create_operator(email: str, display_name: str, password: str, roles: list[str], *, created_by=None) -> OperatorAccount:
    valid = {r.value for r in OperatorRole.Role}
    if not roles or not set(roles) <= valid:
        raise ValueError("invalid operator roles")
    email = normalize_email(email)
    pw = passwords.check_policy(password, context_terms=(email, email.split("@")[0], display_name))
    now = clock.now()
    with transaction.atomic(using="ops"):
        op = OperatorAccount.objects.using("ops").create(
            email=email, display_name=display_name[:200], password_hash=passwords.hash_password(pw), password_changed_at=now,
            email_verified_at=now, status="active")
        for r in roles:
            OperatorRole.objects.using("ops").create(operator=op, role=r, granted_by=created_by)
        audit.emit_platform("ops", "platform.operator.created", actor_type="operator" if created_by else "system",
                            actor_id=created_by, object_type="operator", object_id=str(op.id), details={"roles": sorted(roles)})
    return op
