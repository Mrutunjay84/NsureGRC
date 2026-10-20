"""Support-access grant helpers (D-P0-005 s3). The authoritative state machine and separation of duties live in the DB trigger
`plt_support_grant_guard`; this module adds expiry handling and the per-request validity check."""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.authz.policy import Denied
from ngrc.core import clock

from .models import SupportAccessGrant


def expire_if_due(g: SupportAccessGrant) -> bool:
    """Lazily move an overdue ACTIVE grant to `expired` (system). Returns True if it was expired now."""
    if g.state == "active" and g.expires_at is not None and g.expires_at <= clock.now():
        n = SupportAccessGrant.objects.using("ops").filter(pk=g.pk, state="active").update(
            state="expired", ended_at=clock.now(), ended_by_type="system")
        if n:
            audit.emit_platform("ops", "platform.support.ended", actor_type="system", tenant_id=g.subject_tenant_id,
                                grant_id=g.id, details={"by": "system", "state": "expired"})
            g.state = "expired"
            return True
    return False


def load_active_grant(principal) -> SupportAccessGrant:
    """Re-validated on EVERY request made in a support session: active, unexpired, and for the session's tenant."""
    g = SupportAccessGrant.objects.using("ops").filter(pk=principal.grant_id).first() if principal.grant_id else None
    if g is None:
        raise Denied("grant_missing")
    if expire_if_due(g) or g.state != "active" or g.expires_at is None or g.expires_at <= clock.now():
        raise Denied("grant_inactive")
    if g.subject_tenant_id != principal.tenant_id:
        raise Denied("grant_tenant_mismatch")
    principal.extra["grant"] = g
    return g
