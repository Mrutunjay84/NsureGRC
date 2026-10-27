"""Core notification event recording (D-P5-007).

Event-triggered only - no condition/scheduled notifications (no task scheduler exists anywhere in this
codebase), no delivery channel beyond an in-app row the recipient's own client would have to query for (no
email/webhook infrastructure exists), no preferences (the recipient is always the triggering object's own
already-recorded owner/assigned_to/reviewer field). Callers must already be inside the target tenant's
`tenant_context()`, same convention as every other domain's service module.
"""
from __future__ import annotations

from ngrc.audit import service as audit
from ngrc.core import clock

from .models import Notification


def notify(recipient, category: str, message: str, *, object_type: str, object_id, created_by) -> Notification | None:
    """Creates a Notification for `recipient`, or creates nothing and returns None if `recipient` is None -
    there is no one to notify, and fabricating a recipient would be inventing a signal, not deriving one."""
    if recipient is None:
        return None
    notification = Notification.objects.create(
        recipient=recipient, category=category, message=message, object_type=object_type, object_id=object_id,
        created_by=created_by,
    )
    audit.record("notification.created", actor_id=created_by, object_type="notification",
                 object_id=str(notification.id), details={"category": category})
    return notification


def mark_read(notification: Notification, *, actor_id) -> Notification:
    """Stamps read_at. One-way - no mark_unread: nothing in this codebase's precedent (unlike Finding's
    verification-gated reopen) motivates un-reading a notification. Idempotent: calling it again on an
    already-read notification just re-stamps the timestamp, never errors."""
    notification.read_at = clock.now()
    notification.save(update_fields=["read_at"])
    return notification
