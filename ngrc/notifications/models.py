"""In-app, event-triggered notification records (D-P5-007). Plain TEN - no CAT/PLT content. Mutable, no
append-only trigger: marking read is an ordinary field update, same class of operation as Task/Finding
status fields, not a governed state machine."""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel


class Notification(TenantOwnedModel):
    """One event-triggered notice for one recipient (D-P5-007). `recipient` is a plain UUID, not an FK - IAM
    is IDN class, not TEN, same convention as every other identity reference in this codebase (owner,
    assigned_to, reviewer, ...). `object_type`/`object_id` name what this is about, same shape as
    ngrc.audit's own event records - no FK into the many possible source domains."""

    recipient = models.UUIDField()
    category = models.SlugField(max_length=100)
    message = models.CharField(max_length=500)
    object_type = models.CharField(max_length=100)
    object_id = models.UUIDField()
    read_at = models.DateTimeField(null=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_notification"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_notification_tenant_id_uniq"),
        ]
