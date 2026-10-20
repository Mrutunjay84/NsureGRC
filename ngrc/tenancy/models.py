"""TEN class: tenant roles and memberships (RLS FORCEd; composite same-tenant FK is created in SQL migration)."""
from __future__ import annotations

from django.db import models

from ngrc.core.models import TenantOwnedModel


class TenantRole(TenantOwnedModel):
    key = models.SlugField(max_length=64)
    name = models.CharField(max_length=100)
    permissions = models.JSONField(default=list)  # validated against the tenant permission catalogue by the service
    is_system = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_role"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "key"], name="ten_role_tenant_key_uniq"),
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_role_tenant_id_uniq"),  # target of composite FKs
        ]


class Membership(TenantOwnedModel):
    class Kind(models.TextChoices):
        MEMBER = "member"
        EXTERNAL_PARTY = "external_party"  # consultant / MSP operator in P0 (D-P0-005 s2)
        EXTERNAL_AUDITOR = "external_auditor"

    class Status(models.TextChoices):
        ACTIVE = "active"
        SUSPENDED = "suspended"

    principal_id = models.UUIDField()  # FK to idn_account(id) created in SQL (no cross-alias ORM relation)
    role_id = models.UUIDField()  # composite FK (tenant_id, role_id) -> ten_role(tenant_id, id) created in SQL
    kind = models.CharField(max_length=20, choices=Kind.choices, default=Kind.MEMBER)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    expires_at = models.DateTimeField(null=True)  # mandatory for external auditors (service-enforced)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_membership"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "principal_id"], name="ten_membership_tenant_principal_uniq")
        ]
