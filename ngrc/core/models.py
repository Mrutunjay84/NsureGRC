"""Abstract base models enforcing the table classes of D-P0-009."""
from __future__ import annotations

import uuid

from django.db import models

from .context import assert_tenant_context, current_tenant_id
from .errors import TenantContextMissing


class TenantQuerySet(models.QuerySet):
    """ORM guard layer: every DB-touching path resolves `.db`, which raises without a tenant context."""

    @property
    def db(self):
        assert_tenant_context("default")
        return super().db

    def bulk_create(self, objs, *args, **kwargs):
        assert_tenant_context("default")
        return super().bulk_create(objs, *args, **kwargs)


class TenantManager(models.Manager.from_queryset(TenantQuerySet)):
    pass


class ClassifiedModel(models.Model):
    """Every concrete model declares its class and connection aliases."""

    ngrc_class: str = ""  # CAT | PLT | IDN | TEN
    ngrc_read_db: str | None = None
    ngrc_write_db: str | None = None

    class Meta:
        abstract = True


class TenantOwnedModel(ClassifiedModel):
    """TEN class: `tenant_id` NOT NULL, immutable, RLS FORCEd (see ngrc.core.sqlgen)."""

    ngrc_class = "TEN"
    ngrc_read_db = "default"
    ngrc_write_db = "default"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        "control_plane.Tenant", on_delete=models.PROTECT, db_column="tenant_id", related_name="+", editable=False
    )

    objects = TenantManager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        tid = current_tenant_id()
        if tid is None:
            raise TenantContextMissing("tenant-owned data written without an active tenant context")
        if self.tenant_id is None:
            self.tenant_id = tid  # explicit scope from context; RLS WITH CHECK still verifies equality
        assert_tenant_context("default")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        assert_tenant_context("default")
        return super().delete(*args, **kwargs)
