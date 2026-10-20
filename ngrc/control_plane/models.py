"""PLT class (platform control plane) - D-P0-009. No tenant_id column except `subject_tenant_id` on rows ABOUT a tenant."""
from __future__ import annotations

import uuid

from django.db import models

from ngrc.authn.abstract import AbstractAccount, AbstractSession, AbstractThrottle, AbstractWebAuthnCredential
from ngrc.core.models import ClassifiedModel


class Tenant(ClassifiedModel):
    """Tenant registry. The tenant data plane (ngrc_app) can read ONLY its own row (RLS `id = ngrc_current_tenant()`);
    all writes go through the operator plane (ngrc_ops)."""

    ngrc_class = "PLT"
    ngrc_read_db = "default"
    ngrc_write_db = "ops"

    class Status(models.TextChoices):
        ACTIVE = "active"
        SUSPENDED = "suspended"
        OFFBOARDING = "offboarding"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=63, unique=True)
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "plt_tenant"


class OperatorAccount(AbstractAccount):
    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    class Meta:
        db_table = "plt_operator_account"


class OperatorRole(ClassifiedModel):
    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    class Role(models.TextChoices):
        ADMIN = "platform_admin"
        SECURITY = "platform_security"
        CURATOR = "platform_curator"
        SUPPORT = "platform_support"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    operator = models.ForeignKey(OperatorAccount, on_delete=models.CASCADE, related_name="roles")
    role = models.CharField(max_length=24, choices=Role.choices)
    granted_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "plt_operator_role"
        constraints = [models.UniqueConstraint(fields=["operator", "role"], name="plt_operator_role_uniq")]


class OperatorSession(AbstractSession):
    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    account = models.ForeignKey(OperatorAccount, on_delete=models.CASCADE, related_name="sessions")
    support_grant_id = models.UUIDField(null=True)  # set while acting under an active support grant

    class Meta:
        db_table = "plt_operator_session"


class OperatorWebAuthnCredential(AbstractWebAuthnCredential):
    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    account = models.ForeignKey(OperatorAccount, on_delete=models.CASCADE, related_name="webauthn")

    class Meta:
        db_table = "plt_operator_webauthn_credential"


class OperatorThrottle(AbstractThrottle):
    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    class Meta:
        db_table = "plt_operator_throttle"


class SupportAccessGrant(ClassifiedModel):
    """Support / break-glass grant (D-P0-005 s3-4). State machine and separation of duties are ALSO enforced by DB
    trigger `plt_support_grant_guard` (see migration 0002). Tenant consent columns are writable only via SECURITY
    DEFINER functions, never by the operator plane."""

    ngrc_class = "PLT"
    ngrc_read_db = "ops"
    ngrc_write_db = "ops"

    class State(models.TextChoices):
        REQUESTED = "requested"
        APPROVED = "approved"
        TENANT_CONSENTED = "tenant_consented"
        ACTIVE = "active"
        EXPIRED = "expired"
        REVOKED = "revoked"
        DENIED = "denied"

    class Profile(models.TextChoices):
        DIAGNOSTIC = "diagnostic_metadata"
        READ_LIMITED = "read_limited"
        WRITE_LIMITED = "write_limited"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, db_column="subject_tenant_id", related_name="+")
    requester = models.ForeignKey(OperatorAccount, on_delete=models.PROTECT, related_name="+")
    ticket_ref = models.CharField(max_length=100)
    reason = models.TextField()
    profile = models.CharField(max_length=24, choices=Profile.choices)
    scope = models.JSONField(default=list)  # module names; empty for diagnostic_metadata
    duration_minutes = models.IntegerField()
    break_glass = models.BooleanField(default=False)
    state = models.CharField(max_length=20, choices=State.choices, default=State.REQUESTED)
    approver = models.ForeignKey(OperatorAccount, null=True, on_delete=models.PROTECT, related_name="+")
    approved_at = models.DateTimeField(null=True)
    second_approver = models.ForeignKey(OperatorAccount, null=True, on_delete=models.PROTECT, related_name="+")
    # tenant side (written only via SECURITY DEFINER functions)
    consent_user_id = models.UUIDField(null=True)
    consented_at = models.DateTimeField(null=True)
    restricted_class_consent = models.BooleanField(default=False)
    activated_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=True)
    ended_at = models.DateTimeField(null=True)
    ended_by_type = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "plt_support_access_grant"
