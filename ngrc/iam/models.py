"""IDN class (customer identity & credentials) - D-P0-009. Reachable only through the `auth` connection (ngrc_auth);
the tenant data plane sees at most the 4-column `Profile` projection under an RLS policy."""
from __future__ import annotations

import uuid

from django.db import models

from ngrc.authn.abstract import AbstractAccount, AbstractSession, AbstractThrottle, AbstractWebAuthnCredential
from ngrc.core.models import ClassifiedModel


class _Idn(ClassifiedModel):
    ngrc_class = "IDN"
    ngrc_read_db = "auth"
    ngrc_write_db = "auth"

    class Meta:
        abstract = True


class Account(AbstractAccount):
    ngrc_class = "IDN"
    ngrc_read_db = "auth"
    ngrc_write_db = "auth"

    class Meta:
        db_table = "idn_account"


class Profile(ClassifiedModel):
    """Read-only projection of idn_account (id, email, display_name, status) for the tenant plane (column-level GRANT +
    RLS: visible only for members of the current tenant or the current principal). Never contains credentials."""

    ngrc_class = "IDN"
    ngrc_read_db = "default"
    ngrc_write_db = "default"

    id = models.UUIDField(primary_key=True)
    email = models.EmailField()
    display_name = models.CharField(max_length=200)
    status = models.CharField(max_length=24)

    class Meta:
        db_table = "idn_account"
        managed = False


class Session(AbstractSession):
    ngrc_class = "IDN"
    ngrc_read_db = "auth"
    ngrc_write_db = "auth"

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="sessions")
    # Active tenant chosen after authentication; never taken from client input. Deliberately NOT named `tenant_id`:
    # IDN-class tables carry no plain tenant_id column (D-P0-009 s2.2) so the classification check can be exact.
    active_tenant_id = models.UUIDField(null=True)

    class Meta:
        db_table = "idn_session"


class TotpFactor(_Idn):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="totp")
    secret_sealed = models.BinaryField()  # AES-256-GCM envelope (ngrc.core.crypto.seal); AAD binds account+field
    confirmed_at = models.DateTimeField(null=True)
    last_used_step = models.BigIntegerField(default=0)  # replay prevention: highest accepted time step
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "idn_totp_factor"


class WebAuthnCredential(AbstractWebAuthnCredential):
    ngrc_class = "IDN"
    ngrc_read_db = "auth"
    ngrc_write_db = "auth"

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="webauthn")

    class Meta:
        db_table = "idn_webauthn_credential"


class RecoveryCode(_Idn):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="recovery_codes")
    digest = models.CharField(max_length=64)  # HMAC-SHA-256(pepper, code)
    used_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "idn_recovery_code"
        indexes = [models.Index(fields=["account", "digest"])]


class AuthToken(_Idn):
    class Purpose(models.TextChoices):
        VERIFY_EMAIL = "verify_email"
        PASSWORD_RESET = "password_reset"  # noqa: S105  # nosec B105

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="tokens")
    purpose = models.CharField(max_length=20, choices=Purpose.choices)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "idn_auth_token"


class Throttle(AbstractThrottle):
    ngrc_class = "IDN"
    ngrc_read_db = "auth"
    ngrc_write_db = "auth"

    class Meta:
        db_table = "idn_throttle"


class Invitation(_Idn):
    """Tenant invitation. IDN class (deviation A10 from D-P0-009 s6: created/listed by tenant admins only through
    SECURITY DEFINER functions that bind to the current tenant). Only the token HASH is stored."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subject_tenant_id = models.UUIDField()
    email = models.EmailField(max_length=254)
    role_id = models.UUIDField()
    kind = models.CharField(max_length=20, default="member")  # member | external_party | external_auditor
    membership_expires_at = models.DateTimeField(null=True)  # mandatory for external auditors (service-enforced)
    token_hash = models.CharField(max_length=64, unique=True)
    invited_by = models.UUIDField(null=True)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True)
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "idn_invitation"


class RecoveryRequest(_Idn):
    """Lost-factor recovery request (D-P0-008 s7.4, control F-ATH-015). IDN class: every state change goes through SECURITY DEFINER
    functions (see migration 0005) - no runtime role has INSERT/UPDATE here, and a trigger enforces the state machine, the approver's
    independence and the cooling-off even against the owner role. `subject_tenant_id` is the tenant whose Owner/Admin (kind admin_assisted)
    approves; a sole Owner (kind last_owner) needs Platform Security. Only the HASH of the cancel token is stored."""

    class Kind(models.TextChoices):
        ADMIN_ASSISTED = "admin_assisted"
        LAST_OWNER = "last_owner"

    class State(models.TextChoices):
        REQUESTED = "requested"
        APPROVED = "approved"
        CANCELLED = "cancelled"
        COMPLETED = "completed"
        EXPIRED = "expired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="recovery_requests")
    subject_tenant_id = models.UUIDField()
    kind = models.CharField(max_length=20, choices=Kind.choices)
    state = models.CharField(max_length=12, choices=State.choices, default=State.REQUESTED)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    cooling_seconds = models.IntegerField()
    approver_id = models.UUIDField(null=True)
    approver_realm = models.CharField(max_length=10, null=True)
    approved_at = models.DateTimeField(null=True)
    cooling_until = models.DateTimeField(null=True)
    cancel_token_hash = models.CharField(max_length=64, unique=True)
    ended_at = models.DateTimeField(null=True)
    ended_reason = models.CharField(max_length=40, null=True)
    request_ip = models.GenericIPAddressField(null=True)

    class Meta:
        db_table = "idn_recovery_request"
        constraints = [
            models.UniqueConstraint(fields=["account"], condition=models.Q(state__in=["requested", "approved"]), name="idn_recovery_one_open"),
            models.CheckConstraint(condition=models.Q(kind__in=["admin_assisted", "last_owner"]), name="idn_recovery_kind"),
            models.CheckConstraint(condition=models.Q(state__in=["requested", "approved", "cancelled", "completed", "expired"]), name="idn_recovery_state"),
            models.CheckConstraint(condition=models.Q(cooling_seconds__gte=3600), name="idn_recovery_cooling_floor"),
            models.CheckConstraint(condition=models.Q(expires_at__gt=models.F("created_at")), name="idn_recovery_expiry_after_creation"),
            models.CheckConstraint(condition=models.Q(approver_realm__isnull=True) | models.Q(approver_realm__in=["tenant", "platform"]),
                                   name="idn_recovery_approver_realm"),
        ]
