"""Abstract models shared by the customer realm (idn_*) and the operator realm (plt_operator_*) - D-P0-005 s1.

Two separate concrete stores are derived from these: credentials of one realm are never valid in the other.
"""
from __future__ import annotations

import uuid

from django.db import models

from ngrc.core.models import ClassifiedModel


class AbstractAccount(ClassifiedModel):
    class Status(models.TextChoices):
        PENDING = "pending"
        ACTIVE = "active"
        DISABLED = "disabled"
        RECOVERY_REQUIRED = "recovery_required"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254, unique=True)  # stored lower-cased by the service layer
    display_name = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.PENDING)
    password_hash = models.CharField(max_length=255, blank=True)  # Argon2id PHC string; never returned by any API
    password_changed_at = models.DateTimeField(null=True)
    email_verified_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login_at = models.DateTimeField(null=True)

    class Meta:
        abstract = True


class AbstractSession(ClassifiedModel):
    class Stage(models.TextChoices):
        PASSWORD_OK = "password_ok"  # noqa: S105  # nosec B105
        ENROLL_MFA = "enroll_mfa"  # no factor enrolled yet: only enrolment endpoints allowed
        ACTIVE = "active"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # SHA-256 of the opaque session id; the raw id lives only in the cookie (a DB read yields no usable session)
    token_hash = models.CharField(max_length=64, unique=True)
    stage = models.CharField(max_length=16, choices=Stage.choices)
    created_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    expires_at = models.DateTimeField()  # absolute timeout
    idle_timeout_s = models.IntegerField()
    auth_methods = models.JSONField(default=list)
    password_at = models.DateTimeField(null=True)
    mfa_at = models.DateTimeField(null=True)
    step_up_at = models.DateTimeField(null=True)
    step_up_method = models.CharField(max_length=16, blank=True)
    webauthn_challenge = models.JSONField(null=True)  # {challenge, purpose, binding, expires}; consumed single-use
    ip = models.GenericIPAddressField(null=True)
    user_agent = models.CharField(max_length=256, blank=True)
    revoked_at = models.DateTimeField(null=True)
    revoked_reason = models.CharField(max_length=64, blank=True)

    class Meta:
        abstract = True


class AbstractWebAuthnCredential(ClassifiedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential_id = models.BinaryField(unique=True)
    public_key = models.BinaryField()
    sign_count = models.BigIntegerField(default=0)
    transports = models.JSONField(default=list)
    aaguid = models.CharField(max_length=64, blank=True)
    backup_eligible = models.BooleanField(default=False)
    backup_state = models.BooleanField(default=False)
    flagged_clone = models.BooleanField(default=False)  # signature-counter regression observed
    nickname = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True)

    class Meta:
        abstract = True


class AbstractThrottle(ClassifiedModel):
    key = models.CharField(max_length=128, primary_key=True)  # e.g. "acct:<sha256>" or "ip:<addr>"
    failures = models.IntegerField(default=0)
    window_started = models.DateTimeField()
    locked_until = models.DateTimeField(null=True)
    updated_at = models.DateTimeField()

    class Meta:
        abstract = True
