"""TOTP (RFC 6238 / RFC 4226) via pyotp (D-P0-008 s7.1): SHA-1, 6 digits, 30 s, 160-bit secret, +/-1 step window,
replay prevention by persisting the highest accepted time step, secret stored AES-256-GCM sealed (customer realm only)."""
from __future__ import annotations

import hmac
import re
import uuid

import pyotp
from django.db import transaction

from ngrc.core import clock
from ngrc.core.crypto import aad_for, open_sealed, seal

STEP_S = 30
_CODE = re.compile(r"[0-9]{6}")  # ASCII digits only: \d also matches other scripts, and "$" tolerates a trailing newline


def _factor_model():
    from ngrc.iam.models import TotpFactor

    return TotpFactor


def _secret_of(factor) -> str:
    return open_sealed(bytes(factor.secret_sealed), aad_for("identity", factor.id, "totp_secret")).decode("ascii")


def begin_enrollment(account) -> tuple[str, str]:
    """Replace any unconfirmed factor and return (base32 secret, otpauth URI). Shown to the user exactly once."""
    F = _factor_model()
    F.objects.using("auth").filter(account=account, confirmed_at__isnull=True).delete()
    secret = pyotp.random_base32(length=32)  # 32 base32 chars = 160 bits
    fid = uuid.uuid4()
    F.objects.using("auth").create(id=fid, account=account, secret_sealed=seal(secret.encode("ascii"),
                                   aad_for("identity", fid, "totp_secret")))
    uri = pyotp.TOTP(secret).provisioning_uri(name=account.email, issuer_name="NsureGRC")
    return secret, uri


def _match_step(secret: str, code: str, now_ts: int) -> int | None:
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        return None
    base = now_ts // STEP_S
    totp = pyotp.TOTP(secret)
    hit = None
    for off in (0, -1, 1):  # constant work: evaluate all candidates
        step = base + off
        if hmac.compare_digest(totp.at(step * STEP_S), code) and hit is None:
            hit = step
    return hit


def confirm_enrollment(account, code: str) -> bool:
    F = _factor_model()
    f = F.objects.using("auth").filter(account=account, confirmed_at__isnull=True).order_by("-created_at").first()
    if f is None:
        return False
    step = _match_step(_secret_of(f), code, int(clock.now().timestamp()))
    if step is None:
        return False
    F.objects.using("auth").filter(pk=f.pk).update(confirmed_at=clock.now(), last_used_step=step)
    return True


def has_factor(account) -> bool:
    return _factor_model().objects.using("auth").filter(account=account, confirmed_at__isnull=False).exists()


def verify(account, code: str) -> str:
    """Return 'ok' | 'invalid' | 'replay' | 'no_factor'."""
    F = _factor_model()
    f = F.objects.using("auth").filter(account=account, confirmed_at__isnull=False).first()
    if f is None:
        return "no_factor"
    step = _match_step(_secret_of(f), code, int(clock.now().timestamp()))
    if step is None:
        return "invalid"
    with transaction.atomic(using="auth"):
        # atomic compare-and-set: a second use of the same (or an earlier) time step is a replay
        updated = F.objects.using("auth").filter(pk=f.pk, last_used_step__lt=step).update(last_used_step=step)
    return "ok" if updated == 1 else "replay"


def remove(account) -> int:
    return _factor_model().objects.using("auth").filter(account=account).delete()[0]
