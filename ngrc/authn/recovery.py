"""Recovery codes (D-P0-008 s7.3): 10 single-use codes, 80 bits of CSPRNG entropy each (>= 64-bit baseline), shown once,
stored only as HMAC-SHA-256 with a server-held pepper. Regenerating invalidates all previous codes. Customer realm only."""
from __future__ import annotations

import base64
import secrets

from django.db import transaction

from ngrc.core import clock
from ngrc.core.crypto import recovery_code_digest

COUNT = 10


def _model():
    from ngrc.iam.models import RecoveryCode

    return RecoveryCode


def _normalise(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _format(raw: bytes) -> str:
    s = base64.b32encode(raw).decode("ascii")  # 10 bytes -> exactly 16 chars, no padding
    return "-".join(s[i : i + 4] for i in range(0, 16, 4))


def generate(account) -> list[str]:
    R = _model()
    codes = [_format(secrets.token_bytes(10)) for _ in range(COUNT)]
    with transaction.atomic(using="auth"):
        R.objects.using("auth").filter(account=account).delete()
        R.objects.using("auth").bulk_create(
            [R(account=account, digest=recovery_code_digest(_normalise(c))) for c in codes])
    return codes


def consume(account, code: str) -> bool:
    """Single use, atomic: only one concurrent caller can flip used_at from NULL."""
    R = _model()
    d = recovery_code_digest(_normalise(code))
    return R.objects.using("auth").filter(account=account, digest=d, used_at__isnull=True).update(
        used_at=clock.now()) == 1


def remaining(account) -> int:
    return _model().objects.using("auth").filter(account=account, used_at__isnull=True).count()
