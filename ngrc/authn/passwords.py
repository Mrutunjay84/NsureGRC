"""Password policy and Argon2id hashing (D-P0-008 s2-3).

[STD] NIST SP 800-63B-4: no composition rules, no rotation, NFC normalisation, blocklist, accept >= 64 chars.
[BASELINE] min 12 / max 128 chars; Argon2id parameters from settings (floor enforced by config validators).
"""
from __future__ import annotations

import threading
import unicodedata
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from django.conf import settings

# Bound concurrent memory-hard hashing so the login endpoint cannot be used as a memory/CPU amplifier (ADR s3).
_HASH_SLOTS = threading.BoundedSemaphore(int(getattr(settings, "NGRC_MAX_CONCURRENT_HASHES", 8)))


class PolicyViolation(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@lru_cache(maxsize=1)
def _hasher() -> PasswordHasher:
    p = settings.PASSWORD_HASHING
    return PasswordHasher(time_cost=p["time_cost"], memory_cost=p["memory_cost_kib"], parallelism=p["parallelism"])


@lru_cache(maxsize=1)
def _blocklist() -> frozenset[str]:
    path = Path(settings.PASSWORD_POLICY["blocklist_path"])
    if not path.is_file():
        return frozenset()
    return frozenset(line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def normalize(password: str) -> str:
    return unicodedata.normalize("NFC", password)


def check_policy(password: str, *, context_terms: tuple[str, ...] = ()) -> str:
    """Return the NFC-normalised password or raise PolicyViolation with a stable code."""
    pw = normalize(password)
    pol = settings.PASSWORD_POLICY
    n = len(pw)  # code points
    if n < pol["min_length"]:
        raise PolicyViolation("too_short")
    if n > pol["max_length"]:
        raise PolicyViolation("too_long")
    low = pw.lower()
    if low in _blocklist():
        raise PolicyViolation("blocklisted")
    for term in ("nsuregrc", *context_terms):  # whole-password context check, not substring (NIST)
        if term and low == term.lower():
            raise PolicyViolation("blocklisted")
    return pw


def hash_password(password: str) -> str:
    with _HASH_SLOTS:
        return _hasher().hash(normalize(password))


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        with _HASH_SLOTS:
            return _hasher().verify(stored_hash, normalize(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher().check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher().hash("ngrc-dummy-password-for-timing-equalisation")


def burn_verification() -> None:
    """Spend the same effort as a real verification for unknown accounts (timing equalisation, ADR s3)."""
    verify_password(_dummy_hash(), "not-the-password")


def reset_caches() -> None:  # tests only
    _hasher.cache_clear()
    _blocklist.cache_clear()
    _dummy_hash.cache_clear()
