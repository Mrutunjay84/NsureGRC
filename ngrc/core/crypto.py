"""Cryptographic helpers. NO custom primitives: only `secrets`, `hashlib`, `hmac` and `cryptography`'s AESGCM (D-P0-007 s3).

KEY PROVIDER STATUS: the only provider implemented is `local` (a master key from the environment). It is REAL
AES-256-GCM envelope encryption, but the master key is NOT held in a KMS/HSM and there is no rotation service.
It is therefore DEV-ONLY and prod settings refuse it (open item O-4). Do not present it as production key management.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

_VERSION = b"\x01"
_KEY_ID = b"local-dev-1"  # key version stored beside ciphertext so rotation can be added later


def new_token() -> str:
    """256-bit CSPRNG token (url-safe)."""
    return secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_token(token: str) -> str:
    """Hash-only storage for >=128-bit random tokens (D-P0-007 s3). Not for low-entropy secrets."""
    return sha256_hex(token)


def recovery_code_digest(code: str) -> str:
    """HMAC-SHA-256 with a server-held pepper for recovery codes (lower entropy than session tokens)."""
    key = settings.TOKEN_PEPPER.encode("utf-8")
    return hmac.new(key, code.encode("utf-8"), hashlib.sha256).hexdigest()


def keyed_identifier_hash(identifier: str) -> str:
    """Keyed hash used to log failed-login identifiers without storing the raw (possibly mistyped-password) value."""
    key = settings.TOKEN_PEPPER.encode("utf-8")
    return hmac.new(key, b"ident|" + identifier.lower().encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _master_key() -> bytes:
    if getattr(settings, "KEY_PROVIDER", "") != "local":
        raise NotImplementedError("Only the DEV-ONLY local key provider exists; KMS provider is open item O-4")
    raw = base64.urlsafe_b64decode(_pad(settings.FIELD_ENCRYPTION_KEY))
    if len(raw) < 32:
        raise ValueError("NGRC_FIELD_ENCRYPTION_KEY must decode to at least 32 bytes")
    return raw[:32]


def _pad(s: str) -> bytes:
    s = s.replace("+", "-").replace("/", "_")
    return (s + "=" * (-len(s) % 4)).encode("ascii")


def seal(plaintext: bytes, aad: bytes) -> bytes:
    """Envelope encryption: random 256-bit data key per record, wrapped with the master key; AAD binds context."""
    data_key = AESGCM.generate_key(bit_length=256)
    n1, n2 = os.urandom(12), os.urandom(12)
    wrapped = AESGCM(_master_key()).encrypt(n1, data_key, aad)
    ct = AESGCM(data_key).encrypt(n2, plaintext, aad)
    return b"".join([_VERSION, bytes([len(_KEY_ID)]), _KEY_ID, n1, bytes([len(wrapped)]), wrapped, n2, ct])


def open_sealed(blob: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if ciphertext, key or AAD (tenant/record/field binding) differ."""
    if blob[:1] != _VERSION:
        raise ValueError("unknown ciphertext version")
    i = 1
    klen = blob[i]
    i += 1 + klen
    n1 = blob[i : i + 12]
    i += 12
    wlen = blob[i]
    i += 1
    wrapped = blob[i : i + wlen]
    i += wlen
    n2 = blob[i : i + 12]
    ct = blob[i + 12 :]
    data_key = AESGCM(_master_key()).decrypt(n1, wrapped, aad)
    return AESGCM(data_key).decrypt(n2, ct, aad)


def aad_for(scope: str, record_id, field: str) -> bytes:
    """AAD binds ciphertext to (scope = tenant id or 'identity', record id, field name)."""
    return f"{scope}|{record_id}|{field}".encode()
