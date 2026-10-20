"""Cryptographic helper tests (D-P0-007 s3): real AES-256-GCM envelope encryption with AAD binding; dev-only key provider is honest."""
import re

import pytest
from cryptography.exceptions import InvalidTag
from django.conf import settings

from ngrc.core import crypto

pytestmark = pytest.mark.security
AAD = crypto.aad_for("11111111-1111-1111-1111-111111111111", "rec-1", "api_key")


def test_seal_open_round_trip_and_randomisation():
    pt = b"integration-credential-value"
    a, b = crypto.seal(pt, AAD), crypto.seal(pt, AAD)
    assert a != b and pt not in a and pt not in b  # fresh data key + nonces per record
    assert crypto.open_sealed(a, AAD) == pt == crypto.open_sealed(b, AAD)


def test_ciphertext_is_bound_to_tenant_record_and_field():
    blob = crypto.seal(b"secret", AAD)
    for wrong in (crypto.aad_for("22222222-2222-2222-2222-222222222222", "rec-1", "api_key"),   # another tenant
                  crypto.aad_for("11111111-1111-1111-1111-111111111111", "rec-2", "api_key"),   # another record
                  crypto.aad_for("11111111-1111-1111-1111-111111111111", "rec-1", "other_field")):  # another field
        with pytest.raises(InvalidTag):
            crypto.open_sealed(blob, wrong)


def test_any_bit_flip_is_detected():
    blob = bytearray(crypto.seal(b"integrity-matters", AAD))
    for i in (len(blob) - 1, len(blob) // 2, 30):
        mutated = bytearray(blob)
        mutated[i] ^= 0x01
        with pytest.raises((InvalidTag, ValueError)):
            crypto.open_sealed(bytes(mutated), AAD)
    with pytest.raises(ValueError):
        crypto.open_sealed(b"\x09" + bytes(blob[1:]), AAD)  # unknown version


def test_wrong_master_key_cannot_open(monkeypatch):
    blob = crypto.seal(b"x" * 32, AAD)
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", "B" * 43)
    with pytest.raises(InvalidTag):
        crypto.open_sealed(blob, AAD)


def test_short_master_key_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "FIELD_ENCRYPTION_KEY", "QUJD")  # 3 bytes
    with pytest.raises(ValueError):
        crypto.seal(b"x", AAD)


def test_only_the_dev_key_provider_exists_and_production_one_is_not_implemented(monkeypatch):
    monkeypatch.setattr(settings, "KEY_PROVIDER", "kms")
    with pytest.raises(NotImplementedError):
        crypto.seal(b"x", AAD)  # honest status: no pretend KMS (open item O-4)


def test_tokens_are_high_entropy_and_hashed_not_encrypted():
    toks = {crypto.new_token() for _ in range(200)}
    assert len(toks) == 200 and all(len(t) >= 43 for t in toks)  # >= 256 bits of url-safe randomness
    t = crypto.new_token()
    assert re.fullmatch(r"[0-9a-f]{64}", crypto.hash_token(t)) and crypto.hash_token(t) == crypto.hash_token(t) != t


def test_keyed_hashes_depend_on_the_server_pepper(monkeypatch):
    a, b = crypto.recovery_code_digest("ABCD1234"), crypto.keyed_identifier_hash("User@Example.test")
    monkeypatch.setattr(settings, "TOKEN_PEPPER", "a-different-pepper-value-xxxxxxxxxxxxxxxx")
    assert crypto.recovery_code_digest("ABCD1234") != a and crypto.keyed_identifier_hash("user@example.test") != b
    assert crypto.keyed_identifier_hash("User@Example.test") == crypto.keyed_identifier_hash("user@example.test")  # case-insensitive


def test_constant_time_comparison():
    assert crypto.constant_time_equals("abc", "abc") and not crypto.constant_time_equals("abc", "abd")
    assert not crypto.constant_time_equals("abc", "abcd")


def test_no_custom_cryptographic_primitives_in_the_codebase():
    """Only stdlib hashlib/hmac/secrets and the `cryptography` AEAD/Ed25519 APIs are used (no hand-rolled ciphers or RNG)."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "ngrc"
    banned = [r"\bimport random\b", r"from random import", r"\bmd5\b", r"hashlib\.sha1", r"\bDES\b", r"\bRC4\b", r"\bECB\b", r"\bxor\b"]
    offenders = [(p.name, pat) for p in root.rglob("*.py") if "migrations" not in p.parts
                 for pat in banned if re.search(pat, p.read_text(encoding="utf-8"))]
    assert offenders == []
