"""Checkpoint signing backends (D-P0-006 s5).

* `DevFileSigner`  - Ed25519 key in a local file. **DEV/TEST ONLY**: the key lives on the same host as the database, so it
                     provides NO protection against a host-level attacker. Production settings refuse it.
* `kms`            - the production backend (KMS/HSM sign-only key). **NOT IMPLEMENTED** (open item O-4).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from django.conf import settings

log = logging.getLogger("ngrc.audit")


class DevFileSigner:
    algorithm = "ed25519"
    dev_only = True

    def __init__(self, path: str):
        if not path:
            raise RuntimeError("NGRC_AUDIT_SIGNER_KEY_PATH must be set for the dev_file signer")
        p = Path(path)
        if p.exists():
            self._key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            self._key = Ed25519PrivateKey.generate()
            pem = self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
            log.warning("generated DEV-ONLY audit signing key (not a production control)")
        pub = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = "dev-" + pub.hex()[:16]

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_key_raw(self) -> bytes:
        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def get_signer():
    backend = getattr(settings, "AUDIT_SIGNER_BACKEND", "")
    if backend == "dev_file":
        return DevFileSigner(settings.AUDIT_SIGNER_KEY_PATH)
    if backend == "kms":
        raise NotImplementedError("KMS-backed audit signer is not implemented (open item O-4)")
    raise RuntimeError("unknown AUDIT_SIGNER_BACKEND")


def verify_signature(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False
