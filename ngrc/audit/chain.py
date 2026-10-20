"""Independent Python implementation of the audit hash construction (D-P0-006 s3).

The verifier recomputes every hash HERE, so verification does not rely on code that lives in the database (an attacker
with DB write access could alter DB-side functions). Must stay byte-identical to `audit._event_hash` in migration 0001.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

NULL_MARK = b"\xff\xff\xff\xff"
VERSION_TAG = "NGRC-AUDIT-v1"


def lp(b: bytes | None) -> bytes:
    """Length-prefixed bytes: 4-byte big-endian length (== int4send(octet_length)) then bytes; NULL => 0xFFFFFFFF."""
    return NULL_MARK if b is None else len(b).to_bytes(4, "big") + b


def t(s: str | None) -> bytes:
    return lp(None if s is None else s.encode("utf-8"))


def ts_text(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def genesis_hash(stream_key: str) -> bytes:
    return hashlib.sha256(f"NGRC-AUDIT-v1-genesis|{stream_key}".encode()).digest()


def event_hash(*, stream_key: str, seq: int, prev_hash: bytes, event_id: str, occurred_at: datetime, tenant: str | None,
               actor_type: str, actor_id: str | None, grant: str | None, action: str, object_type: str | None,
               object_id: str | None, result: str, reason: str | None, ip_host: str | None, user_agent: str | None,
               session_ref: str | None, request_id: str | None, details_text: str, data_class: str,
               schema_version: int) -> bytes:
    return hashlib.sha256(
        t(VERSION_TAG) + t(stream_key) + t(str(seq)) + lp(prev_hash) + t(event_id) + t(ts_text(occurred_at))
        + t(tenant) + t(actor_type) + t(actor_id) + t(grant) + t(action) + t(object_type) + t(object_id) + t(result)
        + t(reason) + t(ip_host) + t(user_agent) + t(session_ref) + t(request_id) + t(details_text) + t(data_class)
        + t(str(schema_version))
    ).digest()


def checkpoint_message(stream_key: str, seq: int, head_hash: bytes, issued_at: datetime, key_id: str) -> bytes:
    return "|".join(["NGRC-CHECKPOINT-v1", stream_key, str(seq), head_hash.hex(), ts_text(issued_at), key_id]).encode("utf-8")


# ---------------------------------------------------------------------------------------------------- checkpoint format v2 (H-11)
# v2 adds a per-stream checkpoint index and the digest of the PREVIOUS checkpoint, and uses the same length-prefixed encoding as events
# (no delimiter ambiguity). Together they make deletion of a MIDDLE checkpoint, reordering and insertion detectable from the checkpoints
# alone; deletion of the NEWEST checkpoint needs an independent anchor (see docs/AUDIT_COMPLETENESS.md).
CHECKPOINT_V2_TAG = "NGRC-CHECKPOINT-v2"


def checkpoint_genesis_digest(stream_key: str) -> bytes:
    """`prev` of checkpoint index 1 of a stream."""
    return hashlib.sha256(f"NGRC-CHECKPOINT-v2-genesis|{stream_key}".encode()).digest()


def checkpoint_message_v2(stream_key: str, cp_index: int, seq: int, head_hash: bytes, issued_at: datetime, key_id: str,
                          prev_digest: bytes) -> bytes:
    return (t(CHECKPOINT_V2_TAG) + t(stream_key) + t(str(cp_index)) + t(str(seq)) + lp(head_hash) + t(ts_text(issued_at))
            + t(key_id) + lp(prev_digest))


def checkpoint_digest(message: bytes, signature: bytes) -> bytes:
    """Identity of a signed checkpoint: what the next checkpoint commits to, and what a high-water mark / external copy records."""
    return hashlib.sha256(lp(message) + lp(signature)).digest()
