"""Checkpoint sealer (D-P0-006 s5). Runs as its own identity (ngrc_audit_sealer: SELECT chain_head, INSERT checkpoint).

Format 2 checkpoints (H-11) are CHAINED: each carries a per-stream index and the digest of the previous signed checkpoint. A checkpoint is
issued when the stream's head advanced since the last one OR - the HEARTBEAT - when the last checkpoint is older than
`AUDIT_CHECKPOINT_INTERVAL_S`, even if nothing new happened. The heartbeat is what makes "the newest checkpoint silently disappeared" and
"the sealer stopped" visible without any prior state: the newest checkpoint of a live stream is always recent (docs/AUDIT_COMPLETENESS.md).

Dev export: appends signed checkpoints as JSON lines to a LOCAL directory. That is **not** WORM/immutable storage and
is NOT the production control; the production sink (object-lock bucket in a separate account + SIEM) is open item O-4.
A record is exported only if its database row was actually inserted (a concurrent sealer that lost the race exports nothing).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from django.conf import settings
from django.db import IntegrityError, ProgrammingError, connections

from ngrc.core import clock

from .chain import checkpoint_digest, checkpoint_genesis_digest, checkpoint_message_v2, ts_text
from .signer import get_signer

log = logging.getLogger("ngrc.audit")
DB = "audit_sealer"


def _previous(cur, stream_key: str):
    """(last cp_index, its digest, last seq, last issued_at) over format-2 rows; seq/issued_at also consider legacy rows."""
    cur.execute("SELECT max(seq), max(issued_at) FROM audit.checkpoint WHERE stream_key = %s", [stream_key])
    last_seq, last_issued = cur.fetchone()
    cur.execute("SELECT cp_index, seq, head_hash, issued_at, key_id, prev_cp_digest, signature FROM audit.checkpoint "
                "WHERE stream_key = %s AND format_version = 2 ORDER BY cp_index DESC LIMIT 1", [stream_key])
    row = cur.fetchone()
    if row is None:
        return 0, checkpoint_genesis_digest(stream_key), last_seq, last_issued
    idx, seq, head, issued, key_id, prev, sig = row
    msg = checkpoint_message_v2(stream_key, idx, seq, bytes(head), issued, key_id, bytes(prev))
    return idx, checkpoint_digest(msg, bytes(sig)), last_seq, last_issued


def seal_all(signer=None, *, streams: list[str] | None = None, heartbeat: bool = True) -> list[dict]:
    """Issue a chained, signed checkpoint for every stream that is due. Returns the records actually inserted."""
    signer = signer or get_signer()
    interval = int(getattr(settings, "AUDIT_CHECKPOINT_INTERVAL_S", 300))
    sealed: list[dict] = []
    with connections[DB].cursor() as cur:
        cur.execute("SELECT stream_key, seq, last_hash FROM audit.chain_head WHERE seq > 0 ORDER BY stream_key")
        heads = [h for h in cur.fetchall() if streams is None or h[0] in streams]
        for stream_key, seq, head_hash in heads:
            head_hash = bytes(head_hash)
            idx, prev_digest, last_seq, last_issued = _previous(cur, stream_key)
            now = clock.now()
            new_events = last_seq is None or seq > last_seq
            beat_due = heartbeat and last_issued is not None and (now - last_issued).total_seconds() >= interval
            if not (new_events or beat_due):
                continue
            msg = checkpoint_message_v2(stream_key, idx + 1, seq, head_hash, now, signer.key_id, prev_digest)
            sig = signer.sign(msg)
            try:
                cur.execute(
                    "INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature, format_version, "
                    "cp_index, prev_cp_digest) VALUES (%s,%s,%s,%s,%s,%s,%s,2,%s,%s)",
                    [stream_key, seq, head_hash, now, signer.key_id, signer.algorithm, sig, idx + 1, prev_digest])
            except (IntegrityError, ProgrammingError) as exc:  # lost a race to another sealer / continuity trigger refused: nothing to publish
                log.warning("checkpoint %s/%s not inserted (%s)", stream_key, idx + 1, type(exc).__name__)
                continue
            sealed.append({"stream_key": stream_key, "format": 2, "cp_index": idx + 1, "seq": seq, "head_hash": head_hash.hex(),
                           "issued_at": ts_text(now), "key_id": signer.key_id, "algorithm": signer.algorithm, "signature": sig.hex(),
                           "prev_cp_digest": prev_digest.hex(), "digest": checkpoint_digest(msg, sig).hex(),
                           "heartbeat": not new_events, "sink": "dev-local-file (NOT WORM)"})
    export_dir = getattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")
    if export_dir and sealed:
        d = Path(export_dir)
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "checkpoints.jsonl", "a", encoding="utf-8") as fh:
            for rec in sealed:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return sealed
