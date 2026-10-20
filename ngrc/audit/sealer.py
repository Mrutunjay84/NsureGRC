"""Checkpoint sealer (D-P0-006 s5). Runs as its own identity (ngrc_audit_sealer: SELECT chain_head, INSERT checkpoint).

Dev export: appends signed checkpoints as JSON lines to a LOCAL directory. That is **not** WORM/immutable storage and
is NOT the production control; the production sink (object-lock bucket in a separate account + SIEM) is open item O-4.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from django.conf import settings
from django.db import connections

from ngrc.core import clock

from .chain import checkpoint_message, ts_text
from .signer import get_signer

log = logging.getLogger("ngrc.audit")
DB = "audit_sealer"


def seal_all(signer=None) -> list[dict]:
    """Create a signed checkpoint for every stream whose head advanced since its last checkpoint."""
    signer = signer or get_signer()
    sealed: list[dict] = []
    with connections[DB].cursor() as cur:
        cur.execute(
            "SELECT h.stream_key, h.seq, h.last_hash FROM audit.chain_head h "
            "WHERE h.seq > 0 AND h.seq > COALESCE((SELECT max(c.seq) FROM audit.checkpoint c WHERE c.stream_key = h.stream_key), 0)"
        )
        heads = cur.fetchall()
        for stream_key, seq, head_hash in heads:
            head_hash = bytes(head_hash)
            issued = clock.now()
            sig = signer.sign(checkpoint_message(stream_key, seq, head_hash, issued, signer.key_id))
            cur.execute(
                "INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                [stream_key, seq, head_hash, issued, signer.key_id, signer.algorithm, sig],
            )
            rec = {"stream_key": stream_key, "seq": seq, "head_hash": head_hash.hex(), "issued_at": ts_text(issued),
                   "key_id": signer.key_id, "algorithm": signer.algorithm, "signature": sig.hex(),
                   "sink": "dev-local-file (NOT WORM)"}
            sealed.append(rec)
    export_dir = getattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")
    if export_dir and sealed:
        d = Path(export_dir)
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "checkpoints.jsonl", "a", encoding="utf-8") as fh:
            for rec in sealed:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return sealed
