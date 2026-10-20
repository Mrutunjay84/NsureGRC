"""Independent audit verification (D-P0-006 s6). Runs as ngrc_audit_verifier (read-only + INSERT verification_run).

Checks per stream: gapless sequence from 1, hash linkage from the genesis hash, hash recomputation in Python (not via
DB code), head consistency, signed-checkpoint validity, and agreement with the externally exported checkpoint copy.
A violation is written to audit.verification_run and to the platform stream as `audit.integrity_violation`.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from django.conf import settings
from django.db import connections

from ngrc.core import clock

from . import service
from .chain import checkpoint_message, event_hash, genesis_hash
from .signer import verify_signature

DB = "audit_verifier"

_TENANT_SQL = """SELECT event_id::text, seq, occurred_at, tenant_id::text, actor_type, actor_id::text, on_behalf_of_grant::text,
  action, object_type, object_id, result, reason_code, host(source_ip), user_agent, session_ref, request_id, details::text,
  data_class, schema_version, prev_hash, hash FROM audit.tenant_event WHERE tenant_id = %s::uuid ORDER BY seq"""
_PLATFORM_SQL = """SELECT event_id::text, seq, occurred_at, related_tenant_id::text, actor_type, actor_id::text,
  on_behalf_of_grant::text, action, object_type, object_id, result, reason_code, host(source_ip), user_agent, session_ref,
  request_id, details::text, data_class, schema_version, prev_hash, hash FROM audit.platform_event ORDER BY seq"""


@dataclass
class StreamResult:
    stream_key: str
    ok: bool = True
    verified_through_seq: int = 0
    violations: list[str] = field(default_factory=list)

    def fail(self, msg: str):
        self.ok = False
        self.violations.append(msg)


def _load_exported(stream_key: str) -> list[dict]:
    d = getattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")
    if not d or not (Path(d) / "checkpoints.jsonl").exists():
        return []
    out = []
    for line in (Path(d) / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if rec["stream_key"] == stream_key:
            out.append(rec)
    return out


def verify_stream(stream_key: str, public_keys: dict[str, bytes], *, require_export: bool = False) -> StreamResult:
    res = StreamResult(stream_key)
    with connections[DB].cursor() as cur:
        cur.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [stream_key])
        head = cur.fetchone()
        if head is None:
            res.fail("missing chain head")
            return res
        if stream_key == "platform":
            cur.execute(_PLATFORM_SQL)
        else:
            cur.execute(_TENANT_SQL, [stream_key])
        rows = cur.fetchall()
        hashes: dict[int, bytes] = {}
        prev = genesis_hash(stream_key)
        expected_seq = 1
        for (eid, seq, ts, tenant, atype, actor, grant, action, otype, oid, result, reason, ip, ua, sref, rid, details,
             dclass, ver, prev_hash, hsh) in rows:
            prev_hash, hsh = bytes(prev_hash), bytes(hsh)
            if seq != expected_seq:
                res.fail(f"sequence gap or reorder at seq {seq} (expected {expected_seq})")
                expected_seq = seq
            if prev_hash != prev:
                res.fail(f"hash linkage broken at seq {seq}")
            calc = event_hash(stream_key=stream_key, seq=seq, prev_hash=prev_hash, event_id=eid, occurred_at=ts,
                              tenant=tenant, actor_type=atype, actor_id=actor, grant=grant, action=action,
                              object_type=otype, object_id=oid, result=result, reason=reason, ip_host=ip, user_agent=ua,
                              session_ref=sref, request_id=rid, details_text=details, data_class=dclass,
                              schema_version=ver)
            if calc != hsh:
                res.fail(f"event content does not match its hash at seq {seq}")
            hashes[seq] = hsh
            prev = hsh
            expected_seq += 1
        last_seq = expected_seq - 1
        if last_seq != head[0] or (rows and bytes(head[1]) != hashes[last_seq]) or (not rows and head[0] != 0):
            res.fail("chain head does not match the last event (truncation or tail alteration)")
        res.verified_through_seq = last_seq if res.ok else res.verified_through_seq

        cur.execute("SELECT seq, head_hash, issued_at, key_id, algorithm, signature FROM audit.checkpoint "
                    "WHERE stream_key = %s ORDER BY seq", [stream_key])
        cps = cur.fetchall()
        db_cp = {}
        for seq, head_hash, issued, key_id, _alg, sig in cps:
            head_hash, sig = bytes(head_hash), bytes(sig)
            db_cp[seq] = head_hash
            if hashes.get(seq) != head_hash:
                res.fail(f"checkpoint {seq} does not match the event chain")
            pub = public_keys.get(key_id)
            if pub is None:
                res.fail(f"checkpoint {seq} signed by unknown key {key_id}")
            elif not verify_signature(pub, checkpoint_message(stream_key, seq, head_hash, issued, key_id), sig):
                res.fail(f"checkpoint {seq} signature invalid")
    exported = _load_exported(stream_key)
    if require_export and not exported:
        res.fail("no externally exported checkpoints available for comparison")
    for rec in exported:
        seq = rec["seq"]
        if seq not in hashes:
            res.fail(f"exported checkpoint {seq} refers to an event missing from the database")
        elif hashes[seq].hex() != rec["head_hash"]:
            res.fail(f"exported checkpoint {seq} disagrees with the database chain (rewrite after export)")
    return res


def record_run(res: StreamResult, started) -> None:
    with connections[DB].cursor() as cur:
        cur.execute(
            "INSERT INTO audit.verification_run (id, stream_key, started_at, finished_at, status, verified_through_seq, details) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)",
            [str(uuid.uuid4()), res.stream_key, started, clock.now(), "ok" if res.ok else "violation",
             res.verified_through_seq, json.dumps({"violations": res.violations[:20]})],
        )
    if not res.ok:
        service.emit_platform(DB, "audit.integrity_violation", actor_type="service", result="failure",
                              details={"stream": res.stream_key[:40], "detail": (res.violations[0] if res.violations else "")[:200]})


def verify_all(public_keys: dict[str, bytes], *, tenant_ids: list[str] | None = None, require_export: bool = False,
               record: bool = True) -> list[StreamResult]:
    with connections[DB].cursor() as cur:
        cur.execute("SELECT stream_key FROM audit.chain_head ORDER BY stream_key")
        keys = [r[0] for r in cur.fetchall()]
    if tenant_ids is not None:
        keys = [k for k in keys if k in tenant_ids or k == "platform"]
    results = []
    for k in keys:
        started = clock.now()
        res = verify_stream(k, public_keys, require_export=require_export)
        if record:
            record_run(res, started)
        results.append(res)
    return results
