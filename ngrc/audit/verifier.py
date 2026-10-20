"""Independent audit verification (D-P0-006 s6). Runs as ngrc_audit_verifier (read-only + INSERT verification_run).

Two DIFFERENT questions are answered and reported separately (docs/AUDIT_COMPLETENESS.md):

  A. INTERNAL VALIDITY - "the events and checkpoints I was given are consistent": gapless sequence, hash linkage, hash recomputation in Python
     (not via DB code), head consistency, checkpoint signatures, checkpoint index/linkage continuity.
  B. COMPLETENESS - "nothing has silently disappeared, in particular no NEWEST checkpoint": cannot be derived from the data alone, because an
     actor who can delete the newest checkpoint leaves a perfectly valid shorter chain. It is only ever claimed against ANCHORS:
       * external_copy      - every database checkpoint older than a grace window has a copy in the external sink and every sink record exists
                              in the database with identical content (both directions);
       * high_water_mark    - the newest checkpoint verified by an earlier successful run still exists, unchanged;
       * freshness          - the newest checkpoint is recent (the sealer issues heartbeats, so a live stream always has a recent one).
     Verdict `completeness`: violated | not_established (no anchor ran) | consistent (anchors passed but all are rewritable by the actor class
     under consideration) | established (passed against an immutable sink). `established` is unreachable until a WORM sink exists (open item O-4).

A violation is written to audit.verification_run and to the platform stream as `audit.integrity_violation`.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.db import connections

from ngrc.core import clock

from . import alerts, service
from .chain import (
    checkpoint_digest,
    checkpoint_genesis_digest,
    checkpoint_message,
    checkpoint_message_v2,
    event_hash,
    genesis_hash,
)
from .signer import verify_signature

DB = "audit_verifier"

_TENANT_SQL = """SELECT event_id::text, seq, occurred_at, tenant_id::text, actor_type, actor_id::text, on_behalf_of_grant::text,
  action, object_type, object_id, result, reason_code, host(source_ip), user_agent, session_ref, request_id, details::text,
  data_class, schema_version, prev_hash, hash FROM audit.tenant_event WHERE tenant_id = %s::uuid AND seq > %s ORDER BY seq"""
_PLATFORM_SQL = """SELECT event_id::text, seq, occurred_at, related_tenant_id::text, actor_type, actor_id::text,
  on_behalf_of_grant::text, action, object_type, object_id, result, reason_code, host(source_ip), user_agent, session_ref,
  request_id, details::text, data_class, schema_version, prev_hash, hash FROM audit.platform_event WHERE seq > %s ORDER BY seq"""
_CP_SQL = """SELECT format_version, cp_index, seq, head_hash, issued_at, key_id, algorithm, signature, prev_cp_digest
  FROM audit.checkpoint WHERE stream_key = %s ORDER BY cp_id"""


@dataclass
class StreamResult:
    stream_key: str
    ok: bool = True                       # no violation found (A and any checked part of B)
    verified_through_seq: int = 0
    violations: list[str] = field(default_factory=list)
    completeness: str = "not_established"  # violated | not_established | consistent | established
    anchors: list[dict] = field(default_factory=list)   # [{"name": ..., "passed": bool, "tamper_resistant": bool}]
    hwm: dict | None = None               # newest verified format-2 checkpoint {"cp_index", "digest"} - recorded by record_run
    tail: dict | None = None              # {"seq", "hash"} of the last event this run verified - the start point of an incremental run
    mode: str = "full"                    # full | incremental
    checkpoints: dict = field(default_factory=lambda: {"v2": 0, "legacy": 0})
    internally_valid: bool = True         # question A only

    def fail(self, msg: str, *, internal: bool = True):
        self.ok = False
        if internal:
            self.internally_valid = False
        self.violations.append(msg)

    def anchor(self, name: str, passed: bool, tamper_resistant: bool):
        self.anchors.append({"name": name, "passed": passed, "tamper_resistant": tamper_resistant})


def _load_exported(stream_key: str) -> list[dict]:
    d = getattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")
    if not d or not (Path(d) / "checkpoints.jsonl").exists():
        return []
    out = []
    for line in (Path(d) / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec["stream_key"] == stream_key:
            out.append(rec)
    return out


def verify_stream(stream_key: str, public_keys: dict[str, bytes], *, require_export: bool = False, require_fresh: bool = False,
                  require_completeness: bool = False, hwm: dict | None = None, now: datetime | None = None,
                  since: dict | None = None) -> StreamResult:
    """`since` ({"seq", "hash"} from an earlier successful run) makes the run INCREMENTAL: events up to that seq are not recomputed (they were
    verified by the earlier run and are anchored by its recorded tail hash); everything else - new events, linkage to the tail, ALL checkpoints,
    all anchors - is checked as usual. A full run is still needed periodically: an in-place edit of an old event that keeps its stored hash is
    only caught by recomputation."""
    res = StreamResult(stream_key, mode="incremental" if since else "full")
    start = int(since["seq"]) if since else 0
    now = now or clock.now()
    with connections[DB].cursor() as cur:
        cur.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [stream_key])
        head = cur.fetchone()
        if head is None:
            res.fail("missing chain head")
            return res
        if stream_key == "platform":
            cur.execute(_PLATFORM_SQL, [start])
        else:
            cur.execute(_TENANT_SQL, [stream_key, start])
        rows = cur.fetchall()
        hashes: dict[int, bytes] = {}
        prev = bytes.fromhex(since["hash"]) if since else genesis_hash(stream_key)
        if since:
            hashes[start] = prev
        expected_seq = start + 1
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
        if last_seq != head[0] or (last_seq > 0 and bytes(head[1]) != hashes[last_seq]) or (last_seq == 0 and head[0] != 0):
            res.fail("chain head does not match the last event (truncation or tail alteration)")
        res.verified_through_seq = last_seq if res.ok else res.verified_through_seq
        if res.ok and last_seq > 0:
            res.tail = {"seq": last_seq, "hash": hashes[last_seq].hex()}

        cur.execute(_CP_SQL, [stream_key])
        cps = cur.fetchall()

    # ------------------------------------------------------------------------------------------------ A: checkpoint validity + continuity
    tol = timedelta(seconds=int(getattr(settings, "AUDIT_CLOCK_SKEW_TOLERANCE_S", 300)))
    v2: list[dict] = []
    expected_idx, expected_prev = 1, checkpoint_genesis_digest(stream_key)
    last_seq_cp, last_issued = 0, None
    for fmt, idx, seq, head_hash, issued, key_id, _alg, sig, prev_digest in cps:
        head_hash, sig = bytes(head_hash), bytes(sig)
        label = f"checkpoint {idx if fmt == 2 else seq}"
        if seq >= start and hashes.get(seq) != head_hash:      # older heads were verified by the earlier full run (incremental mode)
            res.fail(f"{label} does not match the event chain")
        pub = public_keys.get(key_id)
        if fmt == 1:
            res.checkpoints["legacy"] += 1
            msg = checkpoint_message(stream_key, seq, head_hash, issued, key_id)
        else:
            res.checkpoints["v2"] += 1
            prev_digest = bytes(prev_digest)
            if idx != expected_idx:
                res.fail(f"checkpoint index gap or reorder at {idx} (expected {expected_idx}): a checkpoint is missing or inserted")
                expected_idx = idx
            if prev_digest != expected_prev:
                res.fail(f"checkpoint chain linkage broken at index {idx}")
            if seq < last_seq_cp:
                res.fail(f"checkpoint {idx} moves seq backwards")
            if last_issued is not None and issued < last_issued - tol:
                res.fail(f"checkpoint {idx} is dated before the previous checkpoint")
            msg = checkpoint_message_v2(stream_key, idx, seq, head_hash, issued, key_id, prev_digest)
        if pub is None:
            res.fail(f"{label} signed by unknown key {key_id}")
        elif not verify_signature(pub, msg, sig):
            res.fail(f"{label} signature invalid")
        if fmt == 2:
            digest = checkpoint_digest(msg, sig)
            v2.append({"cp_index": idx, "seq": seq, "head_hash": head_hash, "issued": issued, "digest": digest, "key_id": key_id})
            expected_idx, expected_prev = idx + 1, digest
            last_seq_cp, last_issued = seq, issued
    if v2 and res.internally_valid:
        res.hwm = {"cp_index": v2[-1]["cp_index"], "digest": v2[-1]["digest"].hex()}

    # ------------------------------------------------------------------------------------------------ B: completeness against anchors
    exported = _load_exported(stream_key)
    immutable = bool(getattr(settings, "AUDIT_SINK_IMMUTABLE", False))
    if require_export and not exported:
        res.fail("no externally exported checkpoints available for comparison", internal=False)
    if exported:
        before = len(res.violations)
        by_idx = {c["cp_index"]: c for c in v2}
        db_legacy_seqs = {seq: bytes(hh) for fmt, _i, seq, hh, *_ in cps if fmt == 1}
        seen_idx = set()
        for rec in exported:
            seq = rec["seq"]
            if seq < start:
                pass                                              # covered by the earlier full run; digest comparison below still applies
            elif seq not in hashes:
                res.fail(f"exported checkpoint {rec.get('cp_index', seq)} refers to an event missing from the database", internal=False)
            elif hashes[seq].hex() != rec["head_hash"]:
                res.fail(f"exported checkpoint {rec.get('cp_index', seq)} disagrees with the database chain (rewrite after export)", internal=False)
            if rec.get("format") == 2:
                seen_idx.add(rec["cp_index"])
                db = by_idx.get(rec["cp_index"])
                if db is None:
                    res.fail(f"exported checkpoint {rec['cp_index']} is missing from the database (checkpoint deleted or chain rolled back)", internal=False)
                elif db["digest"].hex() != rec.get("digest"):
                    res.fail(f"checkpoint {rec['cp_index']} differs between the database and the external copy", internal=False)
            elif seq in db_legacy_seqs and db_legacy_seqs[seq].hex() != rec["head_hash"]:
                res.fail(f"legacy checkpoint at seq {seq} differs between the database and the external copy", internal=False)
        grace = timedelta(seconds=int(getattr(settings, "AUDIT_EXPORT_GRACE_S", 120)))
        if require_export:
            for c in v2:
                if c["cp_index"] not in seen_idx and c["issued"] < now - grace:
                    res.fail(f"checkpoint {c['cp_index']} has no external copy (copy removed, or never published)", internal=False)
        res.anchor("external_copy", len(res.violations) == before, immutable)

    if hwm is not None:
        before = len(res.violations)
        mine = next((c for c in v2 if c["cp_index"] == hwm["cp_index"]), None)
        if mine is None:
            res.fail(f"checkpoint {hwm['cp_index']} verified by an earlier run is missing now (newest checkpoint deleted or chain rolled back)",
                     internal=False)
        elif mine["digest"].hex() != hwm["digest"]:
            res.fail(f"checkpoint {hwm['cp_index']} verified by an earlier run has changed", internal=False)
        res.anchor("high_water_mark", len(res.violations) == before, False)

    max_age = int(getattr(settings, "AUDIT_CHECKPOINT_MAX_AGE_S", 900))
    if require_fresh and head[0] > 0:
        before = len(res.violations)
        newest = max((c[4] for c in cps), default=None)
        if newest is None:
            res.fail("the stream has events but no checkpoint at all (sealer not running?)", internal=False)
        elif (now - newest).total_seconds() > max_age:
            res.fail(f"the newest checkpoint is {int((now - newest).total_seconds())} s old (limit {max_age} s): the sealer stopped, or the newest "
                     "checkpoints were deleted", internal=False)
        res.anchor("freshness", len(res.violations) == before, False)

    if any(not a["passed"] for a in res.anchors):
        res.completeness = "violated"
    elif not res.anchors:
        res.completeness = "not_established"          # nothing independent to compare against: A may hold, B is simply unknown
    elif any(a["tamper_resistant"] for a in res.anchors):
        res.completeness = "established"
    else:
        res.completeness = "consistent"               # anchors passed, but the actor class that could delete could also have rewritten them
    if require_completeness and res.completeness in {"not_established"}:
        res.fail("completeness not established: no independent anchor (external copy, earlier verification, fresh heartbeat) was available",
                 internal=False)
    return res


def record_run(res: StreamResult, started) -> None:
    details = {"violations": res.violations[:20], "completeness": res.completeness, "anchors": res.anchors, "checkpoints": res.checkpoints}
    if res.ok and res.hwm:
        details["hwm"] = res.hwm
    if res.ok and res.tail:
        details["tail"] = res.tail
    details["mode"] = res.mode
    with connections[DB].cursor() as cur:
        cur.execute(
            "INSERT INTO audit.verification_run (id, stream_key, started_at, finished_at, status, verified_through_seq, details) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)",
            [str(uuid.uuid4()), res.stream_key, started, clock.now(), "ok" if res.ok else "violation",
             res.verified_through_seq, json.dumps(details)],
        )
    if not res.ok:
        service.emit_platform(DB, "audit.integrity_violation", actor_type="service", result="failure",
                              details={"stream": res.stream_key[:40], "detail": (res.violations[0] if res.violations else "")[:200]})
        alerts.notify(alerts.Alert(kind="integrity_violation", severity="critical", stream=res.stream_key[:40],
                                   message=(res.violations[0] if res.violations else "violation")[:200],
                                   details={"completeness": res.completeness, "violations": len(res.violations)}))


def _last_ok(stream_key: str, key: str) -> dict | None:
    with connections[DB].cursor() as cur:
        cur.execute("SELECT details->%s FROM audit.verification_run WHERE stream_key = %s AND status = 'ok' "
                    "AND details ? %s ORDER BY finished_at DESC LIMIT 1", [key, stream_key, key])
        row = cur.fetchone()
    if not row or not row[0]:
        return None
    return json.loads(row[0]) if isinstance(row[0], str) else row[0]


def last_hwm(stream_key: str) -> dict | None:
    """High-water mark recorded by the most recent SUCCESSFUL verification of this stream (None on a first run)."""
    return _last_ok(stream_key, "hwm")


def last_tail(stream_key: str) -> dict | None:
    """{"seq", "hash"} of the last event verified by the most recent SUCCESSFUL run (start point for an incremental run)."""
    return _last_ok(stream_key, "tail")


def verify_all(public_keys: dict[str, bytes], *, tenant_ids: list[str] | None = None, require_export: bool = False,
               require_fresh: bool = False, require_completeness: bool = False, use_hwm: bool = True, record: bool = True,
               mode: str = "full") -> list[StreamResult]:
    with connections[DB].cursor() as cur:
        cur.execute("SELECT stream_key FROM audit.chain_head ORDER BY stream_key")
        keys = [r[0] for r in cur.fetchall()]
    if tenant_ids is not None:
        keys = [k for k in keys if k in tenant_ids or k == "platform"]
    results = []
    for k in keys:
        started = clock.now()
        since = last_tail(k) if mode == "incremental" else None   # no earlier successful run => this stream is verified in FULL
        res = verify_stream(k, public_keys, require_export=require_export, require_fresh=require_fresh,
                            require_completeness=require_completeness, hwm=last_hwm(k) if use_hwm else None, since=since)
        if record:
            record_run(res, started)
        results.append(res)
    return results
