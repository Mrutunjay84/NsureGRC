"""H-11 - audit checkpoint COMPLETENESS and CONTINUITY (docs/AUDIT_COMPLETENESS.md).

The verifier must distinguish
  A  "the checkpoint chain supplied to me is internally valid"            (`internally_valid`)
  B  "the checkpoint sequence is complete - no newest checkpoint silently disappeared"   (`completeness`)
B is only ever claimed against an ANCHOR (external copy, earlier verification = high-water mark, heartbeat freshness). Without an anchor the verdict
is `not_established`, never "fine". With a rewritable anchor it is at most `consistent`; `established` needs an immutable sink (O-4, unreachable today).
Attackers modelled: schema-owner level (can delete rows and disable triggers) over the database, and - in the dev sink - over the export file.
"""
import json
import threading
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from django.conf import settings

from ngrc.audit import sealer, verifier
from ngrc.audit.chain import checkpoint_message, ts_text
from ngrc.audit.signer import get_signer
from ngrc.core import clock

from .conftest import role_connect
from .test_audit_integrity import _emit, _keys, attacker

pytestmark = pytest.mark.security
INTERVAL = settings.AUDIT_CHECKPOINT_INTERVAL_S
MAX_AGE = settings.AUDIT_CHECKPOINT_MAX_AGE_S


@pytest.fixture
def export(tmp_path, monkeypatch):
    """A private export directory per test (the dev sink), so other tests' checkpoints never interfere."""
    monkeypatch.setattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", str(tmp_path))
    return Path(tmp_path) / "checkpoints.jsonl"


@pytest.fixture
def no_export(monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")


def seal(tenant, **kw):
    return [r for r in sealer.seal_all(streams=[str(tenant.id)], **kw)]


def check(tenant, **kw):
    return verifier.verify_stream(str(tenant.id), _keys(), **kw)


def run_recorded(tenant, **kw):
    """One scheduled-style run: uses the previous run's high-water mark and records this run's."""
    started = clock.now()
    res = verifier.verify_stream(str(tenant.id), _keys(), hwm=verifier.last_hwm(str(tenant.id)), **kw)
    verifier.record_run(res, started)
    return res


def delete_checkpoint(tenant, cp_index):
    with attacker("audit.checkpoint") as c:
        c.execute("DELETE FROM audit.checkpoint WHERE stream_key = %s AND cp_index = %s", [str(tenant.id), cp_index])


def drop_export_record(export_file, cp_index, stream):
    keep = [ln for ln in export_file.read_text().splitlines()
            if not (json.loads(ln)["stream_key"] == stream and json.loads(ln).get("cp_index") == cp_index)]
    export_file.write_text("\n".join(keep) + ("\n" if keep else ""))


def two_checkpoints(tenant):
    _emit(tenant, 2)
    first = seal(tenant)
    _emit(tenant, 2)
    second = seal(tenant)
    assert [r["cp_index"] for r in first + second] == [1, 2]  # precondition: the setup really produced two chained checkpoints
    return first[0], second[0]


# ------------------------------------------------------------------------------------------------ the mechanism
def test_checkpoints_are_chained_and_a_heartbeat_extends_the_chain_without_new_events(tenant_a, export, clock_ctl):
    cp1, cp2 = two_checkpoints(tenant_a)
    assert cp2["prev_cp_digest"] == cp1["digest"] and cp1["prev_cp_digest"] != cp2["prev_cp_digest"]
    assert seal(tenant_a) == []                                  # nothing new and not yet due: no spurious checkpoint
    clock_ctl.advance(seconds=INTERVAL + 1)
    (beat,) = seal(tenant_a)                                     # idle stream, interval elapsed: HEARTBEAT
    assert beat["heartbeat"] is True and beat["cp_index"] == 3 and beat["seq"] == cp2["seq"] and beat["prev_cp_digest"] == cp2["digest"]
    assert seal(tenant_a, heartbeat=False) == []
    res = check(tenant_a)
    assert res.ok and res.internally_valid and res.checkpoints == {"v2": 3, "legacy": 0}


def test_a_valid_chain_alone_never_proves_completeness(tenant_a, no_export):
    """B cannot be derived from the data: deleting the NEWEST checkpoint leaves a perfectly valid shorter chain."""
    _emit(tenant_a, 2)
    seal(tenant_a)
    _emit(tenant_a, 2)
    seal(tenant_a)
    intact = check(tenant_a)
    assert intact.ok and intact.internally_valid and intact.completeness == "not_established"
    delete_checkpoint(tenant_a, 2)
    after = check(tenant_a)
    assert after.ok and after.internally_valid, "A (internal validity) still holds - that is exactly why B needs an anchor"
    assert after.completeness == "not_established"
    strict = check(tenant_a, require_completeness=True)
    assert not strict.ok and any("completeness not established" in v for v in strict.violations)


def test_deleting_the_newest_checkpoint_is_caught_by_the_external_copy(tenant_a, export):
    two_checkpoints(tenant_a)
    assert check(tenant_a, require_export=True).completeness == "consistent"
    delete_checkpoint(tenant_a, 2)
    res = check(tenant_a, require_export=True)
    assert not res.ok and res.internally_valid and res.completeness == "violated"
    assert any("exported checkpoint 2 is missing from the database" in v for v in res.violations)


def test_removing_the_newest_external_copy_is_caught(tenant_a, export):
    """The Phase 1 gap demo (H-11): dropping the newest exported record used to leave the stream 'healthy'."""
    two_checkpoints(tenant_a)
    drop_export_record(export, 2, str(tenant_a.id))
    later = clock.now() + timedelta(seconds=settings.AUDIT_EXPORT_GRACE_S + 5)
    res = check(tenant_a, require_export=True, now=later)
    assert not res.ok and res.completeness == "violated"
    assert any("checkpoint 2 has no external copy" in v for v in res.violations)
    # inside the grace window a fresh checkpoint may legitimately not be published yet: no false alarm
    assert check(tenant_a, require_export=True, now=clock.now()).ok


def test_deleting_the_newest_checkpoint_everywhere_is_caught_by_the_high_water_mark(tenant_a, export):
    two_checkpoints(tenant_a)
    first = run_recorded(tenant_a, require_export=True)
    assert first.ok and verifier.last_hwm(str(tenant_a.id))["cp_index"] == 2
    delete_checkpoint(tenant_a, 2)                                    # attacker controls the database AND the dev sink
    drop_export_record(export, 2, str(tenant_a.id))
    res = run_recorded(tenant_a, require_export=True)
    assert not res.ok and res.completeness == "violated"
    assert any("verified by an earlier run is missing" in v for v in res.violations)
    assert next(a for a in res.anchors if a["name"] == "external_copy")["passed"], "the sink copy is gone too - only the earlier run remembers"
    assert verifier.last_hwm(str(tenant_a.id))["cp_index"] == 2       # a failed run never moves the mark


def test_a_changed_checkpoint_is_not_accepted_as_the_one_verified_earlier(tenant_a, export):
    two_checkpoints(tenant_a)
    run_recorded(tenant_a)
    delete_checkpoint(tenant_a, 2)
    _emit(tenant_a, 1)
    seal(tenant_a)                                                    # a new checkpoint 2 (different content) takes the index
    res = check(tenant_a, hwm=verifier.last_hwm(str(tenant_a.id)))
    assert not res.ok and any("verified by an earlier run has changed" in v for v in res.violations)


def test_deleting_the_newest_checkpoints_and_silencing_the_sealer_is_caught_by_staleness(tenant_a, no_export, clock_ctl):
    two_checkpoints(tenant_a)
    clock_ctl.advance(seconds=MAX_AGE + 60)              # time passes; a live sealer would have issued heartbeats
    delete_checkpoint(tenant_a, 2)                       # no export, no earlier run: only liveness evidence remains
    res = check(tenant_a, require_fresh=True)
    assert not res.ok and any("newest checkpoint is" in v and "old" in v for v in res.violations)
    seal(tenant_a)                                       # the sealer resumes: fresh again (but see the re-seal test for what that cannot hide)
    assert check(tenant_a, require_fresh=True).ok


def test_resealing_over_a_deleted_checkpoint_cannot_replace_it_silently(tenant_a, export):
    """Delete checkpoint 2 and let the sealer issue a new checkpoint 2: the sink still holds the original, so the replacement is exposed."""
    cp1, cp2 = two_checkpoints(tenant_a)
    delete_checkpoint(tenant_a, 2)
    _emit(tenant_a, 1)
    (cp2b,) = seal(tenant_a)
    assert cp2b["cp_index"] == 2 and cp2b["digest"] != cp2["digest"]
    res = check(tenant_a, require_export=True)
    assert not res.ok and res.completeness == "violated"
    assert any("checkpoint 2 differs between the database and the external copy" in v for v in res.violations)


def test_middle_checkpoint_deletion_and_insertion_are_detected_without_any_anchor(tenant_a, no_export):
    _emit(tenant_a, 1)
    seal(tenant_a)
    _emit(tenant_a, 1)
    seal(tenant_a)
    _emit(tenant_a, 1)
    seal(tenant_a)
    assert check(tenant_a).ok
    delete_checkpoint(tenant_a, 2)
    res = check(tenant_a)
    assert not res.ok and not res.internally_valid
    assert any("index gap" in v for v in res.violations) and any("linkage broken at index 3" in v for v in res.violations)


def test_a_forged_checkpoint_with_a_wrong_previous_digest_is_rejected(tenant_a, no_export):
    _emit(tenant_a, 2)
    seal(tenant_a)
    key_id = get_signer().key_id
    with attacker("audit.checkpoint") as c:
        head = c.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [str(tenant_a.id)]).fetchone()
        c.execute("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature, format_version, cp_index, "
                  "prev_cp_digest) VALUES (%s,%s,%s,now(),%s,'ed25519',%s,2,2,%s)",
                  [str(tenant_a.id), head[0], head[1], key_id, b"\x00" * 64, b"\x11" * 32])
    res = check(tenant_a)
    assert not res.ok and any("linkage broken at index 2" in v for v in res.violations) and any("signature invalid" in v for v in res.violations)


def test_legacy_checkpoints_still_verify_and_are_reported_as_legacy(tenant_a, no_export):
    _emit(tenant_a, 2)
    signer = get_signer()
    with attacker("audit.checkpoint") as c:
        head = c.execute("SELECT seq, last_hash FROM audit.chain_head WHERE stream_key = %s", [str(tenant_a.id)]).fetchone()
        issued = clock.now()
        sig = signer.sign(checkpoint_message(str(tenant_a.id), head[0], bytes(head[1]), issued, signer.key_id))
        c.execute("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature) VALUES (%s,%s,%s,%s,%s,'ed25519',%s)",
                  [str(tenant_a.id), head[0], head[1], issued, signer.key_id, sig])
    res = check(tenant_a)
    assert res.ok and res.checkpoints == {"v2": 0, "legacy": 1}
    assert ts_text(issued)  # the legacy message format is unchanged


# ------------------------------------------------------------------------------------------------ database guard on the sealer role
def test_the_sealer_role_cannot_skip_repeat_rewind_or_downgrade_checkpoints(tenant_a, no_export):
    _emit(tenant_a, 3)
    (cp,) = seal(tenant_a)
    sid, key_id = str(tenant_a.id), get_signer().key_id
    base = ("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature, format_version, cp_index, "
            "prev_cp_digest) VALUES (%s, %s, %s, now(), %s, 'ed25519', %s, %s, %s, %s)")
    head = bytes.fromhex(cp["head_hash"])
    attempts = {
        "skip an index": (cp["seq"], 3, 2),
        "repeat an index": (cp["seq"], 1, 2),
        "move seq backwards": (cp["seq"] - 1, 2, 2),
        "restart at 1": (cp["seq"], 1, 2),
    }
    for label, (seq, idx, fmt) in attempts.items():
        with role_connect("ngrc_audit_sealer") as c, pytest.raises(psycopg.errors.Error):
            c.execute(base, [sid, seq, head, key_id, b"\x00" * 64, fmt, idx, b"\x22" * 32])
        _ = label
    with role_connect("ngrc_audit_sealer") as c, pytest.raises(psycopg.errors.Error) as exc:      # downgrade to the unchained legacy format
        c.execute("INSERT INTO audit.checkpoint (stream_key, seq, head_hash, issued_at, key_id, algorithm, signature) "
                  "VALUES (%s,%s,%s,now(),%s,'ed25519',%s)", [sid, cp["seq"], head, key_id, b"\x00" * 64])
    assert "legacy checkpoint format is closed" in exc.value.diag.message_primary
    with role_connect("ngrc_audit_sealer") as c, pytest.raises(psycopg.errors.Error):             # impossible shape
        c.execute(base, [sid, cp["seq"], head, key_id, b"\x00" * 64, 2, 0, b"\x22" * 32])
    with role_connect("ngrc_audit_sealer") as c:                                                    # control: the correct next row is accepted
        c.execute(base, [sid, cp["seq"], head, key_id, b"\x00" * 64, 2, 2, b"\x22" * 32])
        c.commit()
    assert check(tenant_a).checkpoints["v2"] == 2


def test_concurrent_sealers_publish_each_checkpoint_exactly_once(tenant_a, export):
    _emit(tenant_a, 3)
    out, errors, barrier = [], [], threading.Barrier(4)

    def worker():
        from django.db import connections

        barrier.wait()
        try:
            out.extend(seal(tenant_a))
        except Exception as exc:  # noqa: BLE001 - any failure in a concurrent sealer is a test failure, not a warning
            errors.append(repr(exc))
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert not errors, errors
    assert len(out) == 1 and out[0]["cp_index"] == 1, out           # one winner; the losers exported nothing
    lines = [json.loads(ln) for ln in export.read_text().splitlines() if json.loads(ln)["stream_key"] == str(tenant_a.id)]
    assert len(lines) == 1
    assert check(tenant_a, require_export=True).ok


# ------------------------------------------------------------------------------------------------ verdicts and the high-water mark
def test_verdicts_are_recorded_and_only_successful_runs_move_the_high_water_mark(tenant_a, export):
    two_checkpoints(tenant_a)
    assert verifier.last_hwm(str(tenant_a.id)) is None                # first run: no earlier memory
    r1 = run_recorded(tenant_a, require_export=True)
    assert r1.ok and r1.completeness == "consistent"
    names = {a["name"] for a in r1.anchors}
    assert names == {"external_copy"}                                  # no earlier run yet, freshness not requested
    r2 = run_recorded(tenant_a, require_export=True, require_fresh=True)
    assert {a["name"] for a in r2.anchors} == {"external_copy", "high_water_mark", "freshness"} and r2.completeness == "consistent"
    assert all(not a["tamper_resistant"] for a in r2.anchors), "no anchor is tamper-resistant until an immutable sink exists (O-4)"
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'x' WHERE tenant_id = %s AND seq = 1", [str(tenant_a.id)])
    bad = run_recorded(tenant_a)
    assert not bad.ok and not bad.internally_valid
    with role_connect("ngrc_audit_verifier") as c:
        row = c.execute("SELECT status, details->>'completeness' FROM audit.verification_run WHERE stream_key = %s ORDER BY finished_at DESC LIMIT 1",
                        [str(tenant_a.id)]).fetchone()
    assert row[0] == "violation"


def test_an_immutable_sink_is_the_only_way_to_reach_established(tenant_a, export, monkeypatch):
    two_checkpoints(tenant_a)
    assert check(tenant_a, require_export=True).completeness == "consistent"
    monkeypatch.setattr(settings, "AUDIT_SINK_IMMUTABLE", True)       # what a verified WORM sink configuration would assert
    assert check(tenant_a, require_export=True).completeness == "established"
    from config.settings import base

    assert base.AUDIT_SINK_IMMUTABLE is False, "the shipped default must stay False until a WORM sink exists"


def test_without_a_stale_check_the_residual_window_is_the_checkpoint_interval(tenant_a, no_export):
    """Documented limit: events written after the newest honest checkpoint are covered by chain consistency only until the next checkpoint."""
    _emit(tenant_a, 2)
    seal(tenant_a)
    _emit(tenant_a, 2)                                                 # not yet sealed
    res = check(tenant_a)
    assert res.ok and res.verified_through_seq == 4 and res.checkpoints["v2"] == 1
    assert settings.AUDIT_CHECKPOINT_INTERVAL_S <= 300, "the exposure window is bounded by the heartbeat interval (ADR proposal: 5 minutes)"
