"""F-AUD-007 - scheduled audit verification (D-P0-006 s6): runs as the verifier identity, records every run, alerts on violations, and treats
silence as a failure (watchdog). Streams are always restricted to the test's own tenant (+ the platform stream) so other tests' deliberately
tampered tenants do not leak into the verdict.
"""
import json
from pathlib import Path

import pytest
from django.conf import settings
from django.core.management import call_command
from django.urls import Resolver404, resolve

from ngrc.audit import alerts, scheduler, sealer, service, verifier
from ngrc.audit.signer import get_signer
from ngrc.authz import permissions
from ngrc.core import clock

from .conftest import role_connect
from .helpers import audit_events
from .test_audit_integrity import _emit, attacker

pytestmark = pytest.mark.security


@pytest.fixture(autouse=True)
def _clean_alerts():
    alerts.recorder.reset()


@pytest.fixture
def export(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", str(tmp_path))
    return Path(tmp_path) / "checkpoints.jsonl"


def prepared(tenant, n=3):
    _emit(tenant, n)
    service.emit_platform("auth", "auth.logout", actor_type="user")   # make sure the platform stream exists, wherever this test runs
    sealer.seal_all(streams=[str(tenant.id), "platform"])


def run(tenant, **kw):
    return scheduler.run_scheduled_verification(tenant_ids=[str(tenant.id)], **kw)


def runs_of(tenant):
    with role_connect("ngrc_audit_verifier") as c:
        return c.execute("SELECT status, details->>'mode', details->>'completeness' FROM audit.verification_run WHERE stream_key = %s ORDER BY finished_at",
                         [str(tenant.id)]).fetchall()


def test_a_scheduled_run_verifies_each_stream_records_each_result_and_writes_a_summary_event(tenant_a, export):
    prepared(tenant_a)
    s = run(tenant_a)
    assert s.streams_checked == 2 and s.recorded_runs == 2 and s.violations == 0 and s.exit_code == 0, [r.violations for r in s.results]
    assert [r[0] for r in runs_of(tenant_a)] == ["ok"] and runs_of(tenant_a)[0][1] == "full"
    ev = [e for e in audit_events(platform=True, action="audit.verification.completed") if '"mode":"full"' in e["details"].replace(" ", "")]
    assert ev and json.loads(ev[-1]["details"])["violations"] == 0 and ev[-1]["actor_type"] == "service"


def test_a_scheduled_run_detects_tampering_records_it_alerts_and_exits_non_zero(tenant_a, export):
    prepared(tenant_a)
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'tampered' WHERE tenant_id = %s AND seq = 2", [str(tenant_a.id)])
    s = run(tenant_a)
    assert s.violations >= 1 and s.exit_code == 1
    assert [r[0] for r in runs_of(tenant_a)] == ["violation"]
    assert any(e["details"] and str(tenant_a.id)[:40] in e["details"] for e in audit_events(platform=True, action="audit.integrity_violation"))
    assert any(a.kind == "integrity_violation" and a.severity == "critical" and a.stream == str(tenant_a.id)[:40] for a in alerts.recorder.sent)
    assert [e for e in audit_events(platform=True, action="audit.verification.completed") if e["result"] == "failure"]


def test_silence_is_an_alert_the_watchdog_raises_when_no_run_is_recorded(tenant_a, export, clock_ctl):
    prepared(tenant_a)
    run(tenant_a)
    assert scheduler.check_verification_freshness() is True and not [a for a in alerts.recorder.sent if a.kind == "verification_overdue"]
    clock_ctl.advance(hours=settings.AUDIT_VERIFY_MAX_AGE_HOURS + 1)
    assert scheduler.check_verification_freshness() is False
    assert any(a.kind == "verification_overdue" and a.severity == "critical" for a in alerts.recorder.sent)
    assert audit_events(platform=True, action="audit.verification.overdue")


def test_the_watchdog_is_a_separate_entry_point_and_the_command_maps_it_to_the_exit_code(tenant_a, export, clock_ctl):
    prepared(tenant_a)
    run(tenant_a)
    with pytest.raises(SystemExit) as ok:
        call_command("audit_verify", "--check-freshness")
    assert ok.value.code == 0
    clock_ctl.advance(hours=settings.AUDIT_VERIFY_MAX_AGE_HOURS + 1)
    with pytest.raises(SystemExit) as late:
        call_command("audit_verify", "--check-freshness")
    assert late.value.code == 1


def test_incremental_runs_agree_with_full_runs_on_clean_data_and_catch_new_tampering(tenant_a, export):
    prepared(tenant_a, 3)
    full = run(tenant_a, mode="full")
    assert full.exit_code == 0
    _emit(tenant_a, 2)
    sealer.seal_all(streams=[str(tenant_a.id)])
    inc = run(tenant_a, mode="incremental")
    assert inc.exit_code == 0 and [r.mode for r in inc.results if r.stream_key == str(tenant_a.id)] == ["incremental"]
    assert next(r for r in inc.results if r.stream_key == str(tenant_a.id)).tail["seq"] == 5  # 3 + 2 events
    _emit(tenant_a, 1)
    with attacker("audit.tenant_event") as c:
        c.execute("UPDATE audit.tenant_event SET object_id = 'new-tamper' WHERE tenant_id = %s AND seq = (SELECT max(seq) FROM audit.tenant_event WHERE tenant_id = %s)",
                  [str(tenant_a.id), str(tenant_a.id)])
    assert run(tenant_a, mode="incremental").exit_code == 1  # tampering AFTER the recorded tail is caught incrementally
    assert run(tenant_a, mode="full").exit_code == 1


def test_documented_limit_an_in_place_edit_of_an_old_event_needs_a_full_run(tenant_a, export):
    prepared(tenant_a, 3)
    assert run(tenant_a, mode="full").exit_code == 0
    with attacker("audit.tenant_event") as c:   # content changed, stored hash left alone: only recomputation notices
        c.execute("UPDATE audit.tenant_event SET object_id = 'old-edit' WHERE tenant_id = %s AND seq = 1", [str(tenant_a.id)])
    assert run(tenant_a, mode="incremental").exit_code == 0, "incremental mode does not recompute events it already verified (documented trade-off)"
    assert run(tenant_a, mode="full").exit_code == 1, "the periodic FULL run is what closes that gap"


def test_the_job_only_runs_as_the_verifier_identity(tenant_a, export, monkeypatch):
    assert scheduler.database_identity() == "ngrc_audit_verifier"
    monkeypatch.setattr(scheduler, "database_identity", lambda: "ngrc_owner")
    with pytest.raises(scheduler.WrongIdentity):
        run(tenant_a)


@pytest.mark.parametrize("path", ["/api/v1/tenant/audit/verification/", "/api/v1/tenant/audit/verification/disable/", "/api/v1/tenant/audit/verify/",
                                  "/api/v1/tenant/settings/audit/"])
def test_no_tenant_route_can_configure_pause_or_disable_verification(path):
    with pytest.raises(Resolver404):
        resolve(path)
    assert not [k for k in permissions.all_permissions() if "verif" in k]


def test_production_mode_requires_the_external_copy_and_an_independent_anchor(tenant_a, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_CHECKPOINT_EXPORT_DIR", "")
    monkeypatch.setattr(settings, "AUDIT_REQUIRE_EXTERNAL_COPY", True)
    prepared(tenant_a)
    s = run(tenant_a)
    assert s.exit_code == 1 and any("no externally exported checkpoints" in v for r in s.results for v in r.violations)
    monkeypatch.setattr(settings, "AUDIT_REQUIRE_EXTERNAL_COPY", False)
    monkeypatch.setattr(settings, "AUDIT_REQUIRE_COMPLETENESS", True)
    s2 = run(tenant_a)   # freshness anchors the stream, so completeness is 'consistent' and the run passes
    assert s2.exit_code == 0 and set(s2.completeness) <= {"consistent"}


def test_public_keys_come_from_configuration_so_the_verifier_needs_no_private_key(tenant_a, export, monkeypatch):
    prepared(tenant_a)
    signer = get_signer()
    monkeypatch.setattr(settings, "AUDIT_PUBLIC_KEYS", {signer.key_id: signer.public_key_raw().hex()})
    monkeypatch.setattr(settings, "AUDIT_SIGNER_BACKEND", "kms")      # a verifier host that has no dev key file at all
    assert scheduler.published_public_keys() == {signer.key_id: signer.public_key_raw()}
    assert run(tenant_a).exit_code == 0
    monkeypatch.setattr(settings, "AUDIT_PUBLIC_KEYS", {signer.key_id: ("00" * 32)})
    assert run(tenant_a).exit_code == 1
    monkeypatch.setattr(settings, "AUDIT_PUBLIC_KEYS", {})
    with pytest.raises(RuntimeError, match="no audit public keys"):
        scheduler.published_public_keys()


def test_the_seal_command_issues_checkpoints_and_a_heartbeat(tenant_a, export, clock_ctl):
    _emit(tenant_a, 2)
    call_command("audit_seal")
    clock_ctl.advance(seconds=settings.AUDIT_CHECKPOINT_INTERVAL_S + 1)
    sealer.seal_all(streams=[str(tenant_a.id)])
    rows = [json.loads(ln) for ln in export.read_text().splitlines() if json.loads(ln)["stream_key"] == str(tenant_a.id)]
    assert [r["cp_index"] for r in rows] == [1, 2] and rows[1]["heartbeat"] is True


def test_alert_details_may_not_carry_secrets_and_a_failing_sink_never_breaks_the_caller(monkeypatch):
    with pytest.raises(ValueError):
        alerts.Alert(kind="x", severity="warning", message="m", details={"password_hint": "x"})
    with pytest.raises(ValueError):
        alerts.Alert(kind="x", severity="warning", message="m", details={"user_email": "a@b"})
    monkeypatch.setattr(settings, "ALERT_SINKS", ["log", "memory"])
    boom = {"log": lambda a: (_ for _ in ()).throw(RuntimeError("sink down")), "memory": alerts.recorder.sent.append}
    monkeypatch.setattr(alerts, "_SINKS", boom)
    alerts.notify(alerts.Alert(kind="k", severity="critical", message="still delivered to the other sink"))
    assert [a.kind for a in alerts.recorder.sent] == ["k"]


def test_verified_clock_used_by_the_scheduler_is_the_shared_one():
    assert scheduler.clock is clock and verifier.clock is clock
