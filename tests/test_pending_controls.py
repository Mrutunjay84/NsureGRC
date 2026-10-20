"""P2-3: executable specifications for controls that are NOT IMPLEMENTED or BLOCKED, plus runnable demonstrations of dev-only gaps.

Nothing in this file is evidence that a control works. Every test is `xfail(strict=True)`; the outcome is reported as XFAIL, which the
reports count as "not implemented / gap demonstrated", never as a pass. See tests/pending.py for the guard rails and
docs/plans/P2-3_IMPLEMENTATION_PLANS.md for the interface each spec commits to and the definition of done.

Two kinds of test live here:
* SPEC - written against a not-yet-existing interface; stops at `require_route` / `require_symbol` with FeatureAbsent.
* GAP DEMO - runs today against the dev-only stand-in and fails an assertion that states the production property
  (xfail(raises=AssertionError)); it is real execution that proves the stand-in does NOT provide that property.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from django.conf import settings

from ngrc.audit import sealer, service
from ngrc.audit.signer import get_signer
from ngrc.core import crypto
from ngrc.core.context import tenant_context

from .helpers import audit_events
from .pending import pending, require_route, require_symbol

pytestmark = pytest.mark.security

PLAN = "docs/plans/P2-3_IMPLEMENTATION_PLANS.md"


# ================================================================================================ 6. production KMS (F-DAT-006, O-4, BLOCKED)
KM = "F-DAT-006"


def _kms_provider():
    return require_symbol("ngrc.core.keys:KmsKeyProvider")  # selected with hosting (O-4); interface per plan section 6


@pending(KM, f"{PLAN} section 6")
def test_kms_provider_envelope_round_trip_and_aad_binding():
    p = _kms_provider()()
    blob = p.seal(b"payload", b"tenant|record|field")
    assert p.open(blob, b"tenant|record|field") == b"payload"
    with pytest.raises(Exception):  # noqa: B017,PT011 - any authentication failure; exact type is provider specific
        p.open(blob, b"other-tenant|record|field")


@pending(KM, f"{PLAN} section 6")
def test_kms_provider_keeps_old_ciphertext_readable_after_rotation():
    p = _kms_provider()()
    old = p.seal(b"before", b"aad")
    p.rotate()  # new key version becomes current; the old one stays available for decryption
    assert p.open(old, b"aad") == b"before" and p.key_id(p.seal(b"after", b"aad")) != p.key_id(old)


@pending(KM, f"{PLAN} section 6")
def test_kms_signer_is_sign_only_and_the_private_key_is_not_exportable():
    signer = require_symbol("ngrc.audit.signer:KmsSigner")()
    sig = signer.sign(b"message")
    assert signer.verify(sig, b"message") and not hasattr(signer, "_key")
    assert not hasattr(signer, "private_bytes") and not hasattr(signer, "export_private_key")


@pending(KM, f"{PLAN} section 6")
def test_production_settings_start_only_with_kms_backends_and_hold_no_key_material(monkeypatch):
    load = require_symbol("config.settings.prod_check:validate")
    monkeypatch.setenv("NGRC_KEY_PROVIDER", "kms")
    monkeypatch.setenv("NGRC_AUDIT_SIGNER_BACKEND", "kms")
    assert load().ok and "FIELD_ENCRYPTION_KEY" not in load().loaded_secret_names


@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - dev-only local key provider has no key versions/rotation (F-DAT-006, O-4)")
def test_gap_demo_ciphertext_cannot_be_read_after_a_master_key_change():
    """GAP DEMO (runs now): the dev provider has a single master key and ignores the key id stored beside the ciphertext, so rotation
    would orphan existing data. This is why rotation is a plan item and why the local provider is DEV-ONLY."""
    blob = crypto.seal(b"x", b"aad")
    original = settings.FIELD_ENCRYPTION_KEY
    try:
        settings.FIELD_ENCRYPTION_KEY = base64.b64encode(os.urandom(32)).decode()
        try:
            opened = crypto.open_sealed(blob, b"aad")
        except Exception:  # noqa: BLE001 - InvalidTag: the property being demonstrated is "this fails"
            opened = None
    finally:
        settings.FIELD_ENCRYPTION_KEY = original
    assert opened == b"x", "old ciphertext must stay readable after rotation (not provided by the DEV-ONLY local provider)"




@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - DevFileSigner key is a plain file (DEV-ONLY); KMS signer NOT IMPLEMENTED (O-4)")
def test_gap_demo_dev_signing_key_is_readable_by_the_process_that_signs():
    """GAP DEMO (runs now): the dev signer's private key is a file the application process can read, so a host-level attacker (or an
    application RCE) could mint valid checkpoints. A KMS/HSM sign-only key must not be readable by the application at all."""
    get_signer()
    assert not os.access(settings.AUDIT_SIGNER_KEY_PATH, os.R_OK), "signing key must not be readable by the application"




# ================================================================================================ 7. immutable audit storage (F-AUD-006, O-4, BLOCKED)
WM = "F-AUD-006"


def _sink():
    return require_symbol("ngrc.audit.sinks:WormSink")  # object-lock bucket in a separate account (selected with O-4)


@pending(WM, f"{PLAN} section 7")
def test_worm_sink_refuses_overwrite_delete_and_truncate_of_a_published_checkpoint():
    s = _sink()()
    receipt = s.append({"stream_key": "platform", "seq": 1, "head_hash": "00" * 32})
    for attempt in (lambda: s.append({"stream_key": "platform", "seq": 1, "head_hash": "11" * 32}),  # same key, different content
                    lambda: s.delete(receipt), lambda: s.truncate("platform")):
        with pytest.raises(Exception):  # noqa: B017,PT011 - provider-specific refusal
            attempt()
    assert s.read(receipt)["head_hash"] == "00" * 32


@pending(WM, f"{PLAN} section 7")
def test_sink_uses_credentials_the_application_database_and_runtime_roles_do_not_hold():
    s = _sink()()
    assert s.writer_identity != s.reader_identity and s.writer_identity not in {"ngrc_app", "ngrc_ops", "ngrc_owner"}
    assert s.account_id != s.application_account_id  # separate failure domain (D-P0-004 / D-P0-006)


@pending(WM, f"{PLAN} section 7")
def test_sealer_does_not_report_a_checkpoint_published_until_the_sink_acknowledges_it(tenant_a, monkeypatch):
    sinks = require_symbol("ngrc.audit.sinks:get_sink")
    monkeypatch.setattr(sinks(), "append", lambda *a, **k: (_ for _ in ()).throw(OSError("sink unavailable")))
    with tenant_context(tenant_a.id):
        service.emit_tenant("default", "tenant.role.created", tenant_a.id, object_type="role", object_id="r",
                            details={"role_key": "k", "permissions": 1})
    result = sealer.seal_all()
    assert all(not r.get("published") for r in result)  # lag alert, but event capture (the business transaction) is unaffected
    assert audit_events(tenant_id=tenant_a.id, action="tenant.role.created")


@pending(WM, f"{PLAN} section 7")
def test_verifier_compares_database_checkpoints_with_the_sink_copy(tenant_a):
    verify = require_symbol("ngrc.audit.sinks:verify_against_sink")
    assert verify(str(tenant_a.id)).ok


def _two_sealed_checkpoints(tenant, tmp_path):
    settings.AUDIT_CHECKPOINT_EXPORT_DIR = str(tmp_path)
    for i in range(2):
        with tenant_context(tenant.id):
            for n in range(2):
                service.emit_tenant("default", "tenant.role.created", tenant.id, object_type="role", object_id=f"r{i}{n}",
                                    details={"role_key": f"k{i}{n}", "permissions": 1})
        sealer.seal_all()
    return Path(tmp_path) / "checkpoints.jsonl"


@pytest.mark.xfail(raises=AssertionError, strict=True, reason="GAP DEMONSTRATED - dev sink is a plain local file, not WORM (F-AUD-006, O-4)")
def test_gap_demo_the_dev_export_file_can_be_rewritten_by_the_application_process(tenant_a, tmp_path):
    """GAP DEMO (runs now): the dev sink is an ordinary file opened for append by the same process that writes the database, so it is not
    write-once. It is explicitly labelled `NOT WORM` in every exported record."""
    original = settings.AUDIT_CHECKPOINT_EXPORT_DIR
    try:
        path = _two_sealed_checkpoints(tenant_a, tmp_path)
        try:
            with open(path, "r+b") as fh:
                fh.write(b"#")
            rewritten = True
        except OSError:
            rewritten = False
    finally:
        settings.AUDIT_CHECKPOINT_EXPORT_DIR = original
    assert not rewritten, "a published checkpoint must be impossible to modify (object lock / retention)"




def test_harness_separates_absent_features_from_broken_specs():
    """Self-test of the harness (RUNS and must PASS): an absent module/route is FeatureAbsent; an existing one resolves. Any other error
    inside a spec therefore shows up as a real failure, not as a silent xfail."""
    from .pending import FeatureAbsent

    with pytest.raises(FeatureAbsent):
        require_symbol("ngrc.this_module_does_not_exist:thing")
    with pytest.raises(FeatureAbsent):
        require_symbol("ngrc.audit.sealer:no_such_function")
    with pytest.raises(FeatureAbsent):
        require_route("/definitely/not/a/route/", prefix="")
    assert callable(require_symbol("ngrc.audit.sealer:seal_all"))
    require_route("/healthz", prefix="")  # an existing route does not raise
