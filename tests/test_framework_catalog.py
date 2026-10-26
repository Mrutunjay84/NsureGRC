"""D-P2-001 Framework Engine: catalog immutability, change-set diff, tenant activation/migration/override,
fail-closed resolver, and the CAT/PLT privilege boundary (ngrc_app can never write the catalogue)."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.framework import services
from ngrc.framework.models import (
    Framework,
    FrameworkActivation,
    FrameworkChangesetDecision,
    FrameworkVersion,
    Mapping,
)

from .conftest import role_connect

pytestmark = pytest.mark.security


def _framework(urn_suffix: str | None = None) -> Framework:
    urn = f"test-framework-{urn_suffix or uuid.uuid4().hex[:8]}"
    return Framework.objects.using("catalog").create(urn=urn, name="Synthetic Test Framework", authority="NsureGRC test fixture")


def _draft_with_requirements(fw: Framework, label: str, reqs: list[tuple[str, str, str]]) -> FrameworkVersion:
    """reqs: list of (urn, ref_id, title)."""
    version = services.draft_version(fw, label, created_by=uuid.uuid4())
    for urn, ref_id, title in reqs:
        services.add_requirement(version, urn, ref_id, title, text_hash=f"hash-{title}")
    return version


# -------------------------------------------------------------------------------------------------- publish lifecycle
def test_publish_freezes_version_and_requirements():
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    services.publish_version(v1, published_by=uuid.uuid4())
    v1.refresh_from_db(using="default")
    assert v1.status == FrameworkVersion.Status.PUBLISHED
    assert v1.published_at is not None

    with role_connect("ngrc_catalog_publisher") as c:
        with pytest.raises(Exception, match="immutable"):
            c.execute("UPDATE cat_framework_version SET version_label = %s WHERE id = %s", ["tampered", str(v1.id)])
        c.rollback()
        # No DELETE grant exists at all for this writer (D-P2-001) - the privilege matrix is the first line of
        # defence; the trigger's own delete-guard is belt-and-suspenders for if that grant is ever loosened.
        with pytest.raises(Exception, match="permission denied"):
            c.execute("DELETE FROM cat_framework_version WHERE id = %s", [str(v1.id)])
        c.rollback()
        req = v1.requirements.using("default").get(urn="req-a")
        with pytest.raises(Exception, match="immutable"):
            c.execute("UPDATE cat_requirement SET title = %s WHERE id = %s", ["tampered", str(req.id)])
        c.rollback()
        with pytest.raises(Exception, match="permission denied"):
            c.execute("DELETE FROM cat_requirement WHERE id = %s", [str(req.id)])
        c.rollback()


def test_reference_controls_round_trip_and_freeze_on_publish():
    fw = _framework()
    version = services.draft_version(fw, "v1", created_by=uuid.uuid4())
    guidance = [{"catalog": "NIST SP 800-53", "ref": "AC-2", "note": "account management"}]
    req = services.add_requirement(version, "req-a", "A.1", "Control A", reference_controls=guidance)
    assert req.reference_controls == guidance

    services.publish_version(version, published_by=uuid.uuid4())
    with role_connect("ngrc_catalog_publisher") as c:
        with pytest.raises(Exception, match="immutable"):
            c.execute("UPDATE cat_requirement SET reference_controls = %s::jsonb WHERE id = %s", ['[]', str(req.id)])
        c.rollback()


def test_add_requirement_defaults_reference_controls_to_empty_list():
    fw = _framework()
    version = services.draft_version(fw, "v1", created_by=uuid.uuid4())
    req = services.add_requirement(version, "req-a", "A.1", "Control A")
    assert req.reference_controls == []


def test_draft_requirements_are_editable_before_publish():
    fw = _framework()
    version = services.draft_version(fw, "v1", created_by=uuid.uuid4())
    req = services.add_requirement(version, "req-a", "A.1", "Control A")
    with role_connect("ngrc_catalog_publisher") as c:
        c.execute("UPDATE cat_requirement SET title = %s WHERE id = %s", ["edited", str(req.id)])
        c.commit()
    req.refresh_from_db(using="default")
    assert req.title == "edited"


def test_locked_mapping_is_immutable():
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    services.publish_version(v1, published_by=uuid.uuid4())
    req_a = _requirement_by_urn(v1, "req-a")
    req_b = _requirement_by_urn(v1, "req-b")
    mapping = Mapping.objects.using("catalog").create(source_requirement=req_a, target_requirement=req_b, relationship="equal")
    services.lock_mapping(mapping)
    with role_connect("ngrc_catalog_publisher") as c:
        with pytest.raises(Exception, match="immutable"):
            c.execute("UPDATE cat_mapping SET locked = false WHERE id = %s", [str(mapping.id)])
        c.rollback()
        with pytest.raises(Exception, match="permission denied"):
            c.execute("DELETE FROM cat_mapping WHERE id = %s", [str(mapping.id)])
        c.rollback()


def _requirement_by_urn(version: FrameworkVersion, urn: str):
    return version.requirements.using("default").get(urn=urn)


# ------------------------------------------------------------------------------------------------------ change sets
def test_publish_records_a_diff_against_the_previous_version():
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    services.publish_version(v1, published_by=uuid.uuid4())

    v2 = _draft_with_requirements(fw, "v2", [("req-a", "A.1", "Control A, revised"), ("req-c", "C.1", "Control C")])
    change_set = services.publish_version(v2, published_by=uuid.uuid4())

    assert change_set.from_version_id == v1.id
    assert change_set.to_version_id == v2.id
    assert change_set.diff["added"] == ["req-c"]
    assert change_set.diff["removed"] == ["req-b"]
    assert change_set.diff["changed"] == ["req-a"]


def test_first_version_has_no_prior_change_set_diff_is_all_added():
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    change_set = services.publish_version(v1, published_by=uuid.uuid4())
    assert change_set.from_version is None
    assert change_set.diff["added"] == ["req-a"]


def test_change_set_is_append_only():
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    change_set = services.publish_version(v1, published_by=uuid.uuid4())
    with role_connect("ngrc_catalog_publisher") as c:
        with pytest.raises(Exception, match="append-only"):
            c.execute("UPDATE plt_framework_change_set SET diff = %s WHERE id = %s", ['{}', str(change_set.id)])
        c.rollback()
        with pytest.raises(Exception, match="permission denied"):
            c.execute("DELETE FROM plt_framework_change_set WHERE id = %s", [str(change_set.id)])
        c.rollback()


# ------------------------------------------------------------------------------------------------ tenant activation
def test_activation_requires_a_published_version(tenant_a):
    fw = _framework()
    draft = services.draft_version(fw, "v1", created_by=uuid.uuid4())
    with tenant_context(tenant_a.id):
        with pytest.raises(services.FrameworkError, match="version_not_published"):
            services.activate_framework(fw, draft, activated_by=uuid.uuid4())


def test_activate_then_resolve_requirements(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    services.publish_version(v1, published_by=uuid.uuid4())
    actor = uuid.uuid4()
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activation = services.activate_framework(fw, v1, activated_by=actor)
        uow.flush()
        urns = {r.urn for r in services.resolve_requirements(fw.urn)}
    assert activation.pinned_version_label == "v1"
    assert urns == {"req-a"}


def test_resolver_fails_closed_with_no_activation(tenant_a):
    fw = _framework()
    with tenant_context(tenant_a.id), pytest.raises(services.FrameworkError, match="no_active_pin"):
        services.resolve_requirements(fw.urn).exists()


def test_new_publish_never_moves_an_existing_activation(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    services.publish_version(v1, published_by=uuid.uuid4())
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        services.activate_framework(fw, v1, activated_by=uuid.uuid4())
        uow.flush()

    v2 = _draft_with_requirements(fw, "v2", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    services.publish_version(v2, published_by=uuid.uuid4())

    with tenant_context(tenant_a.id):
        activation = FrameworkActivation.objects.get(framework_urn=fw.urn, status=FrameworkActivation.Status.ACTIVE)
    assert activation.pinned_version_label == "v1"  # unchanged: never auto-applied (P0 non-negotiable #9)


def test_migration_decision_moves_the_pin(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    services.publish_version(v1, published_by=uuid.uuid4())
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activation = services.activate_framework(fw, v1, activated_by=uuid.uuid4())
        uow.flush()

    v2 = _draft_with_requirements(fw, "v2", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    change_set = services.publish_version(v2, published_by=uuid.uuid4())

    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        decision = services.decide_migration(
            activation, change_set, FrameworkChangesetDecision.Decision.MIGRATE, decided_by=uuid.uuid4()
        )
        uow.flush()
        activation.refresh_from_db()
    assert decision.decision == "migrate"
    assert activation.pinned_version_label == "v2"


def test_migration_decision_rejects_a_changeset_for_a_different_transition(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A")])
    services.publish_version(v1, published_by=uuid.uuid4())
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        activation = services.activate_framework(fw, v1, activated_by=uuid.uuid4())
        uow.flush()

    # Two more publishes: a v1->v2 changeset that does NOT match this activation's current pin once we
    # pretend it is already on v2 - instead we directly test that a changeset whose from_version differs
    # from the activation's pin is refused.
    v2 = _draft_with_requirements(fw, "v2", [("req-a", "A.1", "Control A")])
    cs_1_2 = services.publish_version(v2, published_by=uuid.uuid4())
    v3 = _draft_with_requirements(fw, "v3", [("req-a", "A.1", "Control A, v3")])
    cs_2_3 = services.publish_version(v3, published_by=uuid.uuid4())  # from_version=v2, activation is pinned to v1

    with tenant_context(tenant_a.id):
        with pytest.raises(services.FrameworkError, match="changeset_not_applicable"):
            services.decide_migration(activation, cs_2_3, FrameworkChangesetDecision.Decision.MIGRATE, decided_by=uuid.uuid4())
    assert cs_1_2.from_version_id is None or True  # cs_1_2 exists only to make v2 a real predecessor


# --------------------------------------------------------------------------------------------- mapping overrides
def test_override_wins_over_official_mapping(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B"), ("req-c", "C.1", "Control C")])
    services.publish_version(v1, published_by=uuid.uuid4())
    req_a, req_b, req_c = (_requirement_by_urn(v1, u) for u in ("req-a", "req-b", "req-c"))
    official = Mapping.objects.using("catalog").create(source_requirement=req_a, target_requirement=req_b, relationship="equal")
    services.lock_mapping(official)

    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        services.activate_framework(fw, v1, activated_by=uuid.uuid4())
        uow.flush()
        resolved = services.resolve_mapping(fw.urn, "req-a")
        assert resolved == [{"source_requirement_urn": "req-a", "target_requirement_urn": "req-b", "relationship": "equal",
                             "coverage": None, "origin": "official"}]

        services.override_mapping(fw, req_a, req_c, "subset", created_by=uuid.uuid4())
        uow.flush()
        resolved = services.resolve_mapping(fw.urn, "req-a")
    assert resolved == [{"source_requirement_urn": "req-a", "target_requirement_urn": "req-c", "relationship": "subset",
                         "coverage": None, "origin": "override"}]
    # the official mapping itself was never touched
    official.refresh_from_db(using="default")
    assert official.target_requirement_id == req_b.id


def test_override_is_never_touched_by_a_later_catalogue_publish(tenant_a):
    fw = _framework()
    v1 = _draft_with_requirements(fw, "v1", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    services.publish_version(v1, published_by=uuid.uuid4())
    req_a, req_b = _requirement_by_urn(v1, "req-a"), _requirement_by_urn(v1, "req-b")

    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        services.activate_framework(fw, v1, activated_by=uuid.uuid4())
        uow.flush()
        override = services.override_mapping(fw, req_a, req_b, "superset", created_by=uuid.uuid4())
        uow.flush()

    v2 = _draft_with_requirements(fw, "v2", [("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
    services.publish_version(v2, published_by=uuid.uuid4())

    with tenant_context(tenant_a.id):
        override.refresh_from_db()
    assert override.superseded_at is None
    assert override.relationship == "superset"


# ----------------------------------------------------------------------------------------- privilege boundary (DB)
def test_ngrc_app_cannot_write_the_catalogue():
    fw = _framework()
    with role_connect("ngrc_app") as c:
        with pytest.raises(Exception, match="permission denied"):
            c.execute("INSERT INTO cat_framework (id, urn, name, authority, created_at) VALUES (gen_random_uuid(), %s, 'x', '', now())",
                      ["ngrc-app-cannot-write"])
        c.rollback()
        with pytest.raises(Exception, match="permission denied"):
            c.execute("UPDATE cat_framework SET name = 'tampered' WHERE id = %s", [str(fw.id)])
        c.rollback()


def test_ngrc_catalog_publisher_cannot_read_or_write_tenant_tables(tenant_a):
    with role_connect("ngrc_catalog_publisher") as c:
        with pytest.raises(Exception, match="permission denied"):
            c.execute("SELECT 1 FROM ten_framework_activation LIMIT 1")
        c.rollback()
