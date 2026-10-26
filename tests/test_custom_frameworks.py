"""D-P2-003: tenant-authored custom frameworks - immutability, tenant isolation, and the resolver's
kind=custom branch (the "single resolver that unions CAT and TEN sources" D-P0-009 asked for)."""
from __future__ import annotations

import uuid

import pytest

from ngrc.audit import service as audit_service
from ngrc.core.context import tenant_context
from ngrc.framework import services
from ngrc.framework.models import CustomFrameworkVersion, FrameworkActivation

from .conftest import role_connect

pytestmark = pytest.mark.security


def _draft_custom_with_requirements(reqs: list[tuple[str, str, str]], label: str = "v1"):
    """reqs: list of (urn, ref_id, title). Returns (framework, version)."""
    fw = services.draft_custom_framework(f"custom-{uuid.uuid4().hex[:8]}", "Our Internal Framework", created_by=uuid.uuid4())
    version = services.draft_custom_version(fw, label, created_by=uuid.uuid4())
    for urn, ref_id, title in reqs:
        services.add_custom_requirement(version, urn, ref_id, title)
    return fw, version


def test_publish_freezes_custom_version_and_requirements(tenant_a):
    # tenant_context() holds an open transaction on the SAME "default" connection Django uses for the ORM
    # writes above; it must exit (commit) before a SEPARATE raw connection (role_connect) can see the
    # published row - otherwise the second connection still sees the pre-publish, uncommitted state.
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A")])
        services.publish_custom_version(version, published_by=uuid.uuid4())
        uow.flush()
        version.refresh_from_db()
        assert version.status == CustomFrameworkVersion.Status.PUBLISHED

    with role_connect("ngrc_app") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(Exception, match="immutable"):
            c.execute("UPDATE ten_framework_custom_version SET version_label = %s WHERE id = %s",
                      ["tampered", str(version.id)])
        c.rollback()


def test_draft_custom_requirements_are_editable_before_publish(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A")])
        uow.flush()
        req = version.requirements.get(urn="req-a")
        req.title = "edited"
        req.save()
        req.refresh_from_db()
        assert req.title == "edited"


def test_cannot_activate_an_unpublished_custom_version(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A")])
        uow.flush()
        with pytest.raises(services.FrameworkError, match="version_not_published"):
            services.activate_custom_framework(fw, version, activated_by=uuid.uuid4())


def test_activate_custom_framework_then_resolve_requirements(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
        services.publish_custom_version(version, published_by=uuid.uuid4())
        activation = services.activate_custom_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()
        assert activation.kind == FrameworkActivation.Kind.CUSTOM
        urns = {r.urn for r in services.resolve_requirements(fw.urn)}
    assert urns == {"req-a", "req-b"}


def test_resolve_mapping_for_a_custom_framework_without_override_is_empty(tenant_a):
    """No CAT Mapping table backs a custom framework - the only source is a MappingOverride, or nothing."""
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
        services.publish_custom_version(version, published_by=uuid.uuid4())
        services.activate_custom_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()
        resolved = services.resolve_mapping(fw.urn, "req-a")
    assert resolved == []


def test_override_resolves_for_a_custom_framework(tenant_a):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A"), ("req-b", "B.1", "Control B")])
        services.publish_custom_version(version, published_by=uuid.uuid4())
        services.activate_custom_framework(fw, version, activated_by=uuid.uuid4())
        uow.flush()
        req_a = version.requirements.get(urn="req-a")
        req_b = version.requirements.get(urn="req-b")
        services.override_mapping(fw, req_a, req_b, "equal", created_by=uuid.uuid4())
        uow.flush()
        resolved = services.resolve_mapping(fw.urn, "req-a")
    assert resolved == [{"source_requirement_urn": "req-a", "target_requirement_urn": "req-b",
                         "relationship": "equal", "coverage": None, "origin": "override"}]


def test_a_tenant_cannot_see_another_tenants_custom_framework(tenant_a, tenant_b):
    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        fw, version = _draft_custom_with_requirements([("req-a", "A.1", "Control A")])
        uow.flush()
        fw_urn = fw.urn
    with tenant_context(tenant_b.id):
        from ngrc.framework.models import CustomFramework
        assert not CustomFramework.objects.filter(urn=fw_urn).exists()


def test_resolver_distinguishes_catalog_and_custom_activations_for_the_same_urn_shape(tenant_a):
    """A catalog FrameworkActivation and a custom one are different `kind`s even if coincidentally
    pointing at urns with the same shape - the resolver must use the stored `kind`, not guess."""
    from ngrc.framework.models import Framework

    cat_fw = Framework.objects.using("catalog").create(urn=f"cat-{uuid.uuid4().hex[:8]}", name="Catalog FW")
    cat_version = services.draft_version(cat_fw, "v1", created_by=uuid.uuid4())
    services.add_requirement(cat_version, "req-a", "A.1", "Catalog Control A")
    services.publish_version(cat_version, published_by=uuid.uuid4())

    with tenant_context(tenant_a.id), audit_service.unit_of_work(tenant_a.id) as uow:
        services.activate_framework(cat_fw, cat_version, activated_by=uuid.uuid4())
        uow.flush()
        urns = {r.urn for r in services.resolve_requirements(cat_fw.urn)}
    assert urns == {"req-a"}  # resolved from CAT, not mistaken for a custom framework
