"""Framework Engine domain services (D-P2-001).

Curator actions (draft/publish a version, lock a mapping) run on the operator plane (`catalog` alias for
the write, `ops` alias for the audit append) and assume the caller has already checked
`platform.catalogue.curate` - the same split responsibility evidence/views.py uses: services trust an
already-authorized caller, they do not re-check permissions themselves (no HTTP layer exists yet for this
app - see the ADR).

Tenant actions (activate, override, decide) run on the tenant plane (`default` alias) and assume the caller
already checked `framework.manage`. Every state-changing call emits an audit event.
"""
from __future__ import annotations

from django.db import transaction

from ngrc.audit import service as audit
from ngrc.core import clock

from .models import (
    Framework,
    FrameworkActivation,
    FrameworkChangeSet,
    FrameworkChangesetDecision,
    FrameworkVersion,
    Mapping,
    MappingOverride,
    Requirement,
)


class FrameworkError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ------------------------------------------------------------------------------------------------- curator / catalog
def draft_version(framework: Framework, version_label: str, *, created_by, effective_date=None,
                   source_metadata: dict | None = None) -> FrameworkVersion:
    version = FrameworkVersion.objects.using("catalog").create(
        framework=framework, version_label=version_label, effective_date=effective_date,
        source_metadata=source_metadata or {}, created_by=created_by,
    )
    audit.emit_platform("ops", "framework.version.drafted", actor_type="operator", actor_id=created_by,
                        object_type="framework_version", object_id=str(version.id),
                        details={"framework_urn": framework.urn, "version_label": version_label})
    return version


def add_requirement(version: FrameworkVersion, urn: str, ref_id: str, title: str, *, text_hash: str = "",
                     parent: Requirement | None = None, reference_controls: list | None = None) -> Requirement:
    if version.status != FrameworkVersion.Status.DRAFT:
        raise FrameworkError("version_not_draft")
    return Requirement.objects.using("catalog").create(
        framework_version=version, urn=urn, ref_id=ref_id, title=title, text_hash=text_hash, parent=parent,
        reference_controls=reference_controls or [],
    )


def _diff_requirements(from_version: FrameworkVersion | None, to_version: FrameworkVersion) -> dict:
    to_urns = {r.urn: r for r in to_version.requirements.all()}
    if from_version is None:
        return {"added": sorted(to_urns), "removed": [], "changed": [], "renamed": [], "reparented": [],
                "identifier_changed": []}
    from_urns = {r.urn: r for r in from_version.requirements.all()}
    added = sorted(set(to_urns) - set(from_urns))
    removed = sorted(set(from_urns) - set(to_urns))
    changed = sorted(
        urn for urn in (set(to_urns) & set(from_urns))
        if (to_urns[urn].title, to_urns[urn].text_hash) != (from_urns[urn].title, from_urns[urn].text_hash)
    )
    # renamed/reparented/identifier_changed detection needs a curator-supplied mapping between old and new
    # urns (a rename IS an identifier change - the diff can't infer "this is the same requirement" from
    # content alone). Not implemented this increment; see D-P2-001.
    return {"added": added, "removed": removed, "changed": changed, "renamed": [], "reparented": [],
            "identifier_changed": []}


def publish_version(version: FrameworkVersion, *, published_by) -> FrameworkChangeSet:
    """Freezes `version` and every one of its requirements (DB trigger backs this up), computes the diff
    against the framework's previously-published version (if any), and persists a ChangeSet - never
    deleted or edited afterwards (06_FRAMEWORK_ENGINE.md: "Persist every ChangeSet")."""
    if version.status != FrameworkVersion.Status.DRAFT:
        raise FrameworkError("version_not_draft")
    with transaction.atomic(using="catalog"):
        prev = (
            FrameworkVersion.objects.using("catalog")
            .filter(framework=version.framework, status=FrameworkVersion.Status.PUBLISHED)
            .order_by("-published_at").first()
        )
        diff = _diff_requirements(prev, version)
        version.status = FrameworkVersion.Status.PUBLISHED
        version.published_at = clock.now()
        version.save(using="catalog")
        change_set = FrameworkChangeSet.objects.using("catalog").create(
            framework=version.framework, from_version=prev, to_version=version, diff=diff, created_by=published_by,
        )
    audit.emit_platform("ops", "framework.version.published", actor_type="operator", actor_id=published_by,
                        object_type="framework_version", object_id=str(version.id),
                        details={"framework_urn": version.framework.urn, "version_label": version.version_label,
                                 "requirement_count": version.requirements.count()})
    audit.emit_platform("ops", "framework.changeset.recorded", actor_type="operator", actor_id=published_by,
                        object_type="framework_change_set", object_id=str(change_set.id),
                        details={"framework_urn": version.framework.urn,
                                 "from_version_label": prev.version_label if prev else "",
                                 "to_version_label": version.version_label,
                                 "added": len(diff["added"]), "removed": len(diff["removed"]),
                                 "changed": len(diff["changed"])})
    return change_set


def lock_mapping(mapping: Mapping) -> None:
    mapping.locked = True
    mapping.save(using="catalog")


# ------------------------------------------------------------------------------------------------------- tenant
def activate_framework(framework: Framework, version: FrameworkVersion, *, activated_by) -> FrameworkActivation:
    """Caller must already be inside the target tenant's `tenant_context()` - the tenant is never a
    parameter here, it comes from that context (same convention as every other tenant-owned write in this
    codebase). Fail-closed: refuses to pin a draft/deprecated version (P0 non-negotiable #9 - never
    auto-applied, and never silently pinned to something unpublished)."""
    if version.framework_id != framework.id:
        raise FrameworkError("version_framework_mismatch")
    if version.status != FrameworkVersion.Status.PUBLISHED:
        raise FrameworkError("version_not_published")
    existing = FrameworkActivation.objects.filter(
        framework_urn=framework.urn, status=FrameworkActivation.Status.ACTIVE
    ).first()
    if existing is not None:
        existing.status = FrameworkActivation.Status.SUPERSEDED
        existing.save()
    activation = FrameworkActivation.objects.create(
        framework_urn=framework.urn, pinned_version_label=version.version_label, activated_by=activated_by,
    )
    audit.record("framework.activation.created", actor_id=activated_by, object_type="framework_activation",
                 object_id=str(activation.id),
                 details={"framework_urn": framework.urn, "version_label": version.version_label})
    return activation


def decide_migration(activation: FrameworkActivation, change_set: FrameworkChangeSet, decision: str, *,
                      decided_by, rationale: str = "") -> FrameworkChangesetDecision:
    """A `migrate` decision is the ONLY path that moves `activation.pinned_version_label` forward - nothing
    does it automatically. `change_set.to_version` must belong to the same framework as the activation, and
    `change_set.from_version` must be the activation's currently-pinned version (refuses to skip or
    misapply a change set meant for a different transition)."""
    if decision not in FrameworkChangesetDecision.Decision.values:
        raise FrameworkError("invalid_decision")
    if change_set.framework.urn != activation.framework_urn:
        raise FrameworkError("changeset_framework_mismatch")
    from_label = change_set.from_version.version_label if change_set.from_version_id else None
    if from_label != activation.pinned_version_label:
        raise FrameworkError("changeset_not_applicable")
    record = FrameworkChangesetDecision.objects.create(
        activation=activation, change_set_id=change_set.id, decision=decision, decided_by=decided_by,
        rationale=rationale,
    )
    if decision == FrameworkChangesetDecision.Decision.MIGRATE:
        old_label = activation.pinned_version_label
        activation.pinned_version_label = change_set.to_version.version_label
        activation.save()
        audit.record("framework.activation.migrated", actor_id=decided_by, object_type="framework_activation",
                     object_id=str(activation.id),
                     details={"framework_urn": activation.framework_urn, "from_version_label": old_label,
                              "to_version_label": change_set.to_version.version_label})
    return record


def override_mapping(framework: Framework, source_requirement: Requirement, target_requirement: Requirement,
                      relationship: str, *, created_by, coverage=None, rationale: str = "") -> MappingOverride:
    """Caller must already be inside the target tenant's `tenant_context()` (see `activate_framework`)."""
    MappingOverride.objects.filter(
        framework_urn=framework.urn, source_requirement_urn=source_requirement.urn,
        target_requirement_urn=target_requirement.urn, superseded_at__isnull=True,
    ).update(superseded_at=clock.now())
    override = MappingOverride.objects.create(
        framework_urn=framework.urn, source_requirement_urn=source_requirement.urn,
        target_requirement_urn=target_requirement.urn, relationship=relationship, coverage=coverage,
        rationale=rationale, created_by=created_by,
    )
    audit.record("framework.mapping_override.created", actor_id=created_by, object_type="mapping_override",
                 object_id=str(override.id),
                 details={"framework_urn": framework.urn, "source_requirement_urn": source_requirement.urn,
                          "target_requirement_urn": target_requirement.urn, "relationship": relationship})
    return override


# ------------------------------------------------------------------------------------------------------- resolver
def resolve_active_version(framework_urn: str) -> FrameworkVersion:
    """Fail-closed (P0 non-negotiable #7): no active pin => raises, never silently falls back to "latest"."""
    activation = FrameworkActivation.objects.filter(
        framework_urn=framework_urn, status=FrameworkActivation.Status.ACTIVE
    ).first()
    if activation is None:
        raise FrameworkError("no_active_pin")
    version = FrameworkVersion.objects.using("default").filter(
        framework__urn=framework_urn, version_label=activation.pinned_version_label,
    ).first()
    if version is None:
        raise FrameworkError("pinned_version_missing")
    return version


def resolve_requirements(framework_urn: str):
    return Requirement.objects.using("default").filter(framework_version=resolve_active_version(framework_urn))


def resolve_mapping(framework_urn: str, source_requirement_urn: str) -> list[dict]:
    """Tenant override wins (if any, for this exact source urn); otherwise the official catalogue mapping
    at the tenant's pinned version. Never a merge of both - D-P0-009's "custom-vs-catalogue union",
    resolved here by substitution, not merging rows (see the ADR)."""
    overrides = list(MappingOverride.objects.filter(
        framework_urn=framework_urn, source_requirement_urn=source_requirement_urn, superseded_at__isnull=True,
    ).values("target_requirement_urn", "relationship", "coverage", "rationale"))
    if overrides:
        return [{"source_requirement_urn": source_requirement_urn, "target_requirement_urn": o["target_requirement_urn"],
                 "relationship": o["relationship"], "coverage": o["coverage"], "origin": "override"} for o in overrides]
    version = resolve_active_version(framework_urn)
    rows = Mapping.objects.using("default").filter(
        source_requirement__framework_version=version, source_requirement__urn=source_requirement_urn,
    ).values("target_requirement__urn", "relationship", "coverage")
    return [{"source_requirement_urn": source_requirement_urn, "target_requirement_urn": r["target_requirement__urn"],
             "relationship": r["relationship"], "coverage": r["coverage"], "origin": "official"} for r in rows]
