"""Framework Engine core catalog (D-P2-001). CAT/PLT classes write through the `catalog` alias
(`ngrc_catalog_publisher`); only `ngrc_app` may SELECT them. TEN classes are the usual tenant-owned shape
(D-P0-009). See `00_CONTROL/PHASE2/D-P2-001_Framework_Engine_Core_Catalog.md` for the full design and the
explicit list of what this increment does NOT implement (live ingestion, custom frameworks, notifications)."""
from __future__ import annotations

import uuid

from django.db import models

from ngrc.core.models import ClassifiedModel, TenantOwnedModel


class Relationship(models.TextChoices):
    EQUAL = "equal"
    SUPERSET = "superset"
    SUBSET = "subset"
    INTERSECT = "intersect"
    NOT_RELATED = "not_related"


# --------------------------------------------------------------------------------------------------------- CAT
class Framework(ClassifiedModel):
    ngrc_class = "CAT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    urn = models.SlugField(max_length=200, unique=True)
    name = models.CharField(max_length=200)
    authority = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cat_framework"


class FrameworkVersion(ClassifiedModel):
    ngrc_class = "CAT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    class Status(models.TextChoices):
        DRAFT = "draft"
        PUBLISHED = "published"
        DEPRECATED = "deprecated"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(Framework, on_delete=models.PROTECT, related_name="versions")
    version_label = models.CharField(max_length=64)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.DRAFT)
    effective_date = models.DateField(null=True)
    published_at = models.DateTimeField(null=True)
    checksum = models.CharField(max_length=64, blank=True)
    source_metadata = models.JSONField(default=dict)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cat_framework_version"
        constraints = [
            models.UniqueConstraint(fields=["framework", "version_label"], name="cat_framework_version_label_uniq"),
        ]


class Requirement(ClassifiedModel):
    ngrc_class = "CAT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT, related_name="requirements")
    urn = models.SlugField(max_length=250)
    ref_id = models.CharField(max_length=64)
    title = models.CharField(max_length=300)
    text_hash = models.CharField(max_length=64, blank=True)
    parent = models.ForeignKey("self", on_delete=models.PROTECT, null=True, related_name="children")
    # Curator-authored informative guidance (e.g. [{"catalog": "NIST SP 800-53", "ref": "AC-2", "note": "..."}]).
    # Not validated against any real external catalog - none is integrated (D-P2-001 addendum). Frozen by the
    # same cat_requirement_guard trigger once the version is published - no trigger change needed.
    reference_controls = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cat_requirement"
        constraints = [
            models.UniqueConstraint(fields=["framework_version", "urn"], name="cat_requirement_urn_uniq"),
        ]


class Mapping(ClassifiedModel):
    ngrc_class = "CAT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, related_name="mappings_from")
    target_requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, related_name="mappings_to")
    relationship = models.CharField(max_length=12, choices=Relationship.choices)
    coverage = models.IntegerField(null=True)  # 0-100, optional (service-validated)
    origin = models.CharField(max_length=20, default="official")
    confidence = models.CharField(max_length=20, blank=True)
    review_state = models.CharField(max_length=20, default="reviewed")
    locked = models.BooleanField(default=False)
    rationale = models.TextField(blank=True)
    valid_from = models.DateField(null=True)
    valid_to = models.DateField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "cat_mapping"
        constraints = [
            models.UniqueConstraint(fields=["source_requirement", "target_requirement"], name="cat_mapping_pair_uniq"),
        ]


# --------------------------------------------------------------------------------------------------------- PLT
class FrameworkChangeSet(ClassifiedModel):
    """Persisted permanently; never edited or deleted once created (D-P2-001)."""

    ngrc_class = "PLT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(Framework, on_delete=models.PROTECT, related_name="change_sets")
    from_version = models.ForeignKey(
        FrameworkVersion, on_delete=models.PROTECT, null=True, related_name="change_sets_from"
    )
    to_version = models.ForeignKey(FrameworkVersion, on_delete=models.PROTECT, related_name="change_sets_to")
    diff = models.JSONField(default=dict)  # {added, removed, changed, renamed, reparented, identifier_changed}
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)  # = the moment to_version was published (same transaction)

    class Meta:
        db_table = "plt_framework_change_set"


class SourceRegistryEntry(ClassifiedModel):
    """Metadata for one external source (D-P2-001 stub; first real use in D-P2-002). `last_payload_sha256`
    backs the "24h Conditional Check": a fetch that hashes the same as last time produces no new draft."""

    ngrc_class = "PLT"
    ngrc_read_db = "default"
    ngrc_write_db = "catalog"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(Framework, on_delete=models.PROTECT, related_name="source_registry_entries")
    authority = models.CharField(max_length=200)
    canonical_url = models.URLField(max_length=500, blank=True)
    licence_note = models.CharField(max_length=300, blank=True)
    last_checked_at = models.DateTimeField(null=True)
    last_payload_sha256 = models.CharField(max_length=64, blank=True)

    class Meta:
        db_table = "plt_framework_source_registry"


# --------------------------------------------------------------------------------------------------------- TEN
# D-P0-009 s2.3: "TEN -> CAT references use stable keys (URN + version), not mutable foreign data" - these
# rows store urns/version labels, never an ORM ForeignKey into a cat_* table. The service layer resolves
# and validates them against the catalog; the DB does not enforce a cross-class FK here by design.
class FrameworkActivation(TenantOwnedModel):
    class Status(models.TextChoices):
        ACTIVE = "active"
        SUPERSEDED = "superseded"

    framework_urn = models.SlugField(max_length=200)
    pinned_version_label = models.CharField(max_length=64)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    activated_by = models.UUIDField(null=True)
    activated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ten_framework_activation"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_framework_activation_tenant_id_uniq"),
        ]


class MappingOverride(TenantOwnedModel):
    framework_urn = models.SlugField(max_length=200)
    source_requirement_urn = models.SlugField(max_length=250)
    target_requirement_urn = models.SlugField(max_length=250)
    relationship = models.CharField(max_length=12, choices=Relationship.choices)
    coverage = models.IntegerField(null=True)
    rationale = models.TextField(blank=True)
    created_by = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    superseded_at = models.DateTimeField(null=True)

    class Meta:
        db_table = "ten_mapping_override"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "id"], name="ten_mapping_override_tenant_id_uniq"),
        ]


class FrameworkChangesetDecision(TenantOwnedModel):
    class Decision(models.TextChoices):
        MIGRATE = "migrate"
        STAY = "stay"
        REJECT = "reject"

    activation = models.ForeignKey(FrameworkActivation, on_delete=models.PROTECT, related_name="+")
    change_set_id = models.UUIDField()  # PLT reference by stable key, not ORM relation (D-P0-009 s2)
    decision = models.CharField(max_length=10, choices=Decision.choices)
    decided_by = models.UUIDField(null=True)
    decided_at = models.DateTimeField(auto_now_add=True)
    rationale = models.TextField(blank=True)

    class Meta:
        db_table = "ten_framework_changeset_decision"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "id"], name="ten_framework_changeset_decision_tenant_id_uniq"
            ),
        ]
