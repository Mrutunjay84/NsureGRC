"""NIST CSF 2.0 ingestion via the official CPRT JSON export (D-P2-002).

Fetch -> parse -> draft only. Publish stays a separate, explicit curator action
(`services.publish_version`) - nothing here auto-publishes. The source URL was verified live during
design: it returns `application/json`, a government work (public domain, no licence question).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ngrc.core import clock
from ngrc.core.net import safe_fetch

from . import services
from .models import Framework, FrameworkVersion, SourceRegistryEntry

CSF_DOC_ID = "CSF_2_0_0"
CSF_URL = (
    "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all"
)
CSF_ALLOWED_HOSTS = frozenset({"csrc.nist.gov"})
URN_PREFIX = "nist-csf-2.0"

_HIERARCHY_TYPES = {"function", "category", "subcategory"}


@dataclass
class ParsedRequirement:
    urn: str
    ref_id: str
    title: str
    parent_urn: str | None
    reference_controls: list[dict] = field(default_factory=list)


@dataclass
class ParsedFramework:
    requirements: list[ParsedRequirement]


def fetch_csf_payload() -> bytes:
    return safe_fetch(CSF_URL, allowed_hosts=CSF_ALLOWED_HOSTS)


def payload_checksum(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_csf_payload(raw: bytes) -> ParsedFramework:
    """Pure, no network. Walks the `projection` relationships to build the function -> category ->
    subcategory hierarchy (the relationship graph is the source of truth; CSF's own id shape, e.g.
    "RS.MA-01" under category "RS.MA" under function "RS", is corroborating, not relied on alone)."""
    data = json.loads(raw)
    elements = {e["element_identifier"]: e for e in data["response"]["elements"]["elements"]}
    relationships = data["response"]["elements"]["relationships"]

    children: dict[str, list[str]] = {}
    for r in relationships:
        if r["relationship_identifier"] == "projection":
            children.setdefault(r["source_element_identifier"], []).append(r["dest_element_identifier"])

    external_refs: dict[str, list[dict]] = {}
    for r in relationships:
        if r["relationship_identifier"] == "external_reference":
            external_refs.setdefault(r["source_element_identifier"], []).append(
                {"catalog": r["dest_doc_identifier"], "ref": r["dest_element_identifier"], "note": ""}
            )

    requirements: list[ParsedRequirement] = []

    def walk(element_id: str, parent_urn: str | None) -> None:
        el = elements.get(element_id)
        if el is None or el["element_type"] not in _HIERARCHY_TYPES:
            return
        title = el["title"] or el["text"]
        guidance = [
            {"catalog": "NIST CSF 2.0 implementation example", "ref": child["element_identifier"], "note": child["text"]}
            for child_id in children.get(element_id, [])
            if (child := elements.get(child_id)) and child["element_type"] == "implementation_example"
        ]
        guidance.extend(external_refs.get(element_id, []))
        urn = f"{URN_PREFIX}:{element_id}"
        requirements.append(ParsedRequirement(urn=urn, ref_id=element_id, title=title, parent_urn=parent_urn,
                                               reference_controls=guidance))
        for child_id in children.get(element_id, []):
            walk(child_id, urn)

    function_ids = sorted(e["element_identifier"] for e in elements.values() if e["element_type"] == "function")
    for fn in function_ids:
        walk(fn, None)

    return ParsedFramework(requirements=requirements)


def build_draft_version(parsed: ParsedFramework, framework: Framework, version_label: str, *, created_by,
                         checksum: str = "") -> FrameworkVersion:
    version = services.draft_version(
        framework, version_label, created_by=created_by,
        source_metadata={"source": "nist_cprt", "doc_identifier": CSF_DOC_ID},
    )
    if checksum:
        version.checksum = checksum
        version.save(using="catalog")
    urn_to_req = {}
    for pr in parsed.requirements:
        parent = urn_to_req.get(pr.parent_urn) if pr.parent_urn else None
        urn_to_req[pr.urn] = services.add_requirement(
            version, pr.urn, pr.ref_id, pr.title, parent=parent, reference_controls=pr.reference_controls,
        )
    return version


def check_csf_source(framework: Framework, *, created_by) -> FrameworkVersion | None:
    """The "24h Conditional Check": fetches, hashes, and only builds a new draft when the payload actually
    changed. Returns the new draft version, or None if nothing changed. Never publishes."""
    raw = fetch_csf_payload()
    checksum = payload_checksum(raw)
    entry, _ = SourceRegistryEntry.objects.using("catalog").get_or_create(
        framework=framework, authority="NIST",
        defaults={"canonical_url": CSF_URL, "licence_note": "US government work (NIST CSWP 29) - public domain"},
    )
    unchanged = bool(entry.last_payload_sha256) and entry.last_payload_sha256 == checksum
    entry.last_checked_at = clock.now()
    if unchanged:
        entry.save(using="catalog")
        return None
    parsed = parse_csf_payload(raw)
    version_label = f"2.0-{checksum[:12]}"
    version = build_draft_version(parsed, framework, version_label, created_by=created_by, checksum=checksum)
    entry.last_payload_sha256 = checksum
    entry.save(using="catalog")
    return version
