"""Evidence application service: validated upload -> immutable revision -> scan -> state (D-P0-007 s5, decision C-6).

Order of an upload (every step fails closed): size-bounded streaming write to a server-generated key -> content inspection against the declared
type -> revision row in `scan_pending` (NOT downloadable) -> scanner verdict -> `collected` or `quarantined`. Orphan objects (stored, then the
request failed before COMMIT) are possible and need a periodic sweep (documented in docs/plans, not implemented).
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import unquote

from django.conf import settings
from django.db.models import Max

from ngrc.audit import service as audit
from ngrc.core import clock

from . import scanner as scanner_mod
from . import sniff, storage
from .models import Evidence, EvidenceRevision


class EvidenceError(Exception):
    def __init__(self, code: str, http: int = 400):
        super().__init__(code)
        self.code, self.http = code, http


_BAD_NAME_CHARS = re.compile(r'[\x00-\x1f\x7f"<>|?*:\\/]')


def clean_filename(raw: str) -> str:
    """Metadata only: percent-decoded, directory parts dropped, control and reserved characters removed, bounded. Never used as a path."""
    name = unquote(raw or "", errors="replace").replace("\\", "/").split("/")[-1]
    name = _BAD_NAME_CHARS.sub("", name).strip(" .")[:200]
    return name or "file"


def upload_revision(evidence: Evidence, user_id, *, filename: str, declared_type: str, read) -> EvidenceRevision:
    """`read(n)` yields the request body in chunks (b'' at the end)."""
    declared = (declared_type or "").split(";")[0].strip().lower()
    if declared not in sniff.ALLOWED:
        raise EvidenceError("type_not_allowed", 415)
    rid = uuid.uuid4()
    key = storage.object_key(evidence.tenant_id, rid)
    store = storage.get_store()
    head, full = bytearray(), (bytearray() if declared in sniff.OOXML else None)

    def chunks():
        while True:
            c = read(storage.CHUNK)
            if not c:
                return
            if len(head) < 8192:
                head.extend(c[: 8192 - len(head)])
            if full is not None:
                full.extend(c)  # bounded: the store aborts once the size limit is exceeded
            yield c

    try:
        size, digest = store.put(key, chunks(), max_bytes=int(settings.EVIDENCE_MAX_BYTES))
    except storage.TooLarge as exc:
        raise EvidenceError("too_large", 413) from exc
    if size == 0:
        store.delete(key)
        raise EvidenceError("empty_file", 400)
    try:
        detected = sniff.inspect(declared, bytes(head), bytes(full) if full is not None else None)
    except sniff.Rejected as exc:
        store.delete(key)
        raise EvidenceError(exc.code, 415) from exc
    try:
        Evidence.objects.select_for_update().get(pk=evidence.pk)  # serialise revision numbering per evidence record
        n = (EvidenceRevision.objects.filter(evidence_id=evidence.pk).aggregate(m=Max("revision_no"))["m"] or 0) + 1
        rev = EvidenceRevision(id=rid, evidence_id=evidence.pk, revision_no=n, filename=clean_filename(filename), declared_type=declared,
                               detected_type=detected, size_bytes=size, sha256=digest, storage_key=key, state="scan_pending", created_by=user_id)
        rev.save(force_insert=True)
    except Exception:
        store.delete(key)
        raise
    audit.record("evidence.revision.added", actor_id=user_id, object_type="evidence_revision", object_id=str(rid),
                 details={"revision_no": n, "size_bytes": size, "detected_type": detected})
    _scan(rev, store, user_id)
    return rev


def _scan(rev: EvidenceRevision, store, user_id) -> None:
    try:
        res = scanner_mod.get_scanner().scan(store.iter_chunks(rev.storage_key))
    except Exception:  # noqa: BLE001 - a scanner failure leaves the revision NOT downloadable (scan_pending) and is audited
        audit.record("evidence.scan.error", actor_id=user_id, object_type="evidence_revision", object_id=str(rev.id), details={"revision_no": rev.revision_no})
        return
    if res.verdict == "clean":
        rev.state = "collected"
        action, details = "evidence.scan.clean", {"revision_no": rev.revision_no}
    elif res.verdict == "infected":
        rev.state = "quarantined"
        action, details = "evidence.scan.quarantined", {"revision_no": rev.revision_no, "detail": res.detail[:100]}
    else:
        audit.record("evidence.scan.error", actor_id=user_id, object_type="evidence_revision", object_id=str(rev.id), details={"revision_no": rev.revision_no})
        return
    rev.scan_detail, rev.scanned_at = res.detail[:100], clock.now()
    rev.save(update_fields=["state", "scan_detail", "scanned_at"])
    audit.record(action, actor_id=user_id, object_type="evidence_revision", object_id=str(rev.id), details=details)
