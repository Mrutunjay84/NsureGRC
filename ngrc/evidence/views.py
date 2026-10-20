"""Evidence API (decision C-6): authorization-checked, application-streamed downloads - no signed storage URLs - and tenant-scoped search.

Download order (fail closed): policy (`evidence.read`) -> RLS-scoped lookup (foreign or unknown ids are an identical 404) -> Restricted class needs
`evidence.read_restricted` -> only a CLEAN-scanned (`collected`) revision is served -> the stored object is read into a bounded spool and its SHA-256 and size
are verified BEFORE any byte is released (decision D-EV-1, interim: pre-verification) -> the `evidence.downloaded` event is queued on the request's
audit unit of work, which commits (or fails the request) before the response body is streamed.
"""
from __future__ import annotations

import logging
import re
import tempfile
from hashlib import sha256
from urllib.parse import quote

from django.conf import settings
from django.db import connections
from django.http import StreamingHttpResponse
from rest_framework import serializers
from rest_framework.response import Response

from ngrc.audit import alerts
from ngrc.audit import service as audit
from ngrc.authz.drf import NgrcAPIView, Policy
from ngrc.authz.policy import resolve_tenant_authz

from . import service, storage
from .models import Evidence, EvidenceRevision

log = logging.getLogger("ngrc.evidence")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _err(code: str, http: int = 400) -> Response:
    return Response({"error": code}, status=http)


def _missing(request) -> Response:
    """Identical 404 for unknown, foreign-tenant and unreadable-Restricted ids - and an audit trail of the attempt (BOLA/IDOR probing)."""
    p = request.user
    audit.emit_denied(permission="evidence.read", route=request.path, reason="object_not_found", tenant_id=p.tenant_id, actor_id=p.account_id,
                      using="autonomous")
    return _err("not_found", 404)


def _can_restricted(request) -> bool:
    return "evidence.read_restricted" in resolve_tenant_authz(request.user).permissions


def _evidence_json(e: Evidence) -> dict:
    return {"id": str(e.id), "title": e.title, "description": e.description, "data_class": e.data_class, "created_at": e.created_at.isoformat()}


def _revision_json(r: EvidenceRevision) -> dict:
    return {"id": str(r.id), "revision_no": r.revision_no, "filename": r.filename, "detected_type": r.detected_type, "size_bytes": r.size_bytes,
            "sha256": r.sha256, "state": r.state, "created_at": r.created_at.isoformat()}


def _visible(request, pk) -> Evidence | None:
    e = Evidence.objects.filter(pk=pk).first()  # RLS: another tenant's id is simply absent
    if e is None or (e.data_class == "R" and not _can_restricted(request)):
        return None  # an unreadable Restricted record is indistinguishable from a missing one
    return e


class EvidenceCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    description = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")
    data_class = serializers.ChoiceField(choices=["C", "R"], default="C")


class EvidenceListView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "evidence.read")

    def get(self, request):
        qs = Evidence.objects.all() if _can_restricted(request) else Evidence.objects.filter(data_class="C")
        return Response({"evidence": [_evidence_json(e) for e in qs.order_by("-created_at")[:100]]})

    def post(self, request):
        self.require(request, "evidence.upload")
        d = EvidenceCreateSerializer(data=request.data)
        d.is_valid(raise_exception=True)
        v = d.validated_data
        if v["data_class"] == "R":
            self.require(request, "evidence.read_restricted")  # cannot create what the caller could not read
        e = Evidence(title=v["title"].strip(), description=v["description"].strip(), data_class=v["data_class"], created_by=request.user.account_id)
        if not e.title:
            return _err("title_required")
        e.save(force_insert=True)
        audit.record("evidence.created", actor_id=request.user.account_id, object_type="evidence", object_id=str(e.id), details={"data_class": e.data_class})
        return Response(_evidence_json(e), status=201)


class EvidenceDetailView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "evidence.read")

    def get(self, request, pk):
        e = _visible(request, pk)
        if e is None:
            return _missing(request)
        revs = EvidenceRevision.objects.filter(evidence_id=e.id).order_by("revision_no")
        return Response({**_evidence_json(e), "revisions": [_revision_json(r) for r in revs]})


class RevisionUploadView(NgrcAPIView):
    """Raw-body upload (`Content-Type` = the declared file type, `X-Filename` = percent-encoded original name). No parser: the body is streamed."""

    ngrc_policy = Policy("tenant", "evidence.upload")
    parser_classes = []

    def post(self, request, pk):
        e = _visible(request, pk)
        if e is None:
            return _missing(request)
        raw_len = request.META.get("CONTENT_LENGTH") or ""
        if not raw_len.isdigit():
            return _err("length_required", 411)
        if int(raw_len) > int(settings.EVIDENCE_MAX_BYTES):
            return self._rejected(request, "too_large", 413)
        try:
            rev = service.upload_revision(e, request.user.account_id, filename=request.META.get("HTTP_X_FILENAME", ""),
                                          declared_type=request.META.get("CONTENT_TYPE", ""), read=request._request.read)
        except service.EvidenceError as exc:
            return self._rejected(request, exc.code, exc.http)
        return Response(_revision_json(rev), status=201)

    @staticmethod
    def _rejected(request, code: str, http: int) -> Response:
        audit.emit_independent("evidence.upload_rejected", request.user.tenant_id, actor_id=request.user.account_id, result="denied",
                               reason_code=code, details={"reason": code})
        return _err(code, http)


def _ascii_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100] or "file"


class RevisionDownloadView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "evidence.read")

    def get(self, request, pk, rid):
        e = _visible(request, pk)
        rev = EvidenceRevision.objects.filter(pk=rid, evidence_id=pk).first() if e is not None else None
        if rev is None:
            return _missing(request)
        if e.data_class == "R":
            self.require(request, "evidence.read_restricted")
        if rev.state != "collected":
            return _err("not_available", 409)  # scan_pending / quarantined: never served
        tenant_id = request.user.tenant_id
        if rev.storage_key != storage.object_key(tenant_id, rev.id):
            log.error("evidence revision %s has an unexpected storage key", rev.id)
            return _missing(request)  # a key that is not THIS tenant's own is never opened
        spool = tempfile.SpooledTemporaryFile(max_size=1 << 20)  # noqa: SIM115 - closed when the response is closed (or on any early exit)
        try:
            h, total = sha256(), 0
            for chunk in storage.get_store().iter_chunks(rev.storage_key):
                total += len(chunk)
                if total > int(settings.EVIDENCE_MAX_BYTES):
                    break
                h.update(chunk)
                spool.write(chunk)
        except storage.StoreError:
            spool.close()
            return self._integrity_failure(request, rev, "missing")
        if h.hexdigest() != rev.sha256 or total != rev.size_bytes:
            spool.close()
            return self._integrity_failure(request, rev, h.hexdigest())
        spool.seek(0)
        audit.record("evidence.downloaded", actor_id=request.user.account_id, object_type="evidence_revision", object_id=str(rev.id),
                     details={"revision_no": rev.revision_no, "revision_sha256": rev.sha256, "size_bytes": rev.size_bytes})

        def body():
            try:
                while chunk := spool.read(storage.CHUNK):
                    yield chunk
            finally:
                spool.close()

        resp = StreamingHttpResponse(body(), content_type="application/octet-stream")  # never the declared type: no sniffing, no inline rendering
        name = rev.filename
        resp["Content-Disposition"] = f"attachment; filename=\"{_ascii_name(name)}\"; filename*=UTF-8''{quote(_CTRL.sub('', name))}"
        resp["Content-Length"] = str(rev.size_bytes)
        resp["Cache-Control"] = "no-store"
        resp["X-Content-Type-Options"] = "nosniff"
        return resp

    @staticmethod
    def _integrity_failure(request, rev, actual: str) -> Response:
        audit.emit_independent("evidence.hash_mismatch", request.user.tenant_id, actor_id=request.user.account_id, result="failure",
                               reason_code="hash_mismatch",
                               details={"revision_no": rev.revision_no, "expected_sha256": rev.sha256, "actual_sha256": actual[:64]},
                               object_type="evidence_revision", object_id=str(rev.id))
        alerts.notify(alerts.Alert(kind="evidence_integrity_failure", severity="critical", stream=str(request.user.tenant_id),
                                   message="stored evidence does not match its recorded hash",
                                   details={"revision_id": str(rev.id), "revision_no": rev.revision_no}))
        return _err("integrity_check_failed", 500)


# ------------------------------------------------------------------------------------------------------ search (F-AUZ-005)
# PostgreSQL full-text search over the tenant's own evidence metadata. It runs on the application role under FORCE'd RLS, so another tenant's rows cannot
# be selected by any query text; websearch_to_tsquery treats operators and field syntax as plain words, so the filter cannot be widened from the query.
_SEARCH_SQL = """SELECT e.id, e.title, e.data_class,
       ts_headline('simple', coalesce(nullif(e.description, ''), e.title), q, 'StartSel=[, StopSel=], MaxFragments=1, MaxWords=30, MinWords=5')
  FROM ten_evidence e, websearch_to_tsquery('simple', %s) AS q
 WHERE e.search_vector @@ q AND (e.data_class = 'C' OR %s)
 ORDER BY ts_rank(e.search_vector, q) DESC, e.created_at DESC
 LIMIT %s"""


class SearchView(NgrcAPIView):
    ngrc_policy = Policy("tenant", "evidence.read")

    def get(self, request):
        q = (request.query_params.get("q") or "").strip()
        if not q or len(q) > int(settings.SEARCH_MAX_QUERY_CHARS) or _CTRL.search(q):
            return _err("invalid_query")
        restricted = _can_restricted(request)  # per-row re-authorisation lives in the SQL predicate: Restricted hits never leave the database unless allowed
        with connections["default"].cursor() as cur:
            cur.execute(_SEARCH_SQL, [q, restricted, int(settings.SEARCH_MAX_RESULTS)])
            rows = cur.fetchall()
        hits = [{"id": str(r[0]), "title": r[1], "data_class": r[2], "snippet": r[3]} for r in rows]
        audit.record("search.executed", actor_id=request.user.account_id, details={"count": len(hits), "query_length": len(q)})
        return Response({"results": hits, "count": len(hits)})
