"""F-DAT-005 - evidence lifecycle (D-P0-007 s5): validated uploads (declared type vs real content, size, archive bombs, executable content), immutable
revisions, a scan outcome that can be recorded once, server-generated storage keys, and the database guarantees underneath (RLS, same-tenant FK, no
DELETE, no downgrade of Restricted records)."""
import hashlib
import io
import os
import uuid
import zipfile
from pathlib import Path

import psycopg
import pytest
from django.conf import settings

from ngrc.evidence import sniff
from ngrc.evidence.storage import KEY_RE, LocalDevStore, StoreError, TooLarge, object_key

from .conftest import role_connect
from .evidence_factory import EICAR_FILE, PDF, PNG, create, make_evidence, stored_path, upload
from .helpers import audit_events

pytestmark = pytest.mark.security
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def zip_bytes(entries: dict[str, bytes], compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def docx(extra: dict | None = None) -> bytes:
    return zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>", **(extra or {})})


def store_files() -> int:
    return sum(1 for p in Path(settings.EVIDENCE_STORE_DIR).rglob("*") if p.is_file())


# ------------------------------------------------------------------------------------------------ validated uploads
@pytest.mark.parametrize("ctype", ["text/html", "image/svg+xml", "application/zip", "application/x-msdownload", "application/octet-stream",
                                   "application/javascript", ""])
def test_types_outside_the_allow_list_are_refused_and_nothing_is_stored(ctype, tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    eid, before = create(owner), store_files()
    r = upload(owner, eid, b"<script>alert(1)</script>", content_type=ctype or "x/x")
    assert r.status_code == 415 and r.json() == {"error": "type_not_allowed"} and store_files() == before
    assert audit_events(tenant_id=tenant_a.id, action="evidence.upload_rejected", reason_code="type_not_allowed", actor_id=owner.account.id)


@pytest.mark.parametrize("content,ctype,code", [
    (PNG, "application/pdf", "content_does_not_match_declared_type"),
    (PDF, "image/png", "content_does_not_match_declared_type"),
    (b"MZ\x90\x00" + b"\x00" * 60, "application/pdf", "executable_content"),
    (b"\x7fELF" + b"\x00" * 60, "image/png", "executable_content"),
    (b"#!/bin/sh\nrm -rf /\n", "text/plain", "executable_content"),
    (b"plain\x00text", "text/plain", "content_does_not_match_declared_type"),
    (b"\xff\xfe\x00bad utf8 \x80\x81", "text/csv", "content_does_not_match_declared_type"),
    (b"not a zip at all", DOCX, "content_does_not_match_declared_type"),
], ids=["png-as-pdf", "pdf-as-png", "pe-as-pdf", "elf-as-png", "shebang-as-text", "nul-in-text", "bad-utf8-csv", "garbage-as-docx"])
def test_content_must_be_what_it_claims_to_be(content, ctype, code, tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    eid, before = create(owner), store_files()
    r = upload(owner, eid, content, content_type=ctype)
    assert r.status_code == 415 and r.json() == {"error": code} and store_files() == before


def test_valid_documents_are_accepted_and_scanned_clean(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    for content, ctype, name in ((PDF, "application/pdf", "a.pdf"), (PNG, "image/png", "a.png"), (b"id,name\n1,x\n", "text/csv", "a.csv"),
                                 (docx(), DOCX, "a.docx"), (b"\xc3\xa9\xc3\xa9 caf\xc3\xa9", "text/plain; charset=utf-8", "a.txt")):
        m = make_evidence(owner, content=content, content_type=ctype, filename=name)
        assert m.state == "collected" and m.sha256 == hashlib.sha256(content).hexdigest() and m.size == len(content), name


@pytest.mark.parametrize("payload,code", [
    pytest.param(zip_bytes({"[Content_Types].xml": b"x", "word/document.xml": b"x", "../../evil.dll": b"x"}), "archive_unsafe_entry", id="traversal entry"),
    pytest.param(zip_bytes({"[Content_Types].xml": b"x", "word/document.xml": b"x", "/etc/passwd": b"x"}), "archive_unsafe_entry", id="absolute entry"),
    pytest.param(zip_bytes({"[Content_Types].xml": b"x", "word/document.xml": b"\x00" * (60 * 1024 * 1024)}), "archive_bomb", id="zip bomb"),
    pytest.param(zip_bytes({"[Content_Types].xml": b"x", **{f"word/n{i}.xml": b"1" for i in range(2100)}}), "archive_too_many_entries", id="too many entries"),
    pytest.param(zip_bytes({"word/document.xml": b"x"}), "content_does_not_match_declared_type", id="no content types"),
    pytest.param(zip_bytes({"[Content_Types].xml": b"x", "xl/workbook.xml": b"x"}), "content_does_not_match_declared_type", id="wrong package kind"),
])
def test_office_packages_are_checked_for_bombs_path_escapes_and_real_structure(payload, code, tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    r = upload(owner, create(owner), payload, content_type=DOCX)
    assert r.status_code == 415 and r.json() == {"error": code}


def test_size_limit_is_enforced_before_and_while_storing(tenant_a, make_user, monkeypatch, tmp_path):
    owner = make_user(tenant_a, "owner")
    monkeypatch.setattr(settings, "EVIDENCE_MAX_BYTES", 1024)
    eid, before = create(owner), store_files()
    r = upload(owner, eid, PDF + b"x" * 2000)
    assert r.status_code == 413 and r.json() == {"error": "too_large"} and store_files() == before
    assert upload(owner, eid, b"").status_code in (400, 411)   # no body: either "empty" or "length required", never stored
    store = LocalDevStore(str(tmp_path))                                  # the streaming limit itself: a body larger than declared is cut off, no partial object
    key = object_key(uuid.uuid4(), uuid.uuid4())
    with pytest.raises(TooLarge):
        store.put(key, iter([b"a" * 600, b"b" * 600]), max_bytes=1000)
    assert not (tmp_path / key).exists()


def test_the_original_filename_is_metadata_only_and_sanitised(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    for raw, expected in (("..\\..\\evil.pdf", "evil.pdf"), ("../../etc/passwd.pdf", "passwd.pdf"), ("a\x00b<>:|?*.pdf", "ab.pdf"), ("  ...  ", "file"),
                          ("n" * 400 + ".pdf", None), ("résumé ‮.pdf", None)):
        m = make_evidence(owner, filename=raw)
        got = owner.api.get(f"/tenant/evidence/{m.id}/").json()["revisions"][0]["filename"]
        assert "/" not in got and "\\" not in got and ".." not in got.replace("...", "") and len(got) <= 200 and "\x00" not in got
        if expected:
            assert got == expected
        assert stored_path(tenant_a.id, m.rev).name == m.rev                   # the stored object is named after the revision UUID, never the file name


def test_revisions_are_numbered_listed_and_each_one_is_independently_downloadable(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m1 = make_evidence(owner, content=PDF + b"one")
    r2 = upload(owner, m1.id, PDF + b"two").json()
    assert (r2["revision_no"], r2["state"]) == (2, "collected")
    detail = owner.api.get(f"/tenant/evidence/{m1.id}/").json()
    assert [(x["revision_no"], x["sha256"]) for x in detail["revisions"]] == [(1, m1.sha256), (2, hashlib.sha256(PDF + b"two").hexdigest())]
    assert b"".join(owner.api.get(f"/tenant/evidence/{m1.id}/revisions/{r2['id']}/download/").streaming_content).endswith(b"two")
    assert b"".join(owner.api.get(f"/tenant/evidence/{m1.id}/revisions/{m1.rev}/download/").streaming_content).endswith(b"one")
    assert len(audit_events(tenant_id=tenant_a.id, action="evidence.revision.added", actor_id=owner.account.id)) >= 2


def test_member_cannot_upload_and_validation_errors_are_clean(tenant_a, make_user):
    owner, member = make_user(tenant_a, "owner"), make_user(tenant_a, "member")
    eid = create(owner)
    assert upload(member, eid).status_code == 403 and member.api.post("/tenant/evidence/", {"title": "x"}).status_code == 403
    for bad in ({"title": ""}, {"title": "   "}, {"title": "t" * 201}, {"title": "ok", "data_class": "X"}, {"title": "ok", "description": "d" * 2001}, {}):
        assert owner.api.post("/tenant/evidence/", bad).status_code == 400, bad
    assert upload(owner, uuid.uuid4()).status_code == 404


def test_eicar_is_quarantined_at_upload_with_a_critical_event(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, content=EICAR_FILE, filename="x.txt", content_type="text/plain")
    assert m.state == "quarantined"
    ev = audit_events(tenant_id=tenant_a.id, action="evidence.scan.quarantined")
    assert ev and ev[-1]["object_id"] == m.rev


# ------------------------------------------------------------------------------------------------ storage keys
@pytest.mark.parametrize("key", ["../../etc/passwd", "/abs/path", "tenants/..", "", "tenants/x/evidence/y", None,
                                 f"tenants/{uuid.uuid4()}/evidence/{uuid.uuid4()}/../x", f"tenants/{uuid.uuid4()}/evidence/{uuid.uuid4()}\\x",
                                 f"tenants/{str(uuid.uuid4()).upper()}/evidence/{uuid.uuid4()}", f"tenants/{uuid.uuid4()}/evidence/{uuid.uuid4()}\n"])
def test_hostile_storage_keys_are_refused(key, tmp_path):
    store = LocalDevStore(str(tmp_path))
    with pytest.raises(StoreError):
        store.open(key)
    with pytest.raises(StoreError):
        store.put(key, iter([b"x"]), max_bytes=10)
    assert not os.listdir(tmp_path)


def test_the_store_never_overwrites_and_keys_are_server_generated(tmp_path):
    store = LocalDevStore(str(tmp_path))
    key = object_key(uuid.uuid4(), uuid.uuid4())
    assert KEY_RE.fullmatch(key)
    store.put(key, iter([b"first"]), max_bytes=100)
    with pytest.raises(FileExistsError):
        store.put(key, iter([b"second"]), max_bytes=100)
    assert (tmp_path / key).read_bytes() == b"first"


def test_the_sniffer_is_pure_and_rejects_the_unknown():
    assert sniff.inspect("application/pdf", PDF) == "application/pdf"
    with pytest.raises(sniff.Rejected):
        sniff.inspect("application/x-unknown", b"abc")


# ------------------------------------------------------------------------------------------------ database guarantees
def app(tenant, role="ngrc_app"):
    c = role_connect(role)
    c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant.id)])
    return c


def test_revision_content_is_immutable_and_the_scan_outcome_final(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner)
    q = make_evidence(owner, content=EICAR_FILE, filename="x.txt", content_type="text/plain")
    cases = [
        (m.rev, "UPDATE ten_evidence_revision SET sha256 = repeat('0', 64) WHERE id = %s", "content is immutable"),
        (m.rev, "UPDATE ten_evidence_revision SET storage_key = 'x' WHERE id = %s", "content is immutable"),
        (m.rev, "UPDATE ten_evidence_revision SET size_bytes = 1 WHERE id = %s", "content is immutable"),
        (m.rev, "UPDATE ten_evidence_revision SET state = 'quarantined', scanned_at = now() WHERE id = %s", "scan outcome is final"),
        (q.rev, "UPDATE ten_evidence_revision SET state = 'collected', scanned_at = now() WHERE id = %s", "scan outcome is final"),
        (m.rev, "UPDATE ten_evidence_revision SET scan_detail = 'rewritten' WHERE id = %s", "scan outcome is final"),
    ]
    for rev, sql, frag in cases:
        with app(tenant_a) as c, pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
            c.execute(sql, [rev])
        assert frag in exc.value.diag.message_primary, (sql, exc.value.diag.message_primary)
    with app(tenant_a) as c, pytest.raises(psycopg.errors.Error):
        c.execute("UPDATE ten_evidence_revision SET state = 'bogus' WHERE id = %s", [m.rev])


def test_a_pending_revision_can_receive_exactly_one_outcome(tenant_a, make_user, monkeypatch):
    from ngrc.evidence import scanner

    owner = make_user(tenant_a, "owner")
    monkeypatch.setattr(scanner, "get_scanner", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    m = make_evidence(owner)
    assert m.state == "scan_pending"
    with app(tenant_a) as c:
        c.execute("UPDATE ten_evidence_revision SET state = 'collected', scanned_at = now() WHERE id = %s", [m.rev])      # the one allowed transition
        c.commit()
    with app(tenant_a) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE ten_evidence_revision SET state = 'quarantined', scanned_at = now() WHERE id = %s", [m.rev])
    pend = make_evidence(owner)
    with app(tenant_a) as c, pytest.raises(psycopg.errors.Error):     # an outcome must carry its time
        c.execute("UPDATE ten_evidence_revision SET state = 'collected' WHERE id = %s", [pend.rev])


def test_nothing_can_delete_or_truncate_evidence_and_restricted_cannot_be_downgraded(tenant_a, make_user):
    owner = make_user(tenant_a, "owner")
    m = make_evidence(owner, data_class="R")
    for sql in ("DELETE FROM ten_evidence_revision", "DELETE FROM ten_evidence", "TRUNCATE ten_evidence_revision", "TRUNCATE ten_evidence"):
        with app(tenant_a) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)
    with role_connect("ngrc_owner") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="never deleted"):
            c.execute("DELETE FROM ten_evidence_revision WHERE id = %s", [m.rev])
        c.rollback()
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        # D-P3-002 added ten_evidence_link, which carries a real FK into this table - Postgres now refuses
        # the bare TRUNCATE outright (FeatureNotSupported) before the no_truncate trigger even fires. Either
        # way truncation is impossible; which guard catches it first is an implementation detail.
        with pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.FeatureNotSupported)):
            c.execute("TRUNCATE ten_evidence_revision")
    with app(tenant_a) as c, pytest.raises(psycopg.errors.InsufficientPrivilege, match="cannot be downgraded"):
        c.execute("UPDATE ten_evidence SET data_class = 'C' WHERE id = %s", [m.id])
    with app(tenant_a) as c, pytest.raises(psycopg.errors.InsufficientPrivilege, match="provenance"):
        c.execute("UPDATE ten_evidence SET created_by = gen_random_uuid() WHERE id = %s", [m.id])


def test_rls_composite_fk_and_with_check_keep_evidence_inside_its_tenant(tenant_a, tenant_b, make_user):
    a, b = make_user(tenant_a, "owner"), make_user(tenant_b, "owner")
    ma, mb = make_evidence(a), make_evidence(b)
    with app(tenant_a) as c:
        assert {str(r[0]) for r in c.execute("SELECT id FROM ten_evidence").fetchall()} >= {ma.id} and mb.id not in str(c.execute("SELECT id FROM ten_evidence").fetchall())
        assert c.execute("SELECT count(*) FROM ten_evidence_revision WHERE evidence_id = %s", [mb.id]).fetchone()[0] == 0
    with role_connect("ngrc_app") as c:                                                  # no tenant context: fail closed
        assert c.execute("SELECT count(*) FROM ten_evidence").fetchone()[0] == 0
    with app(tenant_a) as c, pytest.raises(psycopg.errors.ForeignKeyViolation):          # a revision of tenant A pointing at tenant B's evidence
        c.execute("INSERT INTO ten_evidence_revision (id, tenant_id, evidence_id, revision_no, filename, declared_type, detected_type, size_bytes, sha256, "
                  "storage_key, state, scan_detail, created_at) VALUES (gen_random_uuid(), %s, %s, 9, 'x', 'application/pdf', 'application/pdf', 1, "
                  "repeat('a', 64), gen_random_uuid()::text, 'scan_pending', '', now())", [str(tenant_a.id), mb.id])
    with app(tenant_a) as c, pytest.raises(psycopg.errors.Error):                        # WITH CHECK: writing a row for another tenant
        c.execute("INSERT INTO ten_evidence (id, tenant_id, title, description, data_class, created_at) VALUES (gen_random_uuid(), %s, 't', '', 'C', now())",
                  [str(tenant_b.id)])
    for role in ("ngrc_auth", "ngrc_ops"):
        with role_connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT 1 FROM ten_evidence LIMIT 1")


def test_ten_evidence_and_ten_evidence_revision_follow_the_tenant_table_template(tenant_a):
    with role_connect("ngrc_owner") as c:
        for t in ("ten_evidence", "ten_evidence_revision"):
            rls, force = c.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s", [t]).fetchone()
            assert rls and force, t
            assert c.execute("SELECT count(*) FROM pg_policy WHERE polrelid = %s::regclass", [t]).fetchone()[0] >= 2
        assert c.execute("SELECT count(*) FROM pg_indexes WHERE indexname = 'ten_evidence_search_idx'").fetchone()[0] == 1


def test_a_reader_without_the_upload_permission_can_read_but_not_create_or_upload(tenant_a, make_user):
    """The upload permission is checked on its own: a role with evidence.read only passes the route policy but not the mutation."""
    owner = make_user(tenant_a, "owner")
    r = owner.api.post("/tenant/roles/", {"key": "evidence-reader", "name": "Evidence reader", "permissions": ["tenant.view", "evidence.read"]})
    assert r.status_code == 201, r.content
    reader = make_user(tenant_a, "evidence-reader")
    m = make_evidence(owner)
    assert reader.api.get("/tenant/evidence/").status_code == 200
    assert reader.api.post("/tenant/evidence/", {"title": "nope"}).status_code == 403
    assert upload(reader, m.id).status_code == 403
    assert audit_events(tenant_id=tenant_a.id, action="authz.denied", reason_code="permission_missing", actor_id=reader.account.id)
