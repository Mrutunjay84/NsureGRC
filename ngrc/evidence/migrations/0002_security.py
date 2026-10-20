"""TEN-class security for evidence (D-P0-003, D-P0-007 s5): FORCE'd RLS via the standard template, same-tenant composite FK, a generated full-text
column for tenant-scoped search, immutable revisions (content columns frozen, a scan outcome may be recorded exactly once, no deletion), and a
guard against downgrading a Restricted record to Confidential. ngrc_app gets SELECT/INSERT/UPDATE only - never DELETE (retention / legal hold /
purge are later, approved workflows, open items O-2 and O-8)."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_evidence", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_evidence_revision", "SELECT, INSERT, UPDATE"),
    "ALTER TABLE ten_evidence_revision ADD CONSTRAINT ten_evidence_revision_evidence_fk "
    "FOREIGN KEY (tenant_id, evidence_id) REFERENCES ten_evidence (tenant_id, id)",
    # tenant-scoped full-text search runs on this column under RLS (control F-AUZ-005); 'simple' = no language assumptions, immutable => allowed in a generated column
    "ALTER TABLE ten_evidence ADD COLUMN search_vector tsvector GENERATED ALWAYS AS "
    "(to_tsvector('simple'::regconfig, coalesce(title, '') || ' ' || coalesce(description, ''))) STORED",
    "CREATE INDEX ten_evidence_search_idx ON ten_evidence USING gin (search_vector)",
    """CREATE FUNCTION ten_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'evidence provenance is immutable' USING ERRCODE = '42501'; END IF;
  IF OLD.data_class = 'R' AND NEW.data_class <> 'R' THEN
    RAISE EXCEPTION 'a Restricted record cannot be downgraded (reclassification is an approved workflow)' USING ERRCODE = '42501'; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_evidence_guard BEFORE UPDATE ON ten_evidence FOR EACH ROW EXECUTE FUNCTION ten_evidence_guard()",
    """CREATE FUNCTION ten_evidence_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'evidence revisions are immutable and never deleted' USING ERRCODE = '42501'; END IF;
  IF NEW.evidence_id <> OLD.evidence_id OR NEW.revision_no <> OLD.revision_no OR NEW.filename <> OLD.filename
     OR NEW.declared_type <> OLD.declared_type OR NEW.detected_type <> OLD.detected_type OR NEW.size_bytes <> OLD.size_bytes
     OR NEW.sha256 <> OLD.sha256 OR NEW.storage_key <> OLD.storage_key OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'evidence revision content is immutable' USING ERRCODE = '42501'; END IF;
  IF NEW.state IS DISTINCT FROM OLD.state OR NEW.scan_detail IS DISTINCT FROM OLD.scan_detail OR NEW.scanned_at IS DISTINCT FROM OLD.scanned_at THEN
    IF OLD.state <> 'scan_pending' THEN
      RAISE EXCEPTION 'the scan outcome is final' USING ERRCODE = '42501'; END IF;
    IF NEW.state NOT IN ('collected', 'quarantined') OR NEW.scanned_at IS NULL THEN
      RAISE EXCEPTION 'a scan outcome must be collected or quarantined and carry its time' USING ERRCODE = '23514'; END IF;
  END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_evidence_revision_guard BEFORE UPDATE OR DELETE ON ten_evidence_revision FOR EACH ROW EXECUTE FUNCTION ten_evidence_revision_guard()",
    """CREATE FUNCTION ten_evidence_revision_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'evidence revisions are never truncated' USING ERRCODE = '42501'; END $$""",
    "CREATE TRIGGER ten_evidence_revision_no_truncate BEFORE TRUNCATE ON ten_evidence_revision FOR EACH STATEMENT EXECUTE FUNCTION ten_evidence_revision_no_truncate()",
]


class Migration(migrations.Migration):
    dependencies = [("core", "0001_helper_functions"), ("evidence", "0001_initial"), ("control_plane", "0001_initial")]
    operations = [migrations.RunSQL(FORWARD)]
