"""D-P2-001 security: CAT/PLT grants (ngrc_app reads, ngrc_catalog_publisher writes, no RLS - not tenant
data), TEN RLS for the tenant-owned tables (standard template), and publish-time immutability triggers for
cat_framework_version, cat_requirement, cat_mapping and plt_framework_change_set."""
from django.db import migrations

from ngrc.core import sqlgen

CAT_PLT_TABLES = [
    "cat_framework",
    "cat_framework_version",
    "cat_requirement",
    "cat_mapping",
    "plt_framework_change_set",
    "plt_framework_source_registry",
]

FORWARD = [
    *[stmt for t in CAT_PLT_TABLES for stmt in sqlgen.catalog_table_grants(t)],
    # No DELETE for ngrc_app on any of these: superseding/deciding is modelled as a new row or a status
    # flip (status/superseded_at), never a deletion - history stays queryable (D-P0-009 s2.3 spirit).
    *sqlgen.tenant_table_forward("ten_framework_activation", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_mapping_override", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_framework_changeset_decision", "SELECT, INSERT"),

    # cat_framework_version: frozen once published_at is set - content columns and published_at itself
    # cannot change, status cannot return to 'draft', and the row cannot be deleted (P0 non-negotiable #3).
    """CREATE FUNCTION cat_framework_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'a published framework version cannot be deleted' USING ERRCODE = '42501';
    END IF;
    IF NEW.version_label IS DISTINCT FROM OLD.version_label OR NEW.effective_date IS DISTINCT FROM OLD.effective_date
       OR NEW.checksum IS DISTINCT FROM OLD.checksum OR NEW.source_metadata IS DISTINCT FROM OLD.source_metadata
       OR NEW.framework_id IS DISTINCT FROM OLD.framework_id OR NEW.published_at IS DISTINCT FROM OLD.published_at
       OR NEW.status = 'draft' THEN
      RAISE EXCEPTION 'a published framework version is immutable' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER cat_framework_version_guard BEFORE UPDATE OR DELETE ON cat_framework_version "
    "FOR EACH ROW EXECUTE FUNCTION cat_framework_version_guard()",

    # cat_requirement: frozen once its framework_version has been published - a draft version's
    # requirements may still be edited freely while the curator is authoring it.
    """CREATE FUNCTION cat_requirement_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_published boolean;
BEGIN
  SELECT published_at IS NOT NULL INTO v_published FROM cat_framework_version WHERE id = OLD.framework_version_id;
  IF v_published THEN
    RAISE EXCEPTION 'a requirement of a published framework version is immutable' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER cat_requirement_guard BEFORE UPDATE OR DELETE ON cat_requirement "
    "FOR EACH ROW EXECUTE FUNCTION cat_requirement_guard()",

    # cat_mapping: frozen once locked (one-way; unlocking is itself a disallowed update).
    """CREATE FUNCTION cat_mapping_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.locked THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'a locked mapping cannot be deleted' USING ERRCODE = '42501';
    END IF;
    RAISE EXCEPTION 'a locked mapping is immutable' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER cat_mapping_guard BEFORE UPDATE OR DELETE ON cat_mapping "
    "FOR EACH ROW EXECUTE FUNCTION cat_mapping_guard()",

    # plt_framework_change_set: append-only from creation - "persist every ChangeSet" (06_FRAMEWORK_ENGINE.md).
    """CREATE FUNCTION plt_framework_change_set_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'a framework change set is append-only' USING ERRCODE = '42501';
END $$""",
    "CREATE TRIGGER plt_framework_change_set_guard BEFORE UPDATE OR DELETE ON plt_framework_change_set "
    "FOR EACH ROW EXECUTE FUNCTION plt_framework_change_set_guard()",
]

REVERSE = [
    "DROP TRIGGER IF EXISTS plt_framework_change_set_guard ON plt_framework_change_set",
    "DROP FUNCTION IF EXISTS plt_framework_change_set_guard()",
    "DROP TRIGGER IF EXISTS cat_mapping_guard ON cat_mapping",
    "DROP FUNCTION IF EXISTS cat_mapping_guard()",
    "DROP TRIGGER IF EXISTS cat_requirement_guard ON cat_requirement",
    "DROP FUNCTION IF EXISTS cat_requirement_guard()",
    "DROP TRIGGER IF EXISTS cat_framework_version_guard ON cat_framework_version",
    "DROP FUNCTION IF EXISTS cat_framework_version_guard()",
    *sqlgen.tenant_table_reverse("ten_framework_changeset_decision"),
    *sqlgen.tenant_table_reverse("ten_mapping_override"),
    *sqlgen.tenant_table_reverse("ten_framework_activation"),
]


class Migration(migrations.Migration):
    dependencies = [("framework", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
