"""D-P2-003: RLS for the new TEN custom-framework tables (standard template) and the same publish-time
immutability guards D-P2-001 gave the CAT tables, scoped to these tables."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_framework_custom", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_framework_custom_version", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_framework_custom_requirement", "SELECT, INSERT, UPDATE"),

    """CREATE FUNCTION ten_framework_custom_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    IF TG_OP = 'DELETE' THEN
      RAISE EXCEPTION 'a published custom framework version cannot be deleted' USING ERRCODE = '42501';
    END IF;
    IF NEW.version_label IS DISTINCT FROM OLD.version_label OR NEW.effective_date IS DISTINCT FROM OLD.effective_date
       OR NEW.checksum IS DISTINCT FROM OLD.checksum OR NEW.source_metadata IS DISTINCT FROM OLD.source_metadata
       OR NEW.framework_id IS DISTINCT FROM OLD.framework_id OR NEW.published_at IS DISTINCT FROM OLD.published_at
       OR NEW.status = 'draft' THEN
      RAISE EXCEPTION 'a published custom framework version is immutable' USING ERRCODE = '42501';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_framework_custom_version_guard BEFORE UPDATE OR DELETE ON ten_framework_custom_version "
    "FOR EACH ROW EXECUTE FUNCTION ten_framework_custom_version_guard()",

    """CREATE FUNCTION ten_framework_custom_requirement_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_published boolean;
BEGIN
  SELECT published_at IS NOT NULL INTO v_published FROM ten_framework_custom_version WHERE id = OLD.framework_version_id;
  IF v_published THEN
    RAISE EXCEPTION 'a requirement of a published custom framework version is immutable' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_framework_custom_requirement_guard BEFORE UPDATE OR DELETE ON ten_framework_custom_requirement "
    "FOR EACH ROW EXECUTE FUNCTION ten_framework_custom_requirement_guard()",
]

REVERSE = [
    "DROP TRIGGER IF EXISTS ten_framework_custom_requirement_guard ON ten_framework_custom_requirement",
    "DROP FUNCTION IF EXISTS ten_framework_custom_requirement_guard()",
    "DROP TRIGGER IF EXISTS ten_framework_custom_version_guard ON ten_framework_custom_version",
    "DROP FUNCTION IF EXISTS ten_framework_custom_version_guard()",
    *sqlgen.tenant_table_reverse("ten_framework_custom_requirement"),
    *sqlgen.tenant_table_reverse("ten_framework_custom_version"),
    *sqlgen.tenant_table_reverse("ten_framework_custom"),
]


class Migration(migrations.Migration):
    dependencies = [("framework", "0005_frameworkactivation_kind_customframework_and_more")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
