"""D-P4-001: RLS for the two new TEN tables (standard template). ten_finding is a living record - no
immutability trigger, same precedent as every other mutable object in this domain. ten_security_exception
is "append-only" per 07_CONTROL_EVIDENCE.md's own wording, enforced here the same way ten_evidence_revision
is (D-P0-007 s5): a flat BEFORE UPDATE OR DELETE reject plus a BEFORE TRUNCATE guard - no field-by-field
carve-out, because unlike an evidence revision's scan outcome, nothing on this row is ever meant to change
after creation."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_finding", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_security_exception", "SELECT, INSERT"),
    """CREATE FUNCTION ten_security_exception_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'security exceptions are append-only and never deleted' USING ERRCODE = '42501'; END IF;
  RAISE EXCEPTION 'security exceptions are append-only and immutable' USING ERRCODE = '42501';
END $$""",
    "CREATE TRIGGER ten_security_exception_guard BEFORE UPDATE OR DELETE ON ten_security_exception "
    "FOR EACH ROW EXECUTE FUNCTION ten_security_exception_guard()",
    """CREATE FUNCTION ten_security_exception_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'security exceptions are never truncated' USING ERRCODE = '42501'; END $$""",
    "CREATE TRIGGER ten_security_exception_no_truncate BEFORE TRUNCATE ON ten_security_exception "
    "FOR EACH STATEMENT EXECUTE FUNCTION ten_security_exception_no_truncate()",
]

REVERSE = [
    "DROP TRIGGER IF EXISTS ten_security_exception_no_truncate ON ten_security_exception",
    "DROP FUNCTION IF EXISTS ten_security_exception_no_truncate()",
    "DROP TRIGGER IF EXISTS ten_security_exception_guard ON ten_security_exception",
    "DROP FUNCTION IF EXISTS ten_security_exception_guard()",
    *sqlgen.tenant_table_reverse("ten_security_exception"),
    *sqlgen.tenant_table_reverse("ten_finding"),
]


class Migration(migrations.Migration):
    dependencies = [("controls", "0009_findings_and_exceptions")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
