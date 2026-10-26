"""D-P4-002: RLS for the three new TEN tables (standard template). ten_risk_assessment/ten_risk_scenario
are living records - no immutability trigger, same precedent as every other mutable object in this
codebase. ten_risk_acceptance is append-only, same reasoning and same trigger template as
ngrc.controls's ten_security_exception_guard (D-P4-001): a formal, approved, expiring decision captured
once at creation, never mutated after."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_risk_assessment", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_risk_scenario", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_risk_acceptance", "SELECT, INSERT"),
    """CREATE FUNCTION ten_risk_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'risk acceptances are append-only and never deleted' USING ERRCODE = '42501'; END IF;
  RAISE EXCEPTION 'risk acceptances are append-only and immutable' USING ERRCODE = '42501';
END $$""",
    "CREATE TRIGGER ten_risk_acceptance_guard BEFORE UPDATE OR DELETE ON ten_risk_acceptance "
    "FOR EACH ROW EXECUTE FUNCTION ten_risk_acceptance_guard()",
    """CREATE FUNCTION ten_risk_acceptance_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'risk acceptances are never truncated' USING ERRCODE = '42501'; END $$""",
    "CREATE TRIGGER ten_risk_acceptance_no_truncate BEFORE TRUNCATE ON ten_risk_acceptance "
    "FOR EACH STATEMENT EXECUTE FUNCTION ten_risk_acceptance_no_truncate()",
]

REVERSE = [
    "DROP TRIGGER IF EXISTS ten_risk_acceptance_no_truncate ON ten_risk_acceptance",
    "DROP FUNCTION IF EXISTS ten_risk_acceptance_no_truncate()",
    "DROP TRIGGER IF EXISTS ten_risk_acceptance_guard ON ten_risk_acceptance",
    "DROP FUNCTION IF EXISTS ten_risk_acceptance_guard()",
    *sqlgen.tenant_table_reverse("ten_risk_acceptance"),
    *sqlgen.tenant_table_reverse("ten_risk_scenario"),
    *sqlgen.tenant_table_reverse("ten_risk_assessment"),
]


class Migration(migrations.Migration):
    dependencies = [("risk", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
