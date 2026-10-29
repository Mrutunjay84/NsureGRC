"""D-P7-001: RLS for the four new TEN tables (standard template). All living records - no immutability
trigger, same precedent as every other mutable object in this codebase outside the append-only
EvidenceRevision/SecurityException/RiskAcceptance class."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_third_party_entity", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_third_party_representative", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_third_party_solution", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_third_party_assessment", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_third_party_assessment"),
    *sqlgen.tenant_table_reverse("ten_third_party_solution"),
    *sqlgen.tenant_table_reverse("ten_third_party_representative"),
    *sqlgen.tenant_table_reverse("ten_third_party_entity"),
]


class Migration(migrations.Migration):
    dependencies = [("thirdparty", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
