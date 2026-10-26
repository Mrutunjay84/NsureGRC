"""D-P4-004: RLS for the three new TEN tables (standard template). All living records - no immutability
trigger, same precedent as every other mutable object in this codebase outside the append-only
EvidenceRevision/SecurityException/RiskAcceptance class."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_policy", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_objective", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_issue", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_issue"),
    *sqlgen.tenant_table_reverse("ten_objective"),
    *sqlgen.tenant_table_reverse("ten_policy"),
]


class Migration(migrations.Migration):
    dependencies = [("governance", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
