"""D-P4-005: RLS for the two new TEN tables (standard template). Both are living records - no
immutability trigger here. ten_audit_item is NOT yet DB-immutable once its parent Audit reaches `locked`;
the ADR's own Risks section flags this honestly as a real gap, not silently assumed away, for a future
increment to close with a trigger keyed on the parent's status."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_compliance_audit", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_audit_item", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_audit_item"),
    *sqlgen.tenant_table_reverse("ten_compliance_audit"),
]


class Migration(migrations.Migration):
    dependencies = [("compliance_audit", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
