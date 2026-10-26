"""D-P4-006: RLS for the five new TEN tables (standard template). All living records - no immutability
trigger, same precedent as every other mutable object in this codebase outside the append-only
EvidenceRevision/SecurityException/RiskAcceptance class."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_processing_activity", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_purpose", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_personal_data", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_rights_request", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_privacy_breach", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_privacy_breach"),
    *sqlgen.tenant_table_reverse("ten_rights_request"),
    *sqlgen.tenant_table_reverse("ten_personal_data"),
    *sqlgen.tenant_table_reverse("ten_purpose"),
    *sqlgen.tenant_table_reverse("ten_processing_activity"),
]


class Migration(migrations.Migration):
    dependencies = [("privacy", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
