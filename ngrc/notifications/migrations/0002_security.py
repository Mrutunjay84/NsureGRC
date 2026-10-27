"""D-P5-007: RLS for the new TEN table (standard template). A living record - no immutability trigger,
same precedent as every other mutable object in this codebase outside the append-only
EvidenceRevision/SecurityException/RiskAcceptance class (marking read is an ordinary field update)."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_notification", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_notification"),
]


class Migration(migrations.Migration):
    dependencies = [("notifications", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
