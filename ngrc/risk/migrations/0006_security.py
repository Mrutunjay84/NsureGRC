"""D-P7-002: RLS for the two new TEN tables (standard template). Living records - no immutability trigger,
same precedent as ten_risk_scenario/ten_incident."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_asset", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_asset_bia", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_asset_bia"),
    *sqlgen.tenant_table_reverse("ten_asset"),
]


class Migration(migrations.Migration):
    dependencies = [("risk", "0005_assets")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
