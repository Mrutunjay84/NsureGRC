"""D-P4-003: RLS for ten_incident (standard template). Living record - no immutability trigger, same
precedent as RiskAssessment/RiskScenario (incidents are actively updated through their lifecycle, unlike
RiskAcceptance's one-time governed decision)."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_incident", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_incident"),
]


class Migration(migrations.Migration):
    dependencies = [("risk", "0003_incidents")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
