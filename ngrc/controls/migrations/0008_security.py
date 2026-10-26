"""D-P3-005: RLS for the two new TEN tables (standard template). No cross-app composite FK needed - both
ControlPlan and Task stay inside the controls app. No immutability trigger either - same D-P3-001..004
precedent: these are living operational records under active editing (status, lifecycle), not frozen
catalogue content."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_control_plan", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_task", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_task"),
    *sqlgen.tenant_table_reverse("ten_control_plan"),
]


class Migration(migrations.Migration):
    dependencies = [("controls", "0007_tasks_and_control_plans")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
