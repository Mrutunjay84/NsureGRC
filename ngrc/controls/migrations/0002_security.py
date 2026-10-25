"""D-P3-001: RLS for the new TEN control tables (standard template). No immutability trigger here -
unlike framework versions/requirements, controls and assertions are living records a reviewer may keep
editing (lifecycle, satisfaction_state, review_state) - there is no "publish freezes it" step for this
domain in this increment."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_common_control", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_implementation_control", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_control_assertion", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_control_assertion"),
    *sqlgen.tenant_table_reverse("ten_implementation_control"),
    *sqlgen.tenant_table_reverse("ten_common_control"),
]


class Migration(migrations.Migration):
    dependencies = [("controls", "0001_initial")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
