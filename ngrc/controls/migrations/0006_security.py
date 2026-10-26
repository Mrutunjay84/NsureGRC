"""D-P3-003: RLS for the two new TEN tables (standard template). No composite cross-app FK needed this
time - both Test and TestResult stay inside the controls app, an ordinary Django FK (like
ImplementationControl -> CommonControl) is consistent with that precedent. No immutability trigger either -
same D-P3-001/002 precedent: these are living governance records under active reviewer edits (status,
lifecycle), not frozen catalogue content."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_test", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_test_result", "SELECT, INSERT, UPDATE"),
]

REVERSE = [
    *sqlgen.tenant_table_reverse("ten_test_result"),
    *sqlgen.tenant_table_reverse("ten_test"),
]


class Migration(migrations.Migration):
    dependencies = [("controls", "0005_tests_and_test_results")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
