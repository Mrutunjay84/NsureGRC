from django.db import migrations

from ngrc.core import sqlgen


class Migration(migrations.Migration):
    """Tenant-context readers and the tenant_id immutability trigger function used by every TEN table."""

    initial = True
    dependencies = []
    operations = [migrations.RunSQL(sqlgen.CORE_FUNCTIONS_SQL, reverse_sql=sqlgen.CORE_FUNCTIONS_REVERSE)]
