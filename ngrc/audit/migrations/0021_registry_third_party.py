"""Seed the audit actions added for Third Parties (D-P7-001, ACTIONS_THIRD_PARTY).
Registry rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_THIRD_PARTY


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_THIRD_PARTY:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0020_registry_mfa_dev_bypass")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
