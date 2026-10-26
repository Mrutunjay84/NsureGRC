"""Seed the audit actions added for findings and security exceptions (D-P4-001, ACTIONS_FINDINGS). Registry
rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_FINDINGS


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_FINDINGS:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0012_registry_tasks")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
