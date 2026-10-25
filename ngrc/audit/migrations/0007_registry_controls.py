"""Seed the audit actions added for common/implementation controls and control assertions (D-P3-001,
ACTIONS_CONTROLS). Registry rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_CONTROLS


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_CONTROLS:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0006_registry_custom_frameworks")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
