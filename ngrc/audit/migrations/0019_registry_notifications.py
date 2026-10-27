"""Seed the audit action added for the notification service core (D-P5-007, ACTIONS_NOTIFICATIONS).
Registry rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_NOTIFICATIONS


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_NOTIFICATIONS:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0018_registry_privacy")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
