"""Seed audit.action_registry from ngrc.audit.actions.ACTIONS (frozen at release; later changes = new migration)."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_P1 as ACTIONS  # frozen: later additions are seeded by 0003


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_audit_schema")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
