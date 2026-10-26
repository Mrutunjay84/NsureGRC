"""Seed the audit action added for mark_assertion_reviewed (D-P3-004, ACTIONS_ASSERTION_REVIEW). Registry
rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_ASSERTION_REVIEW


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_ASSERTION_REVIEW:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0010_registry_satisfaction")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
