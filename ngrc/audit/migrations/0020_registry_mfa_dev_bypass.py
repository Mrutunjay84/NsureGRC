"""Seed the audit action added for the NGRC_MFA_REQUIRED dev-only bypass (ACTIONS_MFA_DEV_BYPASS).
Registry rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_MFA_DEV_BYPASS


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_MFA_DEV_BYPASS:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0019_registry_notifications")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
