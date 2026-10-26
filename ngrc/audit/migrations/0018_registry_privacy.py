"""Seed the audit actions added for the privacy foundation (D-P4-006, ACTIONS_PRIVACY). Registry rows are
append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_PRIVACY


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_PRIVACY:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0017_registry_compliance_audit")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
