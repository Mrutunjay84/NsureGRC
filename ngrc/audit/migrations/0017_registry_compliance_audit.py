"""Seed the audit actions added for compliance audits and audit items (D-P4-005,
ACTIONS_COMPLIANCE_AUDIT). Registry rows are append-only; this migration only adds rows."""
from django.db import migrations

from ngrc.audit.actions import ACTIONS_COMPLIANCE_AUDIT


def seed(apps, schema_editor):
    with schema_editor.connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE ngrc_audit_owner")
        for a in ACTIONS_COMPLIANCE_AUDIT:
            cur.execute(
                "INSERT INTO audit.action_registry (action, category, severity, stream, allowed_detail_keys, writers) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                [a.name, a.category, a.severity, a.stream, list(a.detail_keys), list(a.writers)],
            )
        cur.execute("RESET ROLE")


class Migration(migrations.Migration):
    dependencies = [("audit", "0016_registry_governance")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
