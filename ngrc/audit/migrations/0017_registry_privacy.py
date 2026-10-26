"""Seed the audit actions added for the privacy foundation (D-P4-006, ACTIONS_PRIVACY). Registry rows are
append-only; this migration only adds rows.

NOTE: this branch was cut before D-P4-005's compliance_audit migration (also claiming 0017) merged to
main - renumbered to 0018 (dependency updated) when this branch is rebased onto main, before opening the
PR, same pattern as D-P3/D-P4's other parallel-branch increments."""
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
    dependencies = [("audit", "0016_registry_governance")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
