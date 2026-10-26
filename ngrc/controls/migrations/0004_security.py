"""D-P3-002: RLS for the two new TEN tables (standard template), plus the same-tenant composite FK from
`ten_evidence_link.evidence_revision_id` into `ten_evidence_revision` - identical pattern and reasoning to
`ten_evidence_revision.evidence_id` -> `ten_evidence` (evidence/0002_security): a plain single-column Django
FK's referential check runs as the table owner and does not honour RLS, so anything pointing into the
evidence domain specifically (data_class C|R) gets the stronger composite constraint. No immutability
trigger on either new table - same D-P3-001 precedent: both are living governance records a reviewer keeps
editing (review_state, lifecycle), not frozen catalogue content."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_evidence_requirement", "SELECT, INSERT, UPDATE"),
    *sqlgen.tenant_table_forward("ten_evidence_link", "SELECT, INSERT, UPDATE"),
    "ALTER TABLE ten_evidence_link ADD CONSTRAINT ten_evidence_link_revision_fk "
    "FOREIGN KEY (tenant_id, evidence_revision_id) REFERENCES ten_evidence_revision (tenant_id, id)",
]

REVERSE = [
    "ALTER TABLE ten_evidence_link DROP CONSTRAINT IF EXISTS ten_evidence_link_revision_fk",
    *sqlgen.tenant_table_reverse("ten_evidence_link"),
    *sqlgen.tenant_table_reverse("ten_evidence_requirement"),
]


class Migration(migrations.Migration):
    dependencies = [("controls", "0003_evidence_requirements_and_links"),
                    ("evidence", "0003_composite_fk_target_for_evidence_links")]
    operations = [migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE)]
