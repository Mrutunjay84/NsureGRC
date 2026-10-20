"""IDN tables must not carry a plain `tenant_id` (D-P0-009 s2.2): rename idn_session.tenant_id -> active_tenant_id and
redefine the one SQL function that referenced the column."""
from django.db import migrations

FORWARD = [
    """CREATE OR REPLACE FUNCTION idn_revoke_tenant_sessions(p_principal uuid, p_reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_n integer;
BEGIN
  IF ngrc_current_tenant() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  UPDATE idn_session SET revoked_at = now(), revoked_reason = left(p_reason, 64)
   WHERE account_id = p_principal AND active_tenant_id = ngrc_current_tenant() AND revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$""",
]


class Migration(migrations.Migration):
    dependencies = [("iam", "0003_session_revocation_fn")]
    operations = [
        migrations.RenameField("session", "tenant_id", "active_tenant_id"),
        migrations.RunSQL(FORWARD, reverse_sql=migrations.RunSQL.noop),
    ]
