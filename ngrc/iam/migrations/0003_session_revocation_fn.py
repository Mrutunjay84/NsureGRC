"""Lets the tenant plane end a member's sessions bound to ITS tenant (e.g. role reduced, suspended) without any other
privilege on idn_session (D-P0-008 s9: revocation on role/permission reduction)."""
from django.db import migrations

FORWARD = [
    """CREATE FUNCTION idn_revoke_tenant_sessions(p_principal uuid, p_reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_n integer;
BEGIN
  IF ngrc_current_tenant() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  UPDATE idn_session SET revoked_at = now(), revoked_reason = left(p_reason, 64)
   WHERE account_id = p_principal AND tenant_id = ngrc_current_tenant() AND revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$""",
    "REVOKE ALL ON FUNCTION idn_revoke_tenant_sessions(uuid, text) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION idn_revoke_tenant_sessions(uuid, text) TO ngrc_app",
]


class Migration(migrations.Migration):
    dependencies = [("iam", "0002_security")]
    operations = [migrations.RunSQL(FORWARD, reverse_sql=["DROP FUNCTION IF EXISTS idn_revoke_tenant_sessions(uuid, text)"])]
