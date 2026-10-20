"""IDN-class security (D-P0-009 s3): the tenant data plane (ngrc_app) gets NO privileges on credential/session/token
tables. It sees only a 4-column projection of idn_account, filtered by RLS, and creates/lists invitations through
SECURITY DEFINER functions bound to its current tenant."""
from django.db import migrations

SEARCH_PATH = "SET search_path = pg_catalog, public"
IDN_TABLES = ["idn_account", "idn_session", "idn_totp_factor", "idn_webauthn_credential", "idn_recovery_code",
              "idn_auth_token", "idn_throttle", "idn_invitation"]

FORWARD = [
    *[f"REVOKE ALL ON {t} FROM PUBLIC" for t in IDN_TABLES],
    *[f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO ngrc_auth" for t in IDN_TABLES],
    # --- RLS on idn_account only to protect the tenant-plane projection
    "ALTER TABLE idn_account ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY auth_all ON idn_account TO ngrc_auth USING (true) WITH CHECK (true)",
    "CREATE POLICY owner_all ON idn_account TO ngrc_owner USING (true) WITH CHECK (true)",
    "CREATE POLICY profile_visibility ON idn_account FOR SELECT TO ngrc_app USING ("
    "id = ngrc_current_principal() OR EXISTS (SELECT 1 FROM ten_membership m "
    "WHERE m.principal_id = idn_account.id AND m.tenant_id = ngrc_current_tenant()))",
    # column-level grant: password_hash & friends are NOT selectable by ngrc_app
    "GRANT SELECT (id, email, display_name, status) ON idn_account TO ngrc_app",

    # --- invitations (tenant admins act only through these functions)
    f"""CREATE FUNCTION idn_create_invitation(p_tenant uuid, p_email text, p_role_id uuid, p_kind text,
                                             p_membership_expires timestamptz, p_token_hash text, p_expires timestamptz)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER {SEARCH_PATH} AS $$
DECLARE v_id uuid := gen_random_uuid();
BEGIN
  IF p_tenant IS NULL OR p_tenant IS DISTINCT FROM ngrc_current_tenant() THEN
    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM ten_role WHERE id = p_role_id AND tenant_id = p_tenant) THEN
    RAISE EXCEPTION 'role not in tenant' USING ERRCODE = '42501'; END IF;
  INSERT INTO idn_invitation (id, subject_tenant_id, email, role_id, kind, membership_expires_at, token_hash,
                              invited_by, created_at, expires_at)
    VALUES (v_id, p_tenant, lower(p_email), p_role_id, p_kind, p_membership_expires, p_token_hash,
            ngrc_current_principal(), now(), p_expires);
  RETURN v_id;
END $$""",
    f"""CREATE FUNCTION idn_list_invitations() RETURNS TABLE (id uuid, email text, role_id uuid, kind text,
  created_at timestamptz, expires_at timestamptz, accepted_at timestamptz, revoked_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER {SEARCH_PATH} AS $$
BEGIN
  IF ngrc_current_tenant() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  RETURN QUERY SELECT i.id, i.email::text, i.role_id, i.kind::text, i.created_at, i.expires_at, i.accepted_at, i.revoked_at
    FROM idn_invitation i WHERE i.subject_tenant_id = ngrc_current_tenant() ORDER BY i.created_at DESC;
END $$""",
    f"""CREATE FUNCTION idn_revoke_invitation(p_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER {SEARCH_PATH} AS $$
DECLARE v_n int;
BEGIN
  IF ngrc_current_tenant() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  UPDATE idn_invitation SET revoked_at = now()
   WHERE id = p_id AND subject_tenant_id = ngrc_current_tenant() AND accepted_at IS NULL AND revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n = 1;
END $$""",
    # --- acceptance runs in the auth service (no tenant context): creates the membership under a transient context
    f"""CREATE FUNCTION ten_membership_from_invitation(p_invitation uuid, p_account uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER {SEARCH_PATH} AS $$
DECLARE
  inv idn_invitation%ROWTYPE;
  v_email text;
  v_prev text := coalesce(current_setting('app.tenant_id', true), '');
  v_id uuid := gen_random_uuid();
BEGIN
  SELECT * INTO inv FROM idn_invitation WHERE id = p_invitation FOR UPDATE;
  IF NOT FOUND OR inv.accepted_at IS NOT NULL OR inv.revoked_at IS NOT NULL OR inv.expires_at <= now() THEN
    RAISE EXCEPTION 'invitation not usable' USING ERRCODE = '42501'; END IF;
  SELECT lower(email) INTO v_email FROM idn_account WHERE id = p_account;
  IF v_email IS DISTINCT FROM lower(inv.email) THEN
    RAISE EXCEPTION 'invitation not issued to this account' USING ERRCODE = '42501'; END IF;
  PERFORM set_config('app.tenant_id', inv.subject_tenant_id::text, true);
  INSERT INTO ten_membership (id, tenant_id, principal_id, role_id, kind, status, expires_at, created_by, created_at)
    VALUES (v_id, inv.subject_tenant_id, p_account, inv.role_id, inv.kind, 'active', inv.membership_expires_at,
            inv.invited_by, now());
  UPDATE idn_invitation SET accepted_at = now() WHERE id = p_invitation;
  PERFORM set_config('app.tenant_id', v_prev, true);
  RETURN v_id;
END $$""",
    "REVOKE ALL ON FUNCTION idn_create_invitation(uuid, text, uuid, text, timestamptz, text, timestamptz) FROM PUBLIC",
    "REVOKE ALL ON FUNCTION idn_list_invitations() FROM PUBLIC",
    "REVOKE ALL ON FUNCTION idn_revoke_invitation(uuid) FROM PUBLIC",
    "REVOKE ALL ON FUNCTION ten_membership_from_invitation(uuid, uuid) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION idn_create_invitation(uuid, text, uuid, text, timestamptz, text, timestamptz) TO ngrc_app",
    "GRANT EXECUTE ON FUNCTION idn_list_invitations() TO ngrc_app",
    "GRANT EXECUTE ON FUNCTION idn_revoke_invitation(uuid) TO ngrc_app",
    "GRANT EXECUTE ON FUNCTION ten_membership_from_invitation(uuid, uuid) TO ngrc_auth",
]

REVERSE = [
    "DROP FUNCTION IF EXISTS ten_membership_from_invitation(uuid, uuid)",
    "DROP FUNCTION IF EXISTS idn_revoke_invitation(uuid)",
    "DROP FUNCTION IF EXISTS idn_list_invitations()",
    "DROP FUNCTION IF EXISTS idn_create_invitation(uuid, text, uuid, text, timestamptz, text, timestamptz)",
    "DROP POLICY IF EXISTS profile_visibility ON idn_account",
]


class Migration(migrations.Migration):
    # needs ten_membership to exist for the projection policy
    dependencies = [("core", "0001_helper_functions"), ("iam", "0001_initial"), ("tenancy", "0001_initial")]
    operations = [migrations.RunSQL(FORWARD, reverse_sql=REVERSE)]
