"""Fix: plt_provision_tenant() inserted the Owner invitation without `kind` (NOT NULL, Django-level default only), so tenant
provisioning always failed. Found by the Phase 1 test suite (tests/test_rls_tenant_isolation.py)."""
from django.db import migrations

SEARCH_PATH = "SET search_path = pg_catalog, public"

FORWARD = [
    f"""CREATE OR REPLACE FUNCTION plt_provision_tenant(p_slug text, p_name text, p_owner_email text, p_invite_token_hash text,
                                           p_invite_expires timestamptz, p_roles jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER {SEARCH_PATH} AS $$
DECLARE
  v_tid uuid := gen_random_uuid();
  v_owner_role uuid;
  v_prev text := coalesce(current_setting('app.tenant_id', true), '');
BEGIN
  INSERT INTO plt_tenant (id, slug, name, status, created_at) VALUES (v_tid, p_slug, p_name, 'active', now());
  PERFORM set_config('app.tenant_id', v_tid::text, true);
  INSERT INTO ten_role (id, tenant_id, key, name, permissions, is_system, created_at)
    SELECT gen_random_uuid(), v_tid, r->>'key', r->>'name', r->'permissions', true, now()
    FROM jsonb_array_elements(p_roles) AS r;
  SELECT id INTO v_owner_role FROM ten_role WHERE tenant_id = v_tid AND key = 'owner' AND is_system;
  IF v_owner_role IS NULL THEN RAISE EXCEPTION 'owner role definition missing' USING ERRCODE = '22023'; END IF;
  INSERT INTO idn_invitation (id, subject_tenant_id, email, role_id, kind, token_hash, invited_by, created_at, expires_at)
    VALUES (gen_random_uuid(), v_tid, lower(p_owner_email), v_owner_role, 'member', p_invite_token_hash, NULL, now(),
            p_invite_expires);
  PERFORM set_config('app.tenant_id', v_prev, true);
  RETURN v_tid;
END $$""",
]


class Migration(migrations.Migration):
    dependencies = [("control_plane", "0002_security"), ("iam", "0001_initial")]
    # The previous body is restored by 0002's definition only if 0002 is re-applied; the old body was defective, so the
    # reverse is intentionally a no-op rather than re-installing the broken function.
    operations = [migrations.RunSQL(FORWARD, reverse_sql=migrations.RunSQL.noop)]
