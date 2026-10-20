"""PLT-class security: tenant registry RLS, operator-plane grants, support-grant state machine (DB-enforced),
tenant-side consent functions and tenant provisioning (D-P0-005, D-P0-009).

Runs as ngrc_owner. Functions are SECURITY DEFINER with a pinned search_path; EXECUTE is revoked from PUBLIC and
granted explicitly.
"""
from django.db import migrations

SEARCH_PATH = "SET search_path = pg_catalog, public"

FORWARD = [
    # ---------------------------------------------------------------- plt_tenant (readable by tenant plane: own row only)
    "ALTER TABLE plt_tenant ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE plt_tenant FORCE ROW LEVEL SECURITY",
    "REVOKE ALL ON plt_tenant FROM PUBLIC",
    "CREATE POLICY app_own_row ON plt_tenant FOR SELECT TO ngrc_app USING (id = ngrc_current_tenant())",
    "CREATE POLICY auth_read ON plt_tenant FOR SELECT TO ngrc_auth USING (true)",
    "CREATE POLICY ops_all ON plt_tenant TO ngrc_ops USING (true) WITH CHECK (true)",
    "CREATE POLICY owner_all ON plt_tenant TO ngrc_owner USING (true) WITH CHECK (true)",
    "GRANT SELECT ON plt_tenant TO ngrc_app, ngrc_auth",
    "GRANT SELECT, INSERT, UPDATE ON plt_tenant TO ngrc_ops",   # no DELETE: offboarding is a later, ADR'd workflow
    # ---------------------------------------------------------------- operator realm tables: ngrc_ops only
    *[f"REVOKE ALL ON {t} FROM PUBLIC" for t in (
        "plt_operator_account", "plt_operator_role", "plt_operator_session",
        "plt_operator_webauthn_credential", "plt_operator_throttle", "plt_support_access_grant")],
    *[f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO ngrc_ops" for t in (
        "plt_operator_account", "plt_operator_role", "plt_operator_session",
        "plt_operator_webauthn_credential", "plt_operator_throttle")],
    # ---------------------------------------------------------------- support grants
    # ngrc_ops may INSERT/SELECT and UPDATE ONLY operator-side columns. Consent columns are NOT updatable by ngrc_ops.
    "GRANT SELECT, INSERT ON plt_support_access_grant TO ngrc_ops",
    "GRANT UPDATE (state, approver_id, approved_at, second_approver_id, activated_at, expires_at, ended_at, "
    "ended_by_type) ON plt_support_access_grant TO ngrc_ops",
    "GRANT SELECT ON plt_support_access_grant TO ngrc_audit_owner",   # audit function verifies an active grant
    "GRANT SELECT ON plt_operator_role TO ngrc_audit_owner",
    """CREATE FUNCTION plt_support_grant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_max int;
  v_by_owner boolean := (current_user = 'ngrc_owner');   -- true only inside our SECURITY DEFINER functions
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'requested' THEN RAISE EXCEPTION 'grant must start in state requested' USING ERRCODE = '23514'; END IF;
    IF btrim(NEW.ticket_ref) = '' OR btrim(NEW.reason) = '' THEN
      RAISE EXCEPTION 'ticket reference and reason are mandatory' USING ERRCODE = '23514';
    END IF;
    v_max := CASE WHEN NEW.break_glass THEN 120 ELSE 480 END;
    IF NEW.duration_minutes < 1 OR NEW.duration_minutes > v_max THEN
      RAISE EXCEPTION 'duration outside permitted maximum' USING ERRCODE = '23514';
    END IF;
    IF NEW.approver_id IS NOT NULL OR NEW.second_approver_id IS NOT NULL OR NEW.consent_user_id IS NOT NULL
       OR NEW.activated_at IS NOT NULL OR NEW.expires_at IS NOT NULL OR NEW.restricted_class_consent THEN
      RAISE EXCEPTION 'approval/consent/activation fields must be empty on insert' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM plt_operator_role r WHERE r.operator_id = NEW.requester_id
                   AND r.role IN ('platform_support', 'platform_admin')) THEN
      RAISE EXCEPTION 'requester lacks a role that may request support access' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;

  -- UPDATE: identity of the request is immutable
  IF NEW.id <> OLD.id OR NEW.subject_tenant_id <> OLD.subject_tenant_id OR NEW.requester_id <> OLD.requester_id
     OR NEW.ticket_ref <> OLD.ticket_ref OR NEW.reason <> OLD.reason OR NEW.profile <> OLD.profile
     OR NEW.scope::text <> OLD.scope::text OR NEW.duration_minutes <> OLD.duration_minutes
     OR NEW.break_glass <> OLD.break_glass OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'grant request fields are immutable' USING ERRCODE = '42501';
  END IF;
  IF OLD.state IN ('expired', 'revoked', 'denied') THEN
    RAISE EXCEPTION 'grant is in a terminal state' USING ERRCODE = '42501';
  END IF;
  -- consent columns only change inside the tenant-side SECURITY DEFINER functions
  IF (NEW.consent_user_id IS DISTINCT FROM OLD.consent_user_id OR NEW.consented_at IS DISTINCT FROM OLD.consented_at
      OR NEW.restricted_class_consent IS DISTINCT FROM OLD.restricted_class_consent) AND NOT v_by_owner THEN
    RAISE EXCEPTION 'tenant consent can only be recorded by the tenant' USING ERRCODE = '42501';
  END IF;
  -- approver fields are write-once
  IF OLD.approver_id IS NOT NULL AND NEW.approver_id IS DISTINCT FROM OLD.approver_id THEN
    RAISE EXCEPTION 'approver cannot be changed' USING ERRCODE = '42501'; END IF;
  IF OLD.second_approver_id IS NOT NULL AND NEW.second_approver_id IS DISTINCT FROM OLD.second_approver_id THEN
    RAISE EXCEPTION 'second approver cannot be changed' USING ERRCODE = '42501'; END IF;

  IF NEW.state = OLD.state THEN
    RETURN NEW;   -- non-state column touch (already constrained above)
  END IF;

  IF OLD.state = 'requested' AND NEW.state = 'approved' THEN
    IF NEW.approver_id IS NULL OR NEW.approved_at IS NULL THEN RAISE EXCEPTION 'approval incomplete' USING ERRCODE = '23514'; END IF;
    IF NEW.approver_id = NEW.requester_id THEN
      RAISE EXCEPTION 'requester cannot approve own request' USING ERRCODE = '42501'; END IF;
    IF NOT EXISTS (SELECT 1 FROM plt_operator_role r WHERE r.operator_id = NEW.approver_id AND r.role = 'platform_security') THEN
      RAISE EXCEPTION 'approver must hold platform_security' USING ERRCODE = '42501'; END IF;
    IF NEW.break_glass THEN
      IF NEW.second_approver_id IS NULL OR NEW.second_approver_id IN (NEW.requester_id, NEW.approver_id) THEN
        RAISE EXCEPTION 'break-glass needs a distinct second approver' USING ERRCODE = '42501'; END IF;
      IF NOT EXISTS (SELECT 1 FROM plt_operator_role r WHERE r.operator_id = NEW.second_approver_id AND r.role = 'platform_admin') THEN
        RAISE EXCEPTION 'second approver must hold platform_admin' USING ERRCODE = '42501'; END IF;
    ELSIF NEW.second_approver_id IS NOT NULL THEN
      RAISE EXCEPTION 'second approver only applies to break-glass' USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.state = 'approved' AND NEW.state = 'tenant_consented' THEN
    IF NEW.break_glass THEN RAISE EXCEPTION 'break-glass grants skip tenant consent' USING ERRCODE = '42501'; END IF;
    IF NOT v_by_owner OR NEW.consent_user_id IS NULL OR NEW.consented_at IS NULL THEN
      RAISE EXCEPTION 'tenant consent must be recorded by the tenant' USING ERRCODE = '42501'; END IF;
  ELSIF (OLD.state = 'tenant_consented' AND NEW.state = 'active' AND NOT OLD.break_glass)
        OR (OLD.state = 'approved' AND NEW.state = 'active' AND OLD.break_glass) THEN
    IF NEW.activated_at IS NULL OR NEW.expires_at IS NULL THEN RAISE EXCEPTION 'activation incomplete' USING ERRCODE = '23514'; END IF;
    IF abs(extract(epoch FROM (NEW.activated_at - now()))) > 120 THEN
      RAISE EXCEPTION 'activation time must be current' USING ERRCODE = '23514'; END IF;
    IF NEW.expires_at <= NEW.activated_at
       OR NEW.expires_at > NEW.activated_at + (OLD.duration_minutes * interval '1 minute') THEN
      RAISE EXCEPTION 'expiry exceeds granted duration' USING ERRCODE = '23514'; END IF;
  ELSIF OLD.state = 'active' AND NEW.state IN ('expired', 'revoked') THEN
    IF NEW.ended_at IS NULL THEN RAISE EXCEPTION 'ended_at required' USING ERRCODE = '23514'; END IF;
  ELSIF OLD.state IN ('requested', 'approved', 'tenant_consented') AND NEW.state IN ('denied', 'revoked') THEN
    IF NEW.ended_at IS NULL THEN RAISE EXCEPTION 'ended_at required' USING ERRCODE = '23514'; END IF;
  ELSE
    RAISE EXCEPTION 'illegal grant transition % -> %', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF NEW.state IN ('denied', 'revoked', 'expired') AND NEW.ended_by_type = '' THEN
    RAISE EXCEPTION 'ended_by_type required' USING ERRCODE = '23514'; END IF;
  IF NEW.ended_by_type = 'tenant' AND NOT v_by_owner THEN
    RAISE EXCEPTION 'tenant-ended grants are recorded only via the tenant functions' USING ERRCODE = '42501'; END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER plt_support_grant_guard BEFORE INSERT OR UPDATE ON plt_support_access_grant "
    "FOR EACH ROW EXECUTE FUNCTION plt_support_grant_guard()",
    # no DELETE/TRUNCATE of grants at all (history is evidence)
    """CREATE FUNCTION plt_support_grant_no_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'support grants are never deleted' USING ERRCODE = '42501'; END $$""",
    "CREATE TRIGGER plt_support_grant_no_delete BEFORE DELETE ON plt_support_access_grant "
    "FOR EACH ROW EXECUTE FUNCTION plt_support_grant_no_delete()",
    "CREATE TRIGGER plt_support_grant_no_truncate BEFORE TRUNCATE ON plt_support_access_grant "
    "FOR EACH STATEMENT EXECUTE FUNCTION plt_support_grant_no_delete()",

    # ---------------------------------------------------------------- tenant-side functions (ngrc_app, bound to current tenant)
    f"""CREATE FUNCTION plt_grant_tenant_decide(p_grant uuid, p_action text, p_restricted boolean DEFAULT false)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER {SEARCH_PATH} AS $$
DECLARE
  g plt_support_access_grant%ROWTYPE;
  v_principal uuid := ngrc_current_principal();
BEGIN
  SELECT * INTO g FROM plt_support_access_grant WHERE id = p_grant FOR UPDATE;
  IF NOT FOUND OR g.subject_tenant_id IS DISTINCT FROM ngrc_current_tenant() THEN
    RAISE EXCEPTION 'grant not found' USING ERRCODE = '42501';
  END IF;
  IF v_principal IS NULL OR NOT EXISTS (
       SELECT 1 FROM ten_membership m JOIN ten_role r ON r.id = m.role_id AND r.tenant_id = m.tenant_id
       WHERE m.principal_id = v_principal AND m.status = 'active' AND (m.expires_at IS NULL OR m.expires_at > now())
         AND r.is_system AND r.key = 'owner') THEN
    RAISE EXCEPTION 'only a tenant Owner may decide on support access' USING ERRCODE = '42501';
  END IF;
  IF p_action = 'consent' THEN
    IF g.state <> 'approved' OR g.break_glass THEN RAISE EXCEPTION 'grant not awaiting consent' USING ERRCODE = '42501'; END IF;
    UPDATE plt_support_access_grant SET state = 'tenant_consented', consent_user_id = v_principal,
           consented_at = now(), restricted_class_consent = coalesce(p_restricted, false) WHERE id = p_grant;
  ELSIF p_action = 'deny' THEN
    IF g.state NOT IN ('requested', 'approved', 'tenant_consented') THEN RAISE EXCEPTION 'grant cannot be denied' USING ERRCODE = '42501'; END IF;
    UPDATE plt_support_access_grant SET state = 'denied', ended_at = now(), ended_by_type = 'tenant' WHERE id = p_grant;
  ELSIF p_action = 'revoke' THEN
    IF g.state NOT IN ('approved', 'tenant_consented', 'active') THEN RAISE EXCEPTION 'grant cannot be revoked' USING ERRCODE = '42501'; END IF;
    UPDATE plt_support_access_grant SET state = 'revoked', ended_at = now(), ended_by_type = 'tenant' WHERE id = p_grant;
  ELSE
    RAISE EXCEPTION 'unknown action' USING ERRCODE = '22023';
  END IF;
END $$""",
    f"""CREATE FUNCTION plt_list_grants_for_tenant() RETURNS TABLE (
  id uuid, ticket_ref text, reason text, profile text, scope jsonb, duration_minutes int, break_glass boolean,
  state text, requester_name text, approved_at timestamptz, consented_at timestamptz, activated_at timestamptz,
  expires_at timestamptz, ended_at timestamptz, ended_by_type text, restricted_class_consent boolean, created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER {SEARCH_PATH} AS $$
BEGIN
  IF ngrc_current_tenant() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  RETURN QUERY
    SELECT g.id, g.ticket_ref::text, g.reason, g.profile::text, g.scope::jsonb, g.duration_minutes, g.break_glass,
           g.state::text, o.display_name::text, g.approved_at, g.consented_at, g.activated_at, g.expires_at, g.ended_at,
           g.ended_by_type::text, g.restricted_class_consent, g.created_at
    FROM plt_support_access_grant g JOIN plt_operator_account o ON o.id = g.requester_id
    WHERE g.subject_tenant_id = ngrc_current_tenant() ORDER BY g.created_at DESC;
END $$""",
    "REVOKE ALL ON FUNCTION plt_grant_tenant_decide(uuid, text, boolean) FROM PUBLIC",
    "REVOKE ALL ON FUNCTION plt_list_grants_for_tenant() FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION plt_grant_tenant_decide(uuid, text, boolean) TO ngrc_app",
    "GRANT EXECUTE ON FUNCTION plt_list_grants_for_tenant() TO ngrc_app",

    # ---------------------------------------------------------------- tenant provisioning (ngrc_ops; narrowly scoped, D-P0-003 s8)
    f"""CREATE FUNCTION plt_provision_tenant(p_slug text, p_name text, p_owner_email text, p_invite_token_hash text,
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
  INSERT INTO idn_invitation (id, subject_tenant_id, email, role_id, token_hash, invited_by, created_at, expires_at)
    VALUES (gen_random_uuid(), v_tid, lower(p_owner_email), v_owner_role, p_invite_token_hash, NULL, now(), p_invite_expires);
  PERFORM set_config('app.tenant_id', v_prev, true);
  RETURN v_tid;
END $$""",
    "REVOKE ALL ON FUNCTION plt_provision_tenant(text, text, text, text, timestamptz, jsonb) FROM PUBLIC",
    "GRANT EXECUTE ON FUNCTION plt_provision_tenant(text, text, text, text, timestamptz, jsonb) TO ngrc_ops",
]

REVERSE = [
    "DROP FUNCTION IF EXISTS plt_provision_tenant(text, text, text, text, timestamptz, jsonb)",
    "DROP FUNCTION IF EXISTS plt_list_grants_for_tenant()",
    "DROP FUNCTION IF EXISTS plt_grant_tenant_decide(uuid, text, boolean)",
    "DROP TRIGGER IF EXISTS plt_support_grant_no_truncate ON plt_support_access_grant",
    "DROP TRIGGER IF EXISTS plt_support_grant_no_delete ON plt_support_access_grant",
    "DROP TRIGGER IF EXISTS plt_support_grant_guard ON plt_support_access_grant",
    "DROP FUNCTION IF EXISTS plt_support_grant_no_delete()",
    "DROP FUNCTION IF EXISTS plt_support_grant_guard()",
]


class Migration(migrations.Migration):
    dependencies = [("core", "0001_helper_functions"), ("control_plane", "0001_initial")]
    operations = [migrations.RunSQL(FORWARD, reverse_sql=REVERSE)]
