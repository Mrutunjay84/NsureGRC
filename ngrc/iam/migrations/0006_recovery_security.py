"""F-ATH-014 / F-ATH-015 database controls.

1. FACTOR GUARD: a trigger refuses to delete an account's last USABLE factor (confirmed TOTP / non-cloned WebAuthn credential) for every role except
   the owner role (used only by the recovery-completion function and migrations). Concurrent removals serialise on the account row, so two
   simultaneous requests cannot both succeed. The operator realm gets the same guard (operators have no self-service removal at all).
2. RECOVERY REQUEST: no runtime role can INSERT/UPDATE; every change is made by a SECURITY DEFINER function that checks the caller; a trigger
   enforces the state machine, approver independence (never the account itself), the realm of the approver per kind, the cooling-off window
   (cooling_until = approved_at + cooling_seconds, completion impossible earlier) and immutability of terminal states - even against the owner role.
3. Functions: create (auth service), cancel (public cancel link), complete (auth service; deletes the old factors), tenant list/decide (Owner/Admin
   of the target's tenant, never the target), platform list/decide (Platform Security only, sole-Owner requests only), notify targets.
"""
from django.db import migrations

SP = "SET search_path = pg_catalog, public"

FORWARD = [
    # ------------------------------------------------------------------------------------------------ factor guards
    """CREATE FUNCTION idn_factor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_other int;
BEGIN
  IF current_user = 'ngrc_owner' THEN RETURN OLD; END IF;   -- recovery completion / migrations (reviewed SECURITY DEFINER path)
  IF TG_TABLE_NAME = 'idn_totp_factor' THEN                                                           -- (nested: OLD fields differ per table)
    IF OLD.confirmed_at IS NULL THEN RETURN OLD; END IF;                                              -- unfinished enrolment is not a factor
  ELSE
    IF OLD.flagged_clone THEN RETURN OLD; END IF;                                                     -- a cloned credential is not usable
  END IF;
  PERFORM 1 FROM idn_account WHERE id = OLD.account_id FOR UPDATE;                                     -- serialise concurrent removals
  IF NOT FOUND THEN RETURN OLD; END IF;                                                                -- the account itself is being deleted
  SELECT (SELECT count(*) FROM idn_totp_factor t WHERE t.account_id = OLD.account_id AND t.confirmed_at IS NOT NULL
                AND NOT (TG_TABLE_NAME = 'idn_totp_factor' AND t.id = OLD.id))
       + (SELECT count(*) FROM idn_webauthn_credential w WHERE w.account_id = OLD.account_id AND NOT w.flagged_clone
                AND NOT (TG_TABLE_NAME = 'idn_webauthn_credential' AND w.id = OLD.id))
    INTO v_other;
  IF v_other < 1 THEN
    RAISE EXCEPTION 'the last usable authentication factor cannot be removed' USING ERRCODE = '42501';
  END IF;
  RETURN OLD;
END $$""",
    "CREATE TRIGGER idn_totp_factor_guard BEFORE DELETE ON idn_totp_factor FOR EACH ROW EXECUTE FUNCTION idn_factor_guard()",
    "CREATE TRIGGER idn_webauthn_credential_guard BEFORE DELETE ON idn_webauthn_credential FOR EACH ROW EXECUTE FUNCTION idn_factor_guard()",
    """CREATE FUNCTION plt_credential_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_other int;
BEGIN
  IF current_user = 'ngrc_owner' OR OLD.flagged_clone THEN RETURN OLD; END IF;
  PERFORM 1 FROM plt_operator_account WHERE id = OLD.account_id FOR UPDATE;
  IF NOT FOUND THEN RETURN OLD; END IF;
  SELECT count(*) INTO v_other FROM plt_operator_webauthn_credential w WHERE w.account_id = OLD.account_id AND NOT w.flagged_clone AND w.id <> OLD.id;
  IF v_other < 1 THEN
    RAISE EXCEPTION 'the last usable operator credential cannot be removed' USING ERRCODE = '42501';
  END IF;
  RETURN OLD;
END $$""",
    "CREATE TRIGGER plt_operator_webauthn_credential_guard BEFORE DELETE ON plt_operator_webauthn_credential FOR EACH ROW EXECUTE FUNCTION plt_credential_guard()",

    # ------------------------------------------------------------------------------------------------ recovery request: privileges + state machine
    "REVOKE ALL ON idn_recovery_request FROM PUBLIC",
    "GRANT SELECT ON idn_recovery_request TO ngrc_auth",
    """CREATE FUNCTION idn_recovery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_by_owner boolean := (current_user = 'ngrc_owner');   -- true only inside our SECURITY DEFINER functions
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NOT v_by_owner THEN RAISE EXCEPTION 'recovery requests are created only through idn_recovery_create' USING ERRCODE = '42501'; END IF;
    IF NEW.state <> 'requested' OR NEW.approver_id IS NOT NULL OR NEW.approver_realm IS NOT NULL OR NEW.approved_at IS NOT NULL
       OR NEW.cooling_until IS NOT NULL OR NEW.ended_at IS NOT NULL OR NEW.ended_reason IS NOT NULL THEN
      RAISE EXCEPTION 'a new recovery request must be empty of decisions' USING ERRCODE = '23514'; END IF;
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.account_id <> OLD.account_id OR NEW.subject_tenant_id <> OLD.subject_tenant_id OR NEW.kind <> OLD.kind
     OR NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at OR NEW.cooling_seconds <> OLD.cooling_seconds
     OR NEW.cancel_token_hash <> OLD.cancel_token_hash OR NEW.request_ip IS DISTINCT FROM OLD.request_ip THEN
    RAISE EXCEPTION 'recovery request identity is immutable' USING ERRCODE = '42501'; END IF;
  IF OLD.state IN ('cancelled', 'completed', 'expired') THEN
    RAISE EXCEPTION 'recovery request is in a terminal state' USING ERRCODE = '42501'; END IF;
  IF NOT v_by_owner THEN RAISE EXCEPTION 'recovery requests change only through their functions' USING ERRCODE = '42501'; END IF;
  IF OLD.approver_id IS NOT NULL AND (NEW.approver_id IS DISTINCT FROM OLD.approver_id OR NEW.approver_realm IS DISTINCT FROM OLD.approver_realm
     OR NEW.approved_at IS DISTINCT FROM OLD.approved_at OR NEW.cooling_until IS DISTINCT FROM OLD.cooling_until) THEN
    RAISE EXCEPTION 'the approval and the cooling-off window are write-once' USING ERRCODE = '42501'; END IF;

  IF OLD.state = 'requested' AND NEW.state = 'approved' THEN
    IF NEW.approver_id IS NULL OR NEW.approved_at IS NULL OR NEW.cooling_until IS NULL THEN
      RAISE EXCEPTION 'approval incomplete' USING ERRCODE = '23514'; END IF;
    IF NEW.approver_id = NEW.account_id THEN
      RAISE EXCEPTION 'nobody can approve their own recovery' USING ERRCODE = '42501'; END IF;
    IF NEW.approver_realm IS DISTINCT FROM (CASE NEW.kind WHEN 'admin_assisted' THEN 'tenant' ELSE 'platform' END) THEN
      RAISE EXCEPTION 'this kind of recovery needs a different approver realm' USING ERRCODE = '42501'; END IF;
    IF abs(extract(epoch FROM (NEW.approved_at - now()))) > 120 THEN
      RAISE EXCEPTION 'approval time must be current' USING ERRCODE = '23514'; END IF;
    IF NEW.cooling_until <> NEW.approved_at + (NEW.cooling_seconds * interval '1 second') THEN
      RAISE EXCEPTION 'the cooling-off window cannot be shortened or extended' USING ERRCODE = '42501'; END IF;
    IF now() >= NEW.expires_at THEN RAISE EXCEPTION 'request expired' USING ERRCODE = '42501'; END IF;
  ELSIF OLD.state = 'approved' AND NEW.state = 'completed' THEN
    IF now() < OLD.cooling_until THEN RAISE EXCEPTION 'the cooling-off period has not elapsed' USING ERRCODE = '42501'; END IF;
    IF now() >= OLD.expires_at THEN RAISE EXCEPTION 'request expired' USING ERRCODE = '42501'; END IF;
    IF NEW.ended_at IS NULL THEN RAISE EXCEPTION 'ended_at required' USING ERRCODE = '23514'; END IF;
  ELSIF OLD.state IN ('requested', 'approved') AND NEW.state = 'cancelled' THEN
    IF NEW.ended_at IS NULL OR NEW.ended_reason IS NULL THEN RAISE EXCEPTION 'cancellation incomplete' USING ERRCODE = '23514'; END IF;
  ELSIF OLD.state IN ('requested', 'approved') AND NEW.state = 'expired' THEN
    IF now() < OLD.expires_at THEN RAISE EXCEPTION 'not yet expired' USING ERRCODE = '23514'; END IF;
  ELSE
    RAISE EXCEPTION 'illegal recovery transition % -> %', OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER idn_recovery_guard BEFORE INSERT OR UPDATE ON idn_recovery_request FOR EACH ROW EXECUTE FUNCTION idn_recovery_guard()",
    """CREATE FUNCTION idn_recovery_no_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'recovery requests are never deleted' USING ERRCODE = '42501'; END $$""",
    "CREATE TRIGGER idn_recovery_no_delete BEFORE DELETE ON idn_recovery_request FOR EACH ROW EXECUTE FUNCTION idn_recovery_no_delete()",
    "CREATE TRIGGER idn_recovery_no_truncate BEFORE TRUNCATE ON idn_recovery_request FOR EACH STATEMENT EXECUTE FUNCTION idn_recovery_no_delete()",

    # ------------------------------------------------------------------------------------------------ functions
    f"""CREATE FUNCTION idn_recovery_create(p_account uuid, p_tenant uuid, p_cooling int, p_expires timestamptz, p_cancel_hash text, p_ip inet)
RETURNS TABLE (id uuid, kind text) LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
DECLARE
  v_prev text := coalesce(current_setting('app.tenant_id', true), '');
  v_id uuid := gen_random_uuid();
  v_peers int; v_kind text;
BEGIN
  PERFORM set_config('app.tenant_id', p_tenant::text, true);
  IF NOT EXISTS (SELECT 1 FROM idn_account a WHERE a.id = p_account AND a.status = 'active') THEN
    RAISE EXCEPTION 'account not active' USING ERRCODE = '42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM ten_membership m WHERE m.principal_id = p_account AND m.tenant_id = p_tenant AND m.status = 'active'
                 AND (m.expires_at IS NULL OR m.expires_at > now())) THEN
    RAISE EXCEPTION 'not an active member of that tenant' USING ERRCODE = '42501'; END IF;
  SELECT count(*) INTO v_peers FROM ten_membership m JOIN ten_role r ON r.id = m.role_id AND r.tenant_id = m.tenant_id
   WHERE m.tenant_id = p_tenant AND m.principal_id <> p_account AND m.status = 'active' AND (m.expires_at IS NULL OR m.expires_at > now())
     AND r.is_system AND r.key IN ('owner', 'admin');
  v_kind := CASE WHEN v_peers > 0 THEN 'admin_assisted' ELSE 'last_owner' END;
  UPDATE idn_recovery_request q SET state = 'expired', ended_at = now(), ended_reason = 'expired'
   WHERE q.account_id = p_account AND q.state IN ('requested', 'approved') AND q.expires_at <= now();
  INSERT INTO idn_recovery_request (id, account_id, subject_tenant_id, kind, state, created_at, expires_at, cooling_seconds,
                                    cancel_token_hash, request_ip)
    VALUES (v_id, p_account, p_tenant, v_kind, 'requested', now(), p_expires, p_cooling, p_cancel_hash, p_ip);
  PERFORM set_config('app.tenant_id', v_prev, true);
  RETURN QUERY SELECT v_id, v_kind;
END $$""",
    f"""CREATE FUNCTION idn_recovery_notify_targets(p_request uuid) RETURNS TABLE (email text)
LANGUAGE plpgsql STABLE SECURITY DEFINER {SP} AS $$
DECLARE v_prev text := coalesce(current_setting('app.tenant_id', true), ''); r idn_recovery_request%ROWTYPE;
BEGIN
  SELECT * INTO r FROM idn_recovery_request WHERE idn_recovery_request.id = p_request;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id', r.subject_tenant_id::text, true);
  RETURN QUERY SELECT a.email::text FROM ten_membership m JOIN ten_role ro ON ro.id = m.role_id AND ro.tenant_id = m.tenant_id
    JOIN idn_account a ON a.id = m.principal_id
   WHERE m.tenant_id = r.subject_tenant_id AND m.principal_id <> r.account_id AND m.status = 'active'
     AND (m.expires_at IS NULL OR m.expires_at > now()) AND ro.is_system AND ro.key IN ('owner', 'admin') AND a.status = 'active';
  PERFORM set_config('app.tenant_id', v_prev, true);
END $$""",
    f"""CREATE FUNCTION idn_recovery_cancel(p_token_hash text) RETURNS TABLE (account_id uuid, subject_tenant_id uuid, kind text)
LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
BEGIN
  RETURN QUERY WITH u AS (
    UPDATE idn_recovery_request q SET state = 'cancelled', ended_at = now(), ended_reason = 'cancelled_by_user'
     WHERE q.cancel_token_hash = p_token_hash AND q.state IN ('requested', 'approved') AND q.expires_at > now()
     RETURNING q.account_id AS a_id, q.subject_tenant_id AS t_id, q.kind::text AS k)
   SELECT u.a_id, u.t_id, u.k FROM u;
END $$""",
    f"""CREATE FUNCTION idn_recovery_cancel_for_account(p_request uuid, p_account uuid) RETURNS TABLE (subject_tenant_id uuid, kind text)
LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
BEGIN
  RETURN QUERY WITH u AS (
    UPDATE idn_recovery_request q SET state = 'cancelled', ended_at = now(), ended_reason = 'cancelled_by_user'
     WHERE q.id = p_request AND q.account_id = p_account AND q.state IN ('requested', 'approved') AND q.expires_at > now()
     RETURNING q.subject_tenant_id AS t_id, q.kind::text AS k)
   SELECT u.t_id, u.k FROM u;
END $$""",
    f"""CREATE FUNCTION idn_recovery_complete(p_request uuid, p_account uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
DECLARE r idn_recovery_request%ROWTYPE;
BEGIN
  SELECT * INTO r FROM idn_recovery_request q WHERE q.id = p_request AND q.account_id = p_account FOR UPDATE;
  IF NOT FOUND OR r.state <> 'approved' THEN RAISE EXCEPTION 'recovery not approved' USING ERRCODE = '42501'; END IF;
  IF now() < r.cooling_until THEN RAISE EXCEPTION 'recovery cannot complete before the cooling-off period has elapsed' USING ERRCODE = '42501'; END IF;
  IF now() >= r.expires_at THEN RAISE EXCEPTION 'request expired' USING ERRCODE = '42501'; END IF;
  DELETE FROM idn_totp_factor WHERE account_id = p_account;
  DELETE FROM idn_webauthn_credential WHERE account_id = p_account;
  DELETE FROM idn_recovery_code WHERE account_id = p_account;
  UPDATE idn_recovery_request SET state = 'completed', ended_at = now(), ended_reason = 'completed' WHERE id = p_request;
  RETURN true;
END $$""",
    f"""CREATE FUNCTION idn_recovery_tenant_list() RETURNS TABLE (id uuid, account_id uuid, display_name text, email text, kind text, state text,
  created_at timestamptz, expires_at timestamptz, approved_at timestamptz, cooling_until timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER {SP} AS $$
BEGIN
  IF ngrc_current_tenant() IS NULL OR ngrc_current_principal() IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM ten_membership m JOIN ten_role ro ON ro.id = m.role_id AND ro.tenant_id = m.tenant_id
                  WHERE m.principal_id = ngrc_current_principal() AND m.tenant_id = ngrc_current_tenant() AND m.status = 'active'
                    AND (m.expires_at IS NULL OR m.expires_at > now()) AND ro.is_system AND ro.key IN ('owner', 'admin')) THEN
    RAISE EXCEPTION 'only a tenant Owner or Administrator may see recovery requests' USING ERRCODE = '42501'; END IF;
  RETURN QUERY SELECT q.id, q.account_id, a.display_name::text, a.email::text, q.kind::text, q.state::text, q.created_at, q.expires_at,
                      q.approved_at, q.cooling_until
    FROM idn_recovery_request q JOIN idn_account a ON a.id = q.account_id
   WHERE q.subject_tenant_id = ngrc_current_tenant() AND q.kind = 'admin_assisted' ORDER BY q.created_at DESC LIMIT 100;
END $$""",
    f"""CREATE FUNCTION idn_recovery_tenant_decide(p_request uuid, p_action text) RETURNS TABLE (account_id uuid, cooling_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
DECLARE r idn_recovery_request%ROWTYPE; v_me uuid := ngrc_current_principal();
BEGIN
  IF ngrc_current_tenant() IS NULL OR v_me IS NULL THEN RAISE EXCEPTION 'tenant context required' USING ERRCODE = '42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM ten_membership m JOIN ten_role ro ON ro.id = m.role_id AND ro.tenant_id = m.tenant_id
                  WHERE m.principal_id = v_me AND m.tenant_id = ngrc_current_tenant() AND m.status = 'active'
                    AND (m.expires_at IS NULL OR m.expires_at > now()) AND ro.is_system AND ro.key IN ('owner', 'admin')) THEN
    RAISE EXCEPTION 'only a tenant Owner or Administrator may decide on recovery' USING ERRCODE = '42501'; END IF;
  SELECT * INTO r FROM idn_recovery_request q WHERE q.id = p_request AND q.subject_tenant_id = ngrc_current_tenant() AND q.kind = 'admin_assisted' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'recovery request not found' USING ERRCODE = '42501'; END IF;
  IF r.account_id = v_me THEN RAISE EXCEPTION 'nobody can decide on their own recovery' USING ERRCODE = '42501'; END IF;
  IF r.state <> 'requested' OR r.expires_at <= now() THEN RAISE EXCEPTION 'request is not awaiting a decision' USING ERRCODE = '42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM ten_membership m WHERE m.principal_id = r.account_id AND m.tenant_id = ngrc_current_tenant() AND m.status = 'active') THEN
    RAISE EXCEPTION 'the requester is no longer a member' USING ERRCODE = '42501'; END IF;
  IF p_action = 'approve' THEN
    UPDATE idn_recovery_request SET state = 'approved', approver_id = v_me, approver_realm = 'tenant', approved_at = now(),
           cooling_until = now() + (cooling_seconds * interval '1 second') WHERE id = p_request;
  ELSIF p_action = 'deny' THEN
    UPDATE idn_recovery_request SET state = 'cancelled', ended_at = now(), ended_reason = 'denied_by_approver' WHERE id = p_request;
  ELSE RAISE EXCEPTION 'unknown action' USING ERRCODE = '22023'; END IF;
  RETURN QUERY SELECT q.account_id, q.cooling_until FROM idn_recovery_request q WHERE q.id = p_request;
END $$""",
    f"""CREATE FUNCTION plt_recovery_platform_list() RETURNS TABLE (id uuid, tenant_id uuid, tenant_name text, display_name text, email text,
  state text, created_at timestamptz, expires_at timestamptz, approved_at timestamptz, cooling_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER {SP} AS $$
  SELECT q.id, q.subject_tenant_id, t.name::text, a.display_name::text, a.email::text, q.state::text, q.created_at, q.expires_at, q.approved_at, q.cooling_until
    FROM idn_recovery_request q JOIN idn_account a ON a.id = q.account_id JOIN plt_tenant t ON t.id = q.subject_tenant_id
   WHERE q.kind = 'last_owner' ORDER BY q.created_at DESC LIMIT 100
$$""",
    f"""CREATE FUNCTION plt_recovery_platform_decide(p_request uuid, p_operator uuid, p_action text) RETURNS TABLE (account_id uuid, cooling_until timestamptz, email text)
LANGUAGE plpgsql SECURITY DEFINER {SP} AS $$
DECLARE r idn_recovery_request%ROWTYPE;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM plt_operator_role o JOIN plt_operator_account a ON a.id = o.operator_id
                  WHERE o.operator_id = p_operator AND o.role = 'platform_security' AND a.status = 'active') THEN
    RAISE EXCEPTION 'only an active Platform Security operator may decide on a last-Owner recovery' USING ERRCODE = '42501'; END IF;
  SELECT * INTO r FROM idn_recovery_request q WHERE q.id = p_request AND q.kind = 'last_owner' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'recovery request not found' USING ERRCODE = '42501'; END IF;
  IF r.state <> 'requested' OR r.expires_at <= now() THEN RAISE EXCEPTION 'request is not awaiting a decision' USING ERRCODE = '42501'; END IF;
  IF p_action = 'approve' THEN
    UPDATE idn_recovery_request SET state = 'approved', approver_id = p_operator, approver_realm = 'platform', approved_at = now(),
           cooling_until = now() + (cooling_seconds * interval '1 second') WHERE id = p_request;
  ELSIF p_action = 'deny' THEN
    UPDATE idn_recovery_request SET state = 'cancelled', ended_at = now(), ended_reason = 'denied_by_approver' WHERE id = p_request;
  ELSE RAISE EXCEPTION 'unknown action' USING ERRCODE = '22023'; END IF;
  RETURN QUERY SELECT q.account_id, q.cooling_until, a.email::text FROM idn_recovery_request q JOIN idn_account a ON a.id = q.account_id WHERE q.id = p_request;
END $$""",
    # default-deny execute
    *[f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC" for sig in (
        "idn_recovery_create(uuid, uuid, int, timestamptz, text, inet)", "idn_recovery_notify_targets(uuid)", "idn_recovery_cancel(text)",
        "idn_recovery_complete(uuid, uuid)", "idn_recovery_cancel_for_account(uuid, uuid)", "idn_recovery_tenant_list()", "idn_recovery_tenant_decide(uuid, text)",
        "plt_recovery_platform_list()", "plt_recovery_platform_decide(uuid, uuid, text)")],
    "GRANT EXECUTE ON FUNCTION idn_recovery_create(uuid, uuid, int, timestamptz, text, inet), idn_recovery_notify_targets(uuid), "
    "idn_recovery_cancel(text), idn_recovery_cancel_for_account(uuid, uuid), idn_recovery_complete(uuid, uuid) TO ngrc_auth",
    "GRANT EXECUTE ON FUNCTION idn_recovery_tenant_list(), idn_recovery_tenant_decide(uuid, text) TO ngrc_app",
    "GRANT EXECUTE ON FUNCTION plt_recovery_platform_list(), plt_recovery_platform_decide(uuid, uuid, text) TO ngrc_ops",
]


class Migration(migrations.Migration):
    dependencies = [("iam", "0005_recovery_request"), ("tenancy", "0002_security"), ("control_plane", "0002_security")]
    operations = [migrations.RunSQL(FORWARD)]
