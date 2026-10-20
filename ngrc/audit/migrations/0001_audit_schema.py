"""Audit subsystem (D-P0-006): schema `audit`, owned by NOLOGIN role ngrc_audit_owner.

* No role holds INSERT/UPDATE/DELETE/TRUNCATE on the event tables - events enter ONLY through the SECURITY DEFINER
  `audit.append_*` functions, which validate the action registry, writer role, tenant binding and detail allow-list,
  then chain the SHA-256 hash under a row lock on the stream head.
* BEFORE UPDATE/DELETE/TRUNCATE triggers reject mutation even for the owner (defence in depth against grant mistakes).
* Hash construction is documented in the function `audit._event_hash` and replicated independently in Python
  (`ngrc.audit.chain`) by the verifier - verification does not trust DB-side code.
This migration is applied by ngrc_owner using `SET LOCAL ROLE ngrc_audit_owner` (reviewed migration path only).
"""
from django.db import migrations

APPEND_SIG = (
    "p_actor_type text, p_actor uuid, p_grant uuid, p_action text, p_otype text, p_oid text, p_result text, "
    "p_reason text, p_ip inet, p_ua text, p_sref text, p_rid text, p_details jsonb, p_class text"
)
APPEND_TYPES = "text, uuid, uuid, text, text, text, text, text, inet, text, text, text, jsonb, text"

HASH_ARGS = (
    "{stream}, v_seq, v_prev, v_id, v_ts, {tenant}, p_actor_type, p_actor, p_grant, p_action, p_otype, p_oid, "
    "p_result, p_reason, p_ip, p_ua, p_sref, p_rid, p_details, p_class, 1"
)

EVENT_COLUMNS = """
  event_id uuid PRIMARY KEY,
  {tenant_col},
  seq bigint NOT NULL,
  occurred_at timestamptz NOT NULL,
  actor_type text NOT NULL CHECK (actor_type IN ('user','operator','service','system','anonymous')),
  actor_id uuid,
  on_behalf_of_grant uuid,
  action text NOT NULL REFERENCES audit.action_registry (action),
  object_type text,
  object_id text,
  result text NOT NULL CHECK (result IN ('success','denied','failure')),
  reason_code text,
  source_ip inet,
  user_agent text,
  session_ref text,
  request_id text,
  details jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  data_class text NOT NULL DEFAULT 'C' CHECK (data_class IN ('P','I','C','R')),
  schema_version int NOT NULL DEFAULT 1,
  prev_hash bytea NOT NULL,
  hash bytea NOT NULL
"""

FORWARD = [
    "CREATE SCHEMA audit AUTHORIZATION ngrc_audit_owner",
    # ngrc_owner has SET but NOT INHERIT on ngrc_audit_owner: everything the audit owner owns is touched only after SET ROLE
    "SET LOCAL ROLE ngrc_audit_owner",
    "REVOKE ALL ON SCHEMA audit FROM PUBLIC",
    "GRANT USAGE ON SCHEMA audit TO ngrc_app, ngrc_auth, ngrc_ops, ngrc_audit_reader_platform, ngrc_audit_sealer, ngrc_audit_verifier",

    # ------------------------------------------------------------------ tables
    """CREATE TABLE audit.action_registry (
  action text PRIMARY KEY, category text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('info','notice','warning','critical')),
  stream text NOT NULL CHECK (stream IN ('tenant','platform','both')),
  allowed_detail_keys text[] NOT NULL DEFAULT '{}', writers text[] NOT NULL)""",
    "CREATE TABLE audit.chain_head (stream_key text PRIMARY KEY, seq bigint NOT NULL, last_hash bytea NOT NULL)",
    "CREATE TABLE audit.tenant_event (" + EVENT_COLUMNS.format(tenant_col="tenant_id uuid NOT NULL") + ", UNIQUE (tenant_id, seq))",
    "CREATE TABLE audit.platform_event (" + EVENT_COLUMNS.format(tenant_col="related_tenant_id uuid") + ", UNIQUE (seq))",
    "CREATE INDEX tenant_event_time ON audit.tenant_event (tenant_id, occurred_at)",
    "CREATE INDEX platform_event_time ON audit.platform_event (occurred_at)",
    """CREATE TABLE audit.checkpoint (
  stream_key text NOT NULL, seq bigint NOT NULL, head_hash bytea NOT NULL, issued_at timestamptz NOT NULL,
  key_id text NOT NULL, algorithm text NOT NULL, signature bytea NOT NULL, PRIMARY KEY (stream_key, seq))""",
    """CREATE TABLE audit.verification_run (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), stream_key text NOT NULL, started_at timestamptz NOT NULL,
  finished_at timestamptz NOT NULL, status text NOT NULL CHECK (status IN ('ok','violation','error')),
  verified_through_seq bigint, details jsonb NOT NULL DEFAULT '{}'::jsonb)""",

    # ------------------------------------------------------------------ immutability (defence in depth)
    """CREATE FUNCTION audit.deny_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit data is append-only (% on %)', TG_OP, TG_TABLE_NAME USING ERRCODE = '42501'; END $$""",
    """CREATE FUNCTION audit.head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR NEW.stream_key <> OLD.stream_key OR NEW.seq <> OLD.seq + 1 THEN
    RAISE EXCEPTION 'chain head may only advance by exactly one' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$""",
    *[
        stmt
        for t in ("tenant_event", "platform_event", "checkpoint", "verification_run", "action_registry")
        for stmt in (
            f"CREATE TRIGGER no_update_delete BEFORE UPDATE OR DELETE ON audit.{t} FOR EACH ROW EXECUTE FUNCTION audit.deny_mutation()",
            f"CREATE TRIGGER no_truncate BEFORE TRUNCATE ON audit.{t} FOR EACH STATEMENT EXECUTE FUNCTION audit.deny_mutation()",
        )
    ],
    "CREATE TRIGGER head_guard BEFORE UPDATE ON audit.chain_head FOR EACH ROW EXECUTE FUNCTION audit.head_guard()",
    "CREATE TRIGGER no_delete BEFORE DELETE ON audit.chain_head FOR EACH ROW EXECUTE FUNCTION audit.deny_mutation()",
    "CREATE TRIGGER no_truncate BEFORE TRUNCATE ON audit.chain_head FOR EACH STATEMENT EXECUTE FUNCTION audit.deny_mutation()",

    # ------------------------------------------------------------------ row level security + grants
    "ALTER TABLE audit.tenant_event ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE audit.tenant_event FORCE ROW LEVEL SECURITY",
    "ALTER TABLE audit.platform_event ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE audit.platform_event FORCE ROW LEVEL SECURITY",
    "CREATE POLICY owner_insert ON audit.tenant_event FOR INSERT TO ngrc_audit_owner WITH CHECK (true)",
    "CREATE POLICY owner_insert ON audit.platform_event FOR INSERT TO ngrc_audit_owner WITH CHECK (true)",
    "CREATE POLICY tenant_read ON audit.tenant_event FOR SELECT TO ngrc_app USING (tenant_id = ngrc_current_tenant())",
    "CREATE POLICY verifier_read ON audit.tenant_event FOR SELECT TO ngrc_audit_verifier USING (true)",
    "CREATE POLICY verifier_read ON audit.platform_event FOR SELECT TO ngrc_audit_verifier USING (true)",
    "CREATE POLICY platform_reader_read ON audit.platform_event FOR SELECT TO ngrc_audit_reader_platform USING (true)",
    "GRANT SELECT ON audit.tenant_event TO ngrc_app, ngrc_audit_verifier",
    "GRANT SELECT ON audit.platform_event TO ngrc_audit_reader_platform, ngrc_audit_verifier",
    "GRANT SELECT ON audit.chain_head TO ngrc_audit_sealer, ngrc_audit_verifier",
    "GRANT SELECT, INSERT ON audit.checkpoint TO ngrc_audit_sealer",
    "ALTER TABLE audit.checkpoint ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE audit.checkpoint FORCE ROW LEVEL SECURITY",
    "CREATE POLICY sealer_all ON audit.checkpoint FOR ALL TO ngrc_audit_sealer USING (true) WITH CHECK (true)",
    "CREATE POLICY verifier_read ON audit.checkpoint FOR SELECT TO ngrc_audit_verifier USING (true)",
    "CREATE POLICY tenant_read ON audit.checkpoint FOR SELECT TO ngrc_app USING (stream_key = ngrc_current_tenant()::text)",
    "GRANT SELECT ON audit.checkpoint TO ngrc_audit_verifier, ngrc_app",
    "GRANT SELECT, INSERT ON audit.verification_run TO ngrc_audit_verifier",
    "GRANT SELECT ON audit.action_registry TO ngrc_audit_verifier",

    # ------------------------------------------------------------------ canonical hash construction
    """CREATE FUNCTION audit._lp(b bytea) RETURNS bytea LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN b IS NULL THEN decode('ffffffff', 'hex') ELSE int4send(octet_length(b)) || b END $$""",
    """CREATE FUNCTION audit._t(t text) RETURNS bytea LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT audit._lp(convert_to(t, 'UTF8')) $$""",
    """CREATE FUNCTION audit._event_hash(p_stream text, p_seq bigint, p_prev bytea, p_event_id uuid, p_ts timestamptz,
  p_tenant uuid, p_actor_type text, p_actor uuid, p_grant uuid, p_action text, p_otype text, p_oid text, p_result text,
  p_reason text, p_ip inet, p_ua text, p_sref text, p_rid text, p_details jsonb, p_class text, p_ver int)
RETURNS bytea LANGUAGE sql STABLE AS $$
SELECT sha256(
     audit._t('NGRC-AUDIT-v1') || audit._t(p_stream) || audit._t(p_seq::text) || audit._lp(p_prev)
  || audit._t(p_event_id::text)
  || audit._t(to_char(p_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  || audit._t(p_tenant::text) || audit._t(p_actor_type) || audit._t(p_actor::text) || audit._t(p_grant::text)
  || audit._t(p_action) || audit._t(p_otype) || audit._t(p_oid) || audit._t(p_result) || audit._t(p_reason)
  || audit._t(host(p_ip)) || audit._t(p_ua) || audit._t(p_sref) || audit._t(p_rid) || audit._t(p_details::text)
  || audit._t(p_class) || audit._t(p_ver::text)) $$""",
    """CREATE FUNCTION audit._validate(p_action text, p_stream text, p_details jsonb, p_caller text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE reg audit.action_registry%ROWTYPE; bad text;
BEGIN
  SELECT * INTO reg FROM audit.action_registry WHERE action = p_action;
  IF NOT FOUND THEN RAISE EXCEPTION 'unregistered audit action' USING ERRCODE = '22023'; END IF;
  IF reg.stream <> 'both' AND reg.stream <> p_stream THEN
    RAISE EXCEPTION 'action not valid for this stream' USING ERRCODE = '22023'; END IF;
  IF NOT (p_caller = ANY (reg.writers)) THEN
    RAISE EXCEPTION 'role not permitted to emit this action' USING ERRCODE = '42501'; END IF;
  IF p_details IS NULL OR jsonb_typeof(p_details) <> 'object' THEN
    RAISE EXCEPTION 'details must be a JSON object' USING ERRCODE = '22023'; END IF;
  IF pg_column_size(p_details) > 4096 THEN RAISE EXCEPTION 'details too large' USING ERRCODE = '22023'; END IF;
  SELECT k INTO bad FROM jsonb_object_keys(p_details) AS k WHERE NOT (k = ANY (reg.allowed_detail_keys)) LIMIT 1;
  IF FOUND THEN RAISE EXCEPTION 'detail key not allowed for this action' USING ERRCODE = '22023'; END IF;
END $$""",

    # ------------------------------------------------------------------ append: tenant stream
    f"""CREATE FUNCTION audit.append_tenant_event(p_tenant uuid, {APPEND_SIG}) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_caller text := session_user;
  v_key text := p_tenant::text;
  v_head audit.chain_head%ROWTYPE;
  v_seq bigint; v_prev bytea; v_hash bytea;
  v_id uuid := gen_random_uuid();
  v_ts timestamptz := clock_timestamp();
  v_old text;
BEGIN
  p_details := coalesce(p_details, '{{}}'::jsonb);
  IF p_tenant IS NULL THEN RAISE EXCEPTION 'tenant required' USING ERRCODE = '22023'; END IF;
  PERFORM audit._validate(p_action, 'tenant', p_details, v_caller);
  IF v_caller = 'ngrc_app' THEN
    IF p_tenant IS DISTINCT FROM ngrc_current_tenant() THEN
      RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501'; END IF;
  ELSIF v_caller = 'ngrc_auth' THEN
    v_old := coalesce(current_setting('app.tenant_id', true), '');
    PERFORM set_config('app.tenant_id', p_tenant::text, true);
    IF p_actor IS NULL OR NOT EXISTS (SELECT 1 FROM ten_membership WHERE principal_id = p_actor) THEN
      RAISE EXCEPTION 'actor has no membership in tenant' USING ERRCODE = '42501'; END IF;
    PERFORM set_config('app.tenant_id', v_old, true);
  ELSIF v_caller = 'ngrc_ops' THEN
    IF p_grant IS NULL OR NOT EXISTS (
         SELECT 1 FROM plt_support_access_grant g WHERE g.id = p_grant AND g.subject_tenant_id = p_tenant
           AND (p_action <> 'support.action' OR (g.state = 'active' AND g.expires_at > now()))) THEN
      RAISE EXCEPTION 'no valid support grant for this tenant' USING ERRCODE = '42501'; END IF;
  ELSE
    RAISE EXCEPTION 'role not permitted to write the tenant audit stream' USING ERRCODE = '42501';
  END IF;
  INSERT INTO audit.chain_head (stream_key, seq, last_hash)
    VALUES (v_key, 0, sha256(convert_to('NGRC-AUDIT-v1-genesis|' || v_key, 'UTF8'))) ON CONFLICT (stream_key) DO NOTHING;
  SELECT * INTO v_head FROM audit.chain_head WHERE stream_key = v_key FOR UPDATE;
  v_seq := v_head.seq + 1; v_prev := v_head.last_hash;
  v_hash := audit._event_hash({HASH_ARGS.format(stream="v_key", tenant="p_tenant")});
  INSERT INTO audit.tenant_event (event_id, tenant_id, seq, occurred_at, actor_type, actor_id, on_behalf_of_grant, action,
      object_type, object_id, result, reason_code, source_ip, user_agent, session_ref, request_id, details, data_class,
      schema_version, prev_hash, hash)
    VALUES (v_id, p_tenant, v_seq, v_ts, p_actor_type, p_actor, p_grant, p_action, p_otype, p_oid, p_result, p_reason,
      p_ip, p_ua, p_sref, p_rid, coalesce(p_details, '{{}}'::jsonb), p_class, 1, v_prev, v_hash);
  UPDATE audit.chain_head SET seq = v_seq, last_hash = v_hash WHERE stream_key = v_key;
  RETURN v_seq;
END $$""",

    # ------------------------------------------------------------------ append: platform stream
    f"""CREATE FUNCTION audit.append_platform_event(p_related_tenant uuid, {APPEND_SIG}) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_caller text := session_user;
  v_key text := 'platform';
  v_head audit.chain_head%ROWTYPE;
  v_seq bigint; v_prev bytea; v_hash bytea;
  v_id uuid := gen_random_uuid();
  v_ts timestamptz := clock_timestamp();
BEGIN
  p_details := coalesce(p_details, '{{}}'::jsonb);
  PERFORM audit._validate(p_action, 'platform', p_details, v_caller);
  IF v_caller = 'ngrc_app' AND p_related_tenant IS NOT NULL AND p_related_tenant IS DISTINCT FROM ngrc_current_tenant() THEN
    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501'; END IF;
  INSERT INTO audit.chain_head (stream_key, seq, last_hash)
    VALUES (v_key, 0, sha256(convert_to('NGRC-AUDIT-v1-genesis|' || v_key, 'UTF8'))) ON CONFLICT (stream_key) DO NOTHING;
  SELECT * INTO v_head FROM audit.chain_head WHERE stream_key = v_key FOR UPDATE;
  v_seq := v_head.seq + 1; v_prev := v_head.last_hash;
  v_hash := audit._event_hash({HASH_ARGS.format(stream="v_key", tenant="p_related_tenant")});
  INSERT INTO audit.platform_event (event_id, related_tenant_id, seq, occurred_at, actor_type, actor_id, on_behalf_of_grant,
      action, object_type, object_id, result, reason_code, source_ip, user_agent, session_ref, request_id, details,
      data_class, schema_version, prev_hash, hash)
    VALUES (v_id, p_related_tenant, v_seq, v_ts, p_actor_type, p_actor, p_grant, p_action, p_otype, p_oid, p_result,
      p_reason, p_ip, p_ua, p_sref, p_rid, coalesce(p_details, '{{}}'::jsonb), p_class, 1, v_prev, v_hash);
  UPDATE audit.chain_head SET seq = v_seq, last_hash = v_hash WHERE stream_key = v_key;
  RETURN v_seq;
END $$""",

    # ------------------------------------------------------------------ execute grants (default-deny)
    f"REVOKE ALL ON FUNCTION audit.append_tenant_event(uuid, {APPEND_TYPES}) FROM PUBLIC",
    f"REVOKE ALL ON FUNCTION audit.append_platform_event(uuid, {APPEND_TYPES}) FROM PUBLIC",
    f"GRANT EXECUTE ON FUNCTION audit.append_tenant_event(uuid, {APPEND_TYPES}) TO ngrc_app, ngrc_auth, ngrc_ops",
    f"GRANT EXECUTE ON FUNCTION audit.append_platform_event(uuid, {APPEND_TYPES}) TO ngrc_app, ngrc_auth, ngrc_ops, "
    "ngrc_audit_verifier, ngrc_audit_reader_platform",
    "RESET ROLE",
    # the audit owner must be able to evaluate the context helpers and read the two tables it validates against
    "GRANT EXECUTE ON FUNCTION ngrc_current_tenant(), ngrc_current_principal() TO ngrc_audit_owner",
]

REVERSE = [
    "DROP SCHEMA audit CASCADE",
]


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0001_helper_functions"),
        ("control_plane", "0002_security"),
        ("tenancy", "0002_security"),
    ]
    operations = [migrations.RunSQL(FORWARD, reverse_sql=REVERSE)]
