"""TEN-class security for tenant roles & memberships: FORCE RLS, composite same-tenant FKs, system-role and
last-owner guards, restricted ngrc_auth read paths (D-P0-003, D-P0-009)."""
from django.db import migrations

from ngrc.core import sqlgen

FORWARD = [
    *sqlgen.tenant_table_forward("ten_role"),
    *sqlgen.tenant_table_forward("ten_membership"),
    # --- referential integrity that cannot cross tenants (D-P0-003 s5)
    "ALTER TABLE ten_membership ADD CONSTRAINT ten_membership_role_fk "
    "FOREIGN KEY (tenant_id, role_id) REFERENCES ten_role (tenant_id, id)",
    "ALTER TABLE ten_membership ADD CONSTRAINT ten_membership_principal_fk "
    "FOREIGN KEY (principal_id) REFERENCES idn_account (id)",
    # --- tenant roles can never carry platform permissions; permissions must be a JSON array
    "ALTER TABLE ten_role ADD CONSTRAINT ten_role_perms_array CHECK (jsonb_typeof(permissions) = 'array')",
    r"ALTER TABLE ten_role ADD CONSTRAINT ten_role_no_platform_perms CHECK (permissions::text !~ 'platform\.')",
    # --- system roles (owner/admin/member) are immutable to the tenant plane
    """CREATE FUNCTION ten_role_system_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.is_system AND current_user <> 'ngrc_owner' THEN
    RAISE EXCEPTION 'system roles cannot be modified or deleted' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  IF NEW.is_system IS DISTINCT FROM OLD.is_system AND current_user <> 'ngrc_owner' THEN
    RAISE EXCEPTION 'is_system cannot be changed' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_role_system_guard BEFORE UPDATE OR DELETE ON ten_role FOR EACH ROW EXECUTE FUNCTION ten_role_system_guard()",
    """CREATE FUNCTION ten_role_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.is_system AND current_user <> 'ngrc_owner' THEN
    RAISE EXCEPTION 'system roles are created only at tenant provisioning' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $$""",
    "CREATE TRIGGER ten_role_insert_guard BEFORE INSERT ON ten_role FOR EACH ROW EXECUTE FUNCTION ten_role_insert_guard()",
    # --- last active Owner can never be removed/demoted/suspended
    """CREATE FUNCTION ten_membership_last_owner_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_was_owner boolean; v_others int;
BEGIN
  SELECT EXISTS (SELECT 1 FROM ten_role r WHERE r.id = OLD.role_id AND r.tenant_id = OLD.tenant_id
                 AND r.is_system AND r.key = 'owner') INTO v_was_owner;
  IF NOT v_was_owner OR OLD.status <> 'active' THEN RETURN COALESCE(NEW, OLD); END IF;
  IF TG_OP = 'UPDATE' AND NEW.status = 'active' AND NEW.role_id = OLD.role_id THEN RETURN NEW; END IF;
  SELECT count(*) INTO v_others FROM ten_membership m JOIN ten_role r ON r.id = m.role_id AND r.tenant_id = m.tenant_id
   WHERE m.tenant_id = OLD.tenant_id AND m.id <> OLD.id AND m.status = 'active' AND r.is_system AND r.key = 'owner';
  IF v_others = 0 THEN RAISE EXCEPTION 'cannot remove the last active tenant Owner' USING ERRCODE = '23514'; END IF;
  RETURN COALESCE(NEW, OLD);
END $$""",
    "CREATE TRIGGER ten_membership_last_owner_guard BEFORE UPDATE OR DELETE ON ten_membership "
    "FOR EACH ROW EXECUTE FUNCTION ten_membership_last_owner_guard()",
    # --- narrow read paths for other roles (policy-limited, no tenant context needed)
    "CREATE POLICY auth_own_memberships ON ten_membership FOR SELECT TO ngrc_auth USING (principal_id = ngrc_current_principal())",
    "GRANT SELECT ON ten_membership TO ngrc_auth",
    "CREATE POLICY auth_own_roles ON ten_role FOR SELECT TO ngrc_auth USING (EXISTS ("
    "SELECT 1 FROM ten_membership m WHERE m.role_id = ten_role.id AND m.tenant_id = ten_role.tenant_id "
    "AND m.principal_id = ngrc_current_principal()))",
    "GRANT SELECT ON ten_role TO ngrc_auth",
    # audit append function (owned by ngrc_audit_owner) verifies membership for auth-service tenant events
    "CREATE POLICY audit_owner_membership ON ten_membership FOR SELECT TO ngrc_audit_owner USING (tenant_id = ngrc_current_tenant())",
    "GRANT SELECT ON ten_membership TO ngrc_audit_owner",
]

REVERSE = [
    "DROP TRIGGER IF EXISTS ten_membership_last_owner_guard ON ten_membership",
    "DROP FUNCTION IF EXISTS ten_membership_last_owner_guard()",
    "DROP TRIGGER IF EXISTS ten_role_insert_guard ON ten_role",
    "DROP FUNCTION IF EXISTS ten_role_insert_guard()",
    "DROP TRIGGER IF EXISTS ten_role_system_guard ON ten_role",
    "DROP FUNCTION IF EXISTS ten_role_system_guard()",
]


class Migration(migrations.Migration):
    dependencies = [("core", "0001_helper_functions"), ("tenancy", "0001_initial"), ("iam", "0001_initial"),
                    ("control_plane", "0001_initial")]
    operations = [migrations.RunSQL(FORWARD, reverse_sql=REVERSE)]
