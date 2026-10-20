"""SQL generators for reviewed migrations: RLS templates, grants, helper functions (D-P0-003 s4, D-P0-009).

Every statement here runs as `ngrc_owner` inside `manage.py migrate --database=owner`. Nothing in this module is
executed at runtime by application roles.
"""
from __future__ import annotations

import re

_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

CORE_FUNCTIONS_SQL = [
    # Tenant / principal context readers. Malformed value => cast error => statement fails (fail closed).
    """CREATE FUNCTION ngrc_current_tenant() RETURNS uuid
       LANGUAGE sql STABLE PARALLEL SAFE
       AS $$ SELECT NULLIF(pg_catalog.current_setting('app.tenant_id', true), '')::uuid $$""",
    """CREATE FUNCTION ngrc_current_principal() RETURNS uuid
       LANGUAGE sql STABLE PARALLEL SAFE
       AS $$ SELECT NULLIF(pg_catalog.current_setting('app.principal_id', true), '')::uuid $$""",
    """CREATE FUNCTION ngrc_tenant_id_immutable() RETURNS trigger
       LANGUAGE plpgsql
       AS $$ BEGIN
         IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
           RAISE EXCEPTION 'tenant_id is immutable' USING ERRCODE = '42501';
         END IF;
         RETURN NEW;
       END $$""",
    "GRANT EXECUTE ON FUNCTION ngrc_current_tenant(), ngrc_current_principal() TO ngrc_app, ngrc_auth, ngrc_ops, "
    "ngrc_audit_owner, ngrc_audit_reader_platform, ngrc_audit_verifier",
]
CORE_FUNCTIONS_REVERSE = [
    "DROP FUNCTION IF EXISTS ngrc_tenant_id_immutable()",
    "DROP FUNCTION IF EXISTS ngrc_current_principal()",
    "DROP FUNCTION IF EXISTS ngrc_current_tenant()",
]


def _check(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def tenant_table_forward(table: str, privileges: str = "SELECT, INSERT, UPDATE, DELETE") -> list[str]:
    """TEN class template: ENABLE + FORCE RLS, fail-closed policy, immutable tenant_id, default-deny grants."""
    t = _check(table)
    return [
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY tenant_isolation ON {t} TO ngrc_app "
        f"USING (tenant_id = ngrc_current_tenant()) WITH CHECK (tenant_id = ngrc_current_tenant())",
        # The owner (migration identity / SECURITY DEFINER functions) is FORCE-subject too: it honours the same context.
        f"CREATE POLICY owner_context ON {t} TO ngrc_owner "
        f"USING (tenant_id = ngrc_current_tenant()) WITH CHECK (tenant_id = ngrc_current_tenant())",
        f"ALTER TABLE {t} ALTER COLUMN tenant_id SET DEFAULT ngrc_current_tenant()",
        f"CREATE TRIGGER {t}_tenant_immutable BEFORE UPDATE ON {t} FOR EACH ROW EXECUTE FUNCTION ngrc_tenant_id_immutable()",
        f"REVOKE ALL ON {t} FROM PUBLIC",
        f"GRANT {privileges} ON {t} TO ngrc_app",
    ]


def tenant_table_reverse(table: str) -> list[str]:
    t = _check(table)
    return [
        f"DROP TRIGGER IF EXISTS {t}_tenant_immutable ON {t}",
        f"DROP POLICY IF EXISTS tenant_isolation ON {t}",
        f"DROP POLICY IF EXISTS owner_context ON {t}",
        f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY",
        f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY",
    ]


def grant(table: str, role: str, privileges: str, columns: str | None = None) -> str:
    t, r = _check(table), _check(role)
    if columns:
        privs = ", ".join(f"{p.strip()} ({columns})" for p in privileges.split(","))
        return f"GRANT {privs} ON {t} TO {r}"
    return f"GRANT {privileges} ON {t} TO {r}"


def revoke_public(table: str) -> str:
    return f"REVOKE ALL ON {_check(table)} FROM PUBLIC"
