"""D-P0-009 testing requirements: manifest <=> catalogue equality, class-shape checks, privilege matrix, no TEN references
from non-TEN classes, tenant-scoped uniqueness. These run against the REAL migrated schema (pg_catalog), so they fail the
build whenever a migration adds an unclassified table or drifts from the privilege matrix."""
from pathlib import Path

import psycopg
import pytest
import yaml

from .conftest import role_connect

pytestmark = pytest.mark.security

MANIFEST = Path(__file__).resolve().parent.parent / "db" / "table_classification.yaml"
CLASSES = {"CAT", "PLT", "IDN", "TEN", "AUD", "SYS"}
DATA_CLASSES = {"P", "I", "C", "R"}
RUNTIME_ROLES = ["ngrc_app", "ngrc_auth", "ngrc_ops", "ngrc_audit_reader_platform", "ngrc_audit_sealer", "ngrc_audit_verifier",
                  "ngrc_catalog_publisher"]
CAT_PLT_FRAMEWORK_TABLES = ["cat_framework", "cat_framework_version", "cat_requirement", "cat_mapping",
                            "plt_framework_change_set", "plt_framework_source_registry"]
PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
CRUD = {"SELECT", "INSERT", "UPDATE", "DELETE"}
IDN_TABLES = ["idn_account", "idn_session", "idn_totp_factor", "idn_webauthn_credential", "idn_recovery_code",
              "idn_auth_token", "idn_throttle", "idn_invitation"]
OPERATOR_TABLES = ["plt_operator_account", "plt_operator_role", "plt_operator_session", "plt_operator_webauthn_credential",
                   "plt_operator_throttle"]

# The privilege matrix (D-P0-009 s3), TABLE-level privileges. Anything not listed MUST be empty. idn_account's column-level grant
# for ngrc_app and plt_support_access_grant's column-level UPDATE for ngrc_ops are asserted separately below.
EXPECTED = {
    "ngrc_app": {"ten_role": CRUD, "ten_membership": CRUD, "plt_tenant": {"SELECT"}, "audit.tenant_event": {"SELECT"},
                 "audit.checkpoint": {"SELECT"},
                 "ten_evidence": {"SELECT", "INSERT", "UPDATE"}, "ten_evidence_revision": {"SELECT", "INSERT", "UPDATE"},  # never DELETE
                 **{t: {"SELECT"} for t in CAT_PLT_FRAMEWORK_TABLES},  # D-P2-001: read-only, never writes the catalogue
                 "ten_framework_activation": {"SELECT", "INSERT", "UPDATE"},
                 "ten_mapping_override": {"SELECT", "INSERT", "UPDATE"},
                 "ten_framework_changeset_decision": {"SELECT", "INSERT"},
                 "ten_framework_custom": {"SELECT", "INSERT", "UPDATE"},
                 "ten_framework_custom_version": {"SELECT", "INSERT", "UPDATE"},
                 "ten_framework_custom_requirement": {"SELECT", "INSERT", "UPDATE"},
                 "ten_common_control": {"SELECT", "INSERT", "UPDATE"},
                 "ten_implementation_control": {"SELECT", "INSERT", "UPDATE"},
                 "ten_control_assertion": {"SELECT", "INSERT", "UPDATE"},
                 "ten_evidence_requirement": {"SELECT", "INSERT", "UPDATE"},
                 "ten_evidence_link": {"SELECT", "INSERT", "UPDATE"},
                 "ten_test": {"SELECT", "INSERT", "UPDATE"},
                 "ten_test_result": {"SELECT", "INSERT", "UPDATE"},
                 "ten_control_plan": {"SELECT", "INSERT", "UPDATE"},
                 "ten_task": {"SELECT", "INSERT", "UPDATE"},
                 "ten_finding": {"SELECT", "INSERT", "UPDATE"},
                 "ten_security_exception": {"SELECT", "INSERT"},
                 "ten_risk_assessment": {"SELECT", "INSERT", "UPDATE"},
                 "ten_risk_scenario": {"SELECT", "INSERT", "UPDATE"},
                 "ten_risk_acceptance": {"SELECT", "INSERT"},
                 "ten_incident": {"SELECT", "INSERT", "UPDATE"},
                 "ten_policy": {"SELECT", "INSERT", "UPDATE"},
                 "ten_objective": {"SELECT", "INSERT", "UPDATE"},
                 "ten_issue": {"SELECT", "INSERT", "UPDATE"},
                 "ten_compliance_audit": {"SELECT", "INSERT", "UPDATE"},
                 "ten_audit_item": {"SELECT", "INSERT", "UPDATE"}},
    "ngrc_auth": {**{t: CRUD for t in IDN_TABLES}, "plt_tenant": {"SELECT"}, "ten_membership": {"SELECT"},
                  "ten_role": {"SELECT"}, "idn_recovery_request": {"SELECT"}},  # recovery: read-only, every write via SECURITY DEFINER fns
    "ngrc_ops": {**{t: CRUD for t in OPERATOR_TABLES}, "plt_tenant": {"SELECT", "INSERT", "UPDATE"},
                 "plt_support_access_grant": {"SELECT", "INSERT"}},
    "ngrc_audit_reader_platform": {"audit.platform_event": {"SELECT"}},
    "ngrc_audit_sealer": {"audit.chain_head": {"SELECT"}, "audit.checkpoint": {"SELECT", "INSERT"}},
    "ngrc_audit_verifier": {"audit.tenant_event": {"SELECT"}, "audit.platform_event": {"SELECT"}, "audit.chain_head": {"SELECT"},
                            "audit.checkpoint": {"SELECT"}, "audit.verification_run": {"SELECT", "INSERT"},
                            "audit.action_registry": {"SELECT"}},
    # D-P2-001: the only writer of CAT/this PLT content. Never DELETE: published/locked rows are frozen by a
    # trigger; drafts are discarded via a status flip, not deletion.
    "ngrc_catalog_publisher": {t: {"SELECT", "INSERT", "UPDATE"} for t in CAT_PLT_FRAMEWORK_TABLES},
}


@pytest.fixture(scope="module")
def manifest():
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    return {t["table"]: t for t in doc["tables"]}


@pytest.fixture(scope="module")
def catalogue():
    """Everything we need from pg_catalog, read once as the schema owner."""
    out = {}
    with role_connect("ngrc_owner") as c:
        tables = c.execute(
            "SELECT n.nspname, c.relname, c.oid, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname IN ('public','audit')"
        ).fetchall()
        for schema, name, oid, rls, force in tables:
            full = name if schema == "public" else f"{schema}.{name}"
            cols = c.execute("SELECT attname, attnotnull FROM pg_attribute WHERE attrelid = %s AND attnum > 0 AND NOT attisdropped",
                             [oid]).fetchall()
            policies = [r[0] for r in c.execute("SELECT polname FROM pg_policy WHERE polrelid = %s", [oid]).fetchall()]
            triggers = [r[0] for r in c.execute("SELECT tgname FROM pg_trigger WHERE tgrelid = %s AND NOT tgisinternal", [oid]).fetchall()]
            out[full] = {"oid": oid, "rls": rls, "force": force, "cols": dict(cols), "policies": policies, "triggers": triggers}
        fks = c.execute(
            "SELECT con.conrelid::regclass::text, con.confrelid::regclass::text, con.conkeyattrs "
            "FROM (SELECT conrelid, confrelid, conname, conkey AS conkeyattrs FROM pg_constraint WHERE contype = 'f') con").fetchall()
        out["__fks"] = [(a.replace("public.", ""), b.replace("public.", "")) for a, b, _ in fks]
        out["__fk_cols"] = c.execute(
            "SELECT con.conrelid::regclass::text, att.attname, con.confrelid::regclass::text FROM pg_constraint con "
            "JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey) WHERE con.contype = 'f'"
        ).fetchall()
        out["__unique"] = c.execute(
            "SELECT con.conrelid::regclass::text, con.conname, array_agg(att.attname) FROM pg_constraint con "
            "JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey) "
            "WHERE con.contype = 'u' GROUP BY 1, 2").fetchall()
        out["__views"] = c.execute(
            "SELECT n.nspname || '.' || c.relname, coalesce(c.reloptions::text, '') FROM pg_class c JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE c.relkind IN ('v','m') AND n.nspname IN ('public','audit')").fetchall()
        out["__public_acl"] = c.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, "
            "LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a "
            "WHERE n.nspname IN ('public','audit') AND c.relkind IN ('r','p','v','m') AND a.grantee = 0").fetchall()
    return out


def _tables(catalogue):
    return {k for k in catalogue if not k.startswith("__")}


# --------------------------------------------------------------------------------------------- manifest <=> catalogue
def test_manifest_entries_are_well_formed(manifest):
    for name, e in manifest.items():
        assert e["class"] in CLASSES, name
        assert e["data_class"] in DATA_CLASSES, name
        assert e["rls"] in {"required", "none"}, name
        assert e.get("domain") and e.get("owner_module"), name


def test_manifest_equals_catalogue(manifest, catalogue):
    actual = _tables(catalogue)
    assert set(manifest) - actual == set(), "manifest lists tables that do not exist"
    assert actual - set(manifest) == set(), "UNCLASSIFIED tables exist (add them to db/table_classification.yaml)"


def test_rls_flag_matches_manifest(manifest, catalogue):
    for name, e in manifest.items():
        cat = catalogue[name]
        assert cat["rls"] == (e["rls"] == "required"), f"{name}: RLS state differs from manifest"


# --------------------------------------------------------------------------------------------- class shape
def test_ten_tables_shape(manifest, catalogue):
    ten = [t for t, e in manifest.items() if e["class"] == "TEN"]
    assert ten, "at least the tenancy tables must be TEN"
    for t in ten:
        cat = catalogue[t]
        assert cat["cols"].get("tenant_id") is True, f"{t}: tenant_id must exist and be NOT NULL"
        assert cat["rls"] and cat["force"], f"{t}: RLS must be ENABLED and FORCED"
        assert cat["policies"], f"{t}: no RLS policy"
        assert f"{t}_tenant_immutable" in cat["triggers"], f"{t}: tenant_id immutability trigger missing"
        assert any(a == t and b == "plt_tenant" and col == "tenant_id" for (a, col, b) in catalogue["__fk_cols"]), \
            f"{t}: no FK tenant_id -> plt_tenant"


def test_ten_unique_constraints_are_tenant_scoped(manifest, catalogue):
    ten = {t for t, e in manifest.items() if e["class"] == "TEN"}
    for table, name, cols in catalogue["__unique"]:
        if table in ten:
            assert "tenant_id" in cols, f"{table}.{name} is unique across tenants (cols={cols})"


def test_non_tenant_classes_have_no_plain_tenant_id(manifest, catalogue):
    for t, e in manifest.items():
        if e["class"] in {"CAT", "PLT", "IDN", "SYS"}:
            assert "tenant_id" not in catalogue[t]["cols"], f"{t}: {e['class']} tables must not carry a plain tenant_id"
        declared = e.get("tenant_column")
        tenantish = {c for c in catalogue[t]["cols"] if "tenant" in c}
        if e["class"] != "TEN" and t != "audit.tenant_event":
            assert tenantish <= ({declared} if declared else set()), f"{t}: undeclared tenant-referencing column(s) {tenantish}"
        if declared:
            assert declared in catalogue[t]["cols"], f"{t}: declared tenant column {declared} does not exist"


def test_no_foreign_key_from_non_ten_classes_into_ten(manifest, catalogue):
    for src, dst in catalogue["__fks"]:
        if dst in manifest and manifest[dst]["class"] == "TEN":
            assert manifest[src]["class"] == "TEN", f"{src} ({manifest[src]['class']}) references TEN table {dst}"


def test_audit_tables_have_mutation_guards(manifest, catalogue):
    for t, e in manifest.items():
        if e["class"] != "AUD":
            continue
        trig = set(catalogue[t]["triggers"])
        assert trig & {"no_update_delete", "head_guard"}, f"{t}: no mutation-guard trigger"
        assert "no_truncate" in trig, f"{t}: no TRUNCATE guard"


def test_views_over_tenant_data_would_need_security_invoker(catalogue):
    for name, opts in catalogue["__views"]:
        assert "security_invoker=true" in opts.replace(" ", ""), f"view {name} must be security_invoker (D-P0-009 s5d)"


def test_public_has_no_table_privileges(catalogue):
    assert catalogue["__public_acl"] == []


# --------------------------------------------------------------------------------------------- privilege matrix
def _granted(conn, role: str, oid: int) -> set[str]:
    """By OID: resolving `audit.x` by name would itself require USAGE on the schema."""
    return {p for p in PRIVS if conn.execute("SELECT has_table_privilege(%s, %s::oid, %s)", [role, oid, p]).fetchone()[0]}


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_privilege_matrix_is_exact(role, manifest, catalogue):
    with role_connect("ngrc_owner") as c:
        for table in manifest:
            want = EXPECTED[role].get(table, set())
            got = _granted(c, role, catalogue[table]["oid"])
            assert got == want, f"{role} on {table}: granted {sorted(got)}, matrix says {sorted(want)}"


def test_migration_identity_has_no_privileges_on_audit(manifest, catalogue):
    with role_connect("ngrc_owner") as c:
        for table in (t for t, e in manifest.items() if e["class"] == "AUD"):
            assert _granted(c, "ngrc_owner", catalogue[table]["oid"]) == set(), table


def test_idn_account_column_level_grants():
    """ngrc_app sees only the four profile columns of idn_account - never password_hash or any credential material."""
    with role_connect("ngrc_owner") as c:
        cols = [r[0] for r in c.execute("SELECT attname FROM pg_attribute WHERE attrelid = 'idn_account'::regclass "
                                        "AND attnum > 0 AND NOT attisdropped").fetchall()]
        readable = {col for col in cols if c.execute("SELECT has_column_privilege('ngrc_app','idn_account',%s,'SELECT')",
                                                      [col]).fetchone()[0]}
        writable = {col for col in cols if any(c.execute("SELECT has_column_privilege('ngrc_app','idn_account',%s,%s)",
                                                         [col, p]).fetchone()[0] for p in ("INSERT", "UPDATE"))}
    assert readable == {"id", "email", "display_name", "status"}
    assert writable == set()
    assert "password_hash" in cols


def test_ops_can_only_update_operator_side_grant_columns():
    allowed = {"state", "approver_id", "approved_at", "second_approver_id", "activated_at", "expires_at", "ended_at", "ended_by_type"}
    with role_connect("ngrc_owner") as c:
        cols = [r[0] for r in c.execute("SELECT attname FROM pg_attribute WHERE attrelid = 'plt_support_access_grant'::regclass "
                                        "AND attnum > 0 AND NOT attisdropped").fetchall()]
        upd = {col for col in cols if c.execute("SELECT has_column_privilege('ngrc_ops','plt_support_access_grant',%s,'UPDATE')",
                                                 [col]).fetchone()[0]}
    assert upd == allowed
    assert {"consent_user_id", "consented_at", "restricted_class_consent", "ticket_ref", "profile"}.isdisjoint(upd)


# --------------------------------------------------------------------------------------------- tenant plane vs credentials
@pytest.mark.parametrize("table", IDN_TABLES + OPERATOR_TABLES + ["plt_support_access_grant"])
def test_tenant_plane_cannot_touch_credential_or_platform_tables(table, tenant_a):
    # support grants are only reachable through the reviewed SECURITY DEFINER functions, never by table access
    with role_connect("ngrc_app") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT * FROM {table} LIMIT 1")


def test_tenant_plane_cannot_read_password_hash(tenant_a):
    with role_connect("ngrc_app") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT password_hash FROM idn_account")
    with role_connect("ngrc_app") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT * FROM idn_account")


def test_operator_plane_has_no_access_to_tenant_data(tenant_a):
    for table in ("ten_role", "ten_membership"):
        with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT 1 FROM {table} LIMIT 1")


def test_ops_cannot_read_customer_identity(tenant_a):
    for table in IDN_TABLES:
        with role_connect("ngrc_ops") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT 1 FROM {table} LIMIT 1")


# --------------------------------------------------------------------------------------------- identity projection visibility
def test_profile_visibility_only_for_members_or_self(tenant_a, tenant_b, make_member):
    import uuid

    from .conftest import make_account

    member, outsider = make_account(), make_account()
    make_member(tenant_a, member)
    make_member(tenant_b, outsider)
    with role_connect("ngrc_app") as c:
        c.execute("SELECT set_config('app.tenant_id', %s, true)", [str(tenant_a.id)])
        visible = {r[0] for r in c.execute("SELECT id FROM idn_account").fetchall()}
        assert member.id in visible and outsider.id not in visible
    with role_connect("ngrc_app") as c:  # no tenant: only the caller's own identity (principal context)
        c.execute("SELECT set_config('app.principal_id', %s, true)", [str(outsider.id)])
        assert {r[0] for r in c.execute("SELECT id FROM idn_account").fetchall()} == {outsider.id}
    with role_connect("ngrc_app") as c:
        assert c.execute("SELECT count(*) FROM idn_account").fetchone()[0] == 0
        _ = uuid


def test_membership_self_listing_through_auth_role(tenant_a, tenant_b, make_member):
    from ngrc.iam import services

    from .conftest import make_account

    acct = make_account()
    make_member(tenant_a, acct, "admin")
    make_member(tenant_b, acct, "member")
    listing = services.list_memberships(acct.id)
    assert {m["tenant_id"] for m in listing} == {tenant_a.id, tenant_b.id}
    assert {m["role"] for m in listing} == {"admin", "member"}
    stranger = make_account()
    assert services.list_memberships(stranger.id) == []
