-- NsureGRC cluster-level role bootstrap (D-P0-003 s2, D-P0-006 s4, D-P0-009 s3).
-- Run ONCE per cluster by a DBA / infrastructure automation as a superuser. NOT run by the application.
--
--   psql -v ON_ERROR_STOP=1 \
--        -v owner_pw="$NGRC_DB_OWNER_PASSWORD" -v app_pw="$NGRC_DB_APP_PASSWORD" \
--        -v auth_pw="$NGRC_DB_AUTH_PASSWORD"   -v ops_pw="$NGRC_DB_OPS_PASSWORD" \
--        -v auditreader_pw="$NGRC_DB_AUDIT_READER_PASSWORD" \
--        -v sealer_pw="$NGRC_DB_AUDIT_SEALER_PASSWORD" -v verifier_pw="$NGRC_DB_AUDIT_VERIFIER_PASSWORD" \
--        -v catalog_pw="$NGRC_DB_CATALOG_PASSWORD" \
--        -f 00_roles.sql
--
-- No passwords are stored in this file. Every runtime role is NOSUPERUSER NOBYPASSRLS and owns nothing.

-- Migration identity: owns schema objects. Used ONLY by the migration job (never by runtime processes).
CREATE ROLE ngrc_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Owner of audit.* objects. NOLOGIN: nobody can authenticate as it. The migration identity may SET ROLE to it
-- while applying reviewed audit migrations (D-P0-006 s4.3).
CREATE ROLE ngrc_audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- SET only, NO inheritance (PostgreSQL 16+): the migration identity holds none of the audit owner's privileges unless it
-- explicitly runs SET ROLE inside a reviewed audit migration. Otherwise a compromised ngrc_owner could write audit rows.
GRANT ngrc_audit_owner TO ngrc_owner WITH INHERIT FALSE, SET TRUE;

-- Runtime roles
CREATE ROLE ngrc_app  LOGIN PASSWORD :'app_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;  -- tenant data plane (API + workers)
CREATE ROLE ngrc_auth LOGIN PASSWORD :'auth_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;  -- identity / credentials only
CREATE ROLE ngrc_ops  LOGIN PASSWORD :'ops_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;  -- platform control plane

-- Audit duty separation (D-P0-006 s3-6)
CREATE ROLE ngrc_audit_reader_platform LOGIN PASSWORD :'auditreader_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE ngrc_audit_sealer          LOGIN PASSWORD :'sealer_pw'      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE ngrc_audit_verifier        LOGIN PASSWORD :'verifier_pw'    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- D-P2-001: the only role that may write CAT (catalogue) / this PLT framework-engine state. No RLS - CAT/PLT
-- carry no tenant_id (D-P0-009); isolation here is role separation, same reasoning as ngrc_auth/ngrc_app.
CREATE ROLE ngrc_catalog_publisher LOGIN PASSWORD :'catalog_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Defence in depth: RLS can never be switched off for runtime roles; bounded statement time.
ALTER ROLE ngrc_app  SET row_security = on;
ALTER ROLE ngrc_auth SET row_security = on;
ALTER ROLE ngrc_ops  SET row_security = on;
ALTER ROLE ngrc_app  SET statement_timeout = '30s';
ALTER ROLE ngrc_auth SET statement_timeout = '30s';
ALTER ROLE ngrc_ops  SET statement_timeout = '30s';
ALTER ROLE ngrc_catalog_publisher SET statement_timeout = '30s';
