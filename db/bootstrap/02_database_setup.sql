-- Per-database setup. Run connected to the target database AS ngrc_owner (the database owner).
-- Idempotent. Establishes default-deny: no PUBLIC access, explicit CONNECT / USAGE only.
-- Table-level privileges are granted by reviewed migrations (ngrc.core.sqlgen), never here.

REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO ngrc_app, ngrc_auth, ngrc_ops, ngrc_owner,
      ngrc_audit_reader_platform, ngrc_audit_sealer, ngrc_audit_verifier;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ngrc_app, ngrc_auth, ngrc_ops, ngrc_audit_owner;

-- Defence in depth: runtime roles can never create objects or change RLS settings.
