-- DEV/TEST ONLY. Never run against staging or production.
-- Lets the automated test session drop/recreate the throw-away database `ngrc_test` without a superuser.
--   psql -v ON_ERROR_STOP=1 -v testadmin_pw="$NGRC_DB_TESTADMIN_PASSWORD" -f 01_dev_test_admin.sql
CREATE ROLE ngrc_test_admin LOGIN PASSWORD :'testadmin_pw' CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT ngrc_owner TO ngrc_test_admin;   -- required to create a database OWNED BY ngrc_owner
