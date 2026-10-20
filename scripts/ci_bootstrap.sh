#!/usr/bin/env bash
# CI ONLY. Creates the least-privilege roles on the CI PostgreSQL service and writes a throw-away env file with RANDOM passwords.
# No password is stored in the repository; the file is created with mode 600 in the runner temp dir and never printed.
set -euo pipefail
: "${PGHOST:?}" "${PGPORT:?}" "${PGUSER:?}" "${PGPASSWORD:?}"      # superuser of the ephemeral CI service
ENV_FILE="${NGRC_ENV_FILE:-$RUNNER_TEMP/ngrc-ci.env}"
umask 077
gen() { openssl rand -hex 24; }
{
  echo "NGRC_ENV=test"
  echo "NGRC_DB_HOST=$PGHOST"
  echo "NGRC_DB_PORT=$PGPORT"
  echo "NGRC_DB_NAME=ngrc_dev"
  echo "NGRC_DB_TEST_NAME=ngrc_test"
  for n in OWNER APP AUTH OPS AUDIT_READER AUDIT_SEALER AUDIT_VERIFIER TESTADMIN; do
    echo "NGRC_DB_${n}_PASSWORD=$(gen)"
  done
  echo "NGRC_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')"
  echo "NGRC_FIELD_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')"
  echo "NGRC_TOKEN_PEPPER=$(openssl rand -base64 32 | tr -d '\n')"
} > "$ENV_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
psql -v ON_ERROR_STOP=1 \
  -v owner_pw="$NGRC_DB_OWNER_PASSWORD" -v app_pw="$NGRC_DB_APP_PASSWORD" -v auth_pw="$NGRC_DB_AUTH_PASSWORD" \
  -v ops_pw="$NGRC_DB_OPS_PASSWORD" -v auditreader_pw="$NGRC_DB_AUDIT_READER_PASSWORD" \
  -v sealer_pw="$NGRC_DB_AUDIT_SEALER_PASSWORD" -v verifier_pw="$NGRC_DB_AUDIT_VERIFIER_PASSWORD" \
  -f db/bootstrap/00_roles.sql
psql -v ON_ERROR_STOP=1 -v testadmin_pw="$NGRC_DB_TESTADMIN_PASSWORD" -f db/bootstrap/01_dev_test_admin.sql
echo "NGRC_ENV_FILE=$ENV_FILE" >> "$GITHUB_ENV"
echo "roles created; env file written (not displayed)"
