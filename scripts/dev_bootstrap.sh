#!/usr/bin/env bash
# DEV ONLY. Bootstraps a local PostgreSQL cluster (Linux/WSL) for NsureGRC development and tests.
#  * Generates random role passwords into ~/.config/nsuregrc/dev.env (mode 600, outside the repo). Never printed.
#  * Runs db/bootstrap/*.sql as the postgres superuser. Requires root (or sudo) for `su postgres`.
# Production roles/credentials are provisioned by infrastructure automation + a secrets manager (open item O-4).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "run as root (e.g. wsl -u root)"; exit 1; fi
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${NGRC_DEV_USER:-flash}"
ENV_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)/.config/nsuregrc"
ENV_FILE="$ENV_DIR/dev.env"

mkdir -p "$ENV_DIR"; chmod 700 "$ENV_DIR"
if [[ ! -f "$ENV_FILE" ]]; then
  gen() { openssl rand -hex 24; }
  umask 077
  cat > "$ENV_FILE" <<EOF
NGRC_ENV=dev
NGRC_DB_HOST=127.0.0.1
NGRC_DB_PORT=5432
NGRC_DB_NAME=ngrc_dev
NGRC_DB_TEST_NAME=ngrc_test
NGRC_DB_OWNER_PASSWORD=$(gen)
NGRC_DB_APP_PASSWORD=$(gen)
NGRC_DB_AUTH_PASSWORD=$(gen)
NGRC_DB_OPS_PASSWORD=$(gen)
NGRC_DB_AUDIT_READER_PASSWORD=$(gen)
NGRC_DB_AUDIT_SEALER_PASSWORD=$(gen)
NGRC_DB_AUDIT_VERIFIER_PASSWORD=$(gen)
NGRC_DB_CATALOG_PASSWORD=$(gen)
NGRC_DB_TESTADMIN_PASSWORD=$(gen)
NGRC_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n')
NGRC_FIELD_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
NGRC_TOKEN_PEPPER=$(openssl rand -base64 32 | tr -d '\n')
EOF
  chown -R "$TARGET_USER":"$TARGET_USER" "$ENV_DIR"
  echo "generated $ENV_FILE (not displayed)"
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

PSQL_SU=(su postgres -c)
run_su() { su postgres -c "$1"; }

if ! run_su "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='ngrc_owner'\"" | grep -q 1; then
  run_su "psql -v ON_ERROR_STOP=1 \
    -v owner_pw='$NGRC_DB_OWNER_PASSWORD' -v app_pw='$NGRC_DB_APP_PASSWORD' -v auth_pw='$NGRC_DB_AUTH_PASSWORD' \
    -v ops_pw='$NGRC_DB_OPS_PASSWORD' -v auditreader_pw='$NGRC_DB_AUDIT_READER_PASSWORD' \
    -v sealer_pw='$NGRC_DB_AUDIT_SEALER_PASSWORD' -v verifier_pw='$NGRC_DB_AUDIT_VERIFIER_PASSWORD' \
    -v catalog_pw='$NGRC_DB_CATALOG_PASSWORD' \
    -f '$REPO_DIR/db/bootstrap/00_roles.sql'"
  run_su "psql -v ON_ERROR_STOP=1 -v testadmin_pw='$NGRC_DB_TESTADMIN_PASSWORD' -f '$REPO_DIR/db/bootstrap/01_dev_test_admin.sql'"
  echo "roles created"
else
  echo "roles already exist (passwords unchanged)"
fi

if ! run_su "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$NGRC_DB_NAME'\"" | grep -q 1; then
  run_su "psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE $NGRC_DB_NAME OWNER ngrc_owner\""
fi
# Setup runs AS ngrc_owner (database owner) over TCP using the owner password
PGPASSWORD="$NGRC_DB_OWNER_PASSWORD" psql -h 127.0.0.1 -U ngrc_owner -d "$NGRC_DB_NAME" -v ON_ERROR_STOP=1 \
  -v dbname="$NGRC_DB_NAME" -f "$REPO_DIR/db/bootstrap/02_database_setup.sql"
echo "database $NGRC_DB_NAME ready"
