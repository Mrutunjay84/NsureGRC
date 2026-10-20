#!/usr/bin/env bash
# DEV ONLY: drop and recreate the development database `ngrc_dev` (roles are kept) and re-run migrations.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "run as root (wsl -u root)"; exit 1; fi
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${NGRC_DEV_USER:-flash}"
ENV_FILE="$(getent passwd "$TARGET_USER" | cut -d: -f6)/.config/nsuregrc/dev.env"
set -a; source "$ENV_FILE"; set +a
su postgres -c "psql -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS $NGRC_DB_NAME' -c 'CREATE DATABASE $NGRC_DB_NAME OWNER ngrc_owner'"
PGPASSWORD="$NGRC_DB_OWNER_PASSWORD" psql -h 127.0.0.1 -U ngrc_owner -d "$NGRC_DB_NAME" -v ON_ERROR_STOP=1 \
  -v dbname="$NGRC_DB_NAME" -f "$REPO_DIR/db/bootstrap/02_database_setup.sql" >/dev/null
echo "database $NGRC_DB_NAME recreated (run: manage.py migrate --database=owner)"
