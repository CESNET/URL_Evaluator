#!/bin/sh
# Migrates the url_evaluator SQLite database to the newest schema version.
#
# Workflow:
#   1. Detect pending (not-yet-applied) migrations from install/migrations/*.sql.
#      If none are pending, exit cleanly without touching the DB or backup dir.
#   2. Delete any previous backup in the backup directory.
#   3. Backup the current active DB into the backup directory (kept until next run).
#   4. Apply every pending migration in order, recording each applied file in
#      the schema_migrations table.
#
# The migration SQL files are the only part that changes as new versions are released.

BASEDIR=$(dirname "$0")
. "$BASEDIR/common.sh"

# --- Config path with fallback ---
if [ -z "$CONFIG" ]; then
    if [ -f "/etc/url_evaluator/config.yaml" ]; then
        CONFIG="/etc/url_evaluator/config.yaml"
    else
        CONFIG="./etc/config.yaml"
    fi
fi

MIGRATIONS_DIR="$BASEDIR/migrations"

echob "=============== Migrate DB ==============="

# --- Resolve database path from the config file ---
if [ ! -f "$CONFIG" ]; then
    echor "Config file not found: $CONFIG"
    exit 1
fi
DB_PATH=$(sed -n 's/^db_path:[[:space:]]*//p' "$CONFIG" | tr -d '"'"'"' ' | head -n 1)
if [ -z "$DB_PATH" ]; then
    echor "Could not parse db_path from $CONFIG"
    exit 1
fi

DB_DIR=$(dirname "$DB_PATH")
BACKUP_DIR="$DB_DIR/backup"
BACKUP_FILE="$BACKUP_DIR/db_backup.sqlite"

if [ ! -f "$DB_PATH" ]; then
    echor "Database not found: $DB_PATH (nothing to migrate)"
    exit 1
fi

# --- 1. Detect pending migrations first (no side effects if none) ---
sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));"

pending=""
# Use find + sort to guarantee right order of migrations (001, 002, ...)
for migration in $(find "$MIGRATIONS_DIR" -maxdepth 1 -name "*.sql" | sort); do
    [ -e "$migration" ] || continue
    name=$(basename "$migration")
    already=$(sqlite3 "$DB_PATH" "SELECT 1 FROM schema_migrations WHERE name='$name' LIMIT 1;")
    if [ "$already" != "1" ]; then
        # Append migration path on its own line
        pending="${pending}${migration}
"
    fi
done

# If nothing is pending, exit cleanly (no backup churn, no deletes).
if [ -z "$pending" ]; then
    echob "** No pending migrations - skipping backup and exiting **"
    exit 0
fi

# --- 2. Cleanup old backup (from the previous migration run) ---
echob "** Cleaning up old backup **"
mkdir -p "$BACKUP_DIR"
if [ -f "$BACKUP_FILE" ]; then
    rm -f "$BACKUP_FILE"
    echo "Removed previous backup $BACKUP_FILE"
else
    echo "No previous backup to remove"
fi

# --- 3. Backup the current active DB (transaction-safe) ---
echob "** Backing up current DB **"
if ! sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"; then
    echor "Backup failed, aborting migration (DB left untouched)"
    exit 1
fi
echo "Backup stored at $BACKUP_FILE"

# --- 4. Apply pending migrations in order ---
echob "** Applying migrations **"

applied=0
# Iterate over the collected pending list (already sorted). Use a positional
# parameter trick to avoid running the loop in a subshell on POSIX sh, so the
# `applied` counter persists after the loop.
set -- $pending
for migration do
    [ -n "$migration" ] || continue
    name=$(basename "$migration")
    echo "Applying $name ..."

    if sqlite3 "$DB_PATH" ".bail on" ".read $migration"; then
        sqlite3 "$DB_PATH" "INSERT INTO schema_migrations (name) VALUES ('$name');"
        echo "Applied $name"
        applied=$((applied + 1))
    else
        echor "Migration $name failed; database may need manual attention. Backup is at $BACKUP_FILE"
        exit 1
    fi
done

echob "** Migration finished: $applied applied, backup kept at $BACKUP_FILE **"
exit 0
