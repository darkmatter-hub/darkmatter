#!/usr/bin/env bash
# Refresh supabase/schema_full.sql from the live database.
#
# Run this after any schema change. Thirteen tables once existed only inside
# the Supabase instance with no CREATE TABLE statement in this repo; when the
# free-tier project auto-paused it entered a 90-day deletion window and those
# definitions would have been unrecoverable. This script exists so that can
# never happen again.
#
# Usage:
#   bash scripts/dump-schema.sh
#
# Requires DATABASE_URL in .env (gitignored) pointing at the SESSION POOLER:
#   postgresql://postgres.<ref>:<password>@aws-1-<region>.pooler.supabase.com:5432/postgres
#
# Notes:
#   - Use the session pooler, not the transaction pooler (6543): pg_dump needs
#     session-level features and will fail partway through on 6543.
#   - The direct host (db.<ref>.supabase.co) is IPv6-only on the free tier and
#     is unreachable from most home networks.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f .env ]; then
  echo "ERROR: .env not found. It must define DATABASE_URL." >&2
  exit 1
fi

DATABASE_URL=$(grep -m1 '^DATABASE_URL=' .env | cut -d= -f2-)
if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL is not set in .env" >&2
  exit 1
fi

# Locate pg_dump: PATH first, then the standard Windows install location.
PG_DUMP=""
if command -v pg_dump >/dev/null 2>&1; then
  PG_DUMP="pg_dump"
else
  for v in 18 17 16 15; do
    candidate="/c/Program Files/PostgreSQL/$v/bin/pg_dump.exe"
    [ -x "$candidate" ] && { PG_DUMP="$candidate"; break; }
  done
fi

if [ -z "$PG_DUMP" ]; then
  echo "ERROR: pg_dump not found. Install it with:" >&2
  echo "  winget install PostgreSQL.PostgreSQL.17" >&2
  exit 1
fi

export PGCONNECT_TIMEOUT=15
OUT="supabase/schema_full.sql"

echo "Dumping schema to $OUT ..."
# pg_dump 17+ emits \restrict / \unrestrict psql guards with a random token on
# every run. Left in, they produce a spurious two-line diff each time and bury
# real schema changes. This file is a version-controlled reference, so strip
# them and keep diffs meaningful.
"$PG_DUMP" --schema-only --no-owner --no-privileges --schema=public \
  "$DATABASE_URL" | grep -vE '^\\(un)?restrict ' > "$OUT"

# Refuse to leave a dump containing credentials on disk.
if grep -qE 'postgresql://|pooler\.supabase\.com' "$OUT"; then
  echo "ERROR: dump contains a connection string. Not writing it to git." >&2
  rm -f "$OUT"
  exit 1
fi

tables=$(grep -ciE '^CREATE TABLE ' "$OUT" || true)
policies=$(grep -c 'CREATE POLICY' "$OUT" || true)
echo "Done: $tables tables, $policies RLS policies, $(wc -l < "$OUT") lines."
echo "Review with 'git diff $OUT', then commit."
