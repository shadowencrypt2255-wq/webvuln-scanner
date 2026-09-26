#!/usr/bin/env bash
set -euo pipefail

# The API service runs database migrations before starting. Worker/other
# services skip migrations (RUN_MIGRATIONS=0) to avoid races.
if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
  echo "Running database migrations..."
  alembic upgrade head
  if [ "${SEED_REFERENCE_DATA:-1}" = "1" ]; then
    echo "Seeding reference data (MITRE techniques, default detection rules)..."
    python -c "from app.db_init import seed_reference_data; from app.core.database import SessionLocal; db=SessionLocal(); seed_reference_data(db); db.close()"
  fi
fi

exec "$@"
