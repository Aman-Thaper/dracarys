#!/usr/bin/env bash
set -euo pipefail

case "${1:-api}" in
  api)
    # Run migrations when using a persistent (non-sqlite) database.
    if [[ "${DRACARYS_DATABASE_URL:-}" == postgresql* ]]; then
      echo "[entrypoint] running migrations..."
      alembic upgrade head || true
    fi
    exec uvicorn dracarys.api.app:app --host 0.0.0.0 --port 8000
    ;;
  lab)
    exec python -m lab.run --host 0.0.0.0 --port "${DRACARYS_LAB_PORT:-8888}" --patches "${DRACARYS_LAB_PATCHES:-}"
    ;;
  *)
    exec "$@"
    ;;
esac
