#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
../.venv/bin/alembic upgrade head
exec ../.venv/bin/uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8765 --no-access-log
