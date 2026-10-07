#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
python -c 'from app.deployment import Deployment; assert Deployment.from_env().hosted'
python -m alembic upgrade head
exec python -m uvicorn app.main:create_app --factory --host 0.0.0.0 --port "${PORT:-10000}" --workers 1 --no-access-log
