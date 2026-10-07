#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
printf '%s\n' 'WebScope Test Application — FOR LOCAL SECURITY TESTING ONLY' 'Listening on loopback port 9998.'
exec .venv/bin/uvicorn fixtures.demo:app --host 127.0.0.1 --port 9998 --no-access-log
