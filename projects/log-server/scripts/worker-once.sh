#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
docker compose --env-file .env -f docker-compose.yml -f docker-compose.worker.yml run --rm ai-log-analyzer-worker node worker/auto-analyzer.cjs --once
