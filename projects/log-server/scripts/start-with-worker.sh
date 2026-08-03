#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Please review it."
fi

if [ ! -f config/worker/auto-analyzer.env ]; then
  cp config/worker/auto-analyzer.env.example config/worker/auto-analyzer.env
  echo "Created config/worker/auto-analyzer.env. Please review LiteLLM settings."
fi

docker compose --env-file .env -f docker-compose.yml -f docker-compose.worker.yml up -d
