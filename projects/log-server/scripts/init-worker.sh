#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p config/worker ai-log-analyzer-app/worker plugins/wx-loganalyzer-app

if [ ! -f config/worker/auto-analyzer.env ]; then
  cp config/worker/auto-analyzer.env.example config/worker/auto-analyzer.env
  echo "Created config/worker/auto-analyzer.env. Edit LiteLLM settings before starting worker."
else
  echo "config/worker/auto-analyzer.env already exists, keep it unchanged."
fi

echo "Done. Next: bash scripts/start-with-worker.sh"
