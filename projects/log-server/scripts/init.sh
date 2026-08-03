#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p logs plugins

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit image names and passwords before production use."
else
  echo ".env already exists, keep it unchanged."
fi

echo "Done. Next: bash scripts/start.sh"
