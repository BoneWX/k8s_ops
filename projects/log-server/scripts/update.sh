#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Please edit it before production use."
fi

if [ ! -f config/worker/auto-analyzer.env ]; then
  cp config/worker/auto-analyzer.env.example config/worker/auto-analyzer.env
  echo "Created config/worker/auto-analyzer.env. Please edit LiteLLM settings."
fi

backup_runtime_config() {
  local stamp backup_dir copied
  stamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="config/backups/update-${stamp}"
  copied=0

  for file in .env config/worker/auto-analyzer.env config/worker/auto-analysis-rules.json; do
    if [ -f "$file" ]; then
      mkdir -p "$backup_dir/$(dirname "$file")"
      cp -p "$file" "$backup_dir/$file"
      copied=1
    fi
  done

  if [ "$copied" -eq 1 ]; then
    echo "Backed up runtime config to ${backup_dir}"
  fi
}

backup_runtime_config

set -a
source .env
set +a

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.worker.yml)

if [ "$#" -gt 0 ]; then
  echo "Updating selected service(s): $*"
  "${compose[@]}" up -d --force-recreate "$@"
else
  echo "Updating all log-server services..."
  "${compose[@]}" up -d --force-recreate
fi

echo
"${compose[@]}" ps

check_url() {
  local name="$1"
  local url="$2"

  echo
  echo "Checking ${name}: ${url}"
  if curl -fsS "${url}" >/tmp/log-server-update-check.out 2>/tmp/log-server-update-check.err; then
    cat /tmp/log-server-update-check.out
    echo
  else
    echo "WARN: ${name} check failed"
    cat /tmp/log-server-update-check.err || true
    echo
  fi
}

check_url "Loki" "http://127.0.0.1:${LOKI_HTTP_PORT:-3100}/ready"
check_url "Grafana" "http://127.0.0.1:${GRAFANA_HTTP_PORT:-3000}/api/health"
check_url "Alloy" "http://127.0.0.1:${ALLOY_HTTP_PORT:-12345}/-/ready"
check_url "AI worker" "http://127.0.0.1:${WORKER_HTTP_PORT:-18080}/health"

rm -f /tmp/log-server-update-check.out /tmp/log-server-update-check.err

echo
echo "Update finished."
