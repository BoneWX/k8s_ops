#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

write_test=false
if [[ "${1:-}" == "--write-test" ]]; then
  write_test=true
  shift
fi

domain="${1:-network}"
log_type="${2:-switch}"
test_file="${3:-switch-test.log}"

info() {
  printf '\n[INFO] %s\n' "$*"
}

ok() {
  printf '[OK] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  printf '[FAIL] %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

require_command docker
require_command curl
require_command grep

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  warn ".env not found; using compose defaults."
fi

host_log_dir="${HOST_LOG_DIR:-./logs}"
loki_port="${LOKI_HTTP_PORT:-3100}"
alloy_port="${ALLOY_HTTP_PORT:-12345}"
host_type_dir="${host_log_dir%/}/${domain}/${log_type}"
host_log_file="${host_type_dir}/${test_file}"
container_type_dir="/var/log/central/${domain}/${log_type}"
container_log_file="${container_type_dir}/${test_file}"
selector="{job=\"central-file-log\", log_domain=\"${domain}\", log_type=\"${log_type}\"}"

info "Checking environment"
printf 'Work dir: %s\n' "$(pwd)"
printf 'HOST_LOG_DIR: %s\n' "$host_log_dir"
printf 'Target host path: %s\n' "$host_log_file"
printf 'Target Loki selector: %s\n' "$selector"

if [[ "$write_test" == true ]]; then
  info "Writing a test log line"
  mkdir -p "$host_type_dir" || fail "Cannot create $host_type_dir. Try running with sudo or fix permissions."
  printf '%s %s-%s-check ERROR link down timeout failed test from check-file-log-ingest\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$domain" "$log_type" >>"$host_log_file" \
    || fail "Cannot write $host_log_file. Try running with sudo or fix permissions."
  chmod -R a+rX "$host_log_dir" || warn "Could not chmod $host_log_dir; continuing."
  ok "Wrote test line to $host_log_file"
fi

info "Checking host log file"
if [[ -f "$host_log_file" ]]; then
  ok "Host log file exists"
  tail -n 5 "$host_log_file" || true
else
  warn "Host log file does not exist: $host_log_file"
  warn "Create it or rerun this script with --write-test."
fi

info "Checking containers"
docker ps --format '{{.Names}}' | grep -qx 'logserver-loki' || fail "Container logserver-loki is not running"
docker ps --format '{{.Names}}' | grep -qx 'logserver-alloy' || fail "Container logserver-alloy is not running"
ok "Loki and Alloy containers are running"

if docker ps --format '{{.Names}}' | grep -qx 'logserver-ai-log-analyzer-worker'; then
  ok "AI worker container is running"
else
  warn "AI worker container is not running. Raw log ingest can still work, but AI results will not appear."
fi

info "Checking Alloy container mount"
docker exec logserver-alloy ls -ld /var/log/central "$container_type_dir" || {
  warn "Alloy cannot see $container_type_dir."
  warn "Check .env HOST_LOG_DIR and restart Alloy: bash scripts/update.sh alloy"
}

if docker exec logserver-alloy test -f "$container_log_file"; then
  ok "Alloy can see $container_log_file"
  docker exec logserver-alloy tail -n 5 "$container_log_file" || true
else
  warn "Alloy cannot see expected file: $container_log_file"
fi

info "Checking Alloy runtime config"
docker exec logserver-alloy grep -nE 'central-file-log|log_domain|log_type|/var/log/central' /etc/alloy/config.alloy || {
  fail "Alloy runtime config does not contain expected central-file-log/log_domain/log_type settings"
}

info "Checking service health"
curl -fsS "http://127.0.0.1:${loki_port}/ready" >/dev/null && ok "Loki is ready" || fail "Loki is not ready"
curl -fsS "http://127.0.0.1:${alloy_port}/-/ready" >/dev/null && ok "Alloy is ready" || warn "Alloy ready endpoint failed"

info "Checking Loki label values"
printf 'job values: '
curl -fsS "http://127.0.0.1:${loki_port}/loki/api/v1/label/job/values" || warn "Could not read Loki job label values"
printf '\nlog_domain values: '
curl -fsS "http://127.0.0.1:${loki_port}/loki/api/v1/label/log_domain/values" || warn "Could not read Loki log_domain label values"
printf '\nlog_type values: '
curl -fsS "http://127.0.0.1:${loki_port}/loki/api/v1/label/log_type/values" || warn "Could not read Loki log_type label values"
printf '\n'

info "Querying Loki for the target selector"
end_ns="$(date +%s%N)"
start_ns="$((end_ns - 3600 * 1000000000))"
query_url="http://127.0.0.1:${loki_port}/loki/api/v1/query_range"
response="$(
  curl -fsS -G "$query_url" \
    --data-urlencode "query=${selector}" \
    --data-urlencode "start=${start_ns}" \
    --data-urlencode "end=${end_ns}" \
    --data-urlencode "limit=20" \
    --data-urlencode "direction=BACKWARD"
)" || fail "Loki query failed"

printf '%s\n' "$response"

if printf '%s\n' "$response" | grep -q '"result":\[\]'; then
  warn "No logs found for ${selector} in the last hour."
  warn "If the file exists in the Alloy container, wait 10-20 seconds and rerun."
  warn "If it still fails, check: docker logs --tail=200 logserver-alloy"
else
  ok "Loki returned logs for ${selector}"
fi

info "Useful next commands"
printf 'docker logs --tail=200 logserver-alloy\n'
printf 'docker logs --tail=200 logserver-ai-log-analyzer-worker\n'
printf 'Grafana Explore query: %s\n' "$selector"

