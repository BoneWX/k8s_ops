#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

failures=0
warnings=0
tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t log-server-check)"
trap 'rm -rf "$tmp_dir"' EXIT

info() {
  printf '\n[INFO] %s\n' "$*"
}

ok() {
  printf '[OK] %s\n' "$*"
}

warn() {
  warnings=$((warnings + 1))
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  failures=$((failures + 1))
  printf '[FAIL] %s\n' "$*" >&2
}

die() {
  printf '[FAIL] %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

require_command curl
require_command docker
require_command grep

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  warn ".env not found; using defaults from compose files."
fi

loki_port="${LOKI_HTTP_PORT:-3100}"
grafana_port="${GRAFANA_HTTP_PORT:-3000}"
alloy_port="${ALLOY_HTTP_PORT:-12345}"
worker_port="${WORKER_HTTP_PORT:-18080}"
plugin_id="wx-loganalyzer-app"
worker_env="config/worker/auto-analyzer.env"
worker_rules="config/worker/auto-analysis-rules.json"
worker_script="ai-log-analyzer-app/worker/auto-analyzer.cjs"

check_url() {
  local name="$1"
  local url="$2"
  local required="${3:-required}"
  local out="${4:-$tmp_dir/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').out}"
  local err="$out.err"

  printf 'Checking %s: %s\n' "$name" "$url"
  if curl -fsS --max-time 35 "$url" >"$out" 2>"$err"; then
    ok "$name reachable"
    return 0
  fi

  if [[ "$required" == "required" ]]; then
    fail "$name check failed"
  else
    warn "$name check failed"
  fi
  sed 's/^/  /' "$err" >&2 || true
  return 1
}

check_container() {
  local name="$1"
  local required="${2:-required}"
  local matched

  matched="$(docker ps --format '{{.Names}}' | grep -Ex "$name" | head -n 1 || true)"
  if [[ -n "$matched" ]]; then
    ok "Container ${matched} is running"
    return 0
  fi

  if [[ "$required" == "required" ]]; then
    fail "Container matching ${name} is not running"
  else
    warn "Container matching ${name} is not running"
  fi
  return 1
}

json_valid() {
  local file="$1"

  if command -v node >/dev/null 2>&1; then
    node - "$file" <<'JS'
      const fs = require("fs");
      JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
JS
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    json.load(fh)
PY
    return
  fi

  return 127
}

json_path() {
  local file="$1"
  local path="$2"

  if command -v node >/dev/null 2>&1; then
    node - "$file" "$path" <<'JS'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const path = process.argv[3];
const value = path.split(".").reduce((current, key) => (current == null ? undefined : current[key]), data);
if (value === undefined || value === null) {
  process.exit(0);
}
if (typeof value === "object") {
  console.log(JSON.stringify(value));
} else {
  console.log(String(value));
}
JS
    return
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" "$path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

value = data
for key in sys.argv[2].split("."):
    if not isinstance(value, dict) or key not in value:
        sys.exit(0)
    value = value[key]

if isinstance(value, (dict, list)):
    print(json.dumps(value, ensure_ascii=False))
elif isinstance(value, bool):
    print(str(value).lower())
elif value is not None:
    print(value)
PY
    return
  fi

  return 127
}

json_rules_count() {
  local file="$1"
  if command -v node >/dev/null 2>&1; then
    node - "$file" <<'JS'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
console.log(Array.isArray(data.rules) ? data.rules.length : 0);
JS
    return
  fi
  python3 - "$file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
print(len(data.get("rules", [])))
PY
}

json_enabled_rules_count() {
  local file="$1"
  if command -v node >/dev/null 2>&1; then
    node - "$file" <<'JS'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
console.log((Array.isArray(data.rules) ? data.rules : []).filter((rule) => rule.enabled !== false).length);
JS
    return
  fi
  python3 - "$file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
print(len([rule for rule in data.get("rules", []) if rule.get("enabled", True) is not False]))
PY
}

json_rules_summary() {
  local file="$1"
  if command -v node >/dev/null 2>&1; then
    node - "$file" <<'JS'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
for (const rule of Array.isArray(data.rules) ? data.rules : []) {
  console.log(`${rule.enabled === false ? "off" : "on"} ${rule.id || ""} ${rule.logDomain || "*"}/${rule.logType || "*"} -> ${rule.analysisScenarioId || "general"}`);
}
JS
    return
  fi
  python3 - "$file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
for rule in data.get("rules", []):
    print("{} {} {}/{} -> {}".format(
        "off" if rule.get("enabled") is False else "on",
        rule.get("id", ""),
        rule.get("logDomain") or "*",
        rule.get("logType") or "*",
        rule.get("analysisScenarioId") or "general",
    ))
PY
}

read_env_value() {
  local file="$1"
  local key="$2"
  local line

  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "$file" | tail -n 1 || true)"
  line="${line#*=}"
  line="${line%\"}"
  line="${line#\"}"
  line="${line%\'}"
  line="${line#\'}"
  printf '%s' "$line"
}

check_json_file() {
  local file="$1"
  local name="$2"

  if [[ ! -f "$file" ]]; then
    fail "${name} missing: ${file}"
    return 1
  fi

  if json_valid "$file" >/dev/null 2>&1; then
    ok "${name} is valid JSON"
    return 0
  fi

  fail "${name} is not valid JSON: ${file}"
  return 1
}

check_worker_health_body() {
  local file="$1"
  local label="$2"

  local ok_value
  ok_value="$(json_path "$file" 'ok' 2>/dev/null || true)"
  if [[ "$ok_value" == "true" ]]; then
    ok "AI worker health is OK (${label})"
  else
    fail "AI worker health returned ok=false (${label})"
  fi

  local message loki_ok litellm_ok litellm_error health_timeout
  message="$(json_path "$file" 'message' 2>/dev/null || true)"
  loki_ok="$(json_path "$file" 'loki.ok' 2>/dev/null || true)"
  litellm_ok="$(json_path "$file" 'litellm.ok' 2>/dev/null || true)"
  litellm_error="$(json_path "$file" 'litellm.error' 2>/dev/null || true)"
  health_timeout="$(json_path "$file" 'worker.litellmHealthTimeoutMs' 2>/dev/null || true)"

  [[ -n "$message" ]] && printf '  message: %s\n' "$message"
  [[ -n "$loki_ok" ]] && printf '  loki.ok: %s\n' "$loki_ok"
  [[ -n "$litellm_ok" ]] && printf '  litellm.ok: %s\n' "$litellm_ok"
  [[ -n "$litellm_error" ]] && printf '  litellm.error: %s\n' "$litellm_error"
  [[ -n "$health_timeout" ]] && printf '  litellmHealthTimeoutMs: %s\n' "$health_timeout"
  return 0
}

detect_server_host() {
  if [[ -n "${LOG_SERVER_HOST:-}" ]]; then
    printf '%s' "$LOG_SERVER_HOST"
    return
  fi
  if [[ -n "${GRAFANA_PUBLIC_HOST:-}" ]]; then
    printf '%s' "$GRAFANA_PUBLIC_HOST"
    return
  fi
  if command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n 1 || true
  fi
}

info "Checking required files"
[[ -f docker-compose.yml ]] && ok "docker-compose.yml exists" || fail "docker-compose.yml missing"
[[ -f docker-compose.worker.yml ]] && ok "docker-compose.worker.yml exists" || warn "docker-compose.worker.yml missing"
[[ -f "$worker_script" ]] && ok "Worker script exists" || fail "Worker script missing: $worker_script"
[[ -f "$worker_env" ]] && ok "Worker env exists" || fail "Worker env missing: $worker_env"

plugin_json="plugins/${plugin_id}/plugin.json"
plugin_module="plugins/${plugin_id}/module.js"
if check_json_file "$plugin_json" "Grafana plugin.json"; then
  local_plugin_id="$(json_path "$plugin_json" 'id' 2>/dev/null || true)"
  local_plugin_version="$(json_path "$plugin_json" 'info.version' 2>/dev/null || true)"
  [[ "$local_plugin_id" == "$plugin_id" ]] && ok "Plugin id is ${plugin_id}" || fail "Unexpected plugin id: ${local_plugin_id:-empty}"
  [[ -n "$local_plugin_version" ]] && ok "Plugin version: ${local_plugin_version}" || warn "Could not read plugin version"
fi
[[ -s "$plugin_module" ]] && ok "Plugin module.js exists" || fail "Plugin module.js missing or empty"

if [[ ",${GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS:-}," == *",${plugin_id},"* ]]; then
  ok "Unsigned plugin allowlist contains ${plugin_id}"
else
  fail "GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS does not contain ${plugin_id}"
fi

info "Checking worker configuration"
if [[ -f "$worker_env" ]]; then
  litellm_base="$(read_env_value "$worker_env" LITELLM_BASE_URL)"
  litellm_key="$(read_env_value "$worker_env" LITELLM_API_KEY)"
  litellm_timeout="$(read_env_value "$worker_env" LITELLM_HEALTH_TIMEOUT_MS)"
  rules_path_value="$(read_env_value "$worker_env" ANALYZER_RULES_PATH)"

  [[ -n "$litellm_base" ]] && ok "LITELLM_BASE_URL configured: ${litellm_base}" || fail "LITELLM_BASE_URL is empty"
  if [[ -z "$litellm_key" || "$litellm_key" == sk-your-* ]]; then
    fail "LITELLM_API_KEY is empty or still uses the example value"
  else
    ok "LITELLM_API_KEY is configured"
  fi
  if [[ -z "$litellm_timeout" ]]; then
    warn "LITELLM_HEALTH_TIMEOUT_MS is not set; old workers may use a short health timeout"
  elif [[ "$litellm_timeout" =~ ^[0-9]+$ && "$litellm_timeout" -ge 30000 ]]; then
    ok "LITELLM_HEALTH_TIMEOUT_MS=${litellm_timeout}"
  else
    warn "LITELLM_HEALTH_TIMEOUT_MS is low or invalid: ${litellm_timeout}"
  fi
  [[ "$rules_path_value" == "/config/auto-analysis-rules.json" ]] && ok "ANALYZER_RULES_PATH points to /config" || warn "ANALYZER_RULES_PATH is ${rules_path_value:-empty}"
fi

if check_json_file "$worker_rules" "Worker auto-analysis rules"; then
  rules_count="$(json_rules_count "$worker_rules" 2>/dev/null || true)"
  enabled_count="$(json_enabled_rules_count "$worker_rules" 2>/dev/null || true)"
  if [[ "${rules_count:-0}" -gt 0 ]]; then
    ok "Auto-analysis rules: ${rules_count} total, ${enabled_count:-unknown} enabled"
    json_rules_summary "$worker_rules" 2>/dev/null || true
  else
    warn "Worker rules file has zero rules; worker will fall back to the env single rule"
  fi
fi

info "Checking containers"
check_container 'logserver-loki|ai-log-analyzer-loki' required || true
check_container 'logserver-grafana|ai-log-analyzer-grafana' required || true
check_container 'logserver-alloy|ai-log-analyzer-alloy' required || true
check_container 'logserver-ai-log-analyzer-worker|ai-log-analyzer-worker|logserver-ai-worker' optional || true

info "Checking script syntax"
if command -v node >/dev/null 2>&1; then
  node --check "$worker_script" >/dev/null && ok "Worker script passes node --check" || fail "Worker script has syntax errors"
else
  worker_container="$(docker ps --format '{{.Names}}' | grep -Ex 'logserver-ai-log-analyzer-worker|ai-log-analyzer-worker|logserver-ai-worker' | head -n 1 || true)"
  if [[ -n "$worker_container" ]]; then
    docker exec "$worker_container" node --check /app/worker/auto-analyzer.cjs >/dev/null \
    && ok "Worker script passes node --check inside container" \
    || fail "Worker script has syntax errors inside container"
  else
    warn "node is not installed and worker container is not running; skipped worker syntax check"
  fi
fi

info "Checking service health"
check_url "Loki" "http://127.0.0.1:${loki_port}/ready" required || true
check_url "Grafana" "http://127.0.0.1:${grafana_port}/api/health" required || true
check_url "Alloy" "http://127.0.0.1:${alloy_port}/-/ready" required || true

worker_local_health="$tmp_dir/worker-local-health.json"
if check_url "AI worker health (127.0.0.1)" "http://127.0.0.1:${worker_port}/health" required "$worker_local_health"; then
  check_worker_health_body "$worker_local_health" "127.0.0.1"
fi

worker_rules_api="$tmp_dir/worker-rules.json"
if check_url "AI worker rules API" "http://127.0.0.1:${worker_port}/rules" optional "$worker_rules_api"; then
  api_rules_count="$(json_rules_count "$worker_rules_api" 2>/dev/null || true)"
  [[ -n "$api_rules_count" ]] && ok "Worker /rules returned ${api_rules_count} rule(s)" || warn "Worker /rules response could not be parsed"
  if [[ -n "${rules_count:-}" && -n "${api_rules_count:-}" && "$rules_count" != "$api_rules_count" ]]; then
    if [[ "$api_rules_count" -gt "$rules_count" ]]; then
      warn "Worker /rules returned ${api_rules_count} rule(s), while ${worker_rules} has ${rules_count}; extra rules may be auto-generated defaults for newly discovered log groups."
    else
      warn "Worker /rules returned ${api_rules_count} rule(s), but ${worker_rules} has ${rules_count}. Restart worker or check ANALYZER_RULES_PATH mount."
    fi
  fi
fi

server_host="$(detect_server_host)"
if [[ -n "$server_host" && "$server_host" != "localhost" && "$server_host" != "127.0.0.1" ]]; then
  info "Checking browser-facing host path (${server_host})"
  grafana_host_health="$tmp_dir/grafana-host-health.json"
  check_url "Grafana (${server_host})" "http://${server_host}:${grafana_port}/api/health" optional "$grafana_host_health" || true

  worker_host_health="$tmp_dir/worker-host-health.json"
  if check_url "AI worker health (${server_host})" "http://${server_host}:${worker_port}/health" optional "$worker_host_health"; then
    check_worker_health_body "$worker_host_health" "$server_host"
    local_ok="$(json_path "$worker_local_health" 'ok' 2>/dev/null || true)"
    host_ok="$(json_path "$worker_host_health" 'ok' 2>/dev/null || true)"
    if [[ "$local_ok" == "true" && "$host_ok" != "true" ]]; then
      fail "127.0.0.1 worker health is OK but ${server_host} worker health is not. Grafana pages opened by IP will show AI unavailable."
    fi
  fi
fi

info "Checking Grafana served plugin"
served_plugin_json="$tmp_dir/served-plugin.json"
if check_url "Grafana served plugin.json" "http://127.0.0.1:${grafana_port}/public/plugins/${plugin_id}/plugin.json" optional "$served_plugin_json"; then
  served_version="$(json_path "$served_plugin_json" 'info.version' 2>/dev/null || true)"
  if [[ -n "${local_plugin_version:-}" && -n "$served_version" && "$served_version" != "$local_plugin_version" ]]; then
    fail "Grafana served plugin version ${served_version} differs from local ${local_plugin_version}"
  elif [[ -n "$served_version" ]]; then
    ok "Grafana served plugin version: ${served_version}"
  else
    warn "Could not read served plugin version"
  fi
fi

info "Checking Loki labels and AI analysis results"
curl -fsS "http://127.0.0.1:${loki_port}/loki/api/v1/label/log_domain/values" >/dev/null \
  && ok "Loki log_domain labels endpoint works" \
  || warn "Could not read Loki log_domain label values"
curl -fsS "http://127.0.0.1:${loki_port}/loki/api/v1/label/log_type/values" >/dev/null \
  && ok "Loki log_type labels endpoint works" \
  || warn "Could not read Loki log_type label values"

if command -v date >/dev/null 2>&1; then
  end_ns="$(date +%s%N)"
  start_ns="$((end_ns - 24 * 3600 * 1000000000))"
  ai_result_response="$tmp_dir/loki-ai-results.json"
  if curl -fsS -G "http://127.0.0.1:${loki_port}/loki/api/v1/query_range" \
    --data-urlencode 'query={job="ai-log-analysis"}' \
    --data-urlencode "start=${start_ns}" \
    --data-urlencode "end=${end_ns}" \
    --data-urlencode "limit=1" \
    --data-urlencode 'direction=BACKWARD' >"$ai_result_response"; then
    if grep -q '"result":\[\]' "$ai_result_response"; then
      warn 'No {job="ai-log-analysis"} results found in the last 24 hours'
    else
      ok 'Found {job="ai-log-analysis"} result(s) in Loki'
    fi
  else
    warn 'Could not query Loki for {job="ai-log-analysis"}'
  fi
fi

info "Summary"
printf 'Warnings: %s\n' "$warnings"
printf 'Failures: %s\n' "$failures"
if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

ok "All required checks passed"
