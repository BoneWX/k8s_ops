#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_BASE_URL = 'https://open.feishu.cn';
const AUDIT_PATH = '/open-apis/admin/v1/audit_infos';
const TOKEN_PATH = '/open-apis/auth/v3/tenant_access_token/internal';

main().catch((error) => {
  console.error(`[FAIL] ${error.message}`);
  if (process.env.DEBUG) {
    console.error(error);
  }
  process.exitCode = 1;
});

async function main() {
  loadEnvFile(path.join(__dirname, '.env'));
  loadEnvFile(path.join(process.cwd(), '.env'));

  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const config = buildConfig(args);
  const token = config.tenantAccessToken || await fetchTenantAccessToken(config);
  const items = await fetchAuditLogs(config, token);

  if (config.output) {
    await writeJsonl(config.output, items, config.raw);
    console.log(`[OK] Wrote ${items.length} audit log item(s) to ${config.output}`);
    return;
  }

  for (const item of items) {
    process.stdout.write(`${JSON.stringify(config.raw ? item.raw : item)}\n`);
  }
  console.error(`[OK] Fetched ${items.length} audit log item(s)`);
}

function buildConfig(args) {
  const baseUrl = trimEndSlash(args.baseUrl || process.env.FEISHU_BASE_URL || DEFAULT_BASE_URL);
  const pageSize = clampInt(args.pageSize || process.env.FEISHU_PAGE_SIZE || 100, 1, 200);
  const latest = toUnixSeconds(args.latest) || Math.floor(Date.now() / 1000);
  const oldest = toUnixSeconds(args.oldest) || latest - clampInt(args.lastMinutes || process.env.FEISHU_LAST_MINUTES || 60, 1, 60 * 24 * 30) * 60;

  if (latest <= oldest) {
    throw new Error('--latest must be greater than --oldest');
  }

  return {
    baseUrl,
    tenantAccessToken: args.token || process.env.FEISHU_TENANT_ACCESS_TOKEN || '',
    appId: args.appId || process.env.FEISHU_APP_ID || '',
    appSecret: args.appSecret || process.env.FEISHU_APP_SECRET || '',
    userIdType: args.userIdType || process.env.FEISHU_USER_ID_TYPE || 'user_id',
    oldest,
    latest,
    pageSize,
    eventName: args.eventName || '',
    eventModule: args.eventModule || '',
    operatorType: args.operatorType || '',
    operatorValue: args.operatorValue || '',
    userType: args.userType || '',
    objectType: args.objectType || '',
    objectValue: args.objectValue || '',
    output: args.output || '',
    raw: Boolean(args.raw),
    maxPages: clampInt(args.maxPages || 20, 1, 1000),
  };
}

async function fetchTenantAccessToken(config) {
  if (!config.appId || !config.appSecret) {
    throw new Error('Missing token. Set FEISHU_TENANT_ACCESS_TOKEN, or set FEISHU_APP_ID and FEISHU_APP_SECRET.');
  }

  const response = await fetchJson(`${config.baseUrl}${TOKEN_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      app_id: config.appId,
      app_secret: config.appSecret,
    }),
  });

  if (response.code !== 0 || !response.tenant_access_token) {
    throw new Error(`Failed to fetch tenant_access_token: code=${response.code}, msg=${response.msg || ''}`);
  }

  return response.tenant_access_token;
}

async function fetchAuditLogs(config, token) {
  const items = [];
  let pageToken = '';

  for (let page = 1; page <= config.maxPages; page += 1) {
    const url = new URL(`${config.baseUrl}${AUDIT_PATH}`);
    setQuery(url, 'user_id_type', config.userIdType);
    setQuery(url, 'oldest', config.oldest);
    setQuery(url, 'latest', config.latest);
    setQuery(url, 'page_size', config.pageSize);
    setQuery(url, 'event_name', config.eventName);
    setQuery(url, 'event_module', config.eventModule);
    setQuery(url, 'operator_type', config.operatorType);
    setQuery(url, 'operator_value', config.operatorValue);
    setQuery(url, 'user_type', config.userType);
    setQuery(url, 'object_type', config.objectType);
    setQuery(url, 'object_value', config.objectValue);
    setQuery(url, 'page_token', pageToken);

    const response = await fetchJson(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.code !== 0) {
      throw new Error(`Feishu audit API failed: code=${response.code}, msg=${response.msg || ''}`);
    }

    const data = response.data || {};
    for (const item of data.items || []) {
      items.push(normalizeAuditItem(item));
    }

    if (!data.has_more || !data.page_token) {
      break;
    }
    pageToken = data.page_token;
  }

  return items;
}

function normalizeAuditItem(item) {
  const context = item.audit_context || {};
  const detail = item.audit_detail || {};
  const terminal = context.web_context || context.pc_context || context.android_context || context.ios_context || {};

  return {
    source: 'feishu-audit',
    unique_id: item.unique_id || '',
    event_id: item.event_id || '',
    event_name: item.event_name || '',
    event_module: item.event_module ?? null,
    event_time: item.event_time ?? null,
    event_time_iso: item.event_time ? new Date(item.event_time * 1000).toISOString() : '',
    operator_type: item.operator_type ?? null,
    operator_value: item.operator_value || '',
    operator_tenant: item.operator_tenant || '',
    ip: item.ip || terminal.IP || terminal.ip || '',
    city: detail.city || '',
    terminal_type: context.terminal_type ?? null,
    device_model: detail.device_model || '',
    os: detail.os || '',
    objects: item.objects || [],
    recipients: item.recipients || [],
    raw: item,
  };
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data;

  try {
    data = text ? JSON.parse(text) : {};
  } catch (error) {
    throw new Error(`Invalid JSON response from ${url}: HTTP ${response.status}, body=${text.slice(0, 300)}`);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${url}: ${JSON.stringify(data).slice(0, 500)}`);
  }

  return data;
}

async function writeJsonl(filePath, items, raw) {
  await fs.promises.mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
  const content = items.map((item) => JSON.stringify(raw ? item.raw : item)).join('\n');
  await fs.promises.writeFile(filePath, content ? `${content}\n` : '', 'utf8');
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg === '--raw') {
      args.raw = true;
      continue;
    }
    if (!arg.startsWith('--')) {
      throw new Error(`Unexpected argument: ${arg}`);
    }

    const key = toCamelCase(arg.slice(2));
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      throw new Error(`Missing value for ${arg}`);
    }
    args[key] = next;
    index += 1;
  }
  return args;
}

function printHelp() {
  console.log(`Usage:
  node app/feishu-audit-log/fetch-audit-logs.cjs [options]

Options:
  --last-minutes <n>       Query recent n minutes. Default: FEISHU_LAST_MINUTES or 60
  --oldest <seconds>       Query start Unix timestamp in seconds
  --latest <seconds>       Query end Unix timestamp in seconds
  --page-size <1-200>      Page size. Default: FEISHU_PAGE_SIZE or 100
  --max-pages <n>          Pagination safety limit. Default: 20
  --user-id-type <type>    open_id | union_id | user_id. Default: user_id
  --event-name <name>      Filter by event name
  --event-module <n>       Filter by event module
  --operator-type <type>   Filter by operator type, for example user
  --operator-value <id>    Filter by operator id
  --user-type <n>          Filter by user type
  --object-type <n>        Filter by object type
  --object-value <id>      Filter by object id
  --output <file>          Write JSON Lines to file
  --raw                    Output raw Feishu item
  --token <token>          tenant_access_token
  --app-id <id>            Feishu app id
  --app-secret <secret>    Feishu app secret
`);
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const equalsIndex = trimmed.indexOf('=');
    if (equalsIndex < 1) {
      continue;
    }
    const key = trimmed.slice(0, equalsIndex).trim();
    const value = stripQuotes(trimmed.slice(equalsIndex + 1).trim());
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

function setQuery(url, key, value) {
  if (value === undefined || value === null || value === '') {
    return;
  }
  url.searchParams.set(key, String(value));
}

function toUnixSeconds(value) {
  if (!value) {
    return 0;
  }
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    throw new Error(`Invalid Unix timestamp: ${value}`);
  }
  return Math.floor(number);
}

function clampInt(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    throw new Error(`Invalid number: ${value}`);
  }
  return Math.max(min, Math.min(max, Math.floor(number)));
}

function trimEndSlash(value) {
  return String(value).replace(/\/+$/, '');
}

function stripQuotes(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
}
