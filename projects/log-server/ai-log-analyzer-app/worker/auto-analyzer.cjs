#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const http = require('http');
const path = require('path');

loadEnvFile(path.join(process.cwd(), '.env'));
loadEnvFile(path.join(__dirname, '.env'));

const args = new Set(process.argv.slice(2));

const config = {
  lokiBaseUrl: trimRightSlash(envString('LOKI_BASE_URL', 'http://localhost:3100')),
  lokiTenantId: envString('LOKI_TENANT_ID', ''),
  ruleId: envString('ANALYZER_RULE_ID', 'windows-eventlog-errors'),
  triggerQuery: envString('ANALYZER_QUERY', '{job="windows-eventlog"} | json | level <= 3'),
  contextQuery: envString('ANALYZER_CONTEXT_QUERY', '{job="windows-eventlog"}'),
  includeContextLogs: envBoolean('ANALYZER_INCLUDE_CONTEXT_LOGS', true),
  lookbackMinutes: envNumber('ANALYZER_LOOKBACK_MINUTES', 5, 1, 1440),
  contextLookbackMinutes: envNumber('ANALYZER_CONTEXT_LOOKBACK_MINUTES', 30, 1, 1440),
  intervalSeconds: envNumber('ANALYZER_INTERVAL_SECONDS', 300, 10, 86400),
  ruleConcurrency: envNumber('ANALYZER_RULE_CONCURRENCY', 2, 1, 10),
  ruleTimeoutMs: envNumber('ANALYZER_RULE_TIMEOUT_MS', 240000, 30000, 1800000),
  lokiQueryTimeoutMs: envNumber('LOKI_QUERY_TIMEOUT_MS', 60000, 1000, 600000),
  triggerLimit: envNumber('ANALYZER_LIMIT', 100, 1, 5000),
  contextLimit: envNumber('ANALYZER_CONTEXT_LIMIT', 300, 1, 5000),
  maxTriggerEvents: envNumber('ANALYZER_MAX_TRIGGER_EVENTS', 20, 1, 200),
  maxContextLines: envNumber('ANALYZER_MAX_CONTEXT_LINES', 200, 1, 2000),
  promptTriggerSampleMax: envNumber('ANALYZER_PROMPT_TRIGGER_SAMPLE_MAX', 10, 1, 50),
  promptContextSampleMax: envNumber('ANALYZER_PROMPT_CONTEXT_SAMPLE_MAX', 80, 1, 500),
  contextAroundTriggerMinutes: envNumber('ANALYZER_CONTEXT_AROUND_TRIGGER_MINUTES', 5, 1, 120),
  triggerSelectionMode: envString('ANALYZER_TRIGGER_SELECTION_MODE', 'smart'),
  triggerBatchSize: envNumber('ANALYZER_TRIGGER_BATCH_SIZE', 10, 1, 50),
  maxPromptChars: envNumber('ANALYZER_MAX_PROMPT_CHARS', 24000, 4000, 200000),
  seenRetentionHours: envNumber('ANALYZER_SEEN_RETENTION_HOURS', 168, 1, 24 * 90),
  cursorOverlapSeconds: envNumber('ANALYZER_CURSOR_OVERLAP_SECONDS', 60, 0, 3600),
  cachePath: envString('ANALYZER_CACHE_PATH', path.join(__dirname, '.cache', 'seen-events.json')),
  rulesPath: envString('ANALYZER_RULES_PATH', path.join(__dirname, '.cache', 'auto-analysis-rules.json')),
  analysisScenarioId: envString('ANALYZER_ANALYSIS_SCENARIO_ID', 'general'),
  rulePrompt: envString('ANALYZER_RULE_PROMPT', ''),
  autoDefaultRules: envBoolean('ANALYZER_AUTO_DEFAULT_RULES', true),
  defaultRuleSourceJob: envString('ANALYZER_DEFAULT_RULE_SOURCE_JOB', 'central-file-log'),
  defaultRuleLookbackMinutes: envNumber('ANALYZER_DEFAULT_RULE_LOOKBACK_MINUTES', 1440, 1, 10080),
  pushResultToLoki: envBoolean('ANALYZER_PUSH_RESULT_TO_LOKI', true),
  resultJob: envString('ANALYZER_RESULT_JOB', 'ai-log-analysis'),
  alertPushEnabled: envBoolean('ANALYZER_ALERT_PUSH_ENABLED', false),
  alertWebhookUrl: trimRightSlash(envString('ANALYZER_ALERT_WEBHOOK_URL', '')),
  alertMinSeverity: normalizeAlertMinSeverity(envString('ANALYZER_ALERT_MIN_SEVERITY', 'P2')),
  alertTimeoutMs: envNumber('ANALYZER_ALERT_TIMEOUT_MS', 10000, 1000, 120000),
  alertTriggerLogLimit: envNumber('ANALYZER_ALERT_TRIGGER_LOG_LIMIT', 30, 1, 200),
  alertConfigPath: envString('ANALYZER_ALERT_CONFIG_PATH', path.join(__dirname, '.cache', 'alert-config.json')),
  litellmBaseUrl: trimRightSlash(envString('LITELLM_BASE_URL', '')),
  litellmApiKey: envString('LITELLM_API_KEY', ''),
  litellmModel: envString('LITELLM_MODEL', 'claude-deepseek-v4-pro-agent'),
  litellmHealthTimeoutMs: envNumber('LITELLM_HEALTH_TIMEOUT_MS', 30000, 1000, 120000),
  litellmTimeoutMs: envNumber('LITELLM_TIMEOUT_MS', 120000, 10000, 600000),
  litellmMaxTokens: envNumber('LITELLM_MAX_TOKENS', 2400, 256, 12000),
  runOnce: args.has('--once') || envBoolean('ANALYZER_RUN_ONCE', false),
  serveOnly: args.has('--serve-only') || envBoolean('WORKER_SERVE_ONLY', false),
  apiEnabled: args.has('--serve') || args.has('--serve-only') || envBoolean('WORKER_API_ENABLED', false),
  apiHost: envString('WORKER_API_HOST', '0.0.0.0'),
  apiPort: envNumber('WORKER_API_PORT', 8080, 1, 65535),
  apiCorsOrigin: envString('WORKER_CORS_ORIGIN', '*'),
  apiMaxBodyBytes: envNumber('WORKER_API_MAX_BODY_BYTES', 2 * 1024 * 1024, 16 * 1024, 20 * 1024 * 1024),
};

const ALERT_PAYLOAD_FIELDS = [
  { id: 'source', label: 'source', defaultEnabled: true },
  { id: 'severity', label: 'severity', defaultEnabled: true },
  { id: 'log_category', label: 'log_category', defaultEnabled: true },
  { id: 'log_domain', label: 'log_domain', defaultEnabled: true },
  { id: 'log_type', label: 'log_type', defaultEnabled: true },
  { id: 'title', label: 'title', defaultEnabled: true },
  { id: 'analysis', label: 'analysis', defaultEnabled: true },
  { id: 'trigger_total', label: 'trigger_total', defaultEnabled: true },
  { id: 'trigger_logs', label: 'trigger_logs', defaultEnabled: true },
  { id: 'generated_at', label: 'generated_at', defaultEnabled: true },
  { id: 'rule_id', label: 'rule_id', defaultEnabled: false },
  { id: 'rule_name', label: 'rule_name', defaultEnabled: false },
  { id: 'analysis_scenario_id', label: 'analysis_scenario_id', defaultEnabled: false },
  { id: 'analysis_scenario_name', label: 'analysis_scenario_name', defaultEnabled: false },
  { id: 'insight_mode', label: 'insight_mode', defaultEnabled: false },
  { id: 'source_job', label: 'source_job', defaultEnabled: false },
  { id: 'model', label: 'model', defaultEnabled: false },
  { id: 'trigger_query', label: 'trigger_query', defaultEnabled: false },
  { id: 'context_query', label: 'context_query', defaultEnabled: false },
];

const DEFAULT_ALERT_TARGET_ID = 'default-webhook';
const ALERT_TEST_MAX_TIMEOUT_MS = 30000;
const ALERT_TEST_MAX_RESPONSE_BYTES = 16 * 1024;
const RULE_LATEST_PROBE_TTL_MS = 5 * 60 * 1000;
const latestRuleProbeCache = new Map();
const latestRuleProbeInflight = new Map();
const ruleRunRuntime = new Map();
let seenCacheWriteQueue = Promise.resolve();
const ALERT_TEST_FORBIDDEN_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
const ALERT_TEST_NON_SECRET_HEADERS = new Set(['accept', 'accept-language', 'content-type', 'user-agent']);

async function main() {
  if (args.has('--help') || args.has('-h')) {
    printHelp();
    return;
  }

  const apiServer = config.apiEnabled ? await startApiServer() : undefined;

  if (config.runOnce) {
    try {
      await runOnce();
    } finally {
      await closeServer(apiServer);
    }
    return;
  }

  if (config.serveOnly) {
    return;
  }

  console.log(`[auto-analyzer] 自动分析已启动，每 ${config.intervalSeconds} 秒检查一次。`);
  for (;;) {
    try {
      await runOnce();
    } catch (err) {
      console.error(`[auto-analyzer] 本轮执行失败：${formatError(err)}`);
    }
    await sleep(config.intervalSeconds * 1000);
  }
}

async function runOnce() {
  const rules = await loadAnalyzerRules();
  console.log(
    `[auto-analyzer] ${nowText()} checking ${rules.length} auto-analysis rules with concurrency ${config.ruleConcurrency}.`
  );

  const results = await runRulesWithConcurrency(rules, config.ruleConcurrency, runRuleWithRuntime);
  const analyzedRules = results.filter(Boolean).length;

  if (analyzedRules === 0) {
    console.log('[auto-analyzer] no new AI analysis results in this round.');
  }
}

async function runRulesWithConcurrency(items, concurrency, worker) {
  const limit = Math.max(1, Math.min(Number(concurrency) || 1, items.length || 1));
  const results = new Array(items.length).fill(false);
  let nextIndex = 0;

  async function runWorker() {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) {
        return;
      }
      results[index] = await worker(items[index]);
    }
  }

  await Promise.all(Array.from({ length: limit }, runWorker));
  return results;
}

async function runRuleWithRuntime(rule) {
  const startedAtMs = Date.now();
  if (!rule.enabled) {
    updateRuleRunRuntime(rule.id, {
      latestRunStatus: 'skipped',
      latestRunStartedAtMs: startedAtMs,
      latestRunFinishedAtMs: startedAtMs,
      latestRunDurationMs: 0,
      latestRunError: '',
      latestRunMessage: '规则已停用，本轮跳过。',
    });
    return false;
  }

  updateRuleRunRuntime(rule.id, {
    latestRunStatus: 'running',
    latestRunStartedAtMs: startedAtMs,
    latestRunFinishedAtMs: 0,
    latestRunDurationMs: 0,
    latestRunError: '',
    latestRunMessage: '规则正在执行。',
  });

  const controller = new AbortController();
  let rejectTimeout;
  const timeout = new Promise((_, reject) => {
    rejectTimeout = reject;
  });
  const timer = setTimeout(() => {
    const error = new Error(`rule timed out after ${config.ruleTimeoutMs}ms`);
    error.code = 'RULE_TIMEOUT';
    controller.abort(error);
    rejectTimeout(error);
  }, config.ruleTimeoutMs);
  try {
    const analyzed = await Promise.race([runRule(rule, { signal: controller.signal }), timeout]);
    const finishedAtMs = Date.now();
    updateRuleRunRuntime(rule.id, {
      latestRunStatus: analyzed ? 'success' : 'empty',
      latestRunFinishedAtMs: finishedAtMs,
      latestRunDurationMs: finishedAtMs - startedAtMs,
      latestRunError: '',
      latestRunMessage: analyzed ? '本轮已生成新的 AI 分析结果。' : '本轮已完成，没有需要生成的新结果。',
    });
    return analyzed;
  } catch (err) {
    const finishedAtMs = Date.now();
    const errorText = truncateText(formatError(err), 2000);
    const isTimeout = err?.code === 'RULE_TIMEOUT' || controller.signal.aborted || /timed out|timeout|abort/i.test(errorText);
    updateRuleRunRuntime(rule.id, {
      latestRunStatus: isTimeout ? 'timeout' : 'error',
      latestRunFinishedAtMs: finishedAtMs,
      latestRunDurationMs: finishedAtMs - startedAtMs,
      latestRunError: errorText,
      latestRunMessage: isTimeout ? '规则执行超时，调度器已继续处理其他规则。' : '规则执行失败，调度器已继续处理其他规则。',
    });
    console.error(`[auto-analyzer] rule ${rule.id} failed: ${errorText}`);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function updateRuleRunRuntime(ruleId, patch) {
  if (!ruleId) {
    return;
  }
  ruleRunRuntime.set(ruleId, {
    ...(ruleRunRuntime.get(ruleId) || {}),
    ...patch,
  });
}

async function runRule(rule, options = {}) {
  if (!rule.enabled) {
    console.log(`[auto-analyzer] 规则 ${rule.id} 已禁用，跳过。`);
    return false;
  }

  console.log(`[auto-analyzer] ${nowText()} 检查规则 ${rule.id}`);

  const cache = await loadSeenCache();
  const triggerFetch = await queryTriggerLines(rule, cache, options);
  const triggerLines = triggerFetch.lines;
  if (triggerLines.length === 0) {
    console.log(`[auto-analyzer] 规则 ${rule.id} 没有命中新的触发日志。`);
    return false;
  }

  const freshLines = selectTriggerCandidateLines(
    triggerLines.filter((line) => !cache.seen[fingerprintLine(line, rule)]),
    rule
  );
  if (freshLines.length === 0) {
    console.log(`[auto-analyzer] 规则 ${rule.id} 命中 ${triggerLines.length} 行，但都已经分析过。`);
    return false;
  }

  if (!config.litellmBaseUrl || !config.litellmApiKey) {
    console.log(
      `[auto-analyzer] 规则 ${rule.id} 命中 ${freshLines.length} 行新日志，但未配置 LITELLM_BASE_URL / LITELLM_API_KEY，跳过 AI 调用。`
    );
    return false;
  }

  const contextLines = rule.includeContextLogs
    ? await queryLoki(rule.contextQuery, rule.contextLookbackMinutes, rule.contextLimit, options)
    : [];
  const batches = buildTriggerBatches(freshLines, rule);
  let pushedResults = 0;
  let promptTriggerLines = 0;
  let promptContextLines = 0;
  const shouldPublishResults = config.pushResultToLoki || (await hasAlertPushConfigured());

  for (let index = 0; index < batches.length; index += 1) {
    const triggerForPrompt = batches[index];
    const contextForPrompt = rule.includeContextLogs ? selectContextSamples(contextLines, triggerForPrompt, rule) : [];
    const prompt = buildPrompt(triggerForPrompt, contextForPrompt, rule, {
      batchIndex: index + 1,
      batchTotal: batches.length,
      triggerTotal: freshLines.length,
    });
    const analysis = await callLiteLLM(prompt, { signal: options.signal });
    promptTriggerLines += triggerForPrompt.length;
    promptContextLines += contextForPrompt.length;

    if (shouldPublishResults) {
      await pushAnalysisToLoki({
        analysis,
        rule,
        triggerLines: triggerForPrompt,
        triggerTotal: freshLines.length,
        contextLines: contextForPrompt,
        promptChars: prompt.length,
        batchIndex: index + 1,
        batchTotal: batches.length,
        signal: options.signal,
      });
      if (config.pushResultToLoki) {
        pushedResults += 1;
      }
    }

    await markBatchProcessed(cache, rule, triggerForPrompt);
  }

  console.log(
    `[auto-analyzer] 规则 ${rule.id} 已分析 ${batches.length} 批，触发样本 ${promptTriggerLines}/${freshLines.length} 行，上下文样本 ${promptContextLines}/${contextLines.length} 行，结果${
      config.pushResultToLoki ? '已写回 Loki' : '已生成'
    }${pushedResults ? ` ${pushedResults} 条` : ''}。`
  );
  return true;
}

async function startApiServer() {
  const server = http.createServer((request, response) => {
    handleApiRequest(request, response).catch((err) => {
      writeJson(response, 500, {
        ok: false,
        error: formatError(err),
      });
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.apiPort, config.apiHost, () => {
      server.off('error', reject);
      resolve();
    });
  });

  console.log(`[auto-analyzer] Worker API 已启动：http://${config.apiHost}:${config.apiPort}`);
  return server;
}

async function closeServer(server) {
  if (!server) {
    return;
  }

  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function handleApiRequest(request, response) {
  applyCors(response);

  if (request.method === 'OPTIONS') {
    response.writeHead(204);
    response.end();
    return;
  }

  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'GET' && (url.pathname === '/health' || url.pathname === '/api/health')) {
    writeJson(response, 200, await buildWorkerHealth());
    return;
  }

  if (request.method === 'GET' && (url.pathname === '/rules' || url.pathname === '/api/rules')) {
    const rules = await loadAnalyzerRules();
    const cache = await loadSeenCache();
    writeJson(response, 200, {
      ok: true,
      rules,
      rulesPath: config.rulesPath,
      cachePath: config.cachePath,
      runtime: buildRuleRuntimeState(rules, cache),
    });
    return;
  }

  if (
    request.method === 'GET' &&
    (url.pathname === '/rules/runtime' || url.pathname === '/api/rules/runtime')
  ) {
    const rules = await loadAnalyzerRules();
    const cache = await loadSeenCache();
    const requestedRuleIds = parseRequestedRuleIds(url.searchParams.getAll('ruleIds'));
    const configuredRuleIds = new Set(rules.map((rule) => rule.id));
    const selectedRules = requestedRuleIds
      .filter((ruleId) => configuredRuleIds.has(ruleId))
      .map((ruleId) => rules.find((rule) => rule.id === ruleId))
      .filter(Boolean);
    const probeLatest = url.searchParams.get('probeLatest') === 'true';
    const forceProbe = url.searchParams.get('forceProbe') === 'true';

    if (probeLatest) {
      await Promise.allSettled(
        selectedRules
          .filter((rule) => rule.triggerSelectionMode === 'all_batches')
          .map((rule) => probeLatestMatchedLine(rule, cache, { force: forceProbe }))
      );
    }

    writeJson(response, 200, {
      ok: true,
      rules,
      rulesPath: config.rulesPath,
      cachePath: config.cachePath,
      runtime: buildRuleRuntimeState(rules, cache),
    });
    return;
  }

  if (request.method === 'POST' && (url.pathname === '/rules' || url.pathname === '/api/rules')) {
    const body = await readJsonBody(request);
    const rawRules = Array.isArray(body) ? body : Array.isArray(body.rules) ? body.rules : undefined;
    if (!rawRules) {
      writeJson(response, 400, { ok: false, error: 'rules 必须是数组。' });
      return;
    }

    const rules = rawRules.map(normalizeAnalyzerRule).filter((rule) => rule && rule.autoGenerated !== true);
    await saveAnalyzerRules(rules);
    writeJson(response, 200, {
      ok: true,
      rules,
      rulesPath: config.rulesPath,
      savedAt: new Date().toISOString(),
    });
    return;
  }

  if (request.method === 'GET' && (url.pathname === '/alert-config' || url.pathname === '/api/alert-config')) {
    const alertConfig = await loadAlertConfig();
    writeJson(response, 200, {
      ok: true,
      alertConfig,
      alertConfigPath: config.alertConfigPath,
      availableFields: ALERT_PAYLOAD_FIELDS,
    });
    return;
  }

  if (request.method === 'POST' && (url.pathname === '/alert-config' || url.pathname === '/api/alert-config')) {
    const body = await readJsonBody(request);
    const alertConfig = normalizeAlertConfig(body.alertConfig || body);
    await saveAlertConfig(alertConfig);
    writeJson(response, 200, {
      ok: true,
      alertConfig,
      alertConfigPath: config.alertConfigPath,
      savedAt: new Date().toISOString(),
    });
    return;
  }

  if (
    request.method === 'POST' &&
    (url.pathname === '/alert-config/test' || url.pathname === '/api/alert-config/test')
  ) {
    const body = await readJsonBody(request);
    let target;
    try {
      target = normalizeAlertTestTarget(isObject(body.target) ? body.target : body);
    } catch (err) {
      writeJson(response, 400, {
        ok: false,
        error: formatError(err),
      });
      return;
    }

    writeJson(response, 200, await testAlertTarget(target));
    return;
  }

  if (request.method === 'POST' && (url.pathname === '/analyze' || url.pathname === '/api/analyze')) {
    const body = await readJsonBody(request);
    const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
    const model = typeof body.model === 'string' ? body.model.trim() : '';
    const systemPrompt = typeof body.systemPrompt === 'string' ? body.systemPrompt.trim() : '';

    if (!prompt) {
      writeJson(response, 400, { ok: false, error: 'prompt 不能为空。' });
      return;
    }

    const analysis = await callLiteLLM(prompt, { model, systemPrompt });
    writeJson(response, 200, {
      ok: true,
      analysis,
      model: model || config.litellmModel,
      generatedAt: new Date().toISOString(),
    });
    return;
  }

  writeJson(response, 404, {
    ok: false,
    error: 'Not found',
  });
}

async function buildWorkerHealth() {
  const checkedAt = new Date().toISOString();
  const loki = await probeLoki();
  const litellm = await probeLiteLLM();
  const configured = Boolean(config.litellmBaseUrl && config.litellmApiKey);
  const alertConfig = await loadAlertConfig();
  const cache = await loadSeenCache();
  const rules = await loadAnalyzerRules();
  const ok = Boolean(configured && loki.ok && litellm.ok);

  return {
    ok,
    configured,
    title: ok ? '可用' : configured ? '已配置但不可用' : '未完成配置',
    message: ok
      ? 'worker 已连接 Loki 和 LiteLLM。'
      : configured
        ? 'worker 已配置 LiteLLM，但健康检查未全部通过。'
        : 'worker 未配置 LITELLM_BASE_URL 或 LITELLM_API_KEY。',
    checkedAt,
    worker: {
      apiEnabled: config.apiEnabled,
      intervalSeconds: config.intervalSeconds,
      ruleId: config.ruleId,
      resultJob: config.resultJob,
      alertPushEnabled: config.alertPushEnabled,
      alertWebhookConfigured: Boolean(config.alertWebhookUrl),
      alertMinSeverity: config.alertMinSeverity,
      alertConfigPath: config.alertConfigPath,
      alertConfigEnabled: alertConfig.enabled,
      alertTargets: alertConfig.targets.filter((target) => target.enabled && target.url).length,
      litellmHealthTimeoutMs: config.litellmHealthTimeoutMs,
      cachePath: config.cachePath,
      seenEntries: Object.keys(cache.seen || {}).length,
      checkpointEntries: Object.keys(cache.checkpoints || {}).length,
    },
    runtime: buildRuleRuntimeState(rules, cache),
    loki,
    litellm,
  };
}

async function probeLoki() {
  try {
    const response = await fetchWithTimeout(`${config.lokiBaseUrl}/ready`, {
      headers: lokiHeaders(),
      timeoutMs: 10000,
    });

    return {
      ok: response.ok,
      baseUrl: config.lokiBaseUrl,
      error: response.ok ? undefined : `HTTP ${response.status} ${await response.text()}`,
    };
  } catch (err) {
    return {
      ok: false,
      baseUrl: config.lokiBaseUrl,
      error: formatError(err),
    };
  }
}

async function probeLiteLLM() {
  const configured = Boolean(config.litellmBaseUrl && config.litellmApiKey);
  if (!configured) {
    return {
      ok: false,
      configured,
      baseUrl: config.litellmBaseUrl,
      model: config.litellmModel,
      apiKeyConfigured: Boolean(config.litellmApiKey),
      error: '未配置 LITELLM_BASE_URL 或 LITELLM_API_KEY。',
    };
  }

  try {
    const response = await fetchWithTimeout(`${config.litellmBaseUrl}/models`, {
      headers: {
        Authorization: `Bearer ${config.litellmApiKey}`,
      },
      timeoutMs: config.litellmHealthTimeoutMs,
    });

    return {
      ok: response.ok,
      configured,
      baseUrl: config.litellmBaseUrl,
      model: config.litellmModel,
      apiKeyConfigured: true,
      error: response.ok ? undefined : `HTTP ${response.status} ${await response.text()}`,
    };
  } catch (err) {
    return {
      ok: false,
      configured,
      baseUrl: config.litellmBaseUrl,
      model: config.litellmModel,
      apiKeyConfigured: true,
      error: formatError(err),
    };
  }
}

async function queryLoki(query, minutes, limit, options = {}) {
  const nowMs = Date.now();
  const params = new URLSearchParams({
    query,
    start: toLokiTimestampNs(nowMs - minutes * 60 * 1000),
    end: toLokiTimestampNs(nowMs),
    limit: String(limit),
    direction: 'BACKWARD',
  });
  const url = `${config.lokiBaseUrl}/loki/api/v1/query_range?${params.toString()}`;
  const response = await fetchWithTimeout(url, {
    headers: lokiHeaders(),
    timeoutMs: config.lokiQueryTimeoutMs,
    signal: options.signal,
  });
  if (!response.ok) {
    throw new Error(`Loki 查询失败：HTTP ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  if (body.status && body.status !== 'success') {
    throw new Error(`Loki 查询失败：${body.status}`);
  }

  return parseLokiLines(body).sort(compareLineTime);
}

async function queryLokiRange(query, { startNs, endNs, limit, direction = 'BACKWARD', signal } = {}) {
  const params = new URLSearchParams({
    query,
    start: String(startNs),
    end: String(endNs),
    limit: String(limit),
    direction,
  });
  const url = `${config.lokiBaseUrl}/loki/api/v1/query_range?${params.toString()}`;
  const response = await fetchWithTimeout(url, {
    headers: lokiHeaders(),
    timeoutMs: config.lokiQueryTimeoutMs,
    signal,
  });
  if (!response.ok) {
    throw new Error(`Loki 鏌ヨ澶辫触锛欻TTP ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  if (body.status && body.status !== 'success') {
    throw new Error(`Loki 鏌ヨ澶辫触锛?{body.status}`);
  }

  return parseLokiLines(body).sort(compareLineTime);
}

function parseRequestedRuleIds(values) {
  const ruleIds = [];
  const seen = new Set();
  for (const value of Array.isArray(values) ? values : []) {
    for (const part of String(value || '').split(',')) {
      const ruleId = part.trim();
      if (ruleId && !seen.has(ruleId)) {
        seen.add(ruleId);
        ruleIds.push(ruleId);
      }
    }
  }
  return ruleIds;
}

async function probeLatestMatchedLine(rule, cache, options = {}) {
  if (!rule || rule.triggerSelectionMode !== 'all_batches') {
    return undefined;
  }

  const checkpoint = getRuleCheckpoint(cache, rule.id);
  const checkpointNs = checkpoint?.lastProcessedTimestampNs || '';
  const signature = [rule.triggerQuery, rule.lookbackMinutes].join('\n');
  const nowMs = Date.now();
  const cached = latestRuleProbeCache.get(rule.id);
  if (!options.force && cached && cached.signature === signature && cached.expiresAtMs > nowMs) {
    return cached;
  }

  const inflightKey = `${rule.id}\n${signature}`;
  if (latestRuleProbeInflight.has(inflightKey)) {
    return latestRuleProbeInflight.get(inflightKey);
  }

  const probePromise = (async () => {
    const probedAt = new Date().toISOString();
    const endNs = toLokiTimestampNs(Date.now());
    const startNs = checkpointNs
      ? subtractTimestampNs(checkpointNs, config.cursorOverlapSeconds)
      : toLokiTimestampNs(Date.now() - rule.lookbackMinutes * 60 * 1000);

    try {
      const lines = await queryLokiRange(rule.triggerQuery, {
        startNs,
        endNs,
        limit: 1,
        direction: 'BACKWARD',
      });
      const latestLine = lines[lines.length - 1];
      const latestMatchedTimestampNs = latestLine?.timestampNs || '';
      const result = {
        signature,
        expiresAtMs: Date.now() + RULE_LATEST_PROBE_TTL_MS,
        latestMatchedTimestampNs,
        latestMatchedTimestamp: latestMatchedTimestampNs ? formatTimestamp(latestMatchedTimestampNs) : '',
        latestProbeAt: probedAt,
        latestProbeError: '',
      };
      latestRuleProbeCache.set(rule.id, result);
      return result;
    } catch (err) {
      const result = {
        signature,
        expiresAtMs: Date.now() + RULE_LATEST_PROBE_TTL_MS,
        latestMatchedTimestampNs: '',
        latestMatchedTimestamp: '',
        latestProbeAt: probedAt,
        latestProbeError: formatError(err),
      };
      latestRuleProbeCache.set(rule.id, result);
      return result;
    }
  })();

  latestRuleProbeInflight.set(inflightKey, probePromise);
  try {
    return await probePromise;
  } finally {
    latestRuleProbeInflight.delete(inflightKey);
  }
}

function timestampLagSeconds(processedTimestampNs, latestTimestampNs) {
  try {
    const lagNs = BigInt(latestTimestampNs) - BigInt(processedTimestampNs);
    return Number(lagNs > 0n ? lagNs / 1000000000n : 0n);
  } catch {
    return undefined;
  }
}

async function queryTriggerLines(rule, cache, options = {}) {
  const limit = effectiveTriggerQueryLimit(rule);
  if (rule.triggerSelectionMode !== 'all_batches') {
    const lines = await queryLoki(rule.triggerQuery, rule.lookbackMinutes, limit, options);
    return { lines };
  }

  const checkpoint = getRuleCheckpoint(cache, rule.id);
  const nowNs = toLokiTimestampNs(Date.now());
  const fallbackStartNs = toLokiTimestampNs(Date.now() - rule.lookbackMinutes * 60 * 1000);
  const startNs = checkpoint?.lastProcessedTimestampNs
    ? subtractTimestampNs(checkpoint.lastProcessedTimestampNs, config.cursorOverlapSeconds)
    : fallbackStartNs;
  const lines = [];
  let pageStartNs = startNs;
  const maxPages = 50;

  for (let page = 0; page < maxPages; page += 1) {
    const pageLines = await queryLokiRange(rule.triggerQuery, {
      startNs: pageStartNs,
      endNs: nowNs,
      limit,
      direction: 'FORWARD',
      signal: options.signal,
    });
    if (pageLines.length === 0) {
      break;
    }

    lines.push(...pageLines);
    if (pageLines.length < limit) {
      break;
    }

    const lastLine = pageLines[pageLines.length - 1];
    const nextStartNs = advanceTimestampNs(lastLine.timestampNs);
    if (!nextStartNs || nextStartNs === pageStartNs) {
      break;
    }
    pageStartNs = nextStartNs;
    if (BigInt(pageStartNs) >= BigInt(nowNs)) {
      break;
    }
  }

  return { lines: lines.sort(compareLineTime), checkpoint, startNs, endNs: nowNs };
}

function parseLokiLines(body) {
  const streams = body?.data?.result ?? [];
  const lines = [];

  for (const stream of streams) {
    const labels = stream.stream ?? {};
    for (const value of stream.values ?? []) {
      const [timestampNs, text] = value;
      lines.push({ timestampNs, labels, text });
    }
  }

  return lines;
}

async function loadAnalyzerRules() {
  let rules = [];

  try {
    const text = await fsp.readFile(config.rulesPath, 'utf8');
    const parsed = JSON.parse(text);
    const rawRules = Array.isArray(parsed) ? parsed : Array.isArray(parsed.rules) ? parsed.rules : [];
    rules = rawRules.map(normalizeAnalyzerRule).filter(Boolean);
    if (rules.length === 0) {
      console.warn(`[auto-analyzer] 规则文件 ${config.rulesPath} 为空，回退到环境变量单规则。`);
    }
  } catch (err) {
    if (err?.code !== 'ENOENT') {
      console.warn(`[auto-analyzer] 读取规则文件 ${config.rulesPath} 失败：${formatError(err)}，回退到环境变量单规则。`);
    }
  }

  if (rules.length === 0) {
    rules = [buildFallbackRule()];
  }

  if (!config.autoDefaultRules) {
    return rules;
  }

  try {
    const groups = await discoverLogGroups();
    return appendDefaultRulesForGroups(rules, groups);
  } catch (err) {
    console.warn(`[auto-analyzer] 自动发现日志组失败：${formatError(err)}，继续使用已配置规则。`);
    return rules;
  }
}

async function saveAnalyzerRules(rules) {
  await fsp.mkdir(path.dirname(config.rulesPath), { recursive: true });
  await fsp.writeFile(
    config.rulesPath,
    `${JSON.stringify({ version: 1, updated_at: new Date().toISOString(), rules }, null, 2)}\n`,
    'utf8'
  );
}

async function discoverLogGroups() {
  const nowMs = Date.now();
  const params = new URLSearchParams({
    start: toLokiTimestampNs(nowMs - config.defaultRuleLookbackMinutes * 60 * 1000),
    end: toLokiTimestampNs(nowMs),
  });
  params.append('match[]', buildSelector({
    sourceJob: config.defaultRuleSourceJob,
    logDomain: '',
    logType: '',
  }));

  const response = await fetch(`${config.lokiBaseUrl}/loki/api/v1/series?${params.toString()}`, {
    headers: lokiHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Loki series 查询失败：HTTP ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  if (body.status && body.status !== 'success') {
    throw new Error(`Loki series 查询失败：${body.status}`);
  }

  return uniqueLogGroups(
    (body?.data ?? []).map((labels) => ({
      sourceJob: labels.job || config.defaultRuleSourceJob,
      logDomain: labels.log_domain || '',
      logType: labels.log_type || '',
    }))
  );
}

function appendDefaultRulesForGroups(rules, groups) {
  const nextRules = [...rules];
  for (const group of groups) {
    if (nextRules.some((rule) => ruleCoversLogGroup(rule, group))) {
      continue;
    }
    nextRules.push(buildDefaultRuleForGroup(group));
  }
  return nextRules;
}

function buildDefaultRuleForGroup(group) {
  const domain = group.logDomain || 'unknown';
  const type = group.logType || 'all';
  return normalizeAnalyzerRule({
    id: `default-${domain}-${type}-risk`,
    name: `${domain}/${type} 默认自动分析`,
    enabled: true,
    sourceJob: group.sourceJob || config.defaultRuleSourceJob,
    logDomain: group.logDomain,
    logType: group.logType,
    analysisScenarioId: config.analysisScenarioId,
    scenarioName: '通用故障分析',
    scenarioDescription: '自动发现的日志组尚未配置专属场景，临时按该日志组全量采样分析。',
    scenarioPrompt: '根据日志证据判断影响范围、根因假设、关键证据和可执行处置建议。',
    prompt: '该日志组暂未配置专属规则，请按该目录采样日志进行保守分析；证据不足时明确说明需要继续观察。',
    insightMode: 'incident',
    sensitiveOperationMode: 'ai',
    sensitiveOperationRule: '',
    lookbackMinutes: config.lookbackMinutes,
    contextLookbackMinutes: config.contextLookbackMinutes,
    triggerLimit: config.triggerLimit,
    contextLimit: config.contextLimit,
    maxTriggerEvents: config.maxTriggerEvents,
    maxContextLines: config.maxContextLines,
    promptTriggerSampleMax: config.promptTriggerSampleMax,
    promptContextSampleMax: config.promptContextSampleMax,
    contextAroundTriggerMinutes: config.contextAroundTriggerMinutes,
    includeContextLogs: config.includeContextLogs,
    triggerSelectionMode: normalizeTriggerSelectionMode(config.triggerSelectionMode),
    triggerBatchSize: config.triggerBatchSize,
    autoGenerated: true,
  });
}

function normalizeAnalyzerRule(rule) {
  if (!isObject(rule)) {
    return undefined;
  }

  const id = safeId(rule.id || rule.name || config.ruleId);
  const sourceJob = stringOrDefault(rule.sourceJob, 'central-file-log');
  const logDomain = stringOrDefault(rule.logDomain, '');
  const logType = stringOrDefault(rule.logType, '');
  const customLogQL = normalizeCustomLogQL(rule, sourceJob, logDomain, logType);
  const contextLogQL = normalizeContextLogQL(rule, sourceJob, logDomain, logType);
  const triggerQuery = customLogQL || buildTriggerQuery({ sourceJob, logDomain, logType, keywords: rule.triggerKeywords });
  const contextQuery = contextLogQL || buildContextQuery({ sourceJob, logDomain, logType });

  if (!id || !triggerQuery || !contextQuery) {
    return undefined;
  }

  return {
    id,
    name: stringOrDefault(rule.name, id),
    enabled: rule.enabled !== false,
    sourceJob,
    logDomain,
    logType,
    analysisScenarioId: stringOrDefault(rule.analysisScenarioId, config.analysisScenarioId),
    scenarioName: stringOrDefault(rule.scenarioName, ''),
    scenarioDescription: stringOrDefault(rule.scenarioDescription, ''),
    scenarioPrompt: stringOrDefault(rule.scenarioPrompt, ''),
    insightMode: normalizeInsightMode(rule.insightMode),
    sensitiveOperationMode: normalizeSensitiveOperationMode(rule.sensitiveOperationMode),
    sensitiveOperationRule: stringOrDefault(rule.sensitiveOperationRule, '').trim(),
    prompt: stringOrDefault(rule.prompt, config.rulePrompt),
    triggerKeywords: stringOrDefault(rule.triggerKeywords, ''),
    excludeKeywords: stringOrDefault(rule.excludeKeywords, ''),
    triggerSelectionMode: normalizeTriggerSelectionMode(rule.triggerSelectionMode),
    triggerBatchSize: numberOrDefault(rule.triggerBatchSize, config.triggerBatchSize, 1, 50),
    customLogQL,
    contextLogQL,
    triggerQuery: appendExcludeKeywords(triggerQuery, rule.excludeKeywords),
    contextQuery,
    includeContextLogs: booleanOrDefault(rule.includeContextLogs, config.includeContextLogs),
    lookbackMinutes: numberOrDefault(rule.lookbackMinutes, config.lookbackMinutes, 1, 1440),
    contextLookbackMinutes: numberOrDefault(rule.contextLookbackMinutes, config.contextLookbackMinutes, 1, 1440),
    triggerLimit: numberOrDefault(rule.triggerLimit, config.triggerLimit, 1, 5000),
    contextLimit: numberOrDefault(rule.contextLimit, config.contextLimit, 1, 5000),
    maxTriggerEvents: numberOrDefault(rule.maxTriggerEvents, config.maxTriggerEvents, 1, 200),
    maxContextLines: numberOrDefault(rule.maxContextLines, config.maxContextLines, 1, 2000),
    promptTriggerSampleMax: numberOrDefault(rule.promptTriggerSampleMax, config.promptTriggerSampleMax, 1, 50),
    promptContextSampleMax: numberOrDefault(rule.promptContextSampleMax, config.promptContextSampleMax, 1, 500),
    contextAroundTriggerMinutes: numberOrDefault(rule.contextAroundTriggerMinutes, config.contextAroundTriggerMinutes, 1, 120),
    autoGenerated: rule.autoGenerated === true,
  };
}

function normalizeCustomLogQL(rule, sourceJob, logDomain, logType) {
  const explicit = stringOrDefault(rule.customLogQL, '');
  if (explicit) {
    return explicit;
  }

  const triggerQuery = stringOrDefault(rule.triggerQuery, '');
  if (!triggerQuery) {
    return '';
  }

  const generatedTriggerQuery = buildTriggerQuery({ sourceJob, logDomain, logType, keywords: rule.triggerKeywords });
  const generatedTriggerQueryWithExcludes = appendExcludeKeywords(generatedTriggerQuery, rule.excludeKeywords);
  return sameLogQL(triggerQuery, generatedTriggerQuery) || sameLogQL(triggerQuery, generatedTriggerQueryWithExcludes)
    ? ''
    : triggerQuery;
}

function normalizeContextLogQL(rule, sourceJob, logDomain, logType) {
  const explicit = stringOrDefault(rule.contextLogQL, '');
  if (explicit) {
    return explicit;
  }

  const contextQuery = stringOrDefault(rule.contextQuery, '');
  if (!contextQuery) {
    return '';
  }

  const generatedContextQuery = buildContextQuery({ sourceJob, logDomain, logType });
  return sameLogQL(contextQuery, generatedContextQuery) ? '' : contextQuery;
}

function buildFallbackRule() {
  return {
    id: safeId(config.ruleId),
    name: config.ruleId,
    enabled: true,
    sourceJob: inferSourceJob(config.triggerQuery),
    logDomain: '',
    logType: '',
    analysisScenarioId: config.analysisScenarioId,
    scenarioName: '',
    scenarioDescription: '',
    scenarioPrompt: '',
    insightMode: 'incident',
    sensitiveOperationMode: 'ai',
    sensitiveOperationRule: '',
    prompt: config.rulePrompt,
    triggerKeywords: '',
    excludeKeywords: '',
    triggerSelectionMode: normalizeTriggerSelectionMode(config.triggerSelectionMode),
    triggerBatchSize: config.triggerBatchSize,
    triggerQuery: config.triggerQuery,
    contextQuery: config.contextQuery,
    includeContextLogs: config.includeContextLogs,
    lookbackMinutes: config.lookbackMinutes,
    contextLookbackMinutes: config.contextLookbackMinutes,
    triggerLimit: config.triggerLimit,
    contextLimit: config.contextLimit,
    maxTriggerEvents: config.maxTriggerEvents,
    maxContextLines: config.maxContextLines,
    promptTriggerSampleMax: config.promptTriggerSampleMax,
    promptContextSampleMax: config.promptContextSampleMax,
    contextAroundTriggerMinutes: config.contextAroundTriggerMinutes,
  };
}

function uniqueLogGroups(groups) {
  const byKey = new Map();
  for (const group of groups) {
    const normalized = {
      sourceJob: stringOrDefault(group.sourceJob, config.defaultRuleSourceJob),
      logDomain: stringOrDefault(group.logDomain, ''),
      logType: stringOrDefault(group.logType, ''),
    };
    if (!normalized.logDomain) {
      continue;
    }
    byKey.set(`${normalized.sourceJob}::${normalized.logDomain}::${normalized.logType}`, normalized);
  }
  return Array.from(byKey.values()).sort((left, right) =>
    `${left.logDomain}/${left.logType}`.localeCompare(`${right.logDomain}/${right.logType}`)
  );
}

function ruleCoversLogGroup(rule, group) {
  if (rule.enabled === false) {
    return false;
  }

  const ruleJob = stringOrDefault(rule.sourceJob, 'central-file-log');
  const groupJob = stringOrDefault(group.sourceJob, config.defaultRuleSourceJob);
  const ruleDomain = stringOrDefault(rule.logDomain, '');
  const ruleType = stringOrDefault(rule.logType, '');
  const groupDomain = stringOrDefault(group.logDomain, '');
  const groupType = stringOrDefault(group.logType, '');

  return ruleJob === groupJob && (!ruleDomain || ruleDomain === groupDomain) && (!ruleType || ruleType === groupType);
}

function buildTriggerQuery({ sourceJob, logDomain, logType, keywords }) {
  const selector = buildSelector({ sourceJob, logDomain, logType });
  const keywordRegex = keywordsToRegex(keywords);
  return keywordRegex ? `${selector} |~ "${keywordRegex}"` : selector;
}

function buildContextQuery({ sourceJob, logDomain, logType }) {
  return buildSelector({ sourceJob, logDomain, logType });
}

function buildSelector({ sourceJob, logDomain, logType }) {
  const selectors = [`job="${escapeLogQLLabelValue(sourceJob || 'central-file-log')}"`];
  if (logDomain) {
    selectors.push(`log_domain="${escapeLogQLLabelValue(logDomain)}"`);
  } else {
    selectors.push('log_domain=~".+"');
  }
  if (logType) {
    selectors.push(`log_type="${escapeLogQLLabelValue(logType)}"`);
  } else {
    selectors.push('log_type=~".+"');
  }
  return `{${selectors.join(', ')}}`;
}

function appendExcludeKeywords(query, keywords) {
  const excludeRegex = keywordsToRegex(keywords);
  if (!excludeRegex || query.includes(`!~ "${excludeRegex}"`)) {
    return query;
  }
  return `${query} !~ "${excludeRegex}"`;
}

function normalizeTriggerSelectionMode(value) {
  return value === 'latest' || value === 'all_batches' ? value : 'smart';
}

function normalizeInsightMode(value) {
  return value === 'audit' ? 'audit' : 'incident';
}

function normalizeSensitiveOperationMode(value) {
  return value === 'custom' || value === 'sensitive' || value === 'normal' ? value : 'ai';
}

function keywordsToRegex(value) {
  const keywords = splitList(value);
  if (keywords.length === 0) {
    return '';
  }

  return `(?i)(${keywords.map(escapeRegex).join('|')})`;
}

function buildTriggerBatches(lines, rule) {
  if (rule.triggerSelectionMode === 'all_batches') {
    return chunkLines(lines, rule.triggerBatchSize).filter((batch) => batch.length > 0);
  }

  return [selectTriggerSamples(lines, rule)].filter((batch) => batch.length > 0);
}

function selectTriggerSamples(lines, rule) {
  const limit = Math.min(rule.maxTriggerEvents, rule.promptTriggerSampleMax);
  const latest = lines.slice(-rule.maxTriggerEvents);
  if (rule.triggerSelectionMode === 'latest') {
    return latest.slice(-limit).sort(compareLineTime);
  }

  const uniqueByPattern = uniqueLinesByPattern(latest);
  const ranked = uniqueByPattern
    .map((line) => ({ line, score: scoreLine(line) }))
    .sort((left, right) => right.score - left.score || compareLineTime(right.line, left.line))
    .slice(0, limit)
    .map((item) => item.line);

  return ranked.sort(compareLineTime);
}

function effectiveTriggerQueryLimit(rule) {
  const baseLimit = Math.max(1, Number(rule.triggerLimit) || 100);
  if (rule.triggerSelectionMode === 'all_batches') {
    return baseLimit;
  }
  if (!shouldPrioritizeAuditBehaviorLogs(rule)) {
    return baseLimit;
  }

  // Sangfor/action audit streams often mix high-volume device health lines with
  // lower-volume user behavior lines. Pull a wider candidate window first, then
  // trim back to triggerLimit after behavior-aware ranking.
  return Math.min(1000, Math.max(baseLimit, baseLimit * 5));
}

function selectTriggerCandidateLines(lines, rule) {
  if (rule.triggerSelectionMode === 'all_batches') {
    return [...lines].sort(compareLineTime);
  }

  if (!shouldPrioritizeAuditBehaviorLogs(rule) || lines.length <= rule.triggerLimit) {
    return lines;
  }

  return lines
    .map((line) => ({ line, score: auditBehaviorScoreLine(line) }))
    .sort((left, right) => right.score - left.score || compareLineTime(right.line, left.line))
    .slice(0, rule.triggerLimit)
    .map((item) => item.line)
    .sort(compareLineTime);
}

function shouldPrioritizeAuditBehaviorLogs(rule) {
  const domain = String(rule.logDomain || '').toLowerCase();
  const type = String(rule.logType || '').toLowerCase();
  return rule.insightMode === 'audit' && domain === 'network' && type === 'sangfor';
}

function auditBehaviorScoreLine(line) {
  const text = `${line.text || ''} ${JSON.stringify(line.labels || {})}`.toLowerCase();
  let score = 0;

  for (const pattern of [
    /\[log_type:business\]/,
    /\[usr_name:/,
    /\[user:/,
    /\[host_ip:/,
    /\[dst_ip:/,
    /\[src_port:/,
    /\[serv_port:/,
    /\[serv:/,
    /\[app:/,
    /\[url:/,
    /\[dns:/,
    /\[net_action:/,
    /\[up_flux:/,
    /\[down_flux:/,
  ]) {
    if (pattern.test(text)) {
      score += 3;
    }
  }

  if (/\[app:(?!-|unknown)/.test(text)) {
    score += 4;
  }
  if (/\[serv:(?!-|unknown|0\])/.test(text)) {
    score += 3;
  }
  if (/\[url:(?!-)/.test(text) || /\[dns:(?!-)/.test(text)) {
    score += 4;
  }
  if (/\b(deny|denied|blocked|reject|refused|allow|record)\b/.test(text)) {
    score += 3;
  }

  for (const pattern of [
    /d0:udpthread/,
    /d0:reconstruct/,
    /d0:attachlistcreator/,
    /d0:ssldispatcher/,
    /d0:fault/,
    /edr_client_installed/,
    /lost packet/,
    /content\.recon/,
    /ethtool/,
    /#011addr:/,
  ]) {
    if (pattern.test(text)) {
      score -= 8;
    }
  }

  return score;
}

function chunkLines(lines, batchSize) {
  const size = Math.max(1, Math.min(50, Number(batchSize) || 10));
  const batches = [];
  const sorted = [...lines].sort(compareLineTime);
  for (let index = 0; index < sorted.length; index += size) {
    batches.push(sorted.slice(index, index + size));
  }
  return batches;
}

function selectContextSamples(contextLines, triggerLines, rule) {
  if (contextLines.length === 0 || triggerLines.length === 0) {
    return [];
  }

  const maxLines = Math.min(rule.maxContextLines, rule.promptContextSampleMax);
  const windowNs = BigInt(rule.contextAroundTriggerMinutes) * 60n * 1000000000n;
  const triggerTimes = triggerLines.map((line) => safeTimestampNs(line.timestampNs));
  const inWindow = contextLines.filter((line) => {
    const timestamp = safeTimestampNs(line.timestampNs);
    return triggerTimes.some((triggerTime) => absBigInt(timestamp - triggerTime) <= windowNs);
  });

  const candidates = uniqueLinesByPattern(inWindow.length > 0 ? inWindow : contextLines);
  const ranked = candidates
    .map((line) => ({ line, score: scoreLine(line) + (isNearAnyTrigger(line, triggerTimes, windowNs) ? 4 : 0) }))
    .sort((left, right) => right.score - left.score || compareLineTime(left.line, right.line));
  const highSignal = ranked.filter((item) => item.score > 0).slice(0, Math.ceil(maxLines * 0.7)).map((item) => item.line);
  const remaining = candidates.filter((line) => !highSignal.includes(line));
  const timeline = pickEvenlyByTime(remaining, maxLines - highSignal.length);

  return uniqueByFingerprint([...highSignal, ...timeline]).slice(0, maxLines).sort(compareLineTime);
}

function uniqueLinesByPattern(lines) {
  const byPattern = new Map();
  for (const line of lines) {
    const key = normalizeLogPattern(line);
    const current = byPattern.get(key);
    if (!current || scoreLine(line) > scoreLine(current) || compareLineTime(line, current) > 0) {
      byPattern.set(key, line);
    }
  }
  return Array.from(byPattern.values());
}

function uniqueByFingerprint(lines) {
  const seen = new Set();
  const result = [];
  for (const line of lines) {
    const key = `${line.timestampNs}::${line.text}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(line);
  }
  return result;
}

function pickEvenlyByTime(lines, limit) {
  if (limit <= 0 || lines.length === 0) {
    return [];
  }
  const sorted = [...lines].sort(compareLineTime);
  if (sorted.length <= limit) {
    return sorted;
  }

  const picked = [];
  const step = (sorted.length - 1) / Math.max(1, limit - 1);
  for (let index = 0; index < limit; index += 1) {
    picked.push(sorted[Math.round(index * step)]);
  }
  return uniqueByFingerprint(picked);
}

function scoreLine(line) {
  const text = `${line.text} ${JSON.stringify(line.labels || {})}`.toLowerCase();
  let score = 0;
  for (const keyword of [
    'fatal',
    'panic',
    'exception',
    'critical',
    'error',
    'fail',
    'failed',
    'timeout',
    'timed out',
    'refused',
    'reset by peer',
    'down',
    'link down',
    'flap',
    'crc',
    'drop',
    'discard',
    'denied',
    'blocked',
    'attack',
    'oom',
    'out of memory',
  ]) {
    if (text.includes(keyword)) {
      score += 3;
    }
  }
  if (/p[0-2]\b/.test(text)) {
    score += 4;
  }
  if (/warn|warning/.test(text)) {
    score += 1;
  }
  return score;
}

function normalizeLogPattern(line) {
  return String(line.text || '')
    .replace(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/g, '<time>')
    .replace(/\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}\b/g, '<time>')
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<ip>')
    .replace(/\b[0-9a-f]{8,}\b/gi, '<hex>')
    .replace(/\b\d+\b/g, '<num>')
    .replace(/\s+/g, ' ')
    .slice(0, 260);
}

function isNearAnyTrigger(line, triggerTimes, windowNs) {
  const timestamp = safeTimestampNs(line.timestampNs);
  return triggerTimes.some((triggerTime) => absBigInt(timestamp - triggerTime) <= windowNs);
}

function safeTimestampNs(value) {
  try {
    return BigInt(value || '0');
  } catch {
    return 0n;
  }
}

function absBigInt(value) {
  return value < 0n ? -value : value;
}

function formatSensitiveOperationInstruction(mode, customRule = '') {
  const normalizedCustomRule = String(customRule || '').trim();
  if (mode === 'custom') {
    return [
      '- 敏感操作判定使用当前日志组的自定义标准；该标准只用于 AI 研判，不改变原始日志采集范围。',
      normalizedCustomRule
        ? `- 自定义敏感操作判定标准：${normalizedCustomRule}`
        : '- 自定义敏感操作判定标准为空；证据不足时请写“未确定”。',
      '- 如果自定义标准中包含拒绝、阻断、拦截、net_action=2 等条件，且日志命中这些字段或语义，请在“## 敏感操作”中明确写“结论：是”，不要写成未确定。',
      '- 如果同一批日志中既有命中敏感标准的日志，也有未命中的正常日志，请判定为“结论：是（部分日志命中）”，不要写成未确定。',
      '- 请在“## 敏感操作”中必须写明：结论：是/否/未确定；命中范围：全部/部分/无/未知；判定来源：自定义规则；理由：引用日志字段和原始日志证据。',
      '- 请在“## 行为判定”中分开列出“敏感操作日志”和“非敏感/正常日志”；只把符合自定义标准的日志归入敏感操作。',
      '- 请在“## 涉及对象”中分开列出“敏感操作主体”和“正常/背景主体”；不要把正常用户、正常通道或正常目标混入敏感操作主体。',
      '- 如果同一用户同时存在敏感操作和正常操作，请按用户分别列出“敏感操作证据”和“正常操作证据”，不要在同一个标签里同时标注敏感和正常。',
    ].join('\n');
  }
  if (mode === 'sensitive') {
    return '- 敏感操作判定已由规则自定义为“是”。请在“## 敏感操作”中写明：结论：是；判定来源：自定义规则；并解释日志证据。';
  }
  if (mode === 'normal') {
    return '- 敏感操作判定已由规则自定义为“否”。请在“## 敏感操作”中写明：结论：否；判定来源：自定义规则；并解释日志证据。';
  }
  return '- 敏感操作未自定义，请由 AI 根据日志判断。在“## 敏感操作”中必须写明：结论：是/否/未确定；判定来源：AI判断；理由：基于哪些日志字段。';
}

function formatAuditOutputTemplate() {
  return [
    '必须严格按以下 Markdown 模板输出。标题必须逐字一致，不要改名、编号、合并或删除；标题前不要输出任何额外文字。没有内容也要保留标题，并写“无”或“未知”。',
    '“## 行为判定”“## 涉及对象”“## 关键证据”必须引用触发原始日志中的字段和值，例如 user、host_ip、dst_ip、serv、app、net_action、url、DNS、filename；不要只在摘要或建议中提到这些字段。',
    '',
    '## 故障等级',
    '- 等级：P2/P3/P4/未识别',
    '- 理由：一句话说明分级依据。只要存在敏感操作，等级至少为 P2。',
    '- 约束：如果“## 敏感操作”的结论为“否”，且只属于普通记录、低风险、字段异常、日志截断、未知应用等观察项，不得评为 P2，应评为 P4；需要人工关注但没有敏感操作证据时最多评为 P3。',
    '',
    '## 问题概述',
    '- 用 1-3 句话概括本批日志的核心行为、结论和影响。',
    '',
    '## 敏感操作',
    '- 结论：是/否/未确定',
    '- 命中范围：全部/部分/无/未知',
    '- 判定来源：自定义规则/AI判断',
    '- 命中证据：列出命中的字段、值和对应原始日志序号。',
    '- 非敏感或背景说明：如果同批包含正常日志，请说明正常日志范围，不要混入敏感操作主体。',
    '',
    '## 行为判定',
    '- 敏感操作日志：列出命中的日志序号、用户/IP、动作、通道、结果和理由。',
    '- 非敏感/正常日志：列出未命中的正常或背景日志；如无则写“无”。',
    '',
    '## 涉及对象',
    '- 敏感操作主体：只列出命中敏感操作的用户、源IP、终端、部门/组织。',
    '- 正常/背景主体：列出同批中未命中敏感操作的主体；如无则写“无”。',
    '- 目标对象/通道：列出目标IP、域名、应用、文件、外发通道或策略动作。',
    '',
    '## 关键证据',
    '- 按原始日志序号列出关键字段和值，例如 user、host_ip、dst_ip、app、serv、net_action、url、filename、policy、action。',
    '',
    '## 风险与合规影响',
    '- 说明可能的数据泄露、违规外发、越权访问、策略绕过或业务影响；低风险时也要说明原因。',
    '',
    '## 建议处置',
    '- 给出可执行的审计、复核、策略调整、用户确认或放行建议。',
    '',
    '## 后续关注',
    '- 给出需要继续观察的用户、终端、通道、目标或策略项；如无则写“无”。',
  ].join('\n');
}

function buildPrompt(triggerLines, contextLines, rule, batchInfo = {}) {
  const isAuditMode = rule.insightMode === 'audit';
  const sensitiveInstruction = formatSensitiveOperationInstruction(rule.sensitiveOperationMode, rule.sensitiveOperationRule);
  const auditOutputTemplate = isAuditMode ? formatAuditOutputTemplate() : '';
  const triggerBlock = triggerLines.map((line, index) => `${index + 1}. ${formatLine(line)}`).join('\n');
  const contextBlock = contextLines
    .map((line) => formatLine(line))
    .join('\n');
  const batchLines = [
    `- 日志发送方式：${formatTriggerSelectionMode(rule.triggerSelectionMode)}`,
    batchInfo.triggerTotal ? `- 本轮新增候选日志：${batchInfo.triggerTotal} 行` : '',
    batchInfo.batchTotal > 1 ? `- 发送批次：第 ${batchInfo.batchIndex}/${batchInfo.batchTotal} 批` : '',
  ].filter(Boolean);
  const scenarioLines = [
    rule.analysisScenarioId ? `- 场景 ID：${rule.analysisScenarioId}` : '',
    rule.scenarioName ? `- 场景名称：${rule.scenarioName}` : '',
    rule.scenarioDescription ? `- 场景说明：${rule.scenarioDescription}` : '',
    rule.scenarioPrompt ? `- 场景分析侧重点：${rule.scenarioPrompt}` : '',
    rule.autoGenerated ? '- 规则来源：自动发现的日志组尚未配置专属规则，本次使用默认兜底规则。' : '',
    rule.prompt ? `- 本规则补充要求：${rule.prompt}` : '',
  ].filter(Boolean);

  return truncateText(
    [
      isAuditMode
        ? '你是公司内部的安全审计和用户行为分析助手。请根据触发日志做一次结构化审计研判。'
        : '你是公司内部的运维日志分析助手。请根据触发日志和上下文日志做一次结构化故障分析。',
      '',
      '分析要求：',
      '- 使用中文回答。',
      ...batchLines,
      isAuditMode
        ? '- 先判断审计等级：P2/P3/P4/观察/未识别。P2 表示明确高风险或疑似违规，P3 表示需要关注，P4 表示普通记录或低风险。'
        : '- 先判断故障等级：P0/P1/P2/P3/P4/未确定。',
      isAuditMode ? '- 只要存在敏感操作，审计等级至少为 P2；不得把敏感操作输出为 P3/P4/观察。' : '',
      isAuditMode
        ? '- 如果敏感操作结论为“否”，且没有明确数据泄露、违规外发、越权、攻击、策略绕过或命中自定义敏感操作标准的证据，不得输出 P2；普通/低风险记录必须输出 P4，需要关注但无敏感证据时最多输出 P3。'
        : '',
      isAuditMode
        ? '- 输出重点是行为判定、涉及对象、关键证据、风险与合规影响、建议处置和后续关注。'
        : '- 明确影响范围、关键证据、可能根因、建议排查步骤和临时处置动作。',
      isAuditMode
        ? '- 不要把审计日志包装成系统故障；没有故障根因时不要编造根因、修复建议或服务中断。'
        : '',
      isAuditMode
        ? '- 如果一批日志同时包含敏感操作和非敏感/正常操作，请明确区分，不要把整批都归为敏感，也不要因为存在正常日志而否定敏感命中。'
        : '',
      isAuditMode
        ? '- 涉及对象必须按角色分组：敏感操作主体只包含直接命中敏感标准的用户/IP/终端；正常或背景日志中的用户/IP/终端必须放入正常/背景主体或备注，不能混写。'
        : '',
      isAuditMode
        ? '- 对同一用户的不同通道、不同动作要逐项区分，例如“QQ浏览器 net_action=2”为敏感，“飞书 net_action=3”为正常；不要把该用户整体简单标成敏感或正常。'
        : '',
      isAuditMode ? sensitiveInstruction : '',
      isAuditMode
        ? '- 输出格式是强约束：必须完全使用下方“审计/行为分析输出模板”，前端会按这些章节结构化展示；缺少或改名章节会导致页面无法展示对应内容。'
        : '',
      isAuditMode ? '审计/行为分析输出模板：' : '',
      isAuditMode ? auditOutputTemplate : '',
      '- 只引用日志中能看到的证据，不要编造不存在的主机、服务或事件。',
      '- 如果只是单条孤立事件或证据不足，请明确说明需要继续观察或补充哪些信息。',
      '- 自动告警结果需要简洁，控制在 1000 字以内，避免长篇泛化解释。',
      '',
      `触发规则：${rule.id}（${rule.name}）`,
      `日志来源：job=${rule.sourceJob || '-'} domain=${rule.logDomain || '*'} type=${rule.logType || '*'}`,
      `触发 LogQL：${rule.triggerQuery}`,
      rule.includeContextLogs ? `上下文 LogQL：${rule.contextQuery}` : '上下文日志：本规则未携带上下文日志给 AI。',
      '',
      '分析场景：',
      ...(scenarioLines.length > 0 ? scenarioLines : ['- 未指定，使用通用故障分析。']),
      '',
      '本次触发事件：',
      triggerBlock || '无',
      '',
      rule.includeContextLogs ? '上下文日志：' : '上下文日志：未携带',
      rule.includeContextLogs ? contextBlock || '无' : '本规则已关闭上下文日志传输，请只基于触发事件分析。',
    ].join('\n'),
    config.maxPromptChars
  );
}

function formatTriggerSelectionMode(mode) {
  if (mode === 'all_batches') {
    return '全量分批';
  }
  if (mode === 'latest') {
    return '按时间最新';
  }
  return '智能采样';
}

async function callLiteLLM(prompt, options = {}) {
  if (!config.litellmBaseUrl || !config.litellmApiKey) {
    throw new Error('未配置 LITELLM_BASE_URL 或 LITELLM_API_KEY。');
  }

  const model = options.model || config.litellmModel;
  const systemPrompt =
    options.systemPrompt || '你是严谨的日志分析助手，优先基于证据分析，不确定时说明不确定。';
  const response = await fetchWithTimeout(`${config.litellmBaseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.litellmApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      max_tokens: config.litellmMaxTokens,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt },
      ],
    }),
    timeoutMs: config.litellmTimeoutMs,
    signal: options.signal,
  });

  if (!response.ok) {
    throw new Error(`LiteLLM 调用失败：HTTP ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  const content = body?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error(`LiteLLM 返回中没有 choices[0].message.content：${JSON.stringify(body).slice(0, 1000)}`);
  }

  return content;
}
async function fetchWithTimeout(url, { headers = {}, timeoutMs = 10000, signal, ...requestOptions } = {}) {
  const controller = new AbortController();
  const abortFromParent = () => controller.abort(signal?.reason);
  if (signal?.aborted) {
    controller.abort(signal.reason);
  } else if (signal) {
    signal.addEventListener('abort', abortFromParent, { once: true });
  }

  const timer = setTimeout(() => controller.abort(new Error(`request timed out after ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, {
      ...requestOptions,
      headers,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
    if (signal) {
      signal.removeEventListener('abort', abortFromParent);
    }
  }
}
function applyCors(response) {
  response.setHeader('Access-Control-Allow-Origin', config.apiCorsOrigin);
  response.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

function writeJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify(body));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > config.apiMaxBodyBytes) {
        reject(new Error(`请求体过大，超过 ${config.apiMaxBodyBytes} 字节。`));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });

    request.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(text));
      } catch (err) {
        reject(new Error(`请求体不是有效 JSON：${formatError(err)}`));
      }
    });

    request.on('error', reject);
  });
}

function defaultAlertFields() {
  const fields = {};
  for (const field of ALERT_PAYLOAD_FIELDS) {
    fields[field.id] = field.defaultEnabled;
  }
  return fields;
}

function buildEnvAlertConfig() {
  return normalizeAlertConfig({
    version: 1,
    enabled: config.alertPushEnabled && Boolean(config.alertWebhookUrl),
    minSeverity: config.alertMinSeverity,
    triggerLogLimit: config.alertTriggerLogLimit,
    fields: defaultAlertFields(),
    targets: config.alertWebhookUrl
      ? [
          {
            id: DEFAULT_ALERT_TARGET_ID,
            name: 'Default webhook',
            enabled: config.alertPushEnabled,
            url: config.alertWebhookUrl,
            method: 'POST',
            headers: {},
            timeoutMs: config.alertTimeoutMs,
          },
        ]
      : [],
    bindings: [],
  });
}

async function loadAlertConfig() {
  try {
    const text = await fsp.readFile(config.alertConfigPath, 'utf8');
    const parsed = JSON.parse(text);
    return normalizeAlertConfig(parsed.alertConfig || parsed);
  } catch (err) {
    if (err && err.code !== 'ENOENT') {
      console.warn(`[auto-analyzer] failed to load alert config, using env fallback: ${formatError(err)}`);
    }
    return buildEnvAlertConfig();
  }
}

async function saveAlertConfig(alertConfig) {
  await fsp.mkdir(path.dirname(config.alertConfigPath), { recursive: true });
  await fsp.writeFile(config.alertConfigPath, `${JSON.stringify(normalizeAlertConfig(alertConfig), null, 2)}\n`, 'utf8');
}

function normalizeAlertConfig(raw = {}) {
  const fields = defaultAlertFields();
  const rawFields = raw && typeof raw.fields === 'object' && raw.fields ? raw.fields : {};
  for (const field of ALERT_PAYLOAD_FIELDS) {
    if (typeof rawFields[field.id] === 'boolean') {
      fields[field.id] = rawFields[field.id];
    }
  }

  const targets = Array.isArray(raw.targets)
    ? raw.targets.map((target, index) => normalizeAlertTarget(target, index)).filter((target) => target.url)
    : [];
  const bindings = Array.isArray(raw.bindings)
    ? raw.bindings.map((binding, index) => normalizeAlertBinding(binding, index)).filter(Boolean)
    : [];

  return {
    version: 1,
    enabled: normalizeBoolean(raw.enabled, false),
    minSeverity: normalizeAlertMinSeverity(raw.minSeverity || raw.min_severity || config.alertMinSeverity),
    triggerLogLimit: clampInteger(raw.triggerLogLimit ?? raw.trigger_log_limit, config.alertTriggerLogLimit, 1, 200),
    fields,
    targets,
    bindings,
  };
}

function normalizeAlertTarget(raw = {}, index = 0) {
  const id = normalizeConfigId(raw.id || raw.name || `target-${index + 1}`, `target-${index + 1}`);
  return {
    id,
    name: String(raw.name || id).trim() || id,
    enabled: normalizeBoolean(raw.enabled, true),
    url: String(raw.url || raw.webhookUrl || raw.webhook_url || '').trim(),
    method: normalizeHttpMethod(raw.method),
    headers: normalizeAlertHeaders(raw.headers),
    timeoutMs: clampInteger(raw.timeoutMs ?? raw.timeout_ms, config.alertTimeoutMs, 1000, 120000),
  };
}

function normalizeAlertTestTarget(raw = {}) {
  if (!isObject(raw)) {
    throw new Error('target must be an object');
  }

  const target = normalizeAlertTarget(raw, 0);
  if (!target.url) {
    throw new Error('target.url is required');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(target.url);
  } catch {
    throw new Error('target.url must be a valid absolute URL');
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error('target.url must use http or https');
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('target.url must not contain credentials');
  }

  for (const [name, value] of Object.entries(target.headers)) {
    const normalizedName = name.toLowerCase();
    if (ALERT_TEST_FORBIDDEN_HEADERS.has(normalizedName)) {
      throw new Error(`target.headers contains forbidden header: ${truncateText(name, 120)}`);
    }
    try {
      http.validateHeaderName(name);
      http.validateHeaderValue(name, value);
    } catch {
      throw new Error(`target.headers contains invalid header: ${truncateText(name, 120)}`);
    }
  }

  return {
    ...target,
    url: parsedUrl.toString(),
    timeoutMs: clampInteger(
      target.timeoutMs,
      Math.min(config.alertTimeoutMs, ALERT_TEST_MAX_TIMEOUT_MS),
      1000,
      ALERT_TEST_MAX_TIMEOUT_MS
    ),
  };
}

function normalizeAlertBinding(raw = {}, index = 0) {
  const id = normalizeConfigId(raw.id || `binding-${index + 1}`, `binding-${index + 1}`);
  return {
    id,
    name: String(raw.name || id).trim() || id,
    enabled: normalizeBoolean(raw.enabled, true),
    sourceJob: String(raw.sourceJob || raw.source_job || '').trim(),
    logDomain: String(raw.logDomain || raw.log_domain || '').trim(),
    logType: String(raw.logType || raw.log_type || '').trim(),
    ruleIds: normalizeStringArray(raw.ruleIds || raw.rule_ids),
    targetIds: normalizeStringArray(raw.targetIds || raw.target_ids),
  };
}

function normalizeBoolean(value, fallback = false) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'y', 'on'].includes(normalized)) {
      return true;
    }
    if (['false', '0', 'no', 'n', 'off'].includes(normalized)) {
      return false;
    }
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value !== 0;
  }
  return fallback;
}

function normalizeConfigId(value, fallback) {
  const normalized = String(value || '')
    .trim()
    .replace(/[^a-zA-Z0-9_.:-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || fallback;
}

function normalizeStringArray(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(/[,\n]/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeAlertHeaders(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(headers)
      .map(([key, value]) => [String(key || '').trim(), String(value ?? '').trim()])
      .filter(([key]) => key)
  );
}

function normalizeHttpMethod(method) {
  const normalized = String(method || 'POST').trim().toUpperCase();
  return ['POST', 'PUT', 'PATCH'].includes(normalized) ? normalized : 'POST';
}

function clampInteger(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

async function hasAlertPushConfigured() {
  const alertConfig = await loadAlertConfig();
  return alertConfig.enabled && alertConfig.targets.some((target) => target.enabled && target.url);
}

async function resolveAlertDelivery(result) {
  const alertConfig = await loadAlertConfig();
  if (!alertConfig.enabled || severityRank(result?.severity) > severityRank(alertConfig.minSeverity)) {
    return undefined;
  }

  const targets = selectAlertTargets(alertConfig, result);
  if (targets.length === 0) {
    return undefined;
  }
  return { alertConfig, targets };
}

function selectAlertTargets(alertConfig, result) {
  const enabledTargets = alertConfig.targets.filter((target) => target.enabled && target.url);
  if (enabledTargets.length === 0) {
    return [];
  }

  const bindings = alertConfig.bindings.filter((binding) => binding.enabled);
  if (bindings.length === 0) {
    return enabledTargets;
  }

  const matchedBindings = bindings.filter((binding) => matchesAlertBinding(binding, result));
  if (matchedBindings.length === 0) {
    return [];
  }

  const selectedIds = new Set();
  for (const binding of matchedBindings) {
    const targetIds = binding.targetIds.length > 0 ? binding.targetIds : enabledTargets.map((target) => target.id);
    for (const targetId of targetIds) {
      selectedIds.add(targetId);
    }
  }

  return enabledTargets.filter((target) => selectedIds.has(target.id));
}

function matchesAlertBinding(binding, result = {}) {
  if (binding.sourceJob && binding.sourceJob !== result.source_job) {
    return false;
  }
  if (binding.logDomain && binding.logDomain !== result.log_domain) {
    return false;
  }
  if (binding.logType && binding.logType !== result.log_type) {
    return false;
  }
  if (binding.ruleIds.length > 0 && !binding.ruleIds.includes(result.rule_id)) {
    return false;
  }
  return true;
}

function inferSensitiveOperation(analysis, rule, triggerLines = []) {
  if (rule.insightMode !== 'audit') {
    return { value: undefined, source: undefined };
  }
  if (rule.sensitiveOperationMode === 'sensitive') {
    return { value: true, source: 'rule' };
  }
  if (rule.sensitiveOperationMode === 'normal') {
    return { value: false, source: 'rule' };
  }

  const text = String(analysis || '');
  const source = rule.sensitiveOperationMode === 'custom' ? 'rule' : 'ai';
  const sensitiveSection = extractMarkdownSection(text, '敏感操作') || text;
  if (rule.sensitiveOperationMode === 'custom' && hasCustomSensitiveEvidence(text, triggerLines)) {
    return { value: true, source: 'rule' };
  }
  if (/结论\s*[：:]\s*(是|敏感|部分存在|部分命中|存在|有)/.test(sensitiveSection) || /命中范围\s*[：:]\s*(全部|部分)/.test(sensitiveSection)) {
    return { value: true, source };
  }
  if (/结论\s*[：:]\s*(否|非敏感|不是)/.test(sensitiveSection) || /敏感操作\s*[：:]\s*(否|非敏感|不是)/.test(sensitiveSection)) {
    return { value: false, source };
  }
  if (/敏感操作\s*[：:]\s*(是|敏感|部分存在|部分命中|存在|有)/.test(sensitiveSection)) {
    return { value: true, source };
  }
  return { value: undefined, source };
}

function hasCustomSensitiveEvidence(_analysisText, triggerLines = []) {
  return triggerLines.some((line) => {
    const rawText = String(line?.text || '');
    const labelsText = JSON.stringify(line?.labels || {});
    const combined = `${rawText} ${labelsText}`;
    const netAction = extractLogFieldValue(combined, 'net_action');
    if (netAction === '2') {
      return true;
    }
    if (netAction && netAction !== '2') {
      return false;
    }
    return (
      /\bnet_action\s*[=:：]\s*2\b/i.test(combined) ||
      /\[net_action\s*:\s*2\]/i.test(combined) ||
      /"net_action"\s*:\s*"?2"?/i.test(combined)
    );
  });
}

function extractLogFieldValue(text, fieldName) {
  const escapedField = escapeRegExpLiteral(fieldName);
  const matched = String(text || '').match(new RegExp(`(?:^|[\\s,{\\[])"?${escapedField}"?\\s*[=:：]\\s*"?([^"\\s,}\\]]+)`, 'i'));
  return matched?.[1]?.trim();
}

function escapeRegExpLiteral(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function inferAnalysisSeverity(analysis) {
  const text = String(analysis || '');
  const levelSection = extractMarkdownSection(text, '故障等级') || text.slice(0, 800);
  const matched = levelSection.match(/\bP[0-4]\b/i) || text.match(/\bP[0-4]\b/i);
  return normalizeAnalysisSeverity(matched?.[0]);
}

function normalizeAnalysisSeverity(value) {
  const matched = String(value || '').match(/\bP[0-4]\b/i);
  return matched ? matched[0].toUpperCase() : '未识别';
}

function normalizeAlertMinSeverity(value) {
  const normalized = normalizeAnalysisSeverity(value);
  return severityRank(normalized) < Number.POSITIVE_INFINITY ? normalized : 'P2';
}

function severityRank(severity) {
  const normalized = normalizeAnalysisSeverity(severity);
  if (normalized === 'P0') {
    return 0;
  }
  if (normalized === 'P1') {
    return 1;
  }
  if (normalized === 'P2') {
    return 2;
  }
  if (normalized === 'P3') {
    return 3;
  }
  if (normalized === 'P4') {
    return 4;
  }
  return Number.POSITIVE_INFINITY;
}

function inferAlertLogCategory(result = {}) {
  const insightMode = String(result.insight_mode || '').toLowerCase();
  const domain = String(result.log_domain || '').toLowerCase();
  const type = String(result.log_type || '').toLowerCase();
  const auditTypeHints = ['audit', 'dlp', 'sangfor', 'behavior', 'ueba', 'casb'];
  const deviceTypeHints = ['switch', 'firewall', 'router', 'vpn', 'waf', 'ids', 'ips', 'nac', 'ac', 'ap', 'device'];

  if (insightMode === 'audit' || domain === 'audit' || auditTypeHints.some((hint) => type.includes(hint))) {
    return '审计日志';
  }
  if (deviceTypeHints.some((hint) => type.includes(hint))) {
    return '设备日志';
  }
  return '设备日志';
}

function enforceSensitiveMinimumSeverity(severity, sensitiveOperation) {
  const normalized = normalizeAnalysisSeverity(severity);
  if (sensitiveOperation !== true) {
    return normalized;
  }
  return normalized === 'P0' || normalized === 'P1' || normalized === 'P2' ? normalized : 'P2';
}

function normalizeAuditSeverityBySensitivity(severity, sensitiveOperation, analysis, rule) {
  const normalized = enforceSensitiveMinimumSeverity(severity, sensitiveOperation);
  if (rule.insightMode !== 'audit' || sensitiveOperation !== false) {
    return normalized;
  }

  const text = String(analysis || '');
  const lowRiskText =
    /(普通网络流量|普通记录|正常网络活动|正常业务|常规业务|低风险|风险极低|无需紧急处理|无需处理|未发现.*敏感操作|未命中.*敏感|不构成安全风险|未发现.*高风险)/i.test(
      text
    );
  const attentionText = /(建议关注|需要关注|人工复核|进一步确认|日志解析|字段异常|日志截断|未知应用|TABLE_DATA|未识别应用)/i.test(text);

  if ((normalized === 'P0' || normalized === 'P1' || normalized === 'P2') && lowRiskText) {
    return 'P4';
  }
  if ((normalized === 'P0' || normalized === 'P1' || normalized === 'P2') && attentionText) {
    return 'P3';
  }
  return normalized;
}

function formatSensitiveOperationLabel(value) {
  if (value === true) {
    return 'true';
  }
  if (value === false) {
    return 'false';
  }
  return 'unknown';
}

function isMarkdownHeading(line) {
  return /^#{1,6}\s+/.test(String(line || '').trim());
}

function normalizeMarkdownHeading(line) {
  return String(line || '')
    .trim()
    .replace(/^#{1,6}\s+/, '')
    .replace(/^[\d一二三四五六七八九十]+[、.．)]\s*/, '')
    .replace(/[：:]\s*$/, '')
    .trim();
}

function extractMarkdownSection(text, title) {
  const lines = String(text || '').split(/\r?\n/);
  const expectedTitle = normalizeMarkdownHeading(title);
  const start = lines.findIndex((line) => {
    if (!isMarkdownHeading(line)) {
      return false;
    }
    const normalized = normalizeMarkdownHeading(line);
    return normalized === expectedTitle || normalized.includes(expectedTitle);
  });
  if (start < 0) {
    return '';
  }
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (isMarkdownHeading(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end).join('\n').trim();
}

function extractExactMarkdownSection(text, title) {
  const lines = String(text || '').split(/\r?\n/);
  const expectedTitle = normalizeMarkdownHeading(title);
  const start = lines.findIndex((line) => isMarkdownHeading(line) && normalizeMarkdownHeading(line) === expectedTitle);
  if (start < 0) {
    return '';
  }
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (isMarkdownHeading(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start + 1, end).join('\n').trim();
}

function hasUsableAuditSectionContent(content) {
  const raw = String(content || '').trim();
  if (!raw) {
    return false;
  }

  const compact = raw
    .replace(/[`*_#>\-\s\t\r\n，。；;：:、,.]/g, '')
    .trim();
  if (!compact) {
    return false;
  }

  if (/^(无|暂无|未知|不适用|无内容|未提取到对应章节|未从AI结果中提取到对应章节)$/i.test(compact)) {
    return false;
  }

  if (compact.includes('未从AI结果中提取到对应章节') || compact.includes('请复制完整分析结论查看')) {
    return false;
  }

  return true;
}

function ensureAuditDisplaySections(analysis, rule, triggerLines = []) {
  const text = String(analysis || '').trim();
  if (rule.insightMode !== 'audit' || !text) {
    return text;
  }

  const sections = [];
  if (!hasUsableAuditSectionContent(extractExactMarkdownSection(text, '行为判定'))) {
    sections.push(['行为判定', buildFallbackBehaviorSection(triggerLines)]);
  }
  if (!hasUsableAuditSectionContent(extractExactMarkdownSection(text, '涉及对象'))) {
    sections.push(['涉及对象', buildFallbackObjectSection(triggerLines)]);
  }
  if (!hasUsableAuditSectionContent(extractExactMarkdownSection(text, '关键证据'))) {
    sections.push(['关键证据', buildFallbackEvidenceSection(triggerLines)]);
  }

  if (sections.length === 0) {
    return text;
  }

  const appended = sections
    .flatMap(([title, content]) => ['', `## ${title}`, content || '- 未知'])
    .join('\n');
  return `${text}\n${appended}`.trim();
}

function buildFallbackBehaviorSection(triggerLines = []) {
  const hitIndexes = triggerLines
    .map((line, index) => (hasCustomSensitiveEvidence('', [line]) ? `#${String(index + 1).padStart(2, '0')}` : ''))
    .filter(Boolean);
  const actions = collectLogFieldValues(triggerLines, ['net_action', 'action', 'policy_action', 'result']);
  return [
    `- 自动补充：AI 未按模板返回本章节，以下基于 ${triggerLines.length} 行触发原始日志字段提取。`,
    `- 敏感/阻断行为：${hitIndexes.length ? hitIndexes.join('、') : '未从字段明确识别，请结合“敏感操作”和关键证据复核。'}`,
    `- 动作/结果：${formatFallbackValues(actions)}`,
  ].join('\n');
}

function buildFallbackObjectSection(triggerLines = []) {
  const users = collectLogFieldValues(triggerLines, ['user', 'usr_name', 'username', 'account']);
  const sources = collectLogFieldValues(triggerLines, ['host_ip', 'src_ip', 'source_ip', 'client_ip', 'ip']);
  const targets = collectLogFieldValues(triggerLines, ['dst_ip', 'dest_ip', 'server_ip', 'target_ip']);
  const services = collectLogFieldValues(triggerLines, ['serv', 'app', 'protocol', 'service']);
  const resources = collectLogFieldValues(triggerLines, ['url', 'DNS', 'dns', 'filename', 'filetype', 'site']);
  return [
    `- 操作用户：${formatFallbackValues(users)}`,
    `- 源IP/终端：${formatFallbackValues(sources)}`,
    `- 目标对象：${formatFallbackValues(targets)}`,
    `- 应用/服务：${formatFallbackValues(services)}`,
    `- 资源/通道：${formatFallbackValues(resources)}`,
  ].join('\n');
}

function buildFallbackEvidenceSection(triggerLines = []) {
  if (!triggerLines.length) {
    return '- 未提供触发原始日志。';
  }

  return triggerLines
    .slice(0, 10)
    .map((line, index) => {
      const fields = ['user', 'usr_name', 'host_ip', 'src_ip', 'dst_ip', 'serv', 'app', 'net_action', 'url', 'DNS', 'filename'];
      const pairs = fields
        .map((field) => {
          const value = extractFirstLogFieldValue(line.text || '', field);
          return value ? `${field}=${value}` : '';
        })
        .filter(Boolean);
      return `- #${String(index + 1).padStart(2, '0')}：${pairs.length ? pairs.join('，') : truncateText(line.text || '', 180)}`;
    })
    .join('\n');
}

function collectLogFieldValues(triggerLines, fieldNames, limit = 12) {
  const values = new Set();
  for (const line of triggerLines || []) {
    const text = line.text || '';
    for (const fieldName of fieldNames) {
      for (const value of extractLogFieldValues(text, fieldName)) {
        values.add(value);
        if (values.size >= limit) {
          return Array.from(values);
        }
      }
    }
  }
  return Array.from(values);
}

function extractFirstLogFieldValue(text, fieldName) {
  return extractLogFieldValues(text, fieldName)[0] || '';
}

function extractLogFieldValues(text, fieldName) {
  const values = [];
  const bracketRegex = new RegExp(`\\[${escapeRegex(fieldName)}\\s*:\\s*([^\\]]*)\\]`, 'gi');
  let match;
  while ((match = bracketRegex.exec(String(text || ''))) !== null) {
    const value = cleanLogFieldValue(match[1]);
    if (value) {
      values.push(value);
    }
  }

  const equalsRegex = new RegExp(`\\b${escapeRegex(fieldName)}\\s*=\\s*([^\\s,;\\]]+)`, 'gi');
  while ((match = equalsRegex.exec(String(text || ''))) !== null) {
    const value = cleanLogFieldValue(match[1]);
    if (value) {
      values.push(value);
    }
  }
  return values;
}

function cleanLogFieldValue(value) {
  const cleaned = String(value || '')
    .replace(/^["']|["']$/g, '')
    .trim();
  if (!cleaned || cleaned === '-' || cleaned === '/' || /^unknown$/i.test(cleaned) || cleaned === '未知' || cleaned === '未定义位置') {
    return '';
  }
  return truncateText(cleaned, 120);
}

function formatFallbackValues(values) {
  return values.length ? values.join('、') : '未知';
}

function buildAuditSummary(triggerLines = []) {
  const involvedUsers = collectAuditValues(triggerLines, [
    'user', 'usr_name', 'user_name', 'username', 'account', 'operator', 'actor', 'employee', 'login_name',
  ]);
  const sourceIps = collectAuditValues(triggerLines, [
    'host_ip', 'src_ip', 'source_ip', 'client_ip', 'remote_ip', 'origin_ip',
  ]).filter(isAuditIpAddress);
  const destinationIps = collectAuditValues(triggerLines, [
    'dst_ip', 'dest_ip', 'destination_ip', 'server_ip', 'target_ip',
  ]).filter(isAuditIpAddress);
  const operationActions = collectAuditValues(triggerLines, [
    'action', 'operation', 'operate', 'event_action', 'policy_action', 'net_action', 'command',
  ]);
  const operationObjects = collectAuditValues(triggerLines, [
    'object', 'target', 'resource', 'filename', 'file_name', 'file', 'url', 'uri', 'path', 'site',
    'service', 'serv', 'app',
  ]);
  const eventTimes = uniqueAuditValues(
    triggerLines.map((line) => line.timestampNs ? formatTimestamp(line.timestampNs) : line.timestamp).filter(Boolean),
    12
  );

  return {
    involved_users: involvedUsers,
    source_ips: sourceIps,
    destination_ips: destinationIps,
    operation_actions: operationActions,
    operation_objects: operationObjects,
    event_times: eventTimes,
  };
}

function collectAuditValues(triggerLines, fieldNames, limit = 12) {
  const values = [];
  const normalizedFields = new Set(fieldNames.map(normalizeAuditFieldName));

  for (const line of triggerLines || []) {
    collectAuditObjectValues(line.labels, normalizedFields, values, 0);
    const payload = parseJson(line.text || '');
    if (payload && typeof payload === 'object') {
      collectAuditObjectValues(payload, normalizedFields, values, 0);
    }
    for (const fieldName of fieldNames) {
      values.push(...extractLogFieldValues(line.text || '', fieldName));
    }
    if (uniqueAuditValues(values, limit).length >= limit) {
      break;
    }
  }

  return uniqueAuditValues(values, limit);
}

function collectAuditObjectValues(value, normalizedFields, values, depth) {
  if (!value || typeof value !== 'object' || depth > 4) {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectAuditObjectValues(item, normalizedFields, values, depth + 1));
    return;
  }
  for (const [key, nestedValue] of Object.entries(value)) {
    if (normalizedFields.has(normalizeAuditFieldName(key))) {
      if (Array.isArray(nestedValue)) {
        values.push(...nestedValue.filter((item) => item !== null && typeof item !== 'object'));
      } else if (nestedValue !== null && typeof nestedValue !== 'object') {
        values.push(nestedValue);
      }
    }
    if (nestedValue && typeof nestedValue === 'object') {
      collectAuditObjectValues(nestedValue, normalizedFields, values, depth + 1);
    }
  }
}

function uniqueAuditValues(values, limit = 12) {
  const unique = [];
  const seen = new Set();
  for (const value of values || []) {
    const cleaned = cleanLogFieldValue(value);
    const key = cleaned.toLowerCase();
    if (!cleaned || seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(cleaned);
    if (unique.length >= limit) {
      break;
    }
  }
  return unique;
}

function normalizeAuditFieldName(value) {
  return String(value || '').trim().toLowerCase().replace(/[\s_.-]+/g, '');
}

function isAuditIpAddress(value) {
  const text = String(value || '').trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) {
    return text.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  return /^[0-9a-f:]+$/i.test(text) && text.includes(':');
}

async function pushAnalysisToLoki({
  analysis,
  rule,
  triggerLines,
  triggerTotal,
  contextLines,
  promptChars,
  batchIndex = 1,
  batchTotal = 1,
  signal,
}) {
  const sourceLabels = inferSourceLabels(triggerLines, rule);
  const contextForPrompt = contextLines.slice(-rule.maxContextLines);
  const analysisForDisplay = ensureAuditDisplaySections(analysis, rule, triggerLines);
  const sensitiveOperation = inferSensitiveOperation(analysisForDisplay, rule, triggerLines);
  const severity = normalizeAuditSeverityBySensitivity(
    inferAnalysisSeverity(analysisForDisplay),
    sensitiveOperation.value,
    analysisForDisplay,
    rule
  );
  const generatedAt = new Date().toISOString();
  const auditSummary = buildAuditSummary(triggerLines);
  const result = {
    generated_at: generatedAt,
    rule_id: rule.id,
    rule_name: rule.name,
    analysis_scenario_id: rule.analysisScenarioId,
    analysis_scenario_name: rule.scenarioName,
    insight_mode: rule.insightMode,
    severity,
    sensitive_operation: sensitiveOperation.value,
    sensitive_operation_source: sensitiveOperation.source,
    sensitive_operation_rule: rule.sensitiveOperationRule || undefined,
    model: config.litellmModel,
    trigger_query: rule.triggerQuery,
    context_query: rule.contextQuery,
    include_context_logs: rule.includeContextLogs,
    source_job: sourceLabels.source_job,
    log_domain: sourceLabels.log_domain,
    log_type: sourceLabels.log_type,
    trigger_total: triggerTotal,
    trigger_in_prompt: triggerLines.length,
    trigger_selection_mode: rule.triggerSelectionMode,
    trigger_batch_index: batchIndex,
    trigger_batch_total: batchTotal,
    context_lines: contextForPrompt.length,
    ...auditSummary,
    trigger_logs: triggerLines.map(formatEvidenceLine),
    context_logs: contextForPrompt.map(formatEvidenceLine),
    prompt_chars: promptChars,
    analysis: analysisForDisplay,
  };
  const line = JSON.stringify(result);

  if (config.pushResultToLoki) {
  const payload = {
    streams: [
      {
        stream: {
          job: config.resultJob,
          service: 'auto-analyzer',
          rule_id: rule.id,
          source_job: sourceLabels.source_job,
          detected_level: severity,
          sensitive_operation: formatSensitiveOperationLabel(sensitiveOperation.value),
          ...(rule.analysisScenarioId ? { analysis_scenario_id: rule.analysisScenarioId } : {}),
          ...(sourceLabels.log_domain ? { log_domain: sourceLabels.log_domain } : {}),
          ...(sourceLabels.log_type ? { log_type: sourceLabels.log_type } : {}),
        },
        values: [[toLokiTimestampNs(Date.now()), line]],
      },
    ],
  };

  const response = await fetchWithTimeout(`${config.lokiBaseUrl}/loki/api/v1/push`, {
    method: 'POST',
    headers: {
      ...lokiHeaders(),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
    timeoutMs: config.lokiQueryTimeoutMs,
    signal,
  });

  if (!response.ok) {
    throw new Error(`分析结果写回 Loki 失败：HTTP ${response.status} ${await response.text()}`);
  }
  }
  const alertDelivery = await resolveAlertDelivery(result);
  if (alertDelivery) {
    const payload = buildAlertPayload(result, alertDelivery.alertConfig);
    for (const target of alertDelivery.targets) {
      await pushAlertToPlatform(payload, target, signal);
    }
    console.log(
      `[auto-analyzer] rule ${rule.id} pushed alert ${severity} to ${alertDelivery.targets.length} alert target(s).`
    );
  }
}


function buildAlertPayload(result, alertConfig = buildEnvAlertConfig()) {
  const triggerLogs = Array.isArray(result.trigger_logs) ? result.trigger_logs : [];
  const fullPayload = {
    source: 'ai-log-analyzer',
    severity: normalizeAnalysisSeverity(result.severity),
    log_category: inferAlertLogCategory(result),
    log_domain: result.log_domain || '',
    log_type: result.log_type || '',
    title: extractAlertTitle(result.analysis, result),
    analysis: result.analysis || '',
    trigger_total: Number(result.trigger_total) || 0,
    trigger_logs: triggerLogs.slice(0, alertConfig.triggerLogLimit || config.alertTriggerLogLimit).map(formatAlertTriggerLog),
    generated_at: result.generated_at || new Date().toISOString(),
    rule_id: result.rule_id || '',
    rule_name: result.rule_name || '',
    analysis_scenario_id: result.analysis_scenario_id || '',
    analysis_scenario_name: result.analysis_scenario_name || '',
    insight_mode: result.insight_mode || '',
    source_job: result.source_job || '',
    model: result.model || '',
    trigger_query: result.trigger_query || '',
    context_query: result.context_query || '',
  };

  const payload = {};
  const fields = alertConfig.fields || defaultAlertFields();
  for (const field of ALERT_PAYLOAD_FIELDS) {
    if (fields[field.id]) {
      payload[field.id] = fullPayload[field.id];
    }
  }
  return payload;
}

function buildAlertTestPayload() {
  return {
    source: 'ai-log-analyzer',
    severity: 'P2',
    log_category: 'connectivity_test',
    log_domain: 'alert-config',
    log_type: 'test',
    title: 'AI Log Analyzer alert configuration test',
    analysis: 'This is a connectivity test generated from the alert configuration page.',
    trigger_total: 0,
    trigger_logs: [],
    generated_at: new Date().toISOString(),
  };
}

async function testAlertTarget(target) {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), target.timeoutMs);

  try {
    const upstreamResponse = await fetch(target.url, {
      method: target.method,
      headers: {
        'Content-Type': 'application/json',
        ...target.headers,
      },
      body: JSON.stringify(buildAlertTestPayload()),
      redirect: 'manual',
      signal: controller.signal,
    });
    const responseBody = await readBoundedResponseBody(upstreamResponse, ALERT_TEST_MAX_RESPONSE_BYTES);
    const safeResponseBody = redactAlertTestResponseBody(responseBody.text, target.headers);

    return {
      ok: upstreamResponse.ok,
      reachable: true,
      status: upstreamResponse.status,
      statusText: truncateText(upstreamResponse.statusText, 120),
      durationMs: Date.now() - startedAt,
      responseBody: safeResponseBody.text,
      responseBodyTruncated: responseBody.truncated || safeResponseBody.truncated,
      responseBodyBytes: safeResponseBody.bytes,
      testedAt: new Date().toISOString(),
    };
  } catch (err) {
    const timedOut = err?.name === 'AbortError';
    return {
      ok: false,
      reachable: false,
      status: null,
      statusText: '',
      durationMs: Date.now() - startedAt,
      responseBody: '',
      responseBodyTruncated: false,
      responseBodyBytes: 0,
      errorCode: timedOut ? 'TIMEOUT' : normalizeAlertTestNetworkErrorCode(err),
      error: timedOut ? `alert platform request timed out after ${target.timeoutMs} ms` : 'unable to reach alert platform',
      testedAt: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedResponseBody(response, maxBytes) {
  if (!response.body) {
    return { text: '', truncated: false, bytes: 0 };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      const chunk = Buffer.from(value);
      const remaining = maxBytes - bytes;
      if (remaining <= 0) {
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
      if (chunk.length > remaining) {
        chunks.push(chunk.subarray(0, remaining));
        bytes += remaining;
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }

      chunks.push(chunk);
      bytes += chunk.length;
    }
  } finally {
    reader.releaseLock();
  }

  return {
    text: Buffer.concat(chunks, bytes).toString('utf8'),
    truncated,
    bytes,
  };
}

function redactAlertTestResponseBody(text, headers) {
  let redacted = String(text || '');
  for (const [name, value] of Object.entries(headers || {})) {
    if (ALERT_TEST_NON_SECRET_HEADERS.has(name.toLowerCase()) || !value) {
      continue;
    }
    redacted = redacted.split(String(value)).join('[REDACTED]');
  }

  const encoded = Buffer.from(redacted, 'utf8');
  if (encoded.length <= ALERT_TEST_MAX_RESPONSE_BYTES) {
    return { text: redacted, truncated: false, bytes: encoded.length };
  }
  const bounded = encoded.subarray(0, ALERT_TEST_MAX_RESPONSE_BYTES);
  return {
    text: bounded.toString('utf8'),
    truncated: true,
    bytes: bounded.length,
  };
}

function normalizeAlertTestNetworkErrorCode(err) {
  const code = String(err?.cause?.code || '').trim().toUpperCase();
  const allowedCodes = new Set([
    'CERT_HAS_EXPIRED',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'EAI_AGAIN',
    'ECONNREFUSED',
    'ECONNRESET',
    'ENOTFOUND',
    'ETIMEDOUT',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UND_ERR_CONNECT_TIMEOUT',
  ]);
  return allowedCodes.has(code) ? code : 'NETWORK_ERROR';
}

function formatAlertTriggerLog(line) {
  if (typeof line === 'string') {
    return line;
  }
  if (!line || typeof line !== 'object') {
    return String(line ?? '');
  }
  return String(line.display || line.text || JSON.stringify(line));
}

function extractAlertTitle(analysis, result = {}) {
  const text = String(analysis || '');
  const levelSection = extractMarkdownSection(text, '故障等级') || extractMarkdownSection(text, '告警等级') || '';
  const candidates = [levelSection, text]
    .flatMap((section) => String(section || '').split(/\r?\n/))
    .map((line) =>
      line
        .replace(/^#{1,6}\s*/, '')
        .replace(/^[-*]\s*/, '')
        .replace(/^\d+[.)、]\s*/, '')
        .trim()
    )
    .filter(Boolean)
    .filter((line) => !/^P[0-4]\b$/i.test(line))
    .filter((line) => !/^(故障等级|告警等级|总分析|结论|摘要|敏感操作)\s*[:：]?\s*$/i.test(line));

  const withSeverity = candidates.find((line) => /\bP[0-4]\b/i.test(line));
  const chosen = withSeverity || candidates[0] || '';
  const withoutPrefix = chosen.replace(/^\s*\bP[0-4]\b\s*[:：-]?\s*/i, '').trim();
  if (withoutPrefix) {
    return truncateText(withoutPrefix, 120);
  }

  const domain = result.log_domain || 'unknown';
  const type = result.log_type || 'unknown';
  return `${normalizeAnalysisSeverity(result.severity)} ${domain}/${type} AI analysis`;
}

async function pushAlertToPlatform(payload, target = {}, parentSignal) {
  const url = target.url || config.alertWebhookUrl;
  if (!url) {
    throw new Error('alert target url is empty');
  }

  const controller = new AbortController();
  const abortFromParent = () => controller.abort(parentSignal?.reason);
  if (parentSignal?.aborted) {
    controller.abort(parentSignal.reason);
  } else if (parentSignal) {
    parentSignal.addEventListener('abort', abortFromParent, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), target.timeoutMs || config.alertTimeoutMs);
  try {
    const response = await fetch(url, {
      method: target.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(target.headers || {}),
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`alert platform push failed: HTTP ${response.status} ${await response.text()}`);
    }
  } finally {
    clearTimeout(timer);
    if (parentSignal) {
      parentSignal.removeEventListener('abort', abortFromParent);
    }
  }
}


function inferSourceLabels(lines, rule) {
  return {
    source_job: commonLabelValue(lines, 'job') || rule.sourceJob || inferSourceJob(rule.triggerQuery),
    log_domain: commonLabelValue(lines, 'log_domain') || rule.logDomain,
    log_type: commonLabelValue(lines, 'log_type') || rule.logType,
  };
}

function commonLabelValue(lines, labelName) {
  const values = Array.from(
    new Set(
      lines
        .map((line) => String(line.labels?.[labelName] ?? '').trim())
        .filter(Boolean)
    )
  );

  if (values.length === 0) {
    return '';
  }

  return values.length === 1 ? values[0] : 'mixed';
}

function formatEvidenceLine(line) {
  const timestamp = formatTimestamp(line.timestampNs);
  const text = line.text || '';
  return {
    timestamp,
    labels: line.labels || {},
    text,
    display: text,
  };
}

function inferSourceJob(query) {
  const exactMatch = query.match(/\bjob\s*=\s*"([^"]+)"/);
  if (exactMatch?.[1]) {
    return exactMatch[1];
  }

  const regexMatch = query.match(/\bjob\s*=~\s*"([^"]+)"/);
  if (regexMatch?.[1]) {
    return regexMatch[1].replace(/[^\w.-]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
  }

  return 'unknown';
}

function formatLine(line) {
  const payload = parseJson(line.text);
  if (!payload) {
    return `[${formatTimestamp(line.timestampNs)}] ${formatLabels(line.labels)} ${line.text}`;
  }

  if (!isWindowsEventPayload(payload)) {
    return `[${formatTimestamp(line.timestampNs)}] ${formatLabels(line.labels)} ${JSON.stringify(payload)}`;
  }

  const fields = [
    `time=${payload.timeCreated || formatTimestamp(line.timestampNs)}`,
    `eventlog=${payload.channel || line.labels.eventlog || line.labels.channel || '-'}`,
    `source=${payload.source || '-'}`,
    `event_id=${payload.event_id ?? '-'}`,
    `level=${payload.level ?? '-'}`,
    `levelText=${payload.levelText || '-'}`,
    `message=${payload.message || '-'}`,
  ];

  return `${formatLabels(line.labels)} ${fields.join(' ')}`;
}

function isWindowsEventPayload(payload) {
  return Boolean(
    payload.channel ||
      payload.eventlog ||
      payload.event_id !== undefined ||
      payload.eventRecordID !== undefined ||
      payload.levelText ||
      payload.timeCreated
  );
}

function fingerprintLine(line, rule) {
  const payload = parseJson(line.text);
  const stable = payload
    ? {
        rule_id: rule?.id || config.ruleId,
        eventlog: payload.channel || line.labels.eventlog || line.labels.channel || '',
        source: payload.source || '',
        event_id: payload.event_id || '',
        eventRecordID: payload.eventRecordID || '',
        timeCreated: payload.timeCreated || '',
        message: payload.message || '',
      }
    : {
        rule_id: rule?.id || config.ruleId,
        labels: line.labels,
        timestampNs: line.timestampNs,
        text: line.text,
      };

  return crypto.createHash('sha256').update(JSON.stringify(stable)).digest('hex');
}

async function loadSeenCache() {
  await seenCacheWriteQueue.catch(() => undefined);
  return readSeenCacheFile();
}

async function readSeenCacheFile() {
  try {
    const text = await fsp.readFile(config.cachePath, 'utf8');
    const parsed = JSON.parse(text);
    return {
      seen: isObject(parsed.seen)
        ? parsed.seen
        : looksLikeSeenMap(parsed)
          ? parsed
          : {},
      checkpoints: isObject(parsed.checkpoints)
        ? parsed.checkpoints
        : isObject(parsed.cursors)
          ? parsed.cursors
          : isObject(parsed.ruleStates)
            ? parsed.ruleStates
            : {},
    };
  } catch {
    return { seen: {}, checkpoints: {} };
  }
}

async function saveSeenCache(cache) {
  await fsp.mkdir(path.dirname(config.cachePath), { recursive: true });
  await fsp.writeFile(config.cachePath, `${JSON.stringify(cache, null, 2)}\n`, 'utf8');
}

async function updateSeenCache(mutator) {
  const task = seenCacheWriteQueue
    .catch(() => undefined)
    .then(async () => {
      const latest = await readSeenCacheFile();
      await mutator(latest);
      pruneSeenCache(latest);
      await saveSeenCache(latest);
      return latest;
    });
  seenCacheWriteQueue = task.catch(() => undefined);
  return task;
}

function pruneSeenCache(cache) {
  const expireBefore = Date.now() - config.seenRetentionHours * 60 * 60 * 1000;
  for (const [key, value] of Object.entries(cache.seen)) {
    if (Number(value) < expireBefore) {
      delete cache.seen[key];
    }
  }
}

function getRuleCheckpoint(cache, ruleId) {
  const state = cache?.checkpoints?.[ruleId];
  if (!isObject(state)) {
    return undefined;
  }

  const cursor = normalizeTimestampNs(
    state.lastProcessedTimestampNs || state.last_processed_timestamp_ns || state.cursorNs || state.cursor_ns
  );
  if (!cursor) {
    return undefined;
  }

  return {
    lastProcessedTimestampNs: cursor,
    updatedAtMs: Number(state.updatedAtMs || state.updated_at_ms || 0) || 0,
  };
}

function buildRuleRuntimeState(rules, cache) {
  const runtime = {};
  for (const rule of Array.isArray(rules) ? rules : []) {
    const checkpoint = getRuleCheckpoint(cache, rule.id);
    const latestProbe = latestRuleProbeCache.get(rule.id);
    const latestRun = ruleRunRuntime.get(rule.id) || {};
    const lagSeconds = checkpoint?.lastProcessedTimestampNs && latestProbe?.latestMatchedTimestampNs
      ? timestampLagSeconds(checkpoint.lastProcessedTimestampNs, latestProbe.latestMatchedTimestampNs)
      : undefined;
    runtime[rule.id] = {
      enabled: Boolean(rule.enabled),
      triggerSelectionMode: rule.triggerSelectionMode,
      hasCheckpoint: Boolean(checkpoint?.lastProcessedTimestampNs),
      lastProcessedTimestampNs: checkpoint?.lastProcessedTimestampNs || '',
      lastProcessedTimestamp: checkpoint?.lastProcessedTimestampNs
        ? formatTimestamp(checkpoint.lastProcessedTimestampNs)
        : '',
      updatedAt: checkpoint?.updatedAtMs ? new Date(checkpoint.updatedAtMs).toISOString() : '',
      latestMatchedTimestampNs: latestProbe?.latestMatchedTimestampNs || '',
      latestMatchedTimestamp: latestProbe?.latestMatchedTimestamp || '',
      latestProbeAt: latestProbe?.latestProbeAt || '',
      latestProbeError: latestProbe?.latestProbeError || '',
      lagSeconds: Number.isFinite(lagSeconds) ? lagSeconds : undefined,
      latestRunStatus: latestRun.latestRunStatus || '',
      latestRunStartedAt: latestRun.latestRunStartedAtMs ? new Date(latestRun.latestRunStartedAtMs).toISOString() : '',
      latestRunFinishedAt: latestRun.latestRunFinishedAtMs
        ? new Date(latestRun.latestRunFinishedAtMs).toISOString()
        : '',
      latestRunDurationMs: Number.isFinite(latestRun.latestRunDurationMs) ? latestRun.latestRunDurationMs : undefined,
      latestRunError: latestRun.latestRunError || '',
      latestRunMessage: latestRun.latestRunMessage || '',
    };
  }
  return runtime;
}

async function markBatchProcessed(cache, rule, triggerLines) {
  if (!Array.isArray(triggerLines) || triggerLines.length === 0) {
    return;
  }

  const analyzedAt = Date.now();
  const fingerprints = triggerLines.map((line) => fingerprintLine(line, rule));
  for (const line of triggerLines) {
    cache.seen[fingerprintLine(line, rule)] = analyzedAt;
  }

  const lastLine = triggerLines[triggerLines.length - 1];
  const lastTimestampNs = lastLine?.timestampNs || '';
  if (rule.triggerSelectionMode === 'all_batches' && lastLine?.timestampNs) {
    cache.checkpoints = isObject(cache.checkpoints) ? cache.checkpoints : {};
    const current = getRuleCheckpoint(cache, rule.id);
    cache.checkpoints[rule.id] = {
      lastProcessedTimestampNs: maxTimestampNs(current?.lastProcessedTimestampNs, lastLine.timestampNs),
      updatedAtMs: analyzedAt,
    };
  }

  pruneSeenCache(cache);
  await updateSeenCache(async (latest) => {
    latest.seen = isObject(latest.seen) ? latest.seen : {};
    latest.checkpoints = isObject(latest.checkpoints) ? latest.checkpoints : {};
    for (const fingerprint of fingerprints) {
      latest.seen[fingerprint] = analyzedAt;
    }
    if (rule.triggerSelectionMode === 'all_batches' && lastTimestampNs) {
      const current = getRuleCheckpoint(latest, rule.id);
      latest.checkpoints[rule.id] = {
        lastProcessedTimestampNs: maxTimestampNs(current?.lastProcessedTimestampNs, lastTimestampNs),
        updatedAtMs: analyzedAt,
      };
    }
  });
}

function normalizeTimestampNs(value) {
  try {
    const ns = BigInt(String(value || '0').trim());
    return ns > 0n ? ns.toString() : '';
  } catch {
    return '';
  }
}

function subtractTimestampNs(timestampNs, seconds) {
  try {
    const ns = BigInt(String(timestampNs || '0')) - BigInt(Math.max(0, Number(seconds) || 0)) * 1000000000n;
    return ns > 0n ? ns.toString() : '0';
  } catch {
    return '0';
  }
}

function advanceTimestampNs(timestampNs) {
  try {
    return (BigInt(String(timestampNs || '0')) + 1n).toString();
  } catch {
    return '';
  }
}

function maxTimestampNs(left, right) {
  const leftNs = normalizeTimestampNs(left);
  const rightNs = normalizeTimestampNs(right);
  if (!leftNs) {
    return rightNs;
  }
  if (!rightNs) {
    return leftNs;
  }
  return BigInt(leftNs) >= BigInt(rightNs) ? leftNs : rightNs;
}

function looksLikeSeenMap(value) {
  if (!isObject(value)) {
    return false;
  }

  const reservedKeys = new Set(['seen', 'checkpoints', 'cursors', 'ruleStates', 'version', 'updated_at', 'updatedAt']);
  const keys = Object.keys(value);
  return keys.length > 0 && keys.every((key) => !reservedKeys.has(key));
}

function lokiHeaders() {
  return config.lokiTenantId ? { 'X-Scope-OrgID': config.lokiTenantId } : {};
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function formatLabels(labels) {
  const entries = Object.entries(labels ?? {});
  return entries.length ? `{${entries.map(([key, value]) => `${key}="${value}"`).join(',')}}` : '{}';
}

function formatTimestamp(timestampNs) {
  try {
    return new Date(Number(BigInt(timestampNs) / 1000000n)).toISOString();
  } catch {
    return String(timestampNs);
  }
}

function toLokiTimestampNs(timestampMs) {
  return (BigInt(timestampMs) * 1000000n).toString();
}

function compareLineTime(left, right) {
  const leftNs = BigInt(left.timestampNs || '0');
  const rightNs = BigInt(right.timestampNs || '0');
  return leftNs === rightNs ? 0 : leftNs > rightNs ? 1 : -1;
}

function truncateText(text, maxChars) {
  if (text.length <= maxChars) {
    return text;
  }
  return `${text.slice(0, maxChars)}\n\n[已截断，原始长度 ${text.length} 字符]`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nowText() {
  return new Date().toLocaleString('zh-CN', { hour12: false });
}

function formatError(err) {
  if (!(err instanceof Error)) {
    return String(err);
  }

  const parts = [err.message];
  const cause = err.cause;
  if (cause instanceof Error && cause.message && cause.message !== err.message) {
    parts.push(cause.message);
  } else if (cause && typeof cause === 'object') {
    const code = cause.code || cause.errno;
    const address = cause.address;
    const port = cause.port;
    const detail = [code, address, port].filter(Boolean).join(' ');
    if (detail) {
      parts.push(detail);
    }
  }

  return Array.from(new Set(parts.filter(Boolean))).join('；');
}

function trimRightSlash(value) {
  return value.replace(/\/+$/, '');
}

function stringOrDefault(value, fallback) {
  const text = typeof value === 'string' ? value.trim() : '';
  return text || fallback;
}

function numberOrDefault(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

function booleanOrDefault(value, fallback) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) {
      return true;
    }
    if (['0', 'false', 'no', 'off'].includes(normalized)) {
      return false;
    }
  }
  return fallback;
}

function splitList(value) {
  return String(value ?? '')
    .split(/[\n,，;；]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function safeId(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 96);
}

function escapeLogQLLabelValue(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escapeRegex(value) {
  return String(value).replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');
}

function sameLogQL(left, right) {
  return String(left ?? '').replace(/\s+/g, ' ').trim() === String(right ?? '').replace(/\s+/g, ' ').trim();
}

function envString(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

function envNumber(name, fallback, min, max) {
  const parsed = Number(process.env[name]);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, parsed));
}

function envBoolean(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    return fallback;
  }
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const index = line.indexOf('=');
    if (index === -1) {
      continue;
    }

    const key = line.slice(0, index).trim();
    const value = stripQuotes(line.slice(index + 1).trim());
    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function stripQuotes(value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function printHelp() {
  console.log(`AI 日志自动分析 worker

用法：
  node worker/auto-analyzer.cjs --once   单次检查
  node worker/auto-analyzer.cjs          持续定时检查
  node worker/auto-analyzer.cjs --serve  持续定时检查并启动 HTTP API
  node worker/auto-analyzer.cjs --serve-only  只启动 HTTP API

关键环境变量：
  LOKI_BASE_URL=http://localhost:3100
  LITELLM_BASE_URL=http://192.168.114.144/v1
  LITELLM_API_KEY=sk-...
  LITELLM_MODEL=claude-deepseek-v4-pro-agent
  ANALYZER_RULE_CONCURRENCY=2
  ANALYZER_RULE_TIMEOUT_MS=240000
  LOKI_QUERY_TIMEOUT_MS=60000
  WORKER_API_ENABLED=true
  WORKER_API_PORT=8080
`);
}

main().catch((err) => {
  console.error(`[auto-analyzer] 启动失败：${formatError(err)}`);
  process.exitCode = 1;
});
