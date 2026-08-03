# Log Server 部署与运维说明

本目录用于在内网日志服务器上部署一套集中日志采集、查询和 AI 分析环境。系统由 Loki、Grafana、Grafana Alloy 和 AI Log Analyzer worker 组成。

整体目标：

- 统一接入文件日志和 syslog 日志。
- 通过 Loki 保存原始日志，并提供 LogQL 查询。
- 通过 Grafana 插件配置日志组、采集规则、分析场景和展示研判规则。
- 通过 AI worker 周期性查询 Loki，把命中的原始日志发送给大模型分析。
- 把 AI 分析结果写回 Loki，供插件首页检索、筛选和研判。

## 架构

```text
日志源
  -> /data/logs/<一级目录>/<二级目录>/*.log 或 syslog
  -> Grafana Alloy
  -> Loki 原始日志
       {job="central-file-log", log_domain="<一级目录>", log_type="<二级目录>"}
  -> AI Log Analyzer worker
  -> LiteLLM / 大模型
  -> Loki AI 结果
       {job="ai-log-analysis", log_domain="<一级目录>", log_type="<二级目录>"}
  -> Grafana AI Log Analyzer 插件
```

## 组件

| 组件 | 容器名 | 作用 |
| --- | --- | --- |
| Loki | `logserver-loki` | 存储原始日志和 AI 分析结果，提供 LogQL 查询 |
| Grafana | `logserver-grafana` | 查询、展示、插件运行入口 |
| Alloy | `logserver-alloy` | 采集 `/data/logs` 文件日志，接收 syslog，写入 Loki |
| AI worker | `logserver-ai-log-analyzer-worker` | 读取采集规则，查询 Loki，调用 LiteLLM，写回 AI 结果 |

## 目录结构

```text
log-server/
├── docker-compose.yml
├── docker-compose.worker.yml
├── .env.example
├── config/
│   ├── alloy/config.alloy
│   ├── grafana/provisioning/
│   ├── loki/loki.yml
│   └── worker/
│       ├── auto-analyzer.env
│       ├── auto-analysis-rules.json
│       └── seen-events.json
├── ai-log-analyzer-app/
│   └── worker/auto-analyzer.cjs
├── plugins/
│   └── wx-loganalyzer-app/
├── docs/
├── logs/
└── scripts/
```

关键目录说明：

- `config/worker/auto-analysis-rules.json`：页面保存的场景、日志组关联、采集规则和展示研判配置。
- `config/worker/seen-events.json`：worker 已处理日志游标和去重状态。
- `config/worker/auto-analyzer.env`：worker 连接 Loki、LiteLLM、模型和运行参数。
- `plugins/wx-loganalyzer-app/`：Grafana 插件部署包。
- `ai-log-analyzer-app/worker/auto-analyzer.cjs`：AI worker 主程序。

## 首次部署

1. 准备配置文件：

```bash
cd /opt/grafana/deploy/log-server
cp .env.example .env
bash scripts/init.sh
bash scripts/init-worker.sh
```

2. 修改 `.env`：

```bash
vi .env
```

常用配置：

```bash
TZ=Asia/Shanghai
HOST_LOG_DIR=/data/logs
GRAFANA_HTTP_PORT=3000
LOKI_HTTP_PORT=3100
ALLOY_HTTP_PORT=12345
SYSLOG_TCP_PORT=1514
SYSLOG_UDP_PORT=1514
WORKER_HTTP_PORT=18080
GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=wx-loganalyzer-app
```

如果内网使用私有镜像仓库，需要把镜像名改成内网镜像：

```bash
LOKI_IMAGE=registry.intra.local/grafana/loki:3.5.0
GRAFANA_IMAGE=registry.intra.local/grafana/grafana:13.0.1
ALLOY_IMAGE=registry.intra.local/grafana/alloy:v1.11.0
NODE_IMAGE=registry.intra.local/library/node:22-alpine
```

3. 修改 worker 配置：

```bash
vi config/worker/auto-analyzer.env
```

必须确认：

```bash
LITELLM_BASE_URL=http://你的AI网关/v1
LITELLM_API_KEY=sk-...
LITELLM_MODEL=claude-deepseek-v4-pro-agent
WORKER_API_ENABLED=true
WORKER_API_PORT=8080
ANALYZER_RULES_PATH=/config/auto-analysis-rules.json
ANALYZER_CACHE_PATH=/config/seen-events.json
```

4. 启动服务：

```bash
bash scripts/start-with-worker.sh
```

5. 检查状态：

```bash
bash scripts/status.sh
curl -s http://127.0.0.1:18080/health | jq
```

## 访问地址

```text
Grafana:  http://日志服务器IP:3000
Loki:     http://日志服务器IP:3100
Alloy:    http://日志服务器IP:12345
Syslog:   日志服务器IP:1514/tcp 或 1514/udp
Worker:   http://日志服务器IP:18080
```

Grafana 初始账号密码来自 `.env`：

```bash
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=ChangeMe_please
```

## 日志接入规范

推荐所有文件日志统一放到：

```text
/data/logs/<一级目录>/<二级目录>/*.log
```

示例：

```text
/data/logs/network/sangfor/*.log
/data/logs/network/switch/*.log
/data/logs/audit/dlp/*.log
/data/logs/app/nginx/*.log
```

Alloy 会写入 Loki，标签格式为：

```logql
{job="central-file-log", log_domain="<一级目录>", log_type="<二级目录>"}
```

示例查询：

```logql
{job="central-file-log", log_domain="network", log_type="sangfor"}
```

```logql
{job="central-file-log", log_domain="audit", log_type="dlp"}
```

如果新增目录后 Grafana 插件配置页没有出现，先确认 Explore 能查到原始日志，再在配置页点击“刷新日志目录”。

## Syslog 接入

Alloy 默认监听：

```text
1514/tcp
1514/udp
```

网络设备、网关、防火墙、Sangfor 等设备可以把 syslog 发送到：

```text
日志服务器IP:1514
```

如果必须使用传统 514 端口，修改 `.env`：

```bash
SYSLOG_TCP_PORT=514
SYSLOG_UDP_PORT=514
```

注意：Ubuntu 本机如果已有 rsyslog 占用 514，需要先停用或改用 1514。

网络设备接入说明见：

```text
docs/network-log-onboarding.md
```

## AI Log Analyzer 配置模型

插件配置页按照 `/data/logs` 的一级目录和二级目录维护配置。

### 日志组

日志组是 `log_domain/log_type`，对应真实目录：

```text
network/sangfor -> /data/logs/network/sangfor
audit/dlp       -> /data/logs/audit/dlp
```

### 分析场景

分析场景是独立 Prompt 模板。场景可以复用，但需要在日志组下点击“关联场景”后，当前日志组的采集规则才会使用该场景。

### 原始采集规则

原始采集规则绑定在日志组下，决定 worker 从 Loki 取哪些原始日志发送给 AI。

一个日志组可以有多条采集规则。例如 Sangfor 可以按内部日志类型拆分：

```logql
{job="central-file-log", log_domain="network", log_type="sangfor"} |= "[log_type:url"
{job="central-file-log", log_domain="network", log_type="sangfor"} |= "[log_type:business"
{job="central-file-log", log_domain="network", log_type="sangfor"} != "[log_type:url" != "[log_type:business"
```

### 展示与研判配置

展示与研判配置同样绑定在日志组下，但和采集规则分开。它控制：

- AI 结果展示模板：故障分析或审计/行为分析。
- 敏感操作判定方式。
- 自定义敏感操作判定标准。

敏感操作判定只影响 AI 结果标记，不改变采集范围。存在敏感操作时，worker 会把结果最低级别提升到 P2，并写入 `sensitive_operation="true"` 标签。

更详细的插件使用说明见：

```text
plugins/wx-loganalyzer-app/README.md
```

## 告警平台推送配置

P2 及以上 AI 分析结果可以推送到外部告警平台。告警配置独立于采集规则，实际落盘文件为：

```text
config/worker/alert-config.json
```

worker 容器内路径为：

```text
/config/alert-config.json
```

`docker-compose.worker.yml` 已将宿主机 `./config/worker` 挂载到容器 `/config`，因此页面或 API 保存后的配置会永久保存在宿主机 `config/worker/alert-config.json`。

如需先手工准备配置，可复制样例：

```bash
cp config/worker/alert-config.example.json config/worker/alert-config.json
```

worker 提供配置 API：

```bash
curl -s http://127.0.0.1:18080/alert-config | jq
```

保存配置：

```bash
curl -s -X POST http://127.0.0.1:18080/alert-config \
  -H 'Content-Type: application/json' \
  -d @config/worker/alert-config.json | jq
```

告警配置包含三部分：

- `targets`：告警平台目标端，例如 Webhook URL、HTTP 方法、请求头、超时时间。
- `fields`：发送给告警平台的字段白名单，管理员可以选择是否携带 `analysis`、`trigger_logs`、`model`、`trigger_query` 等字段。
- `bindings`：告警目标和日志/规则的关联。可以按 `sourceJob`、`logDomain`、`logType`、`ruleIds` 绑定；为空时表示不限制。

默认推荐 payload 字段：

```json
{
  "source": "ai-log-analyzer",
  "severity": "P2",
  "log_category": "审计日志",
  "log_domain": "network",
  "log_type": "sangfor",
  "title": "大量内网主机访问邮件服务器被拒",
  "analysis": "完整 AI 分析内容",
  "trigger_total": 30,
  "trigger_logs": ["前 N 条原始日志字符串"],
  "generated_at": "2026-07-07T00:00:00.000Z"
}
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `source` | 固定为 `ai-log-analyzer`，用于告警平台识别来源系统 |
| `severity` | AI 研判后的等级，默认 P2 及以上推送 |
| `log_category` | 日志大类，例如 `审计日志` 或 `设备日志` |
| `log_domain` | 原始日志一级目录，也是 Loki 标签 `log_domain` |
| `log_type` | 原始日志二级目录，也是 Loki 标签 `log_type` |
| `title` | 从 AI 分析结论中提取的告警标题 |
| `analysis` | 完整 AI 分析内容 |
| `trigger_total` | 本轮命中的触发日志总数 |
| `trigger_logs` | 前 N 条触发原始日志，数量由 `triggerLogLimit` 控制 |
| `generated_at` | AI 结果生成时间 |

如果未创建 `alert-config.json`，worker 会继续使用 `auto-analyzer.env` 里的旧版告警环境变量作为兜底：

```bash
ANALYZER_ALERT_PUSH_ENABLED=false
ANALYZER_ALERT_WEBHOOK_URL=
ANALYZER_ALERT_MIN_SEVERITY=P2
ANALYZER_ALERT_TRIGGER_LOG_LIMIT=30
```

页面或 API 修改 `alert-config.json` 后不需要重启 worker；worker 每次写回 AI 结果时会重新读取告警配置。修改 `auto-analyzer.env` 或 worker 程序文件后需要重启 worker。

## AI worker 运行机制

worker 周期性读取 `config/worker/auto-analysis-rules.json` 中的规则。

每条规则的基本流程：

```text
读取规则
  -> 按 customLogQL / triggerQuery 查询 Loki 原始日志
  -> 根据日志发送方式挑选候选日志
  -> 按批次构造 Prompt
  -> 调用 LiteLLM
  -> 解析 AI JSON 结果
  -> 写回 Loki {job="ai-log-analysis"}
  -> 更新 seen-events.json
```

查看当前规则：

```bash
curl -s http://127.0.0.1:18080/rules | jq '.rules[] | {id, name, logDomain, logType, customLogQL, triggerQuery, enabled}'
```

查看 worker 日志：

```bash
docker logs --tail=200 logserver-ai-log-analyzer-worker
```

查看 AI 结果：

```logql
{job="ai-log-analysis"}
```

指定日志组：

```logql
{job="ai-log-analysis", log_domain="audit", log_type="dlp"}
```

## 运行态配置持久化

以下文件是运行态配置，不应在更新时覆盖：

```text
.env
config/worker/auto-analyzer.env
config/worker/auto-analysis-rules.json
config/worker/seen-events.json
```

其中：

- `auto-analysis-rules.json` 保存页面创建的场景、日志组关联、采集规则、展示研判配置。
- `seen-events.json` 保存 worker 已处理游标，避免重复分析。

`docker-compose.worker.yml` 将宿主机目录挂载到 worker：

```text
./config/worker:/config
ANALYZER_RULES_PATH=/config/auto-analysis-rules.json
ANALYZER_CACHE_PATH=/config/seen-events.json
```

只要 `config/worker/auto-analysis-rules.json` 不被覆盖，Grafana 重启、worker 重启、插件包更新后，用户在页面保存的规则和场景都会保留。

`scripts/update.sh` 更新前会备份运行态配置到：

```text
config/backups/update-YYYYMMDD-HHMMSS/
```

## 更新策略

常规更新：

```bash
bash scripts/update.sh
```

只更新 Grafana：

```bash
bash scripts/update.sh grafana
```

只更新 worker：

```bash
bash scripts/update.sh ai-log-analyzer-worker
```

页面上保存采集规则、场景、展示配置后，一般不需要重启 worker。worker 下一轮扫描会读取新配置。

以下情况需要重启服务：

- 更新 `plugins/wx-loganalyzer-app/module.js` 或插件包：重启 Grafana。
- 更新 `ai-log-analyzer-app/worker/auto-analyzer.cjs`：重启 worker。
- 修改 `.env` 中端口、镜像、挂载等 compose 参数：重新执行 compose 更新。
- 修改 `config/worker/auto-analyzer.env`：重启 worker。

常用命令：

```bash
docker restart logserver-grafana
docker restart logserver-ai-log-analyzer-worker
```

## 从开发机同步到内网

通常需要同步这些文件或目录：

```text
ai-log-analyzer-app/
plugins/wx-loganalyzer-app/
scripts/
docker-compose.yml
docker-compose.worker.yml
README.md
```

不要用开发机的运行态配置覆盖内网：

```text
config/worker/auto-analysis-rules.json
config/worker/seen-events.json
config/worker/auto-analyzer.env
.env
```

除非明确要重置内网配置。

## 常用排障

### 1. 原始日志是否进入 Loki

```logql
{job="central-file-log", log_domain="<一级目录>", log_type="<二级目录>"}
```

如果这里查不到，问题在日志源、Alloy、目录挂载或 Loki 写入。

### 2. 采集规则是否命中原始日志

把配置页里的自定义触发 LogQL 复制到 Grafana Explore 执行。

例如：

```logql
{job="central-file-log", log_domain="audit", log_type="dlp"} |= "net_action=2"
```

如果 Explore 能查到，但 AI 结果没有，继续看 worker 日志。

### 3. worker 是否正常执行

```bash
curl -s http://127.0.0.1:18080/health | jq
docker logs --since=30m logserver-ai-log-analyzer-worker
```

重点关注：

```text
检查规则
没有命中新的触发日志
已分析 N 批
结果已写回 Loki
执行失败
```

### 4. AI 结果是否写回 Loki

```logql
{job="ai-log-analysis"}
```

按日志组查询：

```logql
{job="ai-log-analysis", log_domain="network", log_type="sangfor"}
```

按采集规则查询：

```logql
{job="ai-log-analysis", rule_id="audit-dlp-risk"}
```

### 5. 页面没有结果

检查：

- 时间窗口是否覆盖 AI 写回时间。
- 日志目录、日志类型、采集规则筛选是否过窄。
- 是否筛选了敏感操作或特定级别。
- Explore 是否能查到 `{job="ai-log-analysis"}`。
- 浏览器是否加载了最新插件 bundle。

### 6. 某类日志总被漏掉

常见原因是同一日志组中混合多种高频日志，单条规则被高频类型占满。

处理方式：

- 按内部字段拆多条采集规则。
- 审计日志优先使用“全量分批”。
- 调大 `本轮最多触发日志数` 和 `全量分批条数`。
- 对 Sangfor 这类日志按 `[log_type:url]`、`[log_type:business]`、其他类型拆分。

## 常用命令

```bash
bash scripts/status.sh
bash scripts/check.sh
bash scripts/logs.sh
bash scripts/logs.sh alloy
bash scripts/logs.sh ai-log-analyzer-worker
bash scripts/restart.sh
bash scripts/stop.sh
```

Docker 直接命令：

```bash
docker ps
docker inspect logserver-ai-log-analyzer-worker
docker logs --tail=200 logserver-ai-log-analyzer-worker
docker logs --tail=200 logserver-grafana
```

## 版本更新检查清单

更新前：

- 备份 `.env`、`config/worker/auto-analyzer.env`、`config/worker/auto-analysis-rules.json`、`config/worker/seen-events.json`。
- 确认本次更新需要重启哪些服务。
- 确认不会覆盖内网用户保存的规则。

更新后：

- `curl -s http://127.0.0.1:18080/health | jq`
- `curl -s http://127.0.0.1:18080/rules | jq '.rules | length'`
- Grafana Explore 查询 `{job="central-file-log"}`。
- Grafana Explore 查询 `{job="ai-log-analysis"}`。
- 插件配置页确认日志目录、采集规则和场景仍存在。
