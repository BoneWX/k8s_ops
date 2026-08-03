# AI Log Analyzer

Grafana 内部 AI 日志分析 App 插件，用于从 Loki 读取原始日志、按配置筛选后发送给 AI worker 分析，并把分析结果写回 Loki 供页面检索、筛选和研判。

当前插件主要服务两类场景：

- 故障/RCA 分析：网络设备、系统、服务异常日志，输出原因、影响和处置建议。
- 审计/行为分析：Sangfor 行为日志、DLP/终端泄密日志、访问审计日志，输出行为判定、涉及对象、风险影响和审计处置建议。

## 架构

```text
/data/logs 原始日志
  -> Alloy / Loki 采集
  -> Loki 原始日志流 {job="central-file-log", log_domain="<一级目录>", log_type="<二级目录>"}
  -> AI worker 按采集规则查询 Loki
  -> LiteLLM / 大模型
  -> Loki 分析结果流 {job="ai-log-analysis", log_domain="<一级目录>", log_type="<二级目录>"}
  -> Grafana 插件日志页展示
```

插件页面只展示 AI worker 已写回 Loki 的分析结果。原始日志是否存在，需要到 Grafana Explore 查询 `{job="central-file-log", ...}` 确认；AI 分析结果是否存在，需要查询 `{job="ai-log-analysis", ...}` 确认。

## 核心概念

### 日志组

日志组对应 `/data/logs/<一级目录>/<二级目录>`：

- 一级目录映射为 `log_domain`，例如 `network`、`audit`。
- 二级目录映射为 `log_type`，例如 `sangfor`、`switch`、`dlp`。

示例：

```text
/data/logs/network/sangfor/*.log -> {job="central-file-log", log_domain="network", log_type="sangfor"}
/data/logs/audit/dlp/*.log      -> {job="central-file-log", log_domain="audit", log_type="dlp"}
```

### 分析场景

分析场景是独立的 AI Prompt 模板，用来告诉 AI 该如何理解这类日志。

场景可以被不同日志组复用，但只有点击“关联场景”后，当前日志组下的采集规则才会使用该场景。场景本身不决定采集哪些原始日志。

适合放在场景里的内容：

- 日志来源和业务含义。
- 需要重点识别的字段。
- 判定逻辑，例如 DLP 中哪些行为属于文件外发、剪贴板外发、邮件外发。
- 输出要求，例如审计结论要区分命中策略、已阻断、已放行、误报和待核实。

### 原始采集规则

原始采集规则绑定在具体日志组下，决定 worker 从 Loki 取哪些原始日志发送给 AI。

同一个日志组可以配置多条采集规则。例如 Sangfor 日志可以按内部 `log_type` 再拆：

- `sangfor-url`
- `sangfor-business`
- `sangfor-other`

采集规则主要控制：

- 是否启用自动分析。
- 自定义触发 LogQL。
- 触发关键词、排除关键词。
- 日志发送方式，例如全量分批、智能采样。
- 查询窗口、每轮最多触发日志数、分批条数。
- 是否携带上下文日志。

采集规则只控制“哪些原始日志进入 AI”。它不负责判断日志是否敏感操作。

### 展示与研判配置

展示与研判配置也绑定在日志组下，但和原始采集规则分开。

它决定 AI 结果按什么模板展示，以及如何标记敏感操作：

- 结果展示模板：故障分析、审计/行为分析。
- 敏感操作判定：由 AI 判断，或按自定义判定标准判断。
- 自定义敏感操作判定标准：会随命中的原始日志一起发送给 AI，用于判断哪些行为属于敏感操作。

敏感操作判定只影响分析结果和页面标记，不改变原始日志采集范围。

当 AI 结果中存在敏感操作时：

- worker 会将结果最低级别提升到 P2。
- Loki 结果标签会包含 `sensitive_operation="true"`。
- 日志列表行会显示“敏感操作”标记。
- 日志页面可以按敏感操作筛选。

## 配置流程

1. 进入 Grafana 插件配置页。
2. 点击“刷新日志目录”，确认 `/data/logs` 下的新目录已出现。
3. 选择一级目录和二级目录，例如 `audit/dlp`。
4. 在“分析场景”区域选择已有场景，或新建场景后点击“关联场景”。
5. 在“展示与研判配置”区域选择结果展示模板，必要时填写敏感操作判定标准，然后点击“保存展示配置”。
6. 在“原始采集规则”区域新增或复制采集规则。
7. 设置采集规则名称、LogQL、发送方式、窗口和分批参数。
8. 点击“保存采集规则”。

保存采集规则后，不需要再保存整个日志组。采集规则和展示配置分别独立保存。

worker 周期默认 300 秒。修改配置后，下一轮 worker 扫描会按新配置执行；如果已经重启或重新部署 worker，需要确认配置文件已持久化。

## LogQL 示例

### Sangfor URL 日志

```logql
{job="central-file-log", log_domain="network", log_type="sangfor"} |= "[log_type:url"
```

### Sangfor 业务日志

```logql
{job="central-file-log", log_domain="network", log_type="sangfor"} |= "[log_type:business"
```

### Sangfor 其他日志，排除 URL 和业务日志

```logql
{job="central-file-log", log_domain="network", log_type="sangfor"} != "[log_type:url" != "[log_type:business"
```

### DLP 日志

```logql
{job="central-file-log", log_domain="audit", log_type="dlp"}
```

### DLP 只采集拒绝/阻断类日志

具体字段以实际日志为准。例如日志中 `net_action=2` 代表拒绝时：

```logql
{job="central-file-log", log_domain="audit", log_type="dlp"} |= "net_action=2"
```

## 日志发送方式

### 全量分批

worker 每轮从 Loki 拉取最多 `本轮最多触发日志数` 条候选日志，再按 `全量分批条数` 拆成多批发送给 AI。

适合：

- 审计日志。
- DLP 日志。
- Sangfor 行为日志。
- 希望尽量覆盖命中日志的场景。

注意：如果一个日志组里混合了多种内部日志类型，并且流量很大，即使使用全量分批，也可能因为每轮上限而优先取到某类高频日志。建议按内部字段拆多条采集规则，例如 `[log_type:url]`、`[log_type:business]`、`[log_type:other_log]`。

### 智能采样

worker 会挑选代表性日志发送给 AI，用于降低 prompt 体积。

适合：

- 故障日志。
- 重复度很高的异常日志。
- 不要求每类日志都完整覆盖的场景。

不适合：

- 高频审计日志。
- 需要区分每一种行为类型的日志。
- 用户行为或 DLP 这类容易被采样漏掉关键子类型的日志。

## DLP Prompt 示例

可以作为 `audit/dlp` 场景 Prompt 的基础：

```text
这是终端泄密管控/DLP 审计日志。请基于日志证据判断是否存在文件外发、剪贴板文本外发、邮件外发、FTP 外发、IM 外发、网盘/文档笔记外发、SMB 外发、代码外发等数据泄露相关行为。

重点识别以下信息：
1. 操作用户、源 IP、终端、部门/组织。
2. 外发通道：应用、浏览器、邮件、FTP、IM、网盘、SMB、代码平台或其他通道。
3. 文件名、文件类型、敏感数据类型、目标地址或接收方。
4. 策略动作：允许、拒绝、阻断、告警、放行。
5. 业务合理性：是否为正常办公传输、白名单例外、误报或需要人工复核。

敏感操作判定：
- 只要日志显示文件外发、剪贴板外发、邮件外发、FTP 外发、IM 外发、网盘/文档笔记外发、SMB 外发、代码外发，均应判定为敏感操作。
- 如果日志显示 net_action=2，或描述为拒绝、阻断、拦截，代表 DLP 策略已命中，应判定存在敏感操作。
- 如果日志显示 net_action=3，或明确允许、放行，需要结合文件类型、目标对象和用户行为判断是否仍需关注。
- 同一批日志同时存在敏感和非敏感操作时，请明确列出哪些用户/行为是敏感操作，哪些是正常背景操作，不要混在同一个结论里。

输出时请优先给出：
1. 是否存在敏感操作。
2. 涉及用户和终端。
3. 外发通道和目标对象。
4. 策略动作是否已阻断。
5. 风险影响。
6. 审计处置建议。
```

如果使用“自定义敏感操作判定标准”，可以把更短、更硬性的规则写在展示配置里，例如：

```text
日志中出现 net_action=2、拒绝、阻断、拦截，或涉及文件外发、剪贴板外发、邮件外发、FTP 外发、IM 外发、网盘/文档笔记外发、SMB 外发、代码外发时，判定为敏感操作。
如果同一批日志同时包含敏感操作和正常操作，必须分别列出，不得把正常用户标为敏感操作主体。
```

## 日志页筛选

日志页查询的是 AI 分析结果，不是原始日志。

常用筛选项：

- 时间窗口。
- 日志目录 `log_domain`。
- 日志类型 `log_type`。
- 原始采集规则。
- 日志级别 P0/P1/P2/P3/P4/未识别。
- 敏感操作。
- 搜索条件，支持在 AI 结论、原始日志摘要、规则信息中检索。

如果刚保存了新采集规则，日志页的采集规则下拉框会自动刷新；如果页面已经打开很久，可以点击“刷新结果”。

## 持久化

页面保存的场景、采集规则、展示配置会写入 worker 的规则配置文件。生产部署时应确保该文件挂载到宿主机，否则容器重建后配置会丢失。

推荐位置：

```text
config/worker/auto-analysis-rules.json
```

实际路径以 worker 启动参数 `ANALYZER_RULES_PATH` 和 `/rules` API 返回为准。

检查当前 worker 看到的规则：

```bash
curl -s http://127.0.0.1:18080/rules | jq '.rules[] | {id, logDomain, logType, customLogQL, triggerQuery, enabled}'
```

检查 worker 健康状态：

```bash
curl -s http://127.0.0.1:18080/health | jq
```

更新部署时不要覆盖运行态规则文件。代码更新只应覆盖插件 bundle、worker 程序和默认模板，不应删除用户已保存的规则。

## 部署和更新

前端插件更新后，需要重启 Grafana 让新 bundle 生效：

```bash
docker restart logserver-grafana
```

worker 代码或 worker 环境变量更新后，需要重启 worker：

```bash
docker restart logserver-ai-log-analyzer-worker
```

只在页面上保存采集规则、场景或展示配置时，一般不需要重启 worker。worker 下一轮扫描会读取新配置。

## 排障

### 原始日志有，AI 日志页没有

1. 在 Explore 查询原始日志：

```logql
{job="central-file-log", log_domain="<一级目录>", log_type="<二级目录>"}
```

2. 检查采集规则 LogQL 是否能命中原始日志。
3. 检查 worker 日志：

```bash
docker logs --tail=200 logserver-ai-log-analyzer-worker
```

4. 检查规则是否启用：

```bash
curl -s http://127.0.0.1:18080/rules | jq '.rules[] | select(.logDomain=="<一级目录>" and .logType=="<二级目录>")'
```

5. 确认日志页时间窗口覆盖 worker 写回时间。

### 某类日志总是漏掉

常见原因是同一个日志组内混合了多种内部日志类型，高频日志占满了每轮上限。

处理方式：

- 不要只用一条大而全的采集规则。
- 按内部字段拆多条采集规则，例如 Sangfor 的 `[log_type:url]`、`[log_type:business]`、`[log_type:other_log]`。
- 高频审计日志优先使用“全量分批”。
- 调整 `本轮最多触发日志数` 和 `全量分批条数`。

### 新目录不显示

1. 确认宿主机目录存在，例如 `/data/logs/audit/dlp`。
2. 确认 Alloy 已采集并写入 Loki。
3. 在配置页点击“刷新日志目录”。
4. 如果页面仍不显示，检查后端目录扫描配置和容器挂载。

### 敏感操作显示不符合预期

1. 检查当前日志组是否使用“审计/行为分析”展示模板。
2. 检查“敏感操作判定”是否选择了正确模式。
3. 如果使用自定义判定标准，确认标准写在“展示与研判配置”里，而不是采集规则 LogQL 里。
4. 如果同一批日志包含敏感和非敏感操作，建议在自定义标准或场景 Prompt 中明确要求 AI 分开列出。

## 开发目录

```text
ai-log-analyzer-app/
  src/
    pages/
      HomePage.tsx
      ConfigPage.tsx
    types.ts
  worker/
    auto-analyzer.cjs

plugins/wx-loganalyzer-app/
  module.js
  module.js.map
  plugin.json
  README.md

config/worker/
  auto-analysis-rules.json
  seen-events.json
```

## 本地构建

在源码目录构建插件：

```bash
npm install
npm run build
```

构建产物需要同步到部署目录：

```text
plugins/wx-loganalyzer-app/module.js
plugins/wx-loganalyzer-app/module.js.map
plugins/wx-loganalyzer-app/plugin.json
```

worker 语法检查：

```bash
node --check ai-log-analyzer-app/worker/auto-analyzer.cjs
```
