# AI 日志分析插件

这是一个用于公司内部 Grafana 的 AI 日志分析 App 插件。它的目标不是把原始日志直接丢给大模型，而是先在前端做脱敏、压缩、聚合和证据提取，再通过自带 AI worker 调用 LiteLLM 网关后面的 DeepSeek / GLM 模型。

## 架构定位

```text
Grafana
  -> AI 日志分析插件
  -> AI worker
  -> LiteLLM 网关
  -> DeepSeek / GLM
```

## 当前第一版能力

- 支持在 Grafana 页面中粘贴异常日志并进行本地预分析。
- 支持常见敏感信息脱敏，包括 token、key、cookie、手机号、邮箱、IP 等。
- 支持把相似异常日志归类，提取高风险日志样本。
- 支持生成结构化中文故障分析 Prompt。
- 支持通过自带 AI worker 调用 LiteLLM，不依赖 `grafana-llm-app`。
- 支持指定 LiteLLM 中的模型名，例如 `deepseek-v4-pro`。
- 支持从 Grafana 已配置的 Loki 数据源拉取日志，填写 LogQL、时间范围和拉取条数后进入 AI 分析。
- 支持常用 LogQL 快捷查询，覆盖错误日志、Windows 文件日志、游戏服务、Nginx、Docker、Kubernetes、数据库/Redis 等场景。
- 支持独立后台 worker 自动查询 Loki、调用 LiteLLM 分析，并把自动分析结果写回 Loki。

第一版会优先发送“脱敏后的摘要和关键证据”，避免把完整原始日志直接发给大模型。

## 目录说明

```text
ai-log-analyzer-app
  src/plugin.json              Grafana 插件元数据
  src/module.ts                Grafana 插件入口
  src/components/App.tsx        应用路由入口
  src/pages/AnalyzerPage.tsx    日志分析主页面
  src/pages/ConfigPage.tsx      插件配置页面
  src/pages/AboutPage.tsx       使用说明页面
  src/utils/logProcessing.ts    日志脱敏、聚合、Prompt 生成逻辑
  src/utils/grafanaLogs.ts      Grafana Loki 数据源读取与 query_range 查询封装
  src/utils/logQueryPresets.ts  常用 LogQL 快捷查询
  src/utils/llm.ts              AI worker API 调用封装
  worker/auto-analyzer.cjs      后台自动分析 worker
  worker/README.md              自动分析 worker 使用说明
```

## 本地开发

安装依赖：

```powershell
npm install
```

如果安装时报 `@grafana/plugin-tools` 找不到，说明依赖文件还是旧版本。当前项目应使用公开的 `@grafana/create-plugin` 作为构建工具。

构建插件：

```powershell
npm run build
```

构建成功后，插件产物会生成在 `dist` 目录。`docker-compose.yml` 会启动本地 Grafana + Loki，并把本地 `dist` 挂载到 Grafana 插件目录中。

启动本地 Grafana + Loki：

```powershell
docker compose up -d
```

本机 worker 需要单独启动：

```powershell
npm run auto-analyze:serve
```

访问地址：

```text
http://localhost:3000/a/wx-loganalyzer-app/analyzer
```

默认 Grafana 登录账号：

```text
admin / admin
```

如果本机之前已经启动过 Grafana，`grafana-data` Docker 卷会保留旧密码；此时 compose 里的默认密码不会覆盖已有账号。

## Grafana 配置

这个插件不依赖 Grafana 官方 `grafana-llm-app`。需要启动自带 AI worker，并让 worker 连接公司内部 LiteLLM 网关。

推荐配置方式：

```text
Worker API: http://<log-server>:18080
LiteLLM Base URL: http://<litellm-host>:<port>/v1
LiteLLM API Key:  专用 LiteLLM 用户 Key
Model:            deepseek-v4-pro 或其他审批通过的模型
```

内部使用时不要使用 LiteLLM master key。建议为 Grafana 单独创建一个专用 key，并配置：

- 允许访问的模型
- 部门或项目预算
- RPM / TPM 限流
- key 负责人
- 审计标识

## Loki / Alloy 采集模板

本地验证链路：

```text
应用日志文件
  -> Grafana Alloy
  -> Loki
  -> Grafana Loki 数据源
  -> AI 日志分析插件
  -> AI worker
  -> LiteLLM
```

### Windows 文件日志

适合 Windows 服务、传奇4、工具服、测试机日志。

```hcl
local.file_match "windows_game_logs" {
  path_targets = [
    {
      __path__ = "D:/logs/**/*.log",
      job = "windows-game-logs",
      service = "game-server",
      env = "test",
      host = "windows-host-01",
      log_type = "server",
    },
  ]
}

loki.source.file "windows_game_logs" {
  targets    = local.file_match.windows_game_logs.targets
  forward_to = [loki.write.local_loki.receiver]
}

loki.write "local_loki" {
  endpoint {
    url = "http://localhost:3100/loki/api/v1/push"
  }
}
```

### Linux 文件日志

适合普通虚机、物理机、单机服务日志。

```hcl
local.file_match "linux_service_logs" {
  path_targets = [
    {
      __path__ = "/data/logs/**/*.log",
      job = "linux-service-logs",
      service = "battle-server",
      env = "prod",
      host = "linux-host-01",
      log_type = "server",
    },
  ]
}

loki.source.file "linux_service_logs" {
  targets    = local.file_match.linux_service_logs.targets
  forward_to = [loki.write.local_loki.receiver]
}
```

### Docker 容器日志

适合单机 Docker 或 docker compose。实际路径和 label 需要根据宿主机目录、容器命名方式调整。

```hcl
local.file_match "docker_logs" {
  path_targets = [
    {
      __path__ = "/var/lib/docker/containers/*/*.log",
      job = "docker-container-logs",
      env = "prod",
      log_type = "docker",
    },
  ]
}

loki.source.file "docker_logs" {
  targets    = local.file_match.docker_logs.targets
  forward_to = [loki.write.local_loki.receiver]
}
```

### Kubernetes 日志

Kubernetes 建议后续按集群情况补充 `discovery.kubernetes` 和 `loki.process`，把 namespace、pod、container、app 等 label 保留下来。第一阶段可以先验证节点文件日志：

```hcl
local.file_match "k8s_pod_logs" {
  path_targets = [
    {
      __path__ = "/var/log/pods/**/*.log",
      job = "kubernetes-pod-logs",
      env = "prod",
      log_type = "k8s",
    },
  ]
}

loki.source.file "k8s_pod_logs" {
  targets    = local.file_match.k8s_pod_logs.targets
  forward_to = [loki.write.local_loki.receiver]
}
```

### Label 建议

建议尽量保持以下 label，方便 Grafana 查询和 AI 分析定位：

```text
env       环境，例如 prod / stage / test / local
host      主机名或节点名
service   服务名，例如 battle-server / gateway / nginx
job       采集任务名
log_type  日志类型，例如 server / access / error / docker / k8s
zone      游戏区服，可选
server_id 游戏服编号，可选
```

常用 LogQL：

```text
{job=~".+"}
{job=~".+"} |~ "(?i)(error|fatal|panic|exception|timeout|failed)"
{service="battle-server", env="prod"} |~ "(?i)(error|timeout|disconnect)"
{service=~"nginx|gateway", log_type=~"access|error"} |~ "(5[0-9][0-9]|upstream|timeout)"
```

## 自动分析 Worker

当前项目已经包含一个最小可运行的后台自动分析 worker，用于定时查询 Loki，发现新的 Windows Event Log 错误/警告后调用 LiteLLM，并把分析结果写回 Loki。

复制配置示例：

```powershell
Copy-Item .\worker\auto-analyzer.env.example .\worker\.env
```

修改 `.\worker\.env` 中的 LiteLLM 配置：

```text
LITELLM_BASE_URL=http://192.168.114.144/v1
LITELLM_API_KEY=sk-...
LITELLM_MODEL=claude-deepseek-v4-pro-agent
```

单次运行：

```powershell
npm run auto-analyze:once
```

持续运行：

```powershell
npm run auto-analyze
```

默认触发查询：

```logql
{job="windows-eventlog"} | json | level <= 3
```

自动分析结果查询：

```logql
{job="ai-log-analysis"}
```

## 生产部署注意事项

自研 Grafana 插件默认没有官方签名，Grafana 生产环境需要显式允许加载该插件。

`grafana.ini` 示例：

```ini
[plugins]
allow_loading_unsigned_plugins = wx-loganalyzer-app
```

环境变量示例：

```powershell
$env:GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS = "wx-loganalyzer-app"
```

正式上线时建议补充内部发布流程，包括版本号、变更记录、构建产物留档、插件签名或白名单审批。

## 后续计划

- 接入 Prometheus 指标，把错误率、延迟、容器重启、资源水位一并交给模型分析。
- 增加日志分析报告模板，输出问题概述、影响范围、关键证据、可能根因、排查步骤、临时处置和长期优化。
- 增加审计记录，只保存调用人、模型、token 用量、摘要和分析结果，不保存原始敏感日志。
