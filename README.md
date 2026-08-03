# Ops

这个仓库用于整理运维、日志、AI 分析、插件开发相关的项目代码、脚本、配置模板和排障笔记。

它不是单一服务仓库，而是一个长期维护的 ops 工作库。不同项目按目录归档，共用同一套 Git 历史。

## 目录约定

```text
ops/
├─ projects/   可部署项目或完整工程
├─ plugins/    插件类项目或插件源码
├─ scripts/    通用脚本、一次性工具和自动化片段
├─ configs/    配置模板、示例配置
├─ notes/      排障记录、部署笔记、设计说明
└─ assets/     图片、架构图、截图等辅助资料
```

## 当前内容

- `projects/log-server/`：Grafana + Loki + Alloy + AI Log Analyzer worker 的日志采集、查询、AI 分析和告警推送部署包。

## 安全约定

- 不提交真实 `.env`、token、密钥、证书、运行日志和数据目录。
- 只提交 `.env.example`、模板配置和脱敏后的说明文档。
- 新增项目时优先补充项目自己的 `README.md`，说明用途、启动方式、配置项和注意事项。

