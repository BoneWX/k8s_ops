# 网络设备日志接入说明

本文用于内网 Ubuntu 日志服务器第一阶段接入交换机、路由器、防火墙等网络设备日志。

## 目标目录

先从宿主机目录开始：

```bash
/data/logs/network
```

建议后续按类型扩展：

```text
/data/logs/network   交换机、路由器、防火墙、负载均衡
/data/logs/security  安全设备、WAF、IDS、EDR
/data/logs/system    Linux 系统与中间件
/data/logs/app       应用服务日志
```

## 服务器配置

在 `/opt/log-server/.env` 中确认：

```bash
HOST_LOG_DIR=/data/logs
```

目录准备：

```bash
sudo mkdir -p /data/logs/network
sudo chown -R root:root /data/logs
sudo chmod -R a+rX /data/logs
```

Alloy 容器会把 `/data/logs` 挂载到容器内 `/var/log/central`。其中 `/data/logs/network` 会单独采集为：

```logql
{job="network-syslog", source_type="network", ingest_type="file"}
```

## 录入策略

交换机写过来的 information 级别日志先全量入 Loki，便于回溯。

AI 自动分析不逐条分析全部 information 日志，只筛选以下风险事件：

- 接口 down / updown / flap
- STP、OSPF、BGP、ISIS 等协议异常
- ACL deny / denied / blocked
- timeout / failed / reset / refused
- CRC、discard、drop、threshold
- auth、login、logout 等认证变更
- attack、malware、critical、warning

worker 触发查询：

```logql
{job="network-syslog"} |~ "(?i)(error|fail|failed|deny|denied|timeout|down|link[ -]?down|interface.*down|updown|flap|mac.*flap|loop|stp|ospf|bgp|isis|attack|blocked|malware|auth|login|logout|threshold|crc|discard|drop|critical|warning|warn)"
```

上下文查询：

```logql
{job="network-syslog"}
```

## 测试步骤

写入一条测试日志：

```bash
echo "Jun 10 10:00:00 sw-core-01 %%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1 changed state to DOWN" \
  | sudo tee -a /data/logs/network/switch-test.log
```

重启 Alloy：

```bash
cd /opt/log-server
bash scripts/update.sh alloy
```

Grafana Explore 查询：

```logql
{job="network-syslog"}
```

触发一次 AI 自动分析：

```bash
bash scripts/worker-once.sh
```

查看 AI 写回结果：

```logql
{job="ai-log-analysis", source_job="network-syslog"}
```

## 设备直接发 Syslog

如果后续设备可以直接发 syslog，不经过文件落盘，也可以发到日志服务器：

```text
日志服务器IP:1514/tcp
日志服务器IP:1514/udp
```

直接 syslog 和 `/data/logs/network` 文件采集都会进入同一个 job：

```logql
{job="network-syslog"}
```

差异可以用 `ingest_type` 和 `transport` 标签区分：

```logql
{job="network-syslog", ingest_type="file"}
{job="network-syslog", transport="udp"}
{job="network-syslog", transport="tcp"}
```
