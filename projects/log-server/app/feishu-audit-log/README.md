# Feishu Audit Log Fetcher

This folder contains a small Node.js program for requesting Feishu behavior audit logs.

The script calls:

```text
GET https://open.feishu.cn/open-apis/admin/v1/audit_infos
```

Required Feishu permission:

```text
admin:audit_info:readonly
```

## Usage

Copy `.env.example` to `.env`, then fill either:

- `FEISHU_TENANT_ACCESS_TOKEN`
- or `FEISHU_APP_ID` and `FEISHU_APP_SECRET`

Run:

```bash
node app/feishu-audit-log/fetch-audit-logs.cjs --last-minutes 60
```

Write JSON Lines:

```bash
node app/feishu-audit-log/fetch-audit-logs.cjs --last-minutes 60 --output logs/feishu-audit.jsonl
```

Use explicit time range. `oldest` and `latest` are Unix timestamps in seconds:

```bash
node app/feishu-audit-log/fetch-audit-logs.cjs --oldest 1718500000 --latest 1718503600
```

Filter examples:

```bash
node app/feishu-audit-log/fetch-audit-logs.cjs --event-name space_edit_doc
node app/feishu-audit-log/fetch-audit-logs.cjs --operator-type user --operator-value ou_xxx
node app/feishu-audit-log/fetch-audit-logs.cjs --object-type 106 --object-value doc_xxx
```

The output is normalized JSON Lines by default. Use `--raw` to keep the raw Feishu item.
