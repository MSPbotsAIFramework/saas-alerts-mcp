# SaaS Alerts MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [SaaS Alerts](https://saasalerts.com)
partner API. SaaS Alerts monitors an MSP's customers' Microsoft 365, Google Workspace,
Salesforce and Dropbox tenants and raises security events (failed and foreign logins, external
file sharing, OAuth grants, admin changes). This server lets an AI agent query and count those
events, run Elasticsearch searches over them, list customers, users, devices, billing and
scheduled reports and, on explicit request, manage customers, whitelists, scheduled reports and
report branding.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: the API key arrives on every request as an HTTP header and is
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-SaaS-Alerts-API-Key` | Yes | string | none | - | SaaS Alerts partner API key | `your-saas-alerts-api-key` |

Where to get it: a SaaS Alerts partner administrator generates an API key in the SaaS Alerts
partner portal. The key acts on the whole partner account (all customers).

How the key is sent to SaaS Alerts: in the `api_key` header of every call to
`https://us-central1-the-byway-248217.cloudfunctions.net/reportApi/api/v1/...`, the API
address published in the SaaS Alerts API reference.

A request to `/mcp` without the key gets HTTP 401.

## Tools

All tools return a JSON string. Event tools return triage fields only (time, type, severity,
description, user, customer, product, IP, location) unless `verbose: true` is passed.

Paging: `saas_alerts_events_query` returns `{events, count, has_more, next_from}` (also with `verbose`);
pass `next_from` as `from` to continue; the API gives no total, use `saas_alerts_events_count`. Lists the
API returns in full (customers, partner and customer users, scheduled reports, device organizations and
the mapped / unmapped / ignored devices, recommended actions) take `offset` / `limit` and return
`next_offset`. When a result is cut to fit the 20,000-character limit, `next_from` / `next_offset` start
right after the last record returned. Elasticsearch results (`events_query_advanced`, `events_scroll`)
that are cut leave out `_scroll_id`, which would skip the rest: run the search again with a smaller
`size`. `saas_alerts_recommended_actions` returns one record per event type; pass `event_type` for one.

| Tool | Purpose | Parameters (required in **bold**) |
|---|---|---|
| `saas_alerts_navigate` | Describe the tools of one area (changes nothing) | **domain** (`events`, `customers`, `users`, `devices`, `billing`, `reports`, `partner`) |
| `saas_alerts_status` | Check the connection (the key works) and list the areas | - |
| `saas_alerts_events_query` | Query events by filters | customer_id, alert_status (`critical`/`medium`/`low`), event_type [..], user_email, start_date, end_date, size (default 50), from, time_sort, verbose |
| `saas_alerts_events_count` | Count events by filters | customer_id, alert_status, event_type [..], start_date, end_date |
| `saas_alerts_events_query_advanced` | Elasticsearch search over events | **query** (search body), scroll, verbose |
| `saas_alerts_events_count_advanced` | Count events matching an Elasticsearch query | **query** |
| `saas_alerts_events_scroll` | Next page of a scrolled search | **scroll_id**, scroll (default `1m`), verbose |
| `saas_alerts_recommended_actions` | Recommended response per event type | event_type, offset, limit |
| `saas_alerts_customers_list` | List customers | offset, limit |
| `saas_alerts_customers_get` | One customer | **customer_id** |
| `saas_alerts_customers_create` | Create a customer (**write**) | **body** {**name**, email} |
| `saas_alerts_customers_update` | Change a customer's name / email (**write**) | **customer_id**, **body** {name, email} |
| `saas_alerts_customers_delete` | Delete a customer (**write**, needs `confirm: true`) | **customer_id**, confirm |
| `saas_alerts_customers_set_whitelists` | Replace a customer's whitelist (**write**) | **customer_id**, **body** {inheritanceWl, asnList, ipRanges, countries} |
| `saas_alerts_customers_set_account_whitelists` | Replace a customer's account-level whitelist (**write**) | **customer_id**, **body** (as above) |
| `saas_alerts_users_get_msp` | The MSP user the key belongs to | - |
| `saas_alerts_users_list_partner` | The partner's own users | - |
| `saas_alerts_users_list_by_customer` | A customer's monitored accounts | **customer_id** |
| `saas_alerts_devices_list_orgs` | Device organizations | - |
| `saas_alerts_devices_list_mapped` | Devices mapped to accounts | **organization_ids** [..] |
| `saas_alerts_devices_list_unmapped` | Devices not mapped, with suggestions | **organization_ids** [..], confidence (0-1, default 0) |
| `saas_alerts_devices_list_ignored` | Devices excluded from mapping | **organization_ids** [..] |
| `saas_alerts_billing_list_dates` | Billing periods | - |
| `saas_alerts_billing_get_details` | Billing details of one period | **billing_date** |
| `saas_alerts_reports_list_scheduled` | Scheduled reports | - |
| `saas_alerts_reports_get_scheduled` | One scheduled report | **report_id** |
| `saas_alerts_reports_create_scheduled` | Schedule a report (**write**) | **body** {reportName, reportId, customerName, frequency, recipients {to, cc, bcc}, branding, metadata} |
| `saas_alerts_reports_delete_scheduled` | Delete a scheduled report (**write**, needs `confirm: true`) | **report_id**, confirm |
| `saas_alerts_partner_get_profile` | The partner profile | - |
| `saas_alerts_partner_update_branding` | Replace report branding (**write**) | **body** {display, color, logo, reportOptions {hideSaasAlertsCoBranding}} |

`start_date` / `end_date` take ISO 8601 or epoch milliseconds and are sent as ISO 8601 UTC.
Body objects are checked against the fields the API documents; an unknown field is rejected
with `invalid_argument` before anything is sent.

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "SaaS Alerts returned HTTP 401 for customers: Unauthorized", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Reads are retried with backoff on 429, 5xx and network
errors; writes are retried only on 429.

## Run locally

```bash
uv sync
uv run python -m saas_alerts_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t saas-alerts-mcp:dev .
docker run --rm -p 8080:8080 saas-alerts-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). The key is never read from the
environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-SaaS-Alerts-API-Key: your-saas-alerts-api-key" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# critical events of the last day
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-SaaS-Alerts-API-Key: your-saas-alerts-api-key" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"saas_alerts_events_query","arguments":{"alert_status":"critical","start_date":"2026-01-01T00:00:00Z","size":20}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (30).** Kept as is because the tool names are an existing contract.
- **API contract.** Requests follow the SaaS Alerts API reference (version 3.362.0). Event
  filters map to the API's `customerId`, `alertStatus`, repeated `eventType`, `userEmail`,
  `start` / `end`, `from`, `size` and `timeSort` query parameters.
- **Elasticsearch tools.** `query` is the search body itself (the API wraps it as `body`).
  `saas_alerts_events_query_advanced` accepts an optional `scroll` lifetime so the response
  carries a `_scroll_id` for `saas_alerts_events_scroll`, which sends the API's required scroll
  lifetime (default `1m`).
- **Devices.** The API requires a `confidence` value for unmapped devices; it defaults to 0
  (all suggestions). The former `only_with_suggestions` flag had no API parameter and was
  removed.
- **Billing.** `billing_date` is sent as the `billingDate` query parameter, which the API
  reference does not list; use a value returned by `saas_alerts_billing_list_dates`.
- **Writes.** Whitelist and branding tools replace the current settings and are annotated as
  destructive. Deletes need `confirm: true`.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
