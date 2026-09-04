# Usage rollups and metrics runbook

Usage is operational telemetry, not audit evidence. A tool call never waits
for the usage pipeline: `UsageSink::record` updates enabled in-process metrics
and attempts a non-blocking send to a bounded channel. The durable audit
journal remains the source of truth if a usage row is dropped.

## Recommended single-replica configuration

Run the `all` role with a persistent volume and configure:

```text
MCP_ROLLUP_STORE=sqlite:///var/lib/mcp-devtools/usage.db
MCP_ROLLUP_RETENTION_DAYS=90
MCP_USAGE_CHANNEL_CAPACITY=4096
MCP_METRICS=on
MCP_RATE_LIMIT_PER_PRINCIPAL=10
MCP_RATE_LIMIT_BURST=20
```

The SQLite adapter is embedded in the binary. It uses WAL mode,
`synchronous=NORMAL`, and forward-only migrations recorded in
`PRAGMA user_version`; a database created by a newer binary is refused rather
than downgraded. Back up the database as a SQLite database, including a
consistent WAL checkpoint or SQLite's backup mechanism—not by copying only
the main file while it is live. C.7 supplies the supported combined
backup/restore workflow.

`memory://` exists for tests and local development. `postgres://` is reserved
and produces a startup error until a partner requires that adapter. Relative
SQLite paths are refused so a changed working directory cannot move usage.

## What is collected

Each row contains timestamp, tenant, subject, vendor, environment, tool,
policy decision, request risk, outcome, and duration. It contains no tool
arguments, response content, token, or credential. Retention defaults to 90
days; set `MCP_ROLLUP_RETENTION_DAYS=0` only when an external retention policy
explicitly owns deletion.

The fixed reports are totals, by principal, by vendor, by tool, denials by
environment, and hourly/daily timelines. C.4 exposes these through the admin
API; SQL is not an API and must not be coupled to by operators.

## Prometheus

`MCP_METRICS=on` exposes `GET /metrics` in Prometheus text format. The route is
unauthenticated so a cluster scraper can use it; do not expose it through the
public ingress. Usage series are labelled only by vendor, tool, decision, and
outcome. Subjects and tenants appear only in the protected rollup reports.

Alert on:

- `mcp_rollups_degraded == 1`: store writes are failing; the consumer retries
  with backoff and health says usage may be dropped.
- increasing `mcp_usage_events_dropped_total`: the bounded channel is full or
  closed. Check store latency/errors before raising the capacity.
- increasing `mcp_rate_limited_total`: validated principals are receiving 429
  responses.
- `mcp_audit_journal_available == 0`: unlike usage loss, this is a fail-closed
  evidence-path incident and tool calls are refused.

The channel capacity is clamped to 64–65,536. Raising it absorbs a short
outage but consumes memory and does not repair a persistently failing store.

## Rate limiting and topology

The token bucket keys on the validated subject after the required-scope check.
Unauthenticated traffic cannot spend another principal's budget. A refusal is
HTTP 429 with an integer `Retry-After` header.

The limiter and its counters are in-process. The supported C.6 deployment is
one gateway replica; several replicas would each grant a separate budget
(CF-16). Likewise, a pure `gateway` role does not attach a rollup channel,
because C.6 has no gateway-to-control usage transport. In a split topology the
control database receives no gateway usage yet (CF-33). Run `MCP_ROLE=all` for
complete rollups until those two scaling items land.
