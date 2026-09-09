# mcp-server-devtools

A unified Rust MCP server that connects AI assistants to the developer tools and services they use every day.

One binary exposes 70 tools across Atlassian, CI/CD, observability, collaboration, API development, device management, learning, and financial research platforms. It supports stdio and streamable HTTP, keeps credentials out of tool arguments, and provides bounded output with resumable artifacts for large responses.

## Integrations

| Integration | MCP tools | Authentication |
|---|---|---|
| Bitbucket Cloud | `bb_get`, `bb_post`, `bb_put`, `bb_patch`, `bb_delete`, `bb_clone` | Atlassian API token or Bitbucket app password |
| Jira Cloud | `jira_get`, `jira_get_attachment`, `jira_post`, `jira_put`, `jira_patch`, `jira_delete` | Atlassian API token |
| Confluence Cloud | `conf_get`, `conf_post`, `conf_put`, `conf_patch`, `conf_delete` | Atlassian API token |
| Zoom | `zoom_get`, `zoom_post`, `zoom_put`, `zoom_patch`, `zoom_delete` | Server-to-Server OAuth |
| CircleCI | `circleci_get`, `circleci_logs`, and write verbs | Personal API token |
| Slack | `slack_get`, `slack_post`, and write verbs | Bot or user OAuth token |
| Postman | `postman_get`, `postman_post`, and write verbs | API key |
| edX / Open edX | Six `edx_discussion_*` tools | Bearer token |
| New Relic | `newrelic_query` | User API key |
| Grafana / Loki | `grafana_list_datasources`, `grafana_query_logs` | Service-account token |
| SonarQube / SonarCloud | `sonarqube_quality_gate`, `sonarqube_search_issues`, `sonarqube_get` | User token |
| Splunk | Four `splunk_*` search and job tools | Authentication token |
| NinjaOne | `ninjaone_login`, `ninjaone_get`, and write verbs | Bearer, session, or console credentials |
| WRDS | Four `wrds_*` discovery and query tools | WRDS username and password |

`artifact_read` is shared across integrations and lets stdio clients retrieve large temporary artifacts in resumable base64 chunks. WRDS contributes four of the 70 tools and is enabled by the default `wrds` Cargo feature.

The Bitbucket, Jira, and Confluence behavior is ported from the corresponding [`@aashari` Atlassian MCP servers](https://github.com/aashari). The other integrations are native to this project.

## Install

The administration console and approval workflows are part of the separate
Enterprise edition. See [edition boundary](docs/edition-boundary-proposal.md).

Download a prebuilt archive from [GitHub Releases](https://github.com/huskercane/mcp-server-devtools/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86-64 | `mcp-devtools-linux-x86_64.tar.gz` |
| macOS Intel | `mcp-devtools-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `mcp-devtools-macos-aarch64.tar.gz` |
| Windows x86-64 | `mcp-devtools-windows-x86_64.zip` |

Each archive has a `.sha256` checksum. On macOS, an unsigned download may need its quarantine attribute removed:

```bash
xattr -d com.apple.quarantine ./mcp-devtools
```

To build from source (Rust 1.96 or later):

```bash
git clone https://github.com/huskercane/mcp-server-devtools.git
cd mcp-server-devtools
cargo build --release
```

The binary is written to `target/release/mcp-devtools`. For a headless build without the desktop keychain or WRDS dependencies:

```bash
cargo build --release --no-default-features
```

## Configure

Only configure the integrations you use. Missing credentials are checked when a corresponding tool is called, so unrelated integrations do not prevent startup.

Configuration is resolved in this order:

1. Process environment
2. `.env` in the working directory
3. Vendor sections in `~/.mcp/configs.json`

The [complete configuration reference](docs/configuration.md) lists every supported setting, its scope, and its default. Common integration settings are:

| Integration | Required or commonly used settings |
|---|---|
| Atlassian | `ATLASSIAN_USER_EMAIL`, `ATLASSIAN_API_TOKEN`, `ATLASSIAN_SITE_NAME` for Jira/Confluence, `BITBUCKET_DEFAULT_WORKSPACE` optionally |
| Zoom | `ZOOM_ACCOUNT_ID`, `ZOOM_CLIENT_ID`, `ZOOM_CLIENT_SECRET` |
| CircleCI | `CIRCLECI_TOKEN` |
| Slack | `SLACK_TOKEN` |
| Postman | `POSTMAN_API_KEY` |
| edX | `EDX_ACCESS_TOKEN`, optional `EDX_API_BASE` |
| New Relic | `NEW_RELIC_API_KEY`, optional `NEW_RELIC_REGION=eu` |
| Grafana | `GRAFANA_URL`, `GRAFANA_TOKEN` |
| SonarQube | `SONARQUBE_URL`, `SONARQUBE_TOKEN` |
| Splunk | `SPLUNK_URL`, `SPLUNK_TOKEN`, optional `SPLUNK_AUTH_SCHEME=splunk` for legacy session keys |
| NinjaOne | `NINJAONE_URL` or `NINJAONE_SERVERS`, plus one supported credential set |
| WRDS | `WRDS_USERNAME`, `WRDS_PASSWORD`; host, port, and database have cloud defaults |

Every MCP tool call is also written to a structured audit log under
`~/.mcp/data`. Audit files are JSONL and contain the tool name, request/client
identity, outcome, duration, and HTTP-cache hit/miss counters, but never
arguments, credentials, URLs, cache contents, or response content. Cache keys
are represented by short one-way fingerprints so repeated lookups can be
correlated safely. Cache events also include the admission action, TTL, age,
remaining TTL, response and stored sizes, compression state, upstream latency,
and cumulative hit/miss totals. Those observations are suitable for evaluating
future cache-admission or TTL bandits offline. Each process keeps at most five
10 MiB segments by default and prunes
prior-session audit data after 30 days or when it exceeds 100 MiB. Configure
this with `AUDIT_LOG_MAX_BYTES`, `AUDIT_LOG_MAX_FILES`,
`AUDIT_LOG_RETENTION_DAYS`, and `AUDIT_LOG_RETENTION_MAX_BYTES`; set
`AUDIT_LOG=off` to disable it explicitly. Audit logging is independent of
`RUST_LOG` and `LOG_STDERR`; file writes, flushes, retention, and rotation run
off the request path on background workers, and clean shutdown drains queued
records.

Example `.env` for Atlassian:

```dotenv
ATLASSIAN_USER_EMAIL=you@example.com
ATLASSIAN_API_TOKEN=ATATT...
ATLASSIAN_SITE_NAME=mycompany
BITBUCKET_DEFAULT_WORKSPACE=my-workspace
```

Example vendor-scoped global config:

```json
{
  "jira": {
    "environments": {
      "ATLASSIAN_USER_EMAIL": "you@example.com",
      "ATLASSIAN_API_TOKEN": "keychain",
      "ATLASSIAN_SITE_NAME": "mycompany"
    }
  },
  "circleci": {
    "environments": {
      "CIRCLECI_TOKEN": "keychain"
    }
  }
}
```

The supported filename is `~/.mcp/configs.json` (not `~/.mcp/mcp.json`). A [complete sample](examples/configs.json) covers every integration. Copy it, then remove integrations you do not use and replace its placeholders:

```bash
mkdir -p ~/.mcp
cp examples/configs.json ~/.mcp/configs.json
```

The server watches the global config and reloads changes without a restart. Startup settings such as `TRANSPORT_MODE`, `PORT`, and logging/audit controls must be process environment variables; see the reference for the exact source boundaries.

### Store secrets in the OS keychain

Desktop builds can store every registered vendor secret in macOS Keychain, Windows Credential Manager, or the Linux keyring. The safest starting point is to migrate plaintext secrets already present in `~/.mcp/configs.json`:

```bash
mcp-devtools creds migrate
```

Migration creates a backup, writes each secret to its vendor-scoped keychain slot, and replaces the config value with `"keychain"`. You can also manage a slot directly:

```bash
mcp-devtools creds set --kind SLACK_TOKEN --vendor slack --principal SLACK_TOKEN
mcp-devtools creds get --kind SLACK_TOKEN --vendor slack --principal SLACK_TOKEN
mcp-devtools creds rm  --kind SLACK_TOKEN --vendor slack --principal SLACK_TOKEN
```

Run `mcp-devtools creds --help` for all supported kinds and vendors. New entries use the `mcp-server-devtools.*` service prefix; reads fall back to the former `mcp-server-atlassian.*` prefix so existing credentials remain usable after the rename.

### Upgrading from mcp-server-atlassian

Replace `mcp-atlassian` with `mcp-devtools` in MCP client commands and executable paths. Existing global config sections under `@huskercane/mcp-server-atlassian` or `mcp-server-atlassian`, and existing keychain entries with the old service prefix, remain readable as compatibility fallbacks. New configuration and credentials use the `mcp-server-devtools` identifiers.

## Connect an MCP client

stdio is the default transport. Point your client at the absolute path to `mcp-devtools` and provide configuration either in the client or through the sources above.

### Codex

```bash
codex mcp add devtools \
  --env ATLASSIAN_USER_EMAIL=you@example.com \
  --env ATLASSIAN_API_TOKEN=ATATT... \
  --env ATLASSIAN_SITE_NAME=mycompany \
  -- /absolute/path/to/mcp-devtools
```

Or add it to `~/.codex/config.toml`:

```toml
[mcp_servers.devtools]
command = "/absolute/path/to/mcp-devtools"

[mcp_servers.devtools.env]
ATLASSIAN_USER_EMAIL = "you@example.com"
ATLASSIAN_API_TOKEN = "ATATT..."
ATLASSIAN_SITE_NAME = "mycompany"
```

### Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "devtools": {
      "command": "/absolute/path/to/mcp-devtools",
      "env": {
        "ATLASSIAN_USER_EMAIL": "you@example.com",
        "ATLASSIAN_API_TOKEN": "ATATT...",
        "ATLASSIAN_SITE_NAME": "mycompany"
      }
    }
  }
}
```

Restart Claude Desktop after changing its configuration.

### Streamable HTTP

```bash
TRANSPORT_MODE=http PORT=3000 ./mcp-devtools
```

Use `http://127.0.0.1:3000/mcp` as the MCP endpoint. `GET /` returns a health response. The server binds to loopback, enforces a local-origin allowlist and a 1 MiB request-body limit, and supports resumable downloads at `/artifacts/{artifactId}`.

## Tool behavior

The REST-style tools accept a relative `path`, optional `queryParams`, optional `jq` JMESPath projection, and `outputFormat` (`toon` by default or `json`). Bitbucket automatically prefixes `/2.0`; Jira, Confluence, and the other REST integrations use their documented API-relative paths.

Specialized tools use typed inputs:

- `circleci_logs` can select failed steps, condense output, and spill large logs to a resumable artifact.
- `edx_discussion_*` provides typed course, topic, thread, comment, and create operations.
- `newrelic_query` accepts a NerdGraph query and variables.
- `grafana_query_logs` runs LogQL through a configured Loki datasource.
- `sonarqube_quality_gate` can resolve the `ceTaskId` printed by CI scanners.
- `splunk_*` supports bounded export searches and asynchronous jobs.
- `ninjaone_*` only sends credentials to configured server aliases, never a caller-supplied host.
- `wrds_query` accepts one read-only `SELECT` or `VALUES` query and applies a row limit.

Tool schemas include read-only, idempotent, and destructive annotations so compatible MCP clients can apply appropriate confirmation policies.

## Command-line API

The command line directly exposes Atlassian REST operations and credential management:

```bash
mcp-devtools bb get --path /workspaces
mcp-devtools jira get --path /rest/api/3/myself
mcp-devtools conf get --path /wiki/api/v2/spaces
mcp-devtools creds --help
```

Use `--query-params`, `--body`, `--jq`, and `--output-format toon|json` as appropriate. Run `mcp-devtools --help` or a subcommand's `--help` for the authoritative option list. Other integrations are exposed through MCP rather than dedicated CLI groups.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Before opening a PR, run the response-pipeline performance probe as well as the correctness checks:

```bash
cargo bench --bench response_pipeline
```

This prints per-stage allocation bytes, allocation counts, timing, and output-size comparisons. For changes on a hot path, run it on the base branch and the PR branch using the same machine and build profile. Allocation counts should not increase; treat small timing changes as noise unless they repeat across several runs.

When profiling the TOON encoder itself, build and run its sustained workload, which lasts 12 seconds by default:

```bash
cargo bench --bench toon_encode_loop
```

Attach Instruments, `sample`, or `samply` to that workload when call-stack data is needed. These are manual profiling probes rather than pass/fail CI benchmarks.

CI builds and tests the default and headless feature sets across Linux, macOS, and Windows. Releases publish checksummed archives for all supported targets.

## CircleCI deployment monitoring

CircleCI deployment monitoring always fetches pipeline, workflow, and job status
paths upstream, including discovery lists and terminal states. Other CircleCI
GETs can use the configured HTTP cache; top-level `fresh: true` bypasses lookup
and storage and removes the previous entry without adding upstream query parameters.
`circleci_get` returns `{data, cache}` (also in TOON): `jq` filters `data` before
wrapping; `cache.hit`, `cache.ageMs`, and `cache.fetchedAt` expose local reuse,
residence age, and the original UTC fetch timestamp. Poll workflow/job status
until completion; pipeline creation alone does not establish deployment success.
See the [tool documentation](src/tools/descriptions/circleci_get.md) and
[incident investigation](docs/circleci-status-freshness.md).

## License

The community edition is licensed under [Apache-2.0](LICENSE). Commercial use,
including internal business use, modification, and redistribution are permitted
under that license. See [NOTICE](NOTICE) for attribution and the
[licensing policy](docs/licensing.md) for the community/enterprise boundary and
the treatment of earlier ISC-licensed versions.

Build profiles and local validation commands: [build performance](docs/build-performance.md).

### Jira screenshots

List image attachments with `jira_get` using path `/rest/api/3/issue/{issueKey}`, `queryParams: {"fields":"attachment"}`, and `jq: "fields.attachment[*].{id:id,filename:filename,mimeType:mimeType,size:size}"`. Then call `jira_get_attachment` with `{"attachmentId":"493334"}` (substitute the selected ID).

The attachment tool returns an MCP image block with lossless base64 data, supporting PNG, JPEG, GIF, and WebP up to 5 MiB. Use numeric attachment IDs, not media UUIDs or `blob:` links from rendered comments. `jira_get` remains a text/JSON tool and must not be used to download image bytes.

Downloads use Jira's [attachment content endpoint](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-attachments/) with `redirect=false` and the configured Jira credentials. Non-image and oversized attachments return errors. Rebuild and restart the MCP server, then refresh the client's tool list to expose the new tool.
