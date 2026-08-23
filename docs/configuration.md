# Configuration reference

Configure only the integrations you use. Missing integration settings are reported when one of that integration's tools is called and do not prevent the server from starting.

## Configuration sources

Integration, HTTP-cache, request-timeout, and streaming settings use this priority order (highest first):

1. Process environment variables
2. `.env` in the server's working directory
3. Vendor sections in `~/.mcp/configs.json`

The supported global filename is `configs.json`; `~/.mcp/mcp.json` is not read. The global file is watched and reloaded while the server is running. Values in process environment variables and `.env` are shared by all integrations. Values in the global file are isolated to their vendor section.

A complete copy-ready example is available at [`examples/configs.json`](../examples/configs.json). Its secret values use the `"keychain"` sentinel; either store those credentials with `mcp-devtools creds set`, run `mcp-devtools creds migrate` on an existing plaintext config, or replace the sentinel with the credential value.

The global file has this shape:

```json
{
  "jira": {
    "environments": {
      "ATLASSIAN_USER_EMAIL": "you@example.com",
      "ATLASSIAN_API_TOKEN": "keychain",
      "ATLASSIAN_SITE_NAME": "mycompany"
    }
  }
}
```

Recognized section names are `bitbucket`, `jira`, `confluence`, `zoom`, `circleci`, `slack`, `postman`, `edx`, `newrelic`, `grafana`, `sonarqube`, `splunk`, `ninjaone`, and `wrds`.

## Integration settings

| Section | Setting | Required/default | Purpose |
|---|---|---|---|
| `bitbucket` | `ATLASSIAN_USER_EMAIL` | Required with API token | Atlassian account email. |
| `bitbucket` | `ATLASSIAN_API_TOKEN` | Required with account email | Atlassian API token; preferred when both Bitbucket credential forms are configured. |
| `bitbucket` | `ATLASSIAN_BITBUCKET_USERNAME` | Alternative | Bitbucket username for app-password authentication. |
| `bitbucket` | `ATLASSIAN_BITBUCKET_APP_PASSWORD` | Alternative | Bitbucket app password. |
| `bitbucket` | `BITBUCKET_DEFAULT_WORKSPACE` | Optional | Default workspace used when a tool does not receive one. |
| `jira`, `confluence` | `ATLASSIAN_USER_EMAIL` | Required | Atlassian account email. |
| `jira`, `confluence` | `ATLASSIAN_API_TOKEN` | Required | Atlassian API token. |
| `jira`, `confluence` | `ATLASSIAN_SITE_NAME` | Required | Site prefix, for example `mycompany` for `mycompany.atlassian.net`. Jira and Confluence may share this value. |
| `zoom` | `ZOOM_ACCOUNT_ID` | Required | Server-to-Server OAuth account ID. |
| `zoom` | `ZOOM_CLIENT_ID` | Required | Server-to-Server OAuth client ID. |
| `zoom` | `ZOOM_CLIENT_SECRET` | Required | Server-to-Server OAuth client secret. |
| `circleci` | `CIRCLECI_TOKEN` | Required | Personal API token. |
| `slack` | `SLACK_TOKEN` | Required | Bot or user OAuth token. |
| `postman` | `POSTMAN_API_KEY` | Required | Postman API key. |
| `edx` | `EDX_ACCESS_TOKEN` | Required | edX/Open edX bearer token. |
| `edx` | `EDX_API_BASE` | `https://courses.edx.org` | LMS base URL for an Open edX instance. |
| `newrelic` | `NEW_RELIC_API_KEY` | Required | New Relic User API key. |
| `newrelic` | `NEW_RELIC_REGION` | `us` | Set to `eu` for EU accounts; other values select the US endpoint. |
| `newrelic` | `NEW_RELIC_API_BASE` | Optional | Explicit NerdGraph base URL; overrides the region. |
| `grafana` | `GRAFANA_URL` | Required | Grafana Cloud or self-hosted base URL. |
| `grafana` | `GRAFANA_TOKEN` | Required | Grafana service-account token. |
| `sonarqube` | `SONARQUBE_URL` | Required | SonarQube base URL, or `https://sonarcloud.io`. |
| `sonarqube` | `SONARQUBE_TOKEN` | Required | SonarQube/SonarCloud user token. |
| `splunk` | `SPLUNK_URL` | Required | Splunk management API base URL. |
| `splunk` | `SPLUNK_TOKEN` | Required | Splunk authentication token. |
| `splunk` | `SPLUNK_AUTH_SCHEME` | `Bearer` | Set to `splunk` for a legacy Splunk session key. |
| `ninjaone` | `NINJAONE_URL` | Required without server aliases | Base URL for a single server. |
| `ninjaone` | `NINJAONE_SERVERS` | Alternative | JSON object of named server URLs or server objects; see below. |
| `ninjaone` | `NINJAONE_ACCESS_TOKEN` | One authentication form | Public v2 API bearer token. |
| `ninjaone` | `NINJAONE_SESSION_KEY` | One authentication form | Legacy console session-key header. |
| `ninjaone` | `NINJAONE_SESSION_COOKIE` | One authentication form | Console `sessionKey` cookie. |
| `ninjaone` | `NINJAONE_EMAIL` | Required for login flow | Console account email. |
| `ninjaone` | `NINJAONE_PASSWORD` | Required for login flow | Console account password. |
| `ninjaone` | `NINJAONE_TOTP_COMMAND` | Optional | Command that returns a current MFA code. |
| `ninjaone` | `NINJAONE_TOTP_SECRET` | Optional | Base32 seed or `otpauth://` URI used to generate MFA codes. |
| `wrds` | `WRDS_USERNAME` | Required | WRDS username. |
| `wrds` | `WRDS_PASSWORD` | Required | WRDS password. |
| `wrds` | `WRDS_HOST` | `wrds-pgdata.wharton.upenn.edu` | PostgreSQL host. |
| `wrds` | `WRDS_PORT` | `9737` | PostgreSQL port. |
| `wrds` | `WRDS_DBNAME` | `wrds` | PostgreSQL database. |
| `wrds` | `WRDS_SSLMODE` | `require` | `require`, `prefer`, or `disable`. |

`NINJAONE_SERVERS` is itself a JSON string when placed in `.env` or the `environments` object. Each alias can be a URL or an object with required `url` and optional `prefix`, `email`, `password`, `totpCommand`, and `totpSecret` fields:

```dotenv
NINJAONE_SERVERS={"production":{"url":"https://app.ninjarmm.com","email":"you@example.com","password":"keychain","totpSecret":"keychain"},"sandbox":"https://sandbox.example.com"}
```

## Shared request, cache, and streaming settings

These settings use the same three-source cascade. When placed in `configs.json`, define a setting in only one vendor section or give it the same value in every section that defines it; conflicting values are intentionally treated as ambiguous.

| Setting | Default/valid range | Purpose |
|---|---|---|
| `ATLASSIAN_REQUEST_TIMEOUT` | `30000` ms; positive integer | Shared upstream HTTP request timeout. Despite the historical name, it applies to the shared HTTP transport. |
| `HTTP_CACHE_ENABLED` | `false` | Enables the bounded in-process cache for successful upstream reads. |
| `HTTP_CACHE_DEFAULT_TTL_SECONDS` | `60`; positive integer | TTL used when the upstream response provides no usable cache lifetime. |
| `HTTP_CACHE_MAX_TTL_SECONDS` | `3600`; positive integer | Maximum admitted TTL. |
| `HTTP_CACHE_MAX_ENTRIES` | `512`; positive integer | Maximum cached response count. |
| `HTTP_CACHE_MAX_BYTES` | `67108864` (64 MiB); positive integer | Maximum stored cache bytes. |
| `HTTP_CACHE_COMPRESSION_THRESHOLD_BYTES` | `16384` (16 KiB); positive integer | Minimum response size considered for compression. |
| `STREAMING_PARTITION_CONCURRENCY` | `4`; `1`–`16` | Maximum concurrent time-partition requests. |
| `STREAMING_ARTIFACT_RETENTION_SECONDS` | `3600`; clamped to `300`–`604800` | How long completed download artifacts remain readable. |
| `STREAMING_ARTIFACT_SWEEP_INTERVAL_SECONDS` | `60`; clamped to `5`–`3600` | Interval between expired-artifact sweeps. |

## Process-only runtime settings

These are read directly from the process environment during startup. They do **not** take effect in `.env` or `~/.mcp/configs.json`; set them in the shell, service definition, or MCP client's `env` object.

| Setting | Default | Purpose |
|---|---|---|
| `TRANSPORT_MODE` | `stdio` | `stdio` or `http`; unknown values log a warning and use stdio. |
| `PORT` | `3000` | Port for HTTP mode. The server binds to `127.0.0.1`. |
| `RUST_LOG` | `info,mcp_server_devtools=debug` | Tracing filter. A valid non-empty value overrides `DEBUG`. |
| `DEBUG` | unset | Exact value `true` or `1` selects the `debug` filter when `RUST_LOG` is absent. |
| `LOG_STDERR` | enabled | `off`, `false`, `0`, or `no` disables console logging; the diagnostic file remains enabled. |
| `AUDIT_LOG` | enabled | `off`, `false`, `0`, or `no` disables structured audit logging. |
| `AUDIT_LOG_MAX_BYTES` | `10485760` (10 MiB) | Maximum bytes per audit segment. |
| `AUDIT_LOG_MAX_FILES` | `5` | Maximum segments retained by the current process. |
| `AUDIT_LOG_RETENTION_DAYS` | `30` | Age limit for prior-session audit logs. |
| `AUDIT_LOG_RETENTION_MAX_BYTES` | `104857600` (100 MiB) | Total size limit for prior-session audit logs. |

Diagnostic and audit logs are written below `~/.mcp/data`. Diagnostic log retention is fixed at seven days and 50 MiB; audit retention is configurable as shown above.

