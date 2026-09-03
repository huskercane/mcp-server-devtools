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

## Enterprise mode (opt-in)

Everything in this section is off by default, and with it off the server
behaves byte-for-byte as before it existed (`tests/auth_mode_tests.rs` locks
that). It is the configuration surface of the enterprise plan
(`docs/enterprise-product-plan.md`, Phase A). Startup is **fail-closed**: an
incomplete or contradictory enterprise configuration refuses to start with a
reason, never falls back to local mode.

Unless noted, these settings use the same three-source cascade as the
integration settings, so they may live in the environment, `.env`, or a
`configs.json` section.

| Setting | Default | Purpose |
|---|---|---|
| `MCP_ROLE` | `all` | Process env only (or `serve --role`). `all`, `gateway`, or `control` (plan ADR-010). `control` serves only the health banner in Phase A. |
| `MCP_AUTH_MODE` | `off` | `off` or `okta`. `okta` requires an HTTP transport, a non-loopback-safe configuration below, a policy, and a journal. Any other value is refused. |
| `MCP_BIND_ADDR` | `127.0.0.1` | Process env only. IP or `ip:port`. A non-loopback bind is refused unless `MCP_AUTH_MODE=okta`. |
| `MCP_PUBLIC_URL` | — (required for `okta`) | The URL clients reach the server at through the ingress: the RFC 9728 `resource` identifier and the base of the `resource_metadata` URL in every `WWW-Authenticate` challenge. Must be `https` (or `http` on loopback). |
| `MCP_OKTA_ISSUER` | — (required for `okta`) | The Okta authorization-server issuer URL; tokens must carry it as `iss`. Must be `https` (or `http` on loopback). |
| `MCP_OKTA_AUDIENCE` | — (required for `okta`) | The audience tokens must carry in `aud`. |
| `MCP_OKTA_JWKS_URL` | `{issuer}/v1/keys` | Where signing keys are fetched. Keys are cached, refreshed in the background every 10 minutes, and refetched (rate-limited to one per 30 s) when a token names an unknown `kid`. Only RSA signing keys with a `kid` are admitted (`use` must be `sig` and `alg` must be `RS256` when present); two admissible keys under one `kid` admit neither. The document is limited to 256 KiB, enforced while it is read. A key that disappears from the set, or is republished under the same `kid` with different material, evicts the tokens it validated from the token cache. |
| `MCP_OKTA_GROUPS_CLAIM` | `groups` | The claim holding group memberships; non-string members are ignored. |
| `MCP_OKTA_CLOCK_SKEW_SECONDS` | `60`; at most `300` | Leeway applied to `exp` and `nbf`. |
| `MCP_REQUIRED_SCOPE` | `mcp:tools` | The scope a token must carry to reach `/mcp`; missing it is a `403 insufficient_scope`. |
| `MCP_TENANT` | issuer host | Tenant label stamped on every principal, audit record, and artifact owner. |
| `MCP_POLICY_FILE` | — (required for `okta`) | YAML policy document (`src/policy/engine.rs` documents the schema; `tests/fixtures/policy/phase-a.yaml` is a worked example). Compiled at startup and hot-reloaded on change; a document that does not compile is refused at startup and ignored on reload. A file that vanishes or becomes unreadable is treated the same way: the last good policy stays in force, the health banner reports that reloads are failing (the reason itself goes to the operator log, not the public banner) (deleting the file is **not** an emergency deny — publish `rules: []` to deny everything). Validate with `mcp-devtools policy check <file>`; ask why a call is allowed or denied with `mcp-devtools policy explain <file> --tool … --arguments … --group … --environment …`, which builds the call exactly as the gateway would and lists the first key every rule fails on. Setting it with `MCP_AUTH_MODE=off` enforces the policy against the `local` principal — a dry run. |
| `MCP_POLICY_PUBLIC_KEY` | — (required for `okta`) | Base64 Ed25519 public key. When set, `MCP_POLICY_FILE` (and `MCP_REVOCATION_FILE`) must carry a verified detached signature in `<file>.sig`, produced by `mcp-devtools policy sign <file> --key <keyfile>` with the private key from `mcp-devtools policy keygen`. A document whose signature is missing or does not verify is refused at startup and ignored on reload (last good policy in force, health degraded). Every load, change, and rejection is a `policy_*` control record in the audit journal; a change is journaled **before** it takes effect and is not applied if the record cannot be made durable. |
| `MCP_REVOCATION_FILE` | — (required for `okta`) | The revocation list (`src/auth/revocation.rs`): revoked subjects, revoked token ids (`jti`), and a `not_before` cut-off that refuses every token issued before it (`revoke all`). Signed with the same key as the policy and hot-reloaded the same way; enforced on every request after token validation, regardless of the validated-token cache, so a change takes effect within one poll (≤ 500 ms). On every change the token cache is cleared and the revoked subjects' sessions are closed (all principal sessions when the cut-off moves). Edit with `mcp-devtools revoke init|subject|token|all|remove|clear-all|show`; every refusal is a `revoked_token_rejected` record in the journal. See `docs/revocation-runbook.md`. |
| `MCP_WRITE_MAX_TOKEN_AGE_SECONDS` | `300`; `0` disables | Plan §3.6 "high-risk operations": a non-read tool call is refused unless the token was issued (`iat`) within this many seconds — a token with no `iat` is refused for writes. Reads are unaffected. Applies only when inbound authentication is required. |
| `MCP_VENDOR_ENVIRONMENT` | unclassified | `prod`, `staging`, `qa`, or `dev`. Vendor-scoped: put it in a vendor's `configs.json` section to classify that account. An unclassified environment matches no environment-scoped rule. |
| `MCP_AUDIT_JOURNAL_DIR` | — (required for `okta`) | Directory for the durable, sequence-numbered audit journal. Every tool call's intent is written and synced **before** dispatch; a journal that cannot accept a record refuses the call, and the health banner answers 503. Operational CLI subcommands refuse to run while this is set (they would bypass the journal). |
| `MCP_AUDIT_SIGNING_KEY` | — (required for `okta`) | Path to the gateway's Ed25519 PKCS#8 key from `mcp-devtools audit keygen` (owner-only file; a Kubernetes Secret mount needs `defaultMode: 0400`). Signs every journal checkpoint. Keep the printed public key for `mcp-devtools audit verify --public-key`. |
| `MCP_AUDIT_CHECKPOINT_RECORDS` | `256` | Records between checkpoints. Every line extends a SHA-256 chain; a checkpoint records the chain value over everything before it, signed. Also written when this many seconds pass (`MCP_AUDIT_CHECKPOINT_SECONDS`) with unsealed records, and at every clean shutdown. |
| `MCP_AUDIT_CHECKPOINT_SECONDS` | `60` | Longest a written record stays unsealed by a checkpoint. |
| `MCP_AUDIT_CHECKPOINT_EXPORT_DIR` | — | Directory each checkpoint is copied to (`checkpoint-<seq>.jsonl`, atomically written), for shipping to object storage or a SIEM. `mcp-devtools audit verify --checkpoints <dir>` compares it to the journal and reports a truncated tail. An export failure is logged, never refuses calls. |
| `MCP_AUDIT_APPEND_TIMEOUT_MS` | `5000`; clamped to `100`–`60000` | Bound on the wait for durable acknowledgement. Before dispatch, a timeout refuses the call. After dispatch, the outcome record is not abandoned: the caller stops waiting at the bound, the write continues on a tracked task, and a graceful shutdown drains such writes for up to 30 s; see `src/policy/egress.rs` for what an intent without an outcome then means. |

Validated tokens are cached for `min(exp, 5 min)` keyed by the token's
SHA-256, so a revoked group membership takes effect when the client's next
token is issued (plan §3.6; the deny-list and `revoke-all` arrive in Phase
B).

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

