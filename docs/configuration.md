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

## Secret references

Any configuration value, in any of the three sources, may be a **reference** to a secret instead of the secret itself (`docs/enterprise-product-plan.md` §3.8):

| Form | Meaning |
|---|---|
| `keychain` or `keychain://` | The OS keychain slot for this key (`mcp-devtools creds set`). Unchanged from before; read on the request path as it always was. |
| `file:///path` | The whole file, less one trailing line break. The path is absolute and taken verbatim (no percent-decoding, no `file://host/…`). |
| `file:///path#key` | The string under `key` in a JSON object held in the file. Several references into one file are served from **one** read, so an email and a token in the same document always change together. |
| `vault://<mount>/<path>#<key>` | The string under `key` in the KV v2 secret at `<mount>/data/<path>` on the HashiCorp Vault / OpenBao server named by `MCP_VAULT_ADDR` (feature `secrets-vault`, on by default; the `MCP_VAULT_*` settings below). The first path segment is the mount; the version is Vault's own version number. `#key` is required — a KV secret is a document of keys. Several references into one secret are served from **one** read. Vault-side setup is in [`secret-sources-runbook.md`](secret-sources-runbook.md). |
| `awssm://…`, `azkv://…` | Reserved for the native adapters (plan C.2c–d, **deferred** until a design partner asks — rev 2.16). Recognised, and refused at startup as "no adapter compiled into this binary". The supported path is a mounted CSI Secrets Store volume and `file://` (`deploy/k8s/secrets-csi.yaml`). |

Anything else is a literal, byte for byte, so a configuration with no references behaves exactly as it did.

The MCP server resolves every reference **before it starts serving**; a file that is missing, a key that is absent, a value that is empty, a scheme with no adapter, or a provider that is compiled in but not configured (a `vault://` reference with no `MCP_VAULT_ADDR`) refuses startup with the reference named (never the value). While it runs, the references are re-read every `MCP_SECRET_REFRESH_INTERVAL_SECONDS` (default `30`, clamped to `1`–`3600`), and a changed document is swapped in whole; an upstream `401` triggers one early re-read, at most every 10 s. A refresh that fails keeps the **last good values** in force and the health banner reports `secret refresh is failing; last good values in force` (the reference and the cause go to the operator log) until a refresh succeeds. A global-config reload that introduces a reference which does not resolve is refused, and the previous configuration stays in force.

Where a referenced value acts as a credential, the audit record and the enterprise-mode result metadata (`_meta["mcp-devtools/upstream"]`) carry its `source` (the scheme) and `version` (the provider's version, or `sha256:` plus the first 16 hex characters of the file's content hash) alongside the credential label; a change of `version` between two records is the evidence of a rotation. The value itself never appears anywhere.

Not covered yet: the one-shot CLI subcommands (`mcp-devtools jira|bb|conf …`) refuse to run while the configuration holds a reference, and credentials nested inside `NINJAONE_SERVERS` entries accept literals and `keychain` only (`docs/enterprise-carry-forward.md`, CF-28 and CF-29).

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

Everything in this section is off by default. With it off, unset and an
explicit `off` are identical to each other in protocol behaviour and tool
surface (`tests/auth_mode_tests.rs` locks that); relative to the server
before the enterprise work, the wire requests it sends are in canonical
form (`docs/enterprise-carry-forward.md`, CF-19, records the exact
differences) and the journal, when configured, carries checkpoint records.
It is the configuration surface of the enterprise plan
(`docs/enterprise-product-plan.md`, Phases A–C). Startup is
**fail-closed**: an incomplete or contradictory enterprise configuration
refuses to start with a reason, never falls back to local mode.

Unless noted, these settings use the same three-source cascade as the
integration settings, so they may live in the environment, `.env`, or a
`configs.json` section.

| Setting | Default | Purpose |
|---|---|---|
| `MCP_ROLE` | `all` | Process env only (or `serve --role`). `all`, `gateway`, or `control` (plan ADR-010). `control` serves the health banner and runs the control plane's background work — audit forwarding (`MCP_AUDIT_FORWARD_URL`, below); `gateway` never forwards. |
| `MCP_AUTH_MODE` | `off` | `off`, `oidc`, or `okta`. `oidc` validates inbound bearer tokens against an OpenID Connect provider chosen by `MCP_OIDC_PROFILE`; it requires an HTTP transport, a non-loopback-safe configuration below, a policy, and a journal. `okta` is an alias of `oidc` with the Okta profile implied, reading the same settings under the `MCP_OKTA_*` names it has always used — a deployment configured before profiles existed keeps working unchanged. Any other value is refused. |
| `MCP_BIND_ADDR` | `127.0.0.1` | Process env only. IP or `ip:port`. A non-loopback bind is refused unless inbound authentication is on (`oidc` / `okta`). |
| `MCP_PUBLIC_URL` | — (required in enterprise mode) | The URL clients reach the server at through the ingress: the RFC 9728 `resource` identifier and the base of the `resource_metadata` URL in every `WWW-Authenticate` challenge. Must be `https` (or `http` on loopback). |
| `MCP_OIDC_PROFILE` | — (required for `oidc`) | `okta`, `entra`, `keycloak`, `auth0`, or `generic`. A profile is a set of defaults — where the signing keys are (`MCP_OIDC_JWKS_URL`), which claim is the subject (`MCP_OIDC_SUBJECT_CLAIM`), which claim carries groups (`MCP_OIDC_GROUPS_CLAIM`) — plus the provider's claim-shape corrections, all over the one validator. Each is described in [`identity-provider-runbook.md`](identity-provider-runbook.md). Not read in `okta` mode (the profile is Okta). |
| `MCP_OIDC_ISSUER` / `MCP_OKTA_ISSUER` | — (required in enterprise mode) | The provider's issuer URL; tokens must carry it as `iss`, with or without a trailing slash (Auth0 and Entra v1 issuers end in one). Must be `https` (or `http` on loopback). One key family per deployment: setting a `MCP_OKTA_*` key in `oidc` mode, or a `MCP_OIDC_*` key in `okta` mode, is refused at startup rather than resolved by precedence. |
| `MCP_OIDC_AUDIENCE` / `MCP_OKTA_AUDIENCE` | — (required in enterprise mode) | The audience tokens must carry in `aud` (a string, or one member of an array). Keycloak emits no `aud` at all until the client has an audience mapper; the token is refused, not the check relaxed. |
| `MCP_OIDC_JWKS_URL` / `MCP_OKTA_JWKS_URL` | per profile | Where signing keys are fetched. Okta: `{issuer}/v1/keys`; Keycloak: `{issuer}/protocol/openid-connect/certs`; Auth0: `{issuer}/.well-known/jwks.json`; Entra and generic: the `jwks_uri` of `{issuer}/.well-known/openid-configuration`, resolved on every fetch, which must name the configured issuer and must itself be `https` (or `http` on loopback). Keys are cached, refreshed in the background every 10 minutes, and refetched (rate-limited to one per 30 s) when a token names an unknown `kid`. Only RSA signing keys with a `kid` are admitted (`use` must be `sig` and `alg` must be `RS256` when present); two admissible keys under one `kid` admit neither. The document is limited to 256 KiB (discovery: 64 KiB), enforced while it is read. A key that disappears from the set, or is republished under the same `kid` with different material, evicts the tokens it validated from the token cache. |
| `MCP_OIDC_SUBJECT_CLAIM` | per profile: `oid` for Entra, otherwise `sub` | The claim that becomes the principal's subject — what policy `subjects`, the revocation list, session binding, and every audit record key on. Entra's `sub` is pairwise per application, so it is not a stable identity across apps; `oid` is. `okta` mode has no such key (the subject is `sub`). |
| `MCP_OIDC_JWKS_FILE` | — | OIDC mode only; mutually exclusive with `MCP_OIDC_JWKS_URL`. Service-readable regular JWKS file (256 KiB maximum), read before every authentication and installed only when content changes. File failures clear signing keys and validated tokens and refuse authentication; no remote fallback. Rotation/withdrawal uses the same admission and cache invalidation as remote JWKS. Mount its parent directory for atomic replacement. See [air-gap operations](air-gap-runbook.md). |
| `MCP_OIDC_GROUPS_CLAIM` / `MCP_OKTA_GROUPS_CLAIM` | per profile: `groups`, none for Auth0 | The claim holding group memberships: a claim name, or a dotted path into nested objects (`realm_access.roles`); a literal name wins over a path, so Auth0's namespaced `https://example.com/groups` is looked up as written. Non-string members are ignored. Keycloak's `/`-prefixed group paths lose the leading slash. When the claim is configured but absent and the token says the groups were too many to include (Entra's `_claim_names` / `_claim_sources`, or `hasgroups`), the token is refused as `groups_overage` rather than read as "no groups". |
| `MCP_OIDC_CLOCK_SKEW_SECONDS` / `MCP_OKTA_CLOCK_SKEW_SECONDS` | `60`; at most `300` | Leeway applied to `exp`, `nbf`, and a future `iat`. |
| `MCP_REQUIRED_SCOPE` | `mcp:tools` | The scope a token must carry to reach `/mcp`; missing it is a `403 insufficient_scope`. |
| `MCP_TENANT` | issuer host | Tenant label stamped on every principal, audit record, and artifact owner. |
| `MCP_POLICY_FILE` | — (required in enterprise mode) | YAML policy document (`src/policy/engine.rs` documents the schema; `tests/fixtures/policy/phase-a.yaml` is a worked example). Compiled at startup and hot-reloaded on change; a document that does not compile is refused at startup and ignored on reload. A file that vanishes or becomes unreadable is treated the same way: the last good policy stays in force, the health banner reports that reloads are failing (the reason itself goes to the operator log, not the public banner) (deleting the file is **not** an emergency deny — publish `rules: []` to deny everything). Validate with `mcp-devtools policy check <file>`; ask why a call is allowed or denied with `mcp-devtools policy explain <file> --tool … --arguments … --group …`, which builds the call exactly as the gateway would — same extractor, same upstream identity from the same configuration cascade (`MCP_VENDOR_ENVIRONMENT`, the credential slot) — and lists the first key every rule fails on; `--environment` overrides the configured environment for a what-if, `--client-name`/`--client-version` supply the reporting client. Setting it with `MCP_AUTH_MODE=off` enforces the policy against the `local` principal — a dry run. |
| `MCP_POLICY_PUBLIC_KEY` | — (required in enterprise mode) | Base64 Ed25519 public key. When set, `MCP_POLICY_FILE` (and `MCP_REVOCATION_FILE`) must carry a verified detached signature in `<file>.sig`, produced by `mcp-devtools policy sign <file> --key <keyfile>` with the private key from `mcp-devtools policy keygen`. A document whose signature is missing or does not verify is refused at startup and ignored on reload (last good policy in force, health degraded). Every load, change, and rejection is a `policy_*` control record in the audit journal; a change is journaled **before** it takes effect and is not applied if the record cannot be made durable. |
| `MCP_REVOCATION_FILE` | — (required in enterprise mode) | The revocation list (`src/auth/revocation.rs`): revoked subjects, revoked token ids (`jti`), and a `not_before` cut-off that refuses every token issued before it (`revoke all`). Signed with the same key as the policy and hot-reloaded the same way; enforced on every request after token validation, regardless of the validated-token cache, so a change takes effect within one poll (≤ 500 ms). On every change the token cache is cleared and the revoked subjects' sessions are closed (all principal sessions when the cut-off moves). Edit with `mcp-devtools revoke init|subject|token|all|remove|clear-all|show`; every refusal is a `revoked_token_rejected` record in the journal. See `docs/revocation-runbook.md`. |
| `MCP_WRITE_MAX_TOKEN_AGE_SECONDS` | `300`; `0` disables | Plan §3.6 "high-risk operations": a non-read tool call is refused unless the token was issued (`iat`) within this many seconds — a token with no `iat` is refused for writes. Reads are unaffected. Applies only when inbound authentication is required. |
| `MCP_CONSOLE_CLIENT_ID` | unset | Public OIDC PKCE client id; mounts `/console` only in a `console` feature build with OIDC authentication on `all`/`control`. No client secret. See [console runbook](console-runbook.md). |
| `MCP_CONSOLE_REDIRECT_PATH` | `/console/callback` | Absolute callback path, without query, fragment, wildcard or route parameters. Register `MCP_PUBLIC_URL` (no trailing slash) plus this path at the IdP; default used when blank. |
| `MCP_CONSOLE_SCOPES` | `openid mcp:admin` | Space-separated authorization scopes; default used when blank. Entra needs the resource-prefixed scope, e.g. `openid api://<resource-app-id>/mcp:admin`; see [provider registration](identity-provider-runbook.md). The access token must still grant `mcp:admin`. |
| `MCP_ADMIN_APPROVALS` | `off` | `off` or `required`. Which admission gate every `/admin/*` mutation consults **before** it appends its durable `admin_mutation` intent (plan §3.10.1, `ports::MutationGate`). `off`, or unset, is the direct gate: every mutation is admitted and behaves exactly as it did before the gate existed. `required` is two-person approval (plan §3.10.3): policy install and deny-list replacement are journaled as proposals and answered `202` until a different administrator of the same tenant approves them with a fresh token; reload, session revoke, and artifact purge stay direct. Requires `MCP_AUDIT_JOURNAL_DIR` (proposals are journal records; pending ones are rebuilt from it at startup) and refuses startup without it. Any other value is refused at startup. Shapes, records, and errors are in [the admin API runbook](admin-api-runbook.md). |
| `MCP_ADMIN_APPROVAL_TTL_SECONDS` | `86400`; `1`–`2592000` | How long a proposal stays approvable under `MCP_ADMIN_APPROVALS=required`. A proposal past it reads as `expired`, and the first decision asked of it journals an `admin_rejection` with reason `expired`. |
| `MCP_VENDOR_ENVIRONMENT` | unclassified | `prod`, `staging`, `qa`, or `dev`. Vendor-scoped: put it in a vendor's `configs.json` section to classify that account. An unclassified environment matches no environment-scoped rule. |
| `MCP_AUDIT_JOURNAL_DIR` | — (required in enterprise mode) | Directory for the durable, sequence-numbered audit journal. Every tool call's intent is written and synced **before** dispatch; a journal that cannot accept a record refuses the call, and the health banner answers 503. Operational CLI subcommands refuse to run while this is set (they would bypass the journal). |
| `MCP_AUDIT_SIGNING_KEY` | — (required in enterprise mode) | Path to the gateway's Ed25519 PKCS#8 key from `mcp-devtools audit keygen`. The file must be readable by nobody but its owner and, at most, its group (`0600`, `0640`, `0440`); a Kubernetes Secret projected under `fsGroup` arrives as `root:<fsGroup>` `0440` and is accepted, anything world-readable or group-writable is refused at startup. Signs every journal checkpoint. Keep the printed public key for `mcp-devtools audit verify --public-key`. |
| `MCP_AUDIT_CHECKPOINT_RECORDS` | `256` | Records between checkpoints. Every line extends a SHA-256 chain; a checkpoint records the chain value over everything before it, signed. Also written when this many seconds pass (`MCP_AUDIT_CHECKPOINT_SECONDS`) with unsealed records, and at every clean shutdown. |
| `MCP_AUDIT_CHECKPOINT_SECONDS` | `60` | Longest a written record stays unsealed by a checkpoint. |
| `MCP_AUDIT_CHECKPOINT_EXPORT_DIR` | — | Directory each checkpoint is copied to (`checkpoint-<seq>.jsonl`, atomically written), for shipping to object storage or a SIEM. `mcp-devtools audit verify --checkpoints <dir>` compares it to the journal and reports a truncated tail, and reports every journal checkpoint the directory lacks. An export failure is logged (`audit checkpoint export failed`) and never refuses calls; treat the log line as an alert, because until the copy is restored a truncation back to that checkpoint would go unreported. |
| `MCP_AUDIT_FORWARD_URL` | — | Enables forwarding of the journal to a SIEM from the `control` (or `all`) role, behind the `AuditForwarder` port (plan §3.9, C.3). The scheme selects the adapter: `syslog+tls://host[:6514]` is RFC 5424 over RFC 5425 octet counting on TLS (plaintext `syslog://` is refused); `https://…/services/collector[/event]` is Splunk HTTP Event Collector; any other `https://` URL is a generic JSON endpoint (a `POST` of a JSON array of records, `Authorization: Bearer` when a token is set). `http://` is accepted on loopback only. Records are the journal's own lines, byte for byte, forwarded in sequence from the last acknowledged one; the cursor survives restarts; delivery is at least once and `seq` is the receiver's deduplication key. An unreachable receiver never stops the process or a tool call — the journal is retained, the health banner reports `audit forwarding is failing; journal retained`, and delivery is retried with backoff (up to a minute). A URL with no adapter, or a certificate that does not load, refuses startup. See [`siem-forwarding-runbook.md`](siem-forwarding-runbook.md). |
| `MCP_AUDIT_FORWARD_FORMAT` | inferred from the URL | `hec` or `json`, when the URL alone does not say (a Splunk collector on an unusual path, or a JSON endpoint whose path happens to contain `/services/collector`). |
| `MCP_AUDIT_FORWARD_TOKEN` | — (required for HEC) | The HEC token (`Authorization: Splunk …`) or the bearer token for a JSON endpoint. May be a secret reference (`file://`, `vault://`); the value in force is read at each delivery, so a rotation takes effect on the next batch without a restart. Never logged. |
| `MCP_AUDIT_FORWARD_JOURNAL_DIR` | `MCP_AUDIT_JOURNAL_DIR` | The journal to forward. In the split topology the `control` replica points this at the gateway's journal volume, mounted read-only. |
| `MCP_AUDIT_FORWARD_STATE_DIR` | the forwarded journal directory | Where the cursor (`audit-forward-cursor.json`) is kept; must be writable, so a read-only journal mount needs its own. Checked at startup. |
| `MCP_AUDIT_FORWARD_BATCH` | `256`; `1`–`4096` | Most records per delivery. |
| `MCP_AUDIT_FORWARD_INTERVAL_SECONDS` | `5`; `1`–`3600` | How long the shipper waits once it has caught up before looking for new records. After a failure the wait doubles per attempt, capped at a minute. |
| `MCP_AUDIT_FORWARD_TIMEOUT_SECONDS` | `10`; `1`–`300` | Per-delivery bound: connect, TLS handshake, and the write or request. |
| `MCP_AUDIT_FORWARD_ORIGIN` | `$HOSTNAME`, else `mcp-server-devtools` | What this process calls itself to the receiver: the syslog `HOSTNAME` field, the HEC `host`. Set it per gateway when several forward to one receiver. |
| `MCP_AUDIT_FORWARD_CA_FILE` | — | PEM file holding the CA that signed the receiver's certificate, added to the system trust store, for a private CA. |
| `MCP_AUDIT_FORWARD_CLIENT_CERT` / `MCP_AUDIT_FORWARD_CLIENT_KEY` | — | (syslog) A PEM client certificate and its PKCS#8, SEC1, or PKCS#1 key, for a receiver that requires mutual TLS. Both or neither. |
| `MCP_ROLLUP_STORE` | — | Usage-rollup backend on a role that serves the control plane: `sqlite:///absolute/path.db` (embedded SQLite) or `memory://` (development/tests). `postgres://` is reserved and refuses startup until that adapter is built. Rows contain usage metadata, including tenant and subject, but never arguments, content, or credentials. In a split `gateway`/`control` topology usage is not yet pushed between roles (CF-33); run `all` for complete rollups. See [`usage-and-metrics-runbook.md`](usage-and-metrics-runbook.md). |
| `MCP_ROLLUP_RETENTION_DAYS` | `90`; `0` keeps all | Age of usage rows retained by the hourly pruning task. This is independent of the audit journal's evidence retention. |
| `MCP_USAGE_CHANNEL_CAPACITY` | `4096`; clamped to `64`–`65536` | Capacity of the non-blocking channel from tool calls to the rollup consumer. A full or closed channel drops usage and increments `mcp_usage_events_dropped_total`; it never delays or refuses a tool call. |
| `MCP_METRICS` | off | `on` or `true` exposes unauthenticated `GET /metrics` in Prometheus text format. Labels are bounded to vendor/tool/decision/outcome and never contain a subject, tenant, token, arguments, or content. Keep the endpoint cluster-internal. |
| `MCP_RATE_LIMIT_PER_PRINCIPAL` | `0` (off) | Sustained requests per second for each validated subject; positive decimals are accepted. Enforced after bearer validation and the `mcp:tools` scope check. The limiter is in-process and therefore assumes one gateway replica (CF-16). A refusal is HTTP 429 with `Retry-After`. At most 10,000 subjects are tracked per process; past that, a new subject is refused (not admitted untracked) until one goes idle. See the usage runbook. |
| `MCP_RATE_LIMIT_BURST` | twice the rate, at least `1` | Token-bucket capacity per principal. Must be at least 1 when the rate limit is enabled. |
| `MCP_SECRET_REFRESH_INTERVAL_SECONDS` | `30`; clamped to `1`–`3600` | How often secret references (`file://…`, "Secret references" above) are re-read. Not enterprise-only: applies whenever the configuration holds a reference. |
| `MCP_VAULT_ADDR` | — | Enables the `vault://` adapter: the Vault / OpenBao address, `https://vault.example:8200`. Must be `https`, or `http` on loopback (a dev server, or a Vault Agent sidecar on the pod). Read at startup; not hot-reloaded. |
| `MCP_VAULT_AUTH` | — (required with `MCP_VAULT_ADDR`) | `kubernetes`, `approle`, or `token`. Explicit: the adapter never tries one method and falls back to another. |
| `MCP_VAULT_ROLE` | — (required for `kubernetes`) | The Vault role bound to the pod's service account (`vault write auth/kubernetes/role/<role> bound_service_account_names=… bound_service_account_namespaces=… token_policies=… token_ttl=…`). The projected service-account token is read at every login, so a rotated projection is used without a restart. |
| `MCP_VAULT_JWT_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Where the projected service-account token is (`kubernetes` auth). |
| `MCP_VAULT_ROLE_ID` | — (required for `approle`) | The AppRole role id. |
| `MCP_VAULT_SECRET_ID` | — (required for `approle`) | The AppRole secret id, or a `file://` reference to a file holding it (re-read at every login, so a rotated secret id is picked up). Only a literal or a `file://` reference: a provider's own credential cannot come from a provider. |
| `MCP_VAULT_TOKEN` | — (required for `token`) | A client token, or a `file://` reference to one. The adapter calls `lookup-self` to learn the lease and renews a renewable token; a token whose policy forbids `lookup-self` is used as given. |
| `MCP_VAULT_AUTH_MOUNT` | `approle` / `kubernetes` | The auth method's mount path when it is not the default. |
| `MCP_VAULT_NAMESPACE` | — | Sent as `X-Vault-Namespace` on every request (Vault Enterprise, HCP Vault). |
| `MCP_VAULT_CACERT` | — | PEM file holding the CA that signed Vault's certificate, for a private CA. |
| `MCP_AUDIT_APPEND_TIMEOUT_MS` | `5000`; clamped to `100`–`60000` | Bound on the wait for durable acknowledgement. Before dispatch, a timeout refuses the call. After dispatch, the outcome record is not abandoned: the caller stops waiting at the bound, the write continues on a tracked task, and a graceful shutdown drains such writes for up to 30 s; see `src/policy/egress.rs` for what an intent without an outcome then means. |

Validated tokens are cached for `min(exp, 5 min)` keyed by the token's
SHA-256, so a revoked group membership takes effect when the client's next
token is issued (plan §3.6); the revocation list above is what cuts a
token off sooner, and it is checked on every request regardless of the
cache. A token whose `iat` lies more than the clock skew in the future is
refused as `not_yet_valid`: it could not be dated against a `revoke all`
cut-off or the fresh-token rule. The `policy_loaded` and
`revocation_loaded` records are appended, and made durable, **before** the
port is bound; a journal that cannot take them stops the server from
starting.

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


### Enterprise-managed authorization (C.1)

`MCP_EMA_ENABLED=true` opts authenticated HTTP deployments into EMA discovery
checks and extension advertisement. The configured OIDC audience must equal
`MCP_PUBLIC_URL`; the issuer must advertise the ID-JAG profile and JWT-bearer
grant. Default is false. See [EMA setup, exchange helper and required external
client matrix](ema-runbook.md). External client interoperability is not yet
claimed. `mcp-devtools auth exchange --help` describes the Unix file-based
protocol helper; it is separate from vendor commands and the admin API.

Linux `.deb`/`.rpm` defaults and protected systemd environment configuration
are documented in [package operations](../deploy/packages/README.md).
The [Compose reference](../deploy/compose/README.md) runs `all` behind TLS
with persistent journal, rollup and policy volumes. Environment changes
require restarting the service; JWKS file contents are checked automatically.
