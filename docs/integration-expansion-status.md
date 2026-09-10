# REST integration expansion: 0.17.0

The initial checkout contained eight partially implemented REST adapters. They
needed compilation fixes, contract corrections, vendor filtering, pagination
metadata, redirect/egress enforcement, retry timing and binary download tools.
This change completes that REST scope with 47 additional tools. AWS and
Playwright are deferred, as are write operations and the optional versioned
performance-telemetry collection proposed in the plan. No adaptive policy or
exploration is enabled.

## Workflows and compatibility

| Adapter | Tools | Implemented workflow | Deterministic evidence |
|---|---:|---|---|
| GitHub | 10 | Repository → file/PR/diff/issue → workflow/job/log | Auth/version headers, Enterprise `/api/v3` context, pagination headers, omitted patches, text/binary files, cross-origin logs |
| GitLab | 10 | Project → file/MR/diff/issue → pipeline/job/trace | API v4 context, nested namespace encoding, project-scoped IIDs, paging, diff flags, large streamed traces |
| Figma | 5 | File/node → components/comments → PNG exports | File URLs, granular custom header, limits/missing nodes, partial renders, CDN credential stripping, PNG dimensions |
| Vercel | 4 | Project → deployment → bounded build/event logs | Team override/default, endpoint versions, bounded non-following log queries, vendor errors |
| Sentry | 5 | Organization projects → issues → event/release diagnosis | Organization scope, Link cursor preservation, latest event selection, error envelopes |
| Artifactory | 5 | Repository → structured search → metadata/build → download | Context normalization, JSON-escaped AQL, bounded search, binary download and SHA-256 mismatch cleanup |
| Snyk | 4 | Organization → projects → SCA findings | Dated API version, regional base, token scheme, cursor and JSON:API errors |
| Mend | 4 | Application → project → security findings | Platform 3.0 summary paths, org-scoped refresh exchange, expiry/rotation/concurrency, local page filters, bounded/redacted auth errors |

Fixtures exercise hosted-shaped and self-hosted/context-path URLs; they do not
prove compatibility with a deployed server version. Live smoke tests were not
run because test tenant accounts and server versions were not supplied. Mend's
contract was checked against the [Platform 3.0 API specification](https://api-docs.mend.io/platform/3.0)
and [authentication documentation](https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0).
Legacy Mend API 2.0 and additional scan products are outside this scope. Figma
exports inspect bounded PNG headers without decoding pixels or rendering inline
images. Image URLs are neither cached nor persisted as raw API responses.

New native tool contracts are intentional additions; the existing 75 tool
schemas/descriptions must remain identical to their previous golden entries.
Read policy uses conservatively unscoped `vendor_resource` plus tool/path/origin
rules; no repository/project resource-ID extraction is claimed. Mend credential
bootstrap uses configured origins and remains part of the documented CF-17
credential-provider exception. Its async refresh gate spans bounded bootstrap
I/O deliberately to prevent concurrent authentication storms.

## Upgrade and redirect dependencies

- Discovery now defaults to `MCP_ENABLED_VENDORS=auto`. Use `all` to retain the
  former full listing, or select vendors explicitly. Reconnect to change the
  inventory; per-call credential refresh and authorization remain live.
- CircleCI absolute signed output URLs now require configured trusted origins.
- GitHub job logs and Figma PNG exports require their actual CDN/storage origins.
- Artifactory external storage and Jira attachment redirects require entries
  when they cross origins; same-origin API GET redirects remain supported.
- Generic GET endpoints can follow at most five authorized hops. Redirected
  mutations/uploads are refused and never replayed. Bootstrap clients are
  separate and do not acquire a new redirect exception.
- Existing multipart upload, streaming writer, disk quotas, artifact ownership,
  retention, HTTP retrieval and `artifact_read` are reused. Arbitrary binary
  downloads produce metadata only, with no archive extraction or text previews.
- Streaming retryable failures honor server timing within a total deadline.
  Non-retrying calls expose timing without introducing mutation retries. Actual
  decoded/encoded limits bound error bodies, including chunked/compressed data.

Configuration and examples are in [the reference](configuration.md#native-rest-integrations)
and [configs.json](../examples/configs.json). Environment-based deployment
configuration needs no new container, Helm sidecar, runtime or build feature.

## Validation

Validation completed locally on Linux with pinned Rust 1.98.1:

- `cargo build --locked` and `cargo build --locked --no-default-features`: pass.
- `cargo clippy --locked --all-targets -- -D warnings`: pass, zero warnings.
- `cargo test --locked --no-fail-fast`: 1,305 passed, zero failed, two ignored
  (the golden-regeneration helper and an existing bootstrap doctest).
- `cargo fmt --all -- --check` and `git diff --check`: pass.
- `cargo deny --locked check --deny warnings`: advisories, bans, licenses and
  sources pass; the only lockfile change is package version 0.17.0.
- All 75 pre-existing golden tool entries compare unchanged. Stdio tests verify
  selected inventories and reject calls to disabled tools; HTTP fixtures cover
  private zero-TTL lists, session reload behavior and existing transport flows.
- macOS/Windows runtime validation and live vendor smoke tests were not run.

### Tool inventory measurement

Measured September 10, 2026 using the real binary over stdio, isolated empty
home/working directories, explicit selection and fixture credential presence.
No upstream credentials or live vendor requests are needed. Byte counts are
UTF-8 compact JSON of the `tools` array (`ensure_ascii=False`, separators
`,`/`:`), not tokenizer estimates. Reproduce after builds stop with
`python3 scripts/measure-tool-inventory.py /absolute/path/to/mcp-devtools`.

| Configuration | Tools | Compact JSON bytes |
|---|---:|---:|
| Empty `auto` | 1 | 844 |
| GitHub configured, `auto` | 11 | 35,719 |
| Explicit `github,gitlab` | 21 | 69,445 |
| Default features, `all` | 122 | 322,253 |
| No default features, `all` | 118 | 315,931 |

The first three rows match in both builds. The four-tool difference is WRDS.
[Raw measurements](benchmarks/2026-09-10-tool-inventory.json) accompany the probe.


### Allocation evidence

The [recorded response-pipeline probe](benchmarks/2026-09-10-rest-integration-expansion.txt)
matches allocation bytes/counts for every comparable row in the September 8
edition-extraction baseline. Representative production stages:

| Stage | Allocated KB | Allocations |
|---|---:|---:|
| Config snapshot | 0 | 0 |
| JMESPath without a filter | 0 | 0 |
| TOON rendering, 500 issues | 1,736 | 19,032 |
| TOON rendering, 5,000 issues | 16,547 | 190,035 |
| Output truncation | 39 | 4 |
| Policy evaluation, 500 rules | 0 | 5 |

Timing is observational; the probe is not a network throughput benchmark and
makes no live-vendor performance claim. No dependency versions or benchmark
profiles changed. The native inventory itself is measured separately below.
