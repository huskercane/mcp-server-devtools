# Integration expansion plan

Date: September 9, 2026. Updated September 10, 2026.

> **Implementation status:** the eight REST integrations and shared transport
> prerequisites are implemented for the 0.17.0 change. This adds 47 native tools
> to the current 75-tool baseline (122 default; 118 without default features).
> It includes session vendor filtering, Retry-After handling, explicit per-hop
> egress enforcement, GitHub job logs, GitLab streamed traces, Figma PNG exports,
> and Artifactory downloads using the existing artifact pipeline. See
> [implementation status and validation](integration-expansion-status.md) and
> [configuration](configuration.md#native-rest-integrations).
> AWS and Playwright are excluded from this implementation at the user's request.
> Adaptive/experimental telemetry and follow-on mutations remain deferred.
> Hosted/self-hosted live compatibility is not claimed from fixture results.

Add AWS, Snyk, Playwright, Vercel, Sentry, JFrog Artifactory, Mend, GitHub,
GitLab, and Figma to the
existing Rust MCP server. Deliver useful discovery and diagnostic workflows
first, then add explicitly scoped mutations. Proposed tool names below are
design targets, subject to endpoint and schema validation during implementation.

## Architecture

Eight integrations follow the existing REST path: Snyk, Vercel, Sentry,
Artifactory, Mend, GitHub, GitLab, and Figma. Use `src/vendor/sonarqube/`,
`src/controllers/sonarqube.rs`, and `src/tools/sonarqube.rs` as the initial
reference. Mend also needs a vendor-owned login/token lifecycle.

For each integration, add vendor/config identifiers and aliases, secret
descriptors in `src/auth/secrets.rs`, bootstrap composition in
`src/bootstrap/vendors.rs`, controllers, argument schemas, tool descriptions,
and router/context wiring in `src/tools/mod.rs`. Update tool-to-vendor
attribution, applicable policy/credential handling, CLI discovery, and tests
that enumerate vendors or tools. Preserve lazy credential validation.

Reuse the existing output formatting, filtering, bounded responses, artifacts,
audit, and identity isolation. Extend shared HTTP capabilities only where a
concrete endpoint requires it: vendor auth schemes, text request bodies,
cursor/header pagination, and bounded log streams. Do not force SDK calls or
browser sessions through the REST `Vendor` abstraction.

AWS uses optional official Rust SDK dependencies. Playwright uses a managed,
pinned runtime behind a Rust adapter. Both must pass the same policy and audit
contracts as REST integrations; their network paths do not automatically
inherit the shared HTTP transport's enforcement.

Connectors remain in Community, consistent with
[the edition boundary](edition-boundary-proposal.md). AWS service access is
separate from the deferred AWS Secrets Manager secret-source adapter.

### Tool contracts and inventory size

Choose purpose-built tools for these integrations deliberately, extending the
SonarQube pattern rather than the generic HTTP verbs documented in
`src/vendor/mod.rs` and used by Bitbucket/Jira. This improves discoverability
and gives each operation a bounded schema and policy meaning; the maintenance
cost is that each additional endpoint (including GitHub endpoints) requires a
code change, documentation, and tests. Existing generic tools keep their contracts.

`CLAUDE.md` requires byte-for-byte parity for the existing TS ports. No TS
reference contract has been designated for these new native vendor adapters;
their schemas and descriptions are new, fixture-tested contracts, not parity
claims. Playwright has a pinned upstream runtime, but our selected wrapper
schemas intentionally differ from its complete tool surface. Preserve existing
port parity while adding these explicitly new contracts.

Step 1 must add a configured-vendor tool listing filter before the new tool
inventory ships. At baseline commit `793ec1b`, the default-feature server returns **70 tools**
from `tools/list`, including four WRDS tools. Measured September 9, 2026 with
an in-process server built from that source, explicit empty configuration, and
an MCP stdio initialize → tools/list exchange; no upstream credentials or
vendor calls were used. Compact JSON for the tools array was **155,601 bytes**
(UTF-8, Python JSON serialization); this is a reproducible payload measure,
not a tokenizer estimate. The 58 proposed additions bring the full inventory
to **128 tools**. README's two stale 65-tool references are corrected alongside
this revision. Measure each optional build configuration when it ships rather
than deriving all future counts from this default-feature baseline. Record
schema/description bytes for representative configured subsets; client context
handling varies, but advertising every unconfigured vendor is unnecessary overhead.

Proposed policy: `MCP_ENABLED_VENDORS=auto` by default, or an explicit comma-
separated vendor allowlist, with `all` as a documented compatibility option.
`auto` uses configuration presence, never live authentication or secret
resolution during discovery; handle env-only settings, secret references,
AWS workload identity, and explicitly enabled Playwright. An explicit allowlist
can enable a vendor without local static credentials. Preserve lazy credential
validation on calls. Keep shared `artifact_read` discoverable and owner-checked.
Apply the same session enablement set to `tools/list` and `tools/call` so an
unlisted, disabled tool cannot be invoked directly. Authorization remains an
independent per-call check. Snapshot only vendor enablement on session creation;
changes to that set take effect on reconnect. The live config watcher in
`src/bootstrap/watcher.rs` continues to replace credentials and other runtime
configuration mid-session: each call uses the latest credential snapshot,
including credential removal/failure, without changing the advertised tool set.
Newly configured vendors appear on reconnect; a removed credential does not
leave a cached credential usable. Enablement is not an emergency revocation
mechanism; live authorization/revocation remains authoritative.

Update `list_tools`'s build-static/principal-agnostic comment and remove its
`CacheScope::Public`/five-minute TTL annotation for filtered lists. Initially
use `CacheScope::Private` with `ttlMs=0` (immediately stale), and do not reuse
inventories across sessions/config generations. The pinned model has Public
and Private scopes, not a separate no-cache scope.
Test different sessions before/after a config reload and credential hot-swap
within a session, including missing credentials, alongside stdio/HTTP, optional
features, empty config, explicit allowlists, and `all`.

Changing the default to `auto` is a compatibility change. The step-1 release
must include migration notes showing `MCP_ENABLED_VENDORS=all` for the former
inventory behavior and a Cargo package version bump with matching release tag.

## Initial tool scope

| Integration | Proposed first tools | Later expansion |
|---|---|---|
| GitHub | `github_list_repositories`, `github_get_file`, `github_list_pull_requests`, `github_get_pull_request`, `github_get_pull_request_diff`, `github_list_issues`, `github_get_issue`, `github_list_workflow_runs`, `github_list_workflow_jobs`, `github_get_job_logs` | Create/update PRs and issues, comments/reviews, merge, workflow dispatch/rerun |
| GitLab | `gitlab_list_projects`, `gitlab_get_file`, `gitlab_list_merge_requests`, `gitlab_get_merge_request`, `gitlab_get_merge_request_diff`, `gitlab_list_issues`, `gitlab_get_issue`, `gitlab_list_pipelines`, `gitlab_list_pipeline_jobs`, `gitlab_get_job_trace` | Create/update MRs and issues, comments/approvals, merge, pipeline trigger/retry |
| Figma | `figma_get_file`, `figma_get_nodes`, `figma_list_components`, `figma_export_images`, `figma_list_comments` | Folder/file discovery, styles, entitled variable access, comment creation |
| Vercel | `vercel_list_projects`, `vercel_list_deployments`, `vercel_get_deployment`, `vercel_get_deployment_logs` | Create/cancel deployments, promote releases, manage domains |
| Sentry | `sentry_list_projects`, `sentry_search_issues`, `sentry_get_issue`, `sentry_get_event`, `sentry_list_releases` | Resolve/reopen/assign issues, create releases |
| Artifactory | `artifactory_list_repositories`, `artifactory_search`, `artifactory_get_file_info`, `artifactory_get_build_info`, `artifactory_download` | Upload, copy/move, promote builds, delete |
| Snyk | `snyk_list_orgs`, `snyk_list_projects`, `snyk_list_issues`, `snyk_get_project` | SBOM retrieval, project import, approved scan execution |
| Mend | `mend_list_applications`, `mend_list_projects`, `mend_list_findings`, `mend_get_project` | Additional licensed product findings, reports, approved scan execution |
| AWS | `aws_get_caller_identity`, `aws_list_resources`, `aws_cloudwatch_filter_logs`, `aws_cloudformation_describe_stack`, `aws_cloudformation_stack_events` | S3/ECS/Lambda diagnostics, then selected service mutations |
| Playwright | `playwright_open`, `playwright_snapshot`, `playwright_click`, `playwright_fill`, `playwright_screenshot`, `playwright_close` | Tabs, console/network diagnostics, traces, test execution |

This proposes 58 tools across ten integrations. Discovery tools provide identifiers for subsequent
calls; findings and logs return actionable detail and explicit continuation
metadata. AWS resource discovery initially means a documented, bounded subset
through Resource Groups Tagging API, not a complete AWS inventory. Start Mend
with SCA findings; validate application/project terminology and endpoint
availability against Platform API 3.0 before freezing the schema.

Avoid unrestricted generic HTTP mutation tools in the initial release. Browser
navigation and interaction can change remote state, so they are not classified
as read-only simply because other initial integrations focus on diagnostics.

## Vendor-specific implementation decisions

### GitHub and GitLab

Implement native REST adapters with repository/project-scoped reads, file
retrieval at an explicit ref, PR/MR detail and diffs, issue detail, and CI
run/pipeline → job → log discovery. Preserve provider-specific schemas and
permissions, using the existing Bitbucket integration as an additional reference.
Bound file, diff, and log output; expose upstream diff truncation explicitly
and place oversized responses in the existing artifact system.

For GitHub, start with configured fine-grained personal access tokens and
document endpoint-specific permissions. Support GitHub.com and a configurable
Enterprise Server API base, including `/api/v3`; pin a tested API version
compatible with each documented server version. Implement Link pagination,
rate-limit handling, and credential-safe job-log redirects. Server-managed
GitHub App token minting/refresh is a later authentication extension.
Sources: [GitHub authentication](https://docs.github.com/en/enterprise-server@3.22/rest/authentication/authenticating-to-the-rest-api)
and [API versions](https://docs.github.com/en/enterprise-server@3.22/rest/about-the-rest-api/api-versions).

For GitLab, support GitLab.com and Self-Managed through a configurable API base
ending in `/api/v4`. Start with personal, project, or group access tokens through
`Authorization: Bearer`, with documented read scopes and resource access. This
is supported for these token types and avoids relying on redirect stripping
for the custom `PRIVATE-TOKEN` header. Explicit per-hop handling remains
required for all authentication schemes. Accept numeric
project IDs or correctly encoded namespace/project paths, distinguish scoped
issue/MR IIDs from global IDs, and handle endpoint-specific offset/keyset
pagination. Keep CI job tokens and OAuth lifecycle support outside initial
authentication scope. Sources:
[GitLab authentication](https://docs.gitlab.com/api/rest/authentication/) and
[REST conventions](https://docs.gitlab.com/api/rest/).

### Figma

Add a native REST adapter for file/node inspection, file component metadata,
rendered image exports, and comments. Accept a file key or validated Figma file
URL, with explicit node IDs and optional version selection. Initially users
supply the file reference; workspace-wide discovery is follow-on scope.
Start with a personal access token in `X-Figma-Token` and document the granular
scopes needed by each endpoint. OAuth lifecycle support is a later extension.
Sources: [authentication](https://developers.figma.com/docs/rest-api/authentication/),
[files and rendering](https://developers.figma.com/docs/rest-api/file-endpoints/),
and [components](https://developers.figma.com/docs/rest-api/component-endpoints/).

Bound document depth, node count, export dimensions, and response size. Fetch
temporary export URLs into owner-scoped artifacts through validated egress
without forwarding the API token to image hosts. Handle missing render results,
expired URLs, rate limits, and unavailable file versions explicitly. Test design
inspection → image export as the first complete workflow. Variable access is
subject to Figma plan/seat restrictions and belongs in a separately validated
extension. Arbitrary canvas editing is outside this REST integration's initial
scope. Source: [Variables API requirements](https://developers.figma.com/docs/rest-api/variables/).

### Vercel and Sentry

Use bearer-token authentication and preserve explicit team/organization/project
scope. Vercel uses endpoint-specific API versions; confirm the supported build
log endpoint and cap streams by time and bytes. Sentry needs cursor pagination
and configurable base URLs for supported hosted/self-hosted deployments.
Bound `sentry_get_event` bodies before JSON parsing, including large stack
traces, breadcrumbs, and contexts; return a bounded summary/artifact only when
the shared limits permit, otherwise a clear size error. Do not fetch event
attachments implicitly.
Sources: [Vercel REST API](https://vercel.com/docs/rest-api),
[Sentry API](https://docs.sentry.io/api/), and
[Sentry authentication](https://docs.sentry.io/api/auth/).

### Snyk

Support the documented API-token authorization scheme rather than assuming
Bearer. Pin a tested date version per supported REST endpoint and retain
JSON:API pagination/error details. Regional endpoints and account API access
must be checked during live validation. Reading existing findings does not
require running the scanner. Sources:
[authentication](https://docs.snyk.io/snyk-api/authentication-for-api) and
[REST versioning](https://docs.snyk.io/snyk-api/rest-api/about-the-rest-api).

### JFrog Artifactory

Use a configurable Artifactory URL and access token. Normalize the
`/artifactory` context once, including installations behind a reverse proxy.
Implement search through bounded, structured filters compiled to AQL; AQL uses
POST with a text body despite being a search operation. Stream downloads into
the existing artifact system with byte limits and checksums when available.
JFrog Xray is a separate future scope, not implied by Artifactory support.
Sources: [access tokens](https://docs.jfrog.com/administration/docs/access-tokens)
and [AQL endpoint](https://docs.jfrog.com/artifactory/reference/searchaql).

### Mend

Target Mend Platform API 3.0 first. Implement the documented login/refresh
exchange with email, user key, and organization UUID; cache tokens by instance,
organization, and credential identity, refresh without concurrent stampedes,
and invalidate on credential changes. Keep authentication responses out of
response artifacts and ordinary response caches. Support instance selection
and cursor pagination. Legacy WhiteSource APIs require a separate adapter if
the user's tenant needs them; do not silently mix API generations. Source:
[Mend API 3.0 setup](https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0).

### AWS

Use the official SDK credential provider chain for profiles, temporary
credentials, IAM Identity Center, and workload roles; let the SDK sign requests
and refresh credentials. Initially add STS, Resource Groups Tagging API,
CloudWatch Logs, and CloudFormation clients under an optional `aws` feature.
Constrain account, region, and service selection through server configuration
and existing authorization. Shared runtime credentials need explicit
attribution; never select arbitrary profiles or roles from tool arguments.
Map SDK responses into the common output/artifact pipeline. Verify SDK egress,
timeouts, retries, audit behavior, credential rotation, minimum Rust version,
and build cost before merging. The step-1 SDK spike must include a dependency
graph and cargo-deny report with the `aws` feature enabled: `deny.toml` rejects
new duplicate versions and its current graph configuration does not enable all
features. Identify every new duplicate, attempt compatible unification, and
document only necessary exact-version exceptions without weakening the global
ban, source, license, or advisory checks. Pin dependencies and keep the Rust
baseline unchanged unless a separate change is justified. Source:
[AWS Rust credentials](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credproviders.html).

### Playwright

Proposed approach: expose a fixed set of Rust tools backed by Microsoft's
Playwright MCP runtime over managed stdio. Map upstream browser tools to our
schemas; do not dynamically expose every upstream tool. Enable the needed
`rmcp` client capabilities only behind an optional `playwright` feature.
Use a pinned, preinstalled Node package and browser binaries, with no runtime
download requirement. The Rust server remains the public MCP endpoint.

Give each authenticated MCP session a separate isolated browser context and
owner-bound session handle. Enforce session limits, idle expiry, cancellation,
child-process cleanup, controlled download paths, and screenshot size limits.
Bound accessibility snapshots independently by node count, depth, text bytes,
and serialized MCP response bytes. Enforce an upstream message cap before
deserialization; do not materialize a huge snapshot just to truncate it later.
The pinned rmcp 3.1.2 provides
`rmcp::transport::async_rw::JsonRpcMessageCodec::new_with_max_length`; wire the
bounded codec into the managed read/write transport rather than its unbounded
`new()` default. Verify framing and oversize failure before JSON deserialization.
Use subtree selection where supported, explicit truncation markers, or a bounded
failure when the runtime cannot constrain output. Test real-page-shaped
snapshots exceeding 10 MiB and verify memory remains bounded.
Treat click/fill/navigation as potentially mutating. Browser subrequests,
redirects, WebSockets, and downloads need network enforcement outside the REST
transport; verify a container/proxy approach before enabling shared HTTP use.
If this cannot be proven initially, ship stdio support first and leave shared
HTTP browser support explicitly unavailable. Do not expose arbitrary JavaScript
execution or shell commands in the first tool set.

This runtime dependency is intentional: the official supported language list
does not include Rust. The first work package must prove the managed bridge,
policy integration, artifacts, and packaging before committing to it. Sources:
[Playwright languages](https://playwright.dev/docs/languages) and
[Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp).

## Large files and binary downloads — required shared contract

This is a release requirement for every integration, including SDK and browser
paths. Listing resources, reading metadata, and inspecting a PR/MR must not
implicitly download attachments, repository archives, Git LFS objects, release
assets, build artifacts, or linked files. File-content tools return metadata
and a clear size/type limitation when content cannot be safely previewed.
Only an explicitly requested download/export operation retrieves binary data.
Binary support in the initial scope is Artifactory downloads and Figma/browser
image exports; other binary download capabilities remain follow-on scope.

### Reuse the existing log streaming pipeline

Implementation decision: reuse the log download infrastructure directly.
`fetch_streamed_artifact_with_policy` handles authenticated vendor downloads;
`fetch_streamed_url` currently fetches absolute unauthenticated/signed URLs but
has the unresolved egress/attribution gaps below. It is not yet suitable for new
vendor download flows as-is. Both use
`persist_decoded_response` and the existing artifact writer. The persistence
path writes byte chunks, not strings, so it already supports binary payloads
after HTTP content decoding. The writer already computes a checksum and
commits through a temporary file. No separate binary downloader is planned.

Keep log parsing, normalization, and head/tail text rendering in log-specific
controllers. Binary tool responses use artifact metadata only; suppress text
preview rendering (and, if useful, head/tail collection) for binary artifacts.
Reuse owner checks, retention, chunk reads, cancellation, and disk accounting.
For SDK/browser sources, adapt their byte streams to the existing writer and
shared budgets rather than duplicating persistence. Their source-specific
network authorization still needs separate integration.

### Known transport gaps — step-1 prerequisites

1. **Absolute URL authorization and attribution.** `fetch_streamed_url` does
   not call `authorize_egress` and labels HTTP logs `streaming-url`. Carry the
   originating vendor/tool/principal and authorize the actual absolute
   destination before every request, recording allowed/denied attempts under
   that identity. Extend the policy context unconditionally with a validated
   destination origin (scheme, host, effective port). `CanonicalTarget` currently
   contains only path/query and `ActionDetails` has no origin; neither can
   authorize a signed URL's host. Include origin in policy evaluation and audit
   attribution, with explicit semantics for existing policies. Authorizing only
   a relative path under the vendor base is insufficient.
   Cover direct signed URLs as well as redirects, without persisting signed
   query credentials. Migrate existing callers too.
2. **Implicit redirects.** Neither `build_client` nor `streaming_client` sets
   a redirect policy today. Set `reqwest::redirect::Policy::none()` on both and
   implement bounded, manually authorized follows where endpoints require them.
   Validate each resolved Location, scheme, origin, and applicable network
   restrictions before sending; handle relative URLs, loops, hop limits, and
   method/body semantics. Use one total deadline and aggregate budget across
   hops/retries. Reject unsupported redirects explicitly. The inaccurate
   cross-host guarantee in `src/policy/canonical.rs` has been corrected in this
   planning revision; implementation must replace it with tested behavior.
   Treat the shared-client flip as a compatibility change: document changed
   redirect behavior and migration in release notes, bump the Cargo package
   version, and keep the release tag aligned. Ship manual supported-endpoint
   behavior and its regression tests together with the default change.
3. **Custom-header credential leakage.** Do not rely on reqwest's built-in
   sensitive-header removal to protect `PRIVATE-TOKEN` or `X-Figma-Token`.
   Rebuild each request's headers from an explicit destination-aware allowlist;
   cross-origin export requests must carry no originating API credentials.
   Use Bearer for GitLab. Figma PAT requests still need `X-Figma-Token`, so
   Figma export support cannot ship before this fix.

Required regression tests: denied direct absolute URL produces no upstream
request; allowed requests retain vendor/principal attribution; GitHub-style
302 to an allowed signed URL succeeds without API credentials; cross-host and
same-host forbidden-path redirects are blocked before the next request; custom
token headers never reach a second origin; relative redirects and loops are
bounded; signed queries remain redacted. Exercise shared and streaming clients
and existing log callers, not just new adapters. Also cap non-success response
bodies at all three current non-success sites in `src/transport/mod.rs`:
`fetch_streamed_artifact_with_policy` (line 1092), `fetch_streamed_url` (line
1307 at the reviewed baseline; locate by function), and shared `fetch` (line
1593). All call `response.text()` without an actual streamed body cap; the
shared path's declared-length check does not cover absent or false lengths.
Use a common bounded error-body reader with byte and time budgets and test
all three with missing/false lengths, compressed expansion, and slow errors.
Track these fixes with the three transport gaps in CF-15 of
[the carry-forward document](enterprise-carry-forward.md#cf-15--response-provided-absolute-urls-bypass-canonicalization).
Keep this plan, the CF-15 update, and the canonicalizer comment correction in
one documentation commit so their tracking statements remain true at that
commit boundary; this planning edit does not create a commit.

The current `src/constants.rs` defines a 10 MiB response limit, a 512 MiB
streamed-artifact limit, a 64 KiB write buffer, a 15-second idle timeout, and a
two-minute streaming deadline. `src/transport/mod.rs` already provides encoded
and decoded byte counters, aggregate accounting, cancellation, and coordinated
streaming disk reservations. `src/transport/raw_response.rs` owns artifact
lifecycle. Audit and extend these primitives; do not create independent,
unbounded download code in each connector. These existing constants are not
proof that all new paths are covered.

Use existing limits and disk reservation semantics as the baseline. First
verify how reservations cover active and retained artifacts; extend only
demonstrated gaps such as principal-level concurrency or image pixel limits.
The previously suggested 50 MiB file cap and additional storage quotas are not
accepted defaults: choose endpoint-specific lower limits only with a concrete
need, without introducing a competing quota system. Any configurable limits
must remain operator-controlled; tool arguments may lower but never raise them.

### Transfer and storage rules

- Check trusted metadata or HEAD when available, but do not depend on HEAD or
  `Content-Length` for enforcement. Count actual bytes on every stream,
  including chunked responses, missing/incorrect lengths, HTTP decompression,
  and aggregate work across retries and multi-file calls. Abort at the cap.
- Stream to a private temporary artifact using bounded buffers. Never read an
  entire binary into a `Vec`, string, JSON parser, or base64 response. Preserve
  the file payload byte-for-byte after HTTP content decoding; do not apply log
  normalization or text previews to arbitrary bytes. Distinguish a compressed
  file from HTTP `Content-Encoding`.
- Use idle and total deadlines, cancellation, bounded concurrency, and disk
  reservations across both active and retained artifacts. Handle disk-full and
  quota failures explicitly. Clean incomplete files on failure/cancellation and
  recover stale temporary files after a crash; publish artifact handles only
  after successful completion. Reuse retention sweeps and reject new downloads
  when quotas cannot be met without deleting an active artifact.
- Validate every redirect and destination under egress policy. Never forward
  API tokens, cookies, or authorization headers to a different origin. Keep
  signed download URLs out of audit logs and tool output. Treat browser
  downloads and AWS SDK streams as independent paths requiring the same proof.
- Generate local names and keep files inside private artifact storage. Do not
  use caller paths or `Content-Disposition` filenames as filesystem paths;
  reject traversal/symlink escapes and keep downloaded files non-executable.
- Calculate SHA-256 while streaming and verify a compatible upstream checksum
  when supplied. Do not interpret ETags as universal checksums or claim a
  locally computed hash proves source authenticity. Mark truncated transfers
  incomplete, never as successful binary artifacts.
- Store ZIP/TAR and other archives as opaque files. No automatic extraction or
  execution. If CI log inspection later needs archive extraction, require a
  dedicated bounded extractor with limits on entries, expanded bytes, nesting,
  and paths, rejecting links and traversal. That is separate from HTTP decoding.
- Resume from the upstream service only with validated range support and a
  stable object validator; otherwise restart within the same overall budgets.
  Reading chunks from a completed local artifact is a separate capability.

### MCP output and previews

Return an owner-scoped artifact handle, sanitized display name, media type,
actual byte count, SHA-256, expiry, and completion status. Never place an entire
binary or its base64 encoding in normal tool output. Use the existing
`artifact_read` for explicitly requested, bounded chunks, with limits measured
after base64 expansion and owner authorization on every read.

Text previews must have independent byte/line caps and preserve a truncation
indicator. Validate text encoding and content rather than trusting an extension
or `Content-Type`; unknown or mismatched types receive metadata only. Images
may produce a separately bounded preview with pixel/dimension and decoder
limits. Never inline SVG/HTML as active content or decode an arbitrary binary
as text. Binary bodies bypass ordinary response caches and text formatting.

### Required download tests

Use synthetic streams and local fixtures, not actual giant downloads: missing
or false length headers; a response just over each limit; endless chunked or
slow streams; compressed expansion; binary labeled as text; non-UTF-8 content;
oversized image dimensions; denied redirects and credential stripping; filename
traversal; checksum mismatch; cancellation; disk exhaustion; concurrent quota
contention; retries consuming aggregate budgets; startup cleanup; expired
artifacts; and cross-principal chunk access. Assert bounded memory and disk
use, removal of partial files, and no success handle for a failed download.
Include browser and SDK adapters in these checks when their download paths
are introduced.

## Deterministic retry handling and performance telemetry

No bandit or RL implementation workstream is included in this expansion.
Preserve client-specified limits, pagination, node depth, subtrees, and output
detail. The server must not silently vary those arguments. Internally batching
several upstream pages to fulfill the same bounded request is a narrower
implementation choice, not a priority learning opportunity. Job polling is
client-driven today; do not add server-side wait loops to manufacture a learner's
action space. Workflow RL belongs in a separate orchestration layer with task
outcomes. Preview learning needs explicit feedback; absence of follow-up reads
does not establish success.

### Step 1: honor Retry-After before considering adaptive backoff

The current transport retry loops do not honor `Retry-After`. Add a common
parser for both delay-seconds and HTTP-date forms, using the existing `httpdate`
dependency. Honor valid delays on responses that are already eligible for
retry, within cancellation, total deadline, attempt, and aggregate-byte budgets.
Never shorten the vendor's requested delay to squeeze in another attempt; if
it exceeds the remaining budget, return a bounded error with retry timing
metadata. Missing or malformed values use a documented, jittered fallback.
Today's code uses `100 ms * 2^min(attempt, 5)` without jitter. Retain that bounded
exponential envelope but sample equal jitter uniformly between half the envelope
and the full envelope, independently per retry, to spread synchronized partition
retries. Inject randomness/time in tests so bounds and cancellation are
deterministic to verify. Valid Retry-After delays are a floor: any jitter added
to them must be nonnegative and fit the remaining deadline. Past dates mean no
additional server-requested delay. Preserve retry eligibility
and idempotency rules, and do not introduce retries for mutations or job polls.
For shared paths that return without retrying, preserve parsed timing metadata
for clients. Coordinate with the manual redirect path for Retry-After on 3xx.
Reference: [HTTP Retry-After semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after).

Test delay-seconds, HTTP dates, missing/invalid/overflowing values, past dates,
deadline exhaustion, cancellation, and no early retry. Verify all existing
retrying paths use the parser without stacking a second retry loop around SDKs.
Test jitter bounds and synchronized partition retries with controlled randomness;
do not use a flaky assertion that real random samples must differ.

### Steps 2–3: instrument existing decisions, without exploration

Extend the metadata-only usage/metrics path (`src/ports/usage_sink.rs`,
`src/rollups/consumer.rs`, `src/ports/rollup_store.rs`, `src/rollups/sqlite.rs`).
Use a versioned performance event or compatible schema extension, bounded
non-blocking delivery, retention, and counted drops. Where telemetry is disabled
or the sink is a no-op, report that no evaluation dataset is being collected.
Current usage emission in `DevtoolsServer::record_outcome` requires an
`EnterpriseCall`; local stdio never constructs one. Extending that event alone
would collect no Community/local transfer evidence. Implement **mode-independent
transfer instrumentation** with an explicit performance context and sink passed
to the transfer/partition machinery, independent of `EnterpriseCall` and audit
scope. Wire a bounded local metrics consumer/storage path when collection is
enabled in Community or local stdio, as well as the Enterprise HTTP composition.
Collection remains explicitly configurable; it must not require Enterprise mode.
Use a deployment-local opaque scope for unauthenticated local calls, never a
fabricated authenticated tenant/principal. Include deployment mode in records
and keep local scopes separate from authenticated tenant state. Avoid duplicate
transfer events when the enterprise outcome hook also emits tool usage.
Acceptance tests must prove retained decision/outcome records for an enabled
local stdio transfer and an enabled Enterprise HTTP transfer, counted drops under
pressure, and no records when collection is disabled. A wired sink with no
emission or consumer does not meet the telemetry milestone.
Do not put decision telemetry in the checkpointed audit journal or alter audit
durability; ordinary authorization and outcome evidence remains unchanged.

Record tenant, vendor, opaque upstream account/quota scope, endpoint class,
timestamp, bounded workload features, eligible execution strategies, selected
strategy, selection probability, strategy version, queue wait, concurrency,
bytes, duration, throttle/retry counts, parsed retry delay, completion/error,
and telemetry sampling/drop information. Do not log arguments, payloads, URLs,
or credentials. For a deterministic decision the selected action's probability
is 1; when there is no strategy decision, mark it inapplicable. Do not invent
counterfactual actions or outcome rewards. Preserve bounded decision/outcome
records where collection is enabled; aggregate rollups alone lose the joint
observations needed for later off-policy analysis.

Instrument the shared transfer machinery so the existing Grafana/Splunk time
partitions and CircleCI download semaphore also supply observations. These are
server-owned concurrency choices; current Grafana/Splunk partition concurrency
is config-bounded and CircleCI uses a fixed semaphore of 16. Instrumentation
must not change those choices or observable result semantics.

If data later justifies an experiment, evaluate time-partition concurrency
first, comparing fixed configuration and AIMD (additive increase, multiplicative
decrease) before a bandit. A bandit must show an improvement over AIMD at equal
work completion, quota cost, and operator bounds. Scope any future adaptive
state by **tenant × vendor × upstream quota/account scope**, not globally by
vendor or separately by principal; never pool state across tenants. Include
decay/reset behavior for quota, plan, and workload changes. Production
exploration is **0% in this plan**; a future proposal needs operator opt-in and
explicit maximum exploration fraction plus per-tenant/vendor request and byte
budgets, with fallback on exhaustion. Exploration must not issue extra vendor
calls just to gather labels. Deterministic telemetry alone cannot evaluate
unsupported alternative actions, and concurrency also couples request outcomes.

Authorization, egress allowlists, credential handling, byte/disk caps, and
vendor enablement remain deterministic regardless of future experimentation.

## Configuration proposal

Preserve process environment → working-directory `.env` → vendor sections in
`~/.mcp/configs.json`. Register secret fields with the existing secret mechanism;
credentials never become tool arguments. These names are proposed:

Required means required when that integration is called, not at process startup.
Optional scope defaults can be supplied by tool arguments where documented;
configuration precedence does not make vendor-specific requirements generic.

| Vendor section | Required when used | Optional/defaulted |
|---|---|---|
| `github` | `GITHUB_TOKEN` | `GITHUB_API_BASE` (GitHub.com), `GITHUB_API_VERSION` (tested default) |
| `gitlab` | `GITLAB_TOKEN` | `GITLAB_API_BASE` (GitLab.com API v4) |
| `figma` | `FIGMA_TOKEN` | None initially; file reference supplied in tool arguments |
| `vercel` | `VERCEL_TOKEN` | `VERCEL_TEAM_ID` (scope default) |
| `sentry` | `SENTRY_TOKEN`; organization in arguments or config for org-scoped calls | `SENTRY_ORG` (scope default), `SENTRY_URL` (hosted default) |
| `artifactory` | `ARTIFACTORY_URL`, `ARTIFACTORY_TOKEN` | None initially |
| `snyk` | `SNYK_TOKEN`; org in arguments or config for org-scoped calls | `SNYK_API_BASE` (hosted default), `SNYK_ORG_ID` (scope default) |
| `mend` | `MEND_API_BASE`, `MEND_EMAIL`, `MEND_USER_KEY`, `MEND_ORG_UUID` | None initially |
| `aws` | Resolvable SDK credentials and region for regional operations | `AWS_PROFILE`, `AWS_REGION` when available through SDK defaults; operator account/service constraints |
| `playwright` | `PLAYWRIGHT_ENABLED=true` and installed, trusted runtime/browser | Runtime location overrides and browser/session limits |
| global | None | `MCP_ENABLED_VENDORS` (`auto`, explicit allowlist, or `all`) |

AWS credentials follow SDK precedence, documented as an explicit exception to
the generic vendor configuration resolver. Any future bridge from configured
secret sources must preserve temporary credential expiry and identity scoping.

## Delivery sequence and completion criteria

1. **Shared prerequisites and early spikes.** Close the three named transport
   gaps above (absolute URL egress/attribution, implicit redirects, and custom
   header leakage), bound error bodies, honor Retry-After as specified above,
   and add their regression tests. Deliver
   configured-vendor listing/call filtering, compatibility behavior, measured
   inventory size, and corrected counts. Establish the shared download contract
   by testing existing primitives and filling demonstrated gaps.
   **Releasable done state:** these shared fixes and filtering work with existing
   vendors and pass their regression checks; no new connector is required.
   Include the redirect-dependency inventory, filtered-list cache tests, hot-reload
   semantics, and release notes for both redirect behavior and the `auto` default.
   Bump `Cargo.toml`/the root lockfile package version when this behavior ships;
   this documentation revision alone does not bump the version.
   Start separate Mend auth, AWS SDK/policy/dependency, and Playwright runtime
   spikes early. Each outputs an endpoint/auth/scope matrix, executable fixture
   proof, and limitations for its own vendor. AWS includes the explicit
   cargo-deny duplicate-version impact report. These vendor-specific spikes
   gate only their dependent integrations, not the shared-fix release or REST work.
2. **GitHub and GitLab.** Deliver separate REST integration changes for repository
   discovery, file reads, PR/MR review, issue inspection, and CI diagnostics.
   Validate hosted and documented self-hosted versions, permissions, nested
   namespaces, pagination, truncated diffs, and log redirects before completion.
   **Releasable done state:** each vendor independently supports repository →
   PR/MR/issue → CI failure diagnosis, with its own tests, configuration and docs.
   **Telemetry is bundled, not a gate:** add the versioned fields above to the
   metrics/rollup path and mode-independent shared transfer instrumentation;
   keep exploration disabled. If telemetry slips, release either vendor with
   collection clearly marked unavailable and track the telemetry work separately.
3. **Vercel and Sentry.** Deliver two separate REST integration changes with
   discovery, diagnostics, scoped credentials, bounded logs, and documentation.
   **Releasable done state:** Vercel deployment/log diagnosis and Sentry
   issue/event diagnosis can each ship alone after their own checks pass.
   **Telemetry is bundled, not a gate:** extend and validate mode-independent
   coverage, tenant/quota scoping, bounded storage, counted drops, and unchanged
   audit checkpoints. It can follow either vendor release; no adaptive policy ships.
4. **Figma.** Deliver file/node inspection, components, image exports, and
   comments. Validate granular token scopes, large documents, missing nodes,
   partial renders, expiring export URLs, and artifact isolation.
   **Releasable done state:** file inspection → bounded image artifact retrieval
   works, with comments/components and the shared transport regressions covered.
5. **Artifactory.** Add repository discovery, structured search, metadata, build
   information, and streamed downloads. Prove context-path handling and artifact
   ownership/size enforcement.
   **Releasable done state:** search → metadata → verified bounded download works
   with tests and configuration/runbook examples; other vendors are not required.
6. **Snyk and Mend.** Deliver separately; test Snyk versioning and Mend token
   refresh/rotation. Return findings with project, severity, location/dependency,
   and remediation details where supplied by the API. Preserve vendor-specific
   fields rather than prematurely inventing a common security schema.
   **Releasable done state:** each vendor separately supports project discovery →
   actionable findings with tested authentication, pagination, and documentation.
7. **AWS.** Ship the bounded service set behind its feature flag. Prove identity,
   region/account scoping, pagination, expired credentials, and SDK transport
   enforcement. Publish the precise discovery coverage and required IAM actions.
   **Releasable done state:** the five-tool SDK scope works with the feature on,
   disappears cleanly with it off, and passes the expanded dependency/CI gates.
8. **Playwright.** Ship the validated runtime bridge, initially Chromium. Add
   local fixture-site browser tests and a separate browser-enabled container
   target. Prove session isolation and cleanup before enabling HTTP sessions.
   **Releasable done state:** the six tools work in documented stdio deployments
   with bounded snapshots/images and lifecycle tests. Shared HTTP browser mode
   can ship later after isolation and network enforcement are proven.
9. **Incremental release validation and follow-on writes.** For each release,
   validate only the completed integrations plus existing-vendor regressions and
   relevant feature combinations. Update inventories/examples and keep unfinished
   integrations unadvertised. **Releasable done state:** that release's selected
   scope passes its checks with documented live-test limitations. Define later
   deployment, publishing, scan, PR/MR, CI-trigger, and issue-write changes
   separately; avoid automatic retries of non-idempotent operations.

Every numbered milestone is independently releasable after its actual shared
prerequisites. Paired vendors can ship separately. Overall completion of all ten
is a roadmap milestone, not a release gate. Follow the existing version/tag
workflow: `Cargo.toml` is the version source of truth and release tags must
match it. Planning does not create or push release tags.

## Validation and definition of done

- Use existing `wiremock` tests for request shape, auth, pagination, empty
  results, vendor errors, rate limits, timeouts, and oversized responses.
- Test missing credentials at call time, configuration precedence, secret
  redaction, credential rotation, tenant isolation, redirect/egress enforcement,
  and audit attribution. Verify authentication payloads are never persisted.
- Test MCP discovery and calls over stdio and HTTP where supported; disabled
  feature builds must omit optional tools cleanly and preserve existing tools.
- For GitHub/GitLab, test private-repository permission errors, ref/path encoding,
  project-scoped IIDs, pagination boundaries, partial diffs, and large CI logs.
  Verify redirected downloads never forward API credentials across origins and
  test the documented Enterprise Server/Self-Managed compatibility matrix.
- Use mock SDK transports and local browser fixtures for deterministic tests.
  Optional live smoke tests need configured test accounts and report skips
  explicitly; fixture success alone does not establish vendor compatibility.
- Run existing formatting, Clippy, tests, and dependency checks from
  `.github/workflows/rust.yml`; expand the matrix for `aws`, `playwright`, their
  combination, and headless builds. Check Windows/macOS/Linux runtime packaging.
- Update `README.md`, `docs/configuration.md`, `examples/configs.json`, tool
  descriptions, and affected Compose/Helm/package documentation. Record Node
  and browser requirements, vendor API availability, and optional build flags.
- Each vendor is done when its own proposed initial workflows work in documented
  deployment modes, its applicable checks pass, existing integrations retain
  their behavior, and live verification limitations are visible. No vendor waits
  for the other nine; follow-on writes remain separate scope.
- Measure the response-pipeline allocation baseline at implementation phase
  boundaries as required by `CLAUDE.md`, investigating material regressions.
  Documentation-only planning revisions do not change that pipeline.
- No download/export tool ships until the shared large-file/binary contract is
  enforced and its applicable failure-path tests pass.

## Assumptions to resolve during implementation

The plan defaults to AWS operational diagnostics, Snyk/Mend existing SCA
findings, Artifactory without Xray, and a Playwright sidecar. Before their
dependent live checks, obtain the AWS services/accounts/regions of interest,
Mend tenant/API generation and enabled products, hosted/self-hosted URLs and
GitHub/GitLab server versions and repository/project scopes, Figma test file
references and token scopes, and
whether browser deployment permits Node/Chromium. These do not block planning
or the common REST implementation work.
