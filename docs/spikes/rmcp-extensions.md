# Spike WP 0.5: does `RequestContext::extensions` propagate a per-request principal through rmcp 3.1.2 streamable HTTP into `call_tool`?

Status: **answered — yes, on every relevant path.** Runnable proof:
`tests/rmcp_extensions_spike_tests.rs`. Decision recorded in
`docs/enterprise-product-plan.md` §0 (rev 2.2); the §9 risk-register entry
"rmcp does not propagate request extensions" is closed, and the
session-keyed fallback is **not** implemented.

## Question

Phase A's design (§3.7) wants the bearer middleware to attach a validated
`Principal` to the axum request and `DevtoolsServer::call_tool`
(`src/tools/mod.rs`) to read it from `context.extensions`. That only works if
rmcp `=3.1.2` carries per-HTTP-request state into the `RequestContext` it
hands the server handler — on **both** HTTP dispatch models:

- the stateless model (MCP 2026-07-28 self-contained requests), and
- the legacy session model (initialize → `Mcp-Session-Id` → per-session
  worker task), where the JSON-RPC message crosses a channel into a
  long-lived service task.

## Finding

rmcp 3.1.2 injects the request's `http::request::Parts` — which contains the
axum/tower extension map, and therefore anything a middleware inserted —
into the JSON-RPC message's extensions on **all four** POST handling paths
(`src/transport/streamable_http_server/tower.rs` in the vendored crate
source, `~/.cargo/registry/src/*/rmcp-3.1.2`):

| Path | Injection site |
|---|---|
| Stateless, per-request negotiated (`Mcp-Method` header) | `tower.rs:1211` (`serve_negotiated_request_directly`) |
| Session POST (existing `Mcp-Session-Id`) | `tower.rs:1764-1770` (requests *and* notifications, before `SessionManager::create_stream`) |
| Initialize (session creation) | `tower.rs:1847` |
| Stateless, non-negotiated | `tower.rs:1966` |

The message then travels (in-process — `Extensions` is never serialized, so
nothing is lost crossing the session channel) into the service loop, which
**moves** the message's extensions into the `RequestContext` it builds for
the handler (`src/service.rs:1560-1571`: `std::mem::swap(&mut extensions,
request.extensions_mut())` → `RequestContext { extensions, .. }`).

This is not incidental: it is documented API. The doc comment on
`StreamableHttpService` (`tower.rs:977-998`) shows exactly the pattern
Phase A needs:

```rust,ignore
let parts = ctx.extensions.get::<http::request::Parts>().unwrap();
let state = parts.extensions.get::<AppState>().unwrap();
```

## Proof

`tests/rmcp_extensions_spike_tests.rs` stands up a minimal rmcp
`ServerHandler` (not `DevtoolsServer` — the production tool surface is
golden-locked and stays untouched) behind a `StreamableHttpService`
configured like production (`with_stateless_protocol_metadata_required(true)`),
with an axum `Extension` layer inserting a marker principal. The handler's
`call_tool` reads `context.extensions → http::request::Parts →
parts.extensions → SpikePrincipal` and echoes what it found. Both tests pass:

- `stateless_call_tool_sees_the_axum_extension_principal`
- `session_call_tool_sees_the_axum_extension_principal` (initialize →
  initialized → tools/call on the session)

## Consequences for Phase A

- The bearer middleware inserts `Principal` via `Request::extensions_mut()`
  (or an `Extension` layer); `call_tool` reads
  `context.extensions.get::<http::request::Parts>()` and then
  `parts.extensions.get::<Principal>()`.
- No session-keyed principal map is needed; sessions still get a fresh
  `Parts` per POST, so a rotated/revoked token is re-observed on the next
  request, not frozen at initialize time.
- Stdio has no `Parts`; absence of the extension marks local mode
  (`Principal::local()`), which is also the loopback-HTTP-without-auth case.
- One coupling to watch on rmcp upgrades: the injected type is
  `http::request::Parts` from the `http` crate — the lookup is `TypeId`-based,
  so the workspace must keep resolving a single `http` major version (it
  does today; `cargo tree` shows one `http v1.x`). A future rmcp bump gets a
  re-run of this spike's tests for free in CI.
