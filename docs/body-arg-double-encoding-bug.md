# `body: Value` args can arrive pre-stringified, breaking write tools

**Status:** reproduced live against `dev-backup2.ninjarmm.com`, 2026-08-24, for `ninjaone_post`
only. Fixed in this branch by advertising `body` as an object; live Claude Code acceptance is
still pending.
**Blast radius:** every `*_post` / `*_put` / `*_patch` tool across all vendors shares the same
vulnerable schema shape — `WriteArgs` (bitbucket, circleci, confluence, jira, postman, slack,
zoom) and `NinjaOneWriteArgs` (`ninjaone_post/put/patch`) both declare `pub body: Value`
(`src/tools/args.rs:160` and `:216`) with no `"type"` in the generated schema before this fix,
confirmed via
the checked-in tool-surface snapshot for `bb_post` and `ninjaone_post`. Only `ninjaone_post`
has actually been reproduced failing; the rest share the schema defect but are **not yet
confirmed** to fail the same way in practice.

## Symptom

Calling `ninjaone_post` with a perfectly valid JSON object body — even the trivial case —
fails with a 400 from the downstream API:

```
mcp__ninjaone__ninjaone_post(
  server: "dev-backup2-1",
  path: "/backup/lockhart/scheduled-deletion",
  queryParams: {"page": "0", "size": "25"},
  body: {}
)
```

```json
{
  "issueToken": "AGENT_SERVICE-main-dev-backup2-1787588157-TUCIRSSC",
  "reason": "Cannot construct instance of `com.ninjarmm.core.dto.lockhart.ScheduledDeletionFilterRequest` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('{}')"
}
```

Jackson's error is the tell: it says it received a **String** value `'{}'`, not a JSON
object. The bytes that actually crossed the wire to the NinjaOne console API were the
literal 4-byte string `"{}"` (quoted) instead of the 2-byte object `{}`. This reproduced
identically with a real, non-trivial filter payload (`organizationIds`, `sortField`, etc. —
same shape as the working `.http` request that succeeds via curl/PowerShell using the exact
same JSON), and with both pretty-printed and single-line formatting of the body argument.
Calling the real API directly (bypassing this MCP tool, replaying the console login flow by
hand) with the identical JSON body succeeds and returns real data — ruling out the endpoint
or the DTO as the cause. The bug is isolated to how the tool argument gets from the calling
client (Claude Code, in this case) into this server's tool-call handler.

## What the evidence actually shows

Compare the JSON Schema this server emits for two arguments on the same tool
(`ninjaone_post`, generated from `NinjaOneWriteArgs` in `src/tools/args.rs`), confirmed via
the checked-in tool-surface snapshot for `bb_post` and `ninjaone_post`:

```jsonc
// queryParams — type is explicit
"queryParams": {
  "type": ["object", "null"],
  "additionalProperties": { "type": "string" }
}

// body — no "type" at all
"body": {
  "description": "JSON request body expected by the selected endpoint."
}
```

`queryParams` is `Option<QueryParams>` where `QueryParams = BTreeMap<String, String>`
(`src/tools/args.rs:42`) — `schemars` emits a concrete `"type": "object"` for that. `body` is
plain `serde_json::Value` (`WriteArgs::body` at `src/tools/args.rs:160`,
`NinjaOneWriteArgs::body` at `src/tools/args.rs:216`), and `schemars`' impl for
`serde_json::Value` is intentionally permissive — it emits `{}` (any type valid), with no
`"type"` key. Both of those schema facts are confirmed.

On the server side, the controller preserves `args.body` as a `Value` untouched
(`src/controllers/ninjaone.rs:119`, `Some(args.body.clone())`), and the outbound request is
built with a single `req.json(body)` call (`src/transport/mod.rs:1749-1750`) — one
serialization pass, using reqwest's own `Serialize` impl, not a manual
`to_string`-then-embed. **The server does not double-encode an object.** So for the observed
`no String-argument constructor ... to deserialize from String value ('{}')` failure to
happen, `options.body` must already have been `Value::String("{}")` — not `Value::Object`
— by the time it reached that call. That much is proven by the code path, independent of any
client.

What is **not** proven yet is *why* it arrived as a string. The leading hypothesis is that
Claude Code's MCP argument encoder uses the absence of an explicit `"type": "object"`/`"array"`
on `body`'s schema to decide to transmit the argument as an opaque string rather than a
nested JSON value — which would exactly explain the symptom, and is consistent with
`queryParams` (which does declare a type) working correctly in the same tool call. But this
is inferred from the schema diff and the observed wire-level effect, not from a captured
`tools/call` JSON-RPC request. Confirming the client-side mechanism requires logging (or
otherwise capturing) the raw incoming MCP request for a reproduction call and checking
whether `params.arguments.body` is a JSON string or a JSON object at that point.

## Blast radius: potential, not confirmed

`WriteArgs` (the same `body: Value` shape) backs `bb_post`, `bb_put`, `bb_patch`,
`circleci_post/put/patch`, `conf_post/put/patch`, `jira_post/put/patch`,
`postman_post/put/patch`, `slack_post/put/patch`, and `zoom_post/put/patch`. All of these
expose the identical schema gap and are therefore **potentially** exposed to the same failure
mode with a client that behaves like the one observed here. Only `ninjaone_post` has actually
been exercised and shown to fail this way; the others have not been reproduced and should be
treated as suspect, not confirmed, until tested.

## Implemented fix

Give `body` an explicit object-shaped schema instead of the fully-open `Value` schema, so
schema-driven clients get the same signal `queryParams` already gives them, without changing
the runtime type the controller/transport code sees. The implementation uses a schema-only
override, leaving the field's Rust type as `Value`:

```rust
#[schemars(with = "std::collections::BTreeMap<String, Value>")]
pub body: Value,
```

on both `WriteArgs::body` and `NinjaOneWriteArgs::body`. This advertises `"type": "object"`
in the generated schema while leaving deserialization, the controller, and
`src/transport/mod.rs` untouched — `Value` still accepts whatever the client actually sends.
Prefer this over widening the advertised type to `"object" | "array"`: every documented
example body across every vendor tool description is a JSON object, and a wider union type
may itself confuse schema-driven clients rather than help them.

Coverage included with the fix:

1. A generated-schema regression test asserts `body` has `"type" == "object"` for both
   `WriteArgs` and `NinjaOneWriteArgs`. The pinned full tool-surface snapshot verifies the
   resulting schema on all 24 shared write tools.
2. A NinjaOne integration test deserializes tool arguments containing `body: {}`, sends them
   through the controller and transport into `wiremock`, and asserts the received request
   bytes are `{}`, not `"{}"`.

Still pending:

3. A captured incoming `tools/call` request (raw JSON-RPC) for one failing call,
   to move the client-side explanation from "leading hypothesis" to confirmed before treating
   the issue as fully understood.

## Acceptance test after applying the fix

The schema override alone is not sufficient evidence of a fix. The decisive test is
reproducing the original failing call from Claude Code against `dev-backup2` (or an
equivalent client) and confirming all three of:

1. The advertised schema for `body` now shows `"type": "object"`.
2. The captured JSON-RPC request contains `params.arguments.body` as a JSON object, not a
   JSON string.
3. The resulting downstream HTTP request body is the literal bytes `{}` (or the real filter
   payload), not `"{}"` (or an escaped/quoted string).

All three passing is what closes this issue — (1) alone only proves the schema changed, not
that the client's behavior changed in response to it.

## Reproduction notes

- Confirmed with `ninjaone_post` against `dev-backup2-1` alias, path
  `/backup/lockhart/scheduled-deletion`, both with a real filter body and with `body: {}`.
  Both produced the identical string-value symptom, ruling out payload shape as a factor.
- Workaround used to unblock testing: replicated the console's 3-step login exchange
  (`/ws/account/authentication-state` → `/ws/account/login` → `/ws/account/mfa-login`,
  documented in `src/vendor/ninjaone/session.rs`) directly via PowerShell
  `Invoke-RestMethod`, using the same `NINJAONE_EMAIL`/`NINJAONE_PASSWORD`/`totpSecret`
  already configured for the `dev-backup2-1` alias in `~/.mcp/configs.json`, then called the
  target endpoint with `Invoke-RestMethod -Body (@{...} | ConvertTo-Json)` — which correctly
  sends a single-encoded JSON object and works.
