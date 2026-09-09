# CircleCI status freshness investigation

Pipeline 5185 / workflow `df722a5b-dd0f-437c-a426-efbda3a7a597` was reported
successful at `2026-09-09T16:36:36Z`, while identical job polls returned `running`.

## Evidence

The local audit file
`~/.mcp/data/mcp-server-devtools.a396c6d4-f570-4ef2-9c46-b2f0914ec428.audit.jsonl`
records the following events on 2026-09-09 (UTC):

| Time | Event | Evidence |
| --- | --- | --- |
| 16:34:18 | Job list fetched and admitted | Resource fingerprint `60d265cea9c98bc9`, key `3d5a47201c762f06`, upstream latency 168 ms, fallback TTL 600,000 ms |
| 16:36:31 | Identical poll hits local cache | Age 134,089 ms; tool duration 0 ms |
| 16:37:24 | Identical poll hits local cache after reported completion | Age 186,574 ms; tool duration 0 ms |
| 16:38:17 | Identical poll hits local cache again | Age 240,178 ms; tool duration 0 ms |
| 16:39:07 | Query variant fetches upstream | Same resource fingerprint, different key `72f9c3c39e6fc508`; miss; upstream latency 118 ms |

The resource fingerprint was independently reproduced using the cache's SHA-256
algorithm over `circleci`, a NUL separator, the exact job endpoint URL, and a
trailing NUL. It matches `/workflow/df722a5b-dd0f-437c-a426-efbda3a7a597/job`.
The audit logs omit bodies and query values; the `running`/`success` contents and
`_fresh` query name come from the incident report. The logs independently prove
that the identical polls were served by this process's cache, without HTTP.

## Request path and cause

`circleci_get` → CircleCI controller token resolution → shared API controller
path normalization and query encoding → `transport::fetch` → local response
cache lookup → (only on a miss) reqwest HTTP request → body classification →
cache admission → JMESPath filtering and TOON/JSON rendering.

The tool and controller do not memoize results. Raw-response files are output
artifacts, not inputs to reads. The reqwest client does not install an HTTP
cache middleware. In this incident, the transport returned from its cache-hit
branch before `send()`; upstream CircleCI or a proxy could not update that poll.

The cache keys include the entire URL, resolved credential digest, and request
representation headers. A unique query creates a different key and is forwarded
upstream by ordinary query encoding. It does not refresh the original entry.
Hits update LRU bookkeeping, not expiry. The shipped fallback is 60 seconds,
but this session's effective fallback was **600 seconds**, as recorded by the
admission event. Other CircleCI responses in the session were admitted for an
hour from upstream cache-control headers. Generic HTTP freshness is unsuitable
for live deployment status, especially when CI changes independently of MCP
write invalidation.

## New behavior

CircleCI paths containing a `pipeline`, `workflow`, or `job` path segment bypass
both local lookup and admission, regardless of global TTL or upstream headers.
This includes lists, queued/running/approval states, and terminal states that
can change through reruns. The policy is in the vendor strategy and enforced
by transport, so direct/controller callers get the same freshness guarantee.
Status polling therefore costs one upstream request per poll; choose a sensible
poll interval and honor rate-limit errors.

`circleci_get` also accepts top-level `fresh: true`. It removes the matching
previous entry and bypasses local lookup and storage for that call, without
adding a query parameter or header upstream. A following ordinary cacheable
read fetches again, rather than reverting to an older snapshot. Errors still
surface as errors; there is no stale-on-error fallback.

GET output now has a `data`/`cache` envelope in JSON and TOON. Existing `jq`
expressions still apply to the upstream body before wrapping. Consumers that
parse unfiltered GET output must read the payload from `data`.

- `cache.hit`: whether MCP reused a local cached response.
- `cache.ageMs`: elapsed local cache residence; zero for an upstream fetch.
- `cache.fetchedAt`: UTC time MCP finished reading the original upstream body;
  retained on hits, refreshed on a new fetch.

These fields measure local provenance, not CircleCI's state-update timestamp or
an upstream proxy's response age. Fresh reads guarantee an upstream request,
not stronger consistency than CircleCI provides.

Deployment monitoring should poll pipeline workflows and the target workflow/job
statuses until completion. Pipeline creation is not deployment success. See
[the tool contract](../src/tools/descriptions/circleci_get.md) for an example.

Regression tests cover running → success/failed with repeated identical polls,
status/discovery endpoint policy under long upstream TTLs, ordinary cache hits
and age metadata, TTL expiry, and explicit fresh reads against an already warm
cache with unchanged upstream requests.
