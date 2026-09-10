# Collecting cache-policy training data

Cache observations are written to the existing `~/.mcp/data/*.audit.jsonl`
stream when audit logging and HTTP caching are enabled. Schema version 2 adds
correlated decisions, cumulative reward components, terminal outcomes, and an
optional randomized collection policy. It does not train or load a model.

## Enable collection

Configure each server process that should collect exploratory data:

```dotenv
HTTP_CACHE_ENABLED=true
HTTP_CACHE_EXPLORATION_ENABLED=true
AUDIT_LOG=on
```

The two `HTTP_CACHE_*` settings can also go in the server working directory’s
`.env`. Audit settings are process-environment settings; auditing is on by
default, so ensure `AUDIT_LOG` is not set to `off` in the launch environment.

Restart that process using the rebuilt binary. Installing a new binary without
restarting existing MCP clients does not update their instrumentation. With
exploration disabled (the default), the server retains the fixed admission
policy and still records the richer telemetry as `fixed-v2`.

`collect-v2` samples once after a successful, cache-eligible upstream read,
using independent randomness from the first byte of a v4 UUID:

| Action | Probability | Behavior |
|---|---:|---|
| `admit` | 0.75 | Store for the ordinary, capped TTL. |
| `admit_half_ttl` | 0.125 | Store for half that TTL. |
| `reject` | 0.125 | Return the fetched response without storing it. |

These probabilities are represented exactly by 192, 32, and 32 of the 256
possible byte values. `candidateActions` and `candidateProbabilities` are
parallel arrays; `actionProbability` is the probability of the selected action.
`baseTtlMs` defines the full-TTL action for that particular decision. The policy
never chooses a TTL longer than the fixed policy would have selected.

Exploration can increase upstream request volume. Vendor exclusions (including
CircleCI status reads), explicit fresh reads, sensitive requests, response cache
restrictions, and size limits still apply. Response-level exclusions emit
`http_cache_ineligible`, not randomized decisions. Disabled caching, request-level
exclusions, and upstream failures do not produce admission decisions.

The sample is **per admission opportunity**, not per user or session. Multiple
concurrent misses can produce separate decisions for the same key; replacement
closes the earlier entry. A rejected concurrent admission leaves any existing
entry untouched. Consequently, this is data for an entry-residency objective;
it is not by itself an unbiased estimate of a different policy's long-run
request volume or workload distribution.

## Recorded fields and joins

All cache records have `schemaVersion: 2`, `serverVersion`, `sessionId`, and a
process-local `cacheEventSequence`. Sequence numbers may arrive out of order
under concurrency; gaps in a retained snapshot identify missing records, such
as retention/rotation loss, failed writes, or incomplete collection. Audit write
failures produce a diagnostic warning. JSONL remains best-effort telemetry, not
the enterprise durable compliance journal.

Join decision, lookup, and outcome records using `(sessionId, decisionId)`.
Do not rely on line order or timestamps to identify an entry: two requests can
race. There is one terminal record per removed entry during normal execution.

- **Decision context:** vendor, hashed resource identity, baseline TTL and its
  source, validator presence, response bytes, would-be stored bytes,
  compression state/cost, upstream fetch latency, cache occupancy before the
  decision, and configured cache limits.
- **Action:** policy version, candidate actions and their probabilities,
  selected action/probability, and chosen TTL.
- **Progress:** each hit includes cumulative hit count, estimated saved latency,
  decode cost, byte-milliseconds of residency, entry age, and remaining TTL.
- **Correlation:** `originCallId`/`originTool` identify the admitting tool call;
  `callId`/`tool` identify the call causing the current event when available.
  Maintenance events have no current tool call. Task-local correlation is not
  automatically inherited by separately spawned tasks; decision IDs remain
  the authoritative join even when call correlation is absent.

Resource fingerprints are domain-separated SHA-256 hashes of vendor plus full
URL, with no identity component. Cache-key fingerprints also partition by
credentials, representation, and owner as before. Neither field logs the URL,
arguments, headers, credentials, or response contents. Resource fingerprints in
schema 2 are not interchangeable with older fingerprint algorithms.

Context fields describe information available **after fetching and preparing a
response, before choosing its admission/TTL**. `entriesBefore` and
`cacheBytesBefore` are inputs; `entries` and `cacheBytes` are post-action cache
state and must not be used as decision-time features. Likewise, hit counts,
remaining TTL at a later lookup, residency, and saved latency are outcome data,
not training features. `tool` on an invalidation event describes the invalidating
call, not the original decision context; use `originTool` for that context.

## Outcomes and reward semantics

Terminal outcomes are `expired`, `evicted`, `invalidated`, `replaced`,
`rejected`, `decode_failed`, or `session_end`. A once-per-second maintenance
pass expires idle entries, so collecting an outcome no longer depends on a
subsequent lookup. Clean process shutdown expires overdue entries, closes
survivors, and then drains the audit writer.

`observationComplete` is false for `session_end` and `decode_failed`: these
records contain partial measurements and must not be treated as completed
zero-reward observations. A hard kill may leave no terminal event; retain any
hit progress as partial evidence, or exclude the decision from complete-case
training. Complete-case filtering can itself bias the sample, so report
censoring by action/session and choose its treatment explicitly.

The raw reward components let a future trainer choose its tradeoff:

- `estimatedSavedLatencyMs = hitCount × upstreamLatencyMs`. In schema 2 the
  upstream measurement includes fetching and classifying the response body,
  not just receiving HTTP headers. It is an estimate of avoided work, not a
  measured counterfactual or proof that the cache stayed fresh.
- `decodeDurationUs` is cumulative local cache decoding time, including a
  failed decode attempt. `compressionDurationUs` measures storage preparation
  after serialization; it includes the compression attempt when applicable.
  Preparation happens before sampling, so rejected admissions also pay this
  cost. Serialization, lookup, and locking overhead are not included in these
  two counters.
- `residencyByteMs` measures stored **payload** bytes times elapsed residency.
  It includes the maintenance delay after TTL expiry, because the bytes really
  remain allocated until removal. It excludes key/metadata overhead.
- Rejection has zero saved latency and zero residency by definition of this
  entry-level objective; it does not claim the rejected resource will never
  be reused. `entryBytes` on rejection is the would-be stored size.

For example, an experiment could optimize estimated saved time minus decode
and compression costs and a weighted byte-time cost. Choose and version those
weights in the trainer, and keep units consistent. Longer TTLs also have a
freshness tradeoff that these observations do not label: validator **presence**
does not measure stale responses. This collection policy only shortens existing
TTLs and does not authorize learning a policy that exceeds them.

## Check the accumulated data

```bash
python3 scripts/operations/cache-training-readiness.py ~/.mcp/data
```

The checker reads current and rotated audit segments without changing them.
It reports corrupt records, schema/policy coverage, sequence gaps, duplicate or
unmatched IDs, censored outcomes, complete exploratory counts by action/vendor,
positive-hit outcomes, and independent session count. Older logs remain useful
for baseline analysis, but their missing fields are not fabricated. Pre-schema-2
decisions are reported separately as legacy data, not invalid policy records.

Do not declare readiness from the total number of JSONL lines. Require useful
complete coverage for every sampled action in the target workload, sufficient
independent sessions and positive outcomes, and a chosen reward. Evaluate on
held-out sessions or later dates, retaining a fixed-policy baseline. Report
uncertainty and censoring rather than assuming any fixed row count guarantees
readiness. Before adopting a learned policy, validate its actual workload-level
benefit online as well as its entry-level offline objective.

Default audit retention is 30 days/100 MiB across prior sessions and five
10 MiB segments per process. For longer collection, archive closed session
files to a separate dataset directory or deliberately increase
`AUDIT_LOG_RETENTION_DAYS`, `AUDIT_LOG_RETENTION_MAX_BYTES`,
`AUDIT_LOG_MAX_BYTES`, and `AUDIT_LOG_MAX_FILES`. Never train while files are
being rewritten: use a snapshot of closed sessions, and retain whole sessions
when splitting training from validation.
