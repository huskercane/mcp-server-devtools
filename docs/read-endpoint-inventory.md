# Read-endpoint inventory: Grafana and Jira (WP 0.8)

Status: drafted with working extractor code for the two proving endpoints;
**pending the two-person review WP 0.8 requires** before the enterprise
read profiles are frozen.
Extractor implementations and their tests: `src/policy/extractors.rs`.
Schema being proven: `ActionContext` / `ActionDetails` in `src/policy/mod.rs` (§3.2).

Scope note: vendors chosen per §12.5 — Grafana proves the schema against a
purpose-built tool, Jira's `POST /rest/api/3/search/jql` proves it against a
passthrough with a body-field allowlist, *before the type is frozen*.
ADR-005 (first workflow) is still a hypothesis; this inventory does not
pre-commit the enterprise subset.

## Conventions

- **Extractor contract**: pure `(request data) → ActionDetails`; sound over
  complete — a scope claim is made only when it is guaranteed. Anything
  unclassifiable is `passthrough` + `resource_type: unknown`, which
  default-deny denies.
- **`request_risk`** is derived from the endpoint contract (purpose-built
  reads are `read` by construction); for unmapped passthrough paths it is
  derived from the HTTP method, with `POST` conservatively `write`.
- **Canonicalization**: extractors currently apply tool-level normalization
  (leading slash, duplicate-slash collapse, trailing-slash trim). The full
  §3.5 canonicalizer (single percent-decode, dot-segment removal, fuzz
  target) is Phase A work (A.6) and runs before extraction in production.
- **Query/body allowlists** below are exhaustive: keys not listed are
  dropped from `query_attributes` and never influence policy; body fields
  not listed are never read by the extractor.

## Grafana

Purpose-built tools (existing, `readOnlyHint = true` by construction), plus
the read endpoints a Phase A/B read profile is expected to cover.
`environment` always comes from vendor-account configuration, never the
request.

| Endpoint | Tool today | `normalized_action` | `resource_type` | `resource_scope` source | Allowlisted attributes | Risk | Status |
|---|---|---|---|---|---|---|---|
| `GET /api/datasources` | `grafana_list_datasources` | `list_datasources` | `datasource` | `scope: collection` | — | read | **Extractor implemented + tested** |
| `GET /api/datasources/proxy/uid/{uid}/loki/api/v1/query_range` | `grafana_query_logs` | `query_logs` | `datasource` | `{uid}` path segment (typed arg, **validated**) | `direction`, `end`, `limit`, `query`, `start`, `step` | read | **Extractor implemented + tested** |
| `GET /api/datasources/uid/{uid}` | — (future) | `read_datasource` | `datasource` | `{uid}` path segment | — | read | Spec only |
| `GET /api/search` | — (future) | passthrough → needs purpose-built tool | `dashboard` | `uid` values in the response, not the request; request scope is query `folderUIDs` | `folderUIDs`, `query`, `type` | read | Spec only |
| `GET /api/dashboards/uid/{uid}` | — (future) | `read_dashboard`* | `dashboard` | `{uid}` path segment | — | read | Spec only (*action variant to add when built) |
| `GET /api/annotations` | — (future) | passthrough | `dashboard` | query `dashboardUID` when present, else none | `dashboardUID`, `from`, `to`, `type` | read | Spec only |
| `GET /api/health` | — | passthrough | none (server metadata) | — | — | read | Spec only; propose always-allow in read profile |

Notes:

- The Loki proxy endpoint is the sharp one: the *proxy* prefix means the
  gateway is executing a query against the datasource with the service
  account's rights. Resource-level policy on the datasource UID
  (`resource_id: ["loki-prod", ...]`, plan §3.2 example) is therefore the
  control that matters, and the extractor guarantees the UID comes from the
  typed argument, not from anything the model can smuggle into the LogQL.
- "Typed argument" was not, by itself, a constraint. The UID is
  interpolated into the proxy path, so `..`, `/`, `%2f`, `?`, or `#` in it
  addresses a different endpoint than the one policy classified —
  especially under a wildcard rule, where a value that *starts* with an
  allowed prefix can canonicalize elsewhere. `extractors::grafana::is_valid_datasource_uid`
  is now the single definition of a legal UID (`[A-Za-z0-9_-]{1,64}`);
  the extractor refuses to classify anything else (`unknown`/`unscoped`,
  and the hostile value never enters `canonical_path`), and
  `controllers::grafana::query_logs` refuses to dispatch it. Two call
  sites, one predicate, so they cannot drift.
- LogQL content (`query`) is **not** parsed for scope claims — labels
  inside LogQL do not restrict which datasource is read. It is kept as a
  bounded allowlisted attribute, not as "raw query text retained for
  audit": see decision 5 below.

## Jira

Jira today is five generic verb passthroughs (`jira_get`, `jira_post`, …),
which is exactly the catalog the brief calls nearly meaningless for
tool-level policy: issue search is a `POST`, so "read-only = `jira_get`"
is unenforceable. The extractor gives the search endpoint (and the typed
reads) semantic identities; everything else stays `passthrough`/`unknown`
and is denied by default-deny.

| Endpoint | `normalized_action` | `resource_type` | `resource_scope` source | Allowlisted attributes / body fields | Risk | Status |
|---|---|---|---|---|---|---|
| `GET /rest/api/3/issue/{key}` | `read_issue` | `issue` | `{key}` path segment | query: `fields` | read | **Extractor implemented + tested** |
| `GET /rest/api/3/project` | `read_project` | `project` | `scope: collection` | — | read | **Extractor implemented + tested** |
| `GET /rest/api/3/project/{key}` | `read_project` | `project` | `{key}` path segment | — | read | **Extractor implemented + tested** |
| `GET /rest/api/3/search/jql` | `search_issues` | `issue` | JQL project clause (see below) | query: `fields`, `jql`, `maxResults` | read | **Extractor implemented + tested** |
| `POST /rest/api/3/search/jql` | `search_issues` | `issue` | JQL project clause only (see below) | body: `jql` **only** | read (explicit downgrade from POST) | **Extractor implemented + tested** |
| `GET /rest/api/3/myself` | passthrough (candidate `read_self`) | none | `scope: unscoped` | — | read | Spec only |
| `GET /rest/api/3/issue/{key}/comment` | candidate `read_issue` (comments) | `issue` | `{key}` path segment | query: `maxResults`, `startAt` | read | Spec only |
| `POST /rest/api/3/issue` | passthrough | `unknown` | — | — (never read) | **write** | **Extractor implemented + tested** — must never classify as read |
| `POST /rest/api/3/issue/bulkfetch` | candidate `read_issue` (bulk) | `issue` | body `issueIdsOrKeys` allowlist | body: `issueIdsOrKeys`, `fields` | read (downgrade) | Spec only — second POST-read case for review |
| anything else | `passthrough` | `unknown` | — | — | method-derived | Implemented (default arm) |

### The body field that is not in Atlassian's schema

`POST /rest/api/3/search/jql` takes `jql`, `maxResults`, `fields`,
`expand`, `nextPageToken`, and friends. It does **not** take `project` —
that field was invented by an earlier revision of this inventory, and the
extractor let it *win* over the JQL. On any deployment that ignores unknown
JSON properties, `{"project":"PUBLIC","jql":"project = SECRET"}` was
classified as a read of `PUBLIC` while Jira executed the query against
`SECRET`. The body allowlist is now the single field Jira actually
executes: `jql`. Scope comes from the text that runs, or it is not claimed.

### JQL project-scope extraction (the canonical passthrough case)

`project_keys_from_jql` in `src/policy/extractors.rs` implements the spec.
It is a **scanner with a structural gate**, not a parser, and the gate runs
before anything is read out of the query:

- A claim is made only for a **flat conjunction of positive clauses**
  containing at least one `project = KEY` or `project in (K1, K2, …)`
  (quoted keys supported, either quote style).
- Rejected outright — no claim, at any nesting depth: an unquoted `OR`,
  `NOT`, or `!` **anywhere** in the query; any `(` that is not the one
  opening an `in` list (so grouping and JQL functions such as
  `membersOf(...)` yield nothing); an unterminated quote; any backslash
  (JQL string escapes are not lexed here, and `\"` is exactly how a fake
  clause would be smuggled past a scanner); a malformed list or dangling
  operator; a query over 8 KiB or 512 tokens.
- The `NOT` rule is why this is a gate rather than a lookbehind. The
  earlier implementation only checked the token immediately before
  `project`, so `NOT (project = PUBLIC)` — whose previous token is `(` —
  was claimed as *restricted to* `PUBLIC` when the query addresses every
  project **except** `PUBLIC`. A rule allowing `PUBLIC` would have
  authorized reads of everything else.
- No claim means `scope: unscoped`: the search still classifies as
  `search_issues`/`issue`/read, but no id-scoped rule matches it. An
  administrator can still write a rule allowing unscoped search — that is
  a policy decision, not an extractor guess.
- Keys are carried as a **list** (`ResourceScope::Ids`), sorted and
  deduplicated — never joined into a string. A quoted project key may
  itself contain a comma, so a comma-joined id is ambiguous by
  construction.
- Documented contract matches the implementation: this rejects *every*
  unquoted `OR`, not only a top-level one. The conservative direction is
  deliberate and the doc no longer promises otherwise.
- Hand-rolled lexer over borrowed slices; no regex, and no allocation
  except for the keys actually claimed (§8 budget).

### Schema decisions from this exercise (§3.2)

Raised as open questions by the first pass and worked through both WP 0.8
review passes. Four are settled and implemented; decision 3 is **provisional**
and holds the §3.2 freeze open — see `docs/enterprise-carry-forward.md` CF-2.

1. **Multi-valued resources — decided: a structured scope, matched
   all-of.** `resource_id: Option<String>` is replaced by
   `ResourceScope { Unscoped | Collection | Ids(Vec<String>) }`.
   Authorization over `Ids` is **all-of**: every id must be allowed.
   Any-of was the tempting reading and it is unsound — under it,
   `project in (PUBLIC, SECRET)` is authorized by a rule allowing
   `PUBLIC` alone, and the response comes back full of `SECRET`.
   `ResourceScope::all_ids_allowed` is the only id-matching helper the type
   offers, so a future rule engine cannot reach for the unsound one by
   accident. Ids are never comma-joined: a quoted Jira project key can
   contain a comma.
2. **Collection reads — decided: explicit, not "no id".**
   `GET /api/datasources` and `GET /rest/api/3/project` are
   `scope: collection`, which is a *distinct* state from `unscoped`.
   Collapsing both to a null id made "this endpoint lists the collection"
   indistinguishable from "we could not tell what this call reaches", and
   they must authorize differently. Neither is matched by an id-scoped
   rule; each needs its own permission.
3. **Resource semantics — PROVISIONAL; blocks the §3.2 freeze.** Jira search returns *issues*, constrained
   by *projects*, so `resource_type: issue` with a project-derived scope is
   not the contradiction it first looks like — but only because scope is
   now a separate, named concept rather than an `issue` id field holding a
   project key. A future `constrained_by` dimension (issues within
   projects `[PLAT, WEB]` as a first-class pair) is **required before the
   schema freezes**, not merely explanatory. Without it a generic policy
   engine cannot tell which permission namespace the ids belong to: it can
   look project keys up in an issue-id allowlist, or collide an issue-rule id
   with a project identifier, and reach a confident wrong decision. It may be
   implemented in Phase A, but it stays an unresolved schema requirement
   until then (`docs/enterprise-carry-forward.md` CF-2).
4. **POST-as-read downgrades — decided: exact endpoints only, one at a
   time.** `POST /rest/api/3/search/jql` is approved as a read downgrade
   now that the fictitious `project` body field is gone and the JQL gate is
   sound. `POST /rest/api/3/issue` stays `write`.
   `POST /rest/api/3/issue/bulkfetch` is **not** approved: it needs its own
   review of Atlassian's request schema, an extractor, defined
   malformed-body behaviour, and adversarial tests. The default for POST
   remains `write`, and every downgrade stays a line item for the
   two-person review.
5. **Caller-controlled attribute text — decided: parse it or digest it.**
   The earlier note promised LogQL and JQL would be kept "for audit". They
   are user- and model-authored search expressions: they can carry tokens
   pasted into a query, customer identifiers, or the contents of whatever
   someone was hunting for. What audit needs is *what was addressed*, which
   the scope already carries. Query text is retained only as a bounded,
   allowlisted `query_attributes` entry.

   The decision covers **every** retained attribute, not only the search
   expressions. `query_attributes` has no verbatim option: each key declares
   a shape (`Enumerated` or `Digest`), the value is retained only if it
   *parses* as that shape, and anything else — including anything over-long
   — becomes `sha256:<64 bits>/<length>`. Bounding a caller-controlled
   string is not redacting it: a token supplied as Jira's `fields` or
   Grafana's `direction` previously reached the serialized `ActionContext`
   intact, merely shorter.

   `fields` (`limit`/`maxResults`, `start`/`end`/`step` too) was originally
   its own shape — `IdentifierList` for `fields` (retained verbatim when
   every comma-separated element matched `[A-Za-z0-9_.*-]+`), `Integer` for
   the numeric bounds (retained as the re-rendered `u64`), `TimeBound` for
   the time bounds. Each alphabet is also a real credential format's
   alphabet: `sk-live-…`/`xoxb-…`/a JWT for the first, and this repository's
   own six-digit NinjaOne TOTP/MFA codes
   (`tests/ninjaone_session_tests.rs`) for the second and third — a bare
   token or a code, with no space or letters to trip a shape check, parsed
   as the declared shape and reached durable evidence unchanged. All three
   are `Digest` now, with no shape-based carve-out for any of them.
   `Enumerated` is the one shape that still survives verbatim, and safely:
   it is not a check on caller text at all, only an exact match against a
   small, server-owned vocabulary (`direction`'s `backward`/`forward`) whose
   membership the caller does not control, so a credential cannot
   coincidentally equal a member of it.

   The same rule now governs the other caller-controlled strings that reach
   durable evidence: the JSON-RPC request id (`policy::correlation_id`) and
   the self-reported `clientInfo` name and version
   (`ClientIdentity::reported`) are **always** digested — the same
   "looks like a plain identifier" shape check had the same bare-token gap,
   for the same reason, and there is no closed set of legitimate client
   names or request ids to allowlist instead. This still correlates,
   because the intent and outcome records digest the same input.

   The first revision of this decision was documented and then contradicted
   by the implementation, which cloned the expression whole and unbounded.
   A second revision closed that gap for values containing a space but left
   the bare-token shape open for `fields`, and left `limit`/`maxResults`/
   `start`/`end`/`step` on their numeric and time-bound shapes entirely — a
   third revision closed the former, a fourth the latter.
   `search_expressions_never_reach_query_attributes_as_text`,
   `caller_supplied_attribute_values_must_parse_or_become_a_digest`,
   `bare_tokens_in_fields_are_digested_not_passed_through`,
   `numeric_values_including_mfa_shaped_codes_are_always_digested`,
   `well_formed_attribute_values_survive_only_when_enumerated`,
   `client_reported_values_are_always_digested`, and
   `correlation_ids_are_digested_but_still_correlate` fail if any of that
   returns.
