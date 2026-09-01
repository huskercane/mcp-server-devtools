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

| Endpoint | Tool today | `normalized_action` | `resource_type` | `resource_id` source | Allowlisted attributes | Risk | Status |
|---|---|---|---|---|---|---|---|
| `GET /api/datasources` | `grafana_list_datasources` | `list_datasources` | `datasource` | — (collection) | — | read | **Extractor implemented + tested** |
| `GET /api/datasources/proxy/uid/{uid}/loki/api/v1/query_range` | `grafana_query_logs` | `query_logs` | `datasource` | `{uid}` path segment (typed arg) | `direction`, `end`, `limit`, `query`, `start`, `step` | read | **Extractor implemented + tested** |
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
- LogQL content (`query`) is retained as a query attribute for audit, but
  is **not** parsed for scope claims — labels inside LogQL do not restrict
  which datasource is read.

## Jira

Jira today is five generic verb passthroughs (`jira_get`, `jira_post`, …),
which is exactly the catalog the brief calls nearly meaningless for
tool-level policy: issue search is a `POST`, so "read-only = `jira_get`"
is unenforceable. The extractor gives the search endpoint (and the typed
reads) semantic identities; everything else stays `passthrough`/`unknown`
and is denied by default-deny.

| Endpoint | `normalized_action` | `resource_type` | `resource_id` source | Allowlisted attributes / body fields | Risk | Status |
|---|---|---|---|---|---|---|
| `GET /rest/api/3/issue/{key}` | `read_issue` | `issue` | `{key}` path segment | query: `fields` | read | **Extractor implemented + tested** |
| `GET /rest/api/3/project` | `read_project` | `project` | — (collection) | — | read | **Extractor implemented + tested** |
| `GET /rest/api/3/project/{key}` | `read_project` | `project` | `{key}` path segment | — | read | **Extractor implemented + tested** |
| `GET /rest/api/3/search/jql` | `search_issues` | `issue` | JQL project clause (see below) | query: `fields`, `jql`, `maxResults` | read | **Extractor implemented + tested** |
| `POST /rest/api/3/search/jql` | `search_issues` | `issue` | body `project` field, else JQL project clause | body: `jql`, `project` **only** | read (explicit downgrade from POST) | **Extractor implemented + tested** |
| `GET /rest/api/3/myself` | passthrough (candidate `read_self`) | none | — | — | read | Spec only |
| `GET /rest/api/3/issue/{key}/comment` | candidate `read_issue` (comments) | `issue` | `{key}` path segment | query: `maxResults`, `startAt` | read | Spec only |
| `POST /rest/api/3/issue` | passthrough | `unknown` | — | — (never read) | **write** | **Extractor implemented + tested** — must never classify as read |
| `POST /rest/api/3/issue/bulkfetch` | candidate `read_issue` (bulk) | `issue` | body `issueIdsOrKeys` allowlist | body: `issueIdsOrKeys`, `fields` | read (downgrade) | Spec only — second POST-read case for review |
| anything else | `passthrough` | `unknown` | — | — | method-derived | Implemented (default arm) |

### JQL project-scope extraction (the canonical passthrough case)

`project_keys_from_jql` in `src/policy/extractors.rs` implements the spec:

- **Sound, not complete.** A project scope is claimed only for a
  conjunction (no top-level `OR`) with at least one positive constraint:
  `project = KEY` or `project in (K1, K2, …)` (quoted keys supported,
  either quote style).
- Negations (`!=`, `not in`), `OR` queries, missing project clauses, and
  anything the lexer cannot consume yield **no claim** (`resource_id:
  none`): the search still classifies as `search_issues`/`issue`/read, but
  a rule that matches on `resource_id` patterns will not match it. An
  administrator can still write a rule allowing unscoped search — that is
  a policy decision, not an extractor guess.
- Multiple keys are sorted, deduplicated, and joined with `,`.
- Hand-rolled lexer; no regex on the hot path (§8 budget).

### Schema findings from this exercise (input to freezing §3.2)

1. **Multi-valued resources.** `project in (PLAT, WEB)` addresses two
   resources; `resource_id: Option<String>` holds them comma-joined today.
   Before freezing, decide whether `resource_id` becomes a list (rule
   matching semantics: any-of). Carried as a review question — not decided
   here.
2. **Collection reads** (`GET /api/datasources`, `GET /rest/api/3/project`)
   are classified type + no id. Rules that name specific ids will not
   match them; profiles need an explicit collection-read rule. This is the
   intended shape but worth calling out in the policy authoring guide.
3. **POST-as-read downgrades** are per-endpoint and explicit
   (`search/jql` now; `issue/bulkfetch` proposed). The default for POST
   stays `write`. Each downgrade is a security-relevant line item for the
   two-person review.
