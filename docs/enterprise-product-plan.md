# MCP DevTools design-partner technical execution plan

Status: proposed execution plan for the direction in the
[enterprise product brief](enterprise-product-brief.md); revision 2 after independent review
Owner: Rohit Singh · Source of record: `docs/enterprise-product-plan.md` in the `mcp-devtools` repository
Classification: internal; share with prospective collaborators under NDA
Last reviewed: August 29, 2026

This document turns the brief's thesis — *semantic, default-deny policy for AI
agents across the engineering stack* — into a sequenced plan with decisions,
work packages, gates, and the non-engineering tracks a security product needs.
The brief argues *what* and *why*; this plan is the *how*, *in what order*, and
*how we know it worked*.

Revision 2 narrows the commitment: the team commits to a **production-quality
vertical slice and two design-partner gates**, not to the full roadmap. Phases
C and D are sketched so their prerequisites are built correctly, but they are
ordered by partner demand and are not scheduled until Gate B passes.

## 0. Decision log

| Rev | Date | Change | Driven by |
|---|---|---|---|
| 1 | 2026-08-28 | Initial plan: six phases, two gates, console in Phase 5 | Brief |
| 1.1 | 2026-08-29 | Admin CLI, policy-engine options, stay-in-Rust decision, Kubernetes topology, container in Phase 1 | Owner |
| 2 | 2026-08-29 | Canonical `ActionContext` for resource-aware policy; durable `AuditSink` split from lossy `UsageSink`; licensing boundary moved to M0; minimal `CredentialBroker` in the first slice; commercial gates moved before Phase C; wedge vendors demoted to a hypothesis; Phase 5 split into C/D; revocation, canonicalization, client-identity, response-metadata, and availability corrections; business-plan gaps and trial metrics added | Independent review |
| 2.1 | 2026-09-01 | ADR-001 decided: enterprise crate lives in a private repository from day one; community crate gains a library target exposing the ports | Owner |
| 2.2 | 2026-09-01 | WP 0.5 spike answered: rmcp 3.1.2 propagates per-request axum extensions into `call_tool`'s `RequestContext` on both the stateless and session HTTP paths (`docs/spikes/rmcp-extensions.md`); the §9 session-keyed fallback is not needed and was not built | Spike |
| 2.3 | 2026-09-01 | M0 engineering landed on `feat/m0-enterprise-foundation`: WP 0.1 (LICENSE, library surface, private repo scaffolded and pushed), 0.4 (core types, `MCP_AUTH_MODE`, fail-closed bind, local-mode byte-identical tests), 0.5 (spike, rev 2.2), 0.6 (`CredentialBroker`), 0.7 (`AuditSink`/`UsageSink`, journal, write-before-dispatch fail-closed), 0.8 start (Grafana+Jira inventory, extractors; schema findings recorded in `docs/read-endpoint-inventory.md` — `ActionContext` not frozen yet). WPs 0.2/0.3 and ADR-002 counsel remain open | Owner + implementation |
| 2.4 | 2026-09-01 | ADR-007 decided: Phase D console is htmx 4.x + askama server-rendering from the `control` role (rendering as a client of the admin API); one vendored, exact-pinned JS asset, no npm toolchain, strict CSP without eval | Owner |
| 2.5 | 2026-09-02 | Phase A engineering landed on `feat/phase-a-secure-remote-slice`: A.1–A.10 as one reviewed commit per WP (`TokenValidator` + Okta JWKS + `StaticValidator`; bearer middleware and RFC 9728 metadata; artifact ownership, session binding, principal-partitioned cache; §3.5 canonicalization with a fuzz target; `PolicyDecisionPoint` + `AllowAll` + file policy with tool-level and egress enforcement and `policy check`; Grafana vertical slice; container + `--role` + ingress examples; the A.10 test set). §3.2 frozen with `constrained_by` (CF-2). Two §3.5 deviations documented in `policy::canonical` (`%2F` kept; trailing slash kept once). Egress *allows* are not journaled separately (the intent's decision plus the outcome record already prove them); egress *denials* are. CF-14 decided: bounded append refuses on timeout; intent = requested-and-authorized, outcome = dispatched. Gate A itself (partner, real IdP, real ingress) is owner-led and not started | Implementation |
| 2.6 | 2026-09-02 | Independent review of the Phase A branch, answered in code and in the register: SonarQube `ce/task` and CircleCI build-details requests now pass the egress chokepoint; the outcome append is cancellation-safe and lists every egress decision (the "allows are not journaled separately" reading of rev 2.5 was too weak for multi-request tools); JWKS read is bounded while streaming, RSA-only admission with unambiguous `kid`s, withdrawn keys evict cached tokens; no claim values in the operator log; a vanished policy file reports degraded health with the last good policy in force; ingress example no longer hashes on `Mcp-Session-Id` (§3.4 corrected); allocation probe gained the JWT cache-hit and journal-append stages. Decisions owed: CF-18 (where Okta/file-policy code lives under ADR-001), CF-19 (canonical wire bytes in local mode). Local-mode parity claim narrowed to protocol, tool surface, and wire requests | Independent review |

| 2.7 | 2026-09-03 | Phase B engineering landed on `feat/phase-a-secure-remote-slice`, one commit per WP in dependency order (B.3, B.4, B.6, B.5+B.7, B.1, B.2): signed policy bundles (Ed25519 detached signatures, `MCP_POLICY_PUBLIC_KEY` required in okta mode) with every load/change/rejection journaled and a change committed only after its record is durable; the revocation list as a second signed document (`MCP_REVOCATION_FILE`: subjects, token ids, `not_before` = `revoke all`), enforced after validation regardless of the token cache, with the fresh-token rule for writes; the journal hash chain with signed checkpoints (`MCP_AUDIT_SIGNING_KEY`), a `CheckpointSink` export, and `audit verify`; activity and access-review exports and the §7 metrics; Slack as the second vendor (five purpose-built reads, extractors shared with the passthrough and the egress chokepoint, the incident-investigation profile); `policy explain`. Three new fail-closed startup requirements in okta mode (policy public key, revocation list, audit signing key). CF-8 closed; CF-16's emergency-deny half closed; CF-18's move list grew (see the register). Gate B itself is owner-led | Implementation |
| 2.8 | 2026-09-03 | Independent review of the Phase B branch, answered in code and in the register: a token whose `iat` is in the future is refused at authentication (it outran every cut-off and counted as fresh for writes); a Slack query naming `channel` twice is not classified (policy judged the first value, Slack could read the second); the verifier reports a journal checkpoint the export lacks (a failed copy was invisible, and a truncation back to it would have stayed so) and duplicate exports; the audit signing key may be group-readable, because a Kubernetes Secret under `fsGroup` is `root:fsGroup 0440` and the owner-only rule made the sample deployment unable to start; a rejected reload is deduplicated only once its record is durable, and by the refused bytes, so distinct bad revisions are distinct records; the `policy_loaded`/`revocation_loaded` records are appended before the port is bound and their failure is a startup failure; key files are installed with a no-replace link and loaded through the handle that was permission-checked, revocation edits serialize on an advisory lock and `init` never replaces; `policy explain` builds its context through the one builder `call_tool` uses, with the live configuration and the real broker; CSV cells that a spreadsheet would evaluate are neutralised; time bounds compare at full precision; four documents corrected. Pushed back: the initialize/revocation interleaving leaves a session object, not access (CF-16). Recorded: the checkpoint threat model and external retention (CF-23), policy and revocation as separate signed documents (CF-24), §7 metrics as proxies (CF-25), the cached `jti` allocation (CF-26), and the remaining unlocked behaviours (CF-27) | Independent review |

Unresolved questions are collected in §11. Work that a phase deliberately
did **not** finish — deferred fixes, decisions we owe someone, and the
allocation baseline for the next phase's comparison — is tracked in
[`docs/enterprise-carry-forward.md`](enterprise-carry-forward.md), which is
the register a phase exit is checked against.

## 1. Guiding constraints

These are fixed unless a decision below explicitly revisits them.

1. **The community gateway does not change.** Every enterprise feature is
   opt-in (`MCP_AUTH_MODE=off` remains the default) and is covered by a test
   proving local stdio/loopback behaviour is byte-identical with it disabled.
2. **Fail closed.** The binary refuses to start if it would bind a non-loopback
   address with inbound authentication off, or if enterprise mode is on and no
   policy is loaded, or if the durable audit journal cannot be opened. There is
   no "temporarily permissive" mode.
3. **Enforce at the egress, on a canonical request.** A tool name is a label;
   the HTTP request the vendor client is about to send is the fact. Policy is
   evaluated where `Vendor` (`src/vendor/mod.rs:57`) builds the upstream
   request, against a canonicalized `ActionContext` (§3.2), so purpose-built
   tools, passthrough tools, and any future tool all hit one chokepoint.
   Tool-level policy is layered *on top* for early denial, never as the only
   guard.
4. **No token passthrough.** The inbound MCP token never leaves the process
   and is never used as an upstream credential. Enforced structurally: the
   `Principal` type carries validated claims, not the raw token.
5. **Evidence is never silently lost.** Security audit records are durable,
   sequenced, and written before dispatch. Usage telemetry may be lossy. The
   two never share a pipeline (§3.3).
6. **Ship every phase independently.** Each phase below has a "done when" that
   is a deployable, tested state on `main`, not a branch.
7. **Baseline stays pinned.** Rust 1.96 / edition 2024 / exact-pinned deps.
   New deps (JWT, JWKS, policy, journal) are pinned the same way and pass
   `cargo deny`.

## 2. Decisions

Each becomes an ADR under `docs/adr/`. Status: **P** proposed, **H**
hypothesis to be confirmed at a gate, **D** decided.

| # | Decision | Recommendation | Status | Why |
|---|---|---|---|---|
| ADR-001 | Repository and code boundary | Public community crate stays as is (ISC). Enterprise code lives in a **private repository** (`mcp-devtools-enterprise`) from day one, depending on the community crate as a library. The community crate therefore exposes a library target (`lib.rs`) with the ports (§3.1) and core types (§3.2) public; the community binary never links enterprise code; the enterprise binary composes the community library + enterprise crate. | D — 2026-09-01 | A private repository is the hardest licence boundary: no shared history, no accidental publication, CLA scoped per repo. Cost: the community crate must commit to a stable-enough library surface for the ports; that surface is versioned like any public API. The enterprise *licence text* itself is still ADR-002 (counsel). |
| ADR-002 | Licence | Add `LICENSE` (ISC) for the community crate now. Decide the enterprise licence (source-available / BSL / commercial) and adopt a CLA **before any enterprise code or external contribution lands** — a hard M0 exit criterion, not a pre-trial one. | P — decide in M0 | Cannot be retrofitted after outside contributions. |
| ADR-003 | Policy representation | A static, versioned YAML document whose rules match a canonical `ActionContext` (§3.2), including resource type, resource id pattern, and classification — not only tool/method/path. Schema designed to compile to Cedar without loss; engine behind the `PolicyDecisionPoint` port. See §2.1. | P | v1 must express "Jira project A, not B" and "this Grafana datasource, not that one", or it is a method-and-path gateway rather than the product in the brief. |
| ADR-004 | TLS termination | Out of process (reverse proxy / k8s ingress) for v1; the binary opens a non-loopback bind only when auth is on. | P | Every enterprise has a TLS ingress. Revisit if a partner cannot front it. |
| ADR-005 | First workflow and vendors | **Hypothesis:** incident investigation — Grafana first (purpose-built read tools already exist), Slack second. Atlassian and CircleCI follow only if the design partner's workflow needs them. Confirmed or replaced at Gate A. | H | Sell a governed workflow, not a bundle of connectors. Grafana makes Phase A's "one vendor" nearly free. |
| ADR-006 | Upstream identity for v1 | Shared, tightly scoped, per-vendor-per-environment service credentials labelled `authority=shared`; no silent fallback to a broader account; delegated OAuth deferred. **Explicitly accepted by the design partner at Gate A** (§4). | H | Buyers may reject a product that is the sole attribution source. Validate before building on it. |
| ADR-007 | Console technology | **htmx 4.x** (4.0.0 at decision time; adopt the current 4.x patch when vendoring) + server-rendered HTML via a compile-time template engine (askama), served by the `control` role, which renders **as a client of the admin API** — the API stays the single JSON enforcement surface (ADR-009) and never grows HTML endpoints. htmx is vendored as one exact-pinned, dependency-free static asset in `console/`, embedded via `rust-embed`; no npm/node in the build chain; no CDN (air-gap, D.4); strict CSP with `htmx.config.allowEval = false` (no `hx-on:`/event filters). D.3's editor widget (e.g. CodeMirror) would be the one additional pinned asset, decided when D.3 is scoped. | D — 2026-09-01 | Keeps "one static binary, no runtime" true on-prem, and keeps the console's JS supply chain to a single auditable file — the SBOM/security-review story a React toolchain would forfeit. Console v1 (D.1) is read-only, the hypermedia sweet spot. htmx 4.0.0 released 2026-08-28 and is not yet npm-`latest`; Phase D starts after Gate B, by which time 4.x is matured — exact patch pinned at build time. |
| ADR-008 | Implementation language | Stay in Rust. See §2.2. | D | The static binary with no runtime is what the buyer audits. |
| ADR-009 | Operator interfaces | One admin REST API; two thin clients — console and `mcp-devtools admin` CLI in the existing `clap` tree. **All controls, including two-person approval, are enforced in the API**, never in a client. | P | Anything clickable must be scriptable; nothing scriptable may bypass a control. |
| ADR-010 | Process topology on Kubernetes | One image, two roles: `gateway ×N` (data plane) and `control ×1` (admin, rollups, reports, console). `--role all` for single-host. See §3.4. | P | Multi-process is natural on k8s; the split is a runtime flag, not a second codebase. |
| ADR-011 | Audit durability | Local append-only journal with sequence numbers and periodic signed checkpoints, written before dispatch; forwarded to SIEM asynchronously. Audit unavailable ⇒ fail closed by default; a documented degraded-read mode is opt-in. | P | The product sells decision evidence. |

### 2.1 Policy engine options

The static YAML file is the right v1, but it is worth knowing what the
second step is and shaping v1 so that step is small. All options sit behind
the same `PolicyDecisionPoint` port.

| Option | Shape | Fits when | Cost / concern |
|---|---|---|---|
| **Static YAML rules over `ActionContext`** (v1) | Data, no logic; compiled to a matcher at load | Small rule sets, reviewable in PRs, golden-testable | No conditions ("only during an incident"); awkward past a few hundred rules |
| **Cedar** (`cedar-policy` crate) | Typed policy language, Rust-native, schema-validated, formally verified evaluator; RBAC + ABAC and *policy analysis* | The natural step two: same binary, no service; analysis proves "no rule grants a write" | Keep YAML as the authoring surface and compile to Cedar underneath |
| **OPA / Rego** | Sidecar, or embedded via `regorus` | Customers standardised on OPA | Hard to audit; sidecar adds a hop on the hot path |
| **CEL** (`cel-interpreter`) | Expression language for `when:` conditions | Conditions without a whole policy language | Not analysable; easy to write unreadable rules |
| **Casbin** (`casbin-rs`) | Model + CSV | Teams that know it | No schema validation or analysis; little over YAML |
| **ReBAC** (OpenFGA, SpiceDB) | Relationship graph | Per-document sharing | External stateful service; not our problem shape |
| **External PDP** | HTTP call-out per decision | Regulated customers requiring decisions in their own system | Latency and availability on the request path; must fail closed |

Recommendation: YAML now; Cedar as the compile target when conditions or
analysis are needed; OPA and external PDP as adapters only under contract.

### 2.2 Should this move to Java?

No. The collaborator pool and the enterprise identity ecosystem are
Java-heavy, but the trade is bad for this product specifically.

- **The deployment story is the product.** A ~20 MB static binary, no
  runtime, no JVM CVE stream, `unsafe` denied, `cargo deny` gating every
  dependency. Regulated and air-gapped buyers audit this. A JVM image is
  10–20× larger with its own patch cadence.
- **Sunk hardening.** Bounded output, resumable artifacts, credential-partitioned
  cache, audit lifecycle, TOON parity, golden-locked tool surface, three-OS CI,
  integration suite over wiremock. A port restarts that at zero.
- **Memory and density.** Per-principal state in a long-running process is
  far cheaper without a GC heap.
- **The libraries exist.** `jsonwebtoken`, `openidconnect`, `oauth2`,
  `cedar-policy`; `rmcp` is the reference-quality MCP SDK.

When Java would be right: if the team maintaining this in two years is
Java-only and unwilling to learn Rust — a people decision to make
explicitly. Being more than one process (ADR-010) does not require more than
one language; the `gateway`/`control` contract is small enough that a control
plane in another language is possible later, but the data plane stays Rust.

## 3. Target architecture

Hexagonal, following `src/ports/mod.rs`: a port exists only where a second
implementation or a test seam is real. Each port below has one at day one.

```text
                    ┌──────────────────────────────────────────┐
  HTTPS ingress ──▶ │ axum layer (src/server/http.rs)          │
  (out of process)  │  • bearer extraction                      │
                    │  • TokenValidator port → Principal        │
                    │  • 401 / 403 + WWW-Authenticate           │
                    │  • /.well-known/oauth-protected-resource  │
                    │  • /artifacts/{id} owner check            │
                    └───────────────┬──────────────────────────┘
                                    │ Principal in request extensions
                    ┌───────────────▼──────────────────────────┐
                    │ DevtoolsServer::call_tool                 │
                    │ (src/tools/mod.rs)                        │
                    │  • build ActionContext (typed args or     │
                    │    passthrough extractors)                │
                    │  • PolicyDecisionPoint: tool-level        │
                    │  • AuditSink: intent + decision, durable, │
                    │    before dispatch                        │
                    └───────────────┬──────────────────────────┘
                                    │
                    ┌───────────────▼──────────────────────────┐
                    │ Vendor request builder (src/vendor/mod.rs)│
                    │  • canonicalize outbound request          │
                    │  • PolicyDecisionPoint: egress            │
                    │  • CredentialBroker: upstream identity;   │
                    │    never the inbound token                │
                    │  • AuditSink: outcome                     │
                    └───────────────┬──────────────────────────┘
                                    │
        cache (partitioned by principal) · artifacts (owned) · UsageSink (lossy)

  operators ──▶ /admin/* (bearer, mcp:admin) ◀── console (embedded) · `mcp-devtools admin`
```

### 3.1 Ports and their two implementations

| Port | Impl 1 (ships first) | Impl 2 (real, day one) | Later |
|---|---|---|---|
| `TokenValidator` | Okta JWKS validator (`iss`, `aud`, `exp`/`nbf`, scopes, groups) | `StaticValidator` for tests and local dev | Entra; EMA access tokens |
| `PolicyDecisionPoint` | File-backed static policy over `ActionContext`, hot-reloaded via the `bootstrap/watcher.rs` pattern | `AllowAll` for `MCP_AUTH_MODE=off` — today's behaviour, made explicit | Cedar compile target; external PDP |
| `CredentialBroker` | Existing env/config/keychain resolution (`auth/secrets.rs`) wrapped so it returns an `UpstreamIdentity` label with vendor, environment, and `Shared`/`Delegated` — **in the first slice** | In-memory broker for tests | Vault / AWS SM / Azure KV; rotation; delegated OAuth |
| `AuditSink` | Durable local journal (ADR-011) | In-memory sink for tests | SIEM forwarders from `control` |
| `UsageSink` | Bounded channel → rollup store, drop-with-counter | No-op | Prometheus, OTLP |

### 3.2 Canonical `ActionContext`

Every decision, audit record, and golden test uses the same object. It is
constructed *before* policy evaluation and never mutated after.

```text
ActionContext
  principal            tenant, subject, groups, scopes, authority
  client               name, version — telemetry only, never an authorization input
                       unless bound to the token (e.g. a client_id claim)
  vendor               jira | slack | grafana | ...
  vendor_account       configured account / base URL label
  environment          prod | staging | qa | dev (from configuration, not the request)
  tool_name
  normalized_action    read_issue | search_issues | query_logs | ... (purpose-built tools
                       set this from their identity; passthroughs map (method, path) via
                       a per-vendor table, else `passthrough`)
  method
  canonical_path       normalized per §3.5
  query_attributes     allowlisted, decoded, sorted query keys/values
  resource_type        issue | project | channel | datasource | ...
  resource_scope       unscoped | collection | ids[...] — which resources of that type
                       the call addresses, extracted from path/args/allowed body fields
  resource_class       optional classification from configuration (e.g. "restricted")
  upstream_identity    from CredentialBroker: label, Shared | Delegated
  request_risk         read | write | destructive — derived, never client-supplied
```

Purpose-built tools build this from typed arguments. Passthrough tools use
per-vendor **extractors**: small, tested functions that pull `resource_type`
and `resource_scope` from the canonical path, allowlisted query keys, and an
allowlist of body fields (`jql` — and only `jql` — on
`POST /rest/api/3/search/jql`). Anything an extractor cannot classify is
`resource_type = unknown`, which default-deny policy treats as denied.

`resource_scope` is three distinct states, not a nullable id, and the
distinction is load-bearing (`docs/read-endpoint-inventory.md`, decisions
1–2):

- `unscoped` — the extractor could not prove what the call reaches;
- `collection` — the endpoint addresses the collection (a list endpoint),
  which is its own permission;
- `ids[...]` — provably restricted to exactly these ids.

**Matching a `resource_id` list against `ids` is all-of, never any-of.**
Every id the call addresses must be allowed. Under any-of,
`project in (PUBLIC, SECRET)` would be authorized by a rule that allows
`PUBLIC` alone, and the response would come back full of `SECRET`. Neither
`unscoped` nor `collection` is matched by an id-scoped rule; each needs an
explicit rule of its own.

Policy rules then match on any subset of these fields:

```yaml
version: 3
rules:
  - id: sre-read-prod-grafana
    subjects: { groups: [SRE] }
    match:
      vendor: grafana
      environment: prod
      request_risk: read
      resource_type: datasource
      resource_id: ["loki-prod", "prom-prod"]
    effect: allow
  - id: dev-jira-search-own-projects
    subjects: { groups: [Developers] }
    match:
      vendor: jira
      normalized_action: [search_issues, read_issue]
      resource_type: [issue, project]
      resource_id: ["PLAT-*", "WEB-*"]
      upstream_identity: { authority: shared }
    effect: allow
```

### 3.3 Two event pipelines

| | `AuditSink` | `UsageSink` |
|---|---|---|
| Purpose | Compliance evidence: who, what, decision, policy version, upstream identity, outcome | Dashboards, capacity, rate limits |
| Delivery | Synchronous append to a local journal **before** dispatch (intent + decision), then outcome; sequence-numbered; periodic signed checkpoints; forwarded asynchronously | Bounded channel; drop-with-counter on overflow |
| When unavailable | Fail closed by default. Optional degraded mode: reads allowed, every record flagged `degraded=true`, writes still denied | Continue |
| Contents | Never a token, never a body, never response content | Metadata only |
| Integrity | Hash chain is tamper-*evident*; checkpoints exported to SIEM/object storage make tampering *detectable* externally | — |

### 3.4 Process topology on Kubernetes

One image, two roles:

```text
                     ┌────────────────────────────────────────────┐
  ingress (TLS) ───▶ │ gateway ×N   (--role gateway)              │
                     │  /mcp · token validation · policy · egress │
                     │  local audit journal · usage events         │
                     └──────────────┬─────────────────────────────┘
                                    │ policy bundle (pull) · audit/usage (push)
                     ┌──────────────▼─────────────────────────────┐
  operators ───────▶ │ control ×1   (--role control)               │
                     │  /admin/* · SQLite rollups · reports        │
                     │  console (embedded) · SIEM forwarding       │
                     └────────────────────────────────────────────┘
```

Availability model, stated plainly for v1:

| Concern | v1 statement |
|---|---|
| `control` availability | Single replica; not HA. Gateways keep serving on the **last signed policy bundle** and keep journaling locally; admin API and console are down until it returns. |
| Local audit spill | Each gateway retains its journal on a persistent volume until `control` acknowledges forwarding; retention configurable (default 7 days); the gateway refuses new calls if the spill volume is full (fail closed). |
| Sessions | v1 runs one gateway replica, so sessions need no affinity. Past one replica, affinity must be established by the initialize *response* (ingress cookie affinity where clients keep cookies) or by a shared session store (Redis/Valkey): hashing the `Mcp-Session-Id` request header cannot bind a response-generated id to its pod and pins every stateless request to one upstream (CF-16). A miss returns the MCP "session not found" so the client re-initialises. |
| Artifacts | Shared `ReadWriteMany` volume or download routed by the same stickiness key; unavailable storage ⇒ the tool returns an explicit error, never a silent truncation. Object-storage adapter later. |
| Cache | Per-pod, bounded, per-principal; hit rate divided by N is accepted. |
| RPO / RTO | Audit RPO = 0 for acknowledged records: the journal is written **and `sync_data`-ed** before dispatch, so "acknowledged" means the record survives host loss, not merely that it reached the page cache. Rollups RPO = last `control` backup (default hourly); RTO = pod restart. |

### 3.5 Outbound request canonicalization

Policy and audit see one canonical form, produced once in the vendor request
builder and fuzz-tested:

- scheme/host/port resolved from **configuration** (vendor account), never
  from the request; user-info in URLs rejected;
- path: percent-decoded once, dot-segments removed, duplicate slashes
  collapsed, trailing slash normalized, case preserved (vendors are
  case-sensitive), then re-encoded;
- query: decoded, keys sorted, only allowlisted keys retained for policy;
- redirects: not followed across hosts; same-host redirects re-evaluated;
- DNS: pinned per vendor account by configured host; no per-request host
  override;
- the canonical string is what golden tests and audit records contain.

### 3.6 Revocation semantics

| Event | Effect | Bound |
|---|---|---|
| Token expiry | Rejected on next request | ≤ token TTL (recommend 5–15 min at the IdP) |
| Validated-token cache | Keyed by token hash; TTL = min(`exp`, 5 min) | Adds ≤ 5 min |
| Group removal at IdP | Takes effect when the client obtains a new token | ≤ token TTL + cache TTL; documented; measured in Phase B |
| Emergency deny-list | Signed revocation list (`MCP_REVOCATION_FILE`, part of the policy bundle): deny by `sub` or `jti`; edited with `mcp-devtools revoke …`; enforced on every request after validation, cache or not; cache cleared and the subject's sessions closed on change (Phase B, B.4) | ≤ file distribution + one poll (500 ms); measured under 2 s in `tests/revocation_tests.rs` |
| Signing-key compromise | Rotate at IdP; gateways refetch JWKS on unknown `kid`; `mcp-devtools revoke all` sets a `not_before` cut-off that refuses every token issued before it, clears the token cache, and closes every principal session | Minutes; `docs/revocation-runbook.md` |
| High-risk operations | `request_risk != read` requires a token issued within `MCP_WRITE_MAX_TOKEN_AGE_SECONDS` (default 300); a token with no `iat` is refused for writes | Enforced in `call_tool` (B.4) |

### 3.7 Where existing code changes

| File | Change |
|---|---|
| `src/server/http.rs` | Bearer middleware; protected-resource metadata route; artifact owner check; non-loopback bind gated on auth mode. Existing Origin guard and body limit stay. |
| `src/tools/mod.rs:367` `call_tool` | Read `Principal` from `context.extensions` (verify rmcp 3.1.2 propagates axum extensions in the spike; fallback is a map keyed by `Mcp-Session-Id` in `server/session.rs`); build `ActionContext`; tool-level policy; durable audit of intent + decision before `tool_router.call`. |
| `src/vendor/mod.rs` `Vendor` | Canonicalize; egress policy; `CredentialBroker` selects upstream identity; outcome audit. |
| `src/transport/response_cache.rs` | Principal partition in the key. |
| `src/transport/raw_response.rs` | `owner_subject` on artifact metadata; `pin_artifact` takes the caller's principal. |
| `src/audit.rs` | Becomes the journal adapter behind `AuditSink`; fields: subject, tenant, decision, rule id, policy version, authority, upstream account, canonical action, sequence, checkpoint. |
| `src/config/mod.rs` | `MCP_AUTH_MODE`, `MCP_OKTA_*`, `MCP_POLICY_FILE`, `MCP_BIND_ADDR`, `MCP_PUBLIC_URL`, `MCP_AUDIT_JOURNAL_DIR`, `MCP_AUDIT_DEGRADED_READS`. |
| Tool responses | Authority and upstream identity go in **structured** MCP result metadata (`_meta` / annotations), never appended to text content. |
| `tests/golden/tool_surface.json` | New purpose-built read tools are a deliberate surface change; regenerate and review as its own commit. |

## 4. Phases and gates

Sizes are relative (S ≈ days, M ≈ 1–2 weeks, L ≈ 3–5 weeks for one engineer
who knows the codebase). Calendar assumes roughly one full-time-equivalent
spread across collaborators. **Only M0, Phase A, and Phase B are committed.**

### M0 — Commercial and architectural foundation (weeks 0–3)

| WP | Work | Size |
|---|---|---|
| 0.1 | Commit the brief and this plan; `LICENSE` (ISC) added; community crate gains a library target exposing ports and core types; private `mcp-devtools-enterprise` repository created with the enterprise crate scaffolded against that library; ADR-002 licence text and CLA decided with counsel | S + legal |
| 0.2 | Threat model (STRIDE over §3), reviewed; each mitigation mapped to a planned test | M |
| 0.3 | Two design-partner targets identified; at least one trial commitment in writing; **their** IdP and first workflow chosen (ADR-005/006 confirmed or replaced) | non-eng |
| 0.4 | `Principal`, `ActionContext`, `PolicyDecision`, `UpstreamIdentity` types; `MCP_AUTH_MODE` with fail-closed bind check; local-mode-unchanged test | S |
| 0.5 | Spike: `RequestContext::extensions` propagation through rmcp streamable HTTP | S |
| 0.6 | Minimal `CredentialBroker`: wrap existing resolution; stable credential label; vendor + environment; `Shared`/`Delegated`; identity in every audit event | S |
| 0.7 | `AuditSink`/`UsageSink` ports with the journal adapter (sequence numbers, write-before-dispatch, fail-closed) and the lossy usage channel | M |
| 0.8 | Read-endpoint inventory for the chosen first two vendors, including `POST` searches, with resource extractors specified per endpoint; two-person review | M |

**Done when:** licensing boundary exists (private enterprise repository builds against the community library; community repo carries `LICENSE`); threat model
reviewed; one partner committed; both builds pass CI with zero warnings; an
audit record with upstream identity is written before any tool dispatches.

**Status 2026-09-01 (engineering scope):**

- [x] Licensing boundary: `LICENSE` (ISC) in the community repo; private
  `mcp-devtools-enterprise` builds and smoke-tests against the community
  library (github.com/huskercane/mcp-devtools-enterprise; licence text
  itself still ADR-002, with counsel).
- [ ] Threat model (WP 0.2) — owner-led, not started here.
- [ ] Partner commitment (WP 0.3) — owner-led, not started here.
- [x] Both repos pass build + clippy `-D warnings` + tests + fmt + deny
  locally; community CI runs the three-OS matrix on push.
- [x] Audit record with upstream identity before dispatch:
  `tests/audit_journal_tests.rs` proves intent-before-dispatch, the
  fail-closed refusal (vendor sees zero requests), and sequence resume.
- [x] WP 0.4/0.5/0.6/0.7 landed; WP 0.8 started (Grafana + Jira, extractor
  code + inventory; the §3.2 schema is deliberately **not frozen** — see
  the findings section of `docs/read-endpoint-inventory.md`, pending the
  two-person review).

### Phase A — Secure remote vertical slice (weeks 3–9)

| WP | Work | Size |
|---|---|---|
| A.1 | `TokenValidator` port; Okta JWKS impl (key cache, rotation, skew); `StaticValidator` | M |
| A.2 | Bearer middleware: 401 + `WWW-Authenticate`; 403 + `insufficient_scope`; nothing about the token in logs | M |
| A.3 | `/.well-known/oauth-protected-resource` (RFC 9728) | S |
| A.4 | Artifact ownership; bearer required on `/artifacts/{id}`; 404 on cross-owner access | S |
| A.5 | Session and cache partitioning by principal; session bound to subject | M |
| A.6 | Canonicalization (§3.5) with a fuzz target | M |
| A.7 | `PolicyDecisionPoint` port; `AllowAll`; file-backed policy over `ActionContext`; tool-level and egress evaluation; `mcp-devtools policy check` | M |
| A.8 | First vendor end-to-end: Grafana (existing purpose-built tools) with extractors, read-only profile, and resource-level rules (datasource) | S |
| A.9 | Container: multi-stage musl → distroless `static`, non-root, read-only root FS, `HEALTHCHECK`, `--role all|gateway|control`, published by `release.yml` with a digest; ingress examples | M |
| A.10 | Tests: JWKS negative matrix; artifact cross-owner; canonicalization fuzz; golden decision table `(principal, ActionContext) → decision`; local-mode-unchanged | M |

**Done when:** an Okta-issued token reaches a container behind TLS ingress,
`grafana_query_logs` against a QA datasource succeeds for group A and is
denied for group B with a reason, the denial and the allow are both in the
journal with policy version and upstream identity, and the journal was
written before dispatch.

**Status 2026-09-02 (engineering scope):**

- [x] A.1–A.10 landed (see §0 rev 2.5 and `docs/enterprise-carry-forward.md`
  for what each closed). `tests/phase_a_vertical_slice_tests.rs` is the
  "done when" in process — every production component in the loop except
  the TLS ingress and the container image, which `tests/auth_mode_tests.rs`
  (binary boundary) and `Dockerfile` + `deploy/k8s/` cover as far as a test
  can without a cluster.
- [x] Per-phase allocation gate run at exit; numbers in the carry-forward
  register's baseline table.
- [x] Independent review (rev 2.6) answered: each accepted finding has a
  regression-locking test; the register records what was changed, what
  was narrowed, and the two decisions owed (CF-18, CF-19).
- [ ] CF-18 — decide, with counsel, whether the Okta validator and file
  policy engine move to the private repository or ADR-001 is amended.
- [ ] Gate A — owner-led: a partner, their IdP, their non-production upstream.
  Steps, what is under test, and the exit are in `docs/gate-a-runbook.md`.
- [ ] `SECURITY.md` + disclosure process (security track, before Gate A).

> **Gate A — problem validation.** One partner runs Phase A against their real
> IdP and a non-production upstream for two weeks. Exit: they confirm the
> problem is material; they explicitly accept the shared-identity model
> (ADR-006: read-only shared accounts, per-vendor-per-environment credentials,
> no silent fallback, `authority=shared` labelling, upstream-vs-gateway
> attribution documented); the second vendor is chosen from their workflow.
> If they reject shared identity, one delegated integration moves into Phase B.

### Phase B — Product differentiation (weeks 9–16)

| WP | Work | Size |
|---|---|---|
| B.1 | Second vendor (hypothesis: Slack) with purpose-built read tools, extractors, read-only profile; third only if the workflow needs it | L |
| B.2 | Resource-aware rules exercised across both vendors; `policy explain` (given an `ActionContext`, show the rule that fires) in CLI | M |
| B.3 | Policy versioning: bundle hash in every audit event; hot reload via signed bundle; audit event on change | S |
| B.4 | Revocation (§3.6): token cache, deny-list, `revoke-all`, measured group-removal window, key-rotation runbook | M |
| B.5 | Minimal access-review export (policy + groups → who can do what) and activity export (JSONL/CSV) from the journal | M |
| B.6 | Signed audit checkpoints exported to a configurable sink; offline verifier in the CLI | M |
| B.7 | Trial metrics instrumented (§7) | S |

**Done when:** the brief's exit criterion passes end-to-end — provision →
read succeeds → group change → denied with reason → revocation window
measured — and the partner can produce an access-review export themselves.

**Status 2026-09-03 (engineering scope):**

- [x] B.1–B.7 landed (see §0 rev 2.7 and `docs/enterprise-carry-forward.md`).
  The "done when" runs in process: `tests/revocation_tests.rs::group_removal_waits_for_the_token_but_revocation_does_not`
  is provision → read → group change → denied with reason → revocation
  window measured, with the real Okta validator on a mock JWKS;
  `tests/phase_b_slack_slice_tests.rs` is the second vendor end to end;
  `tests/audit_report_tests.rs` produces the access-review and activity
  exports through the CLI. The partner-side half of each measurement (the
  identity-provider clock) is Gate B's to record.
- [x] Per-phase allocation gate run at exit; numbers in the register's
  baseline table.
- [ ] Gate B — owner-led: two organizations, trials, pricing, security
  evidence. `docs/gate-a-runbook.md` carries the three new okta-mode
  requirements (policy public key, revocation list, audit signing key) so
  the Gate A image is the Phase B image.
- [ ] CF-18 — the move list grew by every Phase B module; decide before
  any external contribution.
- [x] Independent review of the Phase B branch (rev 2.8): every accepted
  finding answered in code with a regression test, the pushed-back one
  answered in the register, and the rest recorded as CF-23 through CF-27.

> **Gate B — willingness to deploy and pay.** Two organizations complete a
> trial and confirm: they would deploy this instead of distributing personal
> tokens; the upstream identity model is acceptable; a budget owner exists;
> target pricing is not rejected; required security evidence (pen-test, SBOM,
> SOC 2 timeline) is achievable. **Nothing in Phases C–D is scheduled until
> Gate B passes.** If it fails, Phases A–B stay in the open-source gateway as
> a credibility asset.

### Phase C — Enterprise authorization and operations (after Gate B; ordered by partner demand)

| WP | Work | Size |
|---|---|---|
| C.1 | EMA: re-read the current `ext-auth` stable revision; advertise `io.modelcontextprotocol/enterprise-managed-authorization`; ID-JAG exchange (RFC 7523 + 8693), preferring Okta as the AS; interop matrix Claude web/desktop, Claude Code, VS Code, **Codex** (or narrow the public claim) | L |
| C.2 | External secret provider (Vault or partner's choice); credential rotation without restart; assignment policy | M |
| C.3 | SIEM forwarding from `control` (syslog or HTTP) | M |
| C.4 | Admin API (`/admin/*`, `mcp:admin` scope, separate rate limit): policy read/validate/reload/diff, principal lookup, session list/revoke, artifact list/purge, deny-list, reports, usage | M |
| C.5 | `mcp-devtools admin` CLI over C.4, `--json` on every command | M |
| C.6 | Prometheus metrics; per-principal rate limits; usage rollups (SQLite, pinned) | M |
| C.7 | Helm chart; backup/restore; upgrade + rollback; SBOM (CycloneDX) and signed releases in `release.yml` | M |

### Phase D — Administration experience (after Phase C; each item behind demonstrated demand)

| WP | Work | Size |
|---|---|---|
| D.1 | Console v1, read-only: policy viewer + explain, audit search, activity and access-review reports, session/artifact management | L |
| D.2 | Two-person approval for policy change and credential rotation — **enforced in the admin API**; console and CLI merely surface it | M |
| D.3 | Console v2: policy authoring with validation and diff | L |
| D.4 | Additional packaging: `.deb`/`.rpm`, compose reference stack, air-gap runbook (pinned JWKS from file, offline licence, mirrorable images, `cargo vendor` tarball), OVA only on request | M |
| D.5 | Delegated OAuth, one vendor at a time, each behind its own gate | L each |

## 5. Non-engineering tracks (run in parallel)

| Track | Starts | Owner needed | Deliverables |
|---|---|---|---|
| Design partners | M0 | GTM / founder | 1 commitment by M0 exit; 2 trials complete by Gate B; trial agreement template (duration, support, metrics, data collected, security terms, conversion rights, post-trial pricing) |
| Security & compliance | M0 | Security engineer | Threat model (0.2); `SECURITY.md` + disclosure process before Gate A; SBOM (C.7); pen-test before Gate B; SOC 2 readiness plan |
| Legal | M0 | Counsel | `LICENSE`, ADR-001/002, CLA, trial agreement, DPA template |
| GTM | Phase A | GTM | Business-plan sections in §6; pricing hypothesis test; pitch deck; competitive matrix |
| Docs | Every phase | Engineer on the phase | Admin guide, IdP runbooks, policy authoring guide with the profile files as examples |

## 6. Business-plan gaps to close before Gate B

The brief is a product thesis, not a business plan. These sections are
owned work items; their numbers come from the design-partner conversations,
not from this document.

| Section | Contents | Owner | Due |
|---|---|---|---|
| Quantified customer pain | Personal tokens in circulation, provisioning time, revocation delay, audit effort, security-review delays, incidents/near misses | GTM, from partner interviews | Gate A |
| Target-market definition | Firm size, regulated status, number of engineering systems, MCP-client adoption, private-cloud requirement | GTM | Gate A |
| Bottom-up market model | Reachable accounts, expected ACV, penetration assumptions, services revenue | GTM | Gate B |
| Buyer and procurement map | Economic buyer, security approver, platform owner, daily admin, legal path, sales cycle | GTM | Gate B |
| Competitive matrix | First-party connectors, protocol gateways, API gateways, identity vendors, this product | GTM + Eng | Gate A |
| Packaging and pricing | Community / Enterprise Core / Enterprise Plus: environments, users, support, secret providers, SIEM paths, deployment options | GTM | Gate B |
| Design-partner program | Trial terms (see §5) | GTM + Legal | M0 |
| Operating plan | Engineering, security, support, legal, compliance, docs, sales staffing | Founder | Gate B |
| Financial plan | 24–36 month cost, revenue milestones, cash, gross margin, support burden | Founder | Gate B |
| Commercial kill criteria | Conditions under which this stays open source | Founder | M0 (draft), Gate B (final) |

## 7. Design-partner trial metrics

Instrumented in B.7; reported at Gate B.

| Metric | Source |
|---|---|
| Time to provision a new employee (IdP group add → first successful call) | Journal |
| Time for revocation to take effect (group removal → first denial) | Journal, B.4 |
| Personal API tokens eliminated | Partner survey |
| Share of requests covered by an explicit allow rule (vs. default deny) | Journal |
| Cross-environment access attempts blocked | Journal |
| Time to produce an access-review or activity report | Timed, B.5 |
| Administrator hours per month | Partner survey |
| Security-team approval outcome and blockers | Partner |
| Willingness to deploy; willingness to pay within a stated range | Partner, Gate B |

## 8. Security and performance budgets

CI gates from Phase A onward.

### Security

- Threat model (0.2) re-reviewed at each gate; every mitigation maps to a test.
- Secrets hygiene: tokens and credentials never appear in logs, audit, usage,
  error envelopes, or `Debug` output — enforced by a redaction test that greps
  every emitted line in the integration suite for fixture secrets.
- Default-deny everywhere: policy (`unknown` resource type is denied), admin
  scope, artifact ownership, cache partitioning, bind address.
- Client identity (`client_name`/`client_version`) is telemetry; it is an
  authorization input only when bound to the token.
- Hardening baseline: `unsafe_code = "deny"`; `cargo deny`; distroless
  non-root image; read-only root FS; no shell in the image; `SECURITY.md`.
- Abuse controls: per-principal and per-IP rate limits, body limit, output
  limit, JWKS fetch rate limit, session cap per principal.
- Pen-test before Gate B; findings tracked to closure.

### Performance

The community pipeline is already measured (`benches/response_pipeline`);
enterprise mode must not move it noticeably.

| Path | Budget | How it is held |
|---|---|---|
| JWT validation (cache hit) | < 50 µs | Validated-token cache keyed by token hash, TTL = min(`exp`, 5 min); JWKS cached with background refresh |
| `ActionContext` build + canonicalization | < 30 µs | Single pass; no regex on the hot path; extractors are tested table lookups |
| Policy decision | < 20 µs for 500 rules | Rules compiled to a matcher at load; decisions read an `Arc` snapshot |
| Durable audit (intent + decision) | < 200 µs p99 on local NVMe; one fsync per writer batch (concurrent appends group-commit), never fewer — an acknowledged record is on disk | Append-only journal; sequence numbers; per-line hash chain; checkpoint every N records or T seconds, signed (a checkpoint is a signature boundary, not a sync boundary). **Never dropped; fail closed if the journal is unwritable** |
| Usage write | Off the request path | Bounded channel; drop-with-counter |
| Cache partitioning | No measurable change | Fixed-width principal hash prefix in the key |
| Admin API / console | Never contends with `/mcp` | Separate limiter and task budget; queries hit rollups, not the journal |

Each budget gets a `benches/` harness (`harness = false`) and a CI smoke run
that fails on a > 20 % regression against the checked-in baseline.

## 9. Risk register

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---|---|---|---|
| Enterprise code lands under the community licence | Medium | Licensing mess | ADR-001/002 and CLA are M0 exit criteria | Legal |
| Design partner rejects shared identity | Medium | v1 model invalid | Explicit acceptance at Gate A; delegated integration ready to move into Phase B | Product |
| Resource extractors misclassify (a "read" that mutates, or the wrong project) | Medium | Security incident | Two-person review of the inventory; golden decision table; `unknown` denied; fuzz on canonicalization | Eng + Security |
| rmcp does not propagate request extensions | Medium | Blocks Phase A design | WP 0.5 spike; session-keyed fallback | Eng |
| Journal fsync cost on slow storage | Medium | Latency | Batched checkpoints; budget in §8; documented storage requirement | Eng |
| Per-pod state under horizontal scaling | High | Broken clients on k8s | §3.4 stickiness + shared artifact volume; adapters when measured | Eng |
| EMA spec revision before Phase C | High | Rework | C.1 re-read; behind its own sub-feature | Eng |
| Shared credential exceeds a user's upstream rights | High (by design) | Privilege escalation | Read-only profiles; `authority=shared` in metadata and audit; no fallback | Product |
| Catalog breadth dilutes support | High | Support cost | Enterprise mode registers only workflow vendors by default | Product |
| Console scope grows ahead of the API | Medium | Rewrites | Console only in Phase D; approval enforced in the API | Product |
| Usage tracking captures sensitive data | Medium | Privacy breach | Metadata-only schema in the threat model; redaction test covers usage rows | Security |
| Policy hot-reload races in-flight calls | Medium | Inconsistent decisions | Decisions snapshot the policy `Arc` per call | Eng |

## 10. Definition of done for the committed scope (M0 + A + B)

- [ ] Licensing boundary in the repository; `LICENSE`; CLA.
- [ ] Community build unchanged: golden tool surface, audit shape, health banner identical with `MCP_AUTH_MODE=off`. (Narrowed in rev 2.6: unset and explicit-off are identical to each other; the tool surface deliberately grew by five Slack reads in B.1 and the journal now carries checkpoint records.)
- [x] Fail-closed startup on non-loopback bind without auth, auth without policy, or unwritable journal. (Phase B adds: auth without a policy public key, a revocation list, or an audit signing key.)
- [x] Okta token validation with the full negative matrix against a wiremock JWKS.
- [x] `ActionContext` with resource extractors for two vendors; default-deny policy with resource-level rules; golden decision table. (Grafana in A.8, Slack in B.1; cross-vendor rows in B.2.)
- [x] Canonicalization with a fuzz target; canonical form in audit and goldens.
- [x] Durable audit written before dispatch, sequence-numbered, checkpointed, offline-verifiable; usage separately and lossy. (B.6: signed checkpoints, `audit verify`.)
- [ ] Upstream identity from `CredentialBroker` in every audit event and in structured response metadata. (In every event since M0; structured response metadata still open.)
- [x] Artifacts, cache, and sessions principal-owned; cross-principal access is a tested 404.
- [x] Revocation: token cache, deny-list, `revoke-all`, measured group-removal window, key-rotation runbook. (B.4; `docs/revocation-runbook.md`.)
- [ ] Container with `--role`, ingress examples, `SECURITY.md`. (`SECURITY.md` still owner-led.)
- [x] Access-review and activity exports produced by the partner unaided. (B.5: `mcp-devtools audit export …`; the "unaided" half is Gate B's to confirm.)
- [ ] Trial metrics (§7) reported; Gate A and Gate B outcomes recorded in §0.

## 11. Unresolved questions

1. ADR-002: which enterprise licence for the private repository? (Repository location decided 2026-09-01: private from day one — ADR-001.)
2. Which IdP does the first partner use — Okta as assumed, or Entra?
3. Is the incident-investigation workflow (Grafana → Slack) the partner's first workflow, or is it planning/delivery (Jira → CircleCI)?
4. Does the partner require end-to-end upstream user identity for any operation in the first workflow?
5. Degraded-read mode when audit is unavailable: offer it at all in v1?
6. Codex: support claim or drop from the brief?
7. External references in the brief have not been re-verified since August 2026; verify before external circulation.

## 12. Immediate next steps

1. Commit the brief and this plan; add `LICENSE`.
2. Book the counsel conversation for ADR-002 (enterprise licence text) and the CLA; create the private `mcp-devtools-enterprise` repository.
3. Send the outreach kit to the first two candidate design partners; get one commitment in writing.
4. Land WP 0.4 (types, `MCP_AUTH_MODE`, fail-closed bind, local-mode-unchanged test) and WP 0.5 (rmcp extensions spike).
5. Start WP 0.8 with Grafana (datasource extractor) and Jira's `POST /rest/api/3/search/jql` (the canonical example), so the `ActionContext` schema is proven against both a purpose-built and a passthrough tool before it is frozen.
