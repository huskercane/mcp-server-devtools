# Competitive landscape register

Status: living register; feeds the competitive matrix owed at Gate A
([plan §6](enterprise-product-plan.md#6-business-plan-gaps-to-close-before-gate-b))
and the "gateway layer is where the real competition is" risk in the
[brief](enterprise-product-brief.md#competitive-position-and-risks)
Owner: Rohit Singh · Source of record: `docs/competitive-landscape.md` in the `mcp-devtools` repository
Classification: internal; share with prospective collaborators under NDA
Last reviewed: September 5, 2026

This register records every product that a buyer will compare us against, what
it actually does (from its own published material, not from our assumptions),
where it overlaps with the plan, where it does not, and what that changes for
us. An entry is added when a product is named by a prospect, a reviewer, or a
public announcement in our category. An entry is updated, never rewritten, so
the trail of what we believed and when survives.

The comparison is always made against the plan's own definition of the
product: *semantic, default-deny policy for AI agents across the engineering
stack*, enforced at the egress on a canonical upstream request (plan
constraint 3), with brokered upstream identity (constraint 4) and durable,
sequenced evidence (constraint 5). A competitor that does inbound
authentication and tool-name allowlists has matched Phase A's table stakes,
not the product.

## 0. Change log

| Date | Change | Driven by |
|---|---|---|
| 2026-09-05 | Community license changed to Apache-2.0; separate enterprise extensions use proprietary commercial terms. Updated our governance comparison only; competitor assessments were not reverified. | Owner |
| 2026-09-03 | Register created; agentgateway (Solo.io, now under the Agentic AI Foundation) is the first entry; category skeleton from the brief | Owner, after the AAIF announcement |
| 2026-09-03 | Field survey: fourteen further products assessed from primary material where it could be reached (§4.2–§4.15), three more noted as watch items (§6); agentgateway's policy-attribute question answered from its docs (§4.1); two categories added to §1 (auth-brokering integration platforms; evidence proxies) and one split out (platform-suite gateways); §5 synthesis added — credential brokerage is no longer a differentiator on its own, the defensible position is the *combination* of axes A, C, E and F in one self-hosted binary | Owner; web survey |

## 1. Categories

The brief's §"Competitive position and risks" names five categories. The
survey added two the brief did not anticipate and split a third out of
"identity vendors". Each competes on a different axis, so the "what this
changes for us" answer differs per category.

| Category | What they sell | Where they beat us | Where the plan is defensible |
|---|---|---|---|
| **First-party vendor connectors** (Atlassian, Slack, Grafana, CircleCI managed MCP) | Native per-user identity for one vendor | Any single-vendor buyer, day one | Cross-vendor policy, one audit model, one credential-brokerage story |
| **Protocol gateways / MCP proxies** (agentgateway, Pomerium, Obot, IBM ContextForge, Microsoft's OSS gateway, Docker's gateway) | Inbound auth, RBAC, routing, federation and virtualisation of MCP servers they do not own | Breadth of protocols; free and often foundation- or vendor-backed | They see a tool name and an MCP frame; we see the vendor HTTP request we are about to send (constraint 3) |
| **API gateways adding MCP** (Kong, Cloudflare, Apigee-class) | Their existing gateway with an MCP plugin, often generating MCP servers from API specs | Incumbency in the platform team; already in the data path | Generated servers make every API a tool with no semantic model; policy is the plugin chain, not the resource |
| **Identity vendors** (Okta for AI Agents, Microsoft Entra Agent ID) | Runtime authorization and brokered tokens as an extension of the IdP the buyer already owns | Own the identity provider; Okta's gateway already mints per-request scoped upstream tokens | They are SaaS in the data path; they answer *who may act, with which token*, not *against which resource of which vendor*, and they cannot see the upstream request |
| **Platform-suite gateways** (Microsoft Agent 365, Snowflake Cortex AI Gateway) | Agent governance bundled into a suite the buyer already licenses | Zero procurement friction for their installed base | Govern the suite's agents and registered servers; the engineering stack outside the suite is someone else's problem |
| **Auth-brokering integration platforms** (Arcade, Composio, Nango, Pipedream) | Thousands of pre-built tools plus per-user OAuth token vaulting; they *own the tool implementations*, so they are the closest to us on axis A | Catalogue breadth and per-user upstream identity today | Catalogue is the moat they chose and the brief rejected; policy is access control, not resource-aware default-deny; evidence is OpenTelemetry, not a sealed journal |
| **Evidence proxies** (obsigno, cMCP, HELM AI Kernel) | A drop-in proxy that evaluates a policy per `tools/call` and writes a signed, hash-chained ledger with offline verification | They have already shipped the axis F design in the open, some with Cedar | Alpha / developer-preview Python; no identity, no upstream credential handling, no vendor knowledge; they prove the bar, they do not sell the product |
| **MCP-gateway startups** (MintMCP, Bifrost/Maxim, TrueFoundry, Lasso) | Some combination of the above, SaaS-first, with content guardrails | Speed; polished consoles; SOC 2 already done | Self-hosted single static binary with no SaaS in the data path; the regulated-buyer segment |

## 2. Comparison axes

Every entry is scored against the same axes so the matrix in §3 stays
comparable. Scores: **●** has it as we define it · **◐** partial or differently
shaped · **○** absent or not claimed · **?** not yet verified from primary
material · **n/a** not applicable to the category.

| Axis | What "●" means here |
|---|---|
| A. Layer | Owns the vendor client and enforces on the upstream request (constraint 3), versus a proxy in front of servers it does not own |
| B. Inbound identity | OIDC/JWT validation against an enterprise IdP; EMA path planned |
| C. Policy object | Resource-aware (type, id pattern, classification), default-deny, reviewable as data; not only tool/method/path |
| D. Policy language | Reviewable, analysable, golden-testable; conditions without a Turing-complete expression language on the hot path |
| E. Credential brokerage | Selects a labelled upstream identity per vendor and environment; inbound token never used upstream (constraint 4) |
| F. Evidence | Durable, sequenced, written before dispatch, tamper-evident (hash chain, signed checkpoints), exportable for access review |
| G. Revocation | Signed revocation document enforced regardless of token cache; fresh-token rule for writes |
| H. Deployment shape | Self-hosted single static binary, Kubernetes roles, no runtime, `cargo deny`-gated dependency tree |
| I. Model-facing data plane | Bounded output, resumable owned artifacts, principal-partitioned cache |
| J. Governance / licence | Who controls the roadmap; whether the buyer can rely on it being neutral |

## 3. Matrix

| Product | Category | A | B | C | D | E | F | G | H | I | J | Last verified |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **This product** (plan, Phases A+B landed) | — | ● | ● | ● | ◐ YAML now, Cedar planned | ● | ● | ● | ● | ● | Proprietary enterprise extensions over Apache-2.0 community crate | 2026-09-05 |
| agentgateway (Solo.io → AAIF) | Protocol gateway | ○ | ● | ○ tool name + JWT claims only | ◐ CEL | ○ | ◐ | ? | ◐ Rust, k8s Gateway API | ○ | Apache 2.0, LF/AAIF | 2026-09-03 |
| Okta for AI Agents (Runtime Agent Gateway + XAA) | Identity vendor | ○ virtual MCP server | ● | ◐ task-scoped runtime decisions; resource awareness unverified | ? | ● per-request, audience-bound brokered tokens | ◐ structured System Log events | ● "revocable in seconds" | ○ SaaS (self-hosted mentioned, unverified) | ○ | Vendor | 2026-09-03 |
| Microsoft Agent 365 + Entra Agent ID | Platform suite | ○ | ● | ◐ admin approval of MCP servers/tools | ? | ? | ◐ "audit-ready evidence" | ◐ Conditional Access for agents | ○ SaaS | ○ | Vendor; USD 15/user/month | 2026-09-03 |
| Kong Enterprise MCP Gateway | API gateway | ◐ owns the upstream request for the servers it *generates* from APIs | ● OAuth 2.1 resource server | ○ plugin chain | ◐ plugin config | ◐ JWT swap before upstream (3.14, secondary source) | ◐ tool-usage observability | ? | ◐ self-hosted Enterprise or Konnect | ○ | Commercial, paid plugins | 2026-09-03 |
| Cloudflare MCP Server Portals | API gateway / ZTNA | ○ | ● Access | ◐ per server, per toolset | ○ | ? | ◐ aggregated request logs | ◐ Access session controls | ○ SaaS | ○ | Vendor; open beta since 2025-08-26 | 2026-09-03 |
| Pomerium | Protocol gateway | ○ | ● | ◐ `mcp_tool` name match | ◐ PPL | ● acquires, caches, refreshes and injects upstream OAuth tokens | ◐ logs method, tool, parameters | ? | ◐ Go binary, self-hosted | ○ | Apache 2.0 core + hosted Pomerium Zero | 2026-09-03 |
| IBM ContextForge | Protocol gateway | ◐ virtualises REST/gRPC as MCP | ● OIDC SSO, RBAC, teams | ◐ virtual servers bundle tools | ○ | ? "user-scoped OAuth tokens" (secondary) | ◐ OTel + "audit trails" | ? | ○ Python + Postgres + Redis | ○ | Apache 2.0 | 2026-09-03 |
| Microsoft MCP Gateway (OSS) | Protocol gateway | ○ | ● Entra | ◐ role-gated resources | ○ | ○ | ? | ? | ○ C#/ASP.NET on k8s | ○ | MIT | 2026-09-03 |
| Docker MCP Gateway | Protocol gateway (developer) | ○ | ○ | ○ | ○ | ◐ secrets kept out of client env, local | ◐ call tracing | n/a | ○ desktop plugin | ○ | MIT | 2026-09-03 |
| Obot | Protocol gateway | ○ | ● SSO/OIDC | ◐ RBAC per server | ○ | ? | ◐ request/response trails, exportable | ? | ◐ Docker/k8s | ○ | Open source community + Enterprise | 2026-09-03 |
| Arcade.dev | Auth-brokering platform | ◐ owns 7,500+ tool implementations | ● Okta/Auth0/Clerk | ◐ "contextual access controls" | ○ | ● per-user OAuth token vault | ◐ OpenTelemetry | ? | ◐ cloud, marketplace, or Helm self-hosted | ○ | Commercial | 2026-09-03 |
| MintMCP | Startup, hosted | ○ | ● SSO | ◐ RBAC | ○ | ● credential management / OAuth brokering | ◐ audit trails; PII and secret scanning | ? | ○ SaaS | ○ | Commercial; SOC 2 Type II | 2026-09-03 |
| Bifrost (Maxim) | LLM gateway with MCP RBAC | ○ | ◐ virtual keys | ◐ tool allow-lists at discovery and execution | ○ | ○ | ◐ logs args, result, key, parent request | n/a | ? | ○ | Open source (licence unverified) | 2026-09-03 |
| Lasso Security MCP Gateway | Startup, guardrail proxy | ○ | ○ API key | ○ | ◐ natural-language policies via Lasso plugin | ○ | ◐ SQLite/DuckDB request logs | n/a | ○ Python | ○ | MIT | 2026-09-03 |
| obsigno | Evidence proxy | ○ stdio proxy | ○ | ◐ rules see the `tools/call` | ● JSON/YAML rules, Cedar, or OPA; fail closed | ○ | ● Ed25519-signed hash-chained ledger, offline verify, evidence bundles | n/a | ○ Python, alpha 0.3.0 | ○ | Apache 2.0 intended | 2026-09-03 |
| cMCP (AgenTrust) | Evidence proxy | ○ | ○ | ◐ | ● Cedar bundle, hash measured into attestation | ○ | ● hardware-attested signed TRACE claims + audit chain | n/a | ○ Python, dev preview 0.3.x; TPM/SEV-SNP/TDX | ○ | MIT | 2026-09-03 |
| Snowflake Cortex AI Gateway (Natoma) | Platform suite | ○ | ● | ◐ Horizon Catalog policies at tool-call level | ? | ? | ◐ | ? | ○ SaaS | ○ | Vendor | secondary sources only |
| Atlassian managed MCP | First-party | n/a | ● native | ◐ one vendor | ? | n/a | ? | ? | SaaS | ? | Vendor | not yet assessed |

## 4. Entries

### 4.1 agentgateway

| | |
|---|---|
| Category | Protocol gateway / MCP proxy |
| Built by | Solo.io and contributors; joined the Agentic AI Foundation (AAIF, Linux Foundation), announced September 2026 |
| Licence / governance | Apache 2.0; "300+ contributors across 60+ organizations" at joining |
| Language / shape | Rust; bare metal, VMs, containers, Kubernetes with "full Gateway API conformance"; dynamic configuration without downtime |
| Primary sources | [AAIF announcement](https://aaif.io/blog/agentgateway-joins-aaif-as-an-open-gateway-for-agentic-ai-infrastructure); [tool-access docs](https://agentgateway.dev/docs/kubernetes/latest/mcp/tool-access/) (both read 2026-09-03) |
| Assessed | 2026-09-03 |

**What it is, in its own words.** "An open source gateway built for the way
modern AI systems actually work": a unified proxy for MCP, Agent-to-Agent
(A2A), HTTP, gRPC, and LLM inference traffic, with routing and federation
across MCP servers and agents, and "seamless switching between LLM providers".

**What it does.**

- Inbound: JWT authentication, API-key authentication, RBAC, external
  authorization call-out, mTLS, CORS.
- Policy: declarative configuration in Common Expression Language (CEL);
  tool-level access policies through "MCP virtualization", which federates
  several MCP servers behind one endpoint and exposes a chosen subset of
  tools. The documented policy attributes are JWT claims (`jwt.sub`,
  `jwt.iss`, …) and `mcp.tool.name`; the worked example is
  `jwt.sub == "alice" && mcp.tool.name == "add_issue_comment"`. **No
  example inspects tool-call arguments.** A denial surfaces to the client as
  "unauthorized tool call".
- Guardrails: "protections against malicious tool behavior", prompt guards,
  rate limiting, budget controls, model aliasing, content-based routing.
- Observability: "metrics, tracing, and access logging designed for AI and
  agent workflows".

**Overlap with the plan.**

- Rust, self-hosted, Kubernetes-native data plane for governed agent access.
- Inbound JWT validation, RBAC, tool-level allow/deny, audit logging, metrics.
- "One governed endpoint" positioning aimed at the same platform and security
  buyer.

**Where it is a different product.**

- **Layer (axis A).** It proxies MCP servers it does not own. It sees a tool
  name and a protocol frame. This plan *is* the MCP server: it owns the
  Grafana, Jira and Slack clients, so policy is evaluated on the canonical
  upstream HTTP request the vendor client is about to send (constraint 3,
  plan §3.5). The brief's line applies verbatim: most gateways "do not know
  that a Jira search is a `POST`".
- **Policy object (axes C, D).** CEL over JWT claims and the tool name. The
  plan's `ActionContext` (plan §3.2) carries resource type, id pattern and
  classification so a rule can say "Jira project A, not B" and be
  golden-tested; plan §2.1 considered CEL and kept it out of the primary
  language because it is not analysable.
- **Credential brokerage (axis E).** Not claimed. The plan's
  `CredentialBroker` and the no-token-passthrough constraint select a
  labelled upstream identity per vendor and environment and never forward
  the inbound token.
- **Evidence (axis F).** Access logging, metrics and tracing. The plan's
  journal is written before dispatch, sequenced, hash-chained, checkpointed
  under a signing key, verifiable offline, and exported for access review
  (Phase B).
- **Scope.** LLM inference routing, provider switching, prompt guards,
  budget controls, model aliasing, A2A federation. None of that is in the
  plan and none of it should be: it is a different buyer conversation.
- **Governance (axis J).** Foundation-governed Apache 2.0 with a large
  contributor base. The plan is a private enterprise crate over an Apache-2.0
  community crate (ADR-001), which is the opposite trust story: a buyer
  trusts agentgateway because it is neutral, and would trust us because
  the binary is small enough to audit.

**What this changes for us.**

1. **Complementary, not a duplicate.** A customer can run agentgateway as the
   protocol ingress and this binary as a governed backend behind it. ADR-004
   already puts TLS termination out of process, so the topology is natural.
   The Gate A runbook and the ingress examples should show it, and the
   competitive conversation should lead with it.
2. **Phase A's generic half is now table stakes.** Bearer validation, RFC 9728
   metadata, tool-name allowlists and access logging are things a buyer can
   get for free from a Linux Foundation project. They stay in the plan
   because the product needs them, but they are not the pitch. The pitch is
   axes A, C, E, F and G.
3. **The competitive matrix (plan §6, due Gate A) must name it.** A
   foundation-governed project in the same language and deployment shape is
   the comparison every buyer will make first.
4. **Risk register candidate.** "Protocol gateways absorb tool-level policy
   and audit" belongs in plan §9 as its own row. Mitigation is the same as
   the bet in the brief: keep the semantic layer ahead and the evidence bar
   higher than a proxy can reach.
5. **Watch items.** Whether it grows upstream credential injection per tool
   server (would erode axis E); whether its access logs gain tamper-evidence
   (axis F); whether its CEL policy gains `mcp.tool.arguments` (would move C
   from ○ to ◐); whether the AAIF publishes a policy or audit standard that
   we should implement rather than compete with.

**Open questions.** Answered 2026-09-03: the policy sees JWT claims and the
tool name, not arguments (axis C scored ○). Still open: whether the
external-authorization hook receives the `call_tool` payload, which would
let an outside PDP be resource-aware and would be both a threat and an
integration path for ours.

### 4.2 Okta for AI Agents (Runtime Agent Gateway, Cross-App Access)

| | |
|---|---|
| Category | Identity vendor |
| Primary source | [Okta blog, "Securing the agentic enterprise"](https://www.okta.com/blog/ai/okta-securing-ai-agent-identity/) (read 2026-09-03) |
| Deployment | SaaS; the article "references both SaaS and self-hosted options" without detail (**?**) |

**What it is, in its own words.** The Runtime Agent Gateway is the "inline
policy enforcement point (PEP)" that "presents itself as an MCP server"; Okta
is the policy decision point behind it. Cross-App Access (XAA) implements the
Identity Assertion Authorization Grant so that "the human (the `sub` claim)
and the agent (the `act` claim) both travel in the token". Tokens are "minted
at the moment of the request, scoped to the task, audience-bound, and
revocable in seconds"; "short-lived XAA tokens and longer-lived brokered SaaS
tokens" are never exposed to the agent. Audit is "explicit, structured events
(`app.oauth2.token.grant.id_jag`) tied to an immutable transaction identifier".

**Overlap.** This is the strongest overlap on axis E in the survey: brokered
upstream tokens the agent never holds, per request, audience-bound, revocable.
The brief's ADR-006 (shared service credentials, delegated OAuth deferred) is
*behind* Okta on upstream identity, not ahead.

**Different product.** Okta sees an MCP frame and a token exchange; it does
not build the vendor HTTP request, so it cannot express "this Grafana
datasource, not that one" except as an OAuth scope the vendor happens to
define. It is SaaS in the data path, which the brief's target segment refuses.
Its evidence is the Okta System Log, durable and structured but not
tamper-evident by claim and not written before dispatch by the enforcement
point.

**What this changes for us.**

1. The brief's line "Nobody has a good answer for … credential brokerage" is
   no longer true and should be revised before Gate A.
2. Delegated identity via ID-JAG / XAA is the industry answer to the
   attribution problem ADR-006 accepts as a risk. Phase C's delegated OAuth
   should implement the Identity Assertion Authorization Grant rather than a
   bespoke flow, so an Okta shop can hand us a `sub`+`act` token and we
   exchange it downstream. Record as a C.1 sub-item.
3. Positioning against Okta is "behind your IdP, self-hosted, resource-aware":
   Okta decides who may act and with which token; we decide what that token
   may touch at the vendor and keep the sealed record on the customer's disk.

### 4.3 Microsoft Agent 365 and Entra Agent ID

| | |
|---|---|
| Category | Platform suite (identity vendor's bundle) |
| Primary source | [Microsoft Security blog, GA announcement, 2026-05-01](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/) (read 2026-09-03); secondary: M365 admin-center "manage tools for agents" docs |
| Commercials | GA 2026-05-01; "in Microsoft 365 E7 or standalone at USD15 per user per month" |

**What it does.** "Asset context mapping for each agent including the devices
they run on, MCP servers configured for those agents, the identities
associated with them, and the cloud resources those identities can reach";
"policy-based controls to set guardrails for what agents are allowed to do";
Entra network controls extended to agents; "audit-ready evidence". Admins
register remote MCP servers with Entra OAuth and approve tool requests in the
M365 admin center (secondary source). A Tooling Gateway exists per ring with
its own Entra app IDs (secondary source).

**Overlap.** Inventory, approval and Conditional Access over MCP servers an
enterprise's agents use; per-agent identity.

**Different product.** It governs the suite's agents and the servers
registered to them; it does not implement the tools, hold vendor credentials
for Grafana or Jira, or see the upstream request. Whether it governs
third-party MCP servers with the same depth as Microsoft's own is not stated.

**What this changes for us.** An Entra shop will already have a place that
lists "which MCP servers this agent may use". We must be registerable there as
one server with Entra OAuth (C.1b's Entra profile is the prerequisite) and
must not compete with the inventory. Every Gate A/B partner on Microsoft 365
will ask "why not Agent 365?"; the answer is axis A and F, and it should be
in the pitch deck.

### 4.4 Kong Enterprise MCP Gateway

| | |
|---|---|
| Category | API gateway |
| Primary source | [Kong blog, "Introducing Kong's Enterprise MCP Gateway"](https://konghq.com/blog/product-releases/enterprise-mcp-gateway) (read 2026-09-03); the 3.14 token-swap and scope-based tool filtering claims come from a secondary comparison and are marked so |
| Commercials | Kong AI Gateway 3.12+; Kong Gateway Enterprise (self-hosted) or Konnect; "enterprise-only solution that leverages paid plugins" |

**What it does.** Converts existing REST APIs into "remote MCP servers hosted
by Kong" so teams "transform their existing API infrastructure into
MCP-compatible tools instantly, without writing a single line of server
code"; acts as "the OAuth Resource Server in the MCP authentication flow";
"granular tracking of tool usage patterns" and "prompt and completion sizes";
security, guardrail and observability policies applied through the plugin
engine. Roadmap: semantic tool selection, tool bundles, bundle-level policy.

**Overlap.** For the servers Kong *generates*, Kong does own the upstream
request, which is the only other case in this survey where axis A is
partially true. Self-hosted enterprise is available. JWT swap before the
upstream is credential brokerage in shape (secondary source).

**Different product.** Generation from an OpenAPI spec produces one tool per
operation with no notion of resource classification; the brief calls this
the "thirteen vendors times five verbs" liability, and Kong sells it as the
feature. Policy is the plugin chain over HTTP attributes, not a resource-aware
default-deny document. Evidence is observability.

**What this changes for us.** Kong is the incumbent in exactly the platform
team we would sell to. The pitch is that a spec-generated tool surface is the
thing the buyer's security team will refuse, and that we ship purpose-built
read tools whose `readOnlyHint` is true by construction. The plan should
consider running *behind* Kong as an upstream, the same as agentgateway.

### 4.5 Cloudflare MCP Server Portals

| | |
|---|---|
| Category | API gateway / Zero Trust access |
| Primary source | [Cloudflare blog announcement](https://blog.cloudflare.com/zero-trust-mcp-server-portals/) (read 2026-09-03) |
| Commercials | Open beta since 2025-08-26; all Cloudflare One customers; "up to 50 free seats" |

**What it does.** "A single, centralized gateway for all your MCP servers";
Access policies with MFA, device posture and geography; users see only "the
curated list of servers and tools they are authorized to use"; enforcement of
"which MCP Servers the user has access to, regardless of the underlying
server's authorization policies"; aggregation of "all MCP request logs into a
single place". Credential handling and DLP are not described in the
announcement (**?**).

**Overlap.** Per-server and per-toolset authorization; aggregated logging;
IdP integration.

**Different product.** SaaS in the data path; no upstream credential story
stated; no resource-aware policy; logs, not a sealed journal.

**What this changes for us.** A buyer on Cloudflare One gets tool-level
allow-lists for free. That is a strong reason the generic half of Phase A is
not the pitch. Being one registered server behind a Portal is a deployment
we should document.

### 4.6 Pomerium

| | |
|---|---|
| Category | Protocol gateway (identity-aware reverse proxy) |
| Primary sources | [Pomerium MCP docs](https://www.pomerium.com/docs/capabilities/mcp); [GitHub README](https://github.com/pomerium/pomerium) (read 2026-09-03) |
| Licence / shape | Apache 2.0, Go; hosted control plane "Pomerium Zero" as the commercial layer |

**What it does.** Sits between MCP clients and internal servers handling
"authentication, authorization, TLS termination, and all the customary
gateway concerns". Pomerium Policy Language (PPL) with an `mcp_tool` criterion
matching "exact name, prefix, suffix, or list" for allow- and block-lists.
Upstream OAuth is handled by the proxy: "acquiring, caching, and automatically
refreshing access tokens" and "injecting the upstream token into proxied
requests transparently". "Every tool call is logged with the method, tool
name, and parameters."

**Overlap.** Axis E in a self-hosted open-source binary: per-user upstream
OAuth acquired and injected by the gateway. Tool-name policy in a reviewable
policy language.

**Different product.** Proxy; policy on the tool name; logs with parameters
but no tamper-evidence; no vendor semantics.

**What this changes for us.** Pomerium is the open-source proof that "the
gateway holds the upstream token" is a commodity. Our axis E claim must be
about *labelled, environment-scoped, policy-selected* upstream identity with
the decision in the audit record, not about holding tokens.

### 4.7 IBM ContextForge

| | |
|---|---|
| Category | Protocol gateway with API virtualisation |
| Primary source | [ContextForge docs](https://ibm.github.io/mcp-context-forge/latest/) (read 2026-09-03) |
| Licence / shape | Apache 2.0; Python (FastAPI, Pydantic, async SQLAlchemy), SQLite or PostgreSQL, Redis; Helm, Docker Compose |

**What it does.** "Open source registry and proxy that federates MCP, A2A, and
REST/gRPC APIs with centralized governance." JWT, OIDC SSO (Okta, Keycloak,
Entra, IBM Verify), RBAC, teams, OAuth 2.0 with Dynamic Client Registration;
virtual servers bundling selected tools; per-tool concurrency, validation,
timeout and rate-limit rules; "40+ plugins" over gRPC or Unix sockets with
mTLS; OpenTelemetry tracing, Prometheus metrics, structured JSON logs and
"metadata tracking & audit trails".

**Overlap.** Broad enterprise checklist coverage; virtualisation of REST as
MCP gives it partial ownership of the upstream request.

**Different product.** A Python service with a database and a cache behind it,
which is the deployment shape the brief's §2.2 argues against. Policy is
RBAC over tools and virtual servers. Audit is logging.

**What this changes for us.** IBM's presence validates the category for
regulated buyers. The contrast to draw is shape: one static binary, no
runtime, no database for the data plane.

### 4.8 Microsoft MCP Gateway (open source)

| | |
|---|---|
| Category | Protocol gateway |
| Primary source | [GitHub README](https://github.com/microsoft/mcp-gateway) (read 2026-09-03) |
| Licence / shape | MIT; C# / ASP.NET Core on Kubernetes (StatefulSets, headless services) |

**What it does.** "A reverse proxy and management layer for MCP servers,
enabling scalable, session-aware stateful routing and lifecycle management of
MCP servers in Kubernetes environments." Entra bearer auth with app roles;
resource-level read/write gated by creator, `requiredRoles`, and an
`mcp.admin` role. "Agents & Sessions (Preview)".

**Overlap.** Session-sticky routing on k8s is exactly the §3.4 problem.

**Different product.** Session routing and lifecycle for servers it hosts;
policy is role-per-resource; no upstream credentials, no vendor semantics,
audit not described.

**What this changes for us.** Nothing to compete with; worth reading for its
session-store design against plan §3.4.

### 4.9 Docker MCP Gateway

| | |
|---|---|
| Category | Protocol gateway, developer workstation |
| Primary source | [GitHub README](https://github.com/docker/mcp-gateway) (read 2026-09-03) |
| Licence / shape | MIT; Docker Desktop CLI plugin |

**What it does.** Runs "each local MCP server in the catalog in an isolated
Docker container"; keeps "secrets out of environment variables" via Docker
Desktop secrets; "built-in OAuth flows for service authentication"; serves
multiple clients over SSE or streaming; "built-in logging and call tracing".

**What this changes for us.** Not an enterprise competitor. It sets the
developer's expectation that credentials never sit in client config, which
is the expectation our local mode (`MCP_AUTH_MODE=off`) already meets.

### 4.10 Obot

| | |
|---|---|
| Category | Protocol gateway with registry |
| Primary source | [obot.ai](https://obot.ai/) (read 2026-09-03) |
| Licence / shape | "100% Open Source" community edition; Cloud; Enterprise self-hosted on Docker/Kubernetes |

**What it does.** "Host any MCP server from the ecosystem and hand your team
one endpoint"; SSO/OIDC and RBAC; a central MCP Registry with admin review
and approval; "full request/response trails exportable for compliance".

**Different product.** Hosts and proxies servers it does not implement;
RBAC per server; audit trails are request/response logs.

**What this changes for us.** Its registry-with-approval is the admin story
Phase D's console would need to match; note for D.1 scoping.

### 4.11 Arcade.dev

| | |
|---|---|
| Category | Auth-brokering integration platform |
| Primary source | [Arcade docs home](https://docs.arcade.dev/en/home) (read 2026-09-03) |
| Shape | Cloud, Azure/AWS marketplace, or self-hosted via Helm; "hybrid MCP servers" for on-prem components |

**What it is, in its own words.** "The enterprise-ready actions runtime for
AI agents." It "handles OAuth and manages user tokens, API keys, and secrets
for tools like Gmail and Google Drive"; "7,500+ pre-built integrations across
81 MCP servers", described as "agent-optimized tools … built for reliable
execution at scale — not thin API wrappers"; identity via Okta, Auth0, Clerk;
"MCP Gateways" for policy enforcement with "contextual access controls" and
rate limiting; audit through OpenTelemetry logs.

**Overlap.** This is the closest product in *shape*: Arcade owns the tool
implementations, so it sees the upstream request (axis A partial), and it
brokers per-user upstream identity (axis E). Self-hosted is offered.

**Different product.** Its moat is the catalogue the brief chose not to
build. Policy is access control over tools, not a resource-aware
default-deny document evaluated on the canonical request. Evidence is
OpenTelemetry, not a sealed journal. It is sold to agent builders, not to
the security team of an engineering organisation.

**What this changes for us.**

1. Arcade is the product to beat on the "we own the tools" story, so the
   competitive matrix must have it, and the pitch must explain why four
   vendors with resource-classified read tools beat 7,500 integrations for
   a security buyer.
2. The brief's "integrations are not the moat" argument gains a live
   counterexample: Arcade bet the other way. Gate A should test which
   argument the design partner believes.

### 4.12 MintMCP

| | |
|---|---|
| Category | MCP-gateway startup, hosted |
| Primary source | [mintmcp.com](https://www.mintmcp.com/) (read 2026-09-03); Agent Bundles and SCIM from a secondary source |
| Shape | Hosted; SOC 2 Type II |

**What it does.** "10,000+ MCP servers, made enterprise-ready"; central
credential handling and OAuth brokering; RBAC; audit trails; PII detection
and secret scanning; Okta/Azure AD SSO. A customer quote: "an MCP gateway
that hosts our MCPs and manages credentials".

**Different product.** SaaS holding customer vendor credentials, which the
brief names as "a liability we would be volunteering for" and the regulated
segment refuses. Catalogue breadth as the pitch.

**What this changes for us.** It is the SaaS mirror image of our positioning
and a useful foil: the same buyer, the opposite data-path choice.

### 4.13 Bifrost (Maxim AI)

| | |
|---|---|
| Category | LLM gateway with MCP RBAC |
| Primary source | [Maxim article on MCP RBAC](https://www.getmaxim.ai/articles/mcp-rbac-tool-level-permissions-for-production-ai-agents/) (read 2026-09-03); licence and language not stated there (**?**) |

**What it does.** Virtual keys each carrying "a scoped set of MCP client
configurations"; deny by default ("when a virtual key has no MCP
configurations, no MCP tools are available to it"); enforcement "at inference
time, so the model never sees forbidden tools" and "again at execution time";
every tool call logged with "the tool name, the originating MCP server, the
arguments passed in, the result returned, latency, the virtual key … and the
parent LLM request".

**Overlap.** Two-layer enforcement (advertise and execute) is the same
layering as constraint 3's tool-level-plus-egress; deny-by-default keys.

**Different product.** An LLM gateway that also proxies MCP; identity is a
virtual key, not a person; arguments are logged, not judged.

**What this changes for us.** Logging the arguments and the result is a
choice the plan deliberately refuses (no response content in the journal).
Expect buyers to ask for it; the answer is the extractor model, which records
the classified resource instead of the payload.

### 4.14 obsigno

| | |
|---|---|
| Category | Evidence proxy |
| Primary source | [PyPI project page](https://pypi.org/project/obsigno/) (read 2026-09-03) |
| Licence / shape | "Apache-2.0 intended"; Python 3.10+; version 0.3.0, alpha; single maintainer |

**What it does.** "A transparent stdio proxy between an MCP client and
server" that evaluates each `tools/call` before execution, forwards allowed
calls, rejects denied ones with MCP-compatible errors, and writes every
decision to "an Ed25519-signed, hash-chained append-only ledger" in JSONL.
Policy backends: ordered JSON/YAML rules first-match-wins, Cedar via
`cedarpy`, or OPA with fail-closed behaviour. `obsigno-verify` checks the
ledger offline; "portable evidence bundles" include the chain prefix and an
optional policy snapshot. "Drop-in MCP enforcement — replace the server
command; do not change client or server code."

**Overlap.** This is Phase B's audit design (signed, hash-chained,
offline-verifiable, exportable) plus the plan's Cedar direction, already in
the open as a stdio shim.

**Different product.** No identity (stdio, one user), no upstream
credentials, no vendor knowledge, no server ownership, alpha.

**What this changes for us.** The evidence bar we set in Phase B is now a
public expectation, not a differentiator on its own. What remains ours is
that the record is produced by the component that *made the upstream
request*, so the ledger entry can name the classified resource and the
upstream identity, not just the tool name and arguments. Say that
explicitly in the audit docs. Watch for a Rust port.

### 4.15 cMCP (AgenTrust)

| | |
|---|---|
| Category | Evidence proxy, hardware-attested |
| Primary source | [GitHub README](https://github.com/agentrust-io/cmcp) (read 2026-09-03) |
| Licence / shape | MIT; Python; developer preview 0.3.x, launched June 2026; TPM 2.0, AMD SEV-SNP, Intel TDX, software mode for tests |

**What it does.** "Hardware-attested policy enforcement for MCP tool calls":
a Cedar policy bundle evaluated inside a TEE, with "the policy bundle hash …
measured into the hardware attestation report before any code runs";
decisions allow, deny, or redact; sessions produce signed TRACE claims that
"record which tools ran, which policy decided each call, and the full audit
chain", verified by `cmcp_verify` "without trusting the operator".

**Overlap.** Cedar as the engine; signed, verifiable evidence; the
"operator compromise cannot alter policy" threat model is the one CF-23
(checkpoint threat model) is about.

**Different product.** A confidential-computing proxy for a single tool
server; no identity, no upstream credentials, no vendor semantics; preview.

**What this changes for us.** CF-23 should cite this as the reference for
"what does a verifier need to not trust the operator", and answer whether
we want attestation in scope (recommend: not before Gate B; the customer's
own disk plus external retention is the posture the plan already took).

### 4.16 Snowflake Cortex AI Gateway (Natoma)

| | |
|---|---|
| Category | Platform suite |
| Sources | Secondary only (press coverage, Snowflake blog listing, 2026-09-03). **Scores are provisional.** |

**What it does (as reported).** Integrates Natoma, "a centralized MCP gateway
that enforces identity, policy and audit at the tool-call level"; policies
defined in the Horizon Catalog and enforced per tool call; per-user quotas;
"external tool calls an agent makes are approved in advance and auditable
afterward"; governs third-party agents "including Claude Code and Cursor".

**What this changes for us.** A data-platform vendor buying an MCP gateway
and selling it as suite governance is the pattern to expect from every
platform with an installed base. It is not a competitor for the engineering
stack outside Snowflake, but it will be in the buyer's vocabulary. Read the
Snowflake blog before Gate A and score properly.

## 5. What the survey changes, taken together

1. **Axis E is no longer a differentiator on its own.** Okta mints per-request
   audience-bound upstream tokens; Pomerium acquires, refreshes and injects
   upstream OAuth in an Apache-2.0 binary; Arcade and MintMCP vault per-user
   tokens; Kong swaps JWTs before the upstream. The brief's "Nobody has a
   good answer for … credential brokerage" (§"What is real") must be revised
   before Gate A. What is still ours is that the *choice* of upstream
   identity is a policy decision recorded in the same journal entry as the
   resource it touched.
2. **Axis F is a public expectation.** obsigno and cMCP ship signed,
   hash-chained, offline-verifiable ledgers; HELM AI Kernel claims signed
   receipts and an evidence pack (§6). Our Phase B journal meets the bar; it
   does not set it. The differentiator is *what the record can say*: the
   classified resource and the upstream identity, because the writer is the
   component that built the request.
3. **Axis A has two partial neighbours.** Kong's generated servers and
   Arcade's owned tools both see the upstream request. Neither evaluates a
   resource-aware default-deny policy on it. Nobody in the survey combines
   A, C, E and F; nobody does it self-hosted in one static binary. **The
   product is the combination**, and the pitch must say so rather than
   leading with any one axis.
4. **The partner already has a gateway.** Every plausible Gate A partner runs
   at least one of Cloudflare One, Okta, Entra/Agent 365, Kong, or an
   Envoy-based ingress. ADR-004 (TLS out of process) already fits; the
   positioning should be "the governed backend behind your gateway", and
   the Gate A runbook should show at least one of these in front of us.
5. **Delegated identity has a standard.** Okta's XAA uses the Identity
   Assertion Authorization Grant (`sub` + `act`), and Nango lists ID-JAG
   support. Phase C's delegated OAuth should implement ID-JAG, not a bespoke
   exchange. Record as a C.1 sub-item.
6. **The brief's "integrations are not the moat" argument has a live
   counterexample.** Arcade bet on 7,500 integrations plus auth. Gate A
   should test which argument the design partner believes.
7. **Risk register.** Add to plan §9: "Protocol gateways and identity
   vendors absorb tool-level policy, credential brokerage and audit"
   (likelihood high, impact: the generic half of Phase A stops being
   saleable). Mitigation: items 1–3 above.

## 6. Watch list (named, not yet assessed)

| Product | Why it is here | Trigger to assess |
|---|---|---|
| HELM AI Kernel | Signed ALLOW/DENY/ESCALATE receipts bundled into an "offline-verifiable EvidencePack"; an evidence proxy like §4.14–4.15 | A prospect names it, or it gains identity or upstream-credential features |
| Composio, Nango, Pipedream | Auth-brokering integration platforms like Arcade (§4.11); Nango lists ID-JAG and MCP Auth and offers BYOC | Before Gate A, to complete the category |
| TrueFoundry, Zuplo, Gravitee, Tyk | API/AI gateways adding MCP; same shape as Kong (§4.4) | A prospect runs one |
| Aembit | Non-human identity platform with attestation; adjacent to axis E for agents rather than people | If a partner wants workload identity for the gateway itself |
| Apigee | Auto-generates MCP servers from API specs, like Kong; relies on Model Armor for AI protections (secondary source) | A GCP-standardised prospect |
| Microsoft "Securing MCP: a control plane for agent tool execution" | Microsoft's own framing of the category; may signal Agent 365 roadmap | Before Gate B |
| Atlassian managed MCP | First-party connector the brief already names as preferable for an Atlassian-only buyer | Before Gate A |

## 7. How to add an entry

1. Add a row to §0 with the date and what prompted the entry.
2. Add a §4 entry using the same headings: the table of facts, *what it is
   in its own words*, *what it does*, *overlap*, *where it is a different
   product*, *what this changes for us*, *open questions*. Quote primary
   material; mark anything unverified **?**; say when a claim rests on a
   secondary source.
3. Add or correct the §3 row, and set *Last verified*.
4. If the entry changes a decision, a risk, or a gate deliverable, make
   that change in the plan and cite this file; this register does not own
   decisions.
5. If the entry changes the synthesis, update §5 in place and date the
   change in §0.
