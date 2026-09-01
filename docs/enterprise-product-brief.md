# MCP DevTools enterprise product brief

Status: product hypothesis and proposed direction; circulated to prospective collaborators  
Last reviewed: August 28, 2026

## Executive summary

`mcp-devtools` can become a product if it is positioned as more than a collection
of MCP integrations. The stronger product is a self-hosted identity, policy, and
audit gateway that gives enterprise AI clients governed access to engineering and
business systems.

The repository already supplies much of the data plane: one statically linked
Rust binary exposes 67 tools (see `tests/golden/tool_surface.json`) across
Atlassian, CI/CD, observability, collaboration, API development, device
management, learning, and financial research platforms. It supports stdio
and Streamable HTTP, keeps credentials outside tool arguments, annotates tool
behavior, writes structured audit events, bounds model-facing output, and stores
large responses as resumable artifacts.

The commercial opportunity is to add the enterprise control plane around that
data plane:

- enterprise-managed identity and authorization;
- tool-, operation-, environment-, and resource-level policy;
- centralized credential brokerage;
- tenant and user isolation;
- compliance-grade audit export;
- secure deployment and administration across multiple AI clients.

A concise positioning statement is:

> A self-hosted identity and policy gateway that gives enterprise AI agents
> governed access to the engineering stack.

## Why now

Enterprise adoption of MCP creates a recurring problem: connecting a server is
easy, but governing who can use each tool, under which identity, against which
environment, is not. Anthropic's Enterprise-Managed Authorization announcement
describes organization-wide connector provisioning through an identity provider,
with access inherited from existing groups and roles. The underlying MCP
Enterprise-Managed Authorization (EMA) extension is published as stable in the
`ext-auth` repository (see [references](#mcp-and-identity-standards); confirm the
current revision before committing to an implementation) and is open for custom
MCP servers to implement.

EMA removes repeated user consent from the connection flow, but it does not solve
all authorization concerns inside an aggregation gateway. `mcp-devtools` still
needs to decide whether an authenticated person may call `jira_post`, read a
production Grafana datasource, select a NinjaOne server alias, or act through a
particular service account. That policy and credential-brokerage layer is the
product opportunity.

## Product thesis

Organizations do not primarily need another generic MCP server. They need one
governed place to expose an approved set of operational systems to Claude
(web and desktop), Claude Code, VS Code, Codex, and other compatible MCP clients.

The product should provide:

1. **One managed endpoint.** A consistent MCP surface across engineering tools,
   with normalized safety metadata and bounded responses.
2. **Central identity.** Support standard MCP OAuth and EMA through enterprise
   identity providers such as Okta and, subsequently, Microsoft Entra ID.
3. **Default-deny policy.** Map subjects, groups, and scopes to tools, HTTP verbs,
   vendor accounts, server aliases, and environments.
4. **Credential brokerage.** Select an approved upstream identity without
   exposing vendor credentials to the MCP client or model.
5. **Attribution and evidence.** Record who requested an operation, which policy
   allowed it, which upstream identity was used, and whether it succeeded—without
   logging secrets or response content.
6. **Operational controls.** Apply rate limits, output limits, cache isolation,
   session isolation, revocation, and artifact ownership consistently.

## Existing foundation

The current project is already a useful community product and a credible base for
an enterprise edition.

| Capability | Current state | Enterprise implication |
|---|---|---|
| Integrations | 67 tools across 13 vendors (Atlassian counted once) | Broad initial catalog; prioritize a smaller supported enterprise subset |
| Tool shape | Mostly generic verb passthroughs (`jira_get`, `slack_post`, ...) plus a few purpose-built read tools (Grafana, SonarQube, Splunk, WRDS, NinjaOne DB) | Policy needs path-pattern granularity or purpose-built tools; see [policy granularity](#policy-granularity-and-the-passthrough-catalog) |
| Transports | Local stdio and loopback Streamable HTTP | Preserve local mode; add a separately configured remote HTTPS mode |
| Inbound authentication | None; loopback bind is the trust boundary | Everything in the enterprise control plane is new work; nothing to migrate |
| Secrets | Environment, scoped config, and desktop keychain | Add centralized secret providers, rotation, and credential assignment |
| Tool safety | Read-only, idempotent, and destructive annotations | Trustworthy only on purpose-built tools; on verb passthroughs they describe the HTTP method, not the upstream effect. Enforce authorization server-side |
| Audit | Structured call lifecycle and client metadata | Add authenticated subject, tenant, policy decision, and upstream identity |
| Output control | Bounded output and resumable artifacts | Bind artifacts to tenant/subject and authorize every download |
| Cache | Credential-partitioned, bounded response cache | Partition by tenant and principal unless explicitly safe to share |
| HTTP security | Loopback bind, origin allowlist, body limit | Add TLS ingress, bearer-token validation, authorization metadata, and abuse controls |

The detailed proposed Okta and cache design is documented in
[Optional Okta authorization and response-cache design](okta-auth-and-response-cache-design.md).
Current configuration and credential behavior is documented in the
[configuration reference](configuration.md).

## Two editions

### Community gateway

The community edition should remain easy to install and understand:

- local binary;
- stdio or loopback HTTP;
- credentials managed by the user;
- no mandatory identity provider or hosted account;
- existing audit, cache, output, and artifact safeguards;
- open-source integrations and a development path into the enterprise edition.

Keeping this mode unchanged protects the project's strongest adoption path and
avoids forcing enterprise complexity onto individual developers.

### Enterprise control plane

The enterprise edition would add:

- remotely accessible, TLS-only MCP endpoints;
- standard MCP OAuth and EMA support;
- Okta and Entra integrations;
- organization, group, role, and scope policy;
- per-tool and per-environment authorization;
- centrally managed secrets and upstream credential assignment;
- subject- and tenant-aware sessions, caches, and artifacts;
- SIEM/audit export, retention policy, and administrative reporting;
- deployment packages for Kubernetes and common private-cloud environments;
- an administration API and, after the policy model stabilizes, an admin UI.

The enterprise edition can initially be self-hosted. A hosted control plane may
be considered later, but hosting customer credentials and operational data would
materially increase the security, compliance, and support burden.

## The critical identity boundary

Inbound and upstream authorization are separate:

```text
Employee + IdP
      |
      | EMA or standard MCP OAuth token
      v
mcp-devtools policy gateway
      |
      | separately issued vendor credential
      v
Jira / Slack / Grafana / CI / other upstream API
```

An EMA token authorizes access to `mcp-devtools`. It must not be passed through to
an upstream API or treated as a Jira, Slack, or NinjaOne credential. MCP explicitly
forbids token passthrough because it can create confused-deputy vulnerabilities.

The product must make the upstream identity used for every operation explicit.
Three models are useful:

| Model | Advantage | Tradeoff | Appropriate use |
|---|---|---|---|
| Delegated per-user OAuth | Preserves the user's upstream permissions and attribution | Requires a separate OAuth implementation and lifecycle for every vendor | User-owned Jira, Slack, or similar data |
| Shared service identity | Simple deployment and stable automation | Can exceed a user's normal privileges; upstream audit shows the service identity | Narrow, read-only operational access |
| Hybrid | Uses delegation where available and scoped service identities elsewhere | More policy and administration complexity | Most realistic enterprise offering |

The hybrid model is the recommended product direction. Every response and audit
event should clearly identify whether it used delegated or shared authority.

## Proposed authorization model

Authorization should be default-deny in enterprise mode and evaluated before tool
dispatch. A policy decision should include at least:

- tenant and authenticated subject;
- IdP groups, roles, and granted scopes;
- MCP client identity;
- tool name and safety annotations;
- operation or HTTP verb;
- vendor, account, server alias, and environment classification;
- upstream credential identity;
- requested resource classification;
- policy version and decision reason.

Example outcomes include:

- developers may read QA logs but not production logs;
- SRE may query production Grafana but only incident commanders may mutate a
  NinjaOne production resource;
- all write tools require a narrow scope and client confirmation;
- a shared service credential may only be used for allowlisted read endpoints;
- a delegated credential cannot be silently replaced with a broader service
  account when it fails.

Three denial cases need distinct handling:

| Case | Response |
|---|---|
| Missing or invalid inbound token | HTTP `401` with a `WWW-Authenticate` challenge |
| Valid token that lacks a required scope | HTTP `403` with `insufficient_scope` in `WWW-Authenticate` |
| Valid token and scope, but policy denies this specific call (for example a production alias) | Tool-level error carrying the policy reason, plus an audit record |

The first two enforce the protected resource boundary and must not be replaced by
tool-level error text. The third stays inside the established session so the
model can adapt, rather than tearing down a Streamable HTTP session on every
per-tool denial.

## Policy granularity and the passthrough catalog

Most of the current catalog is generic verb passthroughs: `jira_get`,
`jira_post`, `slack_get`, `bb_post`, `conf_delete`, and so on. Tool-level policy
is nearly meaningless at that grain. Jira issue search is
`POST /rest/api/3/search/jql`, so "read-only Jira" cannot mean "`jira_get` only";
allowing `jira_post` for search also allows issue creation. The same applies to
Confluence CQL search and several Slack `conversations.*` methods.

Default-deny in enterprise mode therefore needs one of:

1. **Per-vendor path-pattern and method allowlists** layered over the existing
   passthrough tools (for example `POST /rest/api/3/search/jql` allowed,
   `POST /rest/api/3/issue` denied); or
2. **Purpose-built read tools** for the supported enterprise subset, in the style
   of `grafana_query_logs`, `sonarqube_search_issues`, and `splunk_search`, whose
   `readOnlyHint` is true by construction.

Option 2 is the safer product surface and the better fit for policy authoring;
option 1 preserves catalog breadth. The realistic v1 is option 2 for the
supported subset, with option 1 available for administrators who accept the
maintenance cost. This is likely the largest engineering line item in v1 and it
constrains which integrations are viable first.

## EMA implementation implications

For a managed Claude connector, the product would need to implement the MCP EMA
extension identifier `io.modelcontextprotocol/enterprise-managed-authorization`
and the surrounding OAuth resource-server requirements. At a high level:

1. Publish OAuth Protected Resource Metadata that identifies the authorization
   server and supported scopes.
2. Return a suitable `WWW-Authenticate` challenge on unauthorized MCP requests.
3. Operate or integrate with an authorization server that accepts and validates
   Identity Assertion JWT Authorization Grants (ID-JAGs).
4. Validate the IdP's signature, issuer, audience, expiry, and relevant claims.
5. Issue an MCP access token whose audience is specifically this resource server.
6. Validate that access token on every protected request and map its claims into
   the internal policy context.
7. Advertise and negotiate the EMA extension without changing local stdio mode.

EMA is optional and additive to core MCP authorization. The implementation should
therefore support graceful fallback or a clear configuration error when an MCP
client does not support it.

## Initial customer and wedge

The likely buyer is a platform engineering, security engineering, or enterprise
AI enablement team. The initial customer profile is an organization that:

- is adopting Claude Enterprise or another managed MCP client;
- already governs workforce access through Okta or Entra;
- operates several engineering systems with inconsistent connector policies;
- prefers a self-hosted or private-cloud data path;
- needs auditable, quickly revocable AI access without distributing personal API
  tokens to every employee.

The narrowest credible paid wedge is a read-oriented engineering gateway for
Atlassian, Slack, Grafana, and one CI provider. These systems cover planning,
communication, observability, and delivery while allowing the first policy model
to remain deliberately small.

## Suggested v1

### In scope

- self-hosted deployment behind a supported TLS ingress;
- one organization per deployment;
- Okta first, with an abstraction suitable for Entra later;
- standard MCP OAuth resource metadata plus EMA;
- read-only Jira, Confluence, Slack, Grafana, and CircleCI operations, exposed
  through purpose-built read tools or explicit path allowlists (not
  `*_get` alone; see [policy granularity](#policy-granularity-and-the-passthrough-catalog));
- group-to-tool and group-to-environment policy;
- tightly scoped shared credentials, with explicit audit labeling;
- authenticated subject propagation into audit records;
- subject/tenant ownership for sessions, caches, and artifacts;
- JSONL and one common SIEM export path;
- documented revocation and credential-rotation behavior.

### Explicitly out of scope

- broad write access;
- a general-purpose policy programming language;
- every existing integration at enterprise support quality;
- multi-tenant SaaS hosting;
- delegated OAuth for every upstream vendor;
- a large administration UI before the underlying policy API is stable.

### Exit criteria

The v1 is credible when an administrator can provision an employee through the
IdP, grant access to an approved set of read-only tools, observe an attributable
audit trail, revoke the employee, and verify that subsequent access fails without
manually touching the MCP client or individual connectors.

## Delivery phases

1. **Remote security boundary:** opt-in remote mode, TLS deployment guidance,
   standard MCP OAuth metadata, token validation, and protected artifacts.
2. **Policy engine:** default-deny tool/environment rules, authenticated request
   context, policy versioning, and complete decision audits.
3. **EMA:** ID-JAG exchange integration, IdP administrative configuration, and
   Claude/VS Code interoperability testing.
4. **Credential brokerage:** credential inventory, assignment policy, rotation,
   and clear shared-versus-delegated semantics.
5. **Enterprise operations:** SIEM export, metrics, rate limits, deployment
   packaging, backup/restore, and upgrade procedures.
6. **Delegated integrations:** add per-user OAuth selectively where customers
   require upstream permission fidelity.

Each phase should remain independently deployable. Enterprise features must be
explicitly enabled and must not weaken the local default.

## Business model hypothesis

A practical open-core structure is:

- Community: local gateway, open integrations, local credentials, baseline audit
  and output controls.
- Enterprise: SSO/EMA, centralized policy, secret-provider integrations, audit
  export, enterprise deployment packages, long-term support, and certified client
  compatibility.

Pricing could be based on active users or protected environments, with an annual
self-hosted license. Per-tool pricing would make governance harder to understand;
usage-based pricing could also discourage safe exploratory reads. These are
hypotheses to validate through customer interviews rather than decisions already
made.

## Competitive position and risks

First-party vendor MCP servers will continue to improve and may offer the best
per-user semantics for their own products. For example, Atlassian's managed MCP
offering is likely preferable when an organization only needs Atlassian and wants
native upstream identity.

The defensible layer for `mcp-devtools` is cross-vendor governance:

- one authorization and audit model across many tools;
- consistent controls across several MCP clients;
- policy spanning tool, environment, and credential identity;
- private deployment and data-path control, as a single static Rust binary with
  no language runtime, `unsafe` denied, and a license/advisory gate
  (`cargo deny`), which keeps the attack surface small and simplifies review;
- bounded, cache-aware, model-oriented responses;
- integration-specific safety rules that generic gateways lack.

Principal risks include:

- shared service identities creating privilege escalation or weak attribution;
- the passthrough catalog making "read-only" policy unenforceable without
  path-level rules or a rebuilt tool surface;
- the security and compliance burden of brokering many vendor credentials;
- protocol and client compatibility changing quickly;
- a broad integration catalog diluting enterprise support quality;
- first-party connectors reducing the value of basic connectivity;
- an admin UI being built before policy semantics are validated;
- remote artifact, cache, or session data crossing user or tenant boundaries.

These risks favor a read-only, self-hosted, single-tenant v1 with a small supported
integration set.

## Can this be a product? An honest assessment

Yes, but not the product the repository currently is, and the odds depend on one
bet that has not been made yet.

### What is real

- **The problem is real and getting worse.** Every organization rolling out
  Claude, Copilot, or Cursor hits "who may call what, as whom, against which
  environment" within weeks. EMA solves provisioning. Nobody has a good answer
  for cross-vendor policy, credential brokerage, and evidence; today the
  alternative is distributing personal API tokens and hoping.
- **The data plane is ahead of a from-scratch competitor.** Bounded output,
  resumable artifacts, a credential-partitioned cache, an audit lifecycle, a
  single static binary, a license/advisory gate, and a golden-locked tool
  surface represent six to twelve months of unglamorous work that most gateway
  startups have not done.
- **Self-hosted Rust is a differentiator in the right segment.** Regulated and
  private-cloud buyers who refuse SaaS in the data path are exactly the buyers
  for governed AI access.

### What is not

- **The integrations are not the moat.** Atlassian, Slack, Grafana, and CircleCI
  ship or will ship first-party MCP servers with native per-user identity. A
  generic `jira_post` passthrough loses to Atlassian's connector for an
  Atlassian-only buyer on day one. Thirteen vendors times five verbs is a support
  liability, not an asset.
- **The gateway layer is where the real competition is.** Kong, Cloudflare,
  Envoy-based vendors, Microsoft, Okta, and a growing set of "MCP gateway"
  startups are converging on authentication, policy, and audit in front of MCP
  servers. Most are protocol gateways: they do not know that a Jira search is a
  `POST`. That semantic layer is the only durable edge, and it is the part not
  yet built.
- **Credential brokerage is a liability we would be volunteering for.** Holding
  vendor secrets for many customers' many vendors is an incident waiting to
  happen. It must stay self-hosted for a long time, which caps growth and makes
  support expensive.
- **It is a security product sold to security teams.** That means SOC 2 or an
  equivalent, penetration-test reports, an SBOM, a vulnerability-disclosure
  process, and a support SLA before the first purchase order. The code is
  perhaps 30% of the work; the rest is a company.

### The bet

The product is **semantic, default-deny policy for AI agents across the
engineering stack**, not an MCP server with many connectors. That reframing
changes what gets built next:

1. Cut the catalog to four or five vendors with purpose-built read tools whose
   `readOnlyHint` is true by construction.
2. Build the policy engine, attributable audit, and inbound OAuth/EMA. That is
   the thing a buyer cannot get from Atlassian's connector or from a protocol
   gateway.
3. Prove it with two design-partner customers before pricing anything.

If two security or platform teams say "we would deploy this instead of handing
out tokens" and let us watch them try, it is a product. If not, it remains a
very good open-source gateway that a larger vendor will eventually replicate,
which is still a fine outcome and a strong credibility asset.

The failure mode is not "nobody wants it". It is trying to sell the 67-tool
catalog instead of the policy layer.

## What we need from collaborators

This brief is being circulated to find people who want to pitch in. The gaps,
roughly in the order they block progress:

| Area | What is needed | Why it matters |
|---|---|---|
| Design partners | Two organizations with Okta or Entra and a Claude/Copilot rollout willing to trial a read-only gateway | Validates the thesis before any pricing or UI work |
| Identity engineering | OAuth resource-server metadata, token validation, EMA/ID-JAG exchange, Okta then Entra | Phase 1 and 3; nothing else ships without inbound auth |
| Policy design | A small, default-deny policy model over tool, path pattern, environment, and credential identity; no general-purpose policy language | Phase 2; the actual differentiator |
| Purpose-built read tools | Jira, Confluence, Slack, CircleCI read tools in the style of the existing Grafana, SonarQube, and Splunk tools | Makes "read-only" enforceable |
| Security and compliance | Threat model, pen-test coordination, SBOM, disclosure process, SOC 2 readiness | Table stakes for a security buyer |
| Go-to-market | Customer interviews, pricing validation, first pitch material | Answers the questions in the next section |

Time commitment is flexible; the highest-leverage contribution right now is an
introduction to a design partner or a few hours on the policy model.

## Questions to validate with customers

1. Is the primary need centralized connector provisioning, tool-level policy,
   audit evidence, or credential management?
2. Will customers accept scoped shared service accounts for read-only use cases?
3. Which operations require the exact upstream user's permissions and identity?
4. Are Okta and Entra both launch requirements, or can Okta establish the wedge?
5. Which four integrations cover the first deployable workflow?
6. Must data remain fully in the customer's network?
7. Which SIEM, secret manager, and policy administration systems are mandatory?
8. Who owns the budget: security, platform engineering, or the enterprise AI team?
9. What evidence is required to approve production access?
10. How quickly must employee and group revocation take effect?

## References

### Project references

- [Project overview and supported integrations](../README.md)
- [Configuration and credential reference](configuration.md)
- [Optional Okta authorization and response-cache design](okta-auth-and-response-cache-design.md)
- [HTTP server implementation](../src/server/http.rs)
- [Audit implementation](../src/audit.rs)

### MCP and identity standards

- [MCP Enterprise-Managed Authorization overview](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
- [Stable EMA technical specification](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP authorization extensions repository](https://github.com/modelcontextprotocol/ext-auth)
- [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://www.rfc-editor.org/rfc/rfc9728)
- [OAuth 2.0 Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)
- [JWT Profile for OAuth 2.0 Authorization Grants (RFC 7523)](https://www.rfc-editor.org/rfc/rfc7523)
- [OAuth 2.0 Resource Indicators (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700)

### Product and ecosystem context

- [Anthropic: Centrally manage authorization for MCP connectors](https://claude.com/blog/enterprise-managed-auth)
- [MCP project: Enterprise-Managed Authorization announcement](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [MCP 2026-07-28 specification release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/)

