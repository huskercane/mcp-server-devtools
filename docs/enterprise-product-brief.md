# MCP DevTools enterprise product brief

Status: product hypothesis and proposed direction  
Last reviewed: August 28, 2026

## Executive summary

`mcp-devtools` can become a product if it is positioned as more than a collection
of MCP integrations. The stronger product is a self-hosted identity, policy, and
audit gateway that gives enterprise AI clients governed access to engineering and
business systems.

The repository already supplies much of the data plane: one Rust binary exposes
64 tools across Atlassian, CI/CD, observability, collaboration, API development,
device management, learning, and financial research platforms. It supports stdio
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
Enterprise-Managed Authorization (EMA) extension is stable and open for custom
MCP servers to implement.

EMA removes repeated user consent from the connection flow, but it does not solve
all authorization concerns inside an aggregation gateway. `mcp-devtools` still
needs to decide whether an authenticated person may call `jira_post`, read a
production Grafana datasource, select a NinjaOne server alias, or act through a
particular service account. That policy and credential-brokerage layer is the
product opportunity.

## Product thesis

Organizations do not primarily need another generic MCP server. They need one
governed place to expose an approved set of operational systems to Claude,
Claude Code, Codex, VS Code, and other compatible MCP clients.

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
| Integrations | 64 tools across 14 vendor families | Broad initial catalog; prioritize a smaller supported enterprise subset |
| Transports | Local stdio and loopback Streamable HTTP | Preserve local mode; add a separately configured remote HTTPS mode |
| Secrets | Environment, scoped config, and desktop keychain | Add centralized secret providers, rotation, and credential assignment |
| Tool safety | Read-only, idempotent, and destructive annotations | Use annotations as policy inputs, but enforce authorization server-side |
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

Authorization failures should use the protocol-appropriate HTTP `401` or `403`
response. Tool-level error text is not a substitute for enforcing the protected
resource boundary.

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
- read-only Jira, Confluence, Slack, Grafana, and CircleCI operations;
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
- private deployment and data-path control;
- bounded, cache-aware, model-oriented responses;
- integration-specific safety rules that generic gateways lack.

Principal risks include:

- shared service identities creating privilege escalation or weak attribution;
- the security and compliance burden of brokering many vendor credentials;
- protocol and client compatibility changing quickly;
- a broad integration catalog diluting enterprise support quality;
- first-party connectors reducing the value of basic connectivity;
- an admin UI being built before policy semantics are validated;
- remote artifact, cache, or session data crossing user or tenant boundaries.

These risks favor a read-only, self-hosted, single-tenant v1 with a small supported
integration set.

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

