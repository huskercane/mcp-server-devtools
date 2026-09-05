# Enterprise-managed authorization

Implementation is pinned to the stable ext-auth specification fetched on
2026-09-04 at `fb374c7db2b34f18ca9183882e0beecdf661892b`. The upstream README
labels this extension stable; the normative file is
[`specification/stable/enterprise-managed-authorization.mdx`](https://github.com/modelcontextprotocol/ext-auth/blob/fb374c7db2b34f18ca9183882e0beecdf661892b/specification/stable/enterprise-managed-authorization.mdx).
This is implementation and local protocol evidence only. No Claude, VS Code,
or Codex client interoperability run has been performed or claimed.

## Resource server configuration

Keep the existing signed policy, revocation list, audit journal, and OIDC
configuration. Add:

```dotenv
MCP_AUTH_MODE=oidc
MCP_OIDC_PROFILE=okta
MCP_OIDC_ISSUER=https://acme.okta.com/oauth2/mcp
MCP_OIDC_AUDIENCE=https://mcp.acme.example
MCP_PUBLIC_URL=https://mcp.acme.example
MCP_EMA_ENABLED=true
```

Use the actual issuer identifier, not the token endpoint. The audience must
equal the advertised resource exactly; use the canonical public URL without
a trailing slash. The configured issuer's trailing slash is retained for EMA
metadata checks. Configure the issuer's audience mapper accordingly. The
`okta` auth alias also works. An ordinary OIDC tenant is not automatically
an ID-JAG-capable authorization server.

Before binding HTTP, EMA opt-in fetches RFC 8414 metadata at the configured
issuer (path components follow the well-known path). It requires exact issuer
identity, the ID-JAG grant profile and JWT-bearer grant support. Unavailable,
redirected, oversized or mismatched metadata refuses startup. Endpoints must
use HTTPS except loopback HTTP. Metadata endpoints are trusted through the
operator-configured issuer; deployment egress rules should constrain them.

The public protected-resource metadata continues to point at that issuer.
`initialize` advertises
`io.modelcontextprotocol/enterprise-managed-authorization: {}` only when
inbound auth and EMA are enabled. The flag is fixed for the server instance;
change it by restart. Grant-profile discovery remains in the external
**authorization server's** metadata; we do not forge a local AS document or
mint local access tokens. Existing signed access-token validation, scope
checks, revocation, rate limiting, policy, and durable tool audit all apply.
An ID-JAG header (`oauth-id-jag+jwt`) is always rejected as a resource bearer,
even if a misconfigured grant carries the resource audience.

The issuer owns grant signature/issuer/audience/expiry validation, client
binding, one-time assertion/replay handling and account mapping. A fixture
HTTP issuer cannot prove those controls in a real tenant. Verify them in the
external matrix below before an interoperability claim.

## Exchange helper

The stable flow uses the client's SSO identity assertion at the IdP for
RFC 8693 token exchange, followed by RFC 7523 JWT-bearer at the resource AS.
The first request's audience is the **AS issuer**; its resource is the MCP
resource. The second request carries the ID-JAG as `assertion`. See the
[stable profile](https://github.com/modelcontextprotocol/ext-auth/blob/fb374c7db2b34f18ca9183882e0beecdf661892b/specification/stable/enterprise-managed-authorization.mdx),
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), and
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html).

`auth::ema::OidcExchange` implements these two HTTP legs. The external issuers
remain responsible for authorization. This is a client adapter beside the
OIDC validator, not another `TokenValidator` or a tool credential broker;
the raw assertion never becomes a principal or a vendor credential.

The Unix CLI makes the adapter usable for operator protocol checks:

```sh
mcp-devtools auth exchange \
  --idp-issuer https://acme.okta.com \
  --issuer https://acme.okta.com/oauth2/mcp \
  --resource https://mcp.acme.example --scope mcp:tools \
  --idp-client-id requesting-client \
  --resource-client-id registered-resource-client \
  --identity-token-file /run/credentials/client-id-token \
  --idp-client-assertion-file /run/credentials/idp-client-assertion \
  --resource-client-assertion-file /run/credentials/as-client-assertion \
  --output-token-file /run/credentials/mcp-access-token --json
```

SSO and private-key-JWT creation belong to the calling client. Supply fresh,
independently audience-bound client assertions for each issuer. Omitting an
assertion selects a pre-registered public client; it does not bypass issuer
authentication requirements. No shared secret or credential-chain fallback
is attempted. For SAML SSO, obtain the IdP refresh token first and supply it
with `--refresh-token`; this helper does not implement SAML login.

The output must be a new file, created mode 0600 on Unix; JSON stdout is only
`{"data":{"written":true}}`. The file contains the final access token.
On failure, stdout contains `error` and `error_description`, with nonzero exit;
issuer bodies, assertions and tokens are never printed. A failed output write
may leave a partial newly created file: remove it before a fresh exchange.
The output-file helper is unavailable on Windows pending a private ACL writer;
the exchange adapter and resource server are portable. This helper does not
implement automatic refresh or token persistence for external MCP clients.

Inputs and issuer responses are bounded to 64 KiB, each HTTP request has a
30-second timeout, and redirects and automatic retries are disabled. A failed
exchange must not be retried with a consumed assertion: obtain fresh material.
The ID-JAG response requires the correct issued-token type and JWT header;
Okta's `Bearer` and the profile's `N_A` response labels are accepted only for
the intermediate exchange. The final response must be a bearer access token.
The helper is not a resource-server validator: the resource validates every
final token through the existing OIDC `TokenValidator`.

## Okta Cross-App Access fixture semantics

The fixtures in `tests/fixtures/ema/` are synthetic, shaped from
[Okta's XAA token exchange documentation](https://developer.okta.com/docs/guides/ai-agent-token-exchange/-/main/).
They are not captured production tokens. The tests replace timestamps and
sign with the repository's test RSA key. `sub` remains the subject. `act.sub`
is the current actor; nested `act` objects are history. Signed actor identities
are retained in `TokenFacts` as a bounded chain of at most eight, current first.
Malformed actors fail authentication. Actor groups, scopes, expiry and nested
history never replace top-level claims or grant privileges. This follows
[RFC 8693 §4.1](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1).

Actor-aware policy rules and actor fields in the frozen audit principal schema
are not introduced here. The issuer gates requesting clients; local policy
and journal identity remain the top-level subject. TokenFacts retain actor
identity within authenticated requests. If a deployment needs independent
actor policy or actor searchable audit, scope that schema change explicitly.

## Required external interoperability matrix

Run **every test E01–E16 separately for each row**. Record exact client build,
OS/browser, subscription/organization features, IdP tenant/profile and policy,
AS metadata, MCP build/commit, transport/protocol version, UTC time, result,
and redacted evidence references. A missing client feature is **unsupported**,
not a pass. No row below has been run.

| Client | Required configurations to identify | Status |
|---|---|---|
| Claude web | Browser/version, organization connector and SSO/admin provisioning settings | Not run |
| Claude desktop | Desktop build and OS, organization connector/SSO versus local configuration | Not run |
| Claude Code | CLI build, terminal/OS, organization policy and remote HTTP MCP configuration | Not run |
| VS Code | VS Code build, MCP-hosting extension/version, remote/local extension host and organization settings | Not run |
| Codex | Exact surface (CLI, IDE extension, app or hosted), build/OS and organization remote MCP/SSO configuration; each surface claimed needs a separate run | Not run |

| ID | Required test and evidence |
|---|---|
| E01 | Admin provisions the approved requesting client, resource app and user/group connection; verify access from corporate SSO without per-server consent. Record required client registration/auth method at both issuers. |
| E02 | Unauthenticated MCP request receives 401 with `resource_metadata`; client follows the correct protected-resource URL, matches resource and discovers the configured AS. Capture redacted requests. |
| E03 | Client discovers `authorization_grant_profiles_supported` with ID-JAG and the JWT-bearer grant. Remove the profile marker and test the client's explicit unsupported/fallback behavior; it must not silently send a grant to `/mcp`. |
| E04 | Client's initialization declares the extension where supported and recognizes server declaration. Record negotiated MCP version and actual extension objects. A manually injected bearer is not an EMA pass. |
| E05 | OIDC SSO ID token → RFC 8693: exact grant type, requested ID-JAG type, subject-token type, AS issuer audience, MCP resource and least required scopes. Validate client authentication at the IdP. |
| E06 | If SAML support is claimed: SAML SSO → IdP refresh token → ID-JAG with refresh-token subject type. Otherwise mark this capability unsupported, not tested through an OIDC substitute. |
| E07 | ID-JAG → RFC 7523 at the discovered resource AS, with the registered client ID and required fresh client authentication. Assert no identity token/ID-JAG goes to MCP or vendor endpoints. |
| E08 | Real AS refuses forged signature, wrong issuer, wrong AS audience, wrong resource, wrong client binding, expired/not-yet-valid grant and replayed grant/client assertion. Retain issuer audit/error evidence. |
| E09 | Final access token has the correct MCP audience, issuer, lifetime and least scopes. Real `initialize`, `tools/list`, an allowed read and a policy-denied tool call work as expected; correlate durable subject audit records. |
| E10 | Okta XAA user `sub` plus current `act.sub` and nested history survive issuance as expected. Verify subject remains the user and actor/history groups/scopes cannot escalate. Record any claim transformation by the real issuer. |
| E11 | Missing required scope yields 403/insufficient_scope and the client handles it without an infinite re-auth loop or automatically requesting admin scope. |
| E12 | Access-token expiry, refresh/re-exchange and session reconnection work; new assertions are used as required. Sign-out and account switching do not reuse another subject's MCP session. |
| E13 | Remove the IdP connection/user assignment: new grants are denied. Test existing-token lifetime explicitly; issuer revocation alone is not assumed immediate. Apply local deny-list subject/token/cutoff changes and prove immediate gateway refusal and durable control evidence. |
| E14 | Rotate and withdraw real issuer signing keys; test valid new-key access, cached withdrawn-key eviction, unknown-kid rate limiting, temporary discovery/JWKS outage and recovery with the documented fail-closed/last-good behavior. |
| E15 | Reject mismatched tenant/issuer/resource, ID-JAG-as-bearer, forged/expired access token, cross-subject session reuse and malicious discovery redirects. Ensure no credential appears in logs, telemetry, shared URLs or error dialogs. |
| E16 | Exercise 429/Retry-After, IdP/AS errors, network interruption during both exchanges, client restart and credential-store recovery. Confirm no silent assertion replay, secret leakage, unauthenticated fallback or privilege escalation. |

Local tests cover real HTTP form encoding and resource routing, issuer metadata
refusal, synthetic signed Okta claim shapes, CLI private output and error
redaction. They do not simulate the internal security policy of a real Okta
AS. A generic Keycloak container does not stand in for Okta XAA grant support;
these tenant and client runs remain external evidence (CF-35).
