# MCP security best practices: what we implement, and what we don't

Written 2026-09-06 against the MCP **2026-07-28** [Security Best
Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
page, which complements the MCP Authorization specification.

This is a conformance map, not a summary of the spec. Each section names the
attack the spec describes, states whether it applies to this server, and cites
the code that mitigates it. Where we fall short of a `SHOULD`, the section says
so plainly and says why — a gap an operator can read is worth more than a
claim they cannot check.

The audience is whoever is answering a security questionnaire about this
server, and whoever changes the auth boundary next and needs to know which
properties are load-bearing.

## Summary

| Spec section | Applies | Status |
|---|---|---|
| Confused deputy | No — not an OAuth proxy | N/A by architecture |
| Token passthrough (`MUST NOT`) | Yes | Met, enforced by type shape |
| SSRF | Yes (control-plane fetches only) | Met; private-IP blocking is an operator control, not code |
| State handle hijacking (`MUST`, `MUST NOT`) | Yes | Met |
| Local MCP server compromise | Yes | Met for stdio; `MCP_AUTH_MODE=off` over HTTP is a documented deviation |
| OAuth authorization URL validation | Yes (console) | Met |
| stdio transport in proxy scenarios | No — no proxy architecture | N/A |
| Mix-up attacks | Not today (single issuer) | Defended anyway (RFC 9207 `iss`) |
| Localhost redirect URI impersonation | No — console redirect is the public URL | N/A |
| CIMD trust policies | No — no client-ID metadata documents | N/A |
| Scope minimization | Yes | Met |

Four items are not "met" in the unqualified sense. They are listed under
[Deviations and residual risk](#deviations-and-residual-risk) rather than
buried in the sections above.

## Confused deputy

**N/A by architecture.** The spec's attack needs all four of: a static client
ID against a third-party authorization server, dynamic client registration by
MCP clients, a third-party consent cookie, and no per-client consent at the
proxy.

This server is not an OAuth proxy. It does not register clients, does not mint
authorization codes, does not hold a static client ID on behalf of MCP
clients, and does not sit between an MCP client and a third-party
authorization server. Clients obtain their own tokens from the operator's
identity provider and present them here; the RFC 9728 metadata document at
`/.well-known/oauth-protected-resource` names that provider
(`src/server/auth.rs`, `protected_resource_metadata`) and the flow ends there.

The console (`src/console/`) is a first-party public client with its own
client ID, signing its own administrator in. It proxies nothing on behalf of
a third party, so there is no consent to be confused about.

**If this changes**, the whole "Required Protections" block of the spec —
per-client consent storage, a consent UI with CSRF protection and
`frame-ancestors`, `__Host-` consent cookies bound to `client_id`, exact-match
`redirect_uri` validation, and `state` stored only *after* consent approval —
becomes mandatory. It is not partially satisfied today; it is simply not
reached.

## Token passthrough

> MCP servers **MUST NOT** accept any tokens that were not explicitly issued
> for the MCP server.

**Met.** Two independent halves, both enforced.

**Audience validation.** The JWT validator pins the audience to the configured
resource identifier and the issuer to the configured issuer, accepting both
trailing-slash spellings because providers disagree about it
(`src/auth/oidc.rs:751-752`). `exp`, `iss` and `aud` are required spec claims,
`nbf` is validated when present, and clock skew is bounded by configuration.
The signing algorithm is pinned to RS256 on both the token header
(`src/auth/oidc.rs:1137`) and the JWK itself, so neither `alg: none` nor an
HMAC-for-RSA key confusion is representable. A token minted for another
resource fails `aud` and never reaches a tool.

**No passthrough.** The stronger property is that there is nothing to pass
through. The inbound bearer is read from the header, handed to the validator,
and dropped. What survives is `Principal` (`src/policy/mod.rs:60`: tenant,
subject, groups, scopes, authority) and `TokenFacts`
(`src/ports/token_validator.rs:134`: `iat`, `jti`, validated actors) — claims,
never the credential. No vendor client *can* forward the caller's token
because no vendor client can obtain it. Vendor credentials are resolved
independently from configuration or the OS keychain (`src/auth/secrets.rs`).

This is guiding constraint 4 in `docs/enterprise-product-plan.md` §0, and it
is enforced by shape rather than by discipline — the failure mode the spec
warns about is unreachable rather than merely avoided.

## Server-side request forgery

**Met**, and by a stronger mechanism than the spec asks for, with one
defense-in-depth item left to the operator.

The spec's SSRF section is written for MCP *clients* following OAuth discovery
URLs supplied by a malicious server. The mirror-image surface here is the
control-plane fetches this server makes for itself: OIDC discovery, JWKS, SIEM
forwarding, Vault, and the console's token exchange.

**Tool arguments cannot name a host.** This is the important one, and it is
structural. `CanonicalTarget` accepts only a path-and-query, always joined onto
the vendor's configured base URL; anything shaped like an absolute URL
(`scheme://`) is rejected outright rather than sent as a nonsense path, and
user-info is unrepresentable rather than merely filtered
(`src/policy/canonical.rs`). Scheme, host and port never come from a request.
No tool in `src/tools/` takes a URL parameter. An LLM cannot steer an outbound
request at `169.254.169.254` because it cannot steer the host at all.

**HTTPS enforced.** Every operator-supplied and every discovered URL is held to
https-or-loopback by one shared allowlist check
(`require_https_unless_loopback`, `src/auth/oidc.rs:495`), with parallel checks
at each other boundary: `MCP_PUBLIC_URL` (`src/server/auth.rs`), the admin
client's base origin (`src/admin/http.rs`), Vault (`src/secrets/vault.rs`), and
SIEM forwarding (`src/audit/forward/`). This matches the spec's "reject
`http://` except for loopback" bullet, including the development opt-out.

**Redirects are never followed.** Every `reqwest` client in the process is
built with `redirect::Policy::none()` — `src/auth/oidc.rs:429`,
`src/admin/http.rs:41`, `src/server/http.rs:427`, `src/audit/forward/http.rs:172`,
`src/auth/ema.rs:105`. The spec lists redirect chains as an attack pattern and
suggests "consider disabling automatic redirect following"; we disable it
everywhere, which also keeps a bearer from travelling to a second host.

**Discovery documents are verified, not trusted.** A discovery document must
name the issuer that was configured, and each endpoint it advertises
(`jwks_uri`, `authorization_endpoint`, `token_endpoint`) is parsed and held to
the same https-or-loopback rule before use (`discover_endpoints`,
`src/auth/oidc.rs:594`). Bodies are byte-bounded.

**Not done: private-IP range blocking.** See
[Deviations](#deviations-and-residual-risk).

## State handle hijacking

> MCP servers that implement authorization **MUST** verify all inbound
> requests. MCP servers **MUST NOT** treat possession of a state handle as
> authentication.

**Met.** Every handle this server mints is bound server-side to the principal
that created it, and a handle presented by anyone else is indistinguishable
from one that does not exist.

**MCP session IDs.** `enforce_session_owner` (`src/server/session.rs:200`) runs
inside the bearer middleware, so the validated `Principal` is already in the
request extensions. A request naming a session another principal owns — or one
with no binding — gets the same `404` rmcp gives an unknown session
(`session_not_found`, `src/server/session.rs:235`), so a session ID is not a
capability and probing does not distinguish "not yours" from "not there". A
request with no session ID passes through; if its response *creates* a session,
the session is bound to the requester before the response leaves.

**Artifact IDs.** Identical treatment: only the principal that created an
artifact may download it, and a cross-owner request is the same `404` as an
unknown ID (`download_artifact`, `src/server/http.rs:844`). Without inbound
auth the requester is `local`, which is also what every locally created
artifact is owned by, so community mode is unchanged.

**Console session and login IDs.** 256 bits from a CSPRNG, base64url
(`random_id`, `src/console/session.rs:113`) — the spec's "secure,
non-deterministic handles ... avoid predictable or sequential identifiers".
Both maps are bounded and expiring; a login in flight is consumed exactly once
(`Bounded::take` removes before checking expiry, `src/console/session.rs:68`)
and lives at most five minutes, which is inside the spec's suggested ten.

**Revocation.** When the revocation list changes, sessions belonging to newly
revoked subjects are closed and the validated-token cache is cleared
(`watch_revocations`, `src/server/http.rs`), so nothing derived from a revoked
token outlives it. See `docs/revocation-runbook.md`.

## Local MCP server compromise

The spec's guidance for servers intended to run locally: use `stdio` to limit
access to just the MCP client, or if using an HTTP transport, require an
authorization token or use a Unix domain socket.

**stdio: met.** `src/server/stdio.rs` is the default local transport and is
reachable only by the process that spawned it.

**HTTP with `MCP_AUTH_MODE=oidc`: met.** Every tool call needs a validated
bearer.

**HTTP with `MCP_AUTH_MODE=off`: a documented deviation.** See
[Deviations](#deviations-and-residual-risk).

**DNS rebinding** — listed by the spec as the third local-server attack — is
blocked for browsers by a loopback-only `Origin` allowlist applied globally to
the transport's routes (`origin_allowlist`, `src/server/http.rs:1020`;
`is_allowed_origin`, `:1053`). An attacker page at `evil.example` that resolves
to `127.0.0.1` still sends `Origin: https://evil.example` and is refused with
`403`. A missing `Origin` is allowed, because non-browser MCP clients do not
send one and the header is exactly what distinguishes them; browsers send it on
every cross-origin fetch and form post, which is the case that matters.

A **fail-closed startup gate** refuses to boot with a non-loopback bind while
no inbound authentication exists (`validate_startup_security`,
`src/server/http.rs:1198`). The loopback bind *is* the community trust
boundary; removing it without authentication would expose every configured
vendor credential to the network, so that combination is not a warning, it is a
refusal.

## OAuth authorization URL validation

**Met.** The spec requires clients to allow only `http`/`https` (loopback-only
for `http`), reject `javascript:`, `data:`, `file:`, `vbscript:`, prefer
allowlists over blocklists, and never open URLs through a shell.

The console is the only component that sends a browser to a provider-supplied
URL. `require_https_unless_loopback` (`src/auth/oidc.rs:495`) is
allowlist-based — it admits `https`, and `http` only on loopback, rejecting
everything else — and it is applied to `authorization_endpoint` and
`token_endpoint` at discovery time (`src/auth/oidc.rs:594`), before either is
used. A `javascript:` or `data:` endpoint therefore cannot reach a `Location`
header. No shell is used to open a URL anywhere in this codebase.

**Content Security Policy.** The console serves
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
with no inline script or style, plus `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `no-store` on
everything but static assets (`CSP` and `security_headers`, `src/console/mod.rs`).
This is stricter than the spec's `script-src 'self'` suggestion and covers the
clickjacking requirement the confused-deputy section states for consent pages.

**Cookies.** `HttpOnly; Secure; SameSite=...; Path=...; Max-Age=...` on both
console cookies (`set_cookie`, `src/console/mod.rs`). The session cookie is
`SameSite=Strict` and scoped to `/console`; the login cookie is `SameSite=Lax`
— it must survive the provider's cross-site redirect back to the callback, which
`Strict` would drop — and is scoped to the callback path alone, for five
minutes. The `__Host-` prefix is not used: it requires `Path=/`, and path
scoping is the more valuable of the two properties here. The spec mandates
`__Host-` for *consent* cookies in an OAuth proxy, which we do not have.

**CSRF.** Every non-GET console request must carry the console's own `Origin`,
or `Sec-Fetch-Site: same-origin` when no `Origin` is present (`same_origin`,
`src/console/mod.rs`). Locked by
`tests/console_tests.rs::non_get_requests_need_the_public_origin`, which
exercises nine refused origin/fetch-site combinations and three accepted ones.

**PKCE and `state`.** Authorization-code flow with PKCE `S256`
(`src/console/login.rs:35`); the console is a public client and holds no client
secret. A 256-bit `state` is stored server-side, keyed by the login cookie, and
compared on callback; a mismatch, an empty value, or a second use of the same
login is refused (`callback_handler`, `src/console/mod.rs`).

## stdio transport in proxy scenarios

**N/A.** The spec is explicit that this "only applies to MCP implementations
that use a proxy architecture, not to direct `stdio` transport usage". This
server is not a proxy: it never spawns MCP servers as child processes, and
there is no local proxy authentication token to steal. `unsafe_code = "deny"`
and no process-spawning surface leave nothing for the escalation path to reach.

## Mix-up attacks

**Not applicable today; defended anyway.** The attack needs a client talking to
several authorization servers, one of them hostile. The console has exactly one
configured issuer, and the JWT validator pins `iss` to it
(`src/auth/oidc.rs:751`), so an authorization response from a different
provider cannot yield a usable token here.

The spec's mitigation is RFC 9207 authorization-response validation: bind the
response to the authorization server recorded before the redirect. The console
validates the `iss` parameter when the provider returns one, comparing it to
the configured issuer and refusing a mismatch (`callback_handler`,
`src/console/mod.rs`). An absent `iss` is accepted, because the spec notes the
mitigation "depends on honest authorization servers emitting `iss`" and not all
providers do. The check costs nothing today and stops the configuration from
silently becoming unsafe if a second issuer is ever added.

## Localhost redirect URI impersonation

**N/A.** The console's `redirect_uri` is derived from `MCP_PUBLIC_URL`, which
must be `https` (or `http` on loopback for development) and is validated at
startup (`src/server/auth.rs`). It is a registered server URL, not a
`localhost` port any local process could claim. We also do not use Client ID
Metadata Documents, which is the precondition for the spec's attack.

## CIMD trust policies

**N/A.** This server does not act as an authorization server and does not
accept URL-based client IDs, so there is no client-metadata document to fetch
and no trust policy to apply.

## Scope minimization

**Met.**

- **Two scopes, no wildcards.** `mcp:tools` for the data plane
  (`MCP_REQUIRED_SCOPE`, default in `src/server/auth.rs`) and `mcp:admin` for
  the control plane, which is a separate boundary with its own rate limiter
  (`InboundAuth::for_admin`). No `*`, `all`, or `full-access` scope exists —
  the spec's first "common mistake".
- **Scope is not the only gate on the control plane.** `mcp:admin` admits a
  kind of principal as well as a scope: a token the provider positively marks
  as a machine's (per profile, on validated claims — never on subject naming)
  is refused at `/admin/*` under the default `MCP_ADMIN_PRINCIPALS`, because
  the two-person approval rule compares subjects and two service accounts
  would satisfy it. Locked by `tests/admin_principal_kind_tests.rs`; CF-42
  carries the per-tenant evidence that a real provider emits the marker.
- **The catalog is not published.** `scopes_supported` in the RFC 9728
  document carries only the required scope, not every scope the server knows
  (`src/server/auth.rs:338`) — the spec's second "common mistake". Locked by
  `tests/inbound_auth_tests.rs`.
- **Precise challenges.** A token that validates but lacks the scope gets `403`
  with `WWW-Authenticate: ... error="insufficient_scope", scope="<required>"`
  naming exactly the scope needed (`insufficient_scope`,
  `src/server/auth.rs:497`) — the spec's "emit precise scope challenges; avoid
  returning the full catalog".
- **Scopes are not the authorization decision.** The spec's last common mistake
  is "treating claimed scopes in token as sufficient without server-side
  authorization logic". A valid, correctly scoped token only gets a request as
  far as the policy engine, which decides per action on the canonical outbound
  request and journals the decision (`src/policy/`, plan §1.3). Scope is
  admission; policy is authorization.

## Deviations and residual risk

Four items, in the order an operator should care about them.

### 1. `MCP_AUTH_MODE=off` over loopback HTTP has no inbound token

**Spec:** local servers using an HTTP transport **SHOULD** require an
authorization token or use a Unix domain socket.

**What we do:** in community mode there is no inbound authentication. The
loopback bind is the trust boundary, and startup refuses any non-loopback bind
in this mode (`validate_startup_security`).

**Residual risk:** any process running as any user on that host can call every
tool with the operator's full vendor credential set. The `Origin` allowlist
stops a browser, not a local process.

**Mitigation available to operators:** use the stdio transport for local use —
it is the default and it is reachable only by the client that spawned it — or
run with `MCP_AUTH_MODE=oidc`. This is a deliberate posture (plan §1.2), not an
oversight, but it is weaker than the spec's `SHOULD` and should be stated as
such in any assessment. Whether to close it — a static local token, or a Unix
domain socket — is tracked as **CF-44**.

### 2. No private-IP range blocking on control-plane fetches

**Spec:** clients **SHOULD** block requests to private and reserved ranges
(`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `fc00::/7`,
`fe80::/10`), while also warning "avoid implementing IP validation manually"
because of encoding tricks, and recommending egress proxies.

**What we do:** https-or-loopback only. We do not resolve and range-check.

**Residual risk:** narrow. Attacker-controlled URLs cannot reach these code
paths — tool arguments cannot name a host, and the only URLs fetched come from
operator configuration or from a discovery document served by the configured
issuer over TLS. The realistic case is a compromised or misconfigured identity
provider naming, say, `https://169.254.169.254/...` as its `jwks_uri`. Redirect
following is already off, which removes the redirect-chain variant, and the
TOCTOU DNS-rebinding variant the spec describes would additionally need the
attacker to control DNS for a name with a valid certificate.

**Why not fixed in code:** the spec itself advises against hand-rolled IP
validation, and a correct implementation must pin DNS between check and use. An
egress proxy enforcing network policy — the spec's own recommendation — is the
right control, and it belongs in the deployment, not in this binary.

**Not yet written down:** no runbook currently states the outbound network
posture. `docs/air-gap-runbook.md` covers offline transfer, JWKS provisioning
and vendored builds, not egress restriction, and every other occurrence of
"egress" in `docs/` refers to the *policy* chokepoint in `src/policy/egress.rs`
rather than network policy. Tracked as **CF-43**.

**Action:** operators running this in a cloud environment should restrict
egress from the gateway to the identity provider, the SIEM, and the configured
vendor hosts. Blocking the instance metadata endpoint (`169.254.169.254`) is
the specific control worth naming. Until CF-43 lands, this paragraph is the
only place that is written down.

### 3. `openid` is requested but no ID token is validated

**What we do:** the console requests `openid mcp:admin` by default and reads
only the `access_token` from the exchange (`src/console/login.rs:109`). It does
not request or validate an ID token; the administrator's identity comes from
the access token, which the admin API validates at its own boundary.

**Residual risk:** none identified. Security comes from PKCE, `state`, and the
audience-validated bearer. `openid` remains in the default scopes because
several providers expect it on an OIDC authorization request and operators have
configured against it.

**Previously:** a `nonce` was generated and sent but never verified, because
verifying it requires an ID token nobody validated. That parameter has been
removed rather than left as a check that appears to exist and does not.

### 4. Console routes sit outside the transport's `Origin` allowlist

**What we do:** the console router is merged *after* `.layer(origin_allowlist)`
and `.layer(cors)` in `build_app_inner` (`src/server/http.rs`), so neither
applies to it. This is deliberate and necessary: the allowlist is loopback-only,
and the console is served at the deployment's real public origin, which it would
reject.

**Compensating controls:** the console carries its own origin check on every
non-GET request (`same_origin`), `SameSite` cookies, and a CSP with
`form-action 'self'` and `frame-ancestors 'none'`.

**Why it is called out:** the correctness of this depends on axum's layer
ordering — `.layer()` applies to routes registered before it — which a refactor
could silently invert. It is locked by
`tests/console_tests.rs::non_get_requests_need_the_public_origin`: that test
runs through the composed router and asserts `Origin: https://mcp.example`
returns `200`, which is only possible if the loopback allowlist does not cover
console routes. A separate assertion checks that the console's `403` does not
leak into the server's fallback for unknown paths.

## Keeping this document true

Re-read this page against the spec whenever:

- the MCP specification revision this server targets changes (currently
  `2026-07-28`, see `with_stateless_protocol_metadata_required` in
  `src/server/http.rs`);
- a new inbound authentication mode, issuer, or client is added — in
  particular, anything that would make this server an OAuth proxy, which
  activates the entire confused-deputy section;
- a tool gains a parameter that reaches an outbound URL, which would end the
  structural SSRF argument in [Server-side request forgery](#server-side-request-forgery);
- a new handle type is returned to callers, which needs the owner binding
  described in [State handle hijacking](#state-handle-hijacking).
