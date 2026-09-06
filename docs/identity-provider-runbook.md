# Identity provider runbook

How to point the gateway at each supported identity provider, what to
configure on the provider's side, and the claim-shape gotchas the profile
already handles (plan §3.9, WP C.1b). There is one validator; a **profile**
is the set of defaults and corrections that makes a provider's tokens
readable by it. Everything a profile decides can be overridden with the
`MCP_OIDC_*` settings in [`configuration.md`](configuration.md).

Common to every provider:

- `MCP_AUTH_MODE=oidc`, `MCP_OIDC_PROFILE`, `MCP_OIDC_ISSUER`, and
  `MCP_OIDC_AUDIENCE` are the whole identity configuration in the common
  case. `MCP_AUTH_MODE=okta` with `MCP_OKTA_*` is the Okta profile under
  its original name; do not mix the two families.
- The token must be an RS256 **JWT access token** with a `kid`. An opaque
  access token, an ID token, or an HMAC-signed token is refused.
- The subject the profile names is what policy `subjects`, the revocation
  list, session binding, and every audit record key on. Choose it once;
  changing it later re-keys every existing revocation entry.
- The principal's `authority` in the audit journal is the issuer URL, so a
  record says which provider vouched without the format naming a vendor.
- Every principal is stamped with `MCP_TENANT`, defaulting to the issuer's
  host. Set it explicitly where the host is a shared one
  (`login.microsoftonline.com`, `<tenant>.auth0.com` are fine; a shared
  Keycloak host serving several realms is not).
- Rotation: the gateway refetches keys on an unknown `kid` (one fetch per
  30 s) and every 10 minutes in the background; a withdrawn key stops
  vouching for cached tokens at the next fetch. Rotate at the provider;
  nothing needs restarting. [`revocation-runbook.md`](revocation-runbook.md)
  covers a *compromised* key.

## Console client registration (D.1)

Register a separate **public client** using authorization code with S256
PKCE and no client secret. The callback is exactly `MCP_PUBLIC_URL` without
its trailing slash plus `MCP_CONSOLE_REDIRECT_PATH` (default
`/console/callback`). Set its id as `MCP_CONSOLE_CLIENT_ID`. The console
exchanges the code server-side and retains only the access token; it does
not use an IdP SDK, consume an ID token, or refresh tokens. See the
[console runbook](console-runbook.md) for the Strict-cookie landing page.

**Evidence boundary:** every console registration section below is unproven
against a real tenant, including Okta and Keycloak. The existing validator
fixtures/live tests and wiremock console tests do not prove interactive
client registration. CF-38 in the [register](enterprise-carry-forward.md)
tracks a successful browser login and admin call per provider, including
Entra's scope and code-redemption compatibility. Do not infer production
interoperability from ADR-013's acceptance.

## Okta

| Setting | Value |
|---|---|
| `MCP_OIDC_PROFILE` | `okta` (or `MCP_AUTH_MODE=okta` with `MCP_OKTA_*`) |
| `MCP_OIDC_ISSUER` | `https://<org>.okta.com/oauth2/<authorization server id>` — a **custom** authorization server, not the org server |
| `MCP_OIDC_AUDIENCE` | the authorization server's *Audience* setting |
| Keys | `{issuer}/v1/keys` |
| Scopes | `scp` array |
| Subject | `sub` |
| Groups | `groups` |

On the Okta side: a custom authorization server with the audience above;
an access policy that grants `mcp:tools` (or your `MCP_REQUIRED_SCOPE`)
to the client; a `groups` claim on the access token (Security → API →
Authorization Servers → Claims → *groups*, value type *Groups*, filter as
needed — a filter of `.*` sends every group). Tokens from the org server
(`https://<org>.okta.com`) are not verifiable with published keys; the
issuer must be a custom server.

### Console registration — Okta

Create an OIDC **Native Application** or **Single-Page Application**, with
Authorization Code enabled and client authentication **None** (PKCE).
Register the exact HTTPS callback and assign the administrators who may
sign in. On the custom authorization server, grant this client `mcp:admin`
through its scopes and access policy; keep `MCP_CONSOLE_SCOPES="openid
mcp:admin"`. Its Audience must match the gateway's configured audience.
The console sends no `audience` or `resource` parameter for Okta: the custom
authorization server selects it. See [Okta's PKCE registration guide](https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/).

## Microsoft Entra ID

| Setting | Value |
|---|---|
| `MCP_OIDC_PROFILE` | `entra` |
| `MCP_OIDC_ISSUER` | `https://login.microsoftonline.com/<tenant id>/v2.0` for v2 tokens; `https://sts.windows.net/<tenant id>/` for v1 |
| `MCP_OIDC_AUDIENCE` | the app registration's *Application ID URI* (`api://<client id>`) or, for v2 tokens, the client id |
| Keys | discovery: `{issuer}/.well-known/openid-configuration` → `jwks_uri` |
| Scopes | `scp`, a space-separated **string** |
| Subject | `oid` |
| Groups | `groups`; or `roles` for app roles |

On the Entra side: an app registration exposing an API scope (so tokens
carry your audience rather than Graph's); `accessTokenAcceptedVersion: 2`
in the manifest if the issuer above is the v2 one (the token's `iss` and
`ver` must agree with the configured issuer — a v1 token against the v2
issuer is `wrong_issuer`); *Token configuration → Add groups claim* for
group membership. Use a specific tenant id: the `common` and
`organizations` discovery endpoints return a templated issuer, which the
gateway refuses to take keys from.

Gotchas the profile handles:

- **`sub` is pairwise per application.** The same person has a different
  `sub` in every app, so the profile binds to `oid`, the directory object
  id. Setting `MCP_OIDC_SUBJECT_CLAIM=sub` is possible but means a
  revocation entry written from one app's tokens does not match another's.
- **Groups overage.** Past roughly 200 groups (150 for SAML, 6 for
  implicit flow) the token carries no `groups` claim and instead
  `_claim_names` / `_claim_sources` pointing at Graph. The gateway does
  not follow that pointer; the token is refused as `groups_overage`. Fix
  it at the source: restrict the groups claim to *groups assigned to the
  application*, or use app roles and set `MCP_OIDC_GROUPS_CLAIM=roles`.
  A user in no groups is not an overage and is accepted with none.
- Group values are object ids (GUIDs) unless the claim is configured to
  emit names (cloud-only groups can emit `sAMAccountName` or display name
  for synced groups). Policy `subjects.groups` must match what the token
  carries; `mcp-devtools policy explain --group <value>` shows the effect.

### Console registration — Entra

In the resource API registration, expose a delegated `mcp:admin` scope.
Create a separate console registration with a **Single-page application
(SPA)** redirect URI equal to the callback. Grant its delegated API
permission and the required consent. Set `MCP_CONSOLE_CLIENT_ID` to the
console application's id. Request the resource's fully qualified scope:

```text
MCP_CONSOLE_SCOPES=openid api://<resource-app-id>/mcp:admin
```

Use the resource's actual Application ID URI if it differs from
`api://<resource-app-id>`. The prefix selects the API; the access token's
`scp` must include the unprefixed `mcp:admin`. Configure audience for the
resource API and issuer for the tenant/token version, not the console app
or Graph. The console sends neither `resource` nor `audience` for Entra.

**Known compatibility gap, not a proven recipe:** Microsoft requires an
Origin header when redeeming a code for a SPA redirect URI. D.1 redeems it
server-side without that header, so this registration is expected to fail
at token exchange. The prefixed scope form is also unproven against a real
tenant. Resolve and test the registration/exchange design before deploying
this profile; acceptance of ADR-013 does not close this evidence gap. See
[Microsoft's authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
and CF-38. No client-secret workaround is implemented.

## Keycloak

| Setting | Value |
|---|---|
| `MCP_OIDC_PROFILE` | `keycloak` |
| `MCP_OIDC_ISSUER` | `https://<host>/realms/<realm>` |
| `MCP_OIDC_AUDIENCE` | the value the client's audience mapper adds |
| Keys | `{issuer}/protocol/openid-connect/certs` |
| Scopes | `scope`, a space-separated string |
| Subject | `sub` (the user id) |
| Groups | `groups` from a *Group Membership* mapper; or `realm_access.roles` |

On the Keycloak side, on the client the tokens are issued to:

1. **An audience mapper is not optional.** A Keycloak access token carries
   no `aud` of yours by default (Keycloak 26 emits none at all; older
   realms add `account`), and the gateway refuses it as `missing_claim` /
   `wrong_audience` rather than accept `azp` in its place — `azp` names
   who asked for the token, not who it is for. Add a *Mappers → By
   configuration → Audience* mapper with *Included Custom Audience* =
   `MCP_OIDC_AUDIENCE`, *Add to access token* on.
2. **A Group Membership mapper** (*By configuration → Group Membership*)
   with *Token Claim Name* `groups`, *Add to access token* on. With *Full
   group path* on, values are `/engineering/platform`; the profile removes
   the leading slash, so policy matches `engineering/platform`. With it
   off, values are the leaf names.
3. Realm or client roles instead of groups: set
   `MCP_OIDC_GROUPS_CLAIM=realm_access.roles` (or
   `resource_access.<client>.roles`); the setting is a path into the
   nested claim.

The realm used by CI is `tests/fixtures/keycloak/mcp-realm.json` — two
clients, one with the audience mapper and one without, which is what the
live test uses to prove the refusal. To run it locally:

```bash
docker run -d --name keycloak -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/tests/fixtures/keycloak:/opt/keycloak/data/import:ro" \
  quay.io/keycloak/keycloak:26.5.7 start-dev --import-realm
MCP_KEYCLOAK_URL=http://127.0.0.1:8080 cargo test --test keycloak_live_tests -- --nocapture
```

The test rotates the realm's signing key through the admin API and
withdraws the old one, so it is also the worked example of what rotation
looks like from the gateway's side.

### Console registration — Keycloak

Create an OpenID Connect **public client** (Client authentication off),
Standard flow on, with PKCE method S256 and the exact HTTPS callback as a
Valid Redirect URI. Assign `mcp:admin` as a client scope included in the
access token's `scope`, and configure the audience/group mappers described
above. Set `MCP_CONSOLE_CLIENT_ID` to that client and leave
`MCP_CONSOLE_SCOPES="openid mcp:admin"` unless additional client scopes are
needed. See [Keycloak's client configuration guide](https://www.keycloak.org/docs/latest/server_admin/).

D.1 sends `resource=<configured audience>` in both authorization and token
requests, using [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html).
That is a description of the console's request, not proof that the target
Keycloak version honors resource indicators. Keep the audience mapper:
`resource` does not itself establish that the resulting JWT has the right
`aud`. Prove the complete browser flow against the target realm (CF-38).

## Auth0

| Setting | Value |
|---|---|
| `MCP_OIDC_PROFILE` | `auth0` |
| `MCP_OIDC_ISSUER` | `https://<tenant>.<region>.auth0.com` (or a custom domain); the token's `iss` ends in `/`, and either spelling is accepted |
| `MCP_OIDC_AUDIENCE` | the API's *Identifier* |
| Keys | `{issuer}/.well-known/jwks.json` |
| Scopes | `scope`, a space-separated string |
| Subject | `sub` (`auth0\|…`, `google-oauth2\|…` — the connection is part of it) |
| Groups | none by default; set `MCP_OIDC_GROUPS_CLAIM` to the custom claim |

On the Auth0 side: register an **API** with the identifier above and
require clients to request it as `audience` — without an API audience
Auth0 issues an *opaque* access token, which is refused as `malformed`.
Auth0 puts nothing group-like in an access token by itself; add a
post-login Action that sets a namespaced claim, for example
`api.accessToken.setCustomClaim('https://acme.example/groups', event.user.app_metadata.groups)`,
and set `MCP_OIDC_GROUPS_CLAIM=https://acme.example/groups` (the name is
looked up literally, dots and slashes included). `aud` is an array — the
API identifier plus the `userinfo` URL — which is fine.

### Console registration — Auth0

Create a **Single Page Application** with the exact callback in Allowed
Callback URLs, Authorization Code enabled, and no token endpoint client
secret. Register the API and `mcp:admin` permission and grant access/consent
to the administrators. Set `MCP_CONSOLE_CLIENT_ID` to the SPA client id and
`MCP_CONSOLE_SCOPES="openid mcp:admin"`. D.1 adds `audience` equal to
`MCP_OIDC_AUDIENCE` to the authorization URL; this must be the API Identifier.
The token exchange uses the code and verifier. See [Auth0 authorization
parameters](https://auth0.com/docs/api/authentication/authorization-code-flow/authorize-application).
Confirm the server-side public-client redemption against the tenant;
this console flow has only wiremock evidence (CF-38).

## Any other OpenID Connect provider

| Setting | Value |
|---|---|
| `MCP_OIDC_PROFILE` | `generic` |
| `MCP_OIDC_ISSUER` | the `issuer` of the provider's discovery document |
| Keys | discovery: `{issuer}/.well-known/openid-configuration` → `jwks_uri` |
| Scopes | `scp` or `scope`, string or array |
| Subject | `sub` |
| Groups | `groups`, values as they come |

This is the spec shape with no corrections. If the provider's tokens need
one that a setting cannot express, that is a new profile: a row in
`Profile` in `src/auth/oidc.rs`, a fixture-locked test in
`tests/token_validator_tests.rs`, and a section here.

### Console registration — generic

Register a public authorization-code client with S256 PKCE, no secret, the
exact HTTPS callback, and permission for `openid mcp:admin`. Configure
`MCP_CONSOLE_CLIENT_ID` and any additional scopes in `MCP_CONSOLE_SCOPES`.
Discovery must advertise authorization and token endpoints for the same
issuer. D.1 sends the configured audience as RFC 8707 `resource` at both
endpoints. Check the provider supports that parameter and server-side
public-client code redemption, then verify that its RS256 access token
passes the configured issuer, audience, subject and scope checks through
`GET /admin/policy`. A provider requiring a secret or a different audience
parameter needs an explicit adapter change; generic is not automatic
interoperability. Real-provider proof remains CF-38.

## Troubleshooting by rejection category

The `WWW-Authenticate` challenge and the operator log name a category,
never a claim value.

| Category | Usual cause |
|---|---|
| `keys_unavailable` (503) | The JWKS or discovery URL is unreachable, answers non-2xx, is too large, or the discovery document names a different issuer than configured. |
| `unknown_key` | The token's `kid` is not in the provider's key set: a rotation the gateway has not fetched yet (it fetches on the miss, once per 30 s), or a token from a different issuer / realm / authorization server. |
| `wrong_issuer` | `iss` differs beyond a trailing slash: wrong tenant, realm, or authorization server; Entra v1 token against a v2 issuer. |
| `wrong_audience`, `missing_claim` (`aud`) | No audience mapper (Keycloak), no API audience requested (Auth0), Graph's audience instead of yours (Entra). |
| `missing_claim` (`oid`, `sub`, …) | The subject claim the profile names is absent — usually a client-credentials token with no user, or an ID token sent as an access token. |
| `groups_overage` | Entra left the groups out; see the Entra section. |
| `unsupported_algorithm`, `malformed` | Not an RS256 JWT: an opaque token, an HMAC token, `alg: none`. |
| `not_yet_valid`, `expired` | Clock skew beyond `MCP_OIDC_CLOCK_SKEW_SECONDS`; fix the clock, do not widen the skew. |
