# Administration console

Build with `cargo build --release --features console`. Set
`MCP_CONSOLE_CLIENT_ID` to a public PKCE client registered with the configured
OIDC provider, and serve the `all` or `control` role with OIDC authentication.
The console is mounted only with both the feature and client id; `gateway`
does not serve it. Use HTTPS at `MCP_PUBLIC_URL`, with TLS and HSTS at ingress.
Register the exact callback URI: `MCP_PUBLIC_URL` (without its trailing slash)
plus `MCP_CONSOLE_REDIRECT_PATH` (default `/console/callback`). Keep the public
URL at the origin root and route `/console` and the callback to the same
control process. See [provider registration](identity-provider-runbook.md)
and [configuration](configuration.md).

## Sign-in and cookies

1. Visit `/console` and follow Sign in. `/console/login` discovers the
   configured issuer's authorization endpoint and sends an authorization-code
   request with S256 PKCE, state, nonce, and the configured scopes (default
   `openid mcp:admin`). Audience selection follows the provider profile.
2. The provider returns a code to the registered callback. The console consumes
   the browser's pending login once, checks state, and exchanges the code with
   its PKCE verifier. There is no client secret. A nonce is sent and stored,
   but no ID token is consumed or nonce claim validated.
3. The console presents the access token to one `GET /admin/policy` through
   `LocalAdminClient`. Success or a 503 permits a session; other statuses
   refuse sign-in. A 503 permits landing during backend/auth infrastructure
   unavailability; it is not proof that the token was validated. Subsequent
   admin calls still enforce the bearer boundary.
4. The callback displays **Signed in**, with a Continue link. Follow that link
   to `/console/policy`. This landing page is intentional: a cross-site IdP
   redirect chain may omit a new Strict cookie. A same-site navigation from
   this page lets the browser send it. An automatic callback redirect would
   risk returning the user to sign-in.

| Cookie | Contents and attributes |
|---|---|
| `mcp_console_login` | Opaque 256-bit random id; `HttpOnly; Secure; SameSite=Lax`; path is the callback path; maximum age 300 seconds. Server-side state holds state, nonce and verifier. Lax allows the provider's top-level GET callback. Cleared on successful exchange. |
| `mcp_console_session` | Opaque 256-bit random id; `HttpOnly; Secure; SameSite=Strict; Path=/console`. The access token stays in process memory, never in HTML, browser storage, or the cookie. |

Pending logins and live sessions are each capped at 256 per process. At the
cap, expired entries are swept, then the nearest-expiry entry is evicted.
Session lifetime uses token-response `expires_in`, clamped to one minute
through twelve hours (one hour when absent), rather than decoding JWT `exp`.
The admin boundary enforces actual token expiry on each API call. There is
no refresh-token flow. Restart loses sessions and pending logins: sign in
again. `POST /console/logout` drops the local session and clears its cookie;
it does not sign out of the IdP or revoke the provider's token.

## Headers and Origin check

Every console route carries:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
```

Successfully served embedded static assets instead use
`Cache-Control: private, max-age=86400`. No CDN, inline script,
or inline style is needed. The pinned htmx 4 asset has no `allowEval` key
or code-evaluation path; its digest and these properties are tested. History
storage and injected indicator CSS are disabled; see
[vendored assets](../console/VENDORED.md).

Every method other than GET/HEAD requires `Origin` equal to the origin of
`MCP_PUBLIC_URL`. Only when Origin is absent is `Sec-Fetch-Site: same-origin`
accepted. A mismatched Origin is refused even if Sec-Fetch-Site says
same-origin; missing both is 403. Preserve these browser headers at ingress.
`HX-Request` grants no permission. Plain HTML forms work without JavaScript.

## Pages and errors

| Path under `/console` | What it shows |
|---|---|
| `/policy` | Loaded policy, version and signature; the explain form calls read-only `POST /admin/policy/explain`. Optional identity/environment overrides are simulations. |
| `/activity` | Activity filtered by time, subject and vendor; the API caps results at 10,000 rows. A `stopped` banner means incomplete results: narrow the window. |
| `/access-review` | Tenant and group-membership JSON snapshot form, rendered access review. |
| `/usage` | Totals, principal/vendor/tool groups, denials by environment, timeline. |
| `/sessions`, `/artifacts` | MCP session/artifact inventory, explicitly process-scoped. These are not browser console sessions. |
| `/proposals` | D.2 proposal states and decision details. Read-only: approve/reject remain `mcp-devtools admin proposals approve|reject`. |
| `/health` | The process's `health_banner` directly, behind a local console session; health is not an admin operation. |

Pages call the same admin API as the CLI, under its independent limiter and
task budget. A bearer **401 from an admin call** means the API no longer
accepts the token (for example expired or revoked). The console discards the
session, clears the cookie, and navigates to sign-in, including `HX-Redirect`
for an enhanced form. Local session expiry/eviction/restart also asks for
sign-in. Health and unsubmitted forms do not call the API and therefore do
not themselves discover token revocation.

A 403 at callback can mean missing/expired pending login or state mismatch,
or that the API refused the token: check issuer, audience and `mcp:admin`.
A 502 during sign-in can mean discovery or code exchange failure. A 429 is
the admin limiter/task budget: retry later. `admin_backend_unavailable`
means the requested backend is not available from this process, not an empty
inventory. A separate control process cannot list a gateway's local sessions
or artifacts. `approvals_off` means proposal approval is not enabled.

The [carry-forward register](enterprise-carry-forward.md#cf-37--console-topology-and-browser-session-lifecycle)
tracks topology/session limitations; CF-38 tracks provider proof and CF-39
tracks the read-only proposal page.
