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
   request with S256 PKCE, state, and the configured scopes (default
   `openid mcp:admin`). Audience selection follows the provider profile.
2. The provider returns a code to the registered callback. The console consumes
   the browser's pending login once, checks state, and exchanges the code with
   its PKCE verifier. There is no client secret or ID-token flow. The
   separately landed `06308e4` login fix omits the unused nonce and rejects
   an RFC 9207 `iss`, when present, that differs from the configured issuer.
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
| `mcp_console_login` | Opaque 256-bit random id; `HttpOnly; Secure; SameSite=Lax`; path is the callback path; maximum age 300 seconds. Server-side state holds state and verifier. Lax allows the provider's top-level GET callback. Cleared on successful exchange. |
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
Referrer-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
```

`same-origin` suppresses referrers to other origins while preserving the
`Origin` header on native form submissions. Using `no-referrer` causes browsers
to submit these forms with `Origin: null`, which the origin check rejects.

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
| `/policy/edit` | Textarea authoring, debounced server-side validation and rule diff, validated candidate download and signed-file upload. |
| `/activity` | Activity filtered by time, subject and vendor; the API caps results at 10,000 rows. A `stopped` banner means incomplete results: narrow the window. |
| `/access-review` | Tenant and group-membership JSON snapshot form, rendered access review. |
| `/usage` | Totals, principal/vendor/tool groups, denials by environment, timeline. |
| `/sessions`, `/artifacts` | MCP session/artifact inventory, explicitly process-scoped. These are not browser console sessions. |
| `/proposals`, `/proposals/{id}` | Tenant-scoped proposal inventory and review metadata, with authenticated approve/reject forms. |
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
tracks topology/session limitations; CF-38 tracks provider proof. CF-39 is closed
by interactive decisions; CF-45 records authoring/review boundaries.

## Author, sign and submit a policy (D.3)

1. Open **Policy → Author a policy change**. The textarea starts with the
   policy returned by `GET /admin/policy`. Editing waits 500 ms before sending
   `POST /admin/policy/validate`, then `POST /admin/policy/diff` if valid.
   A newer preview request replaces an in-flight preview; it never swaps the
   editor itself. **Validate and diff** also works without JavaScript.
2. Read the validation envelope and current/candidate rule descriptions.
   This is the existing API's structural comparison, not a line diff or a
   guarantee that the active policy will remain unchanged. Validation does
   not verify a signature. No draft is saved server-side or in browser storage.
3. Select **Download candidate for signing**. The server validates again as
   your bearer and returns `policy-candidate.yaml` as a no-store attachment.
   Browser textarea/form submission may normalize newlines: **the downloaded
   bytes are the signing input**, not an earlier copy from your editor.
4. On the offline signing workstation, using the key corresponding to
   `MCP_POLICY_PUBLIC_KEY`, run:

   ```sh
   mcp-devtools policy sign policy-candidate.yaml --key /secure/policy-key.pk8
   ```

   Keep the private key offline. Return `policy-candidate.yaml` and
   `policy-candidate.yaml.sig`; do not edit or resave either signed document.
   The signature is the existing domain-separated detached base64 signature,
   not a generic signature generated directly over the YAML.
5. Select both files under **Upload signed policy**, then **Submit signed
   policy**. The embedded file helper rejects malformed UTF-8 and reads up to
   256 KiB of policy and 1 KiB of signature. It JSON-escapes the exact text
   (including CRLF and any BOM) before native form submission, avoiding newline
   normalization of signed bytes. The policy parser may reject a BOM; the
   helper never silently removes it. The console form itself has axum's 2 MiB
   encoded-body cap, and the admin boundary retains its own limits. Very
   heavily escaped files can hit that cap below 256 KiB; use the CLI for larger
   inputs. Without JavaScript, expand **JSON upload / no-script fallback** and
   paste the ordinary admin JSON object with `document` and `signature` strings;
   newlines inside strings must be JSON escapes.
6. The console calls `PUT /admin/policy` through `AdminClient`. With
   `MCP_ADMIN_APPROVALS=required`, a valid signed candidate returns **202** and
   a pending proposal id: it has **not** changed the policy. With `off` (the
   default), the same form installs immediately through the direct gate.
   A signature/parse error or audit failure leaves the policy unchanged.
   Result pages preserve the API status and escaped response envelope.

No new configuration or dependency is required. Authoring uses the same
`mcp:admin` scope and PKCE session as reads; the API remains the authorization,
rate/task-budget, signature and durable-intent enforcement surface. A 401
ends the browser session. Candidate downloads and mutation forms require the
same Origin check as existing console POST routes.

## Review, approve or reject

Set `MCP_ADMIN_APPROVALS=required` and a durable `MCP_AUDIT_JOURNAL_DIR` before
using two-person approval. Keep the policy public key and audit signing key
configured as described in the [admin API runbook](admin-api-runbook.md).
From **Proposals**, open the proposal id and review operation, target, proposer,
expiry, state and `candidate_digest`. The existing read API exposes metadata,
not stored document/signature bytes. Obtain those files from the proposer
through your review process. The digest is SHA-256 of document bytes, one NUL
byte, then the signature string with leading/trailing whitespace trimmed,
as the approval adapter defines it. Check it against the handoff before approving. No new
candidate-read API or server-side signing operation was introduced (CF-45).

**Approve stored candidate** posts to the existing authenticated approval API.
A different subject in the same tenant must approve with a token inside
`MCP_WRITE_MAX_TOKEN_AGE_SECONDS`. `403 stale_token` requires signing out and
obtaining a newly issued IdP token; an IdP that reuses an old token may need
explicit reauthentication. The console neither refreshes tokens nor weakens
that rule. The API owns digest verification, signature verification, expiry,
durable approval → mutation intent → effect ordering, and retry behavior.
An approval is applied when `applied_seq` is present. Repeating an applied
approval is idempotent. `409 proposal_incomplete` means application is in flight
or needs reconciliation; poll the proposal before taking further action. An
approved proposal without `applied_seq` is never automatically reapplied,
including older approvals after upgrade. Follow the [interrupted-application
procedure](admin-api-runbook.md#two-person-approval); a new proposal requires a
new independent review. Completion is journaled after the effect, separately
from the durable intent.

**Reject proposal** accepts an optional reason (at most 512 UTF-8 bytes;
multibyte text can reach the API limit before the browser's character limit).
Existing API semantics permit any administrator in the tenant, including the
proposer, to reject. Repeating rejection returns `409 proposal_decided` without
another record; it does not turn a rejection into approval. Observed expiry
returns `409 approval_expired` and journals one expiry rejection. Decisions
remain available in the CLI using the identical API.

D.3 was exercised with local HTTP fixtures, a synthetic signed bearer via
wiremock JWKS, real signed policies and journal verification. The optional
`node tests/console_upload_script_test.cjs` harness checks the file helper's
byte handling with a minimal DOM; it is not part of the build chain and is
not browser proof. No real IdP tenant, headless browser, or hosted CI run is
claimed. CF-38 and CF-45 retain those evidence limits.
