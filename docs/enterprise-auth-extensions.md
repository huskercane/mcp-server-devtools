# Enterprise plan extension: optional MCP authorization extensions

Status: proposed implementation scope; documentation only  
Date: September 6, 2026  
Parent: [Enterprise technical execution plan](enterprise-product-plan.md), C.1 and C.1b  
Recorded as plan revision 2.28. No ADR is opened: AE-2 reuses the ADR-013
inbound-authentication boundary and adds no new enforcement surface. Should
AE-1 conclude that advertisement must move off `initialize`, that handshake
change is its own ADR.

Sources pinned on **September 6, 2026**. The `modelcontextprotocol.io`
extension pages describe the **draft** specification directory
(`specification/draft/`); the shipped EMA implementation is pinned to the
**stable** file at ext-auth `fb374c7db2b34f18ca9183882e0beecdf661892b`
(see the [EMA runbook](ema-runbook.md)). That difference is the subject of
AE-1, not an incidental citation detail. Re-pin these before acting on them.

## Objective

Offer OAuth Client Credentials for automation and Enterprise-Managed
Authorization (EMA) for employees through the existing HTTP/OIDC authentication
boundary. Operators can enable the capabilities their deployment supports.
The first milestone is client credentials support plus an EMA compatibility
audit; implementation and external interoperability are separate completion
criteria.

The [MCP authorization extensions overview](https://modelcontextprotocol.io/extensions/auth/overview)
describes both as opt-in extensions requiring client support. Ordinary
interactive authorization continues to use the core OAuth flow.

| Extension | Identifier | Intended caller | Token acquisition |
|---|---|---|---|
| OAuth Client Credentials | `io.modelcontextprotocol/oauth-client-credentials` | CI pipelines, background jobs, service accounts | Client obtains an access token from the external authorization server using its registered credentials (client secret, or an RFC 7523 private-key JWT assertion — the specification recommends the assertion) |
| Enterprise-Managed Authorization | `io.modelcontextprotocol/enterprise-managed-authorization` | Employees using an organization-managed MCP client | Client exchanges its enterprise identity assertion for an ID-JAG, then exchanges that grant at the resource authorization server for an access token |

The acquisition flows are described in the official
[client credentials guide](https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials)
and [EMA guide](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

## Existing foundation and gaps

| Area | Existing implementation | Proposed work |
|---|---|---|
| HTTP authentication | `src/server/auth.rs` validates bearer tokens through `TokenValidator`, publishes protected-resource metadata, and enforces scopes, revocation and rate limits | Reuse this boundary for final access tokens from both flows |
| OIDC | `src/auth/oidc.rs` provides provider profiles and signed-token claim validation | Verify service-account claim shapes and stable principal mapping for each claimed provider |
| EMA | `MCP_EMA_ENABLED`, `src/auth/ema.rs`, the `auth exchange` helper and `tests/ema_tests.rs` already exist | Audit against a pinned target specification and run external interoperability checks |
| Extension advertisement | EMA advertises through `initialize` (`src/tools/mod.rs:1139`), following the pinned stable file | Choose the target revision: the pinned `rmcp` 3.1.2 already models both `server/discover` and `_meta` client capabilities, so this is a protocol-posture decision, not an SDK gap |
| Client credentials | The two behaviours the specification requires of a resource server — signed-token validation against the AS keys, and scope checks — already exist in `src/server/auth.rs`, so a client-credentials token from the configured issuer **already authenticates today**: nothing requires a human-shaped claim and groups default to empty (`src/policy/mod.rs:81`) | Add explicit capability configuration, the optional advertisement, service-account policy examples and end-to-end evidence; no new request-path enforcement |

The [EMA runbook](ema-runbook.md) records the existing implementation's pinned
ext-auth revision and limitations. C.1 is already implemented; this extension
does not reopen it as an entirely new feature. External EMA evidence remains
tracked by CF-35 in the [carry-forward register](enterprise-carry-forward.md).

## Architecture and responsibility

Both acquisition paths converge on the same request processing:

```text
Automation client -> external AS: client credentials -> access token
Employee client -> enterprise IdP: identity assertion -> ID-JAG
Employee client -> resource AS: ID-JAG -> access token

Client -> HTTP /mcp with access token
       -> OIDC validation, scope/revocation/rate checks
       -> principal -> tool policy -> credential broker -> vendor API
       -> existing audit path
```

The external authorization server owns client registration, client
authentication and token issuance. The MCP client owns acquisition and renewal;
for client credentials it obtains another access token when needed. Client
secrets and private-key assertions belong on that client-to-AS boundary.

The resource server accepts final access tokens bound to its configured issuer
and audience. EMA grants and identity assertions must never become resource
bearer credentials. The existing EMA helper remains a client-side adapter;
it does not turn this server into an authorization server.

These extensions govern inbound MCP access. Upstream Bitbucket, Jira and other
vendor credentials remain under the existing credential broker. Delegated
vendor identity remains the separate D.5 workstream.

## Optional configuration and identity policy

Retain `MCP_AUTH_MODE=oidc`, the existing provider settings, and the `okta`
compatibility alias. Keep the existing `MCP_EMA_ENABLED` setting. Propose
`MCP_CLIENT_CREDENTIALS_ENABLED` as an independent boolean, defaulting to false;
this proposed key is not implemented and is not yet an operator instruction.
Both capabilities may be enabled together when the configured AS supports them.
Reject invalid values and extension opt-in with inbound authentication disabled.

Define the new flag as an explicit support/advertisement setting. It must not
claim to reject tokens acquired through other grants: access tokens do not
necessarily identify their acquisition flow. If an operator requires
machine-only or EMA-only access, enforce that at the AS, or through a separately
specified policy based on trusted signed claims. Capability declarations alone
are never an authorization input.

Service accounts need a stable identity and explicit least-privilege policy.
Test subject, tenant, scopes and any group mapping against provider token
fixtures; an absent human group must neither break intended machine access nor
grant broad access. Bind any client identifier used in authorization to a
validated claim. Do not infer human versus machine identity from subject naming
or unsigned client metadata. Any new principal kind or audit field requires a
separate schema decision; retain the current principal shape for the initial
milestone where it can represent the required policy correctly.

### Non-human principals on the Phase B and D surfaces

Client credentials introduce the first principal with no human behind it. Three
surfaces built after C.1 assume there is one, and AE-1 must close each before
AE-2 enables the flag anywhere an administrator can reach.

1. **Four-eyes approval is bypassable by construction.** The D.2 approval gate
   refuses self-approval on **subject equality within a tenant**
   (`src/approvals/mod.rs:291` scopes the lookup to the approver's tenant,
   `src/approvals/mod.rs:312` returns `SelfApproval`). Two service accounts in
   one tenant satisfy that check, so with `MCP_ADMIN_APPROVALS=required` a
   pipeline identity could submit a signed policy bundle and a second pipeline
   identity approve it, with a correct-looking journal and no human in the loop.
   The mitigating control today is scope, not the approval rule: `/admin/*`
   requires `mcp:admin` (`src/server/auth.rs:172`), a distinct scope with its own
   limiter, so this needs an operator to have granted `mcp:admin` to two service
   accounts. That is a plausible setup — "automate policy deployment" reaches it
   directly — and nothing in the product warns against it. Decide explicitly
   whether machine principals are admitted at `/admin/*` at all. The default should be no: a machine principal is refused at the
   administrative router, enforced on a validated claim rather than on subject
   naming. If a deployment needs machine administration, the four-eyes rule
   needs a stronger predicate than subject inequality, and that is a D.2 change
   with its own tests — not something AE-2 enables implicitly.
2. **Access review reads as a human roster.** The D.1 access review and activity
   pages enumerate principals for a human reviewer. A service account rendered
   identically to an employee makes the review misleading in exactly the
   direction that matters. Machine principals must be distinguishable in that
   view, which requires a validated claim to distinguish them by — the same
   constraint as above, and the reason this is an AE-1 decision rather than a
   rendering detail.
3. **Rate limits and revocation were sized for people.** A CI fleet's request
   profile is not an employee's, so reusing the existing limiter is a decision
   to test, not a given. Offboarding-driven revocation has no analogue for a
   service account whose credential lives at the authorization server: the
   resource server can revoke a session or a subject, but rotation and
   withdrawal of the credential itself are AS-side, and AE-4's rotation guidance
   is where that boundary gets stated.

## Protocol compatibility audit

The [overview](https://modelcontextprotocol.io/extensions/auth/overview) as read
on 2026-09-06 states that both extensions use the standard extension negotiation
mechanism: clients declare support in the `extensions` field of
`io.modelcontextprotocol/clientCapabilities` sent in **each request's `_meta`**,
and servers advertise in the capabilities returned by **`server/discover`**. It
links `specification/draft/` for both.

The shipped EMA implementation advertises through `initialize`
(`src/tools/mod.rs:1139` inserts the extension into `get_info()` capabilities;
`tests/ema_tests.rs:274` locks it), following the **stable** ext-auth file the
runbook pins. So the discrepancy is a draft-versus-stable question, not evidence
that the implementation is behind its own target. AE-1 decides whether to track
draft; it does not assume so.

Three facts the audit no longer has to discover:

- **Client credentials has no stable specification.** Only
  `specification/draft/oauth-client-credentials.mdx` exists. AE-2 therefore ships
  against a draft, while EMA is pinned to a stable file. Say this in the operator
  documentation; a draft extension is a weaker support commitment.
- **Server advertisement is optional for client credentials.** The specification
  makes including the extension in `server/discover` "optional (but recommended
  for discoverability)". The two required server behaviours — validate the token
  against the authorization server's keys, and check scopes — are already
  implemented in `src/server/auth.rs`. AE-2's substance is configuration, policy
  and evidence, not new request-path enforcement.
- **No SDK upgrade is needed for either mechanism.** The pinned `rmcp` 3.1.2
  already models `server/discover` (`DiscoverRequestMethod`, `src/model.rs:1148`)
  and `_meta` client capabilities under
  `io.modelcontextprotocol/clientCapabilities` (SEP-2575, `src/model/meta.rs:396`).
  The open question is our protocol posture, not SDK capability: `get_info()` sets
  `ProtocolVersion::LATEST`, which in 3.1.2 is `2025-11-25`, while the crate also
  parses `2026-07-28`.

Record the target core MCP version, the exact ext-auth commit for each extension,
the pinned `rmcp` version, and the supported client builds. Then implement the
advertisement and declaration handling the chosen revision requires. Do not
silently replace the current `initialize` handshake based only on the overview:
EMA clients built against the stable file read `initialize`, and moving
advertisement is a breaking change for them. Preserve ordinary authenticated
clients where the selected protocol permits them and document any compatibility
boundary.

## Work packages and acceptance criteria

| Package | Deliverable | Completion evidence |
|---|---|---|
| AE-1: compatibility baseline | Pin specifications and document SDK/client compatibility, including the draft-versus-stable advertisement question; decide the three non-human-principal questions above | Reviewed protocol matrix with required changes and unresolved client limitations; a written decision on machine principals at `/admin/*`, in access review, and under the existing limiter |
| AE-2: client credentials | Implement opt-in configuration and advertisement; reuse OIDC validation; document one service-account setup and policy | Configuration and wire tests; real AS token acquisition followed by an allowed tool call and a policy-denied call; a machine principal refused at the administrative router per the AE-1 decision. Absent a real authorization server, the acquisition evidence is CF-42, not a passing check |
| AE-3: EMA audit | Compare existing implementation with AE-1, close protocol gaps and update the runbook | Local regression checks plus the existing E01–E16 matrix for each client/tenant combination claimed; CF-35 stays open for missing evidence |
| AE-4: operations | Publish tested configurations, credential rotation/renewal guidance and support boundaries | Exact client, AS, protocol and server versions with redacted evidence and supported/unsupported/not-run outcomes |

Execute AE-1 first. The initial delivery combines AE-2 with the local EMA audit
in AE-3; external access may limit the interoperability evidence that can be
completed. Documentation of an unrun check is not a passing check. This addendum
does not change the parent plan's design-partner gates or schedule other work.

Every package that changes code exits on the ordinary landing gates — `cargo
build`, `cargo build --no-default-features`, `cargo clippy --all-targets -D
warnings`, `cargo test`, `cargo fmt --all -- --check` and `cargo deny --locked
check --deny warnings` — with zero warnings. AE-2 touches the inbound HTTP
authentication path, so it also runs the per-phase allocation probe (`cargo
bench --bench response_pipeline`) and records bytes and allocation counts per
stage against the Phase D baseline in
[`docs/benchmarks/2026-09-06-d4-packaging.txt`](benchmarks/2026-09-06-d4-packaging.txt).
A material regression (rule of thumb: > 20 % on any stage) is an exit blocker,
not a note. Fresh numbers go in the package's summary so the next one has a
baseline.

Validation should cover wrong issuer/audience, expired tokens, missing scopes,
revocation despite cached validation, and ID-JAG-as-bearer refusal. Exercise
machine policy denial, principal/session isolation, and audit identity through
the real HTTP path. Verify supported advertisement behavior with each flag
off, on, and both on, plus ordinary OIDC regression coverage. Test credential
rotation and token reacquisition at the client/AS boundary. Record actual
revocation timing rather than assuming IdP offboarding immediately invalidates
an already-issued JWT at this server.

Support claims require evidence for the exact provider and client combination.
The existing fixture tests establish local behavior; they do not establish
that an arbitrary OIDC tenant supports ID-JAG or that a particular MCP client
implements either extension.

## Picking order: the low-cost work first

None of this has been started. Recorded here so the cheap, high-value items are
not skipped in favour of the flag, which looks like the obvious first task and
is not. Items 1–3 are roughly two hours in total, are documentation only, need
no gates and no design-partner tenant, and between them turn this addendum from
proposed scope into one shippable support claim plus one stated risk.

**1. Write down that client credentials already works.** No code, no flag. A CI
pipeline can authenticate to this server today with a client-credentials token
from the configured OIDC issuer: the validator checks issuer, audience, expiry,
subject claim and the required scope, and nothing requires a human-shaped claim.
`docs/configuration.md` does not say so. State it with its boundary — we
validate the token and check scopes, which is what the specification requires of
a resource server, but we do not advertise the extension, so a client that
requires advertisement will not use it. This is the one support claim available
without an external tenant, and the highest value per hour in the addendum.

**2. Finish the AE-1 matrix.** Most of the inputs are already recorded above:
draft versus stable, `rmcp` 3.1.2 modelling both mechanisms, advertisement
optional for client credentials, no stable client-credentials file. What remains
is reading the two draft `.mdx` files, confirming the stable EMA file's
advertisement wording, and writing the table. AE-1 is the stated first package
and blocks AE-2 and AE-3; leaving it unfinished is what stalls everything else.

**3. Warn operators about `mcp:admin` and four-eyes.** One paragraph in the
approvals runbook, per the reasoning above: granting `mcp:admin` to two service
accounts satisfies the D.2 self-approval rule with no human in the loop. The
enforcement decision belongs to AE-1; the warning does not have to wait for it.

**4. The flag itself, last.** `MCP_CLIENT_CREDENTIALS_ENABLED` is genuinely
small — mirror `src/auth/ema.rs::enabled()`, mirror the startup refusal for
opt-in with inbound authentication disabled (`src/server/http.rs:159`), add a
second entry to the extensions map (`src/tools/mod.rs:1139`), and mirror
`tests/ema_tests.rs`. Low risk and easy to review, but it buys discoverability
only: advertisement is optional by specification, and what it advertises is a
draft extension. It is not the place to start.

Deliberately **not** in this list, despite appearing cheap: distinguishing
machine principals by a validated claim (claim shapes differ per provider, which
is why C.1b needed profiles — an AE-1 decision plus per-provider fixtures, not
an afternoon); the access-review rendering, which depends on that decision and
overlaps CF-22's existing scope assumption; external authorization-server
evidence (CF-42, needs a real tenant); and moving advertisement off `initialize`,
which is a breaking change for clients built against the stable file and carries
its own ADR.
