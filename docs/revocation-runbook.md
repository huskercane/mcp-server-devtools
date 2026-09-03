# Revocation and key-rotation runbook

Written 2026-09-03 for Phase B (WP B.4) of `docs/enterprise-product-plan.md`.
Plan §3.6 states the revocation semantics; this is how an operator acts on
them, what takes effect when, and what the journal shows afterwards.

## The controls, and their windows

| Event | What to do | Takes effect | Journal evidence |
|---|---|---|---|
| A user leaves, or must lose access now | `mcp-devtools revoke subject <sub>` | ≤ 500 ms after the signed file lands on every gateway (one poll), on the **next request**, whether or not the token is cached | `revocation_changed` (with `revoked_subjects`), then a `revoked_token_rejected` per refused request with the principal and `reason: subject` |
| One token leaked (pasted, logged) but its owner keeps working | `mcp-devtools revoke token <jti>` | same | `revoked_token_rejected` with `reason: token_id` |
| Identity-provider signing key compromised; gateway breach suspected; "everyone re-authenticates now" | rotate the key at the identity provider first, then `mcp-devtools revoke all` | same; every token issued before the cut-off is refused, every principal session is closed, the validated-token cache is cleared | `revocation_changed` with `not_before`; refusals carry `reason: not_before` |
| Group removed at the identity provider (planned offboarding, role change) | nothing — the next token the client obtains lacks the group and policy denies it | when the client mints a new token: **≤ token TTL** (set 5–15 min at the identity provider), plus up to 5 min of validated-token cache for the *old* token's group claims. A token minted before the change keeps its groups until then. If that is too slow, revoke the subject | the first `tool_call_intent` with `decision.effect: deny` after the last `allow` for that subject |
| Token expiry | nothing | on the next request after `exp` (plus configured skew) | none; the challenge says `expired` |

Measured in `tests/revocation_tests.rs` (the printed windows are under 2 s
on a loopback gateway with the default 500 ms poll):

- `a_revoked_subject_is_refused_within_a_poll_and_the_refusal_is_journaled`
- `revoke_all_refuses_tokens_issued_before_the_cutoff_and_closes_their_sessions`
- `group_removal_waits_for_the_token_but_revocation_does_not` — the token
  minted with the group stays allowed after the group is removed at the
  identity provider until it expires; revoking the subject cuts it off within
  one poll.

The bound is the watcher's poll interval on each gateway plus however long
the signed file takes to reach them (a `ConfigMap` update propagates in tens
of seconds on Kubernetes; a shared volume is immediate). Nothing waits for a
cache entry to age out.

## Prerequisites

- `MCP_POLICY_PUBLIC_KEY` on every gateway, `MCP_REVOCATION_FILE` pointing at
  the list, and the list signed (the gateway refuses to start otherwise).
- The policy signing key (`policy-signing.key` from `mcp-devtools policy keygen`)
  with whoever is allowed to revoke. It is the same key that signs the policy:
  revocation is an authorization change, and it should need the same authority.
- `mcp-devtools` on an operator machine (any platform; the CLI reads and
  writes files, and never needs the gateway's configuration).

## Procedures

### Revoke a subject

```bash
mcp-devtools revoke subject alice@acme.example --reason "offboarded 2026-09-03" \
    --file revocations.yaml --key policy-signing.key
mcp-devtools revoke show --file revocations.yaml --public-key "$MCP_POLICY_PUBLIC_KEY"
```

Publish `revocations.yaml` **and** `revocations.yaml.sig` to wherever the
gateways read `MCP_REVOCATION_FILE` from (the `mcp-devtools-policy` ConfigMap in
`deploy/k8s/config.yaml`). The subject's sessions are closed and their next
request is refused with `WWW-Authenticate: … error="invalid_token",
error_description="revoked"`.

Confirm in the journal: a `revocation_changed` record, then
`revoked_token_rejected` records for that subject.

### Revoke a token

Find the `jti`: it is in the identity provider's token logs, or — if the
token was pasted somewhere — decode its payload. Then:

```bash
mcp-devtools revoke token "$JTI" --reason "pasted into JIRA-123" \
    --file revocations.yaml --key policy-signing.key
```

A token with no `jti` cannot be named; revoke its subject instead.

### Revoke everything (`revoke all`)

1. If the identity provider's signing key is the problem, **rotate it there
   first** — otherwise the attacker keeps minting tokens the gateway accepts.
   Gateways refetch the JWKS on an unknown `kid` (rate-limited to one fetch
   per 30 s) and evict cached tokens whose key disappeared.
2. `mcp-devtools revoke all --reason "IdP key rotated after incident INC-42" \
       --file revocations.yaml --key policy-signing.key`
3. Publish the pair. Every gateway clears its validated-token cache and
   closes every principal session; every token with `iat` before the
   cut-off — or with no `iat` — is refused. Clients re-authenticate and
   re-initialise.
4. Once the incident is closed and every legitimate token has aged past the
   cut-off, the cut-off can stay (it costs nothing) or be dropped with
   `mcp-devtools revoke clear-all`.

### Undo

```bash
mcp-devtools revoke remove subject alice@acme.example --file revocations.yaml --key policy-signing.key
mcp-devtools revoke remove token "$JTI" --file revocations.yaml --key policy-signing.key
mcp-devtools revoke clear-all --file revocations.yaml --key policy-signing.key
```

The journal keeps the change history; the file only holds the current list.

## Key rotation

### Identity-provider signing key

Rotate at the identity provider. Gateways pick the new key up on the next
token that names its `kid`, or at the next background refresh (every 10 min).
A key that disappears from the JWKS, or is republished under the same `kid`
with different material, evicts the tokens it validated. If the rotation was
forced by a compromise, follow it with `revoke all` (above).

### Policy signing key (`MCP_POLICY_PUBLIC_KEY`)

The gateway accepts exactly one policy signing key, so rotation is a
re-sign-and-redeploy:

1. `mcp-devtools policy keygen --out policy-signing-new.key` — note the printed
   public key.
2. Sign the current policy and revocation list with the new key:
   `mcp-devtools policy sign policy.yaml --key policy-signing-new.key` and
   `mcp-devtools policy sign revocations.yaml --revocation-list --key policy-signing-new.key`.
3. Deploy the new `MCP_POLICY_PUBLIC_KEY` **and** the new `.sig` files in the
   same rollout. A gateway that restarts with the new key and the old
   signatures refuses to start (fail closed); one that has the new
   signatures and the old key ignores the reload and reports `degraded`
   until the key follows — neither fails open.
4. Destroy the old private key.

If the old key is suspected compromised, treat any policy or revocation
change since the suspected date as untrusted: the journal's `policy_changed`
and `revocation_changed` records carry each document's bundle hash and the
`key_id` that signed it.

### Audit checkpoint signing key (`MCP_AUDIT_SIGNING_KEY`, WP B.6)

Generate a new key with `mcp-devtools audit keygen`, deploy it to the
gateways, and keep the old **public** key: checkpoints already written were
signed with it, and `mcp-devtools audit verify` accepts more than one
`--public-key` so a journal spanning the rotation still verifies end to end.

## What the journal shows

Every revocation-list event is a control record (`kind` starting with
`revocation_`) with the list's version label (`v<n>+sha256:<16 hex>` of the
exact file bytes), the signing `key_id`, and the counts; every refused
request is a `revoked_token_rejected` record with the refused principal and
the reason (`subject`, `token_id`, `not_before`). `mcp-devtools audit export
activity` (WP B.5) and `mcp-devtools audit metrics` (WP B.7) read these to
report the revocation window per subject.
