# Audit journal: verifying it and reporting from it

Written 2026-09-03 for Phase B (WPs B.5, B.6, B.7) of
`docs/enterprise-product-plan.md`. Everything here runs on a **copy** of the
journal on an operator's machine; nothing needs the gateway or the network.

## What is in the journal

`MCP_AUDIT_JOURNAL_DIR/audit-journal.jsonl`: one JSON object per line, with a
contiguous `seq` from 1 and a `kind`:

| `kind` | Written when | Carries |
|---|---|---|
| `tool_call_intent` | before a tool dispatches | principal, canonical action, decision (effect, rule, policy version), upstream identity |
| `tool_call_outcome` | after it completes | outcome, duration, every egress decision and what the transport did with it |
| `egress_decision` | the egress chokepoint denies an upstream request | the denied action |
| `policy_loaded` / `policy_changed` / `policy_rejected` | the policy document is loaded, changed, or refused | version labels (bundle hashes), signature status, reason |
| `revocation_loaded` / `revocation_changed` / `revocation_rejected` | the revocation list is loaded, changed, or refused | counts, `not_before`, signature status |
| `revoked_token_rejected` | a validated token is refused by the revocation list | the principal, the reason (`subject`, `token_id`, `not_before`) |
| `checkpoint` | every N records, T seconds, and at clean close | the chain value over everything before it, signed |

Never a token, never tool arguments, never response content (plan §3.3).
Search expressions and caller-supplied values appear as digests.

## Verifying a copy

```bash
mcp-devtools audit verify /path/to/journal-dir \
    --public-key "$AUDIT_PUBLIC_KEY" \
    --checkpoints /path/to/exported-checkpoints
```

`--public-key` is the public half printed by `mcp-devtools audit keygen`
(repeat it for every key a journal spans). `--checkpoints` is a copy of
`MCP_AUDIT_CHECKPOINT_EXPORT_DIR`. The verifier:

1. reads every line and requires `seq` to be the previous one plus one;
2. recomputes the SHA-256 chain (`chain = H(chain ‖ line)`, seeded) and
   compares it to each checkpoint's `chain`;
3. checks each checkpoint covers exactly the range since the previous one
   and that its signature verifies with the key it names;
4. compares every exported checkpoint to the journal's, byte for byte, and
   flags any export that lies beyond the journal's last record — a
   truncated tail, which the chain alone cannot see.

Exit code 0 means no problem was found; 1 means at least one was, and the
report names each (`--json` for machines). What is **not** covered: records
after the last checkpoint, until the next one is written (bounded by
`MCP_AUDIT_CHECKPOINT_RECORDS` / `MCP_AUDIT_CHECKPOINT_SECONDS`, and sealed at
every clean shutdown). A gateway that died mid-run leaves an unsealed tail;
the report says how many records.

## Activity export

```bash
mcp-devtools audit export activity /path/to/journal-dir \
    --since 2026-09-01T00:00:00Z --until 2026-10-01T00:00:00Z \
    --subject alice@acme.example --vendor grafana \
    --kind tool_call_intent --kind tool_call_outcome \
    --format csv --out activity.csv
```

One row per record (checkpoints excluded), flattened to fixed columns:
sequence, timestamp, kind, request id, subject, tenant, groups, tool, vendor,
environment, normalized action, resource type, resource scope, request risk,
effect, rule id, policy version, reason, upstream identity label and
authority, outcome, duration, and egress counts (allowed / denied / sent).
Intent and outcome rows share a `request_id`; they are not merged, because
the journal's own granularity is the evidence. `--format jsonl` gives the
same rows as JSON Lines. Every filter is optional; time bounds are
RFC 3339 at any precision.

A journal that cannot be read to the end exports what it could and exits
non-zero with the reason.

## Access review

```bash
mcp-devtools audit export access-review \
    --policy policy.yaml --public-key "$MCP_POLICY_PUBLIC_KEY" \
    --groups groups.yaml --tenant acme --format csv --out access-review.csv
```

`groups.yaml` is group → members, exported from the identity provider:

```yaml
SRE: [alice@acme.example, bob@acme.example]
Contractors: [carl@contractor.example]
```

The review lists, for every member, every rule whose `subjects` clause
matches a principal with that subject and those groups (holding the default
required scope), with the rule's match keys as columns — "who can do what"
as the policy would decide it, without a single call. Subjects a rule names
directly are included even when no group lists them. A rule that names a
scope other than the default required one is not reflected; the review is
of people, not tokens.

## Trial metrics (plan §7)

```bash
mcp-devtools audit metrics /path/to/journal-dir [--since …] [--json]
```

| §7 metric | Field |
|---|---|
| Time to provision (group add → first successful call) | per subject, `time_to_first_allow_ms` (first attempt → first success; the identity-provider half of the interval is not in the journal) |
| Time for revocation to take effect | per subject, `revocation_window_ms` (`revocation_changed` → first `revoked_token_rejected`) and `deny_after_allow_ms` (last allowed call → first policy denial, the group-removal proxy) |
| Share of requests covered by an explicit allow rule | `explicit_allow_share` (`allowed_by_rule / calls`) |
| Cross-environment access attempts blocked | `cross_environment_attempts` (denied calls by a subject allowed for the same vendor in another environment) |
| Time to produce a report | `elapsed_ms` on stderr of every export and metrics run |

Counts are over `tool_call_intent` records; outcomes, egress denials,
policy and revocation changes, and checkpoints are counted separately.
