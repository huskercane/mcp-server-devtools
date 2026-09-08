# Gate A runbook — closing the Phase A stage in a live environment

Written 2026-09-02, after the Phase A review closed (PR #14). The plan's
Gate A (`docs/enterprise-product-plan.md` §4) is the only part of Phase A
that cannot be proved in process: it needs a partner, their identity
provider, a real TLS ingress, and their non-production upstream. This is
the checklist for running it and what "closed" means.

## What is under test, and why it is the community image

Everything Gate A exercises lives in the community crate today: Okta token
validation, the file policy engine, the durable journal, the gateway role,
and the container image. The private `mcp-devtools-enterprise` crate is a
surface-check shell over the community library — no binary, no runtime
code, five smoke tests that pin the public API. Handing the partner an
"enterprise build" would hand them nothing to test.

That is the CF-18 question (where the Okta validator and file policy live
under ADR-001), and it cuts both ways here:

- **Decide CF-18 before the partner starts**, or
- **accept up front that Gate A validates the community image** and that a
  later "move" changes the artifact but not the behaviour it proved.

Either is fine. Not deciding, and then moving the code mid-trial, is not.

Phase B did **not** move anything: revocation (B.4) and the rest of Phase B
live in the community crate like Phase A, and CF-18's move list grew
accordingly. The enterprise crate becomes the test artifact only once CF-18
is decided and executed; until then the community image is the artifact.

## Steps

1. **Release.** Merge PR #14. Bump `version` in `Cargo.toml`, build so
   `Cargo.lock` follows, commit to `main`, tag `v<version>` (the hook in
   `scripts/check-release-tag.sh` refuses a mismatch), push the tag.
   `release.yml` publishes the image to GHCR and prints its **digest**.
   Deploy by digest (`image@sha256:…`), never by tag.
2. **Hand over the manifests.** `deploy/k8s/` with the partner's values
   filled in: `MCP_OIDC_PROFILE`, `MCP_OIDC_ISSUER`, `MCP_OIDC_AUDIENCE`
   (per [`identity-provider-runbook.md`](identity-provider-runbook.md);
   `MCP_AUTH_MODE=okta` with `MCP_OKTA_*` still works), `MCP_PUBLIC_URL`,
   `MCP_POLICY_FILE` (start from `deploy/policies/grafana-read-only.yaml`
   with their group names), `MCP_AUDIT_JOURNAL_DIR` on a persistent volume.
   **Phase B added three requirements** the image refuses to start without:
   - `MCP_POLICY_PUBLIC_KEY` — run `mcp-devtools policy keygen --out policy-signing.key`
     on an operator machine, keep the private key there, put the printed
     public key in the ConfigMap, and sign the policy with
     `mcp-devtools policy sign policy.yaml --key policy-signing.key`
     (ship `policy.yaml.sig` next to it; every edit needs a re-sign);
   - `MCP_REVOCATION_FILE` — `mcp-devtools revoke init --file revocations.yaml --key policy-signing.key`
     produces the empty, signed list; ship both files;
   - `MCP_AUDIT_SIGNING_KEY` — `mcp-devtools audit keygen --out audit-signing.key`,
     mounted from a Secret (Kubernetes projects it as `root:<fsGroup>`
     `0440`, which the gateway accepts; world-readable or group-writable is
     refused); keep the printed public key for `mcp-devtools audit verify`.
   `deploy/k8s/config.yaml` shows all three. If the partner's workflow is
   the incident one, start from `deploy/policies/incident-investigation.yaml`
   (Grafana + Slack) instead.
   One gateway replica (the example's default; see CF-16 before scaling).
   Vendor credentials per `docs/configuration.md`.
3. **Smoke.** The two `curl` calls in `deploy/k8s/README.md`: the RFC 9728
   metadata document without a token, then `tools/list` with an
   Okta-issued token. Health (`GET /`) answers 200 and the plain banner.
4. **The "done when", against their IdP.** Mirror
   `tests/phase_a_vertical_slice_tests.rs` by hand:
   - a member of group A calls `grafana_query_logs` on the QA datasource
     and gets data;
   - a member of group B calls the same and gets `Policy denied … (policy
     v…)` with the rule and version in the reason, and Grafana's own logs
     show no request;
   - the journal holds, in sequence: the allow intent, the allow outcome
     (with its `egress` list showing one `attempted` request at 200), the
     deny intent — each with `principal.subject`, `decision.policy_version`,
     and `upstream_identity.label`;
   - the intent line exists on disk before Grafana logs the request
     (compare timestamps, or watch the journal while the call runs).
5. **Rotation and outage, against their IdP.** Rotate the signing key at
   the provider and confirm the next token validates after the refetch and a token
   under the withdrawn key is refused. Block the JWKS URL and confirm cached
   keys keep serving while the log warns.
6. **Measure what the in-process test could not.**
   - Journal append p50/p99 on their storage class
     (`cargo bench --bench response_pipeline`, stage −1c, run on the node,
     or time a burst of calls and read the journal timestamps). The §8
     budget is p99 < 200 µs; the register's 11 µs is a local SSD number.
   - Real ingress and TLS: the `WWW-Authenticate` challenge's
     `resource_metadata` URL resolves through the ingress; SSE responses
     stay open past the proxy's read timeout setting; the 1 MB body cap
     matches.
7. **Two weeks of use.** Their incident workflow, their tokens, their
   policy edits (`policy check` → `policy sign` → apply; the reload is
   journaled). Exercise the Phase B controls once each, against their IdP:
   revoke a test user (`mcp-devtools revoke subject …`) and confirm the
   next request is refused with `error_description="revoked"` and a
   `revoked_token_rejected` record; `revoke all` after a rehearsed key
   rotation; `mcp-devtools audit verify` on a copy of the journal and
   `/journal/checkpoints`; `mcp-devtools audit export access-review` with
   their group export. `mcp-devtools audit metrics` produces the §7
   figures the journal can supply (`docs/audit-reports.md`).

## Exit

Gate A is closed when the partner confirms in writing:

- the problem is material to them;
- they **explicitly accept the shared-identity model** (ADR-006: read-only
  shared accounts, per-vendor-per-environment credentials, no silent
  fallback, `authority=shared` labelling, upstream-vs-gateway attribution
  documented) — or reject it, in which case one delegated integration moves
  into Phase B;
- the second vendor is chosen from their workflow (ADR-005).

Record the outcome in the plan's §0 decision log and the Phase A status,
and move CF-18 to decided.

## Owner-led items this does not cover

`SECURITY.md` and the disclosure process (before Gate A), WP 0.2 (threat
model), WP 0.3 (partner commitment in writing), ADR-002 (licence text,
with counsel; CF-10). See `docs/enterprise-carry-forward.md`.
