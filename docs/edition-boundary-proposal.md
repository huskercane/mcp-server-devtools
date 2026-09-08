# Community and Enterprise boundary proposal

Date: September 8, 2026. Status: accepted by owner; implemented and validated locally. Publication remains
separate from implementation; no release or history rewrite is performed.

## Accepted direction

Maintain two repositories and two products built on one shared core:

- **Community:** a complete, secure, self-managed gateway under Apache-2.0.
- **Enterprise:** proprietary extensions for managed administration, approvals,
  fleet operations, delegated credentials, and organization-wide reporting,
  plus commercially supported releases and deployment services.

Keep security enforcement in the shared core. Charge for operating and governing
deployments across an organization. Avoid duplicating the gateway or selling
individual connectors as separate entitlements.

## Decision history and licensing constraints

Before the September 8 revision, [licensing policy](licensing.md), ADR-001/002,
and the September 5 amendment at
the start of [CF-18](enterprise-carry-forward.md#cf-18--where-the-oidc-validator-and-the-file-policy-engine-live-adr-001)
kept all existing code in this crate Apache-2.0. Conversely, ADR-012 and the
later Phase D entry in CF-18 contemplated extracting approvals and the console
before publication. These were conflicting instructions; the September 8 owner decision resolves
placement in favor of this matrix. The earlier product brief also assigns features to Enterprise
that the later licensing policy explicitly keeps in Community.

The user reports both repositories are private. Local inspection finds a
community library and binary, and a sibling Enterprise library scaffold. Private
repository visibility alone does not establish whether source, binaries, images,
or archives have already been supplied to others under ISC or Apache terms.
Apache's copyright grant is irrevocable; previously granted permissions must be
preserved ([Apache-2.0, section 2](https://www.apache.org/licenses/LICENSE-2.0)).

The owner has explicitly revised the product/licensing decision. Extracting
existing implementations also requires checking ownership and prior distribution
before exclusive commercial distribution. A file move does not itself make code
exclusive. If existing implementations must remain Apache, retain them there and
commercialize new extensions and supported distribution instead.

## Proposed feature allocation

| Capability | Recommended edition | Scope |
|---|---|---|
| Connectors, purpose-built reads, CLI, stdio and HTTP, bounded output, caches and artifacts | Community | Keep the existing functional gateway and fixes available. |
| OIDC validation, existing provider profiles and EMA exchange | Community | Keep implemented authentication and protocol interoperability; paid compatibility support is a service. |
| Egress policy, signed file policies, revocation, identity isolation and shared credential attribution | Community | Preserve a safe, independently usable remote deployment. |
| Local audit journal, checkpoints, verification/export, existing reports and metrics | Community | Preserve trustworthy evidence and diagnosis. |
| Existing secret sources, SIEM forwarding and SQLite rollups | Community | Already covered by the policy; do not create a broad extraction project. |
| Existing admin API/CLI, signed install and emergency revoke/purge | Community | Operators can administer one deployment without purchasing a console. |
| Existing containers, Helm/Compose/systemd packages, offline builds and backup/restore | Community | Keep reproducible deployment and recovery; sell supported releases and assistance. |
| Two-person approvals and proposal lifecycle | Enterprise extraction candidate | Existing D.2 implementation; subject to the licensing decision above. |
| Browser administration console, policy authoring and proposal review | Enterprise extraction candidate | Existing D.1/D.3 implementation; subject to the same decision. |
| Fleet policy rollout, aggregated inventory, shared control state and distributed limits | Enterprise, new work | Multi-deployment management and scaling adapters; shared contracts remain Community. |
| Delegated upstream credentials and consent/token lifecycle | Enterprise, new work | D.5 remains demand-gated; authority enforcement and audit contracts remain in the core. |
| Cross-deployment reports, evidence collection and retention automation | Enterprise, new work | Extend existing local reporting and export rather than removing them. |
| Offline commercial entitlements, supported release lifecycle and contractual support | Enterprise | Entitlements govern Enterprise extensions only; agreement work remains CF-10. |

Native AWS/Azure secret adapters (C.2c/d, CF-30) remain deferred. Decide their
commercial priority from partner demand; they are not needed to establish this
boundary. CF-36 credential-rotation approval remains a separate design question:
the current approval gate cannot approve a secret mutation it does not perform.

## Extraction inventory

The owner accepted this extraction inventory. Prior grants remain intact and
exclusive commercial distribution remains subject to the distribution review:

1. Move `src/approvals`, `src/bootstrap/approvals.rs`,
   `src/server/admin/proposals.rs`, and the proposal-specific admin CLI commands
   into Enterprise, with their recovery and API tests.
2. Move `src/console`, `console/`, console-specific templates/build configuration
   and dependencies, browser helpers and console tests into Enterprise.
3. Keep `MutationGate`, `ProposalRegistry`, `AdminClient`, policy and audit
   contracts in Community. Keep shared signed-install and fail-closed tests.
4. Refactor router/bootstrap composition so Enterprise injects its adapters and
   routes into the Community library. Community must neither depend on nor
   download Enterprise code. Review mixed CLI/config/test files individually.
5. Give Enterprise its own executable, CI, image, packaging and integration
   tests, pinning a version of the Community library. Carry third-party notices
   with the assets that move. Cargo features are build controls, not a license
   boundary.

This is a bounded extraction proposal, not a claim that moving files alone
produces a working second product. Composition, public API access, mixed tests,
configuration compatibility and release artifacts all require verification.

## Backlog ownership and testing

- Community: core/CLI correctness (CF-7/28/29), shared build improvements
  (CF-40), network-posture documentation (CF-43), and the local HTTP decision
  (CF-44). Security fixes follow the affected implementation in both products.
- Enterprise: fleet/scaling extensions in CF-16/33, console lifecycle and browser
  evidence in CF-37/38/45 if extracted, and commercial entitlement work in CF-10.
  Existing single-process Community behavior and its documented limits remain.
- Shared evidence: provider/EMA interoperability (CF-31/35/42), release signing
  and packaging proof (CF-34/41). Run applicable checks against both final
  artifacts; a paid edition is not an exemption from those checks.

The recorded closeout covers D.0–D.4, with external evidence still outstanding;
Gate B is not satisfied and D.5 remains gated. Implementation completion must
not be presented as partner acceptance or production readiness. Establishing
the edition boundary can proceed while waiting for tenant and testing data.

## Implementation and publication sequence

1. Settle the existing-code/distribution boundary and record the exact baseline.
2. Reconcile licensing policy, ADR-001/002/012, CF-10/18 and the product brief
   around this matrix; finalize Enterprise agreement and contribution terms.
3. Extract approvals and console first, preserving a working Community gateway.
4. Validate both binaries, dependency direction, failure behavior, test ownership,
   packaging, notices and feature/configuration documentation.
5. Audit Community Git history and all publication artifacts before opening it:
   deleting files from the current tree does not remove them from history.
6. Finish external evidence gates against the resulting trial artifact. Prioritize
   the next paid extension using the design partners' actual requirements.


[Completed implementation, evidence and publication limits](edition-extraction-validation.md).
