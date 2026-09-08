# Licensing policy

Decision: September 5, 2026; edition boundary revised September 8, 2026.

## Community edition

This repository's community edition is licensed under
[Apache-2.0](../LICENSE), effective with the commit that introduces this policy.
It permits commercial and noncommercial use, including internal business use,
modification, hosting, and redistribution, subject to the license's terms.
Forks must comply with those terms; they do not owe a fee merely because they
are commercial. Apache-2.0 does not grant rights to the project's trademarks.

The license covers the Community crate, including authentication, resource-policy,
audit, administration API/CLI, and existing operations features. The September 8
owner decision extracts the approval workflow implementation and browser console
into the private Enterprise repository. Shared enforcement and extension contracts
remain Apache-2.0. See the [accepted edition boundary](edition-boundary-proposal.md).

## Enterprise edition

The separate `mcp-devtools-enterprise` repository contains proprietary commercial
extensions: approval workflows and the administration console/policy authoring.
Future extensions may include fleet management, delegated upstream credentials,
and organization-wide reporting. Supported releases and deployment/support
services may also be sold. Community commercial use does not require payment.

This policy is not an Enterprise license agreement. Commercial agreement and
contribution terms remain CF-10 legal work. Prior distribution and ownership must
be checked before claiming exclusivity over extracted implementations; this change
does not revoke permissions attached to any previously supplied copies.
Both repositories remain private pending publication review, including Git history
and release artifacts. No release or history rewrite is authorized by this policy.

## Earlier versions and attribution

Earlier copies distributed under ISC retain their applicable ISC permissions;
this change does not retrospectively restrict those copies. The original project
copyright notice and license are retained in [licenses/ISC.txt](../licenses/ISC.txt)
as a historical record, not as an alternative license for subsequent changes.

The owner confirms that the Rust implementation has no outside human
contributions and was developed with coding-agent assistance. The Node.js /
TypeScript Atlassian servers are behavioral references for a separate Rust
implementation. Their existing attribution is retained in [NOTICE](../NOTICE).
Dependencies and any third-party material retain their respective licenses.

Binary release archives and the runtime container include `LICENSE`, `NOTICE`,
and `licenses/ISC.txt`. The container stores them under
`/usr/share/licenses/mcp-devtools/`.
