# Licensing policy

Decision: September 5, 2026.

## Community edition

This repository's community edition is licensed under
[Apache-2.0](../LICENSE), effective with the commit that introduces this policy.
It permits commercial and noncommercial use, including internal business use,
modification, hosting, and redistribution, subject to the license's terms.
Forks must comply with those terms; they do not owe a fee merely because they
are commercial. Apache-2.0 does not grant rights to the project's trademarks.

The license covers the code currently in this crate, including its existing
authentication, resource-policy, audit, administration, and operations features.
This change does not remove those features or make them proprietary.

## Enterprise edition

The selected model for a separate enterprise edition is a proprietary commercial
license in the private `mcp-devtools-enterprise` repository. Future enterprise
extensions may include fleet administration, approval workflows, centralized
policy management, and advanced organizational reporting. Paid services may
include supported releases, deployment assistance, and contractual support.
Feature packaging will be driven by customer demand.

This policy is not an enterprise license agreement and adds no restrictions to
the Apache-licensed community edition. Enterprise agreement text and contribution
terms remain separate legal work; no private-repository files are changed here.

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
