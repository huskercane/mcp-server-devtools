# Release operations

## Backup and restore

`scripts/operations/state-backup.py` runs on a Unix operations host with
Python 3 and the `mcp-devtools` binary. Stop all writers and allow graceful
shutdown to drain before taking a coordinated snapshot. The tool also takes
an exclusive journal lock and refuses an active writer. Back up each journal
stream separately; never merge journals from different roles or replicas.

```sh
python3 scripts/operations/state-backup.py backup --quiesced \
  --journal /state/journal --checkpoints /state/checkpoints \
  --rollups /state/usage.sqlite --destination /backups/pre-upgrade
python3 scripts/operations/state-backup.py restore --quiesced \
  --source /backups/pre-upgrade --destination /state/restored \
  --binary /usr/local/bin/mcp-devtools --public-key "$AUDIT_PUBLIC_KEY"
```

A backup includes the journal, exported checkpoints, a consistent SQLite
backup, and a SHA-256 file manifest. It excludes private signing keys and
provider secrets; retain those through their existing secret-management
process. C.4's activity projection is rebuildable and is excluded. Retain
external checkpoint anchors independently of the backup.

Restore validates the file set, checksums, SQLite integrity, and runs
`mcp-devtools audit verify` with the supplied public keys and checkpoints
before installing a new destination directory. Repeat `--public-key` for key
rotations. Failure leaves the destination absent. Existing destinations are
refused. The restore integration test verifies real signed evidence and real
SQLite rows, and rejects tampered evidence even after its manifest checksum
has been changed to match. This is not a point-in-time recovery service:
writers must be quiesced, and usage remains C.6's lossy telemetry.

The restored layout is `journal/audit-journal.jsonl`, `checkpoints/`, and
`rollups/usage.sqlite`. Point the server configuration at these paths. Ensure
the restored volume is owned/writable by UID/GID 65532 before mounting it in
the non-root pod. Preserve a copy of the original state until validation and
startup complete.

## Upgrade and rollback

1. Record the image digest, configuration, policy/revocation versions, audit
   public keys, and current Helm revision. Verify the new image signature.
2. Quiesce writers and take the backup above. Retain the prior image and
   configuration. Test restore to a separate directory with the target binary.
3. Upgrade with the pinned digest and `helm upgrade --wait`. Recreate strategy
   and one writer per journal mean a maintenance window is expected.
4. Check health, policy/signature startup evidence, a read-only MCP call, admin
   authorization and reports, and `audit verify` against external checkpoints.
5. For rollback, stop writers first and preserve all post-upgrade evidence.
   SQLite migrations are forward-only: an older binary refuses a newer schema.
   Restore the pre-upgrade rollups into a new location when necessary; do not
   overwrite or discard the post-upgrade journal to make an old binary start.
   Verify the chosen journal with the rollback binary before switching paths,
   then use the recorded Helm revision/image. Rebuild activity projections.

## SBOM and release signatures

`release.yml` validates the tag against Cargo.toml, checks out that release
source, and produces a CycloneDX JSON source-dependency SBOM with the pinned
[Anchore SBOM action](https://github.com/anchore/sbom-action). It inventories
the source dependency set, including build/test dependencies; it is not a
claim that every listed crate is linked into every platform binary.

The workflow signs the immutable container digest and verifies it immediately.
It also signs release archives, the SBOM, and digest records as Sigstore bundles.
The [Cosign installer](https://github.com/sigstore/cosign-installer) and Cosign
version are pinned. **Sigstore release signing cannot be exercised locally and
was not exercised here**: the release job needs GitHub's OIDC identity and
registry publication. No local push, tag publication, or release was performed.

For a tag-triggered release, use the expected repository/workflow identity:

```sh
cosign verify \
  --certificate-identity 'https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/vVERSION' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/OWNER/mcp-devtools@sha256:DIGEST
cosign verify-blob --bundle mcp-devtools-linux-x86_64.tar.gz.sigstore.json \
  --certificate-identity 'https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/vVERSION' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mcp-devtools-linux-x86_64.tar.gz
```

Use the exact trusted workflow ref that ran the job for a manual dispatch
(for example `refs/heads/main`); its checked-out source is still the requested
release tag. Do not use an unrestricted identity regular expression. The
verification flags follow [Sigstore's verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).

Local validation used the checksum-verified Helm CLI and real local
journal/checkpoint/SQLite backends. Docker was unavailable because its daemon
was stopped and starting it required interactive sudo. No Kubernetes cluster
rollout or external Sigstore run is claimed.
