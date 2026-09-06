# Air-gap operations

The archive and file-backed JWKS remove Cargo-registry and JWKS-network
requirements. They do not make remote vendor APIs, an external identity
provider, token issuance or the console's PKCE discovery/token exchange work
without network access. Arrange internal IdP and vendor reachability, trusted
internal DNS, CA certificates and accurate clocks. Offline licensing remains
blocked on CF-10; there is no licence-file validator. OVA is on request.

## Transfer and verify

On the connected side, obtain the release archives/packages, vendor source
archive, checksums, SBOM and Sigstore bundles. Verify the signatures and
release identity using the [release runbook](release-operations-runbook.md)
before transfer. Preserve that verification evidence with the transfer record.
A checksum detects changes but does not establish who published a file.
If verifying Sigstore inside the gap, pre-provision its trusted roots and
verification material; no disconnected Sigstore ceremony is claimed here.

Use the immutable `pin:` from `mcp-devtools-container-digest.txt`:

```bash
docker pull ghcr.io/OWNER/mcp-devtools@sha256:DIGEST
docker save ghcr.io/OWNER/mcp-devtools@sha256:DIGEST -o mcp-image.tar
sha256sum mcp-image.tar > mcp-image.tar.sha256
# Transfer the tar, checksum and independently verified release evidence.
sha256sum --check mcp-image.tar.sha256
docker load -i mcp-image.tar
```

For an internal registry, tag and push the loaded image, obtain its resulting
RepoDigest, and pin that destination digest in Compose/Helm. Verify image
identity at the source and destination; do not assume a copied tag is immutable.
Mirror nginx and the optional syslog-ng image in the same way. Runtime image
release digests are supplied by the release workflow; Dockerfile base images
and older CI fixtures use tags, so rebuilding from source also requires
mirroring those build inputs. The vendor tarball covers Cargo crates, not OS
packages, the Rust toolchain, C compiler, cmake, perl, pkg-config or linker.

## Provision and rotate JWKS

On a connected trusted machine, capture the issuer's direct JWKS endpoint:

```bash
mcp-devtools auth jwks fetch --url https://issuer.example/keys --output jwks.next.json
sha256sum jwks.next.json > jwks.next.json.sha256
```

The helper uses the existing Unix-only private-output writer shared with
`auth exchange`; on other platforms it refuses with `private_output_requires_unix`.
File-backed validation itself is platform-independent. The helper requires
HTTPS except loopback, disables redirects, bounds fetch
time and size (256 KiB), parses the document, and requires at least one usable
RS256 signing key. It creates a new 0600 file and refuses overwrite; it does
not print the document. Confirm the endpoint belongs to the intended issuer
through your trusted issuer configuration. The helper does not infer issuer
ownership from a direct JWKS document. Transfer with your authenticated change
process; verify the checksum, inspect the key IDs, and arrange service-readable
permissions before an atomic rename into place.

Keep the existing signed-policy, signed-revocation-list and audit-checkpoint
key requirements; file JWKS changes only the source of issuer signing keys.
The package/Compose instructions include their provisioning.

Configure `MCP_AUTH_MODE=oidc` and `MCP_OIDC_JWKS_FILE=/path/jwks.json`, retaining
the profile, issuer, audience and claim settings. Unset `MCP_OIDC_JWKS_URL`;
setting both is a startup error. The legacy `okta` key family cannot use the
file setting; select `oidc` with profile `okta` instead. Bind-mount the parent
directory in containers, not an individual file inode.

Every authentication reads the bounded regular file asynchronously before
consulting the token cache; SHA-256 change detection avoids reparsing unchanged
keys. This deliberately replaces a timer watcher with request-time checking:
withdrawal is seen on the next authentication even with a warm token cache,
at the cost of local I/O. No file-path latency budget is claimed by the remote
JWKS cache benchmark. Missing, unreadable, oversized, malformed or non-regular
files clear keys and cached tokens and refuse authentication; no remote fallback
or stale-key grace period applies. Recovery is automatic after a valid file
is restored. An empty valid key set withdraws all keys. Tokens still undergo
identical signature, algorithm, issuer, audience, time and claim validation.

For normal rotation, publish old and new keys during the overlap, transfer
that set before issuing with the new key, then withdraw old keys after their
tokens expire. For compromise, withdraw immediately; previously cached tokens
using the withdrawn key stop authenticating. Replacing material under the
same `kid` also invalidates its cached tokens. Keep a monitored refresh and
emergency transfer process: a disconnected file cannot discover an IdP's
later withdrawal on its own. Restoring an older file can restore trust in old
keys, so treat rollback as a security decision and preserve change evidence.

## Build from the vendored archive

Pre-provision Rust/Cargo **1.96.0**, a compatible host linker/C compiler,
cmake, perl and pkg-config. The verified headless path uses bundled SQLite
and TLS crypto; OS keychain libraries are required only if enabling default
features. Verify and unpack:

```bash
sha256sum --check mcp-devtools-vendor.tar.gz.sha256
tar -xzf mcp-devtools-vendor.tar.gz
cd mcp-devtools-source
cargo build --frozen --offline --no-default-features --features wrds,secrets-vault,console
```

The archive includes source, `Cargo.lock`, vendored crates with Cargo's file
checksums, embedded console assets and `.cargo/config.toml` source replacement.
Use `--release` when producing an optimized shipping binary; the release
profile is unchanged. The CI proof builds the command above with an empty
Cargo home and new target directory, so it cannot silently rely on cached
registry sources. `--offline` prevents Cargo fetches; it is not a general
network sandbox for arbitrary dependency build scripts. For strict network
isolation run the build in your disconnected builder with preinstalled OS
inputs. The release job must pass this build before publishing the archive.

See [packages](../deploy/packages/README.md) and
[Compose](../deploy/compose/README.md) for installation, permissions, storage,
TLS, upgrades and rollback. The D.4 benchmark summary and CF-41 record which
local and CI proof was actually exercised.
