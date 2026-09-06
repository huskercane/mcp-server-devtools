# Linux packages

The release publishes `mcp-devtools.deb`, `mcp-devtools.rpm` and
`packages.sha256`, with Sigstore bundles. Verify those as described in
[release operations](../../docs/release-operations-runbook.md). Packages contain
an x86_64 static musl binary from the shipping Dockerfile: WRDS and Vault are
included, OS keychain and the optional console are not. The ordinary platform
archives retain their existing feature selection. No release profile is changed.

Install as root on Debian or UBI/RHEL respectively:

```bash
sha256sum --check packages.sha256
sudo apt-get install ./mcp-devtools.deb
# Or: sudo dnf install ./mcp-devtools.rpm
sudoedit /etc/mcp-devtools/env
sudo chmod 0600 /etc/mcp-devtools/env
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-devtools
curl --fail http://127.0.0.1:3000/
sudo journalctl -u mcp-devtools
```

Installation does not enable or start the service. Its initial mode is local
community access (`MCP_AUTH_MODE=off`, loopback only). Before changing the bind,
configure `MCP_AUTH_MODE=oidc`, `MCP_OIDC_PROFILE`, `MCP_OIDC_ISSUER`,
`MCP_OIDC_AUDIENCE`, and `MCP_PUBLIC_URL`, plus the required signed-policy
and evidence settings: `MCP_POLICY_FILE`, `MCP_POLICY_PUBLIC_KEY`,
`MCP_REVOCATION_FILE` (signed, even when empty), and `MCP_AUDIT_SIGNING_KEY`
(a service-readable checkpoint signing-key file); see [configuration](../../docs/configuration.md).
Put a TLS proxy in front; the service speaks HTTP. An unauthenticated remote
bind is refused even if a proxy is intended. Environment-file edits require
`systemctl restart mcp-devtools`.

The root-owned 0600 environment file is read by the system manager before it
drops privileges. Never change it to be readable by the dynamic service UID.
`DynamicUser`, `StateDirectory`, strict filesystem protection, no privileges,
an empty capability set, private temporary files and umask 0077 are in the
[unit](mcp-devtools.service). Persistent writes belong under
`/var/lib/mcp-devtools`; systemd manages ownership. Do not chown that path to a
numeric transient UID. Journal data defaults to its `journal` subdirectory.
For SQLite set `MCP_ROLLUP_STORE=sqlite:///var/lib/mcp-devtools/usage.sqlite`.
Provision policy/JWKS read-only files under `/etc/mcp-devtools` (public keys
and policy can be 0644; keep credentials in the protected environment file),
and set `MCP_POLICY_FILE` and `MCP_OIDC_JWKS_FILE`. Keep the private
policy-authoring key off the gateway. Provision the audit-checkpoint private
key as an owner-only file in the managed state directory using a service-context
maintenance command; never make it world-readable to accommodate DynamicUser. If policy administration
must replace files, provision them under the managed state directory through
a service-context maintenance command; `/etc` is deliberately not writable.

For one-time audit-key provisioning, stop `mcp-devtools` and create
`/run/systemd/system/mcp-audit-key.service` with this temporary unit:

```ini
[Service]
Type=oneshot
DynamicUser=yes
User=mcp-devtools
StateDirectory=mcp-devtools
ProtectSystem=strict
NoNewPrivileges=yes
CapabilityBoundingSet=
ExecStart=/usr/bin/mcp-devtools audit keygen --out /var/lib/mcp-devtools/audit.key
```

Run `sudo systemctl daemon-reload` and `sudo systemctl start mcp-audit-key`.
The command refuses an existing key. Retain the public verification key from
`sudo journalctl -u mcp-audit-key`; remove the temporary unit and reload the
manager. Set `MCP_AUDIT_SIGNING_KEY=/var/lib/mcp-devtools/audit.key` in the
protected environment, complete the signed policy/revocation configuration,
and start the main unit. This creates the private key with the service's
managed identity without relying on a numeric transient UID. The container
proof exercises this procedure with networking disabled on both distros.

Before upgrade or rollback, stop the unit and take the quiesced verified
backup described in [release operations](../../docs/release-operations-runbook.md).
Package managers preserve modified environment files (RPM uses `noreplace`).
After replacement, run `daemon-reload`, restart, and read health and journal.
Removal does not delete the persistent state; delete it only under your
retention procedure. Package repositories, distro signing keys and automatic
upgrade orchestration are not included.

The release and Rust workflows run `bash scripts/ci/packages-smoke.sh`: install
both formats, start the actual unit with systemd as PID 1, check health and
0600 root ownership, then bootstrap signed policy/revocation and file-JWKS
OIDC with networking disabled, then change to an unauthenticated non-loopback bind and
assert unit failure and no listener. This uses non-privileged rootless Podman containers with systemd support,
without host cgroup mounts. The test requires rootless mode and gives PID 1
`SYS_ADMIN` only inside its subordinate user namespace so it can create the
unit sandbox. The service itself retains an empty capability set.
