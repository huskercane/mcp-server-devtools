# TLS Compose reference

One `--role all` process avoids the split-topology delivery gaps (CF-16/33).
Only nginx publishes a port, 8443 on loopback by default. Set `MCP_TLS_BIND`
when exposing it to your network; `MCP_TLS_PORT` changes the published port. The MCP service always authenticates its
non-loopback listener; the proxy passes Authorization through and terminates
TLS without holding identity authority. Streaming responses are unbuffered.

Run commands here unless a path says otherwise. Supply immutable images and
operator-owned configuration:

```bash
export MCP_IMAGE=registry.example/mcp-devtools@sha256:<verified-release-digest>
export MCP_PROXY_IMAGE=registry.example/nginx@sha256:<verified-mirror-digest>
cp mcp.env.example mcp.env
chmod 0600 mcp.env
mkdir -p tls jwks secrets
# Provision server.pem, server-key.pem and your CA in tls; JWKS in jwks/jwks.json.
# Edit issuer, audience and public URL in mcp.env before starting.
docker compose create mcp
```

Provision your own TLS certificates; never deploy the test private keys.
The proxy runs as UID/GID 101. Give only that identity read access to its
private key (e.g. root:101, 0640, directory traversal allowed). The MCP image
runs as UID/GID 65532; public JWKS files must be readable by that identity.
Mount the JWKS **directory**, so atomic replacement of a file is visible.
Enterprise startup also requires a signed policy, signed revocation list,
policy verifying key, and audit-checkpoint signing key. On the trusted
policy-authoring workstation, run `mcp-devtools policy keygen --out policy.key`,
sign the reviewed `policy.yaml` with `policy sign policy.yaml --key policy.key`,
and create `revoke init --file revocations.yaml --key policy.key`. Set the
printed public key as `MCP_POLICY_PUBLIC_KEY` in `mcp.env`. Transfer only the
policy/revocation documents and `.sig` sidecars to the deployment; keep the
private policy-authoring key off the runtime host. Generate the separate
checkpoint key with `mcp-devtools audit keygen --out secrets/audit.key`; make
it owned/readable only by UID 65532 (0400) and keep it in the read-only secrets
mount. Preserve this key under your key-backup procedure.

Initialize named volumes once, using the same project name on all commands:

```bash
for volume in journal rollups policies; do
  docker run --rm --user 0 -v "mcp-devtools_${volume}:/state"     --entrypoint sh "$MCP_PROXY_IMAGE" -c 'chown 65532:65532 /state'
done
# Copy the reviewed, signed documents provisioned above.
for file in policy.yaml policy.yaml.sig revocations.yaml revocations.yaml.sig; do
  docker cp "$file" "$(docker compose ps -aq mcp):/policies/$file"
done
docker compose up -d --wait
curl --fail --cacert tls/ca.pem https://localhost:8443/
docker compose logs mcp proxy
```

Changing Compose's project name changes the volume names; update the commands
accordingly. Journal, SQLite rollups and policy files persist across container
replacement. Do not use `down -v` on an operating installation. Quiesce the
stack before backup/restore; apply the verified backup procedure in the
[release runbook](../../docs/release-operations-runbook.md) to these volumes.
Updates: verify/mirror the new digest, back up, change `MCP_IMAGE`, then
`docker compose up -d --wait`, followed by `docker compose restart proxy`
to refresh nginx's upstream DNS after container replacement. Rollback uses the previous digest and compatible
verified state. No replicas or high availability are claimed.

For optional RFC 5425 forwarding, uncomment the forwarding settings in
`mcp.env`, provision CA/server/client certificates (the server certificate
must cover DNS `syslog`), make the client key readable only by UID 65532, set
`MCP_SYSLOG_IMAGE` to a mirrored digest, then `docker compose --profile syslog
up -d --wait`. The profile reuses the syslog-ng configuration from
`tests/fixtures/syslog-ng`; it requires mutual TLS and persists received
messages in the `syslog` volume. Its default image is 4.10.1 pinned by digest; substitute your mirrored digest
inside a disconnected deployment.
The reference config and test CA are separate: only the config is reused in
production. TCP acknowledgement limitations remain CF-32.

`bash scripts/ci/compose-smoke.sh mcp-devtools:ci` from the repository root
exercises TLS, unauthenticated refusal, persistent volumes, container replacement and the
optional syslog profile using disposable volumes and fixture certificates.
It deletes only its uniquely named test project. The standard image does
not include the console; an offline source build can enable `console`.
