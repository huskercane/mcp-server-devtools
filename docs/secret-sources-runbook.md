# Secret sources runbook

How to point the gateway's secret **references** at each supported
provider, and what to set up on the provider's side (plan §3.8, C.2). The
reference syntax and every setting are in
[`configuration.md`](configuration.md#secret-references); this runbook is
the provider-side half. Common to every provider:

- References are resolved **before the gateway starts serving**; one that
  does not resolve refuses startup with the reference named. At runtime a
  failing refresh keeps the last good values and degrades the health
  banner; a later success recovers.
- A tool call never waits on a provider: it reads the snapshot the
  background refresher fills every `MCP_SECRET_REFRESH_INTERVAL_SECONDS`
  (default 30), plus one early refresh on an upstream `401`.
- Multi-part credentials (an email and a token, a client id and secret)
  belong in **one** document, so they rotate together.
- The audit record and the enterprise result metadata carry `source` (the
  scheme) and `version` (the provider's version) for every referenced
  credential; the version changing is the rotation evidence.
- The provider's own credential (a Vault token, a secret id) can be a
  literal or a `file://` reference — never another provider reference.

## Mounted files (`file://`)

No provider-side setup. A Kubernetes `Secret` projected as a volume, or a
CSI Secrets Store volume backed by Vault, AWS, or Azure
(`deploy/k8s/secrets-csi.yaml`), is re-projected by the kubelet on change;
the gateway re-reads it on the refresh interval. This is the path that
works on every cloud with no native adapter, and the one to reach for when
the native adapter for a provider is deferred (`awssm://`, `azkv://`;
see below).

## HashiCorp Vault and OpenBao (`vault://`)

One adapter serves both; the KV v2 and auth APIs are the same. CI runs the
live test against `hashicorp/vault:1.21.4` and `openbao/openbao:2.6.2`.

| Setting | Value |
|---|---|
| Reference | `vault://<mount>/<path>#<key>` — `secret/mcp/grafana#token` reads `secret/data/mcp/grafana`, key `token` |
| `MCP_VAULT_ADDR` | `https://vault.example:8200` (`http` only on loopback) |
| `MCP_VAULT_AUTH` | `kubernetes` on Kubernetes; `approle` elsewhere; `token` for development or behind a Vault Agent sidecar |
| `MCP_VAULT_NAMESPACE` | Enterprise / HCP only |
| `MCP_VAULT_CACERT` | the private CA's PEM, if any |

### Vault-side setup

1. **A KV v2 mount and the secret**, one document per credential set:

   ```bash
   vault secrets enable -path=secret -version=2 kv   # dev mode has this already
   vault kv put secret/mcp/grafana token=glsa_…
   vault kv put secret/mcp/atlassian email=svc@acme.example token=ATATT…
   ```

   Reference them as `GRAFANA_TOKEN=vault://secret/mcp/grafana#token`,
   `ATLASSIAN_USER_EMAIL=vault://secret/mcp/atlassian#email`,
   `ATLASSIAN_API_TOKEN=vault://secret/mcp/atlassian#token`. The two
   Atlassian halves come from one read and swap together.

2. **A read-only policy** — the gateway needs `read` on the data paths and
   nothing else (`renew-self` and `lookup-self` are in the `default`
   policy every token carries):

   ```hcl
   path "secret/data/mcp/*" { capabilities = ["read"] }
   ```

   ```bash
   vault policy write mcp-devtools mcp-devtools.hcl
   ```

3. **An auth method.**

   *Kubernetes* (`MCP_VAULT_AUTH=kubernetes`): enable the method, point it
   at the cluster, and bind a role to the gateway's service account. The
   gateway reads the projected token from
   `/var/run/secrets/kubernetes.io/serviceaccount/token` at every login.

   ```bash
   vault auth enable kubernetes
   vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_SERVICE_HOST:443"
   vault write auth/kubernetes/role/mcp-devtools \
     bound_service_account_names=mcp-devtools \
     bound_service_account_namespaces=mcp-devtools \
     token_policies=mcp-devtools token_ttl=1h token_max_ttl=24h
   ```

   Set `MCP_VAULT_ROLE=mcp-devtools`. `deploy/k8s/secrets-vault.yaml` is
   the matching manifest.

   *AppRole* (`MCP_VAULT_AUTH=approle`): for VMs and containers outside
   Kubernetes. Deliver the secret id as a file the gateway reads at login
   (`MCP_VAULT_SECRET_ID=file:///run/secrets/vault-secret-id`), so it can
   be rotated in place.

   ```bash
   vault auth enable approle
   vault write auth/approle/role/mcp-devtools token_policies=mcp-devtools \
     token_ttl=1h token_max_ttl=24h secret_id_ttl=0
   vault read auth/approle/role/mcp-devtools/role-id
   vault write -f auth/approle/role/mcp-devtools/secret-id
   ```

   *Token* (`MCP_VAULT_AUTH=token`): a dev server's root token, or the
   sink file of a Vault Agent sidecar (`MCP_VAULT_TOKEN=file:///vault/token`,
   with `MCP_VAULT_ADDR=http://127.0.0.1:8100` if the agent proxies).

### What the adapter does with the token

It renews a renewable token with `renew-self` once two thirds of its lease
is gone, logs in again when renewal fails or the lease is over, and on a
`403` from a read logs in once more and retries once — so a token an
operator revokes is replaced on the next refresh, and a policy that stops
granting the path shows up as `secret_source_unavailable (forbidden)` in
the operator log, with the reference named and the token never printed.

### Rotation

`vault kv put` a new version. The next refresh (≤ 30 s by default) swaps
the values in whole; the audit record's `version` becomes the new KV
version number. Nothing restarts. For a rollback, `vault kv rollback`
produces a new version too, and is picked up the same way.

### Running the live test locally

```bash
docker run -d --name vault -p 127.0.0.1:8200:8200 hashicorp/vault:1.21.4 \
  server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200
MCP_TEST_VAULT_ADDR=http://127.0.0.1:8200 cargo test --test vault_live_tests -- --nocapture
```

(`openbao/openbao:2.6.2` with the same arguments for OpenBao.) The test
creates its own policy, AppRole, and secret under `secret/mcp-live-test/`.
`scripts/ci/image-vault-smoke.sh <image>` runs the published container
image against the same server.

### Troubleshooting by category

| Category (operator log) | Usual cause |
|---|---|
| `secret_source_unconfigured` | A `vault://` reference with no `MCP_VAULT_ADDR`. |
| `cannot configure the secret source vault://: …` at startup | `MCP_VAULT_AUTH` missing or unknown, a method's credential missing, a plain-`http` address off loopback, an unreadable CA file. |
| `secret_source_unavailable (login refused)` | Wrong role id / secret id, a Kubernetes role not bound to this service account or namespace, or the auth method mounted elsewhere (`MCP_VAULT_AUTH_MOUNT`). |
| `secret_source_unavailable (forbidden)` | The token's policy does not grant `read` on `<mount>/data/<path>`, even after a fresh login. |
| `secret_source_unavailable (sealed)` | Vault answers 503: sealed, or a standby without request forwarding. Last good values stay in force. |
| `secret_source_not_found` | No secret at the path, or the current version is deleted or destroyed. |
| `secret_document_malformed` | The `#key` is not in the secret, or is not a string. |

## AWS Secrets Manager and Azure Key Vault

Deferred (plan rev 2.16): the native `awssm://` and `azkv://` adapters
(C.2c, C.2d) are built when a design partner asks for them. The supported
path on both clouds is a CSI Secrets Store volume and `file://`
(`deploy/k8s/secrets-csi.yaml` shows the Vault provider; the AWS and Azure
providers differ only in their `SecretProviderClass`). The two schemes stay
reserved and are refused at startup by name.
