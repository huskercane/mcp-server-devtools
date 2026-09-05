# MCP DevTools Helm chart

This chart mirrors `deploy/k8s`: one image with gateway/control roles,
non-root UID/GID 65532, dropped capabilities, read-only root filesystem,
projected audit signing key (0400 plus fsGroup), health probes, Recreate
updates, persistent journal storage, gateway disruption budget, and optional
TLS ingress. Each role has its own retained PVC; uninstall does not erase
its evidence. Replica counts above one are refused until CF-16 is resolved.

Create the namespace, vendor-credential Secret, audit-signing-key Secret, and
signed policy ConfigMap described by `deploy/k8s/config.yaml`, replacing every
placeholder. Set `existingSecrets`, `policyConfigMap`, and `config` in a private
values file. Secrets and signing private keys do not belong in values files.
Unlike the raw health-only control starter, this chart's control process uses
the configured OIDC boundary and its own writable journal/PVC for admin evidence.

```sh
helm lint deploy/helm/mcp-devtools --strict
helm upgrade --install devtools deploy/helm/mcp-devtools \
  --namespace mcp-devtools --create-namespace --values deployment-values.yaml \
  --wait --timeout 5m
```

Pin `image.digest` to a verified release digest; otherwise the chart uses the
release tag derived from `Chart.yaml`'s appVersion. Set an existing claim per
role when restoring state. Chart package appVersion must follow Cargo.toml.

For co-located administration and usage, set `roles.gateway.role: all`,
`roles.control.enabled: false`, and
`roles.gateway.env.MCP_ROLLUP_STORE: sqlite:///journal/usage.sqlite`.
Split-role gateway usage and process inventories retain CF-16/CF-33's limits;
the chart does not create a cross-process transport.

CSI/Vault examples from `deploy/k8s/secrets-csi.yaml` and `secrets-vault.yaml`
map to each role's `extraVolumes`, `extraVolumeMounts`, `env`, and optional
`serviceAccountName`. Keep projected tokens explicit; do not enable automatic
service-account-token mounting. Signed policy files are read-only by default;
for audited deny-list uploads, supply a pre-populated writable `policyClaim`
shared with the relevant gateways. Keep one control writer for that volume.

Backup, restore, image verification, upgrade and rollback procedures are in
[`docs/release-operations-runbook.md`](../../../docs/release-operations-runbook.md).
