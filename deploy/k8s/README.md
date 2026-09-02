# Kubernetes deployment example (Phase A)

One image, two roles (plan ADR-010, §3.4): `gateway ×N` behind a TLS
ingress, `control ×1` for the control plane. In Phase A the control role
serves only its health banner; the admin API, rollups, and console arrive
in Phases C and D, so `control.yaml` is here to fix the topology, not
because it does much yet.

Files:

| File | What it is |
|---|---|
| `namespace.yaml` | The `mcp-devtools` namespace. |
| `config.yaml` | ConfigMap with the non-secret enterprise settings and the policy document; Secret template for the vendor credentials. **Fill in the issuer, audience, public URL, and credentials.** |
| `gateway.yaml` | Deployment (non-root, read-only root filesystem, `/tmp` on `emptyDir`, journal on a PVC), Service, PodDisruptionBudget. |
| `control.yaml` | Deployment + Service for the control role. |
| `ingress-nginx.yaml` | ingress-nginx Ingress with TLS via cert-manager, `Mcp-Session-Id` stickiness, and the body limit. |

Apply in order:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/config.yaml      # after editing it
kubectl apply -f deploy/k8s/gateway.yaml
kubectl apply -f deploy/k8s/control.yaml
kubectl apply -f deploy/k8s/ingress-nginx.yaml
```

Then, from a client with an Okta-issued token:

```bash
curl -sS https://mcp.example.com/.well-known/oauth-protected-resource
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"curl","version":"0"}}}}' \
  https://mcp.example.com/mcp
```

## What the manifests enforce

- **Fail closed at startup.** The gateway refuses to start unless the
  issuer, audience, public URL, policy file, and journal directory are all
  set (`docs/configuration.md`, "Enterprise mode"). A pod that is
  misconfigured never becomes Ready.
- **Health means "will serve".** The readiness and liveness probes exec
  `mcp-devtools health`, which answers non-zero when the audit journal can
  no longer accept records — a gateway that would refuse every call is
  taken out of rotation instead of receiving traffic.
- **Journal on a persistent volume.** Audit RPO is 0 only if the journal
  survives the pod. The PVC is `ReadWriteOnce` per replica via a
  `volumeClaimTemplate`-style StatefulSet in your own environment if you
  scale beyond one gateway; the example keeps one replica with one claim so
  the durable-journal property is unambiguous. The gateway also refuses new
  calls while the journal cannot be written, which is the fail-closed half
  of the same guarantee.
- **Read-only root filesystem.** The only writable paths are `/tmp`
  (response artifacts, diagnostic logs — `HOME=/tmp`) and the journal.
- **Session stickiness.** Legacy MCP sessions live in the pod that created
  them; the ingress hashes on `Mcp-Session-Id` so a session's requests
  reach the same replica. Stateless (2026-07-28) requests carry no session
  and balance freely. A miss returns MCP's "session not found" and the
  client re-initialises.
- **TLS terminates at the ingress** (ADR-004). The pod listens on plain
  HTTP inside the cluster.

## Not in this example

Horizontal gateway scaling with a shared artifact volume, the control
plane's admin API, Prometheus metrics, and Helm packaging are Phase C
(plan §4).
