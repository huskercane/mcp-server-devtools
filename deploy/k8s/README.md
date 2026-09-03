# Kubernetes deployment example (Phases A and B)

One image, two roles (plan ADR-010, §3.4): `gateway ×N` behind a TLS
ingress, `control ×1` for the control plane. In Phase A the control role
serves only its health banner; the admin API, rollups, and console arrive
in Phases C and D, so `control.yaml` is here to fix the topology, not
because it does much yet.

Files:

| File | What it is |
|---|---|
| `namespace.yaml` | The `mcp-devtools` namespace. |
| `config.yaml` | ConfigMap with the non-secret enterprise settings, the **signed** policy document and revocation list (`.sig` sidecars included); Secret templates for the vendor credentials and the audit checkpoint signing key. **Fill in the issuer, audience, public URL, policy public key, signatures, and credentials.** |
| `gateway.yaml` | Deployment (non-root, read-only root filesystem, `/tmp` on `emptyDir`, journal on a PVC), Service, PodDisruptionBudget. |
| `control.yaml` | Deployment + Service for the control role. |
| `ingress-nginx.yaml` | ingress-nginx Ingress with TLS via cert-manager and the body limit. No session affinity: see "Sessions" below. |

Before applying, produce the keys and signatures on an operator machine
(never on a gateway) — Phase B, WPs B.3/B.4/B.6:

```bash
mcp-devtools policy keygen --out policy-signing.key       # keep private; paste the public key into MCP_POLICY_PUBLIC_KEY
mcp-devtools policy check policy.yaml
mcp-devtools policy sign  policy.yaml --key policy-signing.key             # → policy.yaml.sig
mcp-devtools revoke init  --file revocations.yaml --key policy-signing.key # → revocations.yaml + .sig
mcp-devtools audit  keygen --out audit-signing.key        # the gateway's; keep the public key for `audit verify`
kubectl create secret generic mcp-devtools-audit-signing-key \
  --from-file=audit-signing.key -n mcp-devtools
```

Every later policy edit is `policy check` → `policy sign` → update the
ConfigMap; a gateway that sees the new document before its new signature
journals one rejected reload and picks the pair up on the next poll. To
revoke a user or a token, `mcp-devtools revoke subject|token|all` rewrites
and re-signs `revocations.yaml`; see `docs/revocation-runbook.md`.

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
  issuer, audience, public URL, policy file, policy public key, revocation
  list, audit signing key, and journal directory are all set and the
  documents' signatures verify (`docs/configuration.md`, "Enterprise
  mode"). A pod that is misconfigured never becomes Ready.
- **Only signed authorization state is applied.** The policy and the
  revocation list are verified against `MCP_POLICY_PUBLIC_KEY` at startup
  and on every reload; an unsigned or missigned document is refused and the
  last good one stays in force (health reports the degraded state). Every
  load, change, and rejection is a record in the audit journal.
- **The journal is verifiable offline.** Checkpoints signed with the
  gateway's key seal the journal every 256 records / 60 s and at shutdown,
  and are copied to `/journal/checkpoints`; ship that directory and run
  `mcp-devtools audit verify` on a copy (`docs/audit-reports.md`).
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
- **Sessions.** Legacy MCP sessions live in the pod that created them,
  and the example runs **one** gateway replica, so nothing more is needed.
  Scaling past one replica needs an affinity mechanism that binds a
  session to the pod that created it. Hashing the `Mcp-Session-Id` header
  at the ingress cannot do that (the initialize request has no id; the id
  is generated in the response), and it would send every stateless request
  to a single pod. Use ingress cookie affinity if your MCP clients keep
  cookies, or a shared session store (plan §3.4; tracked as CF-16). A miss
  returns MCP's "session not found" and the client re-initialises.
- **TLS terminates at the ingress** (ADR-004). The pod listens on plain
  HTTP inside the cluster.

## Not in this example

Horizontal gateway scaling (session affinity, a shared artifact volume),
the control plane's admin API, Prometheus metrics, and Helm packaging are
Phase C (plan §4).
