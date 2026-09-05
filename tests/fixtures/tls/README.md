# Test TLS material (not secrets)

A throwaway certificate authority and two leaf certificates, valid for a
hundred years, used only by the audit-forwarding tests and the `siem` CI
job's syslog-ng container. Nothing here protects anything: the private
keys are public by design. Do not reuse them anywhere.

| File | What |
|---|---|
| `ca.pem`, `ca-key.pem` | The CA (`CN=mcp-devtools test CA`, EC P-256). |
| `server.pem`, `server-key.pem` | Leaf for the receiver: SANs `localhost`, `127.0.0.1`, `::1`, `syslog`. PKCS#8 key. |
| `client.pem`, `client-key.pem` | Leaf for the forwarder's mutual-TLS test (`CN=mcp-devtools`). PKCS#8 key. |
| `openssl-san.cnf` | The extensions used to mint them. |

Regenerate with `openssl` (see the commands in the git history of this
directory) if a test ever needs a different SAN.
