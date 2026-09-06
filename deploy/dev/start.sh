#!/usr/bin/env bash
set -euo pipefail
cd /workspace
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
cargo build --locked --no-default-features --features console,wrds,secrets-vault
cd /state
# Do not load vendor credentials from a developer's checkout .env at runtime.
bin=/build/debug/mcp-devtools
umask 077
mkdir -p /state/journal /tls
# Initialize a fresh generation separately; interrupted initialization is retryable.
if [[ ! -d /state/config ]]; then
    seed=$(mktemp -d /state/seed.XXXXXX)
    "$bin" policy keygen --out "$seed/policy.key" --json > "$seed/policy-key.json"
    "$bin" audit keygen --out "$seed/audit.key" --json > "$seed/audit-key.json"
    printf 'version: 1\ndefault: deny\nrules: []\n' > "$seed/policy.yaml"
    "$bin" policy sign "$seed/policy.yaml" --key "$seed/policy.key"
    "$bin" revoke init --file "$seed/revocations.yaml" --key "$seed/policy.key"
    mv "$seed" /state/config
fi
if [[ ! -f /tls/localhost.crt ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout /tls/localhost.key -out /tls/localhost.crt \
      -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
fi
export MCP_POLICY_FILE=/state/config/policy.yaml
export MCP_POLICY_PUBLIC_KEY
MCP_POLICY_PUBLIC_KEY=$(python3 -c 'import json; print(json.load(open("/state/config/policy-key.json"))["public_key"])')
export MCP_REVOCATION_FILE=/state/config/revocations.yaml
export MCP_AUDIT_SIGNING_KEY=/state/config/audit.key
export MCP_AUDIT_JOURNAL_DIR=/state/journal
export MCP_ROLLUP_STORE=sqlite:///state/usage.sqlite
for ((attempt=0; attempt<120; attempt++)); do
    if curl --fail --silent --output /dev/null http://localhost:8080/realms/mcp/.well-known/openid-configuration; then
        exec "$bin" serve --transport http --role all
    fi
    sleep 2
done
echo 'Keycloak did not become ready within 240 seconds.' >&2
exit 1
