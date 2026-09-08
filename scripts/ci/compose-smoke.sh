#!/usr/bin/env bash
set -euo pipefail
export MCP_IMAGE="${1:?image required}"
export MCP_PROXY_IMAGE="${MCP_PROXY_IMAGE:-nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284}"
root="$PWD"
work="$(mktemp -d)"
export MCP_SECRETS_DIR="$work/secrets"
export MCP_ENV_FILE="$work/mcp.env" MCP_JWKS_DIR="$work/jwks" MCP_TLS_DIR="$root/tests/fixtures/tls"
export COMPOSE_PROJECT_NAME="mcp-d4-$$"
MCP_TLS_PORT="$(python3 - <<'PYTHON'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PYTHON
)"
export MCP_TLS_PORT
compose=(docker compose -f deploy/compose/compose.yaml)
cleanup() { "${compose[@]}" --profile syslog logs || true; "${compose[@]}" --profile syslog down -v || true; rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$MCP_JWKS_DIR" "$MCP_SECRETS_DIR"
helper=(docker run --rm --user "$(id -u):$(id -g)" -v "$work:/work" --entrypoint /mcp-devtools "$MCP_IMAGE")
"${helper[@]}" policy keygen --out /work/policy.key --json > "$work/policy-key.json"
cp deploy/policies/slack-read-only.yaml "$work/policy.yaml"
"${helper[@]}" policy sign /work/policy.yaml --key /work/policy.key --json
"${helper[@]}" revoke init --file /work/revocations.yaml --key /work/policy.key --json
"${helper[@]}" audit keygen --out /work/secrets/audit.key --json
# The private policy-authoring key is never mounted in the runtime service.
docker run --rm --user 0 -v "$MCP_SECRETS_DIR:/state" --entrypoint sh "$MCP_PROXY_IMAGE" -c 'chown 65532:65532 /state/audit.key; chmod 400 /state/audit.key'

python3 - "$MCP_JWKS_DIR/jwks.json" <<'PYTHON'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({'keys':[json.loads(pathlib.Path('tests/fixtures/okta_test_jwk.json').read_text())]}))
PYTHON
python3 - "$work/policy-key.json" "$MCP_ENV_FILE" <<'PYTHON'
import json, pathlib, sys
public = json.loads(pathlib.Path(sys.argv[1]).read_text())['public_key']
text = pathlib.Path('deploy/compose/mcp.env.example').read_text()
pathlib.Path(sys.argv[2]).write_text(text.replace('replace-with-base64-verifying-key', public))
PYTHON
cat >> "$MCP_ENV_FILE" <<'FORWARD'
MCP_AUDIT_FORWARD_URL=syslog+tls://syslog:6514
MCP_AUDIT_FORWARD_CA_FILE=/tls/ca.pem
MCP_AUDIT_FORWARD_CLIENT_CERT=/tls/client.pem
MCP_AUDIT_FORWARD_CLIENT_KEY=/tls/client-key.pem
MCP_AUDIT_FORWARD_INTERVAL_SECONDS=1
FORWARD
# Initialize named volumes with the runtime UID and a reviewed policy.
"${compose[@]}" create mcp
for volume in journal rollups policies; do
  docker run --rm --user 0 -v "${COMPOSE_PROJECT_NAME}_$volume:/state" \
    --entrypoint sh "$MCP_PROXY_IMAGE" -c 'chown 65532:65532 /state'
done
container="$("${compose[@]}" ps -aq mcp)"
for file in policy.yaml policy.yaml.sig revocations.yaml revocations.yaml.sig; do
  docker cp "$work/$file" "$container:/policies/$file"
done
"${compose[@]}" --profile syslog up -d --wait --wait-timeout 90
curl --fail --retry 10 --retry-connrefused --retry-all-errors --retry-delay 1 --cacert tests/fixtures/tls/ca.pem "https://localhost:$MCP_TLS_PORT/" > "$work/health"
grep -qi 'mcp' "$work/health"
test "$(curl --silent --cacert tests/fixtures/tls/ca.pem -o /dev/null -w '%{http_code}' "https://localhost:$MCP_TLS_PORT/mcp")" = 401
# A real signed bearer goes through the file-backed validator in the image.
python3 - "$work/bearer" <<'PYTHON'
import base64, json, pathlib, subprocess, sys, time
b64 = lambda data: base64.urlsafe_b64encode(data).rstrip(b'=')
key = json.loads(pathlib.Path('tests/fixtures/okta_test_jwk.json').read_text())
header = {'alg':'RS256','typ':'JWT','kid':key['kid']}
claims = {'iss':'https://issuer.example','aud':'https://mcp.example:8443',
          'sub':'compose-proof','scope':'mcp:admin mcp:tools','iat':int(time.time()),'exp':int(time.time())+300}
message = b'.'.join(b64(json.dumps(value).encode()) for value in [header,claims])
signature = subprocess.run(['openssl','dgst','-sha256','-sign',
    'tests/fixtures/okta_test_rsa_pkcs1.der','-keyform','DER'],input=message,check=True,capture_output=True).stdout
pathlib.Path(sys.argv[1]).write_bytes(b'Authorization: Bearer '+message+b'.'+b64(signature)+b'\n')
PYTHON
curl --fail --retry 10 --retry-connrefused --retry-all-errors --retry-delay 1 --cacert tests/fixtures/tls/ca.pem -H "@$work/bearer" "https://localhost:$MCP_TLS_PORT/admin/policy" > "$work/policy"
printf '{"keys":[]}\n' > "$MCP_JWKS_DIR/next.json"
mv "$MCP_JWKS_DIR/next.json" "$MCP_JWKS_DIR/jwks.json"
test "$(curl --silent --cacert tests/fixtures/tls/ca.pem -H "@$work/bearer" -o /dev/null -w '%{http_code}' "https://localhost:$MCP_TLS_PORT/admin/policy")" = 401
# The startup policy record must reach the optional mutual-TLS receiver.
for _attempt in {1..30}; do
  if "${compose[@]}" exec -T syslog sh -c 'test -s /var/log/mcp-audit/messages'; then break; fi
  sleep 1
done
"${compose[@]}" exec -T syslog sh -ec 'test -s /var/log/mcp-audit/messages; grep policy /var/log/mcp-audit/messages'
"${compose[@]}" up -d --force-recreate --no-deps --wait --wait-timeout 90 mcp
# nginx resolves the service address on startup; refresh it after replacement.
"${compose[@]}" restart proxy
"${compose[@]}" up -d --wait --wait-timeout 90
curl --fail --retry 10 --retry-connrefused --retry-all-errors --retry-delay 1 --cacert tests/fixtures/tls/ca.pem "https://localhost:$MCP_TLS_PORT/"
"${compose[@]}" exec -T syslog syslog-ng-ctl stats

for volume in journal rollups policies; do
  docker run --rm --user 0 -v "${COMPOSE_PROJECT_NAME}_$volume:/state:ro" \
    --entrypoint sh "$MCP_PROXY_IMAGE" -c 'test -n "$(ls -A /state)"'
done
