#!/usr/bin/env bash
# The published-image proof (plan §3.8, "Published image"; C.2b): run the
# container image an operator would deploy — distroless, non-root,
# read-only root filesystem, `--no-default-features` plus `wrds` and
# `secrets-vault` — with a `vault://` reference against a real Vault, and
# assert the health banner, one tool call whose upstream saw the secret
# Vault holds (never the reference text), and the fail-closed refusal when
# the reference cannot be resolved.
#
# Usage: image-vault-smoke.sh IMAGE
# Env:   VAULT_ADDR (default http://127.0.0.1:8200), VAULT_TOKEN (default root)
#
# Uses the host network so the image reaches Vault and the fake upstream on
# loopback, which is also what keeps plain-http Vault inside the adapter's
# "loopback only" rule.
set -euo pipefail

IMAGE="${1:?usage: image-vault-smoke.sh IMAGE}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
UPSTREAM_PORT=9099
GATEWAY_PORT=3000
WORK="$(mktemp -d)"
SEEN="$WORK/seen-authorization.txt"
HERE="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  docker rm -f mcp-smoke >/dev/null 2>&1 || true
  docker rm -f mcp-smoke-refused >/dev/null 2>&1 || true
  [[ -n "${UPSTREAM_PID:-}" ]] && kill "$UPSTREAM_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # URL, seconds
  local url="$1" seconds="$2" i
  for ((i = 0; i < seconds * 2; i++)); do
    if curl -fs "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "timed out waiting for $url" >&2
  return 1
}

echo "== Vault: wait, then write the secret"
wait_for "$VAULT_ADDR/v1/sys/health" 120
curl -fsS -H "X-Vault-Token: $VAULT_TOKEN" -X POST \
  "$VAULT_ADDR/v1/secret/data/mcp-image-smoke/grafana" \
  -d '{"data":{"token":"glsa_from_vault_smoke"}}' >/dev/null

echo "== fake upstream on 127.0.0.1:$UPSTREAM_PORT"
: > "$SEEN"
python3 "$HERE/fake-upstream.py" "$UPSTREAM_PORT" "$SEEN" &
UPSTREAM_PID=$!
wait_for "http://127.0.0.1:$UPSTREAM_PORT/" 10
: > "$SEEN"

echo "== gateway from $IMAGE (read-only root, host network, vault:// reference)"
docker run -d --name mcp-smoke --network host --read-only --tmpfs /tmp \
  -e MCP_BIND_ADDR=127.0.0.1 -e PORT="$GATEWAY_PORT" \
  -e MCP_VAULT_ADDR="$VAULT_ADDR" -e MCP_VAULT_AUTH=token -e MCP_VAULT_TOKEN="$VAULT_TOKEN" \
  -e GRAFANA_URL="http://127.0.0.1:$UPSTREAM_PORT" \
  -e GRAFANA_TOKEN='vault://secret/mcp-image-smoke/grafana#token' \
  "$IMAGE" --role all >/dev/null
if ! wait_for "http://127.0.0.1:$GATEWAY_PORT/" 60; then
  docker logs mcp-smoke >&2 || true
  exit 1
fi

echo "== health banner"
BANNER="$(curl -fsS "http://127.0.0.1:$GATEWAY_PORT/")"
echo "$BANNER"
grep -q "is running" <<<"$BANNER"
if grep -q "failing" <<<"$BANNER"; then echo "banner reports a failing refresh" >&2; exit 1; fi

echo "== one tool call through the gateway"
RESPONSE="$(curl -fsS -X POST "http://127.0.0.1:$GATEWAY_PORT/mcp" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: grafana_list_datasources' \
  -d '{"jsonrpc":"2.0","id":"smoke-1","method":"tools/call","params":{"name":"grafana_list_datasources","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"image-smoke","version":"0"}}}}')"
echo "$RESPONSE" | head -c 600; echo
if grep -q '"isError":true' <<<"$RESPONSE"; then echo "tool call failed" >&2; exit 1; fi
grep -q '"result"' <<<"$RESPONSE"

echo "== the upstream saw the secret from Vault, not the reference"
cat "$SEEN"
grep -q "Bearer glsa_from_vault_smoke" "$SEEN"
if grep -q "vault://" "$SEEN"; then echo "the reference text went upstream" >&2; exit 1; fi
if docker logs mcp-smoke 2>&1 | grep -q "glsa_from_vault_smoke"; then
  echo "the gateway logged the secret" >&2; exit 1
fi

echo "== an unresolvable reference refuses to start (fail closed)"
set +e
docker run --name mcp-smoke-refused --network host --read-only --tmpfs /tmp \
  -e MCP_BIND_ADDR=127.0.0.1 -e PORT=3001 \
  -e MCP_VAULT_ADDR="$VAULT_ADDR" -e MCP_VAULT_AUTH=token -e MCP_VAULT_TOKEN="$VAULT_TOKEN" \
  -e GRAFANA_URL="http://127.0.0.1:$UPSTREAM_PORT" \
  -e GRAFANA_TOKEN='vault://secret/mcp-image-smoke/absent#token' \
  "$IMAGE" --role all >"$WORK/refused.log" 2>&1
STATUS=$?
set -e
cat "$WORK/refused.log" | tail -5
[[ $STATUS -ne 0 ]] || { echo "the gateway started with an unresolvable reference" >&2; exit 1; }
grep -q "refusing to start" "$WORK/refused.log"
grep -q "secret_source_not_found" "$WORK/refused.log"

echo "== published-image smoke: PASS"
