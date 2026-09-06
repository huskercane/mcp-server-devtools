#!/usr/bin/env bash
# Real systemd as PID 1: never substitute direct binary execution for unit proof.
set -euo pipefail
packages="$(cd "${1:?package directory required}" && pwd)"
name="mcp-package-proof-$$"
# SYS_ADMIN belongs only to the subordinate user namespace, never the host.
# PID 1 needs it to create the unit sandbox; the service itself has no capabilities.
test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
cleanup() {
  local result=$?
  if (( result != 0 )); then
    podman logs "$name" || true
    podman exec "$name" journalctl -u mcp-devtools --no-pager -n 40 || true
  fi
  podman rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
for distro in debian ubi; do
  podman build -f "deploy/packages/Dockerfile.$distro" -t "localhost/mcp-package-test:$distro" deploy/packages
  podman run -d --name "$name" --systemd=always --cap-add SYS_ADMIN --network none \
    --tmpfs /run --tmpfs /tmp \
    -v "$PWD/tests/fixtures/okta_test_jwk.json:/fixture/jwk.json:ro" \
    -v "$packages:/packages:ro" "localhost/mcp-package-test:$distro"
  for _attempt in {1..30}; do
    podman exec "$name" systemctl list-units >/dev/null 2>&1 && break
    sleep 1
  done
  if [[ "$distro" == debian ]]; then
    podman exec "$name" dpkg -i /packages/mcp-devtools.deb
  else
    podman exec "$name" rpm -i /packages/mcp-devtools.rpm
  fi
  podman exec "$name" bash -euc '
    test "$(stat -c "%a:%U:%G" /etc/mcp-devtools/env)" = 600:root:root
    systemctl daemon-reload
    test "$(systemctl show -p DynamicUser --value mcp-devtools)" = yes
    test "$(systemctl show -p ProtectSystem --value mcp-devtools)" = strict
    test "$(systemctl show -p NoNewPrivileges --value mcp-devtools)" = yes
    test -z "$(systemctl show -p CapabilityBoundingSet --value mcp-devtools)"
    systemctl start mcp-devtools
    for _attempt in {1..30}; do
      if curl -fsS http://127.0.0.1:3000/ > /tmp/health; then break; fi
      sleep 1
    done
    systemctl is-active --quiet mcp-devtools
    grep -q "mcp" /tmp/health
    cat /tmp/health
    systemctl stop mcp-devtools
    # Complete offline bootstrap using signed bundles and a service-owned audit key.
    mcp-devtools policy keygen --out /tmp/policy.key --json > /tmp/policy-key.json
    public=$(sed -n "s/.*\"public_key\":\"\\([^\"]*\\)\".*/\\1/p" /tmp/policy-key.json)
    test -n "$public"
    printf "version: 1\ndefault: deny\nrules: []\n" > /etc/mcp-devtools/policy.yaml
    mcp-devtools policy sign /etc/mcp-devtools/policy.yaml --key /tmp/policy.key
    mcp-devtools revoke init --file /etc/mcp-devtools/revocations.yaml --key /tmp/policy.key
    rm /tmp/policy.key
    printf "[Service]\nType=oneshot\nDynamicUser=yes\nUser=mcp-devtools\nStateDirectory=mcp-devtools\nProtectSystem=strict\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nExecStart=/usr/bin/mcp-devtools audit keygen --out /var/lib/mcp-devtools/audit.key\n" > /run/systemd/system/mcp-audit-key.service
    systemctl daemon-reload
    systemctl start mcp-audit-key.service
    rm /run/systemd/system/mcp-audit-key.service
    printf "{\"keys\":[%s]}\n" "$(cat /fixture/jwk.json)" > /etc/mcp-devtools/jwks.json
    printf "MCP_AUTH_MODE=oidc\nMCP_OIDC_PROFILE=generic\nMCP_OIDC_ISSUER=https://issuer.example\nMCP_OIDC_AUDIENCE=https://mcp.example\nMCP_PUBLIC_URL=https://mcp.example\nMCP_OIDC_JWKS_FILE=/etc/mcp-devtools/jwks.json\nMCP_POLICY_FILE=/etc/mcp-devtools/policy.yaml\nMCP_POLICY_PUBLIC_KEY=%s\nMCP_REVOCATION_FILE=/etc/mcp-devtools/revocations.yaml\n" "$public" >> /etc/mcp-devtools/env
    mkdir -p /run/systemd/system/mcp-devtools.service.d
    printf "MCP_AUDIT_SIGNING_KEY=/var/lib/mcp-devtools/audit.key\n" >> /etc/mcp-devtools/env
    systemctl daemon-reload
    systemctl start mcp-devtools
    for _attempt in {1..30}; do
      if curl -fsS http://127.0.0.1:3000/ > /tmp/offline-health; then break; fi
      sleep 1
    done
    systemctl is-active --quiet mcp-devtools
    grep -q "is running" /tmp/offline-health
    cat /tmp/offline-health
    test "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/admin/policy)" = 401
    systemctl stop mcp-devtools
    sed -i "s/MCP_BIND_ADDR=127.0.0.1/MCP_BIND_ADDR=0.0.0.0/; s/MCP_AUTH_MODE=oidc/MCP_AUTH_MODE=off/" /etc/mcp-devtools/env
    mkdir -p /run/systemd/system/mcp-devtools.service.d
    printf "[Service]\nRestart=no\n" > /run/systemd/system/mcp-devtools.service.d/test.conf
    systemctl daemon-reload
    systemctl start mcp-devtools || true
    for _attempt in {1..30}; do
      test "$(systemctl show -p Result --value mcp-devtools)" = exit-code && break
      sleep 1
    done
    test "$(systemctl show -p Result --value mcp-devtools)" = exit-code
    journalctl -u mcp-devtools --no-pager > /tmp/unit.log
    cat /tmp/unit.log
    grep -Ei "non.loopback|refus|loopback" /tmp/unit.log
    ! curl -fsS http://127.0.0.1:3000/
  '
  podman rm -f "$name"
done
