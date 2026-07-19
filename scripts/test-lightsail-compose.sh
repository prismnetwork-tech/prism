#!/usr/bin/env bash
set -euo pipefail

project="prism-lightsail-test-$$"
secrets=deploy/lightsail/secrets/tls
compose=(
  docker compose
  -p "$project"
  --env-file deploy/lightsail/.env.example
  -f deploy/lightsail/compose.yml
)

if [[ -e $secrets ]]; then
  echo "refusing to replace existing Lightsail TLS secrets" >&2
  exit 73
fi

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf deploy/lightsail/secrets
}
trap cleanup EXIT

./scripts/generate-lightsail-tls.sh tunnel.example.invalid "$secrets" >/dev/null 2>&1
"${compose[@]}" config --quiet
docker run --rm \
  -e PRISM_DOMAIN=example.invalid \
  -e PRISM_ACME_EMAIL=operations@example.invalid \
  -v "$PWD/deploy/lightsail/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.10-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
  caddy validate --config /etc/caddy/Caddyfile >/dev/null
"${compose[@]}" up -d cache >/dev/null 2>&1

container=$("${compose[@]}" ps -q cache)
for _ in $(seq 1 30); do
  status=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  [[ $status == healthy ]] && break
  if [[ $status == exited || $status == dead ]]; then
    "${compose[@]}" logs tls-init cache >&2
    exit 1
  fi
  sleep 1
done
[[ $(docker inspect "$container" --format '{{.State.Health.Status}}') == healthy ]]

docker exec "$container" sh -ec '
  test "$(stat -c "%u:%g:%a" /run/prism-tls/cache.key)" = "999:999:400"
  test "$(grep "^Uid:" /proc/1/status | tr -s "\t" " " | cut -d " " -f2)" = "999"
'

echo "Lightsail TLS-init and Valkey composition passed"
