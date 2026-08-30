#!/usr/bin/env bash
set -euo pipefail

project="prism-lightsail-test-$$"
secrets=deploy/lightsail/secrets/tls
proof_fixture=$(mktemp -d "$PWD/.prism-proof-serve.XXXXXX")
caddy_container="prism-proof-caddy-$$"
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
  docker rm -f "$caddy_container" >/dev/null 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$proof_fixture"
  rm -rf deploy/lightsail/secrets
}
trap cleanup EXIT

./scripts/generate-lightsail-tls.sh tunnel.example.invalid "$secrets" >/dev/null 2>&1
"${compose[@]}" config --quiet
"${compose[@]}" --profile workers config --format json | node -e '
let input = "";
process.stdin.on("data", (chunk) => input += chunk);
process.stdin.on("end", () => {
  const config = JSON.parse(input);
  const edge = config.services.edge;
  const worker = config.services["proof-worker"];
  const init = config.services["proof-init"];
  const edgeProof = edge.volumes.find((volume) => volume.target === "/srv/proof");
  const workerProof = worker.volumes.find((volume) => volume.target === "/var/lib/prism-proof");
  const initProof = init.volumes.find((volume) => volume.target === "/var/lib/prism-proof");
  if (!edgeProof || !workerProof || !initProof) throw new Error("proof volume mount is missing");
  if (edgeProof.source !== workerProof.source || edgeProof.source !== initProof.source) {
    throw new Error("Caddy and proof services do not share one artifact volume");
  }
  if (!edgeProof.read_only || workerProof.read_only || initProof.read_only) {
    throw new Error("proof volume read/write modes are unsafe");
  }
  if (worker.environment.PRISM_PROOF_ARTIFACT_DIR !== "/var/lib/prism-proof") {
    throw new Error("proof worker artifact root does not match its mounted volume");
  }
  if (worker.environment.PRISM_ENABLE_X_DIGEST_POSTING !== "0") {
    throw new Error("X digest posting is not disabled by default");
  }
});
'
docker run --rm \
  -e PRISM_DOMAIN=example.invalid \
  -e PRISM_ACME_EMAIL=operations@example.invalid \
  -v "$PWD/deploy/lightsail/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.10-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
  caddy validate --config /etc/caddy/Caddyfile >/dev/null
grep -A6 '@proof_pages path' deploy/lightsail/Caddyfile | grep -F 'max-age=30' >/dev/null
grep -A6 '@proof_receipts path' deploy/lightsail/Caddyfile \
  | grep -F 'max-age=30' >/dev/null
grep -A6 '@proof_sets path' deploy/lightsail/Caddyfile \
  | grep -F 'max-age=31536000, immutable' >/dev/null

mkdir -p \
  "$proof_fixture/pages" \
  "$proof_fixture/receipts" \
  "$proof_fixture/sets/example/pages"
chmod 0755 "$proof_fixture"
printf '%s' '{"kind":"index"}' >"$proof_fixture/index.json"
printf '%s' '{"kind":"page"}' >"$proof_fixture/pages/1.json"
printf '%s' '{"kind":"receipt"}' >"$proof_fixture/receipts/example.json"
printf '%s' '{"kind":"set"}' >"$proof_fixture/sets/example/pages/1.json"
docker run -d --name "$caddy_container" \
  --read-only \
  --tmpfs /config \
  --tmpfs /data \
  -p 127.0.0.1::80 \
  -e PRISM_DOMAIN=:80 \
  -e PRISM_ACME_EMAIL=operations@example.invalid \
  -v "$PWD/deploy/lightsail/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$proof_fixture:/srv/proof:ro" \
  caddy:2.10-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
  caddy run --config /etc/caddy/Caddyfile >/dev/null
proof_port=$(docker port "$caddy_container" 80/tcp | sed -n 's/^127\.0\.0\.1://p')
proof_base="http://127.0.0.1:$proof_port"
proof_ready=0
for _ in $(seq 1 30); do
  if curl --fail --silent "$proof_base/proof-artifacts/index.json" >/dev/null 2>&1; then
    proof_ready=1
    break
  fi
  sleep 1
done
if [[ $proof_ready != 1 ]]; then
  docker logs "$caddy_container" >&2
  exit 1
fi

assert_body() {
  local path=$1 expected=$2 actual
  actual=$(curl --fail --silent "$proof_base$path")
  [[ $actual == "$expected" ]]
}

assert_body /proof-artifacts/index.json '{"kind":"index"}'
assert_body /proof-artifacts/pages/1.json '{"kind":"page"}'
assert_body /proof-artifacts/receipts/example.json '{"kind":"receipt"}'
assert_body /proof-artifacts/sets/example/pages/1.json '{"kind":"set"}'
curl --fail --silent --head "$proof_base/proof-artifacts/index.json" \
  | tr -d '\r' | grep -i '^Cache-Control: no-cache$' >/dev/null
curl --fail --silent --head "$proof_base/proof-artifacts/pages/1.json" \
  | tr -d '\r' | grep -i '^Cache-Control: public, max-age=30$' >/dev/null
curl --fail --silent --head "$proof_base/proof-artifacts/receipts/example.json" \
  | tr -d '\r' | grep -i '^Cache-Control: public, max-age=30$' >/dev/null
curl --fail --silent --head "$proof_base/proof-artifacts/sets/example/pages/1.json" \
  | tr -d '\r' | grep -i '^Cache-Control: public, max-age=31536000, immutable$' >/dev/null

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

node <<'NODE'
const { readFileSync } = require("node:fs");

const doc = readFileSync("deploy/lightsail/README.md", "utf8");
const upgrade = doc.split("## Upgrade an existing deployment\n", 2)[1]
  ?.split("\nInspect health and logs:", 1)[0];
if (!upgrade) throw new Error("Lightsail upgrade procedure is missing");

const steps = [
  "stop -t 180 control-plane lifecycle-worker repro-worker settlement-worker proof-worker",
  "PRISM_RUN_MIGRATIONS_ONLY=1 control-plane",
  "install `operator_maintenance` under advisory lock `4663`",
  "drain the historical generation and then the current generation",
  "settlement-worker repro-worker proof-worker",
  "up -d --no-deps --pull never control-plane",
];
let cursor = -1;
for (const step of steps) {
  const next = upgrade.indexOf(step, cursor + 1);
  if (next < 0) throw new Error(`Lightsail upgrade procedure is missing: ${step}`);
  if (next <= cursor) throw new Error(`Lightsail upgrade procedure is out of order: ${step}`);
  cursor = next;
}
NODE

echo "Lightsail proof serving, TLS-init and Valkey composition passed"
