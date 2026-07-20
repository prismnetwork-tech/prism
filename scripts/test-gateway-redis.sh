#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null
command -v curl >/dev/null

mkdir -p output
root=$(mktemp -d "$PWD/output/gateway-redis.XXXXXX")
chmod 0755 "$root"
container="prism-valkey-test-$$"
gateway_pid=
port=
control_token=0123456789abcdef0123456789abcdef
hmac_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

cleanup() {
  if [[ -n $gateway_pid ]]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$root/ca.key" 2>/dev/null
openssl req -x509 -new -sha256 -days 1 \
  -key "$root/ca.key" \
  -subj "/CN=Prism test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$root/ca.crt" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$root/cache.key" 2>/dev/null
openssl req -new -sha256 \
  -key "$root/cache.key" -subj "/CN=localhost" -out "$root/cache.csr" 2>/dev/null
{
  echo "basicConstraints=critical,CA:FALSE"
  echo "keyUsage=critical,digitalSignature,keyAgreement"
  echo "extendedKeyUsage=serverAuth"
  echo "subjectAltName=DNS:localhost,IP:127.0.0.1"
} > "$root/cache.ext"
openssl x509 -req -sha256 -days 1 \
  -in "$root/cache.csr" \
  -CA "$root/ca.crt" \
  -CAkey "$root/ca.key" \
  -CAcreateserial \
  -extfile "$root/cache.ext" \
  -out "$root/cache.crt" 2>/dev/null
chmod 0644 "$root/ca.crt" "$root/cache.crt"
chmod 0644 "$root/cache.key"

redis_port=$(node -e '
  const server = require("net").createServer();
  server.listen(0, "127.0.0.1", () => {
    process.stdout.write(String(server.address().port));
    server.close();
  });
')
docker run -d --name "$container" \
  -p "127.0.0.1:$redis_port:6379" \
  -v "$root:/tls:ro" \
  valkey/valkey:8-bookworm@sha256:fea8b3e67b15729d4bb70589eb03367bab9ad1ee89c876f54327fc7c6e618571 \
  valkey-server \
  --port 0 \
  --tls-port 6379 \
  --tls-cert-file /tls/cache.crt \
  --tls-key-file /tls/cache.key \
  --tls-ca-cert-file /tls/ca.crt \
  --tls-auth-clients no \
  --requirepass integration-secret >/dev/null
ready=0
for _ in $(seq 1 30); do
  if docker logs "$container" 2>&1 | grep -q "Ready to accept connections tls"; then
    ready=1
    break
  fi
  sleep 1
done
if [[ $ready != 1 ]]; then
  docker logs "$container" >&2
  exit 1
fi

start_gateway() {
  port=$(node -e '
    const server = require("net").createServer();
    server.listen(0, "127.0.0.1", () => {
      process.stdout.write(String(server.address().port));
      server.close();
    });
  ')
  env \
    PRISM_GATEWAY_ADDR="127.0.0.1:$port" \
    PRISM_GATEWAY_CONTROL_TOKEN="$control_token" \
    PRISM_GATEWAY_HMAC_KEY="$hmac_key" \
    PRISM_REDIS_URL="rediss://:integration-secret@localhost:$redis_port/0" \
    PRISM_REDIS_CA_FILE="$root/ca.crt" \
    target/debug/prism-access-gateway >"$root/gateway.log" 2>&1 &
  gateway_pid=$!
  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$gateway_pid" 2>/dev/null; then
      cat "$root/gateway.log" >&2
      return 1
    fi
    sleep 1
  done
  cat "$root/gateway.log" >&2
  return 1
}

start_gateway
grant=$(curl --fail --silent \
  -H "Authorization: Bearer $control_token" \
  -H "Content-Type: application/json" \
  -d "{\"token_id\":\"018f0000-0000-7000-8000-000000000002\",\"lease_id\":\"lease-integration\",\"node_id\":\"0x$(printf 'a%.0s' {1..64})\",\"connection_id\":\"tunnel-integration\",\"ttl_seconds\":300}" \
  "http://127.0.0.1:$port/v1/grants")
token=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).token)' "$grant")
token_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).grant.token_id)' "$grant")

curl --fail --silent \
  -H "Authorization: Bearer $token" \
  "http://127.0.0.1:$port/v1/access" >/dev/null

kill "$gateway_pid"
wait "$gateway_pid" 2>/dev/null || true
gateway_pid=
start_gateway

curl --fail --silent \
  -H "Authorization: Bearer $token" \
  "http://127.0.0.1:$port/v1/access" >/dev/null
curl --fail --silent \
  -H "Authorization: Bearer $control_token" \
  -X DELETE "http://127.0.0.1:$port/v1/grants/$token_id" >/dev/null

revoked_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer $token" \
  "http://127.0.0.1:$port/v1/access")
[[ $revoked_status == 401 ]]

echo "access-gateway Valkey TLS integration passed"
