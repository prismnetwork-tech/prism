#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
pids=()

cleanup() {
  local status="$?"
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${pids[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      if [[ -f "$log" ]]; then
        printf '\n%s\n' "== $(basename "$log") ==" >&2
        tail -100 "$log" >&2
      fi
    done
  fi
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&-
      exec 3<&-
      return
    fi
    sleep 0.1
  done
  return 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$work/ca.key" -out "$work/ca.crt" -subj "/CN=Prism test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$work/server.key" -out "$work/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
printf '%s\n' "subjectAltName=DNS:localhost,IP:127.0.0.1" "extendedKeyUsage=serverAuth" >"$work/server.ext"
openssl x509 -req -days 1 -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -out "$work/server.crt" -extfile "$work/server.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$work/node.key" -out "$work/node.csr" -subj "/CN=test-node" >/dev/null 2>&1
printf '%s\n' "extendedKeyUsage=clientAuth" >"$work/node.ext"
openssl x509 -req -days 1 -in "$work/node.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
  -CAcreateserial -out "$work/node.crt" -extfile "$work/node.ext" >/dev/null 2>&1

cargo build --quiet --manifest-path "$root/Cargo.toml" \
  -p prism-access-gateway -p prismd
node_id="$("$root/target/debug/prismd" create-identity --path "$work/device.json")"

node -e '
  const net = require("net");
  net.createServer((socket) => socket.pipe(socket)).listen(12222, "127.0.0.1");
  net.createServer((socket) => socket.pipe(socket)).listen(18888, "127.0.0.1");
' >"$work/echo.log" 2>&1 &
pids+=("$!")

PRISM_GATEWAY_HMAC_KEY="$(printf '11%.0s' {1..32})" \
PRISM_GATEWAY_CONTROL_TOKEN="$(printf 'control-token-%.0s' {1..4})" \
PRISM_ALLOW_DEVELOPMENT_GRANT_STORE=1 \
PRISM_GATEWAY_ADDR=127.0.0.1:18081 \
PRISM_ENABLE_TUNNEL=1 \
PRISM_TUNNEL_ADDR=127.0.0.1:17443 \
PRISM_RELAY_ADDR=127.0.0.1:17444 \
PRISM_TUNNEL_SERVER_CERTIFICATE="$work/server.crt" \
PRISM_TUNNEL_SERVER_KEY="$work/server.key" \
PRISM_TUNNEL_CLIENT_CA="$work/ca.crt" \
  "$root/target/debug/prism-access-gateway" >"$work/gateway.log" 2>&1 &
pids+=("$!")
wait_for_port 18081
wait_for_port 17443
wait_for_port 17444

control_token="$(printf 'control-token-%.0s' {1..4})"
grant="$(
  curl --fail --silent --show-error \
    -H "Authorization: Bearer $control_token" \
    -H "Content-Type: application/json" \
    -d "{\"token_id\":\"018f0000-0000-7000-8000-000000000001\",\"lease_id\":\"lease-1\",\"node_id\":\"$node_id\",\"connection_id\":\"connection-1\",\"ttl_seconds\":300}" \
    http://127.0.0.1:18081/v1/grants
)"
access_token="$(printf '%s' "$grant" | node -e '
  let input = "";
  process.stdin.on("data", (chunk) => input += chunk);
  process.stdin.on("end", () => process.stdout.write(JSON.parse(input).token));
')"

"$root/target/debug/prismd" tunnel \
  --identity "$work/device.json" \
  --gateway 127.0.0.1:17443 \
  --server-name localhost \
  --ca-certificate "$work/ca.crt" \
  --client-certificate "$work/node.crt" \
  --client-key "$work/node.key" \
  --connection-id connection-1 \
  --ssh-target 127.0.0.1:12222 \
  --jupyter-target 127.0.0.1:18888 \
  --slots 32 >"$work/node.log" 2>&1 &
pids+=("$!")

for _ in $(seq 1 50); do
  if curl --fail --silent --show-error \
    -H "Authorization: Bearer $control_token" \
    -H "Content-Type: application/json" \
    -d "{\"node_id\":\"$node_id\",\"connection_id\":\"connection-1\"}" \
    http://127.0.0.1:18081/v1/probes >"$work/probe.json" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
node -e '
  const probe = require(process.argv[1]);
  if (probe.node_id !== process.argv[2] || probe.connection_id !== "connection-1") {
    process.exit(1);
  }
  if (!probe.cuda_ready_at || !probe.interactive_access_ready_at) {
    process.exit(1);
  }
' "$work/probe.json" "$node_id"

"$root/target/debug/prismd" relay \
  --gateway 127.0.0.1:17444 \
  --server-name localhost \
  --ca-certificate "$work/ca.crt" \
  --token "$access_token" \
  --service ssh \
  --listen 127.0.0.1:19000 >"$work/relay.log" 2>&1 &
pids+=("$!")
wait_for_port 19000
sleep 0.5

node -e '
  const net = require("net");
  const expected = "prism-tunnel-e2e";
  const socket = net.connect(19000, "127.0.0.1", () => socket.write(expected));
  socket.setTimeout(5000);
  socket.once("data", (data) => {
    if (data.toString() !== expected) process.exit(1);
    socket.end();
  });
  socket.once("timeout", () => process.exit(1));
  socket.once("error", () => process.exit(1));
'

node -e '
  const net = require("net");
  const sessions = Array.from({ length: 25 }, (_, index) => new Promise((resolve, reject) => {
    const expected = `fanout-${index}`;
    const socket = net.connect(19000, "127.0.0.1", () => socket.write(expected));
    socket.setTimeout(5000);
    socket.once("data", (data) => {
      if (data.toString() !== expected) {
        reject(new Error(`relay ${index} returned corrupt data`));
        socket.destroy();
        return;
      }
      socket.destroy();
      resolve();
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error(`relay ${index} timed out`));
    });
    socket.once("error", reject);
  }));
  Promise.all(sessions).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
'

READY_FILE="$work/active-ready" node -e '
  const fs = require("fs");
  const net = require("net");
  const socket = net.connect(19000, "127.0.0.1", () => socket.write("active-session"));
  socket.setTimeout(5000);
  socket.once("data", () => {
    fs.writeFileSync(process.env.READY_FILE, "ready");
    socket.setTimeout(5000);
  });
  socket.once("close", () => process.exit(fs.existsSync(process.env.READY_FILE) ? 0 : 1));
  socket.once("timeout", () => process.exit(1));
  socket.once("error", () => process.exit(1));
' &
active_client_pid="$!"
pids+=("$active_client_pid")
for _ in $(seq 1 50); do
  [[ -f "$work/active-ready" ]] && break
  sleep 0.1
done
[[ -f "$work/active-ready" ]]

token_id="$(printf '%s' "$grant" | node -e '
  let input = "";
  process.stdin.on("data", (chunk) => input += chunk);
  process.stdin.on("end", () => process.stdout.write(JSON.parse(input).grant.token_id));
')"
curl --fail --silent --show-error -X DELETE \
  -H "Authorization: Bearer $control_token" \
  "http://127.0.0.1:18081/v1/grants/$token_id" >/dev/null
wait "$active_client_pid"

if node -e '
  const net = require("net");
  const socket = net.connect(19000, "127.0.0.1", () => socket.write("must-fail"));
  socket.setTimeout(1500);
  socket.once("data", () => process.exit(1));
  socket.once("close", () => process.exit(0));
  socket.once("timeout", () => process.exit(0));
  socket.once("error", () => process.exit(0));
'; then
  printf '%s\n' "tunnel e2e passed"
else
  printf '%s\n' "revoked token unexpectedly reached the node" >&2
  exit 1
fi
