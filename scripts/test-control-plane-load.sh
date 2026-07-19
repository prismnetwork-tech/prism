#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
control_pid=

cleanup() {
  if [[ -n $control_pid ]]; then
    kill "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

port=$(node -e '
  const server = require("net").createServer();
  server.listen(0, "127.0.0.1", () => {
    process.stdout.write(String(server.address().port));
    server.close();
  });
')

env \
  PRISM_ALLOW_DEVELOPMENT_AUTH=1 \
  PRISM_ALLOW_DEVELOPMENT_CHAIN=1 \
  PRISM_ALLOW_DEVELOPMENT_REGISTRY=1 \
  PRISM_ALLOW_DEVELOPMENT_STORE=1 \
  PRISM_CONTROL_PLANE_ADDR="127.0.0.1:$port" \
  target/debug/prism-control-plane >"$root/control-plane.log" 2>&1 &
control_pid=$!

for _ in $(seq 1 50); do
  if curl --fail --silent "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$control_pid" 2>/dev/null; then
    cat "$root/control-plane.log" >&2
    exit 1
  fi
  sleep 0.1
done

node scripts/load-http.mjs "http://127.0.0.1:$port/healthz" 1000 25 1000
node scripts/load-http.mjs "http://127.0.0.1:$port/v1/offers" 1000 25 1000

echo "Control-plane HTTP load smoke passed"
