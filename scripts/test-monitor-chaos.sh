#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
container="prism-monitor-chaos-postgres-$$"
control_pid=
monitor_pid=

cleanup() {
  for pid in "$monitor_pid" "$control_pid"; do
    if [[ -n $pid ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

free_port() {
  node -e '
    const server = require("net").createServer();
    server.listen(0, "127.0.0.1", () => {
      process.stdout.write(String(server.address().port));
      server.close();
    });
  '
}

database_port=$(free_port)
docker run -d --name "$container" \
  -e POSTGRES_DB=prism \
  -e POSTGRES_USER=prism \
  -e POSTGRES_PASSWORD=integration-secret \
  -p "127.0.0.1:$database_port:5432" \
  postgres:17-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394 \
  >/dev/null
for _ in $(seq 1 30); do
  docker exec "$container" pg_isready -U prism -d prism >/dev/null 2>&1 && break
  sleep 1
done
database_url="postgres://prism:integration-secret@127.0.0.1:$database_port/prism"
control_port=$(free_port)
monitor_port=$(free_port)

env \
  DATABASE_URL="$database_url" \
  PRISM_ALLOW_DEVELOPMENT_AUTH=1 \
  PRISM_ALLOW_DEVELOPMENT_CHAIN=1 \
  PRISM_ALLOW_DEVELOPMENT_REGISTRY=1 \
  PRISM_CONTROL_PLANE_ADDR="127.0.0.1:$control_port" \
  PRISM_GATEWAY_OBSERVER_TOKEN=0123456789abcdef0123456789abcdef \
  target/debug/prism-control-plane >"$root/control.log" 2>&1 &
control_pid=$!
for _ in $(seq 1 50); do
  curl --fail --silent "http://127.0.0.1:$control_port/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl --fail --silent "http://127.0.0.1:$control_port/healthz" >/dev/null

env \
  DATABASE_URL="$database_url" \
  PRISM_OPERATIONS_MONITOR_ADDR="127.0.0.1:$monitor_port" \
  target/debug/prism-operations-monitor >"$root/monitor.log" 2>&1 &
monitor_pid=$!
for _ in $(seq 1 50); do
  curl --fail --silent "http://127.0.0.1:$monitor_port/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl --fail --silent "http://127.0.0.1:$monitor_port/metrics" | grep -q "prism_active_leases 0"

docker stop "$container" >/dev/null
for _ in $(seq 1 50); do
  status=$(curl --max-time 3 --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$monitor_port/healthz" || true)
  [[ $status == 503 ]] && break
  sleep 0.1
done
[[ $status == 503 ]]

docker start "$container" >/dev/null
for _ in $(seq 1 100); do
  if curl --max-time 6 --fail --silent "http://127.0.0.1:$monitor_port/metrics" | grep -q "prism_active_leases 0"; then
    echo "Operations monitor database recovery passed"
    exit 0
  fi
  sleep 0.1
done

cat "$root/monitor.log" >&2
exit 1
