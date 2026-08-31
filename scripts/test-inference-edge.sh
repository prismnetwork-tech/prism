#!/usr/bin/env bash
set -euo pipefail

# The inference gateway binds loopback unless it is handed a credential, and the
# edge reaches it across the compose network. Three things therefore have to
# agree: the address the gateway binds, the credential it then demands, and the
# header the edge puts on the way through. One of them out of step is a 502 or a
# 401 on every paid route, and it only shows up on the live domain.

compose=deploy/ec2/compose.yml
caddyfile=deploy/ec2/Caddyfile
status=0

fail() {
  echo "$1" >&2
  status=1
}

service() {
  awk -v svc="  $1:" '$0 == svc { inside = 1; next } inside && /^  [a-z]/ { inside = 0 } inside' "$compose"
}

inference=$(service inference)
edge=$(service edge)
host=$(awk '/INFERENCE_HOST:/ { print $2 }' <<<"$inference")

if [[ -z $host ]]; then
  fail "$compose: the inference service names no INFERENCE_HOST, so it binds loopback and the edge cannot reach it"
elif [[ $host != "127.0.0.1" && $host != "localhost" && $host != "::1" ]]; then
  grep -q "INFERENCE_TOKEN:" <<<"$inference" ||
    fail "$compose: the gateway binds $host and is given no INFERENCE_TOKEN, so it refuses to start"
fi

routes=$(grep -c "reverse_proxy inference:" "$caddyfile" || true)
guarded=$(grep -A3 "reverse_proxy inference:" "$caddyfile" | grep -c "header_up Authorization" || true)
[[ $routes -gt 0 ]] || fail "$caddyfile: nothing proxies to the inference gateway"
[[ $routes -eq $guarded ]] ||
  fail "$caddyfile: $((routes - guarded)) of $routes inference routes send no Authorization header, so they answer 401"

if grep -q 'PRISM_INFERENCE_TOKEN' "$caddyfile"; then
  grep -q "PRISM_INFERENCE_TOKEN:" <<<"$edge" ||
    fail "$compose: the Caddyfile reads PRISM_INFERENCE_TOKEN and the edge service is never given it"
fi

[[ $status -eq 0 ]] || exit 1
echo "The edge and the inference gateway agree on address and credential"
