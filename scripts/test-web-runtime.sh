#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
standalone="$root/apps/web/.next/standalone"
port="${PRISM_WEB_TEST_PORT:-3211}"
temporary="$(mktemp -d)"
pid=""

cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$temporary"
}
trap cleanup EXIT

if [[ ! -f "$standalone/apps/web/server.js" ]]; then
  printf '%s\n' "Standalone web build is missing. Run pnpm build first."
  exit 1
fi

(
  cd "$standalone"
  HOSTNAME=127.0.0.1 PORT="$port" NODE_ENV=production node apps/web/server.js
) >"$temporary/server.log" 2>&1 &
pid=$!

for _ in {1..40}; do
  if curl --fail --silent "http://127.0.0.1:$port/api/healthz" >"$temporary/health.json"; then
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    cat "$temporary/server.log"
    exit 1
  fi
  sleep 0.25
done

if ! rg --quiet '"status":"ok"' "$temporary/health.json"; then
  cat "$temporary/server.log"
  printf '%s\n' "Web health endpoint did not become ready."
  exit 1
fi

curl --fail --silent --dump-header "$temporary/headers" \
  --output "$temporary/home.html" "http://127.0.0.1:$port/"

nonce="$(sed -nE "s/.*script-src[^;]*'nonce-([^']+)'.*/\\1/p" "$temporary/headers" | tr -d '\r' | head -1)"
if [[ -z "$nonce" ]]; then
  printf '%s\n' "Production CSP does not contain a script nonce."
  exit 1
fi

if ! rg --quiet --fixed-strings "nonce=\"$nonce\"" "$temporary/home.html"; then
  printf '%s\n' "Rendered scripts do not carry the response CSP nonce."
  exit 1
fi

if sed -nE 's/.*(script-src[^;]*).*/\1/p' "$temporary/headers" | rg --quiet "'unsafe-inline'|'unsafe-eval'"; then
  printf '%s\n' "Production script policy permits unsafe execution."
  exit 1
fi

if ! rg --quiet --fixed-strings "GPU compute" "$temporary/home.html"; then
  printf '%s\n' "Homepage did not render expected content."
  exit 1
fi

printf '%s\n' "Web runtime CSP, hydration nonce, health, and render checks passed"
