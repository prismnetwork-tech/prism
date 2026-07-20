#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

./scripts/generate-lightsail-tls.sh tunnel.example.invalid "$root/tls" >/dev/null 2>&1
openssl verify -CAfile "$root/tls/ca.crt" \
  "$root/tls/server.crt" \
  "$root/tls/cache.crt" \
  "$root/tls/node-client.crt"

openssl x509 -in "$root/tls/server.crt" -noout -text |
  grep -F "DNS:tunnel.example.invalid" >/dev/null
openssl x509 -in "$root/tls/cache.crt" -noout -text |
  grep -F "DNS:cache" >/dev/null
openssl x509 -in "$root/tls/node-client.crt" -noout -text |
  grep -F "TLS Web Client Authentication" >/dev/null

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

[[ $(file_mode "$root/tls/ca.key") == 600 ]]
[[ $(file_mode "$root/tls/server.key") == 600 ]]

echo "Lightsail TLS generation passed"
