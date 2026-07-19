#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

./scripts/generate-lightsail-tls.sh tunnel.example.invalid "$root/tls" >/dev/null 2>&1
openssl verify -CAfile "$root/tls/ca.crt" \
  "$root/tls/server.crt" \
  "$root/tls/cache.crt" \
  "$root/tls/node-client.crt"

openssl x509 -in "$root/tls/server.crt" -noout -text | grep -q "DNS:tunnel.example.invalid"
openssl x509 -in "$root/tls/cache.crt" -noout -text | grep -q "DNS:cache"
openssl x509 -in "$root/tls/node-client.crt" -noout -text | grep -q "TLS Web Client Authentication"

[[ $(stat -f '%Lp' "$root/tls/ca.key" 2>/dev/null || stat -c '%a' "$root/tls/ca.key") == 600 ]]
[[ $(stat -f '%Lp' "$root/tls/server.key" 2>/dev/null || stat -c '%a' "$root/tls/server.key") == 600 ]]

echo "Lightsail TLS generation passed"
