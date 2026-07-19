#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <gateway-hostname> [output-directory]" >&2
  exit 64
fi

hostname=$1
output=${2:-deploy/lightsail/secrets/tls}

if [[ ! $hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || [[ $hostname != *.* ]]; then
  echo "gateway hostname must be a fully qualified DNS name" >&2
  exit 64
fi
if [[ -e $output ]]; then
  echo "refusing to replace existing TLS material at $output" >&2
  exit 73
fi

umask 077
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$temporary/ca.key"
openssl req -x509 -new -sha256 -days 3650 \
  -key "$temporary/ca.key" \
  -subj "/CN=Prism Network private CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$temporary/ca.crt"

issue_certificate() {
  local name=$1
  local common_name=$2
  local extended_usage=$3
  local subject_alt_name=$4

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$temporary/$name.key"
  openssl req -new -sha256 \
    -key "$temporary/$name.key" \
    -subj "/CN=$common_name" \
    -out "$temporary/$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyAgreement"
    echo "extendedKeyUsage=$extended_usage"
    echo "subjectAltName=$subject_alt_name"
  } > "$temporary/$name.ext"
  openssl x509 -req -sha256 -days 397 \
    -in "$temporary/$name.csr" \
    -CA "$temporary/ca.crt" \
    -CAkey "$temporary/ca.key" \
    -CAcreateserial \
    -extfile "$temporary/$name.ext" \
    -out "$temporary/$name.crt"
}

issue_certificate server "$hostname" serverAuth "DNS:$hostname"
issue_certificate cache cache serverAuth "DNS:cache"
issue_certificate node-client prism-node-bootstrap clientAuth "URI:spiffe://prism.network/node/bootstrap"

mkdir -p "$output"
install -m 0600 "$temporary/ca.key" "$output/ca.key"
install -m 0644 "$temporary/ca.crt" "$output/ca.crt"
install -m 0600 "$temporary/server.key" "$output/server.key"
install -m 0644 "$temporary/server.crt" "$output/server.crt"
install -m 0600 "$temporary/cache.key" "$output/cache.key"
install -m 0644 "$temporary/cache.crt" "$output/cache.crt"
install -m 0600 "$temporary/node-client.key" "$output/node-client.key"
install -m 0644 "$temporary/node-client.crt" "$output/node-client.crt"

echo "TLS material written to $output"
echo "Distribute ca.crt and per-node client credentials through a private channel."
