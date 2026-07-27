#!/usr/bin/env bash
# Issue the gateway tunnel and cache leaf certificates from an existing private
# CA. Unlike generate-lightsail-tls.sh this never creates a CA: the control
# plane signs node client certificates with the CA already in the deployment,
# and the tunnel authenticates those clients, so rotating it would lock out
# every enrolled node.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <gateway-hostname> [tls-directory]" >&2
  exit 64
fi

hostname=$1
output=${2:-deploy/ec2/secrets/tls}

if [[ ! $hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || [[ $hostname != *.* ]]; then
  echo "gateway hostname must be a fully qualified DNS name" >&2
  exit 64
fi
if [[ ! -f $output/ca.crt || ! -f $output/ca.key ]]; then
  echo "no certificate authority at $output; this script issues from an existing CA" >&2
  exit 66
fi
for leaf in server cache; do
  if [[ -e $output/$leaf.crt || -e $output/$leaf.key ]]; then
    echo "refusing to replace existing $leaf material in $output" >&2
    exit 73
  fi
done

umask 077
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

issue_certificate() {
  local name=$1
  local common_name=$2
  local subject_alt_name=$3

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$temporary/$name.key"
  openssl req -new -sha256 \
    -key "$temporary/$name.key" \
    -subj "/CN=$common_name" \
    -out "$temporary/$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyAgreement"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=$subject_alt_name"
  } > "$temporary/$name.ext"
  openssl x509 -req -sha256 -days 397 \
    -in "$temporary/$name.csr" \
    -CA "$output/ca.crt" \
    -CAkey "$output/ca.key" \
    -CAcreateserial \
    -extfile "$temporary/$name.ext" \
    -out "$temporary/$name.crt"
}

issue_certificate server "$hostname" "DNS:$hostname"
issue_certificate cache cache "DNS:cache"

install -m 0644 "$temporary/server.crt" "$output/server.crt"
install -m 0600 "$temporary/server.key" "$output/server.key"
install -m 0644 "$temporary/cache.crt" "$output/cache.crt"
install -m 0600 "$temporary/cache.key" "$output/cache.key"

echo "Issued server and cache certificates in $output"
echo "Nodes must trust ca.crt and reach the tunnel as $hostname."
