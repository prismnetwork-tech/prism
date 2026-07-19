#!/usr/bin/env bash
set -euo pipefail

image=ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

docker run --rm \
  -v "$PWD/deploy/node:/units:ro" \
  "$image" sh -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq systemd >/dev/null
    useradd --system prismd
    install -d /usr/local/sbin /etc/prismd /var/lib/prismd/tls
    printf "#!/bin/sh\nexit 0\n" >/usr/local/sbin/prismd
    chmod 0755 /usr/local/sbin/prismd
    printf "[Unit]\nDescription=containerd stub\n[Service]\nExecStart=/bin/true\n" \
      >/etc/systemd/system/containerd.service
    printf "PRISM_CONTROL_PLANE_URL=https://api.example.invalid/\nPRISM_GATEWAY_ADDRESS=gateway.example.invalid:7443\nPRISM_GATEWAY_SERVER_NAME=gateway.example.invalid\nPRISM_CONNECTION_ID=test\n" \
      >/etc/prismd/node.env
    systemd-analyze verify \
      /units/prismd-certificate.service \
      /units/prismd-certificate.timer \
      /units/prismd-commands.service \
      /units/prismd-tunnel.service
  '

echo "Node systemd units passed Ubuntu 24.04 verification"
