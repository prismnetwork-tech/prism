#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/output"
temporary=$(mktemp -d "$root/output/workspace-bootstrap.XXXXXX")
container="prism-workspace-test-$$"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$temporary"
}
trap cleanup EXIT

install -d -m 0700 "$temporary/control"
ssh-keygen -q -t ed25519 -N "" -f "$temporary/id_ed25519"
cp "$temporary/id_ed25519.pub" "$temporary/control/authorized_keys"
cp "$root/node/prismd/assets/workspace-bootstrap.sh" "$temporary/control/bootstrap.sh"
token=$(openssl rand -hex 32)
printf '%s\n' "$token" >"$temporary/control/jupyter_token"
printf 'ready\n' >"$temporary/control/network-ready"
chmod 0400 "$temporary/control/"*

docker build \
  --quiet \
  --file "$root/node/prismd/test-image/Dockerfile" \
  --tag prism-workspace-test:local \
  "$root/node/prismd/test-image" >/dev/null

docker run --detach \
  --name "$container" \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add KILL \
  --cap-add SETGID \
  --cap-add SETUID \
  --cap-add SYS_CHROOT \
  --pids-limit 2048 \
  --user 0:0 \
  --tmpfs /run:rw,nosuid,nodev,mode=0755 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 \
  --tmpfs /workspace:rw,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$temporary/control,dst=/run/prism/control,readonly" \
  --publish 127.0.0.1::2222 \
  --publish 127.0.0.1::8888 \
  --entrypoint /bin/sh \
  prism-workspace-test:local \
  /run/prism/control/bootstrap.sh >/dev/null

ssh_port=$(docker port "$container" 2222/tcp | sed 's/.*://')
jupyter_port=$(docker port "$container" 8888/tcp | sed 's/.*://')

for _ in $(seq 1 120); do
  if ssh -q \
    -i "$temporary/id_ed25519" \
    -p "$ssh_port" \
    -o BatchMode=yes \
    -o ConnectTimeout=1 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    workspace@127.0.0.1 \
    "test \$(id -u) -eq 1000" 2>/dev/null \
    && curl --fail --silent \
      "http://127.0.0.1:$jupyter_port/lab?token=$token" >/dev/null 2>&1; then
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]; then
    docker logs "$container" >&2 || true
    exit 1
  fi
  sleep 1
done

ssh -q \
  -i "$temporary/id_ed25519" \
  -p "$ssh_port" \
  -o BatchMode=yes \
  -o ConnectTimeout=2 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  workspace@127.0.0.1 \
  "test \$(id -u) -eq 1000"
curl --fail --silent --show-error \
  "http://127.0.0.1:$jupyter_port/lab?token=$token" >/dev/null

if ssh -q \
  -i "$temporary/id_ed25519" \
  -p "$ssh_port" \
  -o BatchMode=yes \
  -o ConnectTimeout=2 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  root@127.0.0.1 true 2>/dev/null; then
  echo "workspace bootstrap allowed root SSH" >&2
  exit 1
fi

echo "workspace SSH and Jupyter bootstrap integration passed"
