#!/usr/bin/env bash
set -euo pipefail

# Both bootstraps, run in the same container harness. The GPU is a stub in this
# image, so the coverage here is the SSH, Jupyter and unprivileged-account flow.
# Whether the container toolkit puts a real card in front of the shared script
# is a question only a machine with one can answer.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/output"
temporary=$(mktemp -d "$root/output/workspace-bootstrap.XXXXXX")
containers=()

cleanup() {
  for container in "${containers[@]:-}"; do
    [ -n "$container" ] && docker rm -f "$container" >/dev/null 2>&1 || true
  done
  rm -rf "$temporary"
}
trap cleanup EXIT

docker build \
  --quiet \
  --file "$root/node/prismd/test-image/Dockerfile" \
  --tag prism-workspace-test:local \
  "$root/node/prismd/test-image" >/dev/null

run_bootstrap() {
  local label="$1"
  local bootstrap="$2"
  local container="prism-workspace-test-$label-$$"
  local work="$temporary/$label"

  containers+=("$container")
  install -d -m 0700 "$work" "$work/control"
  ssh-keygen -q -t ed25519 -N "" -f "$work/id_ed25519"
  cp "$work/id_ed25519.pub" "$work/control/authorized_keys"
  cp "$bootstrap" "$work/control/bootstrap.sh"
  local token
  token=$(openssl rand -hex 32)
  printf '%s\n' "$token" >"$work/control/jupyter_token"
  printf 'ready\n' >"$work/control/network-ready"
  chmod 0400 "$work/control/"*

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
    --mount "type=bind,src=$work/control,dst=/run/prism/control,readonly" \
    --publish 127.0.0.1::2222 \
    --publish 127.0.0.1::8888 \
    --entrypoint /bin/sh \
    prism-workspace-test:local \
    /run/prism/control/bootstrap.sh >/dev/null

  local ssh_port jupyter_port
  ssh_port=$(docker port "$container" 2222/tcp | sed 's/.*://')
  jupyter_port=$(docker port "$container" 8888/tcp | sed 's/.*://')

  for _ in $(seq 1 120); do
    if ssh -q \
      -i "$work/id_ed25519" \
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
    -i "$work/id_ed25519" \
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
    -i "$work/id_ed25519" \
    -p "$ssh_port" \
    -o BatchMode=yes \
    -o ConnectTimeout=2 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    root@127.0.0.1 true 2>/dev/null; then
    echo "$label workspace bootstrap allowed root SSH" >&2
    exit 1
  fi

  echo "$label workspace SSH and Jupyter bootstrap integration passed"
}

run_bootstrap passthrough "$root/node/prismd/assets/workspace-bootstrap.sh"
run_bootstrap shared "$root/node/prismd/assets/workspace-bootstrap-shared.sh"

# A shared lease can produce no guest report, so a challenge left in the control
# directory has to end the lease rather than serve a session nothing covers.
refusal="$temporary/refusal"
install -d -m 0700 "$refusal" "$refusal/control"
ssh-keygen -q -t ed25519 -N "" -f "$refusal/id_ed25519"
cp "$refusal/id_ed25519.pub" "$refusal/control/authorized_keys"
cp "$root/node/prismd/assets/workspace-bootstrap-shared.sh" "$refusal/control/bootstrap.sh"
openssl rand -hex 32 >"$refusal/control/jupyter_token"
printf 'ready\n' >"$refusal/control/network-ready"
printf '%s\n' "$(printf 'b%.0s' $(seq 1 64))" >"$refusal/control/attestation_challenge"
chmod 0400 "$refusal/control/"*

if docker run --rm \
  --read-only \
  --user 0:0 \
  --tmpfs /run:rw,nosuid,nodev,mode=0755 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777 \
  --tmpfs /workspace:rw,nosuid,nodev,mode=0700 \
  --mount "type=bind,src=$refusal/control,dst=/run/prism/control,readonly" \
  --entrypoint /bin/sh \
  prism-workspace-test:local \
  /run/prism/control/bootstrap.sh >/dev/null 2>&1; then
  echo "the shared bootstrap served a lease that asked for a guest report" >&2
  exit 1
fi

echo "the shared bootstrap refuses a lease that asked for a guest report"
