#!/usr/bin/env bash
set -euo pipefail

# The stop handshake, end to end, against a fake miner and a stub driver. No GPU
# is needed and none is used. The daemon has to read the driver the way it says
# it does, take the whole process group down, and hold the lease back when the
# card does not come free.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [ ! -d /run/lock ]; then
  echo "this host has no /run/lock, so the reservation the handshake takes cannot be written; skipping" >&2
  exit 0
fi
if ! mkdir -p /run/lock/prismd 2>/dev/null; then
  echo "cannot write /run/lock/prismd; run this as root or as a user that can; skipping" >&2
  exit 0
fi

runner=$(id -un)
[ "$(id -u)" -eq 0 ] && runner=nobody
if ! setpriv \
  --reuid "$(id -u "$runner")" \
  --regid "$(id -g "$runner")" \
  --init-groups \
  --inh-caps=-all \
  --no-new-privs \
  -- true >/dev/null 2>&1; then
  echo "setpriv cannot start a process as $runner here; skipping" >&2
  exit 0
fi

mkdir -p "$root/output"
temporary=$(mktemp -d "$root/output/idle-command.XXXXXX")
chmod 0777 "$temporary"
# The workload's own directory is the one above. This is where the daemon writes
# for itself, and the daemon is what creates it.
daemon_state="$temporary/idle-state"
cleanup() {
  [ -f "$temporary/miner.pid" ] && kill -9 "-$(cat "$temporary/miner.pid")" 2>/dev/null || true
  rm -rf "$temporary"
}
trap cleanup EXIT

cargo build --quiet --offline -p prismd
prismd="${CARGO_TARGET_DIR:-$root/target}/debug/prismd"
uuid=GPU-00000000-0000-0000-0000-00000000beef

cat >"$temporary/nvidia-smi" <<EOF
#!/bin/sh
state="$temporary"
uuid="$uuid"
case "\$*" in
  *query-compute-apps*)
    case "\$(cat "\$state/mode")" in
      free) exit 0 ;;
      busy) printf '%s, 4321, 512 MiB\n' "\$uuid" ;;
      broken) echo 'Unable to determine the device handle' >&2; exit 9 ;;
      follow)
        pid=\$(cat "\$state/miner.pid" 2>/dev/null || echo 0)
        if [ "\$pid" -gt 0 ] && kill -0 "\$pid" 2>/dev/null; then
          printf '%s, %s, 512 MiB\n' "\$uuid" "\$pid"
        fi
        ;;
    esac
    ;;
  *query-gpu=index*) printf '0, %s, NVIDIA Test Card, 24564\n' "\$uuid" ;;
  *query-gpu=driver_version*) printf '580.65.06\n' ;;
  *) exit 0 ;;
esac
EOF
chmod 0755 "$temporary/nvidia-smi"

# The daemon asks for lease containers before it starts anything of its own.
# There is no containerd here, and an answer nobody can read counts as a lease.
cat >"$temporary/nerdctl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$temporary/nerdctl"
export PATH="$temporary:$PATH"

write_miner() {
  cat >"$temporary/miner.sh" <<EOF
#!/bin/sh
$1
echo \$\$ >"$temporary/miner.pid"
$2
EOF
  chmod 0755 "$temporary/miner.sh"
}

write_config() {
  cat >"$temporary/idle.json" <<EOF
{
  "argv": ["$temporary/miner.sh"],
  "user": "$runner",
  "working_directory": "$temporary",
  "stop_grace_seconds": $1,
  "gpu_release_seconds": $2
}
EOF
  chmod 0644 "$temporary/idle.json"
}

idle_check() {
  "$prismd" idle-check \
    --idle-config "$temporary/idle.json" \
    --gpu-uuid "$uuid" \
    --idle-root "$temporary" \
    --idle-state-root "$daemon_state" \
    --state-root "$temporary/leases"
}

reset_state() {
  rm -f "$temporary/miner.pid" "$daemon_state/state.json"
  printf '%s' "$1" >"$temporary/mode"
}

# A miner that stops when it is asked to, and a card the driver reports free
# once it is gone.
write_miner 'echo prism-idle-test starting' 'exec sleep 300'
write_config 10 10
reset_state follow
output=$(idle_check)
printf '%s\n' "$output"
case "$output" in
  *"can hand the GPU to a lease"*) ;;
  *) echo "the handshake did not report a verdict" >&2; exit 1 ;;
esac
grep -q "prism-idle-test starting" "$daemon_state/idle.log"
if [ -e "$temporary/idle.log" ] || [ -e "$temporary/state.json" ]; then
  echo "the daemon wrote its own files into the workload's directory" >&2
  exit 1
fi
echo "a workload that stops on request hands the card over"

# A miner that ignores the request. The grace period has to run out, the process
# group has to be killed, and a handover that needed a kill is not a pass.
write_miner "trap '' TERM" 'while :; do sleep 1; done'
write_config 3 10
reset_state follow
started=$(date +%s)
if idle_check >/dev/null 2>"$temporary/killed.err"; then
  echo "a workload that had to be killed was reported as a clean handover" >&2
  exit 1
fi
elapsed=$(( $(date +%s) - started ))
if [ "$elapsed" -lt 3 ]; then
  echo "the grace period was not honoured before the kill" >&2
  exit 1
fi
if kill -0 "$(cat "$temporary/miner.pid")" 2>/dev/null; then
  echo "the workload survived the handshake" >&2
  exit 1
fi
grep -q "ignored the stop signal and had to be killed" "$temporary/killed.err"
echo "a workload that ignores the request is killed and fails the check"

# A card that never comes free fails the check and leaves the node quarantined.
write_miner 'true' 'exec sleep 300'
write_config 3 3
reset_state busy
if idle_check >/dev/null 2>"$temporary/busy.err"; then
  echo "a card that never came free was reported as handed over" >&2
  exit 1
fi
grep -q "could not release the GPU" "$temporary/busy.err"
grep -q '"phase":"quarantined"' "$daemon_state/state.json"
echo "a card that never comes free fails the check and quarantines the node"

# A driver that will not answer means nobody can say the card is free, and that
# is not the same as free.
write_miner 'true' 'exec sleep 300'
write_config 3 3
reset_state broken
if idle_check >/dev/null 2>"$temporary/broken.err"; then
  echo "an unreadable driver was treated as a free card" >&2
  exit 1
fi
grep -q "could not release the GPU" "$temporary/broken.err"
echo "an unreadable driver is never read as a free card"

echo "idle workload handshake integration passed"
