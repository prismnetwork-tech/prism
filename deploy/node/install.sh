#!/usr/bin/env bash
# Prepares a stock Ubuntu 24.04 x86-64 host to serve Open-mode leases: the
# container runtime, the NVIDIA container tooling, the daemon's accounts and
# directories, and /etc/prismd/node.env. It reads no key material, writes no key
# material, and posts no bond. Re-running it is safe.
set -euo pipefail

nerdctl_version="2.3.5"
nerdctl_sha256="de3206aeb7cbd5f20f5fb1f55c1e3bf2db1be567812a8a3f5e65eba2488347ee"
cni_version="1.9.1"
cni_sha256="b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303"
nvidia_key_url="https://nvidia.github.io/libnvidia-container/gpgkey"
nvidia_key_fingerprint="C95B321B61E88C1809C4F759DDCAE044F796ECB0"
nvidia_keyring="/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg"
nvidia_source_list="/etc/apt/sources.list.d/nvidia-container-toolkit.list"
cni_marker="/usr/local/share/prism/cni-plugins.version"
node_env="/etc/prismd/node.env"

control_plane=""
gateway_address=""
gateway_server_name=""
connection_id=""
gpu_uuid=""
warm_image=""
skip_preflight=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --control-plane URL           Control plane base URL
  --gateway-address HOST:PORT   Gateway the outbound tunnel dials
  --gateway-server-name NAME    TLS server name the gateway presents
  --connection-id ID            Stable identifier for this host's tunnel
  --gpu-uuid UUID               Card to serve. Required when several are visible
  --warm-image REF              Pull this image now so the first lease starts warm
  --skip-preflight              Skip the closing preflight run
  -h, --help                    Show this message

Values already present in /etc/prismd/node.env are left as they are.
EOF
}

log() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --control-plane) control_plane="${2:-}"; shift 2 ;;
    --gateway-address) gateway_address="${2:-}"; shift 2 ;;
    --gateway-server-name) gateway_server_name="${2:-}"; shift 2 ;;
    --connection-id) connection_id="${2:-}"; shift 2 ;;
    --gpu-uuid) gpu_uuid="${2:-}"; shift 2 ;;
    --warm-image) warm_image="${2:-}"; shift 2 ;;
    --skip-preflight) skip_preflight=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "Unknown option: $1" ;;
  esac
done

workdir=""
cleanup() {
  if [[ -n "$workdir" ]]; then
    rm -rf "$workdir"
  fi
}
trap cleanup EXIT

verify_sha256() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | cut -d' ' -f1)"
  if [[ "$actual" != "$expected" ]]; then
    fail "Checksum mismatch for $(basename "$file"). Expected $expected and got $actual. The download is not the release this script pins."
  fi
}

check_privileges() {
  [[ "$(id -u)" == "0" ]] ||
    fail "Run this as root. It installs packages and creates system accounts."
}

os_release_field() {
  awk -F= -v key="$1" '$1 == key { gsub(/"/, "", $2); print $2 }' /etc/os-release
}

check_host() {
  local arch distribution version
  arch="$(uname -m)"
  [[ "$arch" == "x86_64" ]] ||
    fail "This host reports $arch. Open mode serves x86-64 only."
  [[ -r /etc/os-release ]] ||
    fail "/etc/os-release is unreadable. This script expects Ubuntu 24.04."
  distribution="$(os_release_field ID)"
  version="$(os_release_field VERSION_ID)"
  if [[ "$distribution" != "ubuntu" || "$version" != "24.04" ]]; then
    fail "This host reports ${distribution:-an unknown distribution} ${version}. This script targets Ubuntu 24.04."
  fi
}

check_driver() {
  command -v nvidia-smi >/dev/null 2>&1 ||
    fail "nvidia-smi is missing. Install the NVIDIA driver for this card, reboot, then run this script again."
  nvidia-smi -L >/dev/null 2>&1 ||
    fail "nvidia-smi is installed but lists no usable device. Check that the driver module loaded and that the card is not bound to vfio-pci."
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg containerd nftables
  systemctl enable --now containerd
}

install_nerdctl() {
  if [[ "$(nerdctl --version 2>/dev/null || true)" == "nerdctl version ${nerdctl_version}" ]]; then
    log "nerdctl ${nerdctl_version} is already installed."
    return
  fi
  local archive="${workdir}/nerdctl.tar.gz"
  curl -fsSL --retry 3 -o "$archive" \
    "https://github.com/containerd/nerdctl/releases/download/v${nerdctl_version}/nerdctl-${nerdctl_version}-linux-amd64.tar.gz"
  verify_sha256 "$archive" "$nerdctl_sha256"
  tar -C /usr/local/bin -xzf "$archive" nerdctl
  log "Installed nerdctl ${nerdctl_version}."
}

install_cni_plugins() {
  if [[ "$(cat "$cni_marker" 2>/dev/null || true)" == "$cni_version" ]]; then
    log "CNI plugins ${cni_version} are already installed."
    return
  fi
  local archive="${workdir}/cni-plugins.tgz"
  curl -fsSL --retry 3 -o "$archive" \
    "https://github.com/containernetworking/plugins/releases/download/v${cni_version}/cni-plugins-linux-amd64-v${cni_version}.tgz"
  verify_sha256 "$archive" "$cni_sha256"
  install -d -o root -g root -m 0755 /opt/cni/bin "$(dirname "$cni_marker")"
  tar -C /opt/cni/bin -xzf "$archive"
  printf '%s\n' "$cni_version" >"$cni_marker"
  log "Installed CNI plugins ${cni_version}."
}

install_nvidia_container_toolkit() {
  if [[ ! -s "$nvidia_keyring" ]]; then
    local key="${workdir}/nvidia.gpgkey" fingerprints
    curl -fsSL --retry 3 -o "$key" "$nvidia_key_url"
    fingerprints="$(gpg --show-keys --with-colons --with-fingerprint "$key" |
      awk -F: '$1 == "fpr" { print $10 }')"
    grep -qx "$nvidia_key_fingerprint" <<<"$fingerprints" ||
      fail "The key at ${nvidia_key_url} does not carry fingerprint ${nvidia_key_fingerprint}. Confirm the current NVIDIA signing key before trusting this repository."
    gpg --dearmor --output "$nvidia_keyring" "$key"
    chmod 0644 "$nvidia_keyring"
  fi
  printf 'deb [signed-by=%s] https://nvidia.github.io/libnvidia-container/stable/deb/amd64 /\n' \
    "$nvidia_keyring" >"$nvidia_source_list"
  apt-get update -qq
  apt-get install -y -qq nvidia-container-toolkit libnvidia-container-tools
  command -v nvidia-container-cli >/dev/null 2>&1 ||
    fail "nvidia-container-cli is still missing after installing the toolkit. Every lease attaches the card through it, so enrollment would serve nothing."
}

create_accounts_and_directories() {
  id -u prismd >/dev/null 2>&1 ||
    useradd --system --home /var/lib/prismd --shell /usr/sbin/nologin prismd
  id -u prismd-idle >/dev/null 2>&1 ||
    useradd --system --home /var/lib/prismd/idle --shell /usr/sbin/nologin prismd-idle

  install -d -o root -g root -m 0755 /etc/prismd
  # prismd-idle has to reach its own directory. Traverse only: everything under
  # /var/lib/prismd that holds anything keeps its own 0700.
  install -d -o prismd -g prismd -m 0711 /var/lib/prismd
  install -d -o prismd -g prismd -m 0700 /var/lib/prismd/tls
  install -d -o root -g root -m 0700 \
    /var/lib/prismd/workspaces /var/lib/prismd/leases /run/lock/prismd
  # The workload owns the directory it runs in. The daemon's own state file and
  # the workload's log sit next to it, in one only root can write, so the
  # workload cannot decide where root's next write lands.
  install -d -o prismd-idle -g prismd-idle -m 0750 /var/lib/prismd/idle
  install -d -o root -g root -m 0700 /var/lib/prismd/idle-state
  # ProtectSystem=strict refuses to start the unit if a ReadWritePaths entry is
  # missing, and nerdctl creates most of these lazily on first run.
  install -d -o root -g root -m 0755 \
    /var/lib/nerdctl /etc/cni/net.d /var/lib/cni /run/cni /run/netns
}

set_env_value() {
  local key="$1" value="$2"
  if grep -qE "^${key}=" "$node_env"; then
    log "Left ${key} as it stands in ${node_env}."
    return
  fi
  printf '%s=%s\n' "$key" "$value" >>"$node_env"
  log "Set ${key} in ${node_env}."
}

write_node_env() {
  if [[ ! -f "$node_env" ]]; then
    install -o root -g prismd -m 0640 /dev/null "$node_env"
  fi
  set_env_value PRISM_ISOLATION shared
  [[ -n "$control_plane" ]] && set_env_value PRISM_CONTROL_PLANE_URL "$control_plane"
  [[ -n "$gateway_address" ]] && set_env_value PRISM_GATEWAY_ADDRESS "$gateway_address"
  [[ -n "$gateway_server_name" ]] && set_env_value PRISM_GATEWAY_SERVER_NAME "$gateway_server_name"
  [[ -n "$connection_id" ]] && set_env_value PRISM_CONNECTION_ID "$connection_id"
  [[ -n "$gpu_uuid" ]] && set_env_value PRISM_GPU_UUID "$gpu_uuid"
  return 0
}

warm_workspace_image() {
  [[ -n "$warm_image" ]] || return 0
  nerdctl --namespace prism pull "$warm_image"
  log "Pulled ${warm_image}."
}

run_preflight() {
  local binary
  binary="$(command -v prismd 2>/dev/null || true)"
  [[ -n "$binary" ]] || binary="/usr/local/sbin/prismd"
  if [[ ! -x "$binary" ]]; then
    log ""
    log "prismd is not installed here, so preflight did not run. Build it with"
    log "'cargo build --release --package prismd', install it at"
    log "/usr/local/sbin/prismd, then run 'prismd preflight --isolation shared'."
    return 0
  fi
  log ""
  "$binary" preflight --isolation shared
}

print_next_steps() {
  cat <<'EOF'

Host preparation is done. Next, in order:

  sudo -u prismd prismd create-identity

  PRISM_OPERATOR_KEY=0x… prismd register \
    --identity /var/lib/prismd/device.json \
    --rpc-url https://rpc.mainnet.chain.robinhood.com \
    --registry 0xDaE90914CCb3601ABdfAEf994CD07eE7676519Dc \
    --rate-per-second 222 \
    --dry-run

  sudo -u prismd prismd enroll \
    --identity /var/lib/prismd/device.json \
    --control-plane https://api.example.com/ \
    --operator-wallet 0x… --payout-wallet 0x… \
    --gpu-model "NVIDIA GeForce RTX 4090" --vram-mib 24564 \
    --cuda-major 12 --rate-per-second 222 --benchmark-score 1000

Dropping --dry-run posts the bond. OPEN_MODE.md in this directory covers the
idle workload and what a lease does to it.
EOF
}

check_privileges
check_host
check_driver
workdir="$(mktemp -d)"
install_base_packages
install_nerdctl
install_cni_plugins
install_nvidia_container_toolkit
create_accounts_and_directories
write_node_env
warm_workspace_image

if [[ "$skip_preflight" == "1" ]]; then
  print_next_steps
  exit 0
fi

if ! run_preflight; then
  log ""
  log "Preflight reports this host cannot serve Open leases yet. Fix the checks"
  log "it printed, then run 'prismd preflight --isolation shared' again."
  exit 1
fi

print_next_steps
