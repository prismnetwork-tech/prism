# Independent node installation

The physical-node runtime targets Ubuntu 24.04 x86-64 with an NVIDIA GPU bound
as a complete IOMMU group to `vfio-pci`. It launches public OCI images through
containerd and Kata, applies host egress policy, and connects outbound to the
Prism gateway over mTLS.

The daemon, systemd units, certificate flow, tunnel and simulated workspace
lifecycle pass repository integration tests. They have not yet completed an
end-to-end run on physical NVIDIA/Kata/VFIO hardware.

## Host baseline

Install and configure:

- NVIDIA driver and `nvidia-smi`
- containerd, nerdctl and NVIDIA Container Toolkit
- Kata Containers with a QEMU runtime
- IOMMU, `vfio-pci` and complete GPU isolation groups
- nftables
- disabled swap

Build the release binary on a compatible host and install it:

```sh
cargo build --release --package prismd
install -o root -g root -m 0755 \
  target/release/prismd /usr/local/sbin/prismd
```

Run preflight before enrollment:

```sh
prismd preflight
```

Review the full JSON report. Treat a failed `nvidia_smi` or
`nvidia_container_toolkit` check as a blocker even if the current aggregate
`supported` field is true; the aggregate currently validates the host
isolation baseline, not CUDA workspace readiness.

## Identity and enrollment

Create the service account and private directories:

```sh
useradd --system --home /var/lib/prismd --shell /usr/sbin/nologin prismd
install -d -o prismd -g prismd -m 0700 \
  /var/lib/prismd /var/lib/prismd/tls
install -d -o root -g root -m 0700 \
  /var/lib/prismd/workspaces /var/lib/prismd/leases /run/lock/prismd
sudo -u prismd prismd create-identity
```

`create-identity` prints the node ID and stores a mode-`0600` Ed25519 key at
`/var/lib/prismd/device.json`. The current implementation uses a file-backed
key; TPM-backed identity is not implemented.

The operator and payout wallets, advertised rate, GPU inventory and on-chain
bond must agree with the registry before the control plane accepts enrollment:

```sh
sudo -u prismd prismd enroll \
  --identity /var/lib/prismd/device.json \
  --control-plane https://api.example.com/ \
  --operator-wallet 0x0000000000000000000000000000000000000000 \
  --payout-wallet 0x0000000000000000000000000000000000000000 \
  --gpu-model "NVIDIA GPU" \
  --vram-mib 24576 \
  --cuda-major 12 \
  --rate-per-second 222 \
  --benchmark-score 1000
```

Replace every example value. The repository does not yet package a generic
self-service transaction flow for supplier registration and bonding, so
physical enrollment remains operator-assisted.

## Install services

Copy `node.env.example` to `/etc/prismd/node.env`, replace every placeholder,
and install the unit files from this directory under `/etc/systemd/system`.
Keep the environment file, device identity and TLS private key restricted to
their service users.

Issue the first seven-day client certificate, then enable daily renewal and the
runtime services:

```sh
systemctl daemon-reload
systemctl start prismd-certificate.service
systemctl enable --now prismd-certificate.timer
systemctl enable --now prismd-commands.service prismd-tunnel.service
```

Certificate renewal writes the new files atomically and restarts the outbound
tunnel. If renewal fails, the existing tunnel continues and systemd retries on
the next timer activation.

The command supervisor runs as root because VFIO assignment, nftables policy
and containerd require host privileges. The tunnel runs as the unprivileged
`prismd` account. Only one command supervisor may run per host; the exclusive
VFIO reservation rejects a duplicate.

## Security boundary

- Supplier hosts accept no inbound renter ports; access traverses the outbound
  gateway tunnel.
- Workspace credentials expire with the lease and workspace keys are destroyed
  during teardown.
- Terminal contents, notebooks, files and environment values are outside the
  telemetry model.
- Kata reduces exposure to hostile workloads but does not make a permissionless
  supplier trustworthy.
- Do not run confidential or sensitive workloads until independently
  attestable confidential-GPU nodes are available.
