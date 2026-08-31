# Independent node installation

The physical-node runtime targets Ubuntu 24.04 x86-64 with an NVIDIA GPU. It
launches public OCI images through containerd, applies host egress policy, and
connects outbound to the Prism gateway over mTLS.

The daemon, systemd units, certificate flow, tunnel and simulated workspace
lifecycle pass repository integration tests. They have not yet completed an
end-to-end run on physical NVIDIA/Kata/VFIO hardware.

Order of operations: preflight the host, create the device identity, bond it in
the registry, enroll with the control plane, then install the services.

## Isolation mode

The node serves one isolation mode, chosen with `--isolation` or
`PRISM_ISOLATION` and fixed for the life of the daemon. Nothing is detected
automatically.

`kata-vfio` is the default. The GPU is bound as a complete IOMMU group to
`vfio-pci` and the workload runs in a Kata guest that holds the card
exclusively, which is what lets the node publish above `open`. The host work is
the larger part of the job and [GPU_PASSTHROUGH.md](GPU_PASSTHROUGH.md) covers
it.

`shared` leaves the card with the host driver and runs the workload in a
container with the card attached. Stock Ubuntu, an NVIDIA driver and containerd
are enough, and the daemon can run a workload of the operator's choosing between
leases. Such a node publishes `open`. [OPEN_MODE.md](OPEN_MODE.md) is the
runbook and `install.sh` in this directory prepares the host.

The rest of this document assumes `kata-vfio`. OPEN_MODE.md names every place
`shared` differs.

## Host baseline

This is the `kata-vfio` baseline. `shared` has a smaller one that `install.sh`
puts in place, and OPEN_MODE.md lists it.

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

Run preflight before enrollment, naming the mode the node will serve:

```sh
prismd preflight --isolation kata-vfio
prismd preflight --isolation shared
```

Review the full JSON report. Under `kata-vfio`, treat a failed `nvidia_smi` or
`nvidia_container_toolkit` check as a blocker even if the aggregate `supported`
field is true; that aggregate validates the host isolation baseline and says
nothing about CUDA workspace readiness. Under `shared` the aggregate covers the
container path itself, including `nvidia_container_cli`, the binary that hands
the card to a container.

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

## Bond

The control plane will not schedule a node the registry has not bonded, so the
stake goes up before enrollment. Bonds are posted in PRISM on Robinhood Chain
and are returned when the node retires. Compute itself settles in USDG, so this
is the only place the token is involved.

The bond scales with the rate the node charges. Ask the registry what a rate
costs before committing to one:

```sh
prismd register \
  --identity /var/lib/prismd/device.json \
  --rpc-url https://rpc.mainnet.chain.robinhood.com \
  --registry 0xa7Ca8e43c599b978095c391bd018A35BA6e7B71D \
  --rate-per-second 222 \
  --dry-run
```

The dry run signs the device binding, puts it to the registry, and reports what
would happen without spending anything. It is the cheapest way to find a wrong
wallet, an expired identity or a rate you cannot cover.

Drop `--dry-run` to post the bond. The operator key stays on this host: it signs
the binding between the wallet and the device, approves the registry to take the
bond, and pays gas. Pass it in the environment rather than on the command line,
where it would land in shell history:

```sh
PRISM_OPERATOR_KEY=0x… prismd register \
  --identity /var/lib/prismd/device.json \
  --rpc-url https://rpc.mainnet.chain.robinhood.com \
  --registry 0xa7Ca8e43c599b978095c391bd018A35BA6e7B71D \
  --payout-wallet 0x… \
  --rate-per-second 222
```

`--payout-wallet` defaults to the operator wallet. Set it when earnings should
land somewhere the signing key cannot reach.

## Enrollment

The operator and payout wallets, advertised rate and GPU inventory must match
the registration the registry now holds:

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

Replace every example value. Enrollment is permissionless: the control plane
accepts any node whose device key signs the request and whose registration the
registry confirms, so nobody has to approve the host.

## Earnings

A lease pays 90% of confirmed usage to the payout wallet and 10% to the
network. Payment follows the settlement receipt rather than the booking, so a
lease that never admitted a workload pays nothing and refunds the renter.

Rates are quoted in USDG base units per second. At 222, a full hour of use
settles about 0.80 USDG, of which the payout wallet receives about 0.72.

## Trust class

A node reached over the outbound tunnel and reporting a Kata and VFIO posture is
published above `open`, which is the tier renters can require for workloads they
will not put on a host that can read guest memory. Capacity brokered from a
public cloud cannot reach that tier, so this is where self-hosted hardware is
worth more than resold hardware.

A node configured for `shared` reports `open` whatever the host is capable of,
including a host that still has a bound VFIO group and a Kata shim installed.

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
device reservation rejects a duplicate.

## Security boundary

- Supplier hosts accept no inbound renter ports; access traverses the outbound
  gateway tunnel.
- Workspace credentials expire with the lease and workspace keys are destroyed
  during teardown.
- Terminal contents, notebooks, files and environment values are outside the
  telemetry model.
- Kata reduces exposure to hostile workloads but does not make a permissionless
  supplier trustworthy.
- Under `shared` there is no guest boundary. The workload runs in a container
  the host can read, which is what the `open` class states.
- Do not run confidential or sensitive workloads until independently
  attestable confidential-GPU nodes are available.
