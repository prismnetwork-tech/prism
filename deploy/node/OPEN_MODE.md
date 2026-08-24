# Serving leases from a machine you already own

Open mode leaves the GPU with the host driver and runs the renter's workload in
a container with the card attached. There is no IOMMU work and no Kata guest, so
a gaming rig or a single-card workstation can serve leases on the same day it is
set up.

What Open means for the renter: the operator can read everything the workload
touches. That is what the `open` trust class states, and it is why a renter who
needs more sets `min_trust_class` and never reaches this node.
[docs/SECURITY_MODEL.md](../../docs/SECURITY_MODEL.md) has the classes.

A rig that only earns while leased sits idle most of the day, so `prismd` can
run one workload of the operator's choosing between leases and take the card
back before a lease starts. [The idle workload](#the-idle-workload) covers it.

## What the host needs

- Ubuntu 24.04 x86-64.
- An NVIDIA GPU with the vendor driver installed and `nvidia-smi` working.
- Root access.
- `127.0.0.1:2222` and `127.0.0.1:8888` free. A lease binds both, and one lease
  runs per host.
- A wallet holding PRISM for the bond and gas on Robinhood Chain.

## Host preparation

```sh
sudo deploy/node/install.sh \
  --control-plane https://api.example.com/ \
  --gateway-address gateway.example.com:7443 \
  --gateway-server-name gateway.example.com \
  --connection-id my-rig-01
```

The script installs containerd, nerdctl, the CNI plugins and the NVIDIA
Container Toolkit, creates the `prismd` and `prismd-idle` accounts with their
directories, and writes `/etc/prismd/node.env` with `PRISM_ISOLATION=shared`. It
finishes by running preflight when `prismd` is already installed, and otherwise
tells you to run it once you have built the daemon. Values already in `node.env`
are left alone, so re-running it after an edit is safe. It reads no key material
and posts no bond.

Add `--warm-image <ref>` to pull a workspace image while you are here. The first
lease on a cold host otherwise waits out a multi-gigabyte download.

nerdctl and the CNI plugins come from pinned GitHub releases and are checked
against a recorded SHA-256. The toolkit comes from NVIDIA's apt repository,
whose signing key is matched against a fingerprint before anything trusts it.
Both pins live at the top of the script.

Build and install the daemon itself, then run preflight:

```sh
cargo build --release --package prismd
install -o root -g root -m 0755 target/release/prismd /usr/local/sbin/prismd
prismd preflight --isolation shared
```

## Choosing the card

```sh
nvidia-smi --query-gpu=index,uuid,name,memory.total --format=csv
```

With one card visible, leave `PRISM_GPU_UUID` unset. With several, set it.
`prismd` refuses to start rather than guess which card it is selling.

A card bound to `vfio-pci` for a gaming VM is invisible here. Preflight warns
about it and carries on as long as one card is left for the host. It fails only
when every card is bound away, because then there is nothing to serve.

## Preflight

The shared baseline is Linux on x86-64, containerd, nerdctl, nftables,
`nvidia-smi`, `nvidia-container-cli`, at least one host-visible NVIDIA GPU, both
loopback ports bindable, and a forwarding policy that lets container traffic
out. Kata, IOMMU, VFIO and disabled swap are not required. Swap is reported and
warned about, since a paged-out workload gets slow without failing.

`nvidia-container-cli` is the binary that hands the card to a container.
`nerdctl --gpus` execs it, and without it every lease dies at container start.
It ships in `libnvidia-container-tools`, which `install.sh` installs.

### Docker on the same host

Docker sets the iptables `FORWARD` policy to `DROP`. A lease then comes up Ready
with no route out and the renter's first download hangs until the lease expires.
Preflight fails on this and prints the rule to add. Put that rule in the host's
firewall configuration, because a Docker restart resets the policy.

## Identity, bond and enrollment

These are the same steps an isolated node takes, and [README.md](README.md)
covers them in full. Two things differ here.

Enroll with the model and VRAM of the card you are actually serving, read from
`nvidia-smi`. Enrolling an H100's numbers against a 4090 is a signed statement
the dispute queue can act on.

The class published is `open`. Price against that. A renter paying for `open`
capacity is paying for a bonded identity and metered billing, so a rate borrowed
from an isolated node will lose every quote it enters.

## The idle workload

Point `PRISM_IDLE_CONFIG` at a JSON file, conventionally `/etc/prismd/idle.json`.
No config means the feature is off, which is the default. The file is refused if
it is group- or other-writable. Configuring it under `kata-vfio` is refused at
startup, since a card bound to `vfio-pci` is not the host's to use.

`prismd` runs the process itself, as in
[idle.json.example](idle.json.example):

```json
{
  "argv": ["/usr/local/bin/miner", "--pool", "stratum+tcp://pool.example.com:3333"],
  "user": "prismd-idle",
  "working_directory": "/var/lib/prismd/idle",
  "environment": { "MINER_PASSWORD": "x" },
  "stop_grace_seconds": 30,
  "gpu_release_seconds": 20
}
```

Or systemd runs it and `prismd` starts and stops the unit, as in
[idle-systemd.json.example](idle-systemd.json.example):

```json
{ "systemd_unit": "miner.service", "stop_grace_seconds": 30, "gpu_release_seconds": 20 }
```

`argv` is an argument list. A shell line is refused, so quoting mistakes cannot
turn into a command. `argv[0]` has to be an absolute path to a regular file that
is not group- or other-writable. `user` is required and cannot be root. Pool
credentials belong in `environment`, where they stay out of `ps` output and out
of unit files.

The miner binary cannot live under `/home`. `prismd-commands.service` sets
`ProtectHome=true`, so anything the daemon spawns sees an empty `/home`. Install
it in `/usr/local/bin` or `/var/lib/prismd/idle/bin`, or describe it as a
systemd unit and let systemd supervise it.

Output goes to `/var/lib/prismd/idle-state/idle.log`, capped at 8 MiB per file,
with one older copy kept, so at most 16 MiB. A workload that exits keeps
restarting on a backoff that starts at five seconds and doubles to five minutes,
and the backoff resets after ten clean minutes.

`install.sh` creates two directories. `/var/lib/prismd/idle` belongs to
`prismd-idle` and is the workload's own: its home, and where it runs.
`/var/lib/prismd/idle-state` belongs to root at 0700 and holds the daemon's
state file and the workload's log, because a directory the workload can write is
a directory where it chooses what root's next write lands on. `/var/lib/prismd`
above both stays traversable. Setting this up by hand needs the same: the daemon
refuses to start when `idle-state` is not root's.

### Prove the handover before you bond

```sh
prismd idle-check --idle-config /etc/prismd/idle.json
```

Add `--gpu-uuid` when the host has more than one card, the same as for the
daemon.

This starts the configured workload, waits until the card reports a compute
process, then runs the exact stop sequence a lease runs. It prints the measured
time to exit and time to a free GPU against the grace values you configured. A
miner that ignores `SIGTERM`, or that holds VRAM for a while after it exits,
shows up here instead of on a lease somebody paid for.

It passes only when the workload stopped inside both allowances. One that had to
be killed, or a card that came free late, fails the check and names which
allowance was exceeded. Raise `stop_grace_seconds` and `gpu_release_seconds`
until it passes with room to spare. The defaults are thirty seconds for the exit
and twenty for the release.

### What a lease does to the workload

1. `SIGTERM` to the workload's process group.
2. Up to `stop_grace_seconds` for it to exit.
3. `SIGKILL` to the group, then ten seconds.
4. The card is polled until no compute process holds it, up to
   `gpu_release_seconds`.
5. The lease launches.

A missing `nvidia-smi`, a non-zero exit or output that will not parse all count
as busy. The check fails closed, because handing a renter a card another process
still holds is worse than failing the lease.

If the card is still busy when step 4 runs out, the lease fails and says so.
`prismd` then stops restarting the workload and stops publishing telemetry, so
the node's offer ages out of matching within about ninety seconds. A wedged
driver therefore costs one lease and then goes quiet. Both resume after two
consecutive readings show the card free.

After teardown and settlement the workload starts again on its own.

Before the daemon starts the workload it looks for a lease container on the
node, every time. A daemon that restarted while a lease was live therefore
waits for that lease rather than mining on top of it.

## Install the services

`install.sh` prepares the accounts and directories the units expect. Copy the
unit files from this directory into `/etc/systemd/system`, then follow the
certificate and service steps in [README.md](README.md).

`prismd-commands.service` runs as root because nftables policy and containerd
need host privileges. The tunnel runs as the unprivileged `prismd` account.

## What has not been proven on this hardware yet

The workspace image ships NVIDIA userspace matched to the Kata guest kernel.
Under `--gpus` the toolkit bind-mounts the host's driver libraries into the
container and re-runs `ldconfig`. If `libcuda` resolves to a mismatched pair on
your driver, the container starts and CUDA inside it fails. There is no
driver-free workspace image published today, so the only way through it is to
match the host driver to the one the image was built against. This path has not
been exercised on a consumer card, so run a short batch lease against the node
and confirm `nvidia-smi` and a CUDA call both work inside the workspace before
you advertise it.

A batch command served from an Open node carries the operator's word for what
ran. Nothing in the class proves the output came from the command as written.

One lease runs per host, and the loopback ports are fixed at 2222 and 8888.
