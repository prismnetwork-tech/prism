# Node service installation

The initial node target is Ubuntu 24.04 x86-64 with one or more NVIDIA GPUs
bound as complete IOMMU groups to `vfio-pci`. Install the built `prismd` binary
at `/usr/local/sbin/prismd`, then run `prismd preflight` before enrollment.

Create the `prismd` system user, `/var/lib/prismd/tls`, `/var/lib/prismd`,
`/var/lib/prismd/workspaces`, `/var/lib/prismd/leases` and
`/run/lock/prismd`. The identity and TLS private key must be mode `0600`; the
directories must not grant access to unprivileged users.

Copy `node.env.example` to `/etc/prismd/node.env`, replace every placeholder,
and install the units in this directory under `/etc/systemd/system`. The
command supervisor runs as root because VFIO assignment, nftables policy and
containerd require host privileges. The tunnel runs as the unprivileged
`prismd` account. The supervisor publishes idle and lease-bound telemetry so
one device identity sequence cannot be raced by a separate timer.

After device enrollment, issue the first client certificate, then enable its
daily renewal timer and the runtime services:

```sh
systemctl daemon-reload
systemctl start prismd-certificate.service
systemctl enable --now prismd-certificate.timer
systemctl enable --now prismd-commands.service prismd-tunnel.service
```

Renewal writes a new seven-day certificate and key with restrictive
permissions, then restarts the outbound tunnel so the gateway immediately sees
the new certificate fingerprint. A failed renewal leaves the running tunnel in
place and systemd retries on the next timer activation.

Only one command supervisor may run per host. A duplicate supervisor will
fail the exclusive VFIO reservation and must not be used as a failover
mechanism.
