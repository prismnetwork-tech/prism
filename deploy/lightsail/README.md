# Lightsail deployment

This is the full single-host reference topology. It runs the web application,
control plane, physical-node access gateway, PostgreSQL, TLS-only Valkey,
lifecycle, settlement and proof workers, and optional local observability on
one Ubuntu host.

The configuration, certificate bootstrap and Compose topology pass the
repository test suite. This topology has not been release-qualified on a live
Lightsail instance. It is not highly available and should not be treated as a
production deployment without tested backup, restore and host-replacement
procedures.

## Included services

- Caddy HTTPS edge
- Next.js web application
- Rust control plane and access gateway
- PostgreSQL and TLS-only Valkey
- Lifecycle, settlement and proof workers
- Optional operations monitor and Prometheus

The proof worker writes public artifacts to the `proof_data` volume. Caddy
serves the index and immutable artifacts below `/proof-artifacts/`.

## Prepare the host

Install Docker Engine with the Compose plugin on a current Ubuntu LTS host.
Allow public TCP 80 and 443, plus 7443 and 7444 only when physical nodes and
renter relay access are enabled. Do not expose PostgreSQL, Valkey, Prometheus,
the control plane or the internal gateway HTTP port.

Point the deployment hostname at the instance before starting Caddy.

Create the private gateway and cache CA material:

```sh
./scripts/generate-lightsail-tls.sh gateway.example.com
```

The generated `deploy/lightsail/secrets/tls` directory is ignored by Git. The
one-shot `tls-init` service copies only the required runtime files into named
volumes and applies non-root ownership where needed.

This reduced topology keeps the CA private key online so the control plane can
issue and renew node certificates. Restrict host access, encrypt snapshots and
rotate the CA if the host is compromised. The generated bootstrap node
certificate is only for a controlled canary; each supplier device needs its
own certificate and revocation record.

Create the untracked environment file and replace every example value:

```sh
cp deploy/lightsail/.env.example deploy/lightsail/.env
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml config --quiet
```

The worker profile also expects an untracked Vast credential:

```text
deploy/lightsail/secrets/vast-api-key
```

Complete the [Vast launch runbook](../../docs/vast-launch.md) before enabling
the cloud broker. An empty `PRISM_VAST_NODE_ID` disables Vast provisioning
while retaining the physical-node lifecycle.

## Start the stack

Start the core web, API, gateway, database and cache:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml up -d
```

Add the three workers and local alert evaluation:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml \
  --profile workers --profile observability up -d
```

Inspect health and logs:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml ps
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml logs --tail 200
```

Run exactly one lifecycle, settlement and proof worker on this topology. Their
database outboxes provide retry and idempotency; multiple unsupervised copies
are outside the tested operating model.

Prometheus retains 15 days locally and evaluates
`deploy/observability/prism-alerts.yml`. It has no default external
notification receiver. Configure off-host alert delivery before any funded
beta.

## Readiness limits

- The escrow remains paused and this topology has not completed a funded
  mainnet lease.
- Physical NVIDIA/Kata/VFIO/CUDA execution still requires hardware validation.
- Database, cache, proof and Prometheus data share one failure domain.
- Backup restore, host replacement and certificate-revocation drills remain
  operator responsibilities.
- The contracts and infrastructure have not received an independent audit.
