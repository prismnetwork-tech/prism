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

The proof worker and Caddy share the root of the `proof_data` volume. Caddy
serves the authoritative index without caching, direct receipts with a
30-second cache lifetime, and content-addressed page sets as immutable files
below `/proof-artifacts/`. The one-shot `proof-init` service gives the non-root
worker ownership before it starts.

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

## Start a new empty deployment

Do not use this path for a database that has ever accepted a lease. Start the
stateful prerequisites, apply the schema with the control image in one-shot
migration mode, and verify that migrations 0025 through 0028 succeeded before
starting any public service:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml up -d postgres cache
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml run --rm --no-deps \
  -e PRISM_RUN_MIGRATIONS_ONLY=1 control-plane
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml exec -T postgres \
  psql -U prism -d prism -v ON_ERROR_STOP=1 -c \
  'SELECT version, success FROM _sqlx_migrations WHERE version BETWEEN 25 AND 28 ORDER BY version;'
```

Complete the escrow, provider, private-RPC, proof-publisher and recovery gates
in the [Vast launch runbook](../../docs/vast-launch.md) before enabling the
worker profile or admitting funded work. Once those gates pass, start the core
services and then the reviewed worker images from the same release:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml up -d
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml \
  --profile workers --profile observability up -d
```

## Upgrade an existing deployment

Back up PostgreSQL and the deployment configuration first. Drain HTTP traffic,
then stop admissions and every database or proof writer before changing image
references or applying migrations. Disable the legacy static proof publisher if
it exists; it must never overlap the database proof worker.

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml --profile workers \
  stop -t 180 control-plane lifecycle-worker repro-worker settlement-worker proof-worker
if systemctl list-unit-files prism-proof-index.timer --no-legend 2>/dev/null \
  | grep -q '^prism-proof-index.timer'; then
  sudo systemctl disable --now prism-proof-index.timer
fi
if systemctl is-active --quiet prism-proof-index.timer; then
  echo 'static proof publisher is still active' >&2
  exit 1
fi
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml --profile workers \
  ps --status running \
  control-plane lifecycle-worker repro-worker settlement-worker proof-worker
```

The final command must print no containers and the migration query below must
return exactly four successful rows. Never restart an old worker after the new
migrations are installed.

Apply the schema with the new control image without opening its HTTP listener:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml --profile workers \
  run --rm --no-deps -e PRISM_RUN_MIGRATIONS_ONLY=1 control-plane
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml exec -T postgres \
  psql -U prism -d prism -v ON_ERROR_STOP=1 -c \
  'SELECT version, success FROM _sqlx_migrations WHERE version BETWEEN 25 AND 28 ORDER BY version;'
```

Migration 0026 archives and clears only proposal-only cursors it can prove were
unsent. Any other partial cursor aborts before the hardened trigger is
installed. Review the preserved data instead of bypassing the guard.

Keep every normal worker and the control plane stopped. Continue with the
[historical-generation maintenance drain](../../docs/vast-launch.md#historical-generation-maintenance-drain):
pause both escrows, install `operator_maintenance` under advisory lock `4663`,
drain the historical generation and then the current generation using only
explicit generation-bound hardened processes, and perform the one-publisher
proof cutover. Do not use a generic `compose up` during the drain.

Each generation's settlement startup audit must leave no generation binding
`pending`, no nonce `conflict`, and no current job cursor pointing to
`quarantined` bytes. Preserve quarantined attempts and resolve them only from
verified chain evidence; never edit nonce reservations or manufacture a signer.

After the runbook clears only the maintenance latch and one current lifecycle
owner has rebuilt fresh provider health, start the remaining current workers.
Unpause only the current escrow and start the control plane last:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml --profile workers \
  up -d --no-deps --pull never settlement-worker repro-worker proof-worker
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml \
  up -d --no-deps --pull never control-plane
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml \
  --profile observability up -d access-gateway web edge operations-monitor reconciliation-monitor prometheus
```

The proof worker in the first command is idempotent only after the static timer
is disabled and the runbook's proof cutover has completed. Keep admissions
closed if any version, escrow, signer, nonce, provider, proof or migration check
differs from the recorded release plan.

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

Proof publication does not require an X account. `PRISM_ENABLE_X_DIGEST_POSTING`
defaults to `0`; set it to `1` and provide `PRISM_X_USER_ACCESS_TOKEN` only when
daily digest posting is deliberately enabled. The worker finishes an active
publication on SIGTERM and Compose allows three minutes before forcing exit.

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
