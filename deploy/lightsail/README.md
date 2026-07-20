# Lightsail deployment

This topology runs the web application, control plane, access gateway,
PostgreSQL and Valkey on one Lightsail instance. It reduces first-month cost,
but it is not highly available. Database, cache and proof volumes must be
included in encrypted snapshots and tested restores.

## Host preparation

Install Docker Engine with the Compose plugin on a current Ubuntu LTS host.
Point the application DNS record at the instance before starting Caddy.

Create the private gateway and cache CA material:

```sh
./scripts/generate-lightsail-tls.sh tunnel.example.invalid
```

The generated directory is ignored by Git. The one-shot `tls-init` service
copies only runtime certificates into a named volume and assigns the gateway
and Valkey keys to their non-root runtime users. Keep `ca.key` offline after
issuing node certificates. The bootstrap node certificate is for a controlled
canary; production enrollment must issue a separate certificate for each
device and record its revocation status.

Copy `.env.example` to an untracked `.env`, replace every example value and
validate the resolved configuration:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml config --quiet
```

The worker profile expects `secrets/vast-api-key` for the launch-day cloud
broker. Complete [`docs/vast-launch.md`](../../docs/vast-launch.md) before
starting the stack.

Start the full persistent stack, including all three workers and private
Prometheus alert evaluation:

```sh
docker compose --env-file deploy/lightsail/.env \
  -f deploy/lightsail/compose.yml --profile workers --profile observability up -d
```

The lifecycle, settlement and proof workers are long-running database-outbox
consumers. Run exactly one instance of each on this topology. The proof worker
writes public artifacts to the `proof_data` volume; Caddy serves them below
`/proof-artifacts/`.

The operations monitor exposes database-derived metrics only to the private
Compose network. Prometheus retains 15 days locally and evaluates the rules in
`deploy/observability/prism-alerts.yml`. Connect an external notification
receiver before public beta; alert delivery credentials are deployment inputs,
not repository defaults.

Do not expose PostgreSQL, Valkey or the control-plane port publicly. Ports 7443
and 7444 are the mTLS node tunnel and renter relay endpoints. The application
HTTPS endpoint is served by Caddy on port 443.
