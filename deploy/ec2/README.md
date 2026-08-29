# EC2 deployment

This is the single-host topology for the launch path. It runs PostgreSQL, the
Rust control plane, lifecycle and settlement workers, the access gateway with
its Valkey grant store, and a Caddy TLS edge on EC2. The public web application
remains on Render and is proxied by Caddy for `prismnetwork.tech`.

The Compose configuration passes repository validation. The repository does
not contain evidence that a particular EC2 host, backup policy or recovery
procedure has been release-qualified.

## Scope

Included:

- Caddy for the API hostname and the Render web origin
- PostgreSQL
- Control plane
- Vast lifecycle worker
- KMS-backed settlement worker
- Access gateway with the mTLS node tunnel and the renter relay
- Valkey-backed temporary access state

Intentionally excluded:

- Proof and X publishing worker
- Operations monitor and Prometheus
- High availability or managed backups

The gateway is what an independent Kata/VFIO node connects to. It dials out to
the tunnel and never accepts inbound renter ports itself, so without the
gateway running a physical node can enrol, bond and report telemetry while
being unreachable by any renter. The Vast path does not use it at all, because
those instances hand out direct SSH.

Running the gateway does not by itself make this a qualified Kata/VFIO
deployment: no physical node has completed the hardware canary in the
`prism-node` repository.

## Configuration

Create these untracked files:

```text
deploy/ec2/.env
deploy/ec2/secrets/vast-api-key
deploy/ec2/secrets/tls/ca.crt
deploy/ec2/secrets/tls/ca.key
deploy/ec2/secrets/tls/server.crt
deploy/ec2/secrets/tls/server.key
deploy/ec2/secrets/tls/cache.crt
deploy/ec2/secrets/tls/cache.key
```

The environment must provide the image references, domain and ACME email,
database and service secrets, operator subjects, deployed registry and escrow
addresses, RPC URL, KMS key identifiers and the comma-separated
`PRISM_VAST_NODE_IDS` the broker rents against, all required by `compose.yml`.
Managed batch execution also requires `PRISM_REPRO_WORKER_IMAGE`; the worker
reuses the access-credential encryption key and gateway KMS key already used by
the control and lifecycle services.
The gateway additionally needs `PRISM_ACCESS_GATEWAY_IMAGE`,
`PRISM_GATEWAY_HMAC_KEY`, `PRISM_GATEWAY_CONTROL_TOKEN` and
`PRISM_REDIS_PASSWORD`. Every one of these belongs in the env file. Passing a
value inline on the `docker compose` command line survives exactly one
`up`, and the next plain `restart` silently drops it.

### Images

Service images are **linux/arm64**, matching the host: `aws-lc-sys` reliably
crashes the compiler under emulation, so every build runs on the architecture
it targets. Build `deploy/Dockerfile.rust` on arm64, tag each image with the
release commit, then load it directly on the host or push it to Prism's image
registry. An amd64 deployment needs a native amd64 builder, not emulation.

```sh
release=$(git rev-parse HEAD)
tag=$(git rev-parse --short=12 HEAD)

for binary in prism-control-plane prism-lifecycle-worker prism-repro-worker prism-settlement-worker; do
  docker buildx build --platform linux/arm64 --provenance=false --load \
    --file deploy/Dockerfile.rust \
    --build-arg "BINARY=$binary" \
    --build-arg "GIT_SHA=$release" \
    --tag "$binary:$tag" .
done
```

Transfer and load those exact images on the host. Persist all four references
in `/opt/prism/.env`; shell-only assignments do not survive the next Compose
operation:

```dotenv
PRISM_CONTROL_PLANE_IMAGE=prism-control-plane:<tag>
PRISM_LIFECYCLE_WORKER_IMAGE=prism-lifecycle-worker:<tag>
PRISM_REPRO_WORKER_IMAGE=prism-repro-worker:<tag>
PRISM_SETTLEMENT_WORKER_IMAGE=prism-settlement-worker:<tag>
```

Back up Postgres and the deployment files first. Start the control plane alone,
wait for its health check, and verify the newly applied migrations before
starting the coordinated workers:

```sh
docker compose up -d --no-deps --pull never control-plane
docker compose up -d --no-deps --pull never lifecycle-worker repro-worker settlement-worker
```

The public web/MCP image and any deployed proof worker or node daemon must be
built from the same release commit. Verify every service's recorded build SHA
before admitting new work.

### Alerts

Services staying up is not the same as customers being served. The marketplace
has run with no rentable capacity while every container reported healthy, and
settlement has been dead for nineteen hours the same way. `prism-health.timer`
runs `check-prism-health.py` every five minutes against outcomes instead:
whether anything is rentable, whether leases reach their end state, whether the
signers can still pay for the transactions that release money, and what the
reconciliation monitor makes of the escrow.

Install the script at `/usr/local/sbin/check-prism-health.py`, put the settings
in `/opt/prism/alerts.env`, then `systemctl enable --now prism-health.timer`.

```sh
PRISM_ALERT_SIGNERS=settlement=0x...,lifecycle=0x...
PRISM_ALERT_TELEGRAM_TOKEN=...
PRISM_ALERT_TELEGRAM_CHAT=...
VAST_API_KEY=...
```

### The canary

Everything above infers health from parts. The canary proves it by renting: it
quotes, funds on chain, waits for a machine, logs in over SSH, runs a command
and settles, then writes the verdict to `/var/lib/prism/canary.json`. The health
check reads that file and alarms with the step that failed.

This exists because inference kept missing real outages. A lease id that
collided with a superseded escrow took every renter's money and started nothing;
a host was refused for a port it had not been given yet, so no lease could be
provisioned at all; a machine was handed to a renter before it was reachable.
Every gauge above read normal through all three, because each asks whether a
part is working rather than whether a customer can be served.

Install `run-lease-canary.sh` at `/usr/local/sbin/`, put the canary at
`/opt/prism/canary/`, its wallet and caps in `/opt/prism/canary.env`, then
`systemctl enable --now prism-canary.timer`. It runs six-hourly and each run
spends one short lease. The health check waits three missed windows before it
alarms, so a single flaky host does not page anyone.

```sh
PRISM_AGENT_KEY=0x...        # a funded wallet, and only ever this one
PRISM_ESCROW=0x...
CANARY_CONFIRM=1             # without this it only preflights and rents nothing
CANARY_DURATION=600
CANARY_MAX_USDG=0.5
```

With no channel configured the run still prints its findings and exits non-zero,
so `systemctl status prism-health` and the journal hold the answer. That is a
fallback, not a plan: nobody reads a journal they have no reason to open.

Thresholds default to one rentable node, thirty minutes in `settlement_pending`,
fifteen minutes to reach a customer, 0.0005 ETH per signer and $25 of provider
credit, each overridable in the same file. An alarm repeats every six hours
while it lasts and reports once when it clears. `--quiet` checks and prints
without sending or recording anything.

### Gateway certificates

The control plane signs node client certificates with `secrets/tls/ca.key`, and
the tunnel authenticates those clients against the same authority. Issue the
tunnel and cache leaves from the CA that is already deployed rather than
generating a new one, which would lock out every enrolled node:

```sh
./scripts/issue-gateway-tls.sh "$PRISM_DOMAIN" deploy/ec2/secrets/tls
```

The script refuses to run without an existing CA and refuses to overwrite
leaves that are already present. `generate-lightsail-tls.sh` creates a fresh
authority and is only for a deployment that has none.

`PRISM_VAST_NODE_IDS` is a comma separated list of bonded broker identities and
sets how many customers the network can serve at once: the registry frees a node
only when its lease settles, so one identity is one concurrent lease. Each needs
its own onchain registration and a `MIN_BOND` deposit. `PRISM_VAST_NODE_ID` is
still read as a single-node shorthand.

The broker's supply policy comes from `PRISM_VAST_GPU_MODELS` and
`PRISM_VAST_MIN_GPU_RAM_MIB`. A variable set in `.env` but absent from the
host's `compose.yml` never reaches the container, and the effect is an empty
marketplace with a healthy stack, so check the container rather than the file:

```sh
docker compose --env-file deploy/ec2/.env -f deploy/ec2/compose.yml \
  exec lifecycle-worker env | grep PRISM_VAST_
```

The worker also logs the policy it resolved on startup, and says which of the
three reasons it has no capacity: the provider listed nothing, nothing it
listed is a class this broker rents, or everything eligible costs more than a
lease earns.

Validate the fully resolved configuration before changing the host:

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml config --quiet
```

TCP 80, 443, 7443 and 7444 should be public: 7443 is the node tunnel and 7444
is the renter relay that `PRISM_PUBLIC_RELAY_PORT` already advertises. Restrict
SSH to an operator allowlist and do not expose PostgreSQL, Valkey, the
control-plane container port or the gateway's 8081 control port.

## Proof index

`prismnetwork.tech/proof` reads `index.json` from the edge, which serves it out
of `/opt/prism/proof-artifacts`. Publish it with:

```sh
sudo install -m 0755 scripts/publish-proof-index.py /usr/local/sbin/publish-proof-index.py
sudo install -m 0644 deploy/ec2/systemd/prism-proof-index.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now prism-proof-index.timer
```

The timer refreshes every fifteen minutes. Run
`publish-proof-index.py --dry-run` to see what would be published without
writing. Only finalized receipts are published; refunded rows are mostly
provisioning tests rather than work anyone paid for.

Publishing on a timer matters because the index is a static file with no
producer behind it: before this it was regenerated by hand, and the public feed
silently fell eleven days behind the database.

## Start and inspect

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml up -d
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml ps
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml logs --tail 200
```

Run one lifecycle worker and one settlement worker. Before funded use, verify
the deployed image digests, KMS permissions, database backups, restore
procedure, Vast account limits and the complete capped lease lifecycle.

Confirm the gateway is reachable before enrolling a node:

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml exec access-gateway \
  curl --fail --silent http://127.0.0.1:8081/healthz
openssl s_client -connect "$PRISM_DOMAIN:7443" -servername "$PRISM_DOMAIN" </dev/null
```

The tunnel requires a client certificate, so `s_client` without one is expected
to be rejected during the handshake; a refused connection instead means the
port is closed or the service is down.
