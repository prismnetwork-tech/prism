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
addresses, RPC URL, KMS key identifiers and bonded Vast broker node ID required
by `compose.yml`. The gateway additionally needs `PRISM_ACCESS_GATEWAY_IMAGE`,
`PRISM_GATEWAY_HMAC_KEY`, `PRISM_GATEWAY_CONTROL_TOKEN` and
`PRISM_REDIS_PASSWORD`.

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

Validate the fully resolved configuration before changing the host:

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml config --quiet
```

TCP 80, 443, 7443 and 7444 should be public: 7443 is the node tunnel and 7444
is the renter relay that `PRISM_PUBLIC_RELAY_PORT` already advertises. Restrict
SSH to an operator allowlist and do not expose PostgreSQL, Valkey, the
control-plane container port or the gateway's 8081 control port.

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
