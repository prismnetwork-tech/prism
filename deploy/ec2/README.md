# EC2 Vast launch deployment

This is the lean single-host topology for the Vast-backed launch path. It runs
PostgreSQL, the Rust control plane, lifecycle and settlement workers, and a
Caddy TLS edge on EC2. The public web application remains on Render and is
proxied by Caddy for `prismnetwork.tech`.

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

Intentionally excluded:

- Physical-node access gateway and mTLS relay
- Valkey-backed temporary access state
- Jupyter access
- Proof and X publishing worker
- Operations monitor and Prometheus
- High availability or managed backups

This topology therefore supports the disposable Vast direct-SSH path only. It
must not be described as a Kata/VFIO deployment.

## Configuration

Create these untracked files:

```text
deploy/ec2/.env
deploy/ec2/secrets/vast-api-key
deploy/ec2/secrets/tls/ca.crt
deploy/ec2/secrets/tls/ca.key
```

The environment must provide the image references, domain and ACME email,
database and service secrets, operator subjects, deployed registry and escrow
addresses, RPC URL, KMS key identifiers and bonded Vast broker node ID required
by `compose.yml`.

Validate the fully resolved configuration before changing the host:

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml config --quiet
```

Only TCP 80 and 443 should be public. Restrict SSH to an operator allowlist and
do not expose PostgreSQL or the control-plane container port.

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

The mainnet escrow is currently paused and no funded canary has completed.
