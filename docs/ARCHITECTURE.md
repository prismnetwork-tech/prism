# Prism Network architecture

## Trust boundaries

The browser obtains a Privy session, links a payment wallet, and submits escrow
transactions directly to Robinhood Chain. It does not receive settlement keys,
node device keys, gateway control tokens, or provider network addresses.

The control plane schedules only nodes that are bonded onchain, recently
heartbeating, independently observed by the gateway, compatible with the
requested image, and below both the node and network concurrency limits. The
control plane never receives terminal or file data. Its authoritative offer,
telemetry, account-control and quote state lives in PostgreSQL. The process only
permits its in-memory store behind an explicit local-development switch.

RDS manages its master password. The control plane receives a separate,
least-privilege database URL from Secrets Manager; neither credential is kept
in Terraform variables or application configuration.

The gateway accepts outbound node mTLS tunnels, records fresh tunnel
observations independently, and routes short-lived lease-bound SSH or Jupyter
grants through those tunnels. Revocation terminates active relay sessions. It
is the sole service allowed to confirm that a CUDA-ready workspace has usable
access before billing starts onchain. Active probes consume fresh outbound
tunnels for both SSH and Jupyter before the lifecycle worker submits
`startAccess`. The grant is issued only after that transaction reaches
finality.

The lifecycle worker owns authoritative state transitions after provisioning.
It submits `startAccess`, rotates and revokes grants, closes interrupted or
expired leases, assembles settlement evidence, schedules finalization and
publishes terminal receipt records. Every chain action persists signed
transaction bytes, nonce, hash and canonical confirmation block in PostgreSQL.

The metering worker reconciles signed node telemetry with gateway timing,
signs the EIP-712 proposal and chain transaction through a non-exportable AWS
KMS secp256k1 key, and keeps a crash-recoverable submission outbox. The proof
worker independently verifies terminal chain events, publishes immutable
artifacts and delivers the completed UTC-day X digest through a separate
retrying outbox.

The deployment uses a Safe-controlled 48-hour timelock for configuration.
The Safe can pause escrow immediately and resolve a disputed settlement, but
cannot bypass the delay for routine configuration or unpausing.

## Primary interfaces

- `POST /v1/nodes/enroll` registers a device-signed enrollment after checking
  the operator, payout wallet, bond and device hash in the registry.
- `POST /v1/nodes/{node_id}/heartbeat` accepts a device-signed, monotonic
  status update.
- `GET /v1/offers` returns bonded, online, compatible public-image offers.
- `POST /v1/leases/match` returns a five-minute quote; the wallet creates the
  actual escrow directly onchain with a quote-derived client reference.
- `POST /v1/leases/confirm` verifies the finalized quote-bound funding event,
  records the renter wallet and queues the node launch.
- `GET /v1/leases` returns the authenticated account's indexed leases.
- `GET /v1/leases/{lease_id}/access` returns the active account-owned,
  encrypted-at-rest access grant and Jupyter credential.
- `POST /v1/nodes/{node_id}/commands/next` leases a launch command to the
  device after verifying a fresh device signature.
- `POST /v1/nodes/{node_id}/commands/{command_id}/report` records signed
  readiness, completion or failure without accepting replayed requests.
- `POST /v1/grants` is internal-only and creates a bounded SSH/Jupyter grant.
- `POST /v1/probes` is internal-only and confirms both workspace access paths
  through fresh node tunnels.
- `GET /v1/access` validates a bearer grant before tunnel routing.
- `DELETE /v1/grants/{token_id}` revokes a grant through the internal control
  credential.

The control plane must be deployed behind a Privy-verifying auth boundary. The
development identity header is explicitly disabled unless
`PRISM_ALLOW_DEVELOPMENT_AUTH=1` is set.

## Runtime lifecycle

1. The supplier posts a USDG bond and registers a device hash onchain.
2. The renter receives a quote and deposits the maximum USDG cost.
3. The control plane confirms the quote-bound funding event and the node
   command supervisor launches a Kata sandbox with the reserved VFIO group.
4. The gateway confirms CUDA plus SSH/Jupyter readiness and starts billing.
5. Duration expiry, stale node telemetry, stale tunnel state or a signed node
   completion closes access and creates a durable settlement job.
6. The attestor proposes signed metering. After 24 hours without dispute, the
   lifecycle worker finalizes payment/refund and queues public proof.
