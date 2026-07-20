# Vast launch path

Prism can launch with one bonded broker node backed by disposable Vast
instances. This is a separate execution mode, not an emulation of the physical
VFIO/Kata node contract.

The broker advertises one L40S at 222 USDG base units per second, or $0.7992 per
hour. The lifecycle worker only advertises capacity while a verified, rentable
L40S with at least 45 GB of VRAM is available for no more than $0.64 per hour.
At that ceiling, the spread is $0.1592 per rented hour before chain fees,
control-plane infrastructure, failed starts and refunds.

Cloud leases use direct SSH. They do not use the Prism tunnel, Kata, VFIO or
Jupyter relay. The existing physical-node path is unchanged.

## One-time broker setup

Build the CLI and create a dedicated broker identity on the control host:

```sh
cargo build --release -p prismd
install -d -m 0700 /var/lib/prism-cloud
target/release/prismd create-identity \
  --path /var/lib/prism-cloud/device.json
```

Record the returned node ID as `PRISM_VAST_NODE_ID`. Keep the identity file
mode `0600`.

The operator wallet needs Robinhood Chain gas and at least 100 USDG. Register
the identity onchain at the fixed retail rate:

```sh
export PRISM_VAST_NODE_ID=0x...
export PRISM_NODE_REGISTRY_ADDRESS=0x...
export PRISM_CLOUD_OPERATOR_KEY=0x...
forge script contracts/script/RegisterCloudBroker.s.sol:RegisterCloudBroker \
  --rpc-url "$PRISM_RPC_URL" \
  --broadcast \
  --slow
unset PRISM_CLOUD_OPERATOR_KEY
```

Enroll the same identity in the control plane:

```sh
target/release/prismd enroll \
  --identity /var/lib/prism-cloud/device.json \
  --control-plane https://prism.example \
  --operator-wallet 0x... \
  --payout-wallet 0x... \
  --gpu-model L40S \
  --vram-mib 46068 \
  --cuda-major 12 \
  --rate-per-second 222 \
  --benchmark-score 10000
```

The control-plane and onchain operator, payout, rate and device identity must
match. Do not start the physical node command or tunnel services for this
broker identity.

## Vast credentials

Use a scoped Vast key with only `misc`, `instance_read` and `instance_write`.
The worker needs offer search, instance list/show/create/destroy and SSH-key
attachment. It does not need billing or account-write permissions.

Write the key to the ignored Compose secret:

```sh
install -d -m 0700 deploy/lightsail/secrets
install -m 0600 /dev/null deploy/lightsail/secrets/vast-api-key
```

Paste the key into that file without adding it to `.env` or the repository.
Set the broker node ID in `deploy/lightsail/.env`. Keep
`PRISM_VAST_MAX_HOURLY_MICROS=640000` unless the retail rate changes.

## Runtime behavior

The lifecycle worker:

1. searches verified, rentable, single-GPU L40S offers every 30 seconds;
2. removes the broker offer when nothing meets the hard cost ceiling;
3. reconciles instance creation by the unique lease label before creating;
4. creates an `ssh_direct` instance from the renter's pinned OCI image;
5. attaches only the renter's submitted public SSH key;
6. validates the running GPU, VRAM, provider verification, actual hourly cost
   and SSH endpoint before starting paid access onchain;
7. destroys the instance before closing or refunding the lease;
8. settles from explicit Vast execution evidence instead of fabricating signed
   physical-node telemetry.

Instance and offer IDs, costs and lifecycle state are durable in PostgreSQL.
The Vast key remains worker-side and is never returned by the control plane.

## Launch limitations

- Capacity is one concurrent lease because the broker is one registered node.
- Vast is an upstream dependency and can remove an offer between quote and
  provisioning. The ten-minute escrow provision timeout remains the refund
  boundary.
- Provider-reported running state, instance identity and cost are used as cloud
  execution evidence. This path does not produce hardware-rooted VFIO/Kata
  attestation.
- The $0.1592 hourly spread is gross margin, not net profit. Gas, the broker
  bond, control-plane hosting, support and failed provisioning consume it.
