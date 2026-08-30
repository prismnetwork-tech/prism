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

Use a scoped Vast key with only `misc`, `user_read`, `instance_read` and `instance_write`.
The worker needs offer search, instance list/show/create/destroy and SSH-key
attachment, plus the read-only current balance used for admission. It does not
need billing or account-write permissions.

Write the key to the ignored Compose secret:

```sh
install -d -m 0700 deploy/lightsail/secrets
install -m 0600 /dev/null deploy/lightsail/secrets/vast-api-key
```

Paste the key into that file without adding it to `.env` or the repository.
Set the broker node ID in `deploy/lightsail/.env`. Keep
`PRISM_VAST_MAX_HOURLY_MICROS=640000` unless the retail rate changes.
Keep `PRISM_VAST_CREDIT_PER_SLOT_MICROS=5000000` unless the maximum provider
rate or six-hour lease ceiling changes.

## Runtime behavior

The lifecycle worker:

1. reserves fresh account balance for every committed and advertised slot;
2. searches verified, rentable, single-GPU L40S offers every 30 seconds;
3. removes the broker offer when funding or supply does not meet policy;
4. reconciles instance creation by the unique lease label before creating;
5. creates an `ssh_direct` instance from the renter's pinned OCI image;
6. attaches only the renter's submitted public SSH key;
7. validates the running GPU, VRAM, provider verification, actual hourly cost
   and SSH endpoint before starting paid access onchain;
8. destroys an active instance when access closes and queues independent,
   retrying cleanup after a refund so provider downtime cannot block fund release;
9. settles from explicit Vast execution evidence instead of fabricating signed
   physical-node telemetry.

Instance and offer IDs, costs and lifecycle state are durable in PostgreSQL.
The Vast key remains worker-side and is never returned by the control plane.

## Reset a latched provider breaker

`auth_blocked` and `permanent_blocked` are fail-closed states. A successful
balance read does not clear them, including during an overlapping rollout.
Inspect the state first:

```sql
SELECT provider, state, failure_class, balance_micros, blocked_at,
       observed_at, consecutive_failures
FROM cloud_provider_state
WHERE provider = 'vast';
```

For `auth_blocked`, rotate or correct the scoped key and verify account lookup,
offer search and instance-list access outside the worker. For
`permanent_blocked`, correct the request, endpoint, response-schema or policy
error shown in the worker logs. Do not reset while the cause is unknown, and
never set the row to `healthy` manually.

After the provider checks succeed, keep capacity closed and remove only the
latched observation under the same lock used by matching and confirmation:

```sql
BEGIN;
SELECT pg_advisory_xact_lock(4663);
UPDATE cloud_capacity
SET available = FALSE, updated_at = NOW()
WHERE provider = 'vast';
DELETE FROM cloud_provider_state
WHERE provider = 'vast'
  AND state IN ('auth_blocked', 'permanent_blocked');
COMMIT;
```

Within 30 seconds the lifecycle worker must recreate the row from a fresh
provider observation. Reopen service only when the state is `healthy`, its
`observed_at` is less than 90 seconds old, and the number of available rows is
no greater than the funded-slot calculation. If the row latches again, leave
capacity closed and fix the new failure rather than repeating the reset.

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
