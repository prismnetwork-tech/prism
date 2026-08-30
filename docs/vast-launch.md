# Vast launch path

Prism can launch with bonded broker nodes backed by disposable Vast instances.
This is a separate execution mode, not an emulation of the physical VFIO/Kata
node contract.

The default broker rate is 222 USDG base units per second, or $0.7992 per hour.
The lifecycle worker advertises a slot only while a verified, rentable L40S or
RTX 6000 Ada with at least 45 GB of VRAM is available for no more than $0.64 per
hour and the Vast balance covers the configured reserve. At that ceiling, the
spread is $0.1592 per rented hour before chain fees, control-plane
infrastructure, failed starts and refunds.

Cloud leases use direct SSH. They do not use the Prism tunnel, Kata, VFIO or
Jupyter relay. The physical-node path is unchanged.

## One-time broker setup

Build the CLI and create a dedicated broker identity on the control host:

```sh
cargo build --release -p prismd
install -d -m 0700 /var/lib/prism-cloud
target/release/prismd create-identity \
  --path /var/lib/prism-cloud/device.json
```

Record the returned node ID in the complete `PRISM_VAST_NODE_IDS` list. A
single-node deployment may also set `PRISM_VAST_NODE_ID`, but operational and
historical-drain work must use the full list. Keep the identity file mode
`0600`.

The operator wallet needs Robinhood Chain gas and at least 100 USDG. Register
each broker identity onchain at the fixed retail rate:

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
match. Do not start the physical node command or tunnel services for a cloud
broker identity.

## Vast credentials

Use a scoped Vast key with only `misc`, `user_read`, `instance_read` and
`instance_write`. The worker needs offer search, instance list/show/create and
destroy, SSH-key attachment, and the read-only current balance used for
admission. It does not need billing or account-write permissions.

Write the key to the ignored Compose secret:

```sh
install -d -m 0700 deploy/lightsail/secrets
install -m 0600 /dev/null deploy/lightsail/secrets/vast-api-key
```

Paste the key into that file without adding it to `.env` or the repository. Set
the complete broker node list in the deployment environment. Keep
`PRISM_VAST_MAX_HOURLY_MICROS=640000` unless the retail rate changes. Keep
`PRISM_VAST_CREDIT_PER_SLOT_MICROS=5000000` unless the maximum provider rate or
six-hour lease ceiling changes.

## Runtime behavior

The lifecycle worker:

1. binds to one normalized escrow generation at startup;
2. reserves fresh account balance for every committed and advertised slot;
3. searches verified, rentable, single-GPU L40S and RTX 6000 Ada offers every
   30 seconds;
4. removes all Vast capacity when funding, supply or provider health does not
   meet policy;
5. reconciles instance creation by the unique lease label before creating;
6. creates an `ssh_direct` instance from the renter's digest-pinned OCI image;
7. attaches only the managed runner key or renter-submitted public SSH key;
8. validates the running GPU, VRAM, verification, actual hourly cost and pinned
   SSH host key before starting paid access onchain;
9. records every signed lifecycle transaction in immutable attempt history,
   reconciles late outcomes before resigning, and adopts an escrow outcome that
   landed after a worker lost its response;
10. refunds or finalizes independently of provider cleanup, then retries
    `cleanup_cloud` until every current, prepared or lease-labelled instance is
    destroyed; and
11. settles managed work from exact provider and gateway-signed execution
    evidence rather than fabricating physical-node telemetry.

Lifecycle financial actions are claimed only for the configured escrow.
Cleanup is intentionally cross-generation: provider billing is physical state,
not escrow state. The settlement and repro workers are separately bound to the
same configured generation, and all three use monotonic claim generations so a
stale worker cannot overwrite a newer claim.

Instance IDs, offer IDs, hourly cost, host-key commitment, GPU observation,
chain attempt history and cleanup state are durable in PostgreSQL. The Vast key
remains worker-side and is never returned by the control plane.

## Escrow generations and shared physical capacity

An escrow address plus its chain lease id identifies financial work. Vast
capacity does not have that shape. `cloud_provider_state`, `cloud_capacity`,
broker node IDs, the provider account balance and the physical instances are
global and non-generation-keyed.

Do not run historical and current lifecycle workers as two ordinary supply
owners. Both would refresh the same provider row, advertise the same node slots,
reserve the same balance, and inspect or destroy instances from one account.
Escrow filtering prevents the wrong chain call; it does not partition physical
GPUs. A historical generation may run only inside the maintenance drain below,
with admissions stopped, both escrows paused, one latched provider breaker and
the full Vast node list supplied to every lifecycle process.

## Historical-generation maintenance drain

Migration 0028 makes this drain executable. `operator_maintenance` is a durable
provider latch: successful balance observations and provider failures cannot
replace it, marketplace reads require `healthy`, and the lifecycle worker
refuses to create a Vast instance while the latch exists. Label adoption,
instance observation and destruction, `cleanup_cloud`, and generation-fenced
financial reconciliation remain available.

Rehearse the procedure against a restored production snapshot and a provider
sandbox. Record both escrow addresses, every broker node ID, worker image
digest, database backup and provider-instance inventory before starting.

1. **Stop admissions.** Drain in-flight HTTP requests, stop the control plane,
   and keep it stopped until the final step.
2. **Pause both escrows.** Verify the historical and current escrow each report
   `paused = true` at the expected addresses and chain ID. Pause blocks new
   lease creation and access start while close, refund, settlement and finalize
   remain available for the drain.
3. **Stop every normal worker and the static proof publisher.** Wait through the
   worker stop grace periods, verify no process still owns a claim, disable the
   static proof timer and verify no publisher is writing artifacts. Normal
   lifecycle, settlement and repro services remain stopped throughout the
   drain; start only the explicit generation-specific processes named below.
4. **Latch maintenance under lock `4663`.** Run the following as one transaction.
   It refuses to hide an unresolved auth or permanent breaker, writes exactly
   the maintenance state and reason, and closes all Vast capacity atomically:

   ```sql
   BEGIN;
   SELECT pg_advisory_xact_lock(4663);

   DO $maintenance$
   DECLARE
       current_state TEXT;
   BEGIN
       SELECT state INTO current_state
       FROM cloud_provider_state
       WHERE provider = 'vast'
       FOR UPDATE;

       IF current_state IN ('auth_blocked', 'permanent_blocked') THEN
           RAISE EXCEPTION
               'refusing to hide latched Vast provider state: %', current_state;
       END IF;

       INSERT INTO cloud_provider_state (
           provider, state, failure_class, blocked_at, observed_at,
           consecutive_failures, updated_at
       ) VALUES (
           'vast', 'operator_maintenance', 'operator_maintenance',
           NOW(), NOW(), 0, NOW()
       )
       ON CONFLICT (provider) DO UPDATE SET
           state = 'operator_maintenance',
           failure_class = 'operator_maintenance',
           blocked_at = CASE
               WHEN cloud_provider_state.state = 'operator_maintenance'
               THEN COALESCE(cloud_provider_state.blocked_at, NOW())
               ELSE NOW()
           END,
           observed_at = NOW(),
           consecutive_failures = 0,
           updated_at = NOW()
       WHERE cloud_provider_state.state NOT IN (
           'auth_blocked', 'permanent_blocked'
       );

       IF NOT FOUND THEN
           RAISE EXCEPTION 'Vast maintenance latch was not written';
       END IF;
   END
   $maintenance$;

   UPDATE cloud_capacity
   SET available = FALSE, updated_at = NOW()
   WHERE provider = 'vast';
   COMMIT;
   ```

   Verify the provider row is exactly `operator_maintenance` with
   `failure_class = 'operator_maintenance'`, and verify no Vast capacity row is
   available. Do not emulate maintenance by deleting provider health.
5. **Drain the historical generation first.** Explicitly start only its reviewed
   hardened lifecycle, settlement and repro processes, all bound to the
   historical escrow. Supply the complete `PRISM_VAST_NODE_IDS` list. The latch
   blocks advertise and provider create, but permits adoption, observation,
   destruction, cleanup and financial completion. Require no claimable
   financial action, settlement job or managed repro job; reconcile retained
   transaction attempts to finality or an explicit operator conflict; and
   require every provider instance and lease label to be destroyed or
   deliberately quarantined. Then stop these three processes permanently and
   keep the historical escrow paused.
6. **Drain the current generation second.** Only after the historical processes
   are stopped, explicitly start the same hardened processes bound to the
   current escrow. Use the identical full node list and the same drain criteria.
   Stop them when the current drain is complete. Never run the two generation
   sets concurrently.
7. **Perform proof cutover.** Inspect all migration-0027 quarantine rows. Keep
   the static timer disabled, start exactly one database proof worker, require
   advisory lock `4663003`, and let it verify pending rows against each row's
   exact escrow, chain lease id, transaction finality and canonical block.
   Verify the rebuilt index contains only `published` rows, all pending rows
   have resolved, and quarantined documents remain preserved and absent. Never
   run the static bridge and Rust proof worker concurrently.
8. **Clear only maintenance under lock `4663`.** Keep all lifecycle workers
   stopped and run this transaction. It aborts when the row is absent or carries
   any state other than `operator_maintenance`, leaves capacity closed, and
   removes exactly one maintenance row:

   ```sql
   BEGIN;
   SELECT pg_advisory_xact_lock(4663);

   UPDATE cloud_capacity
   SET available = FALSE, updated_at = NOW()
   WHERE provider = 'vast';

   DO $maintenance_clear$
   DECLARE
       current_state TEXT;
       removed INTEGER;
   BEGIN
       SELECT state INTO current_state
       FROM cloud_provider_state
       WHERE provider = 'vast'
       FOR UPDATE;

       IF current_state IS DISTINCT FROM 'operator_maintenance' THEN
           RAISE EXCEPTION
               'refusing to clear Vast provider state: %',
               COALESCE(current_state, '<missing>');
       END IF;

       DELETE FROM cloud_provider_state
       WHERE provider = 'vast' AND state = 'operator_maintenance';
       GET DIAGNOSTICS removed = ROW_COUNT;
       IF removed <> 1 THEN
           RAISE EXCEPTION
               'expected one Vast maintenance row, removed %', removed;
       END IF;
   END
   $maintenance_clear$;
   COMMIT;
   ```

   Never include `operator_maintenance` in the generic auth/permanent breaker
   reset below.
9. **Let one current owner rebuild health.** Start only the normal
   current-generation lifecycle worker with the full node list. It must perform
   fresh balance, offer and instance observations and recreate `healthy`; never
   write `healthy` by hand. Require `observed_at` to be less than 90 seconds old,
   funded-slot bounds, no historical instances and the expected available-node
   set. With the control plane still stopped, start exactly one normal
   current-generation settlement worker and one repro worker from the same
   release. Require the settlement startup audit to have no pending generation
   binding, nonce conflict or current cursor attached to quarantined bytes, and
   verify all three workers recorded the expected build SHA.
10. **Reopen current service and start control last.** Unpause only the current
    escrow after provider health and worker versions pass. Keep the historical
    escrow paused. Start the control plane last and verify a read-only capacity
    call before accepting a wallet approval.

Abort the drain if either escrow identity, chain ID, signer, full node list,
provider inventory, breaker state or proof identity differs from the recorded
plan. Restoring normal concurrent supply is not a fallback; the shared capacity
tables and physical account make it unsafe.

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
`permanent_blocked`, correct the request, endpoint, response schema or policy
error shown in the worker logs. Do not reset while the cause is unknown, and
never set the row to `healthy` manually.

After provider checks succeed, keep capacity closed and remove only the exact
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

Use this reset only for the inspected state; the maintenance drain has the
stricter exact-state clearing rule above. Within 30 seconds the sole current
lifecycle owner must recreate provider state from a fresh observation. Reopen
service only when state is `healthy`, `observed_at` is less than 90 seconds old,
and available rows do not exceed the funded-slot calculation. If the row
latches again, keep capacity closed and correct the cause.

## Proof cutover constraints

Migration 0027 binds each proof receipt to its database lease, lowercase escrow
address and decimal chain lease id. The static bridge may publish valid pending
or published finalized rows during migration, but it excludes quarantine and
recomputes the legacy hash. The database proof worker verifies pending rows on
chain, publishes only verified rows, quarantines identity or canonical-chain
failures, and builds its index only from `published`. The migration guard makes
receipt identity and evidence immutable after insertion. It permits only
pending-to-published and pending-or-published-to-quarantined transitions; no
published or quarantined row can be rolled back and edited.

The worker stages verified receipts and content-addressed pages, then replaces
the index only after a locked second read proves the full staged set still
matches and no pending rows remain. RPC deferrals and backlogs larger than one
1,000-row batch preserve the existing index. A quarantine revokes the direct
receipt artifact even while that index is waiting for other pending rows.

Stop and disable the static timer before starting the database worker or new
receipt producers. Inspect quarantine before release. A quarantined signed
document is evidence of a mismatch, not an editing task; preserve it and fix the
source identity if a replacement artifact is warranted.

## Launch limitations

- Concurrency is bounded by registered broker nodes, funded reserves and fresh
  qualifying offers, not merely by provider inventory.
- Vast can remove an offer between quote and provisioning. The ten-minute
  escrow provision timeout remains the refund boundary.
- Provider running state, instance identity, actual cost and pinned SSH host key
  are managed-cloud execution evidence. They are not hardware-rooted VFIO/Kata
  attestation.
- The $0.1592 hourly spread is gross margin, not net profit. Gas, bonds,
  infrastructure, support, failed provisioning and cleanup consume it.
- Production remains closed until the private RPC, funded Vast reserve, paid
  canary, npm publication and approved-alert gates in the production audit are
  complete.
