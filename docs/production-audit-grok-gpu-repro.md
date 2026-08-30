# Production Audit: Grok GPU Repro

## Release decision

The reviewed release-candidate schema ends at migration 0028. The bot-facing
contract preserves human wallet approval, pins the OCI image by digest, caps
duration and escrow, and returns capability-scoped status, evidence and
verification. The hosted path now fences work by escrow generation, preserves
every signed chain attempt, resolves signer/nonce ownership before settlement,
and publishes proofs only after exact chain-identity verification.

The product is still **not releasable**. Production needs a private Robinhood
Chain RPC endpoint, enough Vast credit for the configured reserve, one paid
end-to-end canary with a verified receipt and cleanup, npm version 0.2.0
published by `winterstacks`, and an explicitly approved alert destination.
Until those gates pass, managed capacity must remain unavailable and the npm
package must remain unpublished.

## Frozen authority and identity model

A database `lease_id` is only an internal key. Chain identity is the tuple
`(escrow_address, chain_lease_id)`, because each escrow deployment owns its own
counter. The control plane stores both identities and receipt publication adds
the escrow address and chain lease id without changing the legacy receipt hash.

Every chain-capable worker is bound at startup to one normalized
`PRISM_LEASE_ESCROW_ADDRESS`:

- The lifecycle worker creates and claims financial actions only for leases
  from that escrow. `cleanup_cloud` is deliberately generation-independent,
  because a provider machine keeps billing regardless of which escrow created
  its lease.
- The settlement worker claims, renews, signs, submits and confirms only when
  the lease, stored evidence, configured escrow and chain lease id still match.
- The repro worker claims and mutates managed jobs only through a lease from
  its configured escrow, and every external-operation heartbeat repeats that
  fence.

Lifecycle, settlement and repro claims also carry monotonic claim generations.
A worker that loses or outlives its claim cannot write a provider binding,
signed transaction, report, retry or terminal outcome over the newer owner.

This fencing makes a generation-specific drain possible. It does **not** make
normal old-generation and current-generation supply safe to run concurrently.
`cloud_provider_state`, `cloud_capacity`, the Vast account, provider instances
and broker node slots are global physical resources; they are not keyed by
escrow generation. Two normal lifecycle workers can overwrite the same health
and capacity rows, count the same funded reserve, advertise the same node, or
race instance creation and cleanup. Historical work therefore requires the
maintenance drain in [Vast launch path](vast-launch.md#historical-generation-maintenance-drain),
not a second ordinary production stack.

## Durable chain attempts and late adoption

Migration 0025 adds append-only `lifecycle_transaction_attempts`. The table
preserves the action, claim generation, nonce, raw signed bytes, transaction
hash, submission count and finality evidence for every prepared lifecycle
transaction. Identity and signed bytes are immutable; submission counts move
one step at a time; outcome states move only forward. Existing signed outbox
transactions are backfilled before the hardened worker starts.

The lifecycle outbox is now a cursor to the selected attempt, not the only copy
of financial evidence. Before resigning, the worker reconciles every preserved
attempt. A transaction that confirms after it was superseded can still become
canonical. An observed pending attempt is retained instead of signing around
it. If the escrow has already started, closed, finalized or refunded a lease,
the worker adopts that chain outcome into local state. A settled outcome with no
observed settling transaction is adopted without inventing a public receipt.

Migration 0026 applies the same model to settlement. Each
`settlement_transaction_attempts` row binds immutable signed bytes and proposal
to internal lease id, escrow address, chain lease id, claim generation, signer
and nonce. The worker records a submission before broadcasting, can safely
resubmit the exact bytes after a lost RPC response, and reconciles all retained
attempts before replacing an expired or unlandable proposal. Pending finality
polls do not consume the job's retry budget. A shallow reverted receipt remains
pending until the configured confirmation threshold makes the outcome final.

The migration handles old partial cursors before installing the strict job
trigger. A proposal-only cursor in `queued`, `processing` or `failed` with no
transaction or confirmation evidence is copied verbatim into the immutable
`settlement_legacy_partial_cursors` archive, cleared, and requeued when active.
Any partial cursor containing transaction or confirmation evidence, a submitted
marker, or a later settlement state aborts migration 0026 before schema changes;
it requires operator review because the migration cannot prove it was unsent.
The permanent job trigger also requires `proposed`, `disputed` and `finalized`
rows to retain the full captured transaction cursor and both confirmation
fields, so a later state cannot become silently unclaimable.

Historical bytes do not become trusted merely because migration copied them.
They enter as `pending`; hardened startup recomputes the raw transaction hash,
recovers its signer, requires chain 4663, checks destination and stored nonce,
and compares exact calldata, chain lease, proposal, usage, receipt hash and
attestation signature against the lease generation. A legacy receipt missing
only the new escrow and chain-lease fields is normalized after those checks,
while its legacy receipt hash remains unchanged. Any other mismatch is retained
as `quarantined` and is excluded from reconciliation, adoption, nonce reuse and
broadcast. If such an attempt is the current job cursor, startup clears only the
job's cursor and requeues active work; the immutable attempt remains available
for review while a newly verified attempt can supersede it. This prevents an
invalid earliest cursor from blocking the claim loop. A quarantined cursor on a
job already marked `proposed`, `disputed` or `finalized` is cleared and the job
is marked `failed` with an explicit audit error rather than left looking safely
settled; its chain state and retained attempt require operator reconciliation.

A pending attempt is reusable only while its signed deadline remains more than
the submission safety margin away. A transaction already known to the RPC does
not bypass that check: stale bytes are retained and superseded by a freshly
signed same-nonce replacement. A transaction that already reached finality is
still adopted as chain truth but is never rebroadcast after its deadline.

A structurally undecodable historical transaction cannot yield an honest signer
or nonce. It is therefore retained as `quarantined` with
`invalid_signed_transaction`; its signer remains null and its nonce reservation
remains migration-pending rather than inventing ownership. The job-cursor guard
requires a verified binding, reserved nonce and matching durable reservation,
so neither the current nor a historical worker can adopt or send those bytes.
The operational cost is manual review: an unsupported transaction type that was
privately submitted before migration cannot be placed in the known nonce graph,
although expected settlement workers produced only the validated legacy form.
Do not delete or relabel the preserved row.

### Historical settlement signer and nonce ownership

`settlement_signer_nonce_reservations` gives each `(signer_address,
transaction_nonce)` one lease owner. Startup recovers the signer from every
historical raw transaction and verifies that the signed nonce equals the stored
nonce before enabling settlement:

- Replacements for one lease share one reservation.
- If several leases historically used the same signer and nonce, a single
  uniquely confirmed lease becomes canonical. Its reservation may be corrected
  once, with the previous owner and reason retained; the other attempts become
  `noncanonical`.
- If no lease is confirmed, or more than one is confirmed, the attempts become
  `conflict` and the worker fails closed for operator resolution.
- New attempts must enter as `reserved`; `pending` exists only for migration
  backfill. Noncanonical and conflict attempts cannot be submitted.

The reservation and attempt tables are append-only apart from their narrowly
defined forward annotations. Deleting collision evidence or manually assigning
a nonce owner is not a recovery procedure. Generation normalization and its job
cursor update are committed only after nonce resolution succeeds. On a conflict,
unsafe current cursors are detached in the same transaction as the conflict
annotation, so repeated startup reports the same conflict instead of wedging on
an immutable half-normalized attempt. The legal recovery path is to verify one
preserved transaction against the chain, append its exact confirmation block
and block hash to that attempt, and restart. Only a single confirmed lease owner
allows the trigger and worker to move `conflict` attempts to `reserved` and
`noncanonical`; zero or multiple confirmed owners remain blocked.

## Exact proof identity, quarantine and publication

Migration 0027 makes `(lease_id, escrow_address, chain_lease_id)` a referenced
identity and stores the escrow address, chain lease id and publication state on
each proof receipt. A publishable document must carry:

- lowercase `escrow_address` equal to the receipt row and lease row;
- decimal `chain_lease_id` equal to the receipt row and lease row; and
- legacy `lease_id` equal to that onchain chain lease id, not the database key.

The migration backfills exact identity. A legacy receipt whose document points
at a different chain lease or escrow is preserved but moved to `quarantined`,
given a reason and stripped of `published_at`. `pending`, `published` and
`quarantined` are exclusive states; only `published` may have `published_at`,
and only `quarantined` may have a quarantine reason.

The static publisher is a bridge during migration. It rejects quarantined rows,
checks the joined lease identity, recomputes the legacy receipt hash and may
include valid pending or published finalized rows so migration 0027 does not
erase the existing feed. The Rust database proof worker is the destination. It
holds advisory lock `4663003`, verifies each pending row against its exact
escrow, chain lease id, transaction receipt, confirmation depth and canonical
block, quarantines malformed or mismatched rows, and builds public artifacts
and daily digests exclusively from published rows.

Cutover must stop and disable the static timer before the Rust proof worker or
new receipt producers start. Inspect every quarantined row, run only one
database proof worker, wait for pending rows to resolve, verify the rebuilt
public index, then leave the static publisher disabled. Never edit a
quarantined signed document to make it publishable; fix the source identity or
keep the artifact excluded.

## Provider admission and cleanup

Provider admission remains fail closed:

- fresh Vast balance funds every committed and advertised slot using the
  configured reserve;
- fresh verified offers must satisfy GPU, VRAM and hourly-cost policy;
- account-scoped auth and permanent failures latch the provider breaker;
- migration 0028's operator-maintenance latch blocks Vast advertisement and
  instance creation without blocking cleanup or financial reconciliation;
- credit and transient failures keep all Vast capacity unavailable until a
  fresh successful observation; and
- refund or finalization completes before independent `cleanup_cloud` retries,
  so provider downtime cannot hold customer escrow hostage.

Cloud cleanup intentionally considers all escrow generations. Capacity cannot
return while a provider instance is still known or ambiguously labelled, even
if its lease belongs to a superseded escrow.

## Rollback contract

Migrations 0021 through 0028 are forward-only. A production rollback must use a
prebuilt compatibility bundle that embeds byte-identical copies of every
applied migration so SQLx accepts the database. It must retain generation
fences, attempt-history semantics and the operator-maintenance latch in any
financial worker that remains running. If a compatible worker is unavailable,
keep that worker stopped; do not restart a pre-hardening signer against the
migrated database.

Rollback restores application behavior and image references, not schema. Never
delete attempt, nonce-reservation or proof-quarantine rows, never run a down
migration, and never rewrite a migration checksum. The compatibility bundle,
database backup and restore path must be built and rehearsed before migration
0025 is allowed onto production.

## Remaining hard release blockers

- [ ] **Private RPC:** configure a production Robinhood Chain endpoint for
  financial workers and the public read path, validate chain ID at startup, and
  exercise retry and ambiguous-response behavior. The public endpoint is not a
  sufficient sole dependency.
- [ ] **Vast funding:** fund the scoped broker account for at least the configured
  per-slot reserve, then require a fresh `healthy` provider state and available
  rows no greater than the funded-slot calculation.
- [ ] **Paid canary:** after explicit human review of network, asset, executor,
  duration, image digest and maximum escrow, run one paid pinned repro. The
  runner reaches `settled` once it has verified the CUDA success marker, the
  gateway-signed report binding, immutable evidence, settlement finality and
  public receipt identity. Provider destruction is not on the read-only MCP
  surface, so the run reaches `complete` only after `repro:verify-cleanup`
  proves the instance is absent from the lifecycle worker's Vast account.
- [ ] **npm publication:** publish version 0.2.0 as `winterstacks` only after the
  paid canary passes, install it from npm into Grok Build and run the forward
  test against all six live MCP tools.
- [ ] **Approved alerts:** review the destination and message side effects before
  enabling durable alerts for provider breaker state, low balance, stale
  capacity, cleanup backlog, submitted chain attempts, settlement conflicts and
  proof lag. The existing timer must not be enabled against an unapproved chat.

## Deployment gates

1. Freeze and commit the release candidate; record exact migration checksums for
   0021 through 0028.
2. Rehearse migrations 0001 through 0028 on disposable PostgreSQL, including
   signer recovery, nonce-collision resolution, proof quarantine and the exact
   operator-maintenance latch and clear transactions.
3. Build and test the forward-compatible rollback bundle before production
   migration.
4. Stop the control plane, lifecycle, repro, settlement and proof workers, and
   disable the static proof publisher before applying migration 0026. Run the
   new control image in migration-only mode; never restart a pre-hardening
   worker against the migrated database. If migration 0026 reports an unsafe
   partial cursor, stop and review it instead of bypassing the guard.
5. Keep every normal service stopped and execute the
   [historical-generation maintenance drain](vast-launch.md#historical-generation-maintenance-drain):
   pause both escrows, latch provider maintenance under lock `4663`, drain the
   historical generation and then the current generation with explicit
   generation-bound hardened processes, and require clean transaction audits.
6. Cut proof publication from the static bridge to exactly one Rust database
   worker during that drain. Never run both publishers together.
7. Clear only the maintenance latch, let one current lifecycle owner rebuild
   fresh provider health, start the current settlement and repro workers from
   the same release SHA, unpause only the current escrow, and start the control
   plane last.
8. Keep managed capacity unavailable while Vast is unfunded.
9. Complete the private-RPC, funded-provider, paid-canary, npm and approved-alert
   gates before calling the release live.

## Security statement

Preparation and read capabilities cannot sign a wallet transaction. The image,
command, duration, minimum VRAM, executor, network, asset and maximum escrow are
fixed before approval. Capability tokens are bearer secrets and belong in MCP
POST bodies or bounded stdin, not process arguments. Vast credentials remain
worker-side, chain signing remains KMS-backed, and GPU inputs must be public and
non-confidential because assigned hosts may be operated by independent
providers.

Managed SSH evidence is inspectable gateway-signed execution evidence. It is
not hardware attestation and does not prove faithful computation. Public proof
establishes an onchain payment outcome paired with platform-verified usage and
the stated trust class; it does not upgrade that claim.
