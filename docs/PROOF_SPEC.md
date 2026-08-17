# Public settlement proof specification

After launch, the public proof feed will expose a receipt artifact and a
matching settlement event. It is intentionally pseudonymous.

```json
{
  "receipt_id": "uuid",
  "lease_id": "opaque lease identifier",
  "node_id_hash": "sha256-derived identifier",
  "gpu_model": "NVIDIA model",
  "runtime_seconds": 0,
  "charged_base_units": 0,
  "refunded_base_units": 0,
  "provider_paid_base_units": 0,
  "failure_class": null,
  "outcome": "finalized | refunded | disputed",
  "trust_class": "open | isolated | attested | confidential",
  "attestation": "sha256 digest of the attestation verdict",
  "receipt_hash": "sha256 canonical JSON hash",
  "transaction_hash": "Robinhood Chain transaction hash"
}
```

`trust_class` records what the renter was promised when the quote was issued,
so a receipt states the terms it settled under and not just the amount. It is
omitted entirely on receipts minted before the field existed, which keeps their
canonical payload, and therefore the receipt hash already committed by their
settlement transaction, byte-identical.

`attestation` commits the receipt to the hardware verdict the class was granted
from, so the terms and the evidence behind them settle in the same hash. It is
omitted entirely when no verdict backed the lease, including on receipts minted
before the field existed, which keeps those payloads and their published hashes
byte-identical. The verdict digest is all that is published. Raw attestation
reports are not, because a report carries the GPU's device serial and would
deanonymize the host.

`receipt_hash` is the SHA-256 hash of the canonical payload with the
`receipt_hash` and `transaction_hash` fields omitted. The transaction hash
cannot be part of the receipt committed by the settlement transaction that
creates it. The proof worker rejects duplicate receipt IDs, malformed
chain/node hashes and artifacts whose hash does not match before it writes
`index.json` and `receipts/<receipt_id>.json`.

Before publishing, the worker verifies that the RPC reports Robinhood Chain ID
4663, the transaction succeeded, the configured confirmation threshold has
elapsed, and the configured escrow emitted a matching finalization or refund
event. Disputed receipts are not published as final proof. It removes stale
receipt artifacts from the generated directory. The public site does not
expose wallet addresses, precise geography, image digests, files, terminal
output or private telemetry.

Proof establishes an onchain payment event paired with a platform-attested
usage record, under a stated trust class. It does not establish that a supplier
executed a workload faithfully, that hardware was unmodified, or that the
deployed contracts have no defect. No receipt states a class above `isolated`,
which is the ceiling `MAX_VERIFIABLE_TRUST_CLASS` enforces on both paths that
publish a class: the offer listing and the quote, rechecked when funding is
confirmed. `isolated` is published only for a lease whose node held a verified
GPU attestation verdict at quote time.

The checked-in proof worker provides receipt-file aggregation, safe-chain
event verification, public artifact generation and a daily X outbox.
Continuous ingestion from settlement events and publication to object storage
remain release-gated. Posting failures
remain outside the settlement path. Because the X endpoint does not expose an
idempotency key, the worker includes a deterministic digest marker in each post
and provides at-least-once, not exactly-once, delivery semantics.
