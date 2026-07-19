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
  "receipt_hash": "sha256 canonical JSON hash",
  "transaction_hash": "Robinhood Chain transaction hash"
}
```

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
usage record. It does not establish that a supplier executed a workload
faithfully, that hardware was unmodified, or that the deployed contracts have
no defect.

The checked-in proof worker provides receipt-file aggregation, safe-chain
event verification, public artifact generation and a daily X outbox.
Continuous ingestion from settlement events and publication to object storage
remain release-gated. Posting failures
remain outside the settlement path. Because the X endpoint does not expose an
idempotency key, the worker includes a deterministic digest marker in each post
and provides at-least-once, not exactly-once, delivery semantics.
