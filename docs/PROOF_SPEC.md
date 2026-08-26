# Public settlement proof specification

After launch, the public proof feed will expose a receipt artifact and a
matching settlement event. It is intentionally pseudonymous.

```json
{
  "receipt_id": "uuid",
  "lease_id": "onchain escrow lease id, as a decimal string",
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

`lease_id` is the lease id the escrow contract assigned onchain, rendered as a
decimal string. It is the value the settlement event carries, so a verifier can
match a receipt to its transaction. It is not the identifier the HTTP API uses
for the same lease; those are separate counters and they do not agree.

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

## Walking the whole set

`index.json` carries `total`, `page_size`, `pages` and `first_page`. `receipts`
is the window the index itself lists; `total` is how many exist. When `total`
is larger than that window, the index is truncated and the complete set is read
by following `first_page` and then each page's `next` until it is `null`. Pages
are newest first and each one repeats `total` and `pages`, so a verifier can
tell mid-walk that the feed moved under it.

## Reproducing the hashes

Everything below is SHA-256 over UTF-8, written as lowercase hex. Three rules
decide whether an independent verifier reproduces a published hash, and all
three are easy to get wrong:

- **Field order is declaration order, not sorted.** The canonical form is the
  struct's own order, listed below. A verifier that sorts keys alphabetically
  computes a different hash.
- **Separators are compact.** No spaces after `:` or `,`.
- **Absent optional fields are omitted, never null.** `trust_class`,
  `attestation` and `credited_seconds` disappear from the payload when unset,
  which is what keeps older receipts byte-identical as fields are added.

`receipt_hash` is taken over exactly these fields, in this order:

```
receipt_id, lease_id, node_id_hash, gpu_model, runtime_seconds,
charged_base_units, refunded_base_units, provider_paid_base_units,
failure_class, outcome, trust_class, attestation, credited_seconds
```

`receipt_hash` and `transaction_hash` are not part of it. `failure_class` is
serialized as `null` when absent; the three optional fields above are omitted.
Numeric fields are JSON numbers, and `lease_id` is a JSON string.

`receipt_set_id` covers a window's receipts. Collect each `receipt_hash`, sort
them ascending as strings, drop duplicates, and hash the resulting compact JSON
array of hex strings.

`digest_id` covers the daily digest document. Serialize the document compactly
with `digest_id` set to the empty string, hash that, then write the result into
the field.

Confidential inference is a different product from a confidential lease, and a
receipt does not blur them. Receipts here cover GPU leases, whose ceiling is
`isolated`. The confidential inference tier runs in a relayed enclave and is
attested through its own endpoint, not through this feed.

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
