# Public settlement proof specification

The public proof feed exposes a receipt artifact and a matching settlement
event. It is intentionally pseudonymous.

```json
{
  "receipt_id": "uuid",
  "lease_id": "onchain escrow lease id, as a decimal string",
  "escrow_address": "lowercase 0x-prefixed escrow address",
  "chain_lease_id": "same decimal string as lease_id",
  "node_id_hash": "sha256-derived identifier",
  "gpu_model": "NVIDIA model",
  "runtime_seconds": 0,
  "charged_base_units": 0,
  "refunded_base_units": 0,
  "provider_paid_base_units": 0,
  "failure_class": null,
  "outcome": "finalized | refunded | disputed",
  "trust_class": "open | isolated | attested | confidential",
  "attestation": {
    "kind": "sev_snp | tdx | nvidia_cc | nvidia_gpu",
    "verdict_digest": "lowercase sha256",
    "verifier_version": "version string"
  },
  "credited_seconds": 0,
  "repro": {
    "executor": "node | managed",
    "token_hash": "lowercase sha256",
    "spec_hash": "lowercase sha256",
    "image_digest": "sha256:...",
    "command_hash": "lowercase sha256",
    "result_hash": "lowercase sha256",
    "stdout_hash": "lowercase sha256",
    "stderr_hash": "lowercase sha256",
    "report_hash": "lowercase sha256",
    "exit_code": 0,
    "expected_exit_code": 0,
    "succeeded": true,
    "truncated": false
  },
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

`repro` is present only for a capability-scoped batch run whose complete report
was verified during settlement. It commits to the authorized workload, command
envelope, signed result, each output stream and whether the reported exit code
matched the expected exit code. The proof feed publishes hashes rather than
commands or output. `executor: "node"` means the enrolled node device key signed
the report. `executor: "managed"` means the escrow's current onchain `gateway()`
signer attested to a centrally orchestrated SSH run.

This is inspectable execution evidence, not a proof of correct computation. A
valid node signature establishes that the enrolled supplier key asserted the
result. A valid managed signature establishes that Prism's gateway asserted
the provider instance, GPU description, SSH host-key commitment, timing and
result. Neither establishes faithful execution or hardware attestation.

`lease_id` is the lease id the escrow contract assigned onchain, rendered as a
decimal string. It is the value the settlement event carries, so a verifier can
match a receipt to its transaction. It is not the identifier the HTTP API uses
for the same lease; those are separate counters and they do not agree.

`escrow_address` and `chain_lease_id` form the receipt's exact chain identity.
Escrow counters restart after a deployment, so `chain_lease_id` alone is not
globally unique. New receipts always carry both fields, the address is lowercase,
and `chain_lease_id` must equal the legacy `lease_id` field. Receipts minted
before this metadata existed may omit both fields; one field without the other
is invalid. These two additive fields are excluded from `receipt_hash`, which
preserves every existing onchain commitment.

`receipt_hash` is the SHA-256 hash of the canonical payload with the
`receipt_hash` and `transaction_hash` fields omitted. The transaction hash
cannot be part of the receipt committed by the settlement transaction that
creates it. The proof worker rejects duplicate receipt IDs, malformed
chain/node hashes and artifacts whose hash does not match before it writes
`index.json` and `receipts/<receipt_id>.json`.

`LeaseFinalized` commits `receipt_hash` onchain. The immutable v1
`LeaseRefunded` event does not: its third field is `reasonHash`. For a
worker-generated `provisioning_timeout` receipt, the proof worker requires that
field to equal Keccak-256 of `prism.provisioning-timeout.v1`. A legacy refund
with no failure class can be matched only to its escrow, chain lease id,
transaction outcome and refunded amount. Its offchain receipt hash is
self-consistency evidence, not a value committed by the refund event.

Before publishing, the worker verifies that the RPC reports Robinhood Chain ID
4663, the transaction succeeded, the configured confirmation threshold has
elapsed, and the configured escrow emitted a matching finalization or refund
event. Finalizations must carry the exact receipt hash; refunds must carry the
amount and, where the receipt names a supported failure class, its canonical
reason hash. Disputed receipts are not published as final proof. When a
previously published row is quarantined, the next complete publication removes
its direct receipt artifact and all obsolete mutable page files. The public site does not
expose wallet addresses, precise geography, full image references, files,
terminal output or private telemetry. A repro receipt does publish the
immutable image digest and hashes of the withheld command, output and signed
report.

## Walking the whole set

`index.json` carries `total`, `page_size`, `pages` and `first_page`. `receipts`
is the window the index itself lists; `total` is how many exist. When `total`
is larger than that window, the index is truncated and the complete set is read
by following `first_page` and then each page's `next` until it is `null`. Pages
are newest first, repeat `total` and `pages`, and live below a path derived from
the exact ordered receipt set. A walk therefore stays on one immutable set even
if a newer index is published concurrently.

Verified individual receipts and immutable pages can be staged early. The
mutable index is replaced only after a locked second database read finds no
pending rows and matches the complete staged published set. A transient RPC
error, a receipt still waiting for confirmations, or a backlog beyond the
1,000-row verification batch leaves the previous authoritative index intact.

## Reproducing the hashes

Receipt and repro commitment hashes below are SHA-256 over UTF-8, written as
lowercase hex. The managed-report signature digest is the explicitly noted
Keccak-256 exception. Three rules decide whether an independent verifier
reproduces a published hash, and all three are easy to get wrong:

- **Field order is declaration order, not sorted.** The canonical form is the
  struct's own order, listed below. A verifier that sorts keys alphabetically
  computes a different hash.
- **Separators are compact.** No spaces after `:` or `,`.
- **Absent optional fields are omitted, never null.** `trust_class`,
  `attestation`, `credited_seconds` and `repro` disappear from the payload when
  unset, which is what keeps older receipts byte-identical as fields are added.

`receipt_hash` is taken over exactly these fields, in this order:

```
receipt_id, lease_id, node_id_hash, gpu_model, runtime_seconds,
charged_base_units, refunded_base_units, provider_paid_base_units,
failure_class, outcome, trust_class, attestation, credited_seconds, repro
```

`receipt_hash`, `transaction_hash`, `escrow_address` and `chain_lease_id` are not
part of it. `failure_class` is serialized as `null` when absent; the four
optional payload fields above are omitted. Numeric fields are JSON numbers, and
`lease_id` is a JSON string.

The nested `repro` object uses this fixed field order:

```
executor, token_hash, spec_hash, image_digest, command_hash, result_hash, stdout_hash,
stderr_hash, report_hash, exit_code, expected_exit_code, succeeded, truncated
```

The v1 repro hashes are lowercase hexadecimal SHA-256:

- `spec_hash` hashes the bytes `prism-gpu-repro-spec-v1\0` followed by compact
  declaration-order JSON with `image`, `command`, `duration_seconds`,
  `min_vram_mib`, `expected_exit_code`.
- `command_hash`, `result_hash` and `report_hash` use the corresponding domains
  `prism-gpu-repro-command-v1\0`, `prism-gpu-repro-result-v1\0` and
  `prism-gpu-repro-report-v1\0`, followed by compact declaration-order JSON of
  the full `NodeCommand`, `CommandResult` and signed executor report. The report
  is `NodeCommandReport` for `node` and `ManagedCommandReport` for `managed`.
- `stdout_hash` and `stderr_hash` hash the exact UTF-8 stream bytes without a
  domain prefix. `truncated` states whether either captured stream lost data.

The private `ReproCapability` also commits to `executor: node | managed`. That
field is carried unchanged by the approval intent, quote, lease, execution
evidence, and settlement validation. If the approved path is no longer live at
funding confirmation, the control plane rejects the confirmation for recovery;
it never substitutes the other executor.

`expected_exit_code` is an integer from 0 through 255. `exit_code` is from -255
through 255 so a future executor can preserve signal-style failures. `succeeded`
must equal `exit_code == expected_exit_code`; it is not an independent claim.

The capability token is never published. `token_hash` is lowercase SHA-256 of
the decoded 32-byte unpadded-base64url token. Publishing that 256-bit commitment
links the receipt to the capability without making the bearer token recoverable.

### Managed report signature

The private managed report contains these signed fields in order:

```
report_id, signer, command_id, lease_id, provider, provider_instance_id,
gpu_model, gpu_vram_mib, transport_host_key_sha256, started_at, finished_at,
outcome, error, result
```

Its digest is Keccak-256 of the bytes
`prism-managed-command-report-v1\0` followed by that payload's compact JSON. The
final `signature` is lowercase `0x`-prefixed 65-byte recoverable secp256k1. It
is excluded from the signature payload but included in `report_hash`. The final
recovery byte may be `0`/`1` or Ethereum-style `27`/`28`; producers emit
`27`/`28`, and high-S signatures are rejected.
The fixed interoperability vector in the protocol tests hashes to
`9177afcd30525f8328cff37aabc5acd9769a954ac4ad4ee45b8e55db0082985d`.
Settlement recovers the signer and resolves `gateway()` directly from the
configured escrow contract. It accepts a managed report only when those
addresses match, its Vast instance matches the private execution evidence, its
GPU meets the authorized spec, its execution interval is contained inside the
lease's onchain Active window, and its completed result is bounded and intact.
The provider instance ID and SSH host-key commitment remain in the private
capsule rather than the global feed.

`receipt_set_id` covers a window's receipts. Collect each `receipt_hash`, sort
them ascending as strings, drop duplicates, and hash the resulting compact JSON
array of hex strings.

`digest_id` covers the daily digest document. Serialize the document compactly
with `digest_id` set to the empty string, hash that, then write the result into
the field.

Confidential inference is a different product from a confidential lease, and a
receipt does not blur them. Receipts here cover GPU leases, whose ceiling is
`attested`. The confidential inference tier runs in a relayed enclave and is
attested through its own endpoint, not through this feed.

Proof establishes an onchain payment event paired with a platform-verified
usage record, under a stated trust class. A repro receipt additionally anchors
hashes derived from a valid node- or gateway-signed report. Neither establishes
faithful execution, unmodified hardware or defect-free contracts. Managed SSH
evidence is specifically not node identity or hardware attestation. No receipt
states a class above `attested`, which is the ceiling
`MAX_VERIFIABLE_TRUST_CLASS` enforces. `isolated` requires a verified GPU
verdict; `attested` additionally requires a fresh lease-bound guest verdict.

The checked-in proof worker provides durable database ingestion, receipt-file
aggregation for development, safe-chain event verification, public artifact
generation and an optional daily X outbox. Database mode is singleton. It verifies each
pending row against that row's exact escrow and indexed chain lease id, isolates
malformed or mismatched rows in `quarantined`, and builds the public index and
daily digest exclusively from `published` rows. A database trigger makes the
inserted identity and evidence immutable and permits only pending-to-published
or pending-or-published-to-quarantined state changes. X posting is disabled unless
`PRISM_ENABLE_X_DIGEST_POSTING=1`; proof publication requires no X credential.
Posting failures remain outside the settlement path. Because the X endpoint does not expose an
idempotency key, the worker includes a deterministic digest marker in each post
and provides at-least-once, not exactly-once, delivery semantics.
