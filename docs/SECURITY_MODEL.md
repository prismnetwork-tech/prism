# Security model

Prism handles renter funds and remote workloads, so its controls are grouped by
what they actually promise: guarantees enforced today, controls gated on hardware
validation, detective controls that catch divergence, and explicit
non-guarantees. Read the non-guarantees before depositing funds.

## Explicit guarantees

- Renter funds are capped at 50 USDG per lease and are held by the escrow
  contract before a workspace is provisioned.
- The contract permits billing to start only through the configured gateway
  signer.
- The contracts enforce one active lease per node and at most 25 network leases.
- The scheduler accepts only bounded, digest-pinned public-image requests.
- Access grants expire after at most one hour and can be revoked in the grant
  store.
- The production worker configuration requires non-exportable secp256k1 KMS keys
  for gateway transactions, EIP-712 metering attestations, and settlement
  transactions. Live KMS signing remains a release gate.

## Release-gated controls

The node runtime reserves one validated IOMMU group, passes only its VFIO devices
to Kata, injects a read-only bootstrap, starts key-only SSH and token-only
Jupyter, uses memory-backed scratch with host swap disabled, and installs an
nftables policy before releasing the guest network gate. The gateway carries SSH
or Jupyter bytes over a revocable mTLS tunnel. These paths pass software and
container integration tests, but cannot become hardware guarantees until the
physical Ubuntu/NVIDIA/Kata test matrix passes.

The control plane verifies that a finalized `LeaseFunded` event contains the exact
quote-derived client reference before associating it with an account. Node
command polls and reports are device-signed, freshness-bounded, single-claim, and
replay-protected.

Chain transaction bytes, hashes, and nonces are persisted before submission.
Confirmation records include the canonical block hash so a removed transaction is
safely rebroadcast after a reorganization. Access and Jupyter credentials are
encrypted before storage and returned only to the active lease's authenticated
account.

## Detective controls

Preventive controls can still drift under bugs, reorgs, or partial failures, so a
read-only reconciliation monitor continuously re-derives the financial invariants
from both PostgreSQL and `LeaseEscrowV1` and pages on any breach. It holds no keys
and cannot mutate state; it only observes.

| Invariant | Breach means |
| --- | --- |
| Escrow balance ≥ tracked open deposits | Funds are missing relative to the ledger |
| No lease open in the database yet released on chain | The platform is metering a lease whose funds are gone |
| `deposit = provider_paid + fee + refunded` per finalized lease | A settlement did not conserve the deposit |
| Onchain active leases ≤ network cap | A concurrency bound was breached |
| No lease stalled past its lifecycle timeout | A lease is stuck instead of refunding |
| Every finalized lease has a proof receipt | Settlement and proof have diverged |

Because the monitor reuses the workers' chain client and settlement math, it
cannot silently share a bug that would make a wrong value look self-consistent —
it checks the recorded outcome against the contract's own events.

## Trust classes

"A supplier is not a trusted computing environment" is true, but it is too
coarse to act on: it bundles confidentiality, execution integrity and fund
custody into one sentence that no single control can retire. Every offer,
quote, lease and receipt therefore carries a trust class, and a renter can
require a minimum one instead of reading a disclaimer.

| Class | The renter can rely on | The renter cannot rely on |
| --- | --- | --- |
| `open` | A bonded, device-signed supplier identity and metered billing against escrow | Anything about confidentiality. The host operator can read memory, disk and VRAM |
| `isolated` | A Kata VM with exclusive VFIO passthrough, a digest-pinned public image and memory-backed scratch | Protection from a privileged host that chooses to inspect the guest |
| `attested` | A launch measurement and GPU device identity checked against vendor roots, so the software that booted is the software we published | Secrecy. Attestation proves what ran, not that nobody watched |
| `confidential` | Guest memory and VRAM encrypted against the host | Correctness of the workload itself, or the absence of contract defects |

The class is derived by the control plane, never asserted by a supplier.
Broker-backed capacity reaches renters over direct SSH with no daemon and no
tunnel, so it is pinned to `open` regardless of what it claims. Anything above
`open` requires a device-signed posture from a node the network holds a bond
for, which makes an overstated claim a signed statement the dispute queue can
act on.

Attestation evidence is carried end to end but is not yet verified, so
`MAX_VERIFIABLE_TRUST_CLASS` in `prism-protocol` clamps every served class to
`isolated`. Nothing is published above what the network can check, and raising
the ceiling requires a verifier, not a configuration change. All capacity live
today is `open`.

## Private data

A trust class describes a workspace. It does not have to describe where a
renter's data lives, and treating those as the same question is what produced
the old advice to keep anything valuable off the network entirely.

Private data belongs in the vault instead. Items are sealed on the renter's
machine under a key derived from a wallet signature and never transmitted, so
the control plane holds ciphertext and no means of reading it. The account,
slot, version and trust floor are authenticated into GCM's associated data,
which makes moving an item between accounts, replaying a superseded version, or
lowering an item's trust floor a failed decrypt rather than a successful lie.

Each item carries the weakest class of workspace it may be shown to, and new
items default to `confidential` — above `MAX_VERIFIABLE_TRUST_CLASS`, so above
anything the network can currently serve. Releasing an item into a lease below
its floor is refused by the control plane and recorded when it is allowed. The
guarantee is therefore precise: storage is confidential today, and use inside a
workspace stays gated on the hardware problem below.

[docs/VAULT.md](VAULT.md) covers the construction and its limits.

## Why confidentiality is a hardware problem

Zero-knowledge proofs establish that a computation was performed correctly.
They do not hide the input from the party doing the computing, because the
prover holds the plaintext, and on a rented GPU the prover is the untrusted
host. Homomorphic encryption and secure multi-party computation address secrecy
but are orders of magnitude too slow for training or transformer inference.
Confidentiality on rented hardware therefore requires a TEE on both sides: an
AMD SEV-SNP or Intel TDX confidential VM for the host, and NVIDIA Confidential
Computing on the GPU. NVIDIA CC begins at Hopper, so the L40S capacity in the
network today cannot reach the `confidential` class on any timeline.

Zero-knowledge work does have a place here, one step removed from the workload.
Robinhood Chain runs Arbitrum Nitro with the RIP-7212 P-256 precompile live at
`0x0100`, so Intel DCAP quotes, which are ECDSA P-256, can be verified onchain
cheaply. AMD SEV-SNP reports and the NVIDIA attestation chain use P-384, which
the precompile does not cover; proving that verification inside a zkVM and
checking the resulting proof against the bn254 pairing precompile at `0x0008`
is the affordable route to `attested` without a trusted attestation service.

## Contract non-guarantees

The contracts are deployed on Robinhood Chain and are not source-verified on
the explorer or independently audited. Operators must verify the checked-in
source, constructor inputs, and runtime bytecode against the deployment.
Emergency pause is available to the administration Safe, `adminClose` can
refund any open lease to its renter, and `NodeRegistryV1.slash` is an owner
call whose `evidenceHash` the contract does not itself check. Per-lease escrow
is capped at 50 USDG, which bounds what any one of these can cost a renter.

## Required operational controls

- Wallet and account risk controls must stop new leases before public beta.
- Objective protocol abuse can be reviewed through the restricted dispute queue.
  Safe owners must verify the evidence hash and decoded calldata before approving
  a slash or settlement resolution.
- Ordinary availability incidents affect reputation, not automatic slashing.
- Proof and X publication must remain separate from settlement so an X API failure
  cannot delay settlement or refunds. Durable database outboxes enforce this
  separation, but a production proof receipt and X digest have not been published
  yet.
