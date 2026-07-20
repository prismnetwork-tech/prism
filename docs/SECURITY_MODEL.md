# Security model

## Explicit guarantees

- Renter funds are capped at 50 USDG per lease and are held by the escrow
  contract before a workspace is provisioned.
- The contract permits billing to start only through the configured gateway
  signer.
- The contracts enforce one active lease per node and at most 25 network
  leases.
- The scheduler accepts only bounded, digest-pinned public-image requests.
- Access grants expire after at most one hour and can be revoked in the grant
  store.
- The production worker configuration requires non-exportable secp256k1 KMS
  keys for gateway transactions, EIP-712 metering attestations and settlement
  transactions. Live KMS signing remains a release gate.

## Release-gated controls

The node runtime reserves one validated IOMMU group, passes only its VFIO
devices to Kata, injects a read-only bootstrap, starts key-only SSH and
token-only Jupyter, uses memory-backed scratch with host swap disabled, and
installs an nftables policy before releasing the guest network gate. The
gateway carries SSH or Jupyter bytes over a revocable mTLS tunnel. These paths
pass software and container integration tests, but cannot become hardware
guarantees until the physical Ubuntu/NVIDIA/Kata test matrix passes.

The control plane verifies that a finalized `LeaseFunded` event contains the
exact quote-derived client reference before associating it with an account.
Node command polls and reports are device-signed, freshness-bounded,
single-claim and replay-protected.

Chain transaction bytes, hashes and nonces are persisted before submission.
Confirmation records include the canonical block hash so a removed transaction
is safely rebroadcast after a reorganization. Access and Jupyter credentials
are encrypted before storage and returned only to the active lease's
authenticated account.

## Non-guarantees

Independent node operators can observe, alter or copy data processed on their
hosts. Kata reduces the renter-to-host attack surface; it does not provide a
confidential-computing guarantee. Do not run secrets, regulated data, private
datasets or valuable model weights on the initial network.

The contracts are deployed and paused on Robinhood Chain. They are not
source-verified on the explorer or independently audited. Before unpausing,
operators must verify the checked-in source, constructor inputs and runtime
bytecode against the deployment. Emergency pause is available to the
administration Safe.

## Required operational controls

- Wallet and account risk controls must stop new leases before public beta.
- Objective protocol abuse can be reviewed through the restricted dispute
  queue. Safe owners must verify the evidence hash and decoded calldata before
  approving a slash or settlement resolution.
- Ordinary availability incidents affect reputation, not automatic slashing.
- Proof and X publication must remain separate from settlement so an X API
  failure cannot delay settlement or refunds. Durable database outboxes enforce
  this separation, but a production proof receipt and X digest have not been
  published yet.
