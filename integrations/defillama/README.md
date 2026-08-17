# DefiLlama fees adapter

Reports what Prism charges for GPU leases to DefiLlama's dimensions dashboards.

`prism-network.ts` belongs at `fees/prism-network/index.ts` in
[DefiLlama/dimension-adapters](https://github.com/DefiLlama/dimension-adapters).
The import paths assume that depth, so it will not resolve anywhere else.

## Where the numbers come from

One event carries all three metrics, so nothing is double counted and no price
lookup of our own is involved:

    LeaseFinalized(leaseId, charged, fee, providerPaid, refunded, receiptHash)

`charged` is what the renter paid for the time actually consumed, and it is
exactly `fee + providerPaid`. Deposits are taken up front, but the unused
remainder is refunded in the same transaction and is not a fee.

| DefiLlama metric | Source |
| --- | --- |
| `dailyFees` | `charged` |
| `dailyRevenue`, `dailyProtocolRevenue` | `fee`, currently 10% |
| `dailySupplySideRevenue` | `providerPaid`, to the GPU operator |

## Testing it

From a checkout of dimension-adapters, with the adapter copied into place:

    ROBINHOOD_RPC="https://rpc.mainnet.chain.robinhood.com" pnpm test fees prism-network
    ROBINHOOD_RPC="https://rpc.mainnet.chain.robinhood.com" pnpm test fees prism-network 2026-08-15

Verified against an independent tally of the same logs: for 2026-08-14 both
report 3.54 charged, 0.35 protocol, 3.19 supply side across 17 leases.

Two things that make this work and are easy to miss. DefiLlama already tracks
Robinhood Chain as `CHAIN.ROBINHOOD` and already prices USDG on it, so neither
needed onboarding. And a compile error in the adapter surfaces from their CLI as
`Protocol "..." not found`, because the importer catches the failed import and
falls through to the factory registry, so check the import paths before
believing the protocol is missing.
