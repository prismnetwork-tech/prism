# Migrating node bonds onto a staked asset

Compute keeps settling in USDG. Only what a node stakes to join changes.

`NodeRegistryV1.bondToken` is immutable, and `LeaseEscrowV1.nodeRegistry` is
immutable too, so the bond asset cannot be swapped in place. A new registry
forces a new escrow, which is why this is a migration rather than a setting.

## Before you start

**Every lease must be settled.** In-flight leases on the old escrow are
invisible to the new one, and the old escrow keeps its own funds. Check:

```sh
docker compose -f /opt/prism/compose.yml exec -T postgres \
  psql -U prism -d prism -tAc \
  "SELECT count(*) FROM leases WHERE state NOT IN ('finalized','refunded','failed');"
```

**The operator must hold the stake.** Registration pulls it, so the wallet that
registers nodes needs `requiredBond(rate) * node count` of the bond token, plus
gas. At 222 micros/s and the parameters below that is 50,000 per node.

## Parameters

`requiredBond(rate) = clamp(bondPerRateUnit * rate, floor, ceiling)`.

A node advertising a higher rate stakes more. `bondPerRateUnit` is adjustable by
the owner afterwards; the floor and ceiling are fixed at deployment and bound
whatever the owner can set. Pick them wide enough to survive a large price move,
because leaving the band means migrating again.

```sh
export PRISM_BOND_TOKEN=0x0a1e0cc751f77c2c93760fc957cc8e4e779b2bc8
export PRISM_BOND_PER_RATE_UNIT=225225225225225225225   # 50,000 at rate 222
export PRISM_BOND_FLOOR=1000000000000000000             # 1
export PRISM_BOND_CEILING=1000000000000000000000000     # 1,000,000
```

## Run

```sh
forge script script/MigrateToStakedBonds.s.sol \
  --rpc-url https://rpc.mainnet.chain.robinhood.com --broadcast --skip-simulation
```

It deploys the registry and escrow, wires them together, and asserts the bond
token took, the escrow still settles in USDG, and the escrow points at the new
registry.

## Re-register every node

Point `PRISM_NODE_REGISTRY_ADDRESS` at the new registry and run
`RegisterCloudBroker.s.sol` once per node id, exactly as nodes were first
registered. Each call pulls the stake.

The device identities are unchanged, so nothing needs re-enrolling with the
control plane. Only the onchain registration moves.

## Cut over

Repoint both addresses in `/opt/prism/.env`, then restart:

```sh
PRISM_NODE_REGISTRY_ADDRESS=<new registry>
PRISM_LEASE_ESCROW_ADDRESS=<new escrow>
```

`docker compose up -d` and confirm `/v1/offers` returns the expected count.
Offers require a bonded, schedulable node, so an empty list means registration
did not complete rather than a quiet degradation.

## Recover the old bonds

The old registry keeps working for withdrawal. For each node, `retire` then
`withdrawBond` returns the original USDG stake to the operator.

## Rolling back

Until the env is repointed, nothing has moved: the old contracts still hold the
nodes and the network keeps serving from them. After repointing, rolling back
means pointing the env at the old pair again, which is safe only while no lease
has been funded against the new escrow.
