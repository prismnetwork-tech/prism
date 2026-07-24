# Canary

A capped, end-to-end mainnet check: an agent wallet funds one short GPU lease,
verifies `nvidia-smi` over SSH, and prints the on-chain funding transaction. Use it
to prove the whole lease path works before opening capacity.

It spends real USDG. Duration is capped at 1 hour and spend at 5 USDG; the defaults
lease for 600s under a 0.5 USDG ceiling (a few cents at L40S rates). A lease that
funds but then fails is always reported by id and settles on-chain when its window
ends, so nothing is left open silently.

## Run

Preflight first (authenticates, checks balances and a live offer, spends nothing):

```sh
npm install
PRISM_AGENT_KEY=0x<funded agent wallet> \
PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
npm start
```

Then fund the lease by adding `CANARY_CONFIRM=1`:

```sh
CANARY_CONFIRM=1 PRISM_AGENT_KEY=0x... PRISM_ESCROW=0x71Df... npm start
```

Optional: `CANARY_DURATION`, `CANARY_MAX_USDG`, `CANARY_MIN_VRAM`, `CANARY_NODE`.

## What lands on-chain, and when

- **Now:** the `createLease` funding tx (printed as the funding tx link) — the agent
  funding an escrow for GPU compute.
- **After the lease window:** the network proposes settlement (`SettlementProposed`
  with the receipt hash).
- **24h later:** `finalize()` becomes callable (`DISPUTE_WINDOW`), the escrow settles,
  and the receipt publishes to the public proof feed.

Pre-production and unaudited. Run against a funded wallet you control.
