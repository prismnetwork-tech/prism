# Canary

A capped, end-to-end mainnet check: an agent wallet funds one short GPU lease,
verifies `nvidia-smi` over SSH, and prints the on-chain funding transaction. Use it
to prove the whole lease path works before opening capacity.

It spends real USDG. Duration is capped at 1 hour and spend at 5 USDG; the defaults
lease for 600s under a 0.5 USDG ceiling. The binding quote is printed before the
funding gate. A lease that funds but then fails reports every available funding
hash and lease id and settles on-chain when its window ends.

## Run

Preflight first (authenticates, checks balances and a live offer, spends nothing):

```sh
npm install
PRISM_AGENT_KEY=0x<funded agent wallet> \
PRISM_ESCROW=0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD \
npm start
```

For a manual production run, prompt on the exact quote and confirm its printed
id only after reviewing the amount, network, node, image and expiry:

```sh
CANARY_CONFIRM=prompt PRISM_AGENT_KEY=0x... \
PRISM_ESCROW=0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD \
npm start
```

`CANARY_CONFIRM=1` is reserved for a pre-authorized automated run with the same
hard caps. It still funds the single quote printed by that process.

Optional: `CANARY_DURATION`, `CANARY_MAX_USDG`, `CANARY_MIN_VRAM`, `CANARY_NODE`.

Validate the caps and configuration without loading a wallet or making a network
request:

```sh
npm start -- --dry-run
```

## What lands on-chain, and when

- **Now:** the `createLease` funding tx (printed as the funding tx link) — the agent
  funding an escrow for GPU compute.
- **After the lease window:** the network proposes settlement (`SettlementProposed`
  with the receipt hash).
- **Five minutes later:** `finalize()` becomes callable (`DISPUTE_WINDOW`), the escrow settles,
  and the receipt publishes to the public proof feed.

The process exits after the GPU command. Keep its result pending until separate
checks prove the cloud instance was destroyed and the settlement receipt is
finalized and published.

Run against a funded wallet you control.

## Paid repro run

`repro.mjs` runs the pinned CUDA vector-add image through the public MCP surface
and the audited escrow, then verifies the result end to end. It has three
stages, and each one refuses to claim anything the stage before it did not
prove. `REPRO_STATE_FILE` must be an absolute path outside the repository; one
state file belongs to one run.

Review the quote. This spends nothing and prints the exact price:

```sh
PRISM_AGENT_KEY=0x... PRISM_RPC_URL=https://... \
REPRO_STATE_FILE=/absolute/path/run.json \
npm run repro:review
```

Fund and execute the reviewed quote. The confirmation string names that one
quote id, so an expired or replaced quote cannot be executed by rerunning the
command:

```sh
REPRO_CONFIRM='CONFIRM <quote id>' PRISM_AGENT_KEY=0x... PRISM_RPC_URL=https://... \
REPRO_STATE_FILE=/absolute/path/run.json \
npm run repro:execute
```

Execution ends at `settled`: the CUDA success marker, the gateway-signed report,
the onchain settlement and the public receipt are all verified, and the
provider machine is not. Verify destruction against the Vast account that ran
the lease to reach `complete`:

```sh
VAST_API_KEY=... VAST_ACCOUNT_ID=<lifecycle worker's Vast account> \
REPRO_STATE_FILE=/absolute/path/run.json \
npm run repro:verify-cleanup
```

`VAST_ACCOUNT_ID` is optional but worth setting, because absence from the wrong
account proves nothing. The lifecycle worker rents from Vast account **675165**
(`mika@prismnetwork.tech`), and its key lives on the control-plane host at
`/run/secrets/vast_api_key`. The `VAST_API_KEY` in `~/.config/prism/keys.env`
belongs to a different, empty account and will report every instance absent.

`npm run repro:inspect` prints the current stage and every identifier the run
has recorded so far.

Guards worth knowing about:

- An execution takes an exclusive `<state file>.lock`. A leftover lock means a
  run died mid-flight; read the chain before another process reuses that nonce.
- Every transaction is refused above `REPRO_MAX_FEE_WEI` (default 0.002 ETH of
  maximum fee), on the prepared request and again on a resumed signed one.
- The public receipt is matched on this run's token commitment and chain lease
  id, so a repeated run against the same spec cannot adopt an earlier receipt.
