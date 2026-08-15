# Stock-token research agent

An agent that rents a Prism GPU to research Robinhood Chain stock tokens, then
executes the trade it picks on Uniswap v4. Everything happens on one chain
(id 4663): the GPU lease is paid in USDG, the research reads Chainlink feeds
and Uniswap v4 pool state, and the resulting swap settles in the same wallet.

```
Chainlink stock feeds ──┐
Uniswap v4 pool state ──┼─> dataset ──> Prism GPU lease ──> Monte Carlo study
Robinhood Earn vault  ──┘                (paid in USDG)          │
                                                                v
                              Uniswap v4 swap  <── decision: edge, odds, basis
```

## Run it

Free, no wallet: research with a local (downscaled) analysis. Needs Node 20+:

```sh
npm install
node agent.mjs
```

Full study on a rented GPU (the lease funds an on-chain USDG escrow, about
0.27 USDG for the 20-minute window at the current rate):

```sh
export PRISM_AGENT_KEY=0x...   # wallet holding USDG + gas on Robinhood Chain
export PRISM_IMAGE=docker.io/pytorch/pytorch@sha256:<digest>   # CUDA + torch, digest-pinned
node agent.mjs --gpu
```

Let it place the swap it chose (2 USDG by default, `SPEND_USDG` to change):

```sh
EXECUTE=1 node agent.mjs --gpu
```

`EXECUTE=1` without `--gpu` also works and trades on the downscaled local
study; the agent prints a note when it does. Resolve a digest for
`PRISM_IMAGE` with
`docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime`.

## Environment

| Variable | Meaning |
| --- | --- |
| `PRISM_AGENT_KEY` | Private key of the wallet that leases and swaps. |
| `PRISM_IMAGE` | Digest-pinned CUDA + PyTorch image for the GPU job. |
| `SPEND_USDG` | Swap size, default 2. |
| `PRISM_RPC_URL` | Your own RPC. A run makes ~1,600 reads; the default public RPC rate-limits, and the agent then retries, reports dropped rounds, and refuses to trade on a badly thinned history. |
| `PRISM_ESCROW` | Override the lease escrow contract. |

## What it reads

- **Chainlink feeds** for NVDA, AAPL, TSLA, SPY on Robinhood Chain: round
  history is the price series the Monte Carlo resamples.
- **Uniswap v4 pools** (StateView): live USDG spot per token, and the
  pool-versus-oracle basis in bps.
- **Robinhood Earn** (Morpho steakUSDG vault): the share rate, printed as
  context for what idle USDG earns. Deposits into that vault are gated onchain
  (`maxDeposit` is 0 for an arbitrary wallet), so it appears here as a
  reference figure, not an execution venue.

## The decision

The GPU job bootstraps 200k paths per ticker from its cleaned return history
(the forward horizon is five days, converted to rounds from the feed's actual
posting cadence), and adds a momentum tilt. The output separates the bootstrap
mean from the tilt so you can see which is driving the number. The agent buys
the best ticker only when three things hold: the expected edge survives the
0.3% pool fee with better-than-even odds, the pool price sits within 300 bps
of the oracle, and the price history was not degraded by RPC throttling. The
swap goes through the Universal Router with a 1% slippage floor anchored to a
pool price re-read just before the order, after a free simulation.

The full 20-minute lease is billed regardless of how fast the job finishes;
releasing a lease discards local key material, it does not stop the clock.

Stock tokens are ERC-20s issued on Robinhood Chain; check your own eligibility
to hold them before executing. This is a demonstration of the pipeline, not
investment advice. Prism is pre-production and unaudited.
