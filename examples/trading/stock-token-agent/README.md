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
                              Uniswap v4 swap  <── decision: best edge > hurdle?
```

## Run it

Free, no wallet — research with a local (downscaled) analysis:

```sh
npm install
node agent.mjs
```

Full study on a rented GPU (the lease funds an on-chain USDG escrow, usually
around $0.15 for the 20-minute window):

```sh
export PRISM_AGENT_KEY=0x...   # wallet holding USDG + gas on Robinhood Chain
export PRISM_IMAGE=docker.io/pytorch/pytorch@sha256:<digest>   # CUDA + torch, digest-pinned
node agent.mjs --gpu
```

Let it place the swap it chose (2 USDG by default, `SPEND_USDG` to change):

```sh
EXECUTE=1 node agent.mjs --gpu
```

Resolve a digest for `PRISM_IMAGE` with
`docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime`.

## What it reads

- **Chainlink feeds** for NVDA, AAPL, TSLA, SPY on Robinhood Chain: round
  history is the price series the Monte Carlo resamples.
- **Uniswap v4 pools** (StateView): live USDG spot and liquidity per token, and
  the pool-versus-oracle basis in bps.
- **Robinhood Earn** (Morpho steakUSDG vault): the share rate, standing in as
  the hurdle idle USDG earns. Deposits into that vault are gated onchain
  (`maxDeposit` is 0 for an arbitrary wallet), so it appears here as a
  benchmark, not an execution venue.

## The decision

The GPU job bootstraps 200k five-day paths per ticker from its return history,
tilts by 20-round momentum, and reports expected return, VaR95, and the
probability of a gain. The agent buys the best ticker only when its expected
edge survives the 0.3% pool fee with better-than-even odds; otherwise it stays
in USDG. The swap goes through the Universal Router with a 1% slippage floor,
after a free simulation.

Stock tokens are ERC-20s issued on Robinhood Chain; check your own eligibility
to hold them before executing. This is a demonstration of the pipeline, not
investment advice. Prism is pre-production and unaudited.
