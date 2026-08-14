# Funding-carry research agent

An agent that rents a Prism GPU to research perp funding carry on
[Lighter](https://lighter.xyz), then reports (and optionally places) the trade
it picks. The GPU lease is paid on-chain in USDG on Robinhood Chain and settles
with a verifiable receipt; Lighter market data needs no API key.

```
Lighter funding rates ──┐
settled funding history ┼─> dataset ──> Prism GPU lease ──> bootstrap carry study
active order books    ──┘                (paid in USDG)          │
                                                                 v
                        lighter-sdk order  <── decision: best p05 carry > 0?
```

## Run it

Free, no wallet — research with a local (downscaled) study:

```sh
python agent.py
```

Full 200k-path study on a rented GPU:

```sh
pip install prismnetwork
export PRISM_AGENT_KEY=0x...   # wallet holding USDG + gas on Robinhood Chain
export PRISM_IMAGE=docker.io/pytorch/pytorch@sha256:<digest>   # CUDA + torch, digest-pinned
python agent.py --gpu
```

Let it place the order it chose (`pip install lighter-sdk`; the API key must
already be registered to the account — the SDK's `system_setup` example does
that once):

```sh
EXECUTE=1 \
LIGHTER_PRIVATE_KEY=... LIGHTER_ACCOUNT_INDEX=... \
python agent.py --gpu
```

## The study

The agent takes the twelve markets with the strongest current funding, pulls a
week of settled hourly funding for each, and bootstraps 200k week-long paths on
the GPU for the side that receives funding today. It ranks by the 5th
percentile of weekly carry, not the mean: a market only qualifies when even a
bad week is expected to pay. If no market clears that bar, the decision is no
position.

Funding rates on Lighter are quoted per 8-hour window even in hourly rows; the
study divides accordingly. Carry here ignores price risk on the position itself
— hedge or size it as your own risk tolerance dictates.

A Lighter API key can move funds, not just trade. Keep it in a wallet you are
prepared to lose and never in a repo. This demonstrates a pipeline, not
investment advice. Prism is pre-production and unaudited.
