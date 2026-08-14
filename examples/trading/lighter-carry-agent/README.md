# Funding-carry research agent

An agent that rents a Prism GPU to research perp funding carry on
[Lighter](https://lighter.xyz), then reports (and optionally places) the trade
it picks. The GPU lease is paid on-chain in USDG on Robinhood Chain (about
0.27 USDG for the 20-minute window) and settles with a verifiable receipt;
Lighter market data needs no API key.

```
Lighter funding rates ──┐
settled funding history ┼─> dataset ──> Prism GPU lease ──> bootstrap carry study
active order books    ──┘                (paid in USDG)          │
                                                                 v
                        lighter-sdk order  <── decision: best p05 carry > 0?
```

## Run it

Free, no wallet, no installs: the local mode is standard library only:

```sh
python3 agent.py
```

Full 200k-path study on a rented GPU (needs Python 3.10+):

```sh
pip install prismnetwork
export PRISM_AGENT_KEY=0x...   # wallet holding USDG + gas on Robinhood Chain
export PRISM_IMAGE=docker.io/pytorch/pytorch@sha256:<digest>   # CUDA + torch, digest-pinned
python3 agent.py --gpu
```

Let it place the order it chose (`pip install lighter-sdk`; the API key must
already be registered to the account; the SDK's `system_setup` example does
that once):

```sh
EXECUTE=1 \
LIGHTER_PRIVATE_KEY=... LIGHTER_ACCOUNT_INDEX=... \
python3 agent.py --gpu
```

## Environment

| Variable | Meaning |
| --- | --- |
| `NOTIONAL_USDC` | Order size, default 20. |
| `LIGHTER_PRIVATE_KEY` / `LIGHTER_ACCOUNT_INDEX` | The Lighter account that trades. |
| `LIGHTER_API_KEY_INDEX` | Non-default API key slot, default 0. |
| `PRISM_AGENT_KEY` / `PRISM_IMAGE` | The wallet and image for the GPU lease. |
| `PRISM_ESCROW` | Override the lease escrow contract. |

## The study

The agent takes the twelve markets with the strongest current funding and
pulls a week of settled funding for each. The two Lighter endpoints quote
different units: current rates are a fraction per 8-hour window, while settled
history rows are percent per hour. The study converts both to hourly fractions
and bootstraps 200k week-long paths on the GPU for the side that receives
funding today, ranking by the 5th percentile of the bootstrap. A market only
qualifies when that percentile is positive; funding regimes persist for days,
so read it as a resampling of last week's hours, not a guarantee about a bad
week. If no market clears the bar, the decision is no position.

Orders are immediate-or-cancel with a 2% price bound on the crossing side; an
order the book cannot fill inside the bound cancels, so verify the position on
your account before assuming carry is on. Carry here ignores price risk on the
position itself; hedge or size it as your own risk tolerance dictates.

A Lighter API key can move funds, not just trade. Keep it in a wallet you are
prepared to lose and never in a repo. This demonstrates a pipeline, not
investment advice. Prism is pre-production and unaudited.
