"""The GPU half of the stock-token agent: a bootstrapped Monte Carlo momentum
study over Chainlink price history, run on a Prism-leased GPU.

Reads the market dataset agent.mjs ships over SSH, resamples each ticker's
return history into 200k forward paths on the GPU, tilts by momentum, and
prints one JSON line the agent parses back out of stdout.
"""

import json
import sys

import torch

PATHS = 200_000
HORIZON_DAYS = 5
ROUNDS_PER_DAY = 2  # stock feeds update on a 24/5 market schedule
MOMENTUM_LOOKBACK = 20
MOMENTUM_TILT = 0.35


def study(history, device):
    prices = torch.tensor([h["price"] for h in history], dtype=torch.float64, device=device)
    returns = torch.log(prices[1:] / prices[:-1])
    # A young feed's first rounds can carry initialization artifacts; a 30%
    # move between consecutive rounds is data noise, not a market move.
    returns = returns[returns.abs() < 0.3]
    if len(returns) < 20:
        return {"momentum_20r": 0.0, "expected_return": 0.0, "var_95": 0.0,
                "p_positive": 0.0, "insufficient_history": True}
    lookback = min(MOMENTUM_LOOKBACK, len(prices) - 1)
    momentum = float(torch.log(prices[-1] / prices[-1 - lookback]))

    steps = HORIZON_DAYS * ROUNDS_PER_DAY
    idx = torch.randint(len(returns), (PATHS, steps), device=device)
    outcomes = returns[idx].sum(dim=1)
    tilted = outcomes + momentum * MOMENTUM_TILT

    return {
        "momentum_20r": momentum,
        "expected_return": float(tilted.mean()),
        "var_95": float(torch.quantile(outcomes, 0.05)),
        "p_positive": float((tilted > 0).double().mean()),
    }


def main():
    with open(sys.argv[1]) as f:
        dataset = json.load(f)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    name = torch.cuda.get_device_name(0) if device == "cuda" else "cpu"
    report = {
        "device": name,
        "paths": PATHS,
        "horizon_days": HORIZON_DAYS,
        "tickers": {sym: study(d["history"], device) for sym, d in dataset["tickers"].items()},
    }
    print(json.dumps(report))


if __name__ == "__main__":
    main()
