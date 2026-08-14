"""The GPU half of the stock-token agent: a bootstrapped Monte Carlo momentum
study over Chainlink price history, run on a Prism-leased GPU.

Reads the market dataset agent.mjs ships over SSH, resamples each ticker's
return history into 200k forward paths on the GPU, tilts by momentum, and
prints one JSON line the agent parses back out of stdout. The report separates
the bootstrap mean from the momentum tilt so a reader can see which one is
driving the expected return.
"""

import json
import statistics
import sys

import torch

PATHS = 200_000
HORIZON_DAYS = 5
MOMENTUM_LOOKBACK = 20
MOMENTUM_TILT = 0.35


def steps_for_horizon(history):
    """Forward horizon in rounds, from the observed feed spacing. The feeds
    post on a market schedule, not a fixed cadence."""
    gaps = [b["t"] - a["t"] for a, b in zip(history, history[1:])]
    median = statistics.median(gaps) if gaps else 86_400
    return max(4, min(200, round(HORIZON_DAYS * 86_400 / median)))


def study(history, device):
    prices = torch.tensor([h["price"] for h in history], dtype=torch.float64, device=device)
    returns = torch.log(prices[1:] / prices[:-1])
    # A 30% move between consecutive rounds is feed noise, not a market move.
    returns = returns[returns.abs() < 0.3]
    if len(returns) < 20:
        return {"momentum": 0.0, "bootstrap_mean": 0.0, "expected_return": 0.0,
                "var_95": 0.0, "p_positive": 0.0, "insufficient_history": True}

    lookback = min(MOMENTUM_LOOKBACK, len(returns))
    momentum = float(returns[-lookback:].sum())
    tilt = momentum * MOMENTUM_TILT

    steps = steps_for_horizon(history)
    idx = torch.randint(len(returns), (PATHS, steps), device=device)
    outcomes = returns[idx].sum(dim=1) + tilt

    return {
        "momentum": momentum,
        "bootstrap_mean": float(outcomes.mean()) - tilt,
        "expected_return": float(outcomes.mean()),
        "var_95": float(torch.quantile(outcomes, 0.05)),
        "p_positive": float((outcomes > 0).double().mean()),
        "returns_used": int(len(returns)),
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
