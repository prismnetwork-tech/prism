"""The GPU half of the funding-carry agent: a bootstrapped study of weekly
funding carry per Lighter market, run on a Prism-leased GPU.

Reads the dataset agent.py ships over SSH, resamples each market's settled
hourly funding into 200k week-long paths on the GPU, and prints one JSON line
the agent parses back out of stdout. Rates are per-8-hour units settled hourly,
so an hour's payment is rate / 8; the studied position is the side that
receives funding at the current rate.
"""

import json
import sys

import torch

PATHS = 200_000
HORIZON_HOURS = 168


def study(market, device):
    rates = torch.tensor([h["rate"] for h in market["history"]], dtype=torch.float64, device=device)
    side = 1.0 if market["current_rate_8h"] > 0 else -1.0
    idx = torch.randint(len(rates), (PATHS, HORIZON_HOURS), device=device)
    outcomes = side * rates[idx].sum(dim=1) / 8
    return {
        "carry_week_mean": float(outcomes.mean()),
        "carry_week_p05": float(torch.quantile(outcomes, 0.05)),
        "p_positive": float((outcomes > 0).double().mean()),
    }


def main():
    with open(sys.argv[1]) as f:
        dataset = json.load(f)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    name = torch.cuda.get_device_name(0) if device == "cuda" else "cpu"
    report = {
        "device": name,
        "paths": PATHS,
        "horizon_hours": HORIZON_HOURS,
        "markets": {sym: study(m, device) for sym, m in dataset["markets"].items()},
    }
    print(json.dumps(report))


if __name__ == "__main__":
    main()
