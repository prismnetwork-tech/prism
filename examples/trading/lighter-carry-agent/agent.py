"""An agent that rents a Prism GPU to research perp funding carry on Lighter,
then reports (and optionally places) the trade it picks.

    python agent.py                 # research with a local, downscaled study (free)
    PRISM_AGENT_KEY=0x... \
    PRISM_IMAGE=<cuda+torch digest> python agent.py --gpu
    ... EXECUTE=1 LIGHTER_PRIVATE_KEY=... python agent.py --gpu   # place the order

End to end:
  1. Pulls live funding rates and a week of settled hourly funding history for
     the most active Lighter perp markets. Market data needs no API key.
  2. Rents a GPU on Prism Network (paid on-chain in USDG on Robinhood Chain),
     ships the dataset, and runs a bootstrapped carry study there (gpu_job.py).
  3. Prints the funding-receiving position with the best risk-adjusted carry.
     With EXECUTE=1 and Lighter credentials it places that order via the
     official lighter-sdk; without them it stays a dry run.

Funding rates on Lighter are quoted per 8-hour window even in hourly rows.
A Lighter API key can move funds, not just trade: keep it in a wallet you are
prepared to lose, never in a repo. Prism is pre-production and unaudited.
This demonstrates a pipeline; it is not investment advice.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request

LIGHTER_API = "https://mainnet.zklighter.elliot.ai"
CANDIDATES = 12
HISTORY_HOURS = 168
NOTIONAL_USDC = float(os.environ.get("NOTIONAL_USDC", "20"))


def fetch(path):
    with urllib.request.urlopen(f"{LIGHTER_API}{path}", timeout=30) as res:
        body = json.load(res)
    if body.get("code") != 200:
        raise RuntimeError(f"lighter {path}: {body}")
    return body


def gather():
    print("reading Lighter: active markets, funding rates, a week of settled funding...")
    books = {b["market_id"]: b for b in fetch("/api/v1/orderBooks")["order_books"]
             if b["status"] == "active" and b["market_type"] == "perp"}
    rates = [r for r in fetch("/api/v1/funding-rates")["funding_rates"]
             if r["exchange"] == "lighter" and r["market_id"] in books]
    rates.sort(key=lambda r: abs(r["rate"]), reverse=True)
    picked = rates[:CANDIDATES]

    end = int(time.time())
    start = end - HISTORY_HOURS * 3600
    markets = {}
    for r in picked:
        rows = fetch(
            f"/api/v1/fundings?market_id={r['market_id']}&resolution=1h"
            f"&start_timestamp={start}&end_timestamp={end}&count_back={HISTORY_HOURS}"
        )["fundings"]
        history = [
            {"rate": float(row["rate"]) * (1 if row["direction"] == "long" else -1)}
            for row in rows
        ]
        if len(history) < 24:
            continue
        symbol = books[r["market_id"]]["symbol"]
        markets[symbol] = {
            "market_id": r["market_id"],
            "current_rate_8h": r["rate"],
            "history": history,
        }
        print(f"  {symbol}: current {r['rate'] * 100:+.4f}%/8h, {len(history)} settled hours")
    return {"generated_at": end, "markets": markets}


def analyze_locally(dataset):
    """The same study as gpu_job.py, downscaled to run anywhere."""
    import random

    print("\nanalyzing locally (small sample; use --gpu for the full study)...")
    report = {"device": "local cpu", "paths": 2000, "horizon_hours": HISTORY_HOURS, "markets": {}}
    for symbol, m in dataset["markets"].items():
        rates = [h["rate"] for h in m["history"]]
        # The receiving side is short when longs currently pay, long otherwise.
        # Its hourly carry is the signed settled rate (per-8h units) over 8.
        side = 1 if m["current_rate_8h"] > 0 else -1
        outcomes = []
        for _ in range(report["paths"]):
            outcomes.append(sum(side * random.choice(rates) for _ in range(HISTORY_HOURS)) / 8)
        outcomes.sort()
        n = len(outcomes)
        report["markets"][symbol] = {
            "carry_week_mean": sum(outcomes) / n,
            "carry_week_p05": outcomes[int(n * 0.05)],
            "p_positive": sum(o > 0 for o in outcomes) / n,
        }
    return report


def analyze_on_gpu(dataset):
    from prismnetwork import PrismAgent

    image = os.environ.get("PRISM_IMAGE")
    key = os.environ.get("PRISM_AGENT_KEY")
    if not image or not key:
        sys.exit("--gpu needs PRISM_AGENT_KEY and PRISM_IMAGE (a digest-pinned CUDA + torch image)")
    agent = PrismAgent(key, os.environ.get("PRISM_ESCROW", "0x62C042265991bEa17B07229322A01850974626dA"))
    agent.authenticate()
    print("\nleasing a GPU on Prism (provisioning usually takes 1-4 minutes)...")
    lease = agent.lease(image=image, duration_seconds=1200, min_vram_mib=16000)
    print(f"leased #{lease.lease_id}, funded on-chain: {lease.funding_hash}")
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "gpu_job.py"), "rb") as f:
            job = base64.b64encode(f.read()).decode()
        payload = base64.b64encode(json.dumps(dataset).encode()).decode()
        remote = " && ".join([
            f"printf %s {job} | base64 -d > /tmp/gpu_job.py",
            f"printf %s {payload} | base64 -d > /tmp/funding.json",
            "python /tmp/gpu_job.py /tmp/funding.json",
        ])
        result = agent.run(lease, remote, timeout=600)
        if result["code"] != 0:
            raise RuntimeError(f"gpu job exit {result['code']}: {result['stderr']}")
        line = [l for l in result["stdout"].splitlines() if l.startswith("{")][-1]
        return json.loads(line)
    finally:
        agent.end_lease(lease)
        print("lease released; it settles on-chain with a public receipt.")


def decide(dataset, analysis):
    print(f"\nanalysis ({analysis['device']}, {analysis['paths']} paths, "
          f"{analysis['horizon_hours']}h horizon), weekly carry for the receiving side:")
    ranked = sorted(
        ((s, a) for s, a in analysis["markets"].items()),
        key=lambda kv: kv[1]["carry_week_p05"], reverse=True,
    )
    for symbol, a in ranked:
        print(f"  {symbol}: mean {a['carry_week_mean'] * 100:+.3f}%/wk, "
              f"p05 {a['carry_week_p05'] * 100:+.3f}%/wk, p(gain) {a['p_positive'] * 100:.0f}%")
    symbol, best = ranked[0]
    if best["carry_week_p05"] <= 0:
        print("\ndecision: no position — no market's carry is positive at the 5th percentile.")
        return None
    market = dataset["markets"][symbol]
    side = "short" if market["current_rate_8h"] > 0 else "long"
    print(f"\ndecision: {side} {symbol} for {NOTIONAL_USDC} USDC to receive funding "
          f"(worst-case weekly carry {best['carry_week_p05'] * 100:+.3f}%).")
    return {"symbol": symbol, "market_id": market["market_id"], "side": side}


def execute(plan):
    """Place the order through the official SDK (pip install lighter-sdk).

    The API key must already be registered to the Lighter account; the SDK's
    system_setup example does that once.
    """
    import asyncio

    import lighter

    async def place():
        client = lighter.SignerClient(
            url=LIGHTER_API,
            private_key=os.environ["LIGHTER_PRIVATE_KEY"],
            account_index=int(os.environ["LIGHTER_ACCOUNT_INDEX"]),
            api_key_index=int(os.environ.get("LIGHTER_API_KEY_INDEX", "0")),
        )
        err = client.check_client()
        if err:
            raise RuntimeError(f"lighter client: {err}")
        detail = fetch(f"/api/v1/orderBookDetails?market_id={plan['market_id']}")["order_book_details"][0]
        price = float(detail["last_trade_price"])
        size_decimals = int(detail["size_decimals"])
        base_amount = max(1, int(NOTIONAL_USDC / price * 10 ** size_decimals))
        tx, tx_hash, err = await client.create_market_order(
            market_index=plan["market_id"],
            client_order_index=int(time.time()),
            base_amount=base_amount,
            avg_execution_price=int(price * 10 ** int(detail["price_decimals"]) * 1.02),
            is_ask=plan["side"] == "short",
        )
        if err:
            raise RuntimeError(f"order rejected: {err}")
        print(f"order sent: {tx_hash}")
        await client.close()

    asyncio.run(place())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gpu", action="store_true", help="run the study on a rented Prism GPU")
    args = parser.parse_args()

    dataset = gather()
    if not dataset["markets"]:
        sys.exit("no market history came back — try again shortly")
    analysis = analyze_on_gpu(dataset) if args.gpu else analyze_locally(dataset)
    plan = decide(dataset, analysis)
    if plan and os.environ.get("EXECUTE") == "1" and os.environ.get("LIGHTER_PRIVATE_KEY"):
        execute(plan)
    elif plan:
        print("dry run — set EXECUTE=1 with Lighter credentials to place the order.")


if __name__ == "__main__":
    main()
