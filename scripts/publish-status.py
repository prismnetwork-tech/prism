#!/usr/bin/env python3
"""Record what each part of Prism was doing, and publish it.

A status page that only reports the present moment is a sentence, not a record:
it cannot tell you whether yesterday was fine, and it lets a bad afternoon
disappear the moment it ends. This runs on the same timer as the health checks,
decides a status for each component, and folds it into a per-day history that
keeps the worst reading of the day rather than the most recent one.

Worst-of-day is deliberate. Averaging a seven hour outage across a day produces
a number that looks like a good day.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone

HISTORY_DAYS = 90
AGENT = "prism-status/1.0"

OPERATIONAL = "operational"
DEGRADED = "degraded"
OUTAGE = "outage"
UNKNOWN = "unknown"

# Worst wins when a day is folded together.
SEVERITY = {UNKNOWN: 0, OPERATIONAL: 1, DEGRADED: 2, OUTAGE: 3}


def psql(container, sql):
    result = subprocess.run(
        ["docker", "exec", container, "psql", "-U", "prism", "-d", "prism", "-tAc", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": AGENT},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        answer = json.loads(response.read())
    if "error" in answer:
        raise RuntimeError(answer["error"])
    return answer["result"]


def marketplace(container):
    """Capacity a renter could pick right now.

    An empty marketplace is not a fault. Supply is drawn as demand arrives, so
    quiet hours legitimately list nothing, and calling that an outage would
    train everyone to ignore the page.
    """
    listed = int(psql(container, "SELECT COUNT(*) FROM node_offers;") or 0)
    if listed == 0:
        return OPERATIONAL, "no capacity listed"
    return OPERATIONAL, f"{listed} machine{'s' if listed != 1 else ''} listed"


def leasing(container, rpc_url, escrow, grace_seconds):
    """Whether a renter who pays gets a machine.

    Asks the escrow rather than our own records. The failure this exists to
    catch is one where the money moves and nothing reaches the database, which
    is invisible to anything that starts from the database.
    """
    if not escrow:
        return UNKNOWN, "escrow address is not configured"
    call = lambda data: rpc(rpc_url, "eth_call", [{"to": escrow, "data": data}, "latest"])
    count = int(call("0xb4c0498b"), 16)
    now = int(time.time())
    abandoned = 0
    for lease_id in range(count, max(count - 25, 0), -1):
        words = call(f"0x9f44657c{lease_id:064x}")[2:]
        status = int(words[13 * 64 : 14 * 64], 16)
        created_at = int(words[6 * 64 : 7 * 64], 16)
        if status == 1 and now - created_at > grace_seconds:
            abandoned += 1
    if abandoned:
        return OUTAGE, f"{abandoned} funded lease(s) never started"
    return OPERATIONAL, "funded leases are reaching machines"


def settlement(container, stale_seconds):
    stuck = int(
        psql(
            container,
            "SELECT COUNT(*) FROM leases WHERE state = 'settlement_pending' "
            f"AND updated_at < NOW() - INTERVAL '{stale_seconds} seconds';",
        )
        or 0
    )
    if stuck:
        return DEGRADED, f"{stuck} lease(s) awaiting finalization"
    return OPERATIONAL, "leases are finalizing and publishing receipts"


def contracts(rpc_url, escrow):
    if not escrow:
        return UNKNOWN, "escrow address is not configured"
    rpc(rpc_url, "eth_call", [{"to": escrow, "data": "0xb4c0498b"}, "latest"])
    return OPERATIONAL, "escrow and registry are reachable"


def probe(name, group, run):
    try:
        status, detail = run()
    except Exception as error:  # a component we cannot read is not a component we can vouch for
        status, detail = UNKNOWN, f"could not be checked: {error}"
    return {"key": name[0], "name": name[1], "group": group, "status": status, "detail": detail}


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            existing = json.load(handle)
        history = existing.get("history")
        return history if isinstance(history, list) else []
    except (OSError, ValueError):
        return []


def fold(history, components, today):
    by_date = {entry["date"]: entry for entry in history if isinstance(entry.get("date"), str)}
    day = by_date.setdefault(today, {"date": today, "statuses": {}})
    for component in components:
        seen = day["statuses"].get(component["key"], UNKNOWN)
        if SEVERITY[component["status"]] > SEVERITY.get(seen, 0):
            day["statuses"][component["key"]] = component["status"]
        elif component["key"] not in day["statuses"]:
            day["statuses"][component["key"]] = component["status"]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%d")
    return sorted((entry for entry in by_date.values() if entry["date"] >= cutoff), key=lambda e: e["date"])


def write(path, payload):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            json.dump(payload, file, separators=(",", ":"), sort_keys=True)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        os.unlink(temporary)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default=os.environ.get("PRISM_POSTGRES_CONTAINER", "prism-network-postgres-1"))
    parser.add_argument("--output", default=os.environ.get("PRISM_STATUS_INDEX", "/opt/prism/proof-artifacts/status.json"))
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    rpc_url = os.environ.get("PRISM_RPC_URL", "https://rpc.mainnet.chain.robinhood.com")
    escrow = os.environ.get("PRISM_LEASE_ESCROW_ADDRESS", "").strip()
    unconfirmed_seconds = int(os.environ.get("PRISM_ALERT_UNCONFIRMED_SECONDS", "900"))
    settlement_seconds = int(os.environ.get("PRISM_ALERT_SETTLEMENT_SECONDS", "1800"))

    components = [
        probe(("marketplace", "Marketplace"), "Renting", lambda: marketplace(arguments.container)),
        probe(("leasing", "Leasing and provisioning"), "Renting",
              lambda: leasing(arguments.container, rpc_url, escrow, unconfirmed_seconds)),
        probe(("settlement", "Settlement and receipts"), "Payment",
              lambda: settlement(arguments.container, settlement_seconds)),
        probe(("contracts", "Onchain contracts"), "Payment", lambda: contracts(rpc_url, escrow)),
    ]

    now = datetime.now(timezone.utc)
    payload = {
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "components": components,
        "history": fold(load(arguments.output), components, now.strftime("%Y-%m-%d")),
    }

    if arguments.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    write(arguments.output, payload)
    for component in components:
        print(f"  {component['status']:<12} {component['name']}: {component['detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
