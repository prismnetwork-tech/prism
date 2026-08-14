#!/usr/bin/env python3
"""Alarm on the ways Prism stops serving customers without falling over.

Every outage so far has been silent. The marketplace ran with no capacity for an
hour because a broker variable was blank, and settlement was dead for nineteen
because every transaction was priced under the base fee. Both services stayed
up and healthy the whole time, so anything watching processes would have seen
nothing wrong.

These checks look at outcomes instead: is there capacity a customer could
actually lease, are leases reaching their end state, can the signers still pay
for the transactions that release money. The reconciliation monitor already
answers the lease-versus-chain questions, so its metrics are read rather than
duplicated.

Alarms fire on change, not on every run, and recoveries are reported too. An
alarm that repeats every five minutes gets muted by whoever reads it.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_STATE = "/var/lib/prism/health-state.json"
REPEAT_SECONDS = 6 * 60 * 60
# The RPC sits behind a CDN that answers urllib's default agent with a 403.
AGENT = "prism-health/1.0"


class Alarm:
    def __init__(self, name, detail):
        self.name = name
        self.detail = detail


def psql(container, sql):
    result = subprocess.run(
        ["docker", "exec", container, "psql", "-U", "prism", "-d", "prism", "-tAc", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def post(url, payload, headers=None):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": AGENT, **(headers or {})},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read()


def get(url, headers=None, timeout=15):
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode()


def rpc(url, method, params):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    answer = json.loads(post(url, body))
    if "error" in answer:
        raise RuntimeError(f"{method}: {answer['error']}")
    return answer["result"]


def check_supply(alarms, container, minimum):
    """A marketplace with nothing rentable is indistinguishable from a healthy
    one until somebody tries to lease."""
    available = int(
        psql(
            container,
            "SELECT count(*) FROM cloud_capacity "
            "WHERE available AND updated_at > NOW() - INTERVAL '5 minutes';",
        )
    )
    if available < minimum:
        alarms.append(
            Alarm("supply", f"{available} node(s) rentable right now, expected at least {minimum}")
        )


def check_stuck(alarms, container, settlement_seconds, provisioning_seconds):
    stuck_settlement = psql(
        container,
        "SELECT coalesce(string_agg(lease_id::text, ', '), '') FROM leases "
        f"WHERE state = 'settlement_pending' AND updated_at < NOW() - INTERVAL '{settlement_seconds} seconds';",
    )
    if stuck_settlement:
        alarms.append(
            Alarm(
                "settlement",
                f"lease(s) {stuck_settlement} have not finalized in {settlement_seconds // 60} minutes",
            )
        )

    stuck_provisioning = psql(
        container,
        "SELECT coalesce(string_agg(lease_id::text, ', '), '') FROM leases "
        "WHERE state IN ('funded', 'provisioning', 'ready') "
        f"AND created_at < NOW() - INTERVAL '{provisioning_seconds} seconds';",
    )
    if stuck_provisioning:
        alarms.append(
            Alarm(
                "provisioning",
                f"lease(s) {stuck_provisioning} never reached a customer in "
                f"{provisioning_seconds // 60} minutes",
            )
        )


def check_unconfirmed(alarms, rpc_url, escrow, grace_seconds, depth):
    """Ask the escrow, not our database, whether anyone has paid and got nothing.

    The stuck-lease checks read the leases table, so they can only see leases we
    managed to record. When confirmation itself is what breaks, the renter's
    money moves on chain and no row is ever written, and every database-shaped
    check stays green through a total outage. That is not hypothetical: lease
    IDs from a redeployed escrow collided with a previous deployment's history,
    confirmation rejected every one of them, and nothing here noticed.
    """
    if not escrow:
        alarms.append(
            Alarm("unconfigured", "PRISM_LEASE_ESCROW_ADDRESS is empty, so nothing watches funding")
        )
        return

    def call(data):
        return rpc(rpc_url, "eth_call", [{"to": escrow, "data": data}, "latest"])

    count = int(call("0xb4c0498b"), 16)
    now = int(time.time())
    abandoned = []
    for lease_id in range(count, max(count - depth, 0), -1):
        words = call(f"0x9f44657c{lease_id:064x}")[2:]
        status = int(words[13 * 64 : 14 * 64], 16)
        created_at = int(words[6 * 64 : 7 * 64], 16)
        # Funded, and past the point where provisioning should have moved it on.
        if status == 1 and now - created_at > grace_seconds:
            abandoned.append(lease_id)

    if abandoned:
        alarms.append(
            Alarm(
                "unconfirmed",
                f"escrow lease(s) {', '.join(str(one) for one in sorted(abandoned))} were funded "
                f"over {grace_seconds // 60} minutes ago and never started",
            )
        )


def check_signers(alarms, rpc_url, signers, floor_wei):
    """A signer that cannot pay for gas stops releasing money, and the leases it
    abandons look fine in every other way."""
    if not signers:
        alarms.append(
            Alarm("unconfigured", "PRISM_ALERT_SIGNERS is empty, so nothing watches signer gas")
        )
        return
    for name, wallet in signers:
        balance = int(rpc(rpc_url, "eth_getBalance", [wallet, "latest"]), 16)
        if balance < floor_wei:
            alarms.append(
                Alarm(
                    f"gas:{name}",
                    f"{wallet[:10]} holds {balance / 1e18:.6f} ETH, under the "
                    f"{floor_wei / 1e18:.6f} floor",
                )
            )


def check_provider_credit(alarms, api_key, floor_dollars):
    if not api_key:
        return
    account = json.loads(
        get(
            "https://console.vast.ai/api/v0/users/current/",
            {"Authorization": f"Bearer {api_key}"},
        )
    )
    credit = float(account.get("credit") or 0)
    if credit < floor_dollars:
        alarms.append(
            Alarm("provider_credit", f"Vast credit is ${credit:.2f}, under the ${floor_dollars:.2f} floor")
        )


def check_canary(alarms, path, stale_seconds):
    """Everything else here infers health. This reads the result of actually
    renting a GPU: quote, fund, provision, log in, run something, settle.

    Every fault worth having found this year was found by leasing, not by
    watching. A lease id that collided with a superseded escrow, a host judged
    on a port it had not been given yet, a machine handed over before it was
    reachable: all of them left every gauge here reading normal, because each
    gauge asks whether a part is working rather than whether a customer can be
    served."""
    try:
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
    except FileNotFoundError:
        alarms.append(Alarm("canary", "no lease has been attempted yet"))
        return
    except (OSError, ValueError) as error:
        alarms.append(Alarm("canary", f"canary result is unreadable: {error}"))
        return

    finished = float(report.get("finished_at", 0))
    age = time.time() - finished
    if age > stale_seconds:
        alarms.append(
            Alarm(
                "canary",
                f"no lease attempted for {int(age // 60)} minutes; the last one "
                f"is too old to say whether renting still works",
            )
        )
        return
    if not report.get("ok"):
        alarms.append(
            Alarm(
                "canary",
                f"renting a GPU failed at the {report.get('stage', 'unknown')} step: "
                f"{report.get('error', 'no detail')}",
            )
        )


def check_reconciliation(alarms, url):
    """The monitor already reconciles leases against the escrow. Read its
    answers rather than asking the same questions a second way."""
    try:
        body = get(url, timeout=10)
    except (urllib.error.URLError, OSError) as error:
        alarms.append(Alarm("reconcile", f"reconciliation monitor is unreachable: {error}"))
        return

    readings = {}
    for line in body.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        key, _, value = line.rpartition(" ")
        try:
            readings[key.strip()] = float(value)
        except ValueError:
            continue

    if readings.get("prism_reconcile_up", 0) != 1:
        alarms.append(Alarm("reconcile", "reconciliation monitor cannot read its own inputs"))
    if readings.get("prism_reconcile_solvency_ok", 1) != 1:
        alarms.append(Alarm("solvency", "escrow USDG no longer covers the open lease deposits"))
    violations = readings.get("prism_reconcile_conservation_violations_total", 0)
    if violations:
        alarms.append(Alarm("conservation", f"{int(violations)} settlement(s) did not conserve USDG"))


def notify(message, telegram_token, telegram_chat, webhook):
    if telegram_token and telegram_chat:
        post(
            f"https://api.telegram.org/bot{telegram_token}/sendMessage",
            {"chat_id": telegram_chat, "text": message, "disable_web_page_preview": True},
        )
        return True
    if webhook:
        post(webhook, {"text": message})
        return True
    return False


def load_state(path):
    try:
        with open(path) as file:
            return json.load(file)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = f"{path}.new"
    with open(temporary, "w") as file:
        json.dump(state, file)
    os.replace(temporary, path)


def parse_signers(raw):
    signers = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, _, wallet = entry.partition("=")
        if not wallet:
            raise SystemExit(f"PRISM_ALERT_SIGNERS entry {entry!r} is not name=0xaddress")
        signers.append((name.strip(), wallet.strip()))
    return signers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default=os.environ.get("PRISM_POSTGRES_CONTAINER", "prism-network-postgres-1"))
    parser.add_argument("--state", default=os.environ.get("PRISM_ALERT_STATE", DEFAULT_STATE))
    parser.add_argument("--quiet", action="store_true", help="check and report, send nothing")
    arguments = parser.parse_args()

    rpc_url = os.environ.get("PRISM_RPC_URL", "https://rpc.mainnet.chain.robinhood.com")
    metrics_url = os.environ.get("PRISM_RECONCILE_METRICS_URL", "http://127.0.0.1:9092/metrics")
    minimum_supply = int(os.environ.get("PRISM_ALERT_MIN_RENTABLE", "1"))
    settlement_seconds = int(os.environ.get("PRISM_ALERT_SETTLEMENT_SECONDS", "1800"))
    provisioning_seconds = int(os.environ.get("PRISM_ALERT_PROVISIONING_SECONDS", "900"))
    escrow = os.environ.get("PRISM_LEASE_ESCROW_ADDRESS", "").strip()
    # The escrow refunds an unprovisioned lease after ten minutes, so anything
    # still funded past that was abandoned rather than merely slow.
    unconfirmed_seconds = int(os.environ.get("PRISM_ALERT_UNCONFIRMED_SECONDS", "900"))
    unconfirmed_depth = int(os.environ.get("PRISM_ALERT_UNCONFIRMED_DEPTH", "25"))
    gas_floor = int(float(os.environ.get("PRISM_ALERT_GAS_FLOOR_ETH", "0.0005")) * 1e18)
    credit_floor = float(os.environ.get("PRISM_ALERT_CREDIT_FLOOR_USD", "25"))
    canary_path = os.environ.get("PRISM_CANARY_RESULT", "/var/lib/prism/canary.json")
    # Two missed runs before anyone is woken, so one flaky host does not page.
    canary_stale = int(os.environ.get("PRISM_ALERT_CANARY_SECONDS", str(3 * 6 * 60 * 60)))
    signers = parse_signers(os.environ.get("PRISM_ALERT_SIGNERS", ""))

    alarms = []
    probes = (
        ("supply", lambda: check_supply(alarms, arguments.container, minimum_supply)),
        ("stuck", lambda: check_stuck(alarms, arguments.container, settlement_seconds, provisioning_seconds)),
        ("unconfirmed", lambda: check_unconfirmed(alarms, rpc_url, escrow, unconfirmed_seconds, unconfirmed_depth)),
        ("signers", lambda: check_signers(alarms, rpc_url, signers, gas_floor)),
        ("credit", lambda: check_provider_credit(alarms, os.environ.get("VAST_API_KEY"), credit_floor)),
        ("reconcile", lambda: check_reconciliation(alarms, metrics_url)),
        ("canary", lambda: check_canary(alarms, canary_path, canary_stale)),
    )
    for name, probe in probes:
        try:
            probe()
        except Exception as error:  # a check that cannot run is itself a finding
            alarms.append(Alarm(f"probe:{name}", f"the {name} check could not run: {error}"))

    now = int(time.time())
    previous = load_state(arguments.state)
    current = {}
    announce = []
    for alarm in alarms:
        first_seen = previous.get(alarm.name, {}).get("first_seen", now)
        last_sent = previous.get(alarm.name, {}).get("last_sent", 0)
        due = alarm.name not in previous or now - last_sent >= REPEAT_SECONDS
        current[alarm.name] = {"first_seen": first_seen, "last_sent": now if due else last_sent}
        if due:
            announce.append(f"PRISM {alarm.name}: {alarm.detail}")

    recovered = sorted(set(previous) - {alarm.name for alarm in alarms})
    for name in recovered:
        announce.append(f"PRISM {name}: recovered")

    for line in announce:
        print(line)
    if not alarms:
        print("all clear")

    delivered = True
    if announce and not arguments.quiet:
        try:
            delivered = notify(
                "\n".join(announce),
                os.environ.get("PRISM_ALERT_TELEGRAM_TOKEN"),
                os.environ.get("PRISM_ALERT_TELEGRAM_CHAT"),
                os.environ.get("PRISM_ALERT_WEBHOOK_URL"),
            )
            if not delivered:
                print("no alert channel configured, so this went nowhere", file=sys.stderr)
        except Exception as error:  # a channel outage is a condition, not a crash
            delivered = False
            print(f"alert delivery failed: {error}", file=sys.stderr)

    # Recording an alarm that never reached anyone would mute the retry.
    if not arguments.quiet and delivered:
        save_state(arguments.state, current)
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
