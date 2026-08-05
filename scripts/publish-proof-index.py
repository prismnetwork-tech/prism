#!/usr/bin/env python3
"""Publish the public settlement proof index.

Reads finalized receipts from the control-plane database and writes the
index.json that the edge serves at /proof/index.json. Refunded rows are held
back: most of them are provisioning tests rather than work anyone paid for.

The write is atomic. Caddy serves this file straight off disk, so rewriting it
in place can hand a reader a truncated document.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import tempfile

QUERY = (
    "select coalesce(json_agg(document order by block_number desc), '[]'::json)::text "
    "from proof_receipts where document->>'outcome' = 'finalized';"
)

REQUIRED_FIELDS = (
    "receipt_id",
    "lease_id",
    "gpu_model",
    "runtime_seconds",
    "charged_base_units",
    "provider_paid_base_units",
    "outcome",
    "receipt_hash",
    "transaction_hash",
)


def fetch(container: str) -> list:
    result = subprocess.run(
        ["docker", "exec", container, "psql", "-U", "prism", "-d", "prism", "-tAc", QUERY],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout.strip())


def check(receipts: list) -> None:
    for receipt in receipts:
        missing = [field for field in REQUIRED_FIELDS if not receipt.get(field)]
        if missing:
            raise SystemExit(
                f"receipt {receipt.get('receipt_id', '?')} is missing {', '.join(missing)}"
            )
        if receipt["outcome"] != "finalized":
            raise SystemExit(f"receipt {receipt['receipt_id']} is not finalized")


def write(path: str, receipts: list) -> None:
    index = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
        "receipts": receipts,
    }
    directory = os.path.dirname(path) or "."
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".index-", suffix=".json")
    try:
        with os.fdopen(handle, "w") as file:
            json.dump(index, file, separators=(",", ":"))
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default=os.environ.get("PRISM_POSTGRES_CONTAINER", "prism-network-postgres-1"))
    parser.add_argument("--output", default=os.environ.get("PRISM_PROOF_INDEX", "/opt/prism/proof-artifacts/index.json"))
    parser.add_argument("--dry-run", action="store_true", help="report what would be published")
    arguments = parser.parse_args()

    receipts = fetch(arguments.container)
    check(receipts)

    if arguments.dry_run:
        print(f"would publish {len(receipts)} receipt(s) to {arguments.output}")
    else:
        write(arguments.output, receipts)
        print(f"published {len(receipts)} receipt(s) to {arguments.output}")

    for receipt in receipts:
        trust = receipt.get("trust_class", "-")
        print(
            f"  lease {receipt['lease_id']} {receipt['gpu_model']} "
            f"{receipt['runtime_seconds']}s charged {receipt['charged_base_units']} "
            f"trust {trust} tx {receipt['transaction_hash'][:14]}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
