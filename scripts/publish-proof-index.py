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
import hashlib
import json
import os
import subprocess
import sys
import tempfile

# A lease id counts from one inside a single escrow deployment, so the same
# number was issued twice when the escrow was replaced: eleven ids appeared on
# two different leases, with different GPUs and different transactions. The
# stored receipt is a signed artifact and is left alone; the escrow that issued
# it is joined on here instead, which makes every published row identify exactly
# one lease.
QUERY = (
    "select coalesce(json_agg(receipt order by block_number desc), '[]'::json)::text from ("
    "  select r.block_number,"
    "         r.document || jsonb_build_object('escrow_address', l.escrow_address) as receipt"
    "  from proof_receipts r"
    "  join leases l on l.lease_id = r.lease_id"
    "  where r.document->>'outcome' = 'finalized'"
    ") as joined;"
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
    "escrow_address",
)

# The receipt hash is what the chain committed to, so it is recomputed here
# rather than read off the row: a document edited in the database has to fail
# publication instead of travelling with a label that stopped describing it.
# The order below is the Rust ReceiptPayload declaration order, because
# canonical JSON there is serde_json::to_string and that emits fields as
# declared, not sorted. Postgres hands jsonb back in its own key order, so the
# payload is rebuilt from these tuples rather than from the row as it arrives.
# escrow_address is joined on at publication and was never in the hash.
PAYLOAD_FIELDS = (
    "receipt_id",
    "lease_id",
    "node_id_hash",
    "gpu_model",
    "runtime_seconds",
    "charged_base_units",
    "refunded_base_units",
    "provider_paid_base_units",
    "failure_class",
    "outcome",
    "trust_class",
    "attestation",
)
OMITTED_WHEN_NULL = ("trust_class", "attestation")
ATTESTATION_FIELDS = ("kind", "verdict_digest", "verifier_version")

TRUST_CLASSES = ("open", "isolated", "attested", "confidential")
MAX_VERIFIABLE_TRUST_CLASS = "isolated"


def fetch(container: str) -> list:
    result = subprocess.run(
        ["docker", "exec", container, "psql", "-U", "prism", "-d", "prism", "-tAc", QUERY],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout.strip())


def receipt_hash(receipt: dict) -> str:
    payload = {}
    for field in PAYLOAD_FIELDS:
        value = receipt.get(field)
        if field in OMITTED_WHEN_NULL and value is None:
            continue
        if field == "attestation":
            value = {key: value.get(key) for key in ATTESTATION_FIELDS}
        payload[field] = value
    canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def check(receipts: list) -> None:
    for receipt in receipts:
        missing = [field for field in REQUIRED_FIELDS if not receipt.get(field)]
        if missing:
            raise SystemExit(
                f"receipt {receipt.get('receipt_id', '?')} is missing {', '.join(missing)}"
            )
        if receipt["outcome"] != "finalized":
            raise SystemExit(f"receipt {receipt['receipt_id']} is not finalized")
        trust = receipt.get("trust_class")
        if trust is not None:
            if trust not in TRUST_CLASSES:
                raise SystemExit(f"receipt {receipt['receipt_id']} has an unknown trust class {trust}")
            if TRUST_CLASSES.index(trust) >= TRUST_CLASSES.index("attested") and not receipt.get(
                "attestation"
            ):
                raise SystemExit(
                    f"receipt {receipt['receipt_id']} claims {trust} with no attestation"
                )
            if TRUST_CLASSES.index(trust) > TRUST_CLASSES.index(MAX_VERIFIABLE_TRUST_CLASS):
                raise SystemExit(
                    f"receipt {receipt['receipt_id']} claims {trust}, which the network does not verify"
                )
        recomputed = receipt_hash(receipt)
        if recomputed != receipt["receipt_hash"]:
            raise SystemExit(
                f"receipt {receipt['receipt_id']} does not hash to {receipt['receipt_hash']}"
            )


# Two rows exactly as the index published them, one from each era of the
# trust_class field. Hashing these is what proves this recomputation agrees with
# the Rust that minted them, which is the only thing that makes a mismatch on a
# live row mean tampering rather than a bug here.
PUBLISHED_RECEIPTS = [
    {
        "outcome": "finalized",
        "lease_id": "52",
        "gpu_model": "RTX 6000Ada",
        "receipt_id": "9fa86919-eacf-87de-8a2f-373b802c27a9",
        "trust_class": "open",
        "node_id_hash": "0x8ce4cc842b5a2010b7e73891c5e6ef5a6f44d8ed375026238cdb41e8c7eba2d8",
        "receipt_hash": "6423582a59bb54c1afac11202e20aaf1235998d41e0965284961e09f9ffc764e",
        "failure_class": None,
        "escrow_address": "0x62c042265991bea17b07229322a01850974626da",
        "runtime_seconds": 900,
        "transaction_hash": "0x96e26448a09ba301951452f737038c1d4443c97af875ea509b2a547e2d4a0301",
        "charged_base_units": 199800,
        "refunded_base_units": 0,
        "provider_paid_base_units": 179820,
    },
    {
        "outcome": "finalized",
        "lease_id": "32",
        "gpu_model": "L40S",
        "receipt_id": "601f5c4e-51e7-8753-8c96-9938bf68e714",
        "node_id_hash": "0x7a727c8a2caf2c0762b4387489284e32f3142d7b699425e84aa798d33a319443",
        "receipt_hash": "b51ff6f0b21eb8584fb2b36a986489a448da8ab997a88fa2014954c2ed49a915",
        "failure_class": None,
        "escrow_address": "0x71df0ef3bc81022cb3bec0b1a05f52f12bafcded",
        "runtime_seconds": 600,
        "transaction_hash": "0x44b1f9ec5bc20b387faa4fe7292ca3b5d5dc0a36c9478e6dc30d136a0038af3c",
        "charged_base_units": 133200,
        "refunded_base_units": 0,
        "provider_paid_base_units": 119880,
    },
]


def rejects(receipt: dict, reason: str) -> None:
    try:
        check([receipt])
    except SystemExit as error:
        assert reason in str(error), f"rejected for the wrong reason: {error}"
        return
    raise AssertionError(f"receipt was published, expected a rejection for {reason}")


def self_test() -> int:
    check(PUBLISHED_RECEIPTS)

    for field in ("charged_base_units", "runtime_seconds", "provider_paid_base_units"):
        rejects(dict(PUBLISHED_RECEIPTS[0], **{field: 1}), "does not hash to")
    rejects(dict(PUBLISHED_RECEIPTS[0], trust_class="isolated"), "does not hash to")
    rejects(dict(PUBLISHED_RECEIPTS[0], trust_class="attested"), "with no attestation")
    rejects(dict(PUBLISHED_RECEIPTS[0], trust_class="turbo"), "unknown trust class")

    attestation = {
        "kind": "nvidia_gpu",
        "verdict_digest": "d" * 64,
        "verifier_version": "prism-attestation/0.1.0",
    }
    rejects(
        dict(PUBLISHED_RECEIPTS[0], trust_class="confidential", attestation=attestation),
        "does not verify",
    )

    attested = dict(PUBLISHED_RECEIPTS[1], trust_class="isolated", attestation=attestation)
    attested["receipt_hash"] = receipt_hash(attested)
    check([attested])
    assert receipt_hash(dict(attested, attestation=dict(attestation, verdict_digest="e" * 64))) != attested[
        "receipt_hash"
    ], "the attestation is outside the hash"

    print(f"hash recomputation and trust rules agree with {len(PUBLISHED_RECEIPTS)} published receipt(s)")
    return 0


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
    parser.add_argument("--self-test", action="store_true", help="check the rules against published receipts")
    arguments = parser.parse_args()

    if arguments.self_test:
        return self_test()

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
