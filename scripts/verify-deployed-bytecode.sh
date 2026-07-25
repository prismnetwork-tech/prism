#!/usr/bin/env bash
# Compare the contracts in this repository against what is deployed on
# Robinhood Chain, using only the public RPC.
#
# Two things legitimately differ from a plain artifact comparison. Immutable
# variables are blank in the compiled artifact and filled in at deploy time, so
# their byte ranges are masked out and reported separately. Solidity also
# appends a CBOR metadata blob whose hash covers comments and file paths, so it
# moves without the executable code changing; it is compared but never fatal.
set -euo pipefail

RPC="${PRISM_RPC_URL:-https://rpc.mainnet.chain.robinhood.com}"

targets=(
  "NodeRegistryV1:0xe3b7eF730637763ed46542d41a6C3f83AfC78f01"
  "LeaseEscrowV1:0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD"
)

forge build >/dev/null 2>&1

failed=0
for target in "${targets[@]}"; do
  name="${target%%:*}"
  address="${target##*:}"

  onchain="$(curl -sS -X POST "$RPC" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$address\",\"latest\"]}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')"

  if ! python3 - "$name" "$address" "$onchain" <<'PY'
import json
import sys

name, address, onchain = sys.argv[1:4]
artifact = json.load(open(f"contracts/out/{name}.sol/{name}.json"))
deployed = artifact["deployedBytecode"]
local = deployed["object"].lower().removeprefix("0x")
chain = onchain.lower().removeprefix("0x")

if not chain:
    print(f"{name} {address}: no code at this address")
    sys.exit(1)


def mask_immutables(code: str) -> str:
    out = list(code)
    for slots in deployed.get("immutableReferences", {}).values():
        for slot in slots:
            start, length = slot["start"] * 2, slot["length"] * 2
            out[start : start + length] = "0" * length
    return "".join(out)


def split_metadata(code: str) -> tuple[str, str]:
    if len(code) < 4:
        return code, ""
    length = int(code[-4:], 16) * 2
    if length + 4 > len(code):
        return code, ""
    return code[: -(length + 4)], code[-(length + 4) :]


local_code, local_meta = split_metadata(mask_immutables(local))
chain_code, chain_meta = split_metadata(mask_immutables(chain))

if local_code != chain_code:
    print(f"{name} {address}: EXECUTABLE CODE DIFFERS from this repository")
    sys.exit(1)

state = "identical" if local_meta == chain_meta else "differs"
print(f"{name} {address}: executable code matches, metadata {state}")
PY
  then
    failed=1
  fi
done

exit "$failed"
