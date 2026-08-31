"""Authenticate a wallet, list GPUs, and optionally lease one and run a command.

    PRISM_AGENT_KEY=0x<agent wallet private key> \\
    PRISM_ESCROW=0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD \\
    python quickstart.py

By default this authenticates and lists GPUs without spending. Set PRISM_RUN_LEASE=1
to lease, run nvidia-smi, and release the lease (spends USDG + gas). Prism is
pre-production and unaudited; do not use funds you cannot lose.
"""
import os
import sys

from prismnetwork import DEFAULT_IMAGE, PrismAgent


def require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"missing {name}")
    return value


agent = PrismAgent(private_key=require("PRISM_AGENT_KEY"), escrow=require("PRISM_ESCROW"))

session = agent.authenticate()
print("authenticated as", session["subject"])

offers = agent.offers()
if not offers:
    sys.exit("no GPUs online right now; try again shortly.")
print(f"{len(offers)} offer(s):", ", ".join(o["gpu"]["model"] for o in offers))

if os.environ.get("PRISM_RUN_LEASE") != "1":
    print("\nauth OK. Set PRISM_RUN_LEASE=1 to lease + run (spends USDG + gas).")
    sys.exit(0)

print("leasing a GPU (provisioning takes a few minutes)...")
lease = agent.lease(image=DEFAULT_IMAGE, duration_seconds=600, min_vram_mib=16000)
print("leased", lease.lease_id, "funded on-chain:", lease.funding_hash)

result = agent.run(lease, "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader")
print(f"\nremote output (exit {result['code']}):\n{result['stdout'] or result['stderr']}")

agent.end_lease(lease)
print("lease released. Settlement and a public receipt follow on chain.")
