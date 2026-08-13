# prismnetwork

Headless GPU leasing on [Prism Network](https://prismnetwork.tech) for autonomous
agents — the Python counterpart to `@prismnetwork/agent-sdk`. Give it a wallet; it
authenticates with a signature, pays on-chain in USDG, provisions a GPU, and runs
over SSH. No browser, no dashboard.

```sh
pip install prismnetwork
```

```python
from prismnetwork import PrismAgent, DEFAULT_IMAGE

agent = PrismAgent(private_key=AGENT_KEY, escrow="0x62C042265991bEa17B07229322A01850974626dA")
agent.authenticate()

lease = agent.lease(image=DEFAULT_IMAGE, duration_seconds=600, min_vram_mib=16000)
out = agent.run(lease, "nvidia-smi")
print(out["stdout"])
agent.end_lease(lease)
```

## What it does

`authenticate()` signs a challenge with the wallet and exchanges it for a bearer
session. `lease()` gets a quote, funds an on-chain USDG escrow bound to the quote
(`createLease`), waits for the GPU to provision, and returns SSH access. `run()`
executes a command over SSH, retrying through the host's sshd warmup. Metering is
per-second; each lease settles on-chain with a verifiable receipt.

Read-only helpers: `offers()`, `balances()`, `leases()`, `quote(...)`, `access(id)`.

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`, 6 decimals) and
native Robinhood-Chain gas.

Requires `ssh` and `ssh-keygen` on `PATH`. Chain id 4663, RPC
`https://rpc.mainnet.chain.robinhood.com`.

Prism is pre-production and unaudited. A permissionless supplier is not a trusted
computing environment; do not lease with a wallet or workload you cannot lose.
