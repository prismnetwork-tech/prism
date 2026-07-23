# Agent quickstart

An autonomous agent leases a real GPU on Prism, runs a command, and reads the
metered result — no browser and no dashboard, authenticated by a wallet
signature and paid in USDG on Robinhood Chain.

## Three ways an agent uses Prism

| Entry point | Use it when | Docs |
| --- | --- | --- |
| **Agent SDK** (`@prism-network/agent-sdk`) | You want a lease you hold and run several commands on | [`sdk`](../../sdk/README.md) |
| **MCP server** (`@prism-network/mcp`) | Your agent speaks Model Context Protocol (Claude, etc.) | [`mcp`](../../mcp/README.md) |
| **x402** (`@prism-network/x402`) | You want a single command run for a single USDG payment | [`x402`](../../x402/README.md) |

This directory is the SDK path — the smallest end-to-end script.

## Run it

```sh
npm install
PRISM_AGENT_KEY=0x<agent wallet private key> \
PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
node quickstart.mjs
```

By default it authenticates and lists online GPUs without spending. Set
`PRISM_RUN_LEASE=1` to actually lease, run `nvidia-smi`, and release the lease —
that step spends USDG and gas.

**Prerequisites:** Node 20+, `ssh` and `ssh-keygen` on `PATH`, and an agent
wallet funded with USDG and native Robinhood-Chain gas (see the SDK's
[funding notes](../../sdk/README.md)). The packages are not yet on npm, so this
example installs the SDK from the repository via a `file:` dependency.

## Before you point it at real funds

Prism is pre-production and unaudited; mainnet escrow is paused pending a funded
canary and physical-hardware validation. Run against a development deployment,
and do not lease with a wallet or workload you cannot afford to lose. A permissionless
supplier is not a trusted computing environment.
