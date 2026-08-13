# Agent quickstart

An autonomous agent leases a real GPU on Prism, runs a command, and reads the
metered result — no browser and no dashboard, authenticated by a wallet
signature and paid in USDG on Robinhood Chain.

## Three ways an agent uses Prism

| Entry point | Use it when | Docs |
| --- | --- | --- |
| **Agent SDK** (`@prismnetwork/agent-sdk`) | You want a lease you hold and run several commands on | [`sdk`](../../sdk/README.md) |
| **MCP server** (`@prismnetwork/mcp`) | Your agent speaks Model Context Protocol (Claude, etc.) | [`mcp`](../../mcp/README.md) |
| **x402** (`@prismnetwork/x402`) | You want a single command run for a single USDG payment | [`x402`](../../x402/README.md) |

This directory is the SDK path — the smallest end-to-end script.

## Run it

```sh
npm install
PRISM_AGENT_KEY=0x<agent wallet private key> \
PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
node quickstart.mjs
```

By default it authenticates and lists online GPUs without spending. Set
`PRISM_RUN_LEASE=1` to actually lease, run `nvidia-smi`, and release the lease —
that step spends USDG and gas.

**Prerequisites:** Node 20+, `ssh` and `ssh-keygen` on `PATH`, and an agent
wallet funded with USDG and native Robinhood-Chain gas (see the SDK's
[funding notes](../../sdk/README.md)). `npm install` pulls the SDK from npm
(`@prismnetwork/agent-sdk`).

## Before you point it at real funds

Prism is pre-production and unaudited, so do not lease with a wallet or workload
you cannot afford to lose. Every offer carries a trust class; all capacity live
today is `open`, which means the host operator can read anything the workload
touches. Pass `minTrustClass` (`min_trust_class` in Python) to refuse anything
weaker than you need.
