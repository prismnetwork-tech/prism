# @prism-network/mcp

An MCP server that lets Claude (or any MCP client) lease and run on real GPUs through [Prism Network](https://prismnetwork.tech). Give it a wallet; it handles auth, on-chain payment, provisioning, and SSH.

## Tools

- **prism_wallet** — the agent's address and USDG/ETH balances.
- **prism_list_gpus** — GPUs available to lease, with price per second/hour.
- **prism_lease_and_run** — lease a GPU, run a command, return the output (one shot).
- **prism_lease** — lease a GPU and keep it; returns `lease_id` + SSH access.
- **prism_run** — run a command on an existing lease.
- **prism_end_lease** — release a lease.

## Configure (Claude Desktop / Code)

```json
{
  "mcpServers": {
    "prism": {
      "command": "npx",
      "args": ["-y", "@prism-network/mcp"],
      "env": {
        "PRISM_AGENT_KEY": "0x<agent wallet private key>",
        "PRISM_ESCROW": "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD"
      }
    }
  }
}
```

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas.

## Note on timing

`prism_lease` / `prism_lease_and_run` block while a GPU provisions (typically 1–4 minutes, occasionally longer on a slow host). Configure your MCP client to allow long tool calls.
