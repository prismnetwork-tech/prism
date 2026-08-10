# @prismnetwork/mcp

An MCP server that lets Claude (or any MCP client) see and lease real GPUs through [Prism Network](https://prismnetwork.tech). Give it a wallet and it handles auth, onchain payment, provisioning, and SSH.

## Try it without a wallet

Looking costs nothing and needs no configuration:

```sh
claude mcp add prism -- npx -y @prismnetwork/mcp
```

Then ask what you can rent. `prism_list_gpus` answers from live capacity with
real prices. Leasing spends money, so those tools ask for a wallet and say so.

## Tools

| Tool | Wallet |
| --- | --- |
| `prism_list_gpus` | no |
| `prism_wallet` | yes |
| `prism_lease_and_run` | yes |
| `prism_lease` | yes |
| `prism_run` | yes |
| `prism_end_lease` | yes |

- `prism_wallet`: the agent's address and USDG/ETH balances.
- `prism_list_gpus`: GPUs available to lease, with price per second and per hour.
- `prism_lease_and_run`: lease a GPU, run a command, return the output (one shot).
- `prism_lease`: lease a GPU and keep it; returns a `lease_id` and SSH access.
- `prism_run`: run a command on an existing lease.
- `prism_end_lease`: release a lease.

## Configure

Point your MCP client (Claude Desktop / Code) at the published server:

```json
{
  "mcpServers": {
    "prism": {
      "command": "npx",
      "args": ["-y", "@prismnetwork/mcp"],
      "env": {
        "PRISM_AGENT_KEY": "0x<agent wallet private key>",
        "PRISM_ESCROW": "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD"
      }
    }
  }
}
```

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas. See the SDK's Funding section for how to fund a fresh wallet.

Or add it to Claude Code in one line:

```sh
claude mcp add prism \
  --env PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
  --env PRISM_AGENT_KEY=0x<agent wallet private key> \
  -- npx -y @prismnetwork/mcp
```

## Timing

`prism_lease` and `prism_lease_and_run` block while a GPU provisions (usually one to four minutes, occasionally longer on a slow host). Configure your MCP client to allow long tool calls.
