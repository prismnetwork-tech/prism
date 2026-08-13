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
| `prism_vault_store` | yes |
| `prism_vault_list` | yes |
| `prism_vault_read` | yes |
| `prism_vault_delete` | yes |
| `prism_vault_release` | yes |

- `prism_wallet`: the agent's address and USDG/ETH balances.
- `prism_list_gpus`: GPUs available to lease, with price per second and per hour.
- `prism_lease_and_run`: lease a GPU, run a command, return the output (one shot).
- `prism_lease`: lease a GPU and keep it; returns a `lease_id` and SSH access.
- `prism_run`: run a command on an existing lease.
- `prism_end_lease`: release a lease.
- `prism_vault_store`: seal private data under the wallet-derived key.
- `prism_vault_list`: list sealed items; values are never returned.
- `prism_vault_read`: decrypt one item in this process.
- `prism_vault_delete`: permanently delete an item.
- `prism_vault_release`: authorize an item into a lease that clears its trust floor.

## Vault

An agent that handles a card, an identity document or a credential should not
write it into a leased workspace. `prism_vault_store` seals it under a key
derived from the agent's wallet inside this server process; Prism receives
ciphertext and holds no way to read it.

Each item names the weakest workspace trust class it may ever be released into,
and new items default to `confidential` — above anything the network serves
today. `prism_vault_release` is therefore refused on current capacity instead of
handing a secret to a host that can read it. Lowering an item's floor is a
deliberate act, and allowed releases are recorded against the account.

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
        "PRISM_ESCROW": "0x62C042265991bEa17B07229322A01850974626dA"
      }
    }
  }
}
```

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas. See the SDK's Funding section for how to fund a fresh wallet.

Or add it to Claude Code in one line:

```sh
claude mcp add prism \
  --env PRISM_ESCROW=0x62C042265991bEa17B07229322A01850974626dA \
  --env PRISM_AGENT_KEY=0x<agent wallet private key> \
  -- npx -y @prismnetwork/mcp
```

## Timing

`prism_lease` and `prism_lease_and_run` block while a GPU provisions (usually one to four minutes, occasionally longer on a slow host). Configure your MCP client to allow long tool calls.
