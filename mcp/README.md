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
| `prism_budget` | no |
| `prism_list_gpus` | no |
| `prism_price_index` | no |
| `prism_receipts` | no |
| `prism_wallet` | yes |
| `prism_leases` | yes |
| `prism_infer` | yes |
| `prism_infer_batch` | yes |
| `prism_confidential_infer` | yes |
| `prism_verify_attestation` | no |
| `prism_lease_and_run` | yes |
| `prism_lease` | yes |
| `prism_run` | yes |
| `prism_batch_run` | yes |
| `prism_end_lease` | yes |
| `prism_vault_store` | yes |
| `prism_vault_list` | yes |
| `prism_vault_read` | yes |
| `prism_vault_delete` | yes |
| `prism_vault_release` | yes |

- `prism_budget`: the spending limits this server enforces, what it has spent
  in the last 24 hours, and the recent charges.
- `prism_wallet`: the agent's address and USDG/ETH balances.
- `prism_list_gpus`: GPUs available to lease, with price per second and per hour.
- `prism_price_index`: sourced and settled pricing per GPU model, for cost estimates.
- `prism_receipts`: recent settled receipts from the public proof feed, with the
  settlement transaction on Robinhood Chain.
- `prism_leases`: this wallet's leases and their state.
- `prism_infer`: buy one LLM generation from the managed inference endpoint,
  paying the quoted USDG price from this wallet (about 0.01 USDG). Waits
  through a cold start; an unconsumed payment is kept and reused on the next
  call instead of paying twice.
- `prism_infer_batch`: buy many generations in one paid call, at the
  single-generation price times the number of prompts. Each prompt runs whole on
  a rented GPU and they are spread across every GPU the endpoint holds, so a
  list of prompts finishes far sooner than the same prompts sent one at a time.
  Returns every answer in order with a Merkle receipt naming the leases that did
  the work.
- `prism_confidential_infer`: buy one generation that runs inside a GPU TEE.
  The message contents are encrypted to a key the enclave's own attestation
  commits to, so this server's relay carries ciphertext and cannot read the
  prompt or the answer. Returns the answer, the cost and a receipt id the
  workload signed over the exact bytes of the exchange.
- `prism_verify_attestation`: check one of those generations against its
  receipt and the hardware behind it. The server remembers the digests of the
  last few confidential calls, so the verdict is bound to the bytes it actually
  sent and received. Every check is reported with its result, including the two
  that cannot be established today: private-key custody, and where TLS
  terminates.
- `prism_lease_and_run`: lease a GPU, run a command, return the output (one shot).
- `prism_lease`: lease a GPU and keep it; returns a `lease_id` and SSH access.
  The SSH block carries `host_key_fingerprint` and `host_key_claim` when the
  network can say which machine should answer, and says so plainly when it
  cannot. Check it before connecting by hand; `prism_run` checks it for you.
- `prism_run`: run a command on an existing lease.
- `prism_batch_run`: fund a lease that runs one command with no interactive
  access; the node reports the signed output. Matches only suppliers at trust
  class `isolated` or above, so it can find no supplier when none is online.
- `prism_end_lease`: release a lease.
- `prism_vault_store`: seal private data under the wallet-derived key.
- `prism_vault_list`: list sealed items; values are never returned.
- `prism_vault_read`: decrypt one item in this process.
- `prism_vault_delete`: permanently delete an item.
- `prism_vault_release`: authorize an item into a lease that clears its trust floor.

## Spending limits

Two ceilings bound what this server can spend, and a refusal quotes both.

| Variable | Default | What it bounds |
| --- | --- | --- |
| `PRISM_MAX_USDG` | 1 | Any single lease or generation. `max_usdg` on a call may lower it, never raise it past this. |
| `PRISM_DAILY_BUDGET_USDG` | 5 | Everything in a rolling 24 hours. `0` removes the ceiling. |
| `PRISM_LEDGER_PATH` | `~/.prism/spend.json` | Where the spend is recorded. |

A `max_usdg` above `PRISM_MAX_USDG` is clamped back to it. The argument is
written by the agent being bounded, so it is treated as a request for a lower
ceiling and never as permission for a higher one.

Spend is written before the money moves, so a crash between funding an escrow
and answering is counted rather than forgiven, and a restart does not hand back
a fresh day's allowance. Only an attempt that provably never reached the chain
is reverted. Two clients pointed at one wallet share one ceiling, because they
share the ledger file.

None of this is the real limit. Fund a dedicated wallet with what you are
willing to lose: that balance is what survives a bug in everything above.

Tools that spend are annotated `destructiveHint` and carry
`anthropic/requiresUserInteraction`, so Claude Code asks before every one of
them even in modes that otherwise approve tools automatically.

## Vault

An agent that handles a card, an identity document or a credential should not
write it into a leased workspace. `prism_vault_store` seals it under a key
derived from the agent's wallet inside this server process; Prism receives
ciphertext and holds no way to read it.

Each item names the weakest workspace trust class it may ever be released into,
and new items default to `confidential`, above anything the network serves
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
        "PRISM_ESCROW": "0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD"
      }
    }
  }
}
```

The wallet needs USDG (`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`) and Robinhood-Chain ETH for gas. See the SDK's Funding section for how to fund a fresh wallet.

Or add it to Claude Code in one line:

```sh
claude mcp add prism \
  --env PRISM_ESCROW=0xfD4228eEEfC49e4b76A0CD40af9fdd546220B2FD \
  --env PRISM_AGENT_KEY=0x<agent wallet private key> \
  -- npx -y @prismnetwork/mcp
```

## Timing

`prism_lease` and `prism_lease_and_run` block while a GPU provisions (usually one to four minutes, occasionally longer on a slow host). Configure your MCP client to allow long tool calls.
