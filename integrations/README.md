# Integrations

Prism speaks the tool dialect of every major agent stack. Each integration is a
thin wrapper over the same surface: see live GPU capacity and prices, rent a
machine with an on-chain USDG payment on Robinhood Chain, run commands on it
over SSH, release it. Every lease settles with a verifiable receipt.

| Stack | Package | Where |
| --- | --- | --- |
| MCP (Claude, Cursor, any MCP client) | `@prismnetwork/mcp` | [`../mcp`](../mcp) |
| LangChain / LangGraph | `prism-langchain` | [`langchain`](langchain) |
| CrewAI | `prism-crewai` | [`crewai`](crewai) |
| AG2 / AutoGen | `prism-autogen` | [`autogen`](autogen) |
| elizaOS | `@prismnetwork/plugin-eliza` | [`eliza`](eliza) |
| Virtuals Protocol GAME | `@prismnetwork/game-plugin` | [`virtuals`](virtuals) |
| Coinbase AgentKit (Python) | `prism-agentkit` | [`../agentkit`](../agentkit) |
| Coinbase AgentKit (TypeScript) | `@prismnetwork/agentkit` | [`../agentkit-ts`](../agentkit-ts) |
| x402 paid endpoint | `@prismnetwork/x402` | [`../x402`](../x402) |

The Python wrappers share `prismnetwork`'s `PrismToolset`; the Node wrappers
share `@prismnetwork/agent-sdk`'s. Both hold the wallet, the open leases, and
the per-lease spending cap (`max_usdg`, default 1.0) in one place, so a lease
opened by one tool is visible to the rest and no framework copy drifts.

## Alongside Robinhood's trading MCP

Prism runs on Robinhood Chain, and Robinhood's own agentic trading MCP speaks
the same protocol, so one Claude session can research on a rented GPU and trade
through a Robinhood agentic account:

```sh
claude mcp add robinhood-trading --transport http https://agent.robinhood.com/mcp/trading
claude mcp add prism -- npx -y @prismnetwork/mcp
```

> "Rent a GPU on Prism, backtest this momentum strategy on it, and if the
> Sharpe clears 1.5 place the rebalance through my Robinhood agentic account."

Robinhood's agentic trading is US-only and onboards from desktop; see
[worked end-to-end examples](../examples/trading) for flows that pair rented
compute with venues reachable from code alone.

## Configuration, everywhere

`PRISM_AGENT_KEY` — private key of a wallet holding USDG and gas on Robinhood
Chain (chain id 4663). `PRISM_ESCROW` — optional, defaults to the live lease
escrow. Reading capacity and prices needs no wallet in the MCP server, the
elizaOS plugin, and the GAME plugin.

Prism is pre-production and unaudited. Do not lease with a wallet or workload
you cannot lose.
