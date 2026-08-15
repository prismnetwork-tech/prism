# Trading examples

Two end-to-end agents that rent a Prism GPU for the heavy analysis, then act on
what it finds. Both run free in a downscaled local mode, use a rented GPU with
`--gpu`, and only ever trade behind an explicit `EXECUTE=1`.

| Example | Data | Compute | Execution |
| --- | --- | --- | --- |
| [`stock-token-agent`](stock-token-agent) | Chainlink stock feeds, Uniswap v4 pools, Robinhood Earn vault, all on Robinhood Chain | Monte Carlo momentum study on a Prism GPU | USDG → stock-token swap through the Universal Router |
| [`lighter-carry-agent`](lighter-carry-agent) | Lighter perp funding rates and settled history | Bootstrapped carry study on a Prism GPU | Perp order via the official lighter-sdk |

The pattern is the same in both: gather real market data, lease a GPU with an
on-chain USDG payment, ship the dataset and a job over SSH, parse the ranked
result, and act only when the edge clears costs. Swap the data source and the
execution adapter and the same skeleton covers other venues.

## From an agent framework instead

The scripts above are deterministic pipelines. To let a model drive the same
loop, mount Prism into the stack you already run (MCP, LangChain, CrewAI,
AG2/AutoGen, elizaOS, or Virtuals GAME; see [integrations](../../integrations))
and, for US Robinhood customers, pair it with Robinhood's own agentic trading
MCP so one session researches on a rented GPU and trades through a Robinhood
agentic account:

```sh
claude mcp add robinhood-trading --transport http https://agent.robinhood.com/mcp/trading
claude mcp add prism -- npx -y @prismnetwork/mcp
```

> "Rent a GPU on Prism, run this momentum study on it, and place the rebalance
> through my Robinhood agentic account if the result clears the hurdle."

Nothing here is investment advice. Stock tokens have holder eligibility rules;
check yours. Prism is pre-production and unaudited; use wallets and keys that
hold only what you are prepared to lose.
