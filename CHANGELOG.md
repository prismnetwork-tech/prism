# Changelog

All notable changes will be documented here.

The project follows semantic versioning after its first stable release.

## Unreleased

### Changed

- A lease from a wallet holding zero USDG or zero gas is refused before a
  quote is created, so a doomed attempt no longer holds capacity against other
  renters.
- A failure after the escrow is funded keeps the SSH key on disk and reports
  the funding hash and lease id; before, both SDKs deleted the only way into a
  machine that was still being paid for.
- Paid waits ride out transient 429/5xx answers, and a batch lease whose node
  died is detected instead of waited out. The Python SDK gains gateway-access
  detection in `run()`, bounded confirmation waits, and a `stdin` parameter
  matching Node's.
- The toolsets validate the command and trust class before any money moves and
  return readable sentences instead of raising into the framework. Read-only
  tools work keyless in both languages, staker-only offers are marked, and
  lease key material is cleaned up at process exit.
- CrewAI tool names are now `prism_*`, and the trust argument is
  `min_trust_class` across every Python and Node adapter (the MCP server keeps
  its published `min_trust` listing argument).
- The MCP server defaults the escrow like every other surface, names the
  actual configuration problem when a wallet is unusable, takes a `max_usdg`
  cap on every lease tool (default 1), returns the lease handle when a funded
  lease's first command fails, adds `prism_batch_result`, and clamps
  `prism_receipts` to 50 entries keyed by the unique `receipt_id`.
- The elizaOS plugin builds one toolset per agent from runtime settings at
  first use, reports refusals as failed actions, and no longer treats a
  pricing question as a reason to lease. The GAME plugin reports Failed
  instead of throwing out of the agent loop.
- Lighter's settled funding rows are percent per hour, not the fractions the
  carry example read them as, which overstated carry 12.5x. The example now
  converts both endpoints to hourly fractions, bounds short orders on the
  correct side, and derives the forward horizon from the feed's real cadence.
- The trading examples validate their environment before doing any work, gate
  execution on the pool-versus-oracle basis, re-read the pool right before the
  swap, retry and report dropped feed rounds, and print the momentum tilt
  separately from the bootstrap mean.

### Added

- Inference gateway 0.2.0: prices scale per request (a model's base plus its
  per-token rate over the requested output cap), the unpaid 402 quotes the
  exact figure, `/v1/models` carries the per-model rates, and `/v1/stats`
  reports generations, tokens, revenue and leases warmed since boot.

- `prism_infer` in the MCP server: one tool call buys a generation from the
  managed inference endpoint. It pays the quoted USDG price from the server's
  wallet, waits through cold starts, and keeps an unconsumed payment for the
  next call instead of paying twice.

- `@prismnetwork/inference-gateway`: managed inference on network GPUs. The
  gateway keeps a leased box warm with ollama and the configured models and
  sells single generations over HTTP for USDG via x402. Payments are consumed
  only when a response is served, generations are capped at 1024 output
  tokens, and an idle box lapses instead of renewing.

- Framework integrations under `integrations/`: LangChain/LangGraph
  (`prism-langchain`), CrewAI (`prism-crewai`), AG2 and AutoGen
  (`prism-autogen`), elizaOS (`@prismnetwork/plugin-eliza`) and Virtuals GAME
  (`@prismnetwork/game-plugin`), all wrapping one shared toolset per language.
- `PrismToolset` in both SDKs: the framework-neutral tool surface holding the
  wallet, open leases and per-lease spending cap in one place. The Node variant
  answers read-only questions from the public API when no wallet is configured.
- Python SDK batch parity: `lease(command=...)`, `result`, `wait_for_result`
  and the `BatchLease` handle, matching the Node SDK.
- MCP server 0.5.0: keyless `prism_price_index` and `prism_receipts` (public
  proof feed), `prism_leases`, and `prism_batch_run` for the signed
  no-interactive-access path.
- Trading examples under `examples/trading`: a stock-token research agent
  (Chainlink + Uniswap v4 + Robinhood Earn data, Monte Carlo on a rented GPU,
  Universal Router execution) and a Lighter funding-carry agent (settled
  funding history, bootstrapped carry study on a rented GPU, lighter-sdk
  execution), both with free local modes and explicit `EXECUTE=1` gates.
- Initial open-source release of the Prism Network pre-production stack.
