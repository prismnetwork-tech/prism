# Changelog

All notable changes will be documented here.

The project follows semantic versioning after its first stable release.

## Unreleased

### Added

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
