# Changelog

All notable changes will be documented here.

The project follows semantic versioning after its first stable release.

## 2026-09-02

- The project's home returns to `github.com/prismnetwork-tech`. Repository
  links, package metadata, the MCP registry namespace
  (`io.github.prismnetwork-tech/mcp`) and the image path
  (`ghcr.io/prismnetwork-tech/prism`) all point at the organization again.

## Unreleased

### Changed

- The repository moved to `winter0x`, and every link across the site, the
  packages and the docs points there. The previous two homes are abandoned
  rather than mirrored: one is hidden from the public by an account
  restriction, and the other cannot run CI for the same reason.

  Two published names move with it, which the earlier move deliberately avoided.
  The MCP registry namespace becomes `io.github.winter0x/mcp` and the container
  image path becomes `ghcr.io/winter0x/prism`. A registry namespace is verified
  by proving ownership of the account that owns it, so leaving it on an account
  that can no longer be used would mean never publishing an update again. The
  existing registry entry stays where it is and stops being maintained.

- Managed inference is repriced against what a generation costs to serve.
  `llama3.2:3b` is 3000 micros plus 3 a token and `llama3.1:8b` is 6000 plus 6,
  which halves the price of a short answer and cuts a full 1024-token one by
  about two thirds. The gateway now ships that rate card as its default instead
  of a flat 10,000-micro fee, `INFERENCE_PRICE_MICROS` sets the base for every
  model without erasing the per-token rates, and a model the card does not list
  is priced as the largest one that was measured. `DEFAULT_PRICE_MICROS` is
  replaced by `DEFAULT_PRICING`.

- Repository links across the site, the packages and the docs now point at the
  new `prismnetworkdottech` organisation. Published artifact names are
  deliberately untouched: container images keep their `ghcr.io` path and the
  MCP registry entry keeps its namespace, because renaming either would break
  what is already published under it.

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

- Open mode for suppliers: a node can now serve leases with the GPU left on the
  host driver, so a stock Ubuntu 24.04 machine with an NVIDIA driver and
  containerd can enroll without IOMMU passthrough or Kata. `deploy/node/install.sh`
  prepares such a host and `deploy/node/OPEN_MODE.md` is the runbook. These
  nodes publish the `open` trust class; the passthrough path is unchanged and
  keeps its own class. Between leases the daemon can run one workload the
  operator configures, typically a miner, and it takes the card back before a
  lease starts. `prismd idle-check` measures that handover on the operator's own
  hardware, which is how they find out whether their miner releases VRAM fast
  enough before they bond.

- A public `/network` page: what the network has settled (leases, GPU hours,
  USDG charged, the share that reached suppliers, refunds, and a per-GPU
  breakdown) beside what it can rent right now. Every settled figure is summed
  from the same public receipt feed the settlements wrote, and capacity comes
  through a new `/api/offers` proxy that prices the headline from offers an
  unstaked wallet can actually match.

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
