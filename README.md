# Prism Network

[![Validate](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml/badge.svg)](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/prismnetwork-tech/prism/badge)](https://securityscorecards.dev/viewer/?uri=github.com/prismnetwork-tech/prism)
[![License](https://img.shields.io/badge/license-Apache--2.0-ccff00)](LICENSE)
[![Headless agent SDK](https://img.shields.io/badge/agents-headless%20SDK-ccff00)](sdk/README.md)
[![MCP + x402](https://img.shields.io/badge/agents-MCP%20%2B%20x402-ccff00)](mcp/README.md)
[![Wallet-signature auth](https://img.shields.io/badge/agents-wallet%20auth-ccff00)](examples/agent-quickstart/README.md)

Prism Network is open infrastructure for metered GPU compute. The current
system implements account and wallet onboarding, GPU offer discovery, USDG
escrow, workload provisioning, time-limited access, metering, settlement and
public receipt generation.

Prism has two execution paths:

- **Independent nodes:** Ubuntu 24.04 x86-64 hosts run public OCI images in Kata
  VM-backed containers with exclusive NVIDIA VFIO passthrough. Access uses
  short-lived SSH or Jupyter credentials through an outbound-only mTLS tunnel.
- **Vast broker:** a bonded broker provisions disposable L40S instances and
  exposes direct SSH. This path relies on provider-reported readiness and
  evidence; it does not provide Kata/VFIO isolation, the Prism gateway, or
  Jupyter access.

Interactive raw GPU leases are what the network serves today. A lease can also
carry a single command instead of a session, which runs on an independent node
and reports back what it printed, but no independent node has completed the
hardware canary yet, so nothing has run that path in production. Managed
inference is not implemented.

## Current state

Verified on 2026-07-20:

| Area | Status |
| --- | --- |
| Public web and API | Live at [prismnetwork.tech](https://prismnetwork.tech), with one Vast-backed L40S offer visible |
| Robinhood Chain contracts | Deployed on mainnet; the lease escrow is live |
| Vast execution | Implemented and locally lifecycle-tested; a funded mainnet canary has not been completed |
| Independent Kata nodes | Daemon, gateway, certificates, commands, tunnel and workspace lifecycle are implemented and integration-tested without physical GPU hardware |
| Settlement and proof | Workers and local end-to-end flows are implemented; no public mainnet settlement receipt exists yet |
| Batch commands | Implemented on the independent-node path; never executed on physical hardware |
| Managed inference | Planned, not implemented |

This is an unaudited pre-production system, so do not put production traffic or
serious money on it yet.

What a supplier protects is stated per offer rather than as one blanket
warning. Every offer, quote, lease and receipt carries a trust class (`open`,
`isolated`, `attested` or `confidential`), and renters can require a minimum
instead of trusting prose:

```bash
curl https://api.prismnetwork.tech/v1/offers?min_trust=isolated
```

The class is derived by the control plane from evidence it can check, never
asserted by a supplier, and it is clamped to what the network can currently
verify. `isolated` requires a GPU attestation report that validates to a pinned
NVIDIA root and answers a challenge issued to the node presenting it, so a
machine cannot claim that class for itself. `attested` requires a launch
measurement of the guest that ran the lease, verified to AMD's root and bound to
the SSH host key generated inside that guest, so the proof is about the session
the renter is in. It proves what started and not that nobody watched. All
capacity live today is `open`, which means the host operator can read anything
the workload touches, and nothing above it is served until the reference
material both classes check against is captured from real hardware and verifies.
See [docs/ATTESTATION.md](docs/ATTESTATION.md) for what is checked and
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for what each class does and
does not promise.

Private data does not have to live in a workspace to be useful. Cards, identity
documents and credentials go in the vault, sealed on your machine under a key
derived from a wallet signature and never sent, so Prism stores ciphertext and
holds no way to read it:

```js
await agent.vault.unlock();
const card = await agent.vault.put({ pan: "4111111111111111" }, { label: "billing" });
```

Every item carries the weakest class of workspace it may be shown to, and new
items default to `confidential` — above what the network can serve — so handing
one to today's capacity is refused rather than quietly allowed. The account,
version and trust floor are authenticated into the ciphertext, which makes
moving an item, replaying an old version, or lowering its floor a failed
decrypt instead of a successful lie. [docs/VAULT.md](docs/VAULT.md) has the
construction and its limits.

## Mainnet contracts

The V1 contracts are non-upgradeable and `LeaseEscrowV1` is live. They have not
received an independent audit. Blockscout reports `NodeRegistryV1` as fully
source-verified and `LeaseEscrowV1` as partially source-verified. The escrow's
executable bytecode matches this tree, while its trailing Solidity metadata
hash differs.

You do not have to take that on trust. `./scripts/verify-deployed-bytecode.sh`
rebuilds both contracts and compares them against the code live on chain using
only the public RPC, masking immutables and reporting the metadata blob
separately:

```
NodeRegistryV1 0xe3b7…8f01: executable code matches, metadata differs
LeaseEscrowV1  0x71Df…cDeD: executable code matches, metadata differs
```

| Contract | Address |
| --- | --- |
| Canonical USDG | [`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`](https://robinhoodchain.blockscout.com/address/0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168) |
| `NodeRegistryV1` | [`0xDaE90914CCb3601ABdfAEf994CD07eE7676519Dc`](https://robinhoodchain.blockscout.com/address/0xDaE90914CCb3601ABdfAEf994CD07eE7676519Dc) |
| `LeaseEscrowV1` | [`0x62C042265991bEa17B07229322A01850974626dA`](https://robinhoodchain.blockscout.com/address/0x62C042265991bEa17B07229322A01850974626dA) |
| Governance Safe | [`0xAF1113cE9E65D79daA87005A729Ab9Bc1A9fc60a`](https://robinhoodchain.blockscout.com/address/0xAF1113cE9E65D79daA87005A729Ab9Bc1A9fc60a) |

Administration, emergency pause and dispute resolution are held by a 2-of-2
governance Safe. Network settings and the USDG address should always
be checked against the
[official Robinhood Chain documentation](https://docs.robinhood.com/chain/connecting/)
and [contract registry](https://docs.robinhood.com/chain/contracts/).

## Architecture

```text
Browser + wallet
       |
       v
Next.js web -----> Rust control plane -----> PostgreSQL
                         |
              +----------+-----------+
              |                      |
              v                      v
      lifecycle worker       settlement/proof workers
              |                      |
       +------+-------+              v
       |              |       Robinhood Chain
       v              v
Vast instance    access gateway
direct SSH       mTLS tunnel/relay
                       |
                       v
               prismd + Kata/VFIO
```

The repository contains:

- `apps/web`: Next.js account, marketplace, supplier, operator and proof UI.
- `crates`: shared Rust protocol and persistence libraries.
- `services`: Rust control plane, access gateway and operations monitor.
- `workers`: lifecycle, settlement and proof workers.
- `node/prismd`: independent-node runtime and workspace supervisor.
- `contracts`: PRISM bond, USDG escrow and administration contracts.
- `sdk`: headless agent SDK for wallet-signature USDG leasing.
- `mcp`: Model Context Protocol server exposing leasing to MCP clients.
- `x402`: pay-per-job GPU execution over HTTP 402.
- `inference`: managed inference, a warm ollama lease behind an x402-paid endpoint.
- `integrations`: LangChain, CrewAI, AG2/AutoGen, elizaOS and Virtuals GAME adapters.
- `examples/trading`: agents that rent a GPU for research, then trade on what it finds.
- `examples/confidential`: an agent pays for TEE-served inference and verifies the attestation itself.
- `deploy/ec2`: lean Vast launch topology with the web application on Render.
- `deploy/lightsail`: full single-host reference topology.
- `deploy/node`: Ubuntu node service units and configuration.
- `infra`: an AWS reference architecture, not the active lean deployment.
- `docs`: design, security boundary, proof format and release documentation.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_MODEL.md)
and [release gates](docs/RELEASE_GATES.md) before operating the system.

## Agent access

Autonomous agents integrate without a browser. An agent proves control of its
funding wallet by signing a short-lived challenge, exchanges it for a bearer
session, and drives the same renter surface — offer discovery and the lease
lifecycle — over the `/api/agent` endpoints. Escrow, readiness, metering and
settlement are identical to the browser path, and the agent boundary reaches
only renter routes.

- [`sdk`](sdk/README.md) — `@prismnetwork/agent-sdk`, headless USDG-funded leasing for Node.
- [`mcp`](mcp/README.md) — `@prismnetwork/mcp`, the same leasing exposed as Model Context Protocol tools.
- [`x402`](x402/README.md) — `@prismnetwork/x402`, pay-per-job GPU execution over HTTP 402.
- [`integrations`](integrations/README.md) — the same tools in the dialect of
  LangChain, CrewAI, AG2/AutoGen, elizaOS, Virtuals GAME and Coinbase AgentKit,
  plus how to pair Prism with Robinhood's agentic trading MCP.

The Node and Python packages are published under the `@prismnetwork` npm scope
and as `prismnetwork`/`prism-*` on PyPI. An agent
workspace is still a disposable environment, not confidential computing;
anything an agent needs to keep private belongs in its vault, which the same
SDK reaches through `agent.vault`.

## Verification

The fast pull-request gate checks the web application, production build,
secrets and repository isolation:

```sh
pnpm install --frozen-lockfile
pnpm check
```

The full local gate additionally runs the Rust and Solidity suites, audits and
security scanners, PostgreSQL and Valkey integrations, Anvil lifecycle tests,
mTLS relay tests, load and recovery checks, deployment validation and
observability checks:

```sh
pnpm check:full
```

The full gate passed locally on 2026-07-20 with 23 web tests, 57 Rust tests and
18 Foundry tests, including fuzz and invariant coverage. That run used
simulated/containerized infrastructure; it is not evidence of physical
NVIDIA/Kata/VFIO execution or a funded mainnet lease.

The hosted full gate is manual and has not yet produced a public run:

```sh
gh workflow run full-validate.yml --ref <branch>
```

Required toolchains are Node.js 24.14, pnpm 10.34.5, Rust 1.94.1, Foundry 1.5,
Docker with Compose and ripgrep.

## Remaining release gates

- Keep the escrow paused until a capped, funded mainnet canary completes from
  deposit through refund or settlement.
- Validate CUDA readiness, Kata isolation, VFIO assignment, egress controls and
  teardown on physical NVIDIA hardware.
- Complete live KMS signing and failure-recovery evidence for lifecycle and
  settlement workers.
- Exercise real Privy signup, external and embedded wallets, SSH access and
  Jupyter access against the release deployment.
- Publish the first confirmed proof receipt and test the independent daily X
  digest outbox.
- Run applied-host backup/restore, load, failover and incident-response drills.
- Obtain independent smart-contract and infrastructure security review before
  raising contract caps.

Copy only the example environment files needed for your target. Never commit
environment files, credentials, deployment outputs or generated artifacts.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), the
[Code of Conduct](CODE_OF_CONDUCT.md) and [governance](GOVERNANCE.md) before
opening a change. Security reports must follow [SECURITY.md](SECURITY.md) and
must not be filed as public issues.

## License

Code is licensed under the [Apache License 2.0](LICENSE). The Prism Network
name and visual identity are governed separately by [TRADEMARKS.md](TRADEMARKS.md).
