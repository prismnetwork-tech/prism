# Prism Network

[![Validate](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml/badge.svg)](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/prismnetwork-tech/prism/badge)](https://securityscorecards.dev/viewer/?uri=github.com/prismnetwork-tech/prism)
[![License](https://img.shields.io/badge/license-Apache--2.0-ccff00)](LICENSE)

Prism Network is open infrastructure for metered GPU compute. It connects
renters to independent NVIDIA capacity through isolated Kata workspaces,
short-lived SSH or Jupyter access, and USDG settlement on Robinhood Chain.

## Project status

Prism is pre-production software. The local software lifecycle is implemented
and tested, but the network is not ready for funded public use.

The following release gates remain external:

- Physical Ubuntu 24.04, NVIDIA, IOMMU, VFIO, Kata and CUDA validation.
- Production Privy, KMS, RPC, Safe, USDG and Robinhood Chain integration.
- Independent smart-contract and infrastructure security audits.
- Applied-host backup, recovery, load and incident-response drills.

Do not use Prism for confidential workloads, regulated data, valuable model
weights or production funds. Independent suppliers are not trusted computing
environments.

## Architecture

```text
Browser and wallet
       |
       v
Next.js application ---> Rust control plane ---> PostgreSQL
       |                       |
       |                       +----> lifecycle and settlement workers
       |                       |
       v                       v
Robinhood Chain         outbound-only mTLS gateway
                               |
                               v
                       prismd + Kata/VFIO GPU
```

The repository contains:

- `apps/web`: Next.js account, marketplace, supplier, operator and proof UI.
- `services`: Rust control plane, access gateway and operations monitor.
- `workers`: lifecycle, settlement and proof workers.
- `node/prismd`: independent-node runtime and workspace supervisor.
- `contracts`: USDG bond, escrow and administration contracts.
- `infra`: Terraform reference architecture.
- `deploy`: container, node, Lightsail and observability assets.
- `docs`: architecture, security boundaries, proof format and release gates.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_MODEL.md)
and [release gates](docs/RELEASE_GATES.md) before running the system.

## Development

Required toolchains:

- Node.js 24.14
- pnpm 10.34.5
- Rust 1.94.1
- Foundry 1.5
- Docker with Compose

Install and run the fast validation path:

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
cargo test --workspace
forge test
```

The full release gate additionally requires PostgreSQL, Valkey, Anvil, Docker
and the security scanners documented in
[security scanning](docs/security-scanning.md):

```sh
./scripts/validate.sh
```

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
