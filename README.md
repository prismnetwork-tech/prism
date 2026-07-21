# Prism Network

[![Validate](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml/badge.svg)](https://github.com/prismnetwork-tech/prism/actions/workflows/validate.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/prismnetwork-tech/prism/badge)](https://securityscorecards.dev/viewer/?uri=github.com/prismnetwork-tech/prism)
[![License](https://img.shields.io/badge/license-Apache--2.0-ccff00)](LICENSE)

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

Only interactive raw GPU leases are in scope today. Batch containers and
managed inference are not implemented.

## Current state

Verified on 2026-07-20:

| Area | Status |
| --- | --- |
| Public web and API | Live at [prismnetwork.tech](https://prismnetwork.tech), with one Vast-backed L40S offer visible |
| Robinhood Chain contracts | Deployed on mainnet; the lease escrow is paused and has no leases |
| Vast execution | Implemented and locally lifecycle-tested; a funded mainnet canary has not been completed |
| Independent Kata nodes | Daemon, gateway, certificates, commands, tunnel and workspace lifecycle are implemented and integration-tested without physical GPU hardware |
| Settlement and proof | Workers and local end-to-end flows are implemented; no public mainnet settlement receipt exists yet |
| Batch and inference | Planned, not implemented |

This is an unaudited pre-production system. Do not deposit funds or use Prism
for confidential workloads, regulated data, valuable model weights or
production traffic. A permissionless supplier is not a trusted computing
environment, and Kata isolation is not confidential-computing attestation.

## Mainnet contracts

The V1 contracts are non-upgradeable. `LeaseEscrowV1` is currently paused.
Their source has not been verified on the explorer and they have not received
an independent audit.

| Contract | Address |
| --- | --- |
| Canonical USDG | [`0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168`](https://robinhoodchain.blockscout.com/address/0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168) |
| `NodeRegistryV1` | [`0xBf83714Ff5d524FA5CD9bdF24495540e979426d7`](https://robinhoodchain.blockscout.com/address/0xBf83714Ff5d524FA5CD9bdF24495540e979426d7) |
| `LeaseEscrowV1` | [`0x4e599D47bA62c2Bb733D41625BF98d6cBbf2dF0f`](https://robinhoodchain.blockscout.com/address/0x4e599D47bA62c2Bb733D41625BF98d6cBbf2dF0f) |
| `AdminTimelock` | [`0x22e2868dCe0E28fb266C5C5BC018Da3145307BBD`](https://robinhoodchain.blockscout.com/address/0x22e2868dCe0E28fb266C5C5BC018Da3145307BBD) |

The timelock delay is 48 hours. Emergency pause and dispute resolution remain
under the configured Safe. Network settings and the USDG address should always
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
- `contracts`: USDG bond, escrow and administration contracts.
- `deploy/ec2`: lean Vast launch topology with the web application on Render.
- `deploy/lightsail`: full single-host reference topology.
- `deploy/node`: Ubuntu node service units and configuration.
- `infra`: an AWS reference architecture, not the active lean deployment.
- `docs`: design, security boundary, proof format and release documentation.

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY_MODEL.md)
and [release gates](docs/RELEASE_GATES.md) before operating the system.

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
