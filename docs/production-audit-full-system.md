# Production audit: full system

Date: 2026-07-19

> Historical audit snapshot. Deployment and repository-control statements
> below describe the state on the audit date; see the root README for current
> readiness.

## Executive summary

The raw-GPU software P0 is implemented and exercised end to end on a local
Robinhood-compatible chain. Readiness drives an idempotent onchain access
start, encrypted renter credentials, automatic close on node loss, metered
settlement, dispute-window finalization, refund, proof publication and a daily
X outbox. Transaction bytes and nonces are persisted before submission, and a
chain snapshot/revert test proves recovery after a submitted transaction is
removed.

The public repository is suitable for an initial open-source release after its
GitHub organization controls are applied. It has fresh brand-owned history,
Apache-2.0 licensing, contribution and security policies, pinned CI actions,
dependency review, CodeQL, OpenSSF Scorecard, DCO enforcement, secret and
identity guards, and reproducible toolchain pins.

This is still not a production network. No physical NVIDIA/Kata/VFIO run, live
Privy session, production KMS signature, Robinhood Chain deployment, real USDG
transfer, public gateway, or X post has occurred. The certificate, operator,
supplier and baseline observability software is implemented, but live-provider,
hardware and host-level recovery evidence is still missing. Mainnet must stay
paused.

Repository release status: **ready after organization hardening**.

Funded-network release status: **blocked**.

## Critical issues (P0 - block release)

No known local raw-GPU P0 implementation item remains.

The following external gates still block any funded release:

- [ ] Apply and test the GitHub organization and protected-branch controls in
  `docs/repository-hardening.md`.
- [ ] Run the dedicated NVIDIA Ubuntu 24.04 Kata/VFIO/CUDA matrix, including
  hostile images, teardown, crash recovery and egress enforcement.
- [ ] Exercise real Privy email, passkey, social, embedded-wallet and linked
  external-wallet flows with production application credentials.
- [ ] Create the production secp256k1 KMS keys and verify their addresses and
  pre-hashed signatures against the configured gateway and attestor roles.
- [ ] Deploy the contracts paused on Robinhood Chain, independently pin USDG
  code/address/decimals, configure the Safe and complete a capped real-USDG
  canary.
- [ ] Apply the Lightsail stack with DNS, trusted TLS, encrypted backups and a
  public mTLS access path.
- [ ] Deliver one real 24-hour digest through the X create-post API without
  allowing publication failure to affect settlement.

## High priority (P1 - fix before public beta)

- [ ] Encrypt/archive private settlement evidence under a dedicated retention
  policy. The reduced Lightsail path keeps it in PostgreSQL; the AWS path must
  write it to the private KMS-encrypted evidence bucket.
- [ ] Run host-level process-kill, encrypted backup restore and gateway restart
  drills on the applied Lightsail instance. Local database interruption, chain
  reorganization, node loss, dispute and X outage paths already pass.
- [ ] Either finish the ECS worker/gateway deployment or remove it as a launch
  option. The Terraform gateway listener, WAF and encryption topology now
  validates, but ECS lifecycle, settlement, proof and monitoring services are
  not defined. The tested launch target remains Lightsail.
- [ ] Add an organization-owned release-signing identity and publish signed
  tags, checksums, provenance and the generated CycloneDX SBOM.

Completed P1 software:

- Device-signed CSR issuance, seven-day certificate rotation, gateway
  fingerprint enforcement, operator revocation and a daily systemd timer.
- Server-side operator allowlisting, account risk/suspension controls, node
  suspension, certificate revocation, slash evidence and append-only audit.
- Wallet-ownership-scoped supplier inventory, reliability and receipt-backed
  earnings UI.
- Database-derived Prometheus metrics and seven alerts for queue failure/age,
  stale tunnels, certificate expiry, concurrency and privileged activity.
- PostgreSQL interruption recovery and bounded control-plane HTTP load tests.
- Operator dispute review with evidence-integrity checks and Safe-ready
  acceptance calldata. Safe approval remains a separate two-person action.
- Bounded software-concurrency checks for 25 scheduler quotes, command polls,
  relay streams and proof artifacts.

## Medium priority (P2 - fix soon after launch)

- [x] Add bounded software-concurrency tests for 25 scheduler quotes, command
  polling, tunnel fan-out and proof publication. These tests do not create 25
  simultaneous hardware leases or establish applied-host capacity.
- [x] Add operator-facing dispute evidence review and Safe resolution calldata
  UX. Safe approval and transaction delivery remain external.
- [ ] Add automatic proof-volume pruning and restore verification for the
  Lightsail topology.
- [ ] Add live authenticated browser automation to CI after a stable Privy
  sandbox tenant exists. Signed-out and configuration-failure states are
  browser-tested locally.

## Low priority (P3 - later phases and debt)

- [ ] Batch container jobs.
- [ ] Managed inference deployments and autoscaling.
- [ ] Confidential-GPU attestation and confidential-workload eligibility.
- [ ] Optional PARA payments through a separately deployed V2 contract.

## Security assessment

The strongest controls are real rather than presentational:

- Escrow and network caps are enforced in both contracts and scheduling.
- Funding is bound to an account-owned quote reference and verified from a
  finalized escrow event.
- Node enrollment, telemetry, command claims and command reports are signed,
  freshness-bounded and replay-protected.
- The runtime admits digest-pinned public images, reserves the VFIO group,
  launches through Kata, blocks host mounts and privileged access, and opens
  the network only after nftables policy is installed.
- SSH and Jupyter use short-lived gateway grants carried over outbound mTLS
  tunnels. Revocation terminates live relay sessions.
- Access tokens and Jupyter credentials are encrypted in authoritative state.
- Production transaction signing refuses application-managed private keys.
  The local signer requires an explicit development switch.
- Settlement intersects chain, gateway and signed-node timing and rejects
  invalid or uncovered telemetry.
- Proof publication re-verifies the canonical transaction, confirmation depth,
  event values and receipt hash.

The main security weaknesses are operational. Device certificates are
identity-bound and short-lived, but the CA is still an online signing key in
the reduced deployment and needs production custody and recovery procedures.
Risk and suspension actions are enforced and audited, but there is no
production sanctions-provider adapter or two-person review workflow. Private
evidence is access controlled but not separately archived on the reduced
deployment. The contracts remain undeployed and unaudited. A production
deployment must publish verified source, constructor arguments, bytecode hashes
and an independent assessment.

## Performance assessment

The contract cap of 25 concurrent leases keeps initial scale bounded.
PostgreSQL uses row locking and `SKIP LOCKED` for work claims, Redis/Valkey
holds temporary access state, and each signer is serialized by a database
advisory lock to prevent nonce races. These choices are adequate for beta
volume.

Local HTTP load testing completed 2,000 requests at concurrency 25 with zero
failures and sub-5 ms p95 on this development host. Concurrent software tests
also exercise 25 scheduler reservations, 25 command claims, 25 live relay
streams and a 25-receipt proof volume. These are regression gates, not a
production capacity envelope. Gateway memory and database pressure still need
applied-host load evidence before caps increase. The single-host Lightsail
topology also creates a deliberate database, cache, web and gateway failure
domain.

## Observability assessment

Services emit structured tracing logs with stable action and lease identifiers.
The operations monitor exports database-derived health, queue age/failure,
tunnel freshness, certificate expiry, receipt lag, lease concurrency and
privileged-action metrics. Prometheus configuration and seven alert rules pass
`promtool`; monitor recovery after a real database interruption is tested.

Distributed traces, an operator dashboard and host/cloud metrics are still
missing. RPC/KMS error rate, PostgreSQL saturation, disk usage, backup age and
alert delivery must be connected on the applied host.

## Recommended architecture changes

The reduced-cost launch architecture is Lightsail plus managed KMS signing.
Keep PostgreSQL as the durable outbox source of truth and Valkey as transient
grant state. Serve the immutable public proof volume through Caddy and snapshot
the database, cache and proof volumes.

Do not describe the current Terraform as deployable AWS parity. The public
application edge, proof WAF, encrypted storage/queues and TCP pass-through
gateway tunnel/relay listeners validate. Before using the HA path, add
lifecycle, settlement, proof and monitoring ECS services plus production
gateway image construction.

## Test coverage and evidence

Current local evidence includes:

- Next.js typecheck, 21 unit tests, production build, standalone runtime
  CSP/nonce verification and real-browser desktop and 390-pixel mobile checks.
- Fifty-one Rust tests with formatting and Clippy warnings denied.
- Eighteen Foundry unit, fuzz and stateful invariant tests. Each invariant ran
  256 sequences of 500 calls.
- PostgreSQL migrations and authenticated control-plane integration, including
  RSA CA issuance, wallet signatures, operator controls and certificate
  revoke/reissue.
- Valkey TLS grant persistence and revocation.
- Real TLS/mTLS node tunnels, active SSH/Jupyter readiness probes, 25-stream
  relay fan-out and live relay revocation.
- Real OpenSSH/Jupyter bootstrap integration with root login rejected.
- Anvil/PostgreSQL lifecycle E2E covering transaction removal/rebroadcast,
  renter access, signed active telemetry, automatic node-loss closure,
  settlement, finalization, timeout refund and proof publication.
- Lightsail TLS generation and Compose/Caddy validation.
- Prometheus configuration, seven alerts, database-recovery chaos, HTTP load,
  scheduler/command concurrency and bounded proof-volume checks.
- Trivy dependency/secret/misconfiguration scans, ephemeral CycloneDX SBOM,
  Cargo/pnpm audits and Slither with 95 detectors.
- Production container builds for all Rust services. The web container reached
  its TypeScript phase but exceeded the local 2 GiB Docker VM; its native
  production build and standalone runtime passed, and CI retains the container
  build as a required gate.
- Dependency, secret, identity and provenance-isolation gates.
- Actionlint, ShellCheck, Terraform validation and dependency-license review.

Unverified coverage is the external P0 list plus the remaining applied-host,
archive, public release-signing, physical multi-node concurrency and HA
deployment work above. Passing software tests must not be presented as proof
of honest GPU execution.

## Action plan

1. Apply and test the organization hardening controls.
2. Provision the organization-owned release-signing identity.
3. Keep contracts paused and complete the external account checklist.
4. Rent one dedicated compatible GPU host and run the hardware release matrix.
5. Apply the Lightsail stack, configure KMS, DNS and trusted certificates, then
   perform restore and process-loss tests.
6. Run real Privy/wallet and X-provider browser flows.
7. Complete backup restore, private-evidence archive and full-concurrency
   drills.
8. Execute a capped real-USDG canary and publish the first proof artifact.
9. Open the unaudited beta only if every release gate has recorded evidence.
