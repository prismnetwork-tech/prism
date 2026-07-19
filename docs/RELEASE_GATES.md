# Release gates

Mainnet remains paused until every gate below is recorded in the release
evidence bundle.

- Foundry unit, fuzz and invariant suites pass.
- Rust workspace and web application build, test and typecheck pass.
- The control plane starts against RDS PostgreSQL; development-only memory mode is disabled.
- Dependency, secret, identity and provenance-isolation scans pass.
- A dedicated NVIDIA Ubuntu host passes `prismd preflight`.
- Kata/VFIO creates an exclusive GPU workspace with a public digest-pinned
  image, outbound tunnel, SSH/Jupyter grant and secure teardown.
- The lifecycle worker advances funded, provisioning, active, closing,
  settlement and terminal states idempotently, including process restart and
  RPC outage.
- A private test environment completes bond, escrow, readiness, meter,
  dispute, finalization, refund, proof artifact and X outbox scenarios.
- Canonical USDG code, address and decimals are independently checked against
  the official Robinhood Chain registry before deployment.
- The Safe owners, KMS attestor public key, deployment bytecode hashes and
  proof artifact bucket are recorded.
- The dedicated X credential is an OAuth 2.0 user access token authorized to
  create posts; app-only credentials are not sufficient.

The first deployment is an unaudited beta. Keep the 50 USDG / six-hour /
one-lease-per-node / 25-network-lease limits for at least 30 incident-free
days before a timelocked change is considered.
