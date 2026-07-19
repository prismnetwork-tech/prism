# Chaos, load and security validation

The local validation suite exercises the failure modes that do not require
external accounts or physical GPU hardware:

- Control-plane restart with PostgreSQL state retained.
- PostgreSQL outage and operations-monitor recovery.
- Chain reorganization and idempotent lifecycle resubmission.
- RPC transaction confirmation delays.
- Provisioning timeout and automatic refund.
- Access-grant revocation during an active relay.
- X delivery through an isolated mock endpoint.
- 1,000-request HTTP load runs at 25 concurrent requests against health and
  offer discovery endpoints.
- Concurrent scheduler reservations and device command claims at the 25-lease
  network cap.
- Twenty-five simultaneous mTLS relay streams through the access gateway.
- Canonical validation and atomic publication of 25 public proof receipts.
- Rust, npm and Solidity test suites, dependency audits, Trivy filesystem
  scanning, Slither analysis and ephemeral CycloneDX SBOM generation.

The load tests are regression gates, not a capacity forecast. The scheduler,
command and proof tests use software fixtures, and the relay test uses one
local node tunnel. Production limits still require multi-node load testing on
the selected Lightsail plan with its real TLS, database volume and network
path.

Physical Kata/VFIO/CUDA isolation, real wallet-provider dialogs, Robinhood
Chain finality, KMS signing, DNS/ACME, external alert delivery and X posting
remain external-environment tests.
