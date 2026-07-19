# Security scanning

`scripts/security-scan.sh` is a required local and CI gate. It runs:

- Trivy vulnerability, secret and configuration scanning at high and critical
  severity.
- Ephemeral CycloneDX SBOM generation and schema sanity checking. The SBOM is
  not published or committed.
- Slither 0.11.3 against Foundry build information, excluding test and script
  contracts.

The Slither gate suppresses five detector classes only where they describe
intentional protocol mechanics:

- `arbitrary-send-eth` and `low-level-calls`: the timelock exists to execute an
  already-hashed arbitrary Safe administration call.
- `reentrancy-events`: the timelock marks the operation executed before the
  call; a revert rolls the mark back.
- `timestamp`: provisioning, access duration, timelock and dispute windows are
  explicitly time-based.
- `assembly`: ECDSA recovery reads the fixed 65-byte signature and separately
  enforces valid recovery IDs and low-s signatures.

These suppressions are not an audit waiver. Changes to those code paths require
manual review and the invariant/fuzz suites must still pass.
