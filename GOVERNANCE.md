# Governance

Prism is maintained by the Prism Network organization.

## Decision model

Routine changes are accepted through reviewed pull requests. Maintainers aim
for consensus and record material decisions in public issues or design
documents.

The following changes require approval from at least two maintainers:

- Smart-contract state transitions, fees, caps or payment assets.
- Authentication, authorization, signing or key-custody behavior.
- Node isolation, network policy or trust-boundary changes.
- Breaking public interfaces or irreversible migrations.
- Release, branch-protection or security-policy changes.

No single maintainer may both author and solely approve a production contract
or fund-handling change.

## Maintainers

Maintainers are accountable for review quality, release integrity, security
response and community conduct. New maintainers require demonstrated,
sustained contributions and consensus from the existing maintainer group.

Organization roles and repository permissions are managed outside Git. The
public list is maintained in [MAINTAINERS.md](MAINTAINERS.md).

## Releases

Releases must:

- Originate from protected `main`.
- Pass required checks.
- Use an immutable, signed tag.
- Include a changelog and generated SBOM.
- Record source commit, container digests and contract bytecode where relevant.

Security embargoes may temporarily limit public discussion. The remediation and
advisory must be published after affected users can update safely.
