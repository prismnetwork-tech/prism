# Security policy

## Supported versions

Prism is pre-production. Security fixes are applied to the current `main`
branch. No tagged version currently receives long-term support.

## Reporting a vulnerability

Do not open a public issue.

Use GitHub's private vulnerability reporting for this repository. If that
channel is unavailable, email `security@prismnetwork.tech` with:

- A concise description and affected component.
- Reproduction steps or a proof of concept.
- Impact and prerequisites.
- Suggested remediation, if known.

Do not include real user data, production credentials or destructive payloads.
We will acknowledge a complete report within three business days and provide a
status update within ten business days.

## Research boundaries

Good-faith research must avoid:

- Accessing data that does not belong to the researcher.
- Degrading availability or exhausting paid resources.
- Moving or retaining funds.
- Social engineering, phishing or credential attacks.
- Publishing details before a coordinated fix is available.

The repository and its tests are the preferred research environment. Mainnet
contracts and public infrastructure are not authorized targets unless a
separate program explicitly says otherwise.

## Security posture

The contracts are unaudited and the GPU trust model does not provide
confidential computing. Review [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
and [docs/RELEASE_GATES.md](docs/RELEASE_GATES.md) before deployment.
