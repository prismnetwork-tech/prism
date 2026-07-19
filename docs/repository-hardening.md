# Repository hardening

These controls are part of the release boundary. They are configured in the
GitHub organization and cannot be enforced by files in the repository.

## Organization

- Require two-factor authentication for every organization member.
- Use organization teams rather than direct collaborator grants.
- Keep at least two organization owners on independently secured accounts.
- Grant the `prism-maintainers` team maintain access to this repository.
- Restrict repository creation, deletion, visibility changes and Actions
  policy changes to organization owners.
- Permit only GitHub-authored, verified Marketplace actions or actions pinned
  to full commit SHAs.

## Repository security

- Enable private vulnerability reporting.
- Enable dependency graph, Dependabot alerts and security updates.
- Enable secret scanning, push protection and validity checks.
- Enable CodeQL default setup only if it does not duplicate the checked-in
  CodeQL workflow.
- Provision and test `security@prismnetwork.tech` and
  `conduct@prismnetwork.tech` before accepting reports.

## Protected `main`

Create a repository ruleset targeting the default branch:

- Block deletion and non-fast-forward updates.
- Require pull requests with two approvals.
- Require approval from Code Owners.
- Dismiss stale approvals after new commits.
- Require every review conversation to be resolved.
- Require linear history and successful deployments where applicable.
- Require the `validate`, `codeql`, `dependency review` and `dco` checks.
- Restrict bypass to an emergency organization-owner role and audit every use.

Do not enable a signed-commit requirement until the organization has
provisioned and documented a brand-owned signing identity for maintainers and
automation. DCO signoff does not replace cryptographic signing.

## Releases

- Create releases only from protected `main`.
- Use immutable, cryptographically signed tags.
- Attach a CycloneDX SBOM, source commit, container digests and checksums.
- Generate provenance with an identity controlled by the organization.
- Publish a changelog and any known security limitations.
- Never publish deployment credentials, private evidence, state files,
  generated source maps or unredacted logs.

## Verification

After applying the controls:

1. Open a test pull request without DCO signoff and confirm it is blocked.
2. Add the author signoff and confirm every required check runs.
3. Attempt a direct push and a force push to `main`; both must fail.
4. Submit a harmless private vulnerability report and verify notification.
5. Push a revoked test credential and confirm push protection blocks it.
6. Create and delete a test release candidate using the documented release
   identity before publishing a real version.
