# Contributing

Prism accepts focused changes that improve the safety, reliability,
interoperability or usability of the network.

## Before opening a change

- Search existing issues and pull requests.
- Use a public issue for normal bugs and proposals.
- Follow [SECURITY.md](SECURITY.md) for vulnerabilities.
- Keep changes scoped; unrelated refactors require separate pull requests.
- Do not include credentials, user data, proprietary assets or generated
  deployment outputs.

Material protocol, contract, trust-boundary or payment changes require a design
issue before implementation.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Install pinned toolchains and dependencies.
3. Add tests for behavior changes.
4. Run the relevant fast checks locally.
5. Run `./scripts/validate.sh` before requesting a release review.
6. Open a pull request using the repository template.

All commits must carry a Developer Certificate of Origin sign-off:

```sh
git commit --signoff
```

The sign-off certifies that you have the right to submit the contribution under
the repository license.

## Review expectations

Reviewers evaluate:

- Correctness across failure and retry paths.
- Authentication, authorization and input-validation boundaries.
- Fund conservation and replay safety for contract changes.
- Privacy, secret handling and log redaction.
- Backward compatibility and migration impact.
- Tests, documentation and operational observability.

Maintainers may require threat-model, invariant, load, hardware or deployment
evidence before merging high-risk changes.

## Style

- Follow the existing module and naming conventions.
- Keep comments focused on non-obvious intent and constraints.
- Prefer explicit failure handling and secure defaults.
- Format Rust with `cargo fmt` and Solidity with `forge fmt`.
- Keep TypeScript strict and warning-free.

## Licensing

Contributions are accepted under Apache-2.0. The project does not accept code
that cannot be redistributed under that license.
