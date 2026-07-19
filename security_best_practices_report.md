# Security best-practices review

Date: 2026-07-19

## Executive summary

The public repository is secure by default for a pre-production release. The
review found and fixed four material web and supply-chain weaknesses: an
unredistributable bundled font, a CSP-incompatible inline bootstrap, permissive
origin fallback, and implicit trust in caller-controlled proxy headers.
Production now fails closed when security dependencies are absent, renders
with a request nonce, and validates the live CSP/hydration contract.

No critical code finding remains from this review. The system is not safe for
funded public use until the external controls in `docs/RELEASE_GATES.md` and
`docs/repository-hardening.md` are complete. The smart contracts have not been
independently audited.

## Critical

No open critical finding.

## High

### SEC-001 — External repository controls are not yet verified

**Status:** Open, release blocking.

Branch rulesets, private vulnerability reporting, secret-scanning push
protection, organization team permissions and the public security mailboxes
must be enabled and tested by an organization owner. The required control set
is recorded in `docs/repository-hardening.md`.

### SEC-002 — Hardware and contract trust boundaries lack independent evidence

**Status:** Open, release blocking.

The repository cannot prove safe physical Kata/VFIO execution or correct
mainnet contract behavior. A dedicated hostile-image hardware run and
independent contract/infrastructure review are mandatory before funded use.
The product warning and release boundary are documented in `README.md` and
`docs/SECURITY_MODEL.md`.

## Medium

### SEC-003 — CSP requires dynamic application rendering

**Status:** Resolved and regression-tested.

Next.js can only attach a request-specific nonce when the route is rendered
dynamically. `apps/web/app/layout.tsx:8` enforces that contract. The proxy
creates a fresh nonce and applies the same policy to the request and response
at `apps/web/proxy.ts:3-14`; the production script policy is defined at
`apps/web/proxy.ts:17-50`. `scripts/test-web-runtime.sh` boots the standalone
build and proves that rendered scripts carry the response nonce.

### SEC-004 — Mutation origin checks previously had an unsafe fallback

**Status:** Resolved.

Production requests now require the configured application origin and requests
without `Origin` are accepted only when Fetch Metadata identifies a same-origin
navigation. See `apps/web/lib/server-origin.ts:6-20`. Every application proxy
request passes this check before authentication or forwarding at
`apps/web/app/api/app/[...path]/route.ts:12-25`.

### SEC-005 — Proxy-derived rate-limit identity was implicitly trusted

**Status:** Resolved.

The application now reads a client IP only from an explicitly configured,
allowlisted trusted-edge header. Unconfigured and arbitrary headers map to a
shared unattributed subject. See
`apps/web/lib/server-rate-limit.ts:137-144`. Production also fails closed when
the TLS-backed rate-limit store is unavailable at
`apps/web/lib/server-rate-limit.ts:20-47`.

### SEC-006 — Contribution and dependency controls needed enforcement

**Status:** Resolved in repository; organization settings remain under SEC-001.

All GitHub Actions are pinned to full commit SHAs, checkout credentials are not
persisted, PR dependencies are reviewed, CodeQL runs extended queries, DCO
signoff must match the commit author, and OpenSSF Scorecard publishes SARIF.
The primary workflow runs with read-only contents permission at
`.github/workflows/validate.yml:12-40`.

## Low

### SEC-007 — Inline styles remain allowed

**Status:** Accepted.

`style-src 'unsafe-inline'` remains at `apps/web/proxy.ts:32` for framework and
component compatibility. Script execution does not allow `unsafe-inline` in
production. Moving every dynamic style to nonce-bearing style elements would
add complexity without materially changing the current pre-production threat
boundary.

## Verification performed

- TypeScript type checking and 21 Vitest tests.
- Next.js production and standalone runtime builds.
- Browser navigation, theme state and responsive rendering.
- Rust formatting, Clippy with warnings denied, 51 unit tests and RustSec.
- Foundry formatting plus 18 unit, fuzz and stateful invariant tests.
- Trivy vulnerability, secret and misconfiguration scanning.
- Slither analysis across 14 contracts with 95 detectors.
- Actionlint and ShellCheck.
- PostgreSQL, Valkey TLS, mTLS tunnel, SSH/Jupyter, lifecycle, chaos, load,
  systemd, TLS, Compose and Prometheus integration checks.
- Credential, prohibited attribution, personal path, binary asset string,
  extended-attribute and repository-isolation scans.

The web container build requires more than the local 2 GB Docker VM available
during this review. Its native production build and standalone runtime checks
passed; the container build remains a required GitHub Actions gate.
