# Production Audit: Proof Publisher

## Executive Summary

The proof publisher is release-ready for the current network volume. It binds
every new receipt to an exact escrow and chain lease ID, verifies settlement
events before publication, publishes immutable page sets behind one mutable
digest-bound index, and removes revoked direct receipts. No P0 or P1 defect
remains in this scope. Deployment still requires the ordered cutover in the EC2
runbook; running the old static publisher and the database worker together is
not supported.

## Critical Issues (P0 - Block Release)

- [x] No unresolved critical issue.

## High Priority (P1 - Fix Before Launch)

- [x] Bind receipt rows, documents, and chain verification to
  `(escrow_address, chain_lease_id)`.
- [x] Make evidence immutable and permit only pending-to-published and
  pending-or-published-to-quarantined state changes.
- [x] Preserve the last complete index while any receipt is pending or a batch
  changes concurrently.
- [x] Bind completion markers to the exact index SHA-256 and rebuild a missing,
  corrupt, or incorrectly cached index.
- [x] Invalidate the in-process fast path when a published row is quarantined.
- [x] Validate reconciliation markers by exact content and cache metadata before
  skipping direct-receipt repair.
- [x] Use short-lived caching for mutable direct receipts and immutable caching
  only for content-addressed page sets and their reconciliation marker.
- [x] Bound S3 operations to 30 seconds and interrupt staging and cleanup on
  shutdown.
- [x] Keep the proof worker dependent only on PostgreSQL so proof cutover cannot
  start the public control plane early.

## Medium Priority (P2 - Fix Soon After Launch)

- [ ] Add publication-lag, pending/quarantined row, last-success, and artifact
  operation metrics with alerts. Structured logs exist, but they do not replace
  an operator-facing freshness signal.
- [ ] Parallelize chain reads with a conservative concurrency limit if volume
  grows materially. Verification is deliberately sequential today and is safe,
  but a large backlog would recover slowly.
- [ ] Define a retention policy for obsolete content-addressed sets. They are
  immutable and harmless, but storage grows monotonically.

## Low Priority (P3 - Technical Debt)

- [ ] Add an operator-only command that compares every direct receipt and page
  against its expected digest. Normal publication verifies direct receipts once
  per set and trusts completed immutable objects afterward.

## Security Assessment

Receipt evidence is checked against the canonical chain, configured escrow,
transaction outcome, confirmation depth, event amounts, and receipt commitment.
Database constraints reject mixed identities and mutable evidence. The worker
accepts only HTTPS RPC endpoints outside loopback, X posting is opt-in, and
artifact keys reject traversal. Production storage credentials must remain
write-scoped to the proof prefix and must not be exposed to the web container.

## Performance Assessment

The steady-state path is constant-cost: one pending query, one published-row
token query, and two artifact metadata checks. A restart intentionally rebuilds
the complete published set, bounded at 100,000 receipts. Index responses include
at most 1,000 receipts; the complete set is split into immutable 500-receipt
pages.

## Observability Assessment

The worker emits structured publication, deferral, quarantine, shutdown, and X
delivery logs. The advisory lock prevents a second database publisher. Release
operations still need external freshness and quarantine alerts before the
publisher can be treated as unattended infrastructure.

## Recommended Architecture Changes

No architecture change blocks this release. Keep the single-writer database
model and content-addressed page sets. Add metrics before network volume makes
log-only operations difficult.

## Test Coverage

- 32 proof-worker unit and failure-recovery tests pass.
- Strict proof-worker Clippy passes with warnings denied.
- The PostgreSQL migration and lifecycle integration test passes against an
  isolated PostgreSQL 17 container.
- 16 browser proof-parser/hash tests pass.
- Web TypeScript checking and the production Next.js build pass.
- Migration `0027_proof_receipt_identity.sql` SHA-256:
  `a620558a4360f0b2889686162f4347a61e2b013e71d2bc9becdc143ed2591f00`.

## Action Plan

1. Stop and disable the static proof-index timer before starting the worker.
2. Apply migration 27 while receipt writers are stopped and inspect every
   quarantined row.
3. Start exactly one proof worker while admissions remain closed.
4. Verify index JSON, immutable page traversal, direct receipts, cache headers,
   and stale-receipt removal from the public edge.
5. Enable freshness and quarantine alerts, then reopen admissions.
