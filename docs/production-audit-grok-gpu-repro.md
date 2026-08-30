# Production Audit: Grok GPU Repro

## Executive Summary

The bot-facing contract describes a bounded, digest-pinned GPU reproduction, preserves human wallet approval, exposes only capability-scoped reads, and distinguishes Grok Build distribution from Grok Bot skills. The hosted execution path has also been hardened so unfunded provider capacity fails closed, provider cleanup cannot hold customer escrow hostage, stale offer failures are remembered, and retryable chain failures do not permanently strand lifecycle actions. The release is not complete until production has a funded Vast account, a private Robinhood Chain RPC endpoint, one paid end-to-end repro with a verified receipt, and npm version 0.2.0 published by `winterstacks`. Until those gates pass, the system must advertise zero managed capacity and the package must remain unpublished.

## Critical Issues (P0 - Block Release)

- [x] Provider offers were advertised without checking whether the broker account could fund them. | A renter could fund a lease that could never create a GPU. | Added durable provider state, fresh account balance checks, a conservative per-slot reserve, funded-slot accounting, and control-plane admission gates.
- [x] Provider cleanup ran before an escrow refund. | A Vast outage could keep customer funds locked and eventually exhaust the only refund action. | Refund and finalization now complete first; independent `cleanup_cloud` actions retry indefinitely and keep the broker slot unavailable until destruction succeeds.
- [x] Retryable RPC failures consumed finite lifecycle attempts. | Rate limiting or an upstream outage could make a financially open lease terminally unclaimable. | Added bounded HTTP retry with jitter and `Retry-After`, typed transient errors, non-consuming lifecycle retries, and unlimited submitted-transaction polling.
- [x] Failed historical financial actions could preserve obsolete signed transactions. | Requeuing them unchanged could resubmit a stale nonce forever, while blindly reviving already terminal leases would waste gas. | Migration 0024 now leaves locally refunded/finalized actions archived and clears transaction and confirmation fields only for nonterminal actions before fresh preflight and signing.
- [x] Terminal cloud rows could remain non-destroyed after the provider instance was already gone. | Stale rows could reserve capacity indefinitely and obscure whether a machine was still billing. | The new lifecycle worker idempotently backfills `cleanup_cloud` actions after rollout; Vast currently reports zero account instances, and cleanup reconciles the local rows without trusting them as provider truth.
- [ ] Vast billing balance is sufficient for at least one configured reserve. | Production correctly exposes no managed GPU capacity while the balance is zero or negative. | Add funds through Vast billing, then verify `cloud_provider_state.state = 'healthy'` and a fresh capacity row. Owner: operator.
- [ ] Production uses a private Robinhood Chain RPC endpoint. | The public endpoint is explicitly rate-limited and is not suitable as the sole financial lifecycle dependency. | Provision an Alchemy or equivalent production endpoint, set the backend RPC environment and public read endpoint, then exercise failover/retry behavior. Owner: operator.
- [ ] A paid end-to-end repro has produced inspectable evidence and an onchain settlement receipt. | Unit and integration tests do not prove provider purchase, GPU startup, runner execution, refund accounting, or public evidence delivery in the deployed environment. | Run the pinned PyTorch SDPA parity repro after funding; verify result, signature bindings, receipt totals, settlement transaction, and provider cleanup.
- [ ] npm 0.2.0 is published and installed from the registry. | A local package is not a release. | Publish only after the paid production run passes, verify `winterstacks` ownership, install from npm into Grok Build, and run the forward test.

## High Priority (P1 - Fix Before Launch)

- [x] Explicitly stale provider offer IDs were retried on every claim. | The cheapest stale offers could prevent the worker from reaching a viable host. | Persist a bounded list in the claim-fenced outbox document and exclude those offers on later attempts.
- [x] Account-wide provider failures were treated like offer races. | Auth, credit, or permanent request failures could produce repeated charge attempts. | Added typed offer, credit, auth, transient, and permanent scopes; account-scoped failures atomically disable all Vast capacity.
- [x] Unknown repro capabilities appeared to wait forever. | A mistyped or fabricated token looked like a valid pending job. | Unknown capabilities now return an explicit not-found error.
- [x] Capability tokens were documented on the command line. | Local process listings could expose a bearer capability. | Added bounded UTF-8 stdin input and made `--token-stdin` the documented path; argv input remains compatibility-only.
- [x] Settlement network and asset were omitted at approval time. | A user could not verify the full financial context before signing. | Preparation output and the skill now require Robinhood Chain, chain ID 4663, USDG, the canonical asset contract, and six decimals.
- [x] Provisioning writes were vulnerable to an expired-claim race. | A stale worker could overwrite a newer provider binding or leave an extra instance billing. | Added monotonic claim generations, live-claim fencing, a shared per-lease advisory lock, and stale-instance cleanup.
- [ ] Durable alerts are enabled for stale cleanup actions, provider breaker state, and stale capacity. | Logs alone may not wake an operator during a billing or escrow incident. | Configure a reviewed alert destination and enable the health timer only after confirming it cannot notify an unintended channel.
- [ ] Latched provider breaker reset is exercised in production. | Auth and unknown permanent failures intentionally require manual recovery. | Follow the documented reset runbook after a controlled latch test and verify fresh provider observation restores capacity.

## Medium Priority (P2 - Fix Soon After Launch)

- [ ] Provider HTTP classification has integration tests against a mock server. | Pure classification tests do not cover response envelopes, body truncation, redirect behavior, or transport timing. | Add deterministic server tests for 400 credit, explicit stale offers, 401/403, 429 with `Retry-After`, 5xx, timeouts, redirects, malformed JSON, and lost create responses.
- [ ] Refund-first cleanup has database-backed concurrency tests. | Unit tests do not fully exercise duplicate workers, claim expiry, externally settled leases, and provider outages together. | Add PostgreSQL integration tests that run competing workers and assert one financial settlement plus eventual idempotent cleanup.
- [ ] RPC endpoint failover is supported. | Retries improve transient survival but one provider remains a regional and vendor dependency. | Add an ordered endpoint pool with health scoring and require independent providers for transaction submission and read confirmation.
- [ ] Managed capacity exposes operator-facing breaker and reserve metrics. | Database state and logs are inspectable but slow to triage. | Export balance age, funded slots, breaker state, create failures by scope, cleanup age, and chain retry counts.
- [ ] Repro evidence has an automated public verification utility. | Inspectable JSON is useful, but users still have to manually validate hashes and signatures. | Ship a verifier that checks spec, result, evidence bindings, signer identity, receipt totals, and chain transaction data without private credentials.

## Low Priority (P3 - Technical Debt)

- [ ] Provider policy is generalized beyond a single broker implementation. | Current state constraints and operational tooling assume Vast. | Generalize only when a second provider is real; premature abstraction would add risk now.
- [ ] Capacity refresh batches registry reads. | Serial paced calls are deliberately conservative but will scale poorly with a large broker pool. | Add a contract multicall or indexed cache once the managed pool exceeds the current small fixed size.
- [ ] Package provenance is signed. | npm integrity protects transport but does not provide an independent release attestation. | Add provenance after the no-source-host release path has a suitable trusted builder.

## Security Assessment

The execution contract has the right authority boundary: preparation and reads cannot sign a wallet transaction, the image is digest-pinned, the command is immutable after preparation, duration and minimum VRAM are fixed, and the maximum escrow is shown before approval. Capability tokens are high-entropy bearer secrets, are sent only in MCP POST bodies, and the bundled CLI has no arbitrary tool selector. The CLI rejects redirects, bounds response bodies, keeps a timeout active through body reads, validates the canonical token shape before making a request, strips control characters from remote errors, and supports stdin so the token need not appear in process arguments.

The remaining security-sensitive operational risks are credential custody and financial dependencies. Vast credentials must remain file-backed or injected by the deployment platform and must never enter images, logs, package contents, or command arguments. The chain signer must remain KMS-backed in production. A private RPC credential must be stored only in production secrets. GPU inputs must be public and non-confidential because assigned machines may be operated by independent providers. Gateway-signed managed execution evidence must not be described as device attestation or proof of correct computation.

The contract security scan is clean across 25 contracts and 95 Slither detectors, and all 55 Foundry tests pass, including three invariant suites with 384,000 calls. Source-level checks now use defensive award bounds and checks-effects-interactions in staking. The deployed immutable staking contract is unchanged; its immutable token runtime has no external-call opcodes, so the reported callback path is unreachable with the deployed token, but the source hardening still applies to future deployments.

Rust dependency audit is clean under one narrow documented exception for the transitive `rsa` timing advisory: Prism uses that path only for public-key verification of AMD certificate signatures and performs no private RSA operation. `h2` and `event-listener` were upgraded to patched releases. The remaining informational `lru` warning requires a panicking key destructor under `catch_unwind` and is transitive through the AWS S3 SDK; Prism uses neither condition. The lockfile also contains a yanked transitive `chacha20` release through `reqwest`/`quinn`, with no compatible upstream replacement yet.

Provider failure messages are bounded and sanitized before logging. Durable provider state stores only balance micros and normalized failure classes, not account identity or raw response bodies. Auth and permanent failures latch, while credit and transient failures recover only after a fresh successful account observation. All capacity queries require both a fresh available host row and a fresh healthy provider state.

## Performance Assessment

The hot marketplace queries add a constant-size `EXISTS` lookup against a primary-keyed provider-state table. Capacity refresh runs at most every 30 seconds and performs one provider account lookup plus one offer survey for the broker pool. Chain maintenance reads are intentionally paced to avoid rate-limit cascades. This is appropriate for the current small managed node pool.

The principal scaling limits are serial registry calls, a single RPC endpoint, one broker account, and label-based reconciliation after ambiguous provider responses. None blocks a small production launch, but the RPC dependency is a release blocker because it is also a financial correctness dependency. Before materially increasing the broker pool, add endpoint failover, metrics, and load tests for capacity listing and confirmation under concurrent repro preparation.

## Observability Assessment

The worker records durable provider health, failure scope, balance, failure count, timestamps, per-node capacity, per-lease cloud state, outbox status, and cleanup errors. Logs distinguish account breaker events, stale offers, sourcing decisions, cloud observation failures, refunds, and cleanup retries. The health script now reads Vast's `balance` field, treats missing credentials as an alarm, and uses the same 90-second capacity freshness window as serving.

Production still needs a reviewed alert sink. The existing health timer remains disabled because enabling it can send external notifications. Required alarms are: provider state not healthy, balance below one reserve, no fresh capacity when funded, cleanup older than ten minutes, submitted lifecycle action older than ten minutes, settlement mismatch, RPC transient-error rate, and proof-index lag.

## Recommended Architecture Changes

1. Introduce a two-provider RPC pool. Submit through one private endpoint and confirm through another independent endpoint, with chain ID validation on startup.
2. Keep financial settlement and provider cleanup as separate state machines. Customer funds must never depend on a provider control plane.
3. Preserve the durable provider breaker as the admission source of truth. UI availability must never infer rentability directly from provider market offers.
4. Add a standalone evidence verifier so a third party can validate a repro capsule without trusting the web application.
5. Add explicit operational endpoints or metrics for breaker reset diagnostics and cleanup backlog; do not make raw database access the normal control plane.

## Test Coverage Gaps

Completed verification covers Rust formatting, strict Clippy checks, chain retry unit tests, lifecycle unit tests, control-plane unit tests, web tests, TypeScript type checking, CLI tests, skill validation, Grok manifest validation, package dry-run contents, and a disposable PostgreSQL migration chain. The release still lacks:

- a paid GPU execution on the deployed image;
- a production wallet approval and settlement receipt;
- a real Vast create failure/recovery matrix;
- concurrent database-backed refund and cleanup tests;
- sustained RPC rate-limit and failover tests;
- a Grok forward test installed from the published npm artifact;
- alert-delivery verification to an explicitly approved destination.

The full repository validation was also reproduced manually, including PostgreSQL lifecycle tests, the durable end-to-end lifecycle fixture, a 1,000-request load smoke, contract invariants, and the security scan. The only unreproduced inherited gate is the SNP reference-measurement test because `node/guest/out/OVMF.fd` is absent from every available worktree and the production host. The gate was not weakened and no substitute artifact was fabricated.

## Action Plan

1. Complete independent review and all local quality gates.
2. Commit immutable release and plugin snapshots locally; do not push to a source host.
3. Rehearse migrations 0001 through 0024 on disposable PostgreSQL.
4. Build and push a rollback-compatible control-plane image first, then release images sequentially to conserve disk.
5. Configure the private RPC endpoint and provider reserve in production secrets.
6. Deploy backend workers and web directly, apply migration 0024, and verify zero capacity while the provider account is unfunded.
7. Fund Vast, verify a fresh healthy provider state, and confirm the advertised slot count never exceeds funded capacity.
8. Prepare the pinned PyTorch SDPA parity repro, show the exact network, asset, executor, duration, image digest, and maximum escrow, then wait for human wallet approval.
9. Verify output, evidence bindings, receipt accounting, chain settlement, and eventual provider destruction.
10. Publish npm 0.2.0 as `winterstacks`, install from npm, validate the plugin, and run the Grok capacity-only forward test.
11. Enable alerts only after the destination and message side effects are explicitly approved.

## Release Decision

**Not yet releasable.** The code-level P0 failures identified in this audit are fixed and local gates are green, but production funding, a private RPC, a paid GPU run, and npm publication remain hard release gates. The safe deployed behavior before those gates is zero managed GPU capacity.
