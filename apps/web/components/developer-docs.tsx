import Link from "next/link";
import { PublicFooter } from "@/components/public-footer";
import { siteUrl } from "@/lib/site";

const sections = [
  ["overview", "Overview"],
  ["architecture", "Architecture"],
  ["quickstart", "Quickstart"],
  ["authentication", "Authentication"],
  ["api", "HTTP API"],
  ["funding", "Funding flow"],
  ["lifecycle", "Lease lifecycle"],
  ["runtime", "Runtime modes"],
  ["contracts", "Contracts"],
  ["settlement", "Settlement"],
  ["security", "Security model"],
  ["operations", "Operations"],
  ["errors", "Errors"],
  ["agent", "Agent access"],
] as const;

const contracts = [
  ["USDG", "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", "6 decimals"],
  ["NodeRegistryV1", "0xe3b7eF730637763ed46542d41a6C3f83AfC78f01", "Supplier bonds and offers"],
  ["LeaseEscrowV1", "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD", "Lease funding and settlement"],
  ["Governance Safe", "0xAF1113cE9E65D79daA87005A729Ab9Bc1A9fc60a", "Administration, emergency and dispute authority"],
] as const;

const states = [
  ["funded", "Escrow event confirmed and associated with a five-minute quote."],
  ["provisioning", "Capacity assignment and workspace provisioning are in progress."],
  ["ready", "GPU and access admission checks passed; access start is pending finality."],
  ["active", "Billable access is available to the authenticated renter."],
  ["closing", "Credentials are revoked and the runtime is being destroyed."],
  ["settlement_pending", "Usage evidence has produced an onchain settlement proposal."],
  ["disputed", "Finalization is blocked pending Safe-controlled resolution."],
  ["finalized", "Provider payment, platform fee, and renter refund are complete."],
  ["refunded", "The lease ended without a provider charge."],
  ["failed", "Provisioning failed before a final onchain transition was recorded."],
] as const;

const errors = [
  ["400", "invalid_request", "Malformed path, JSON, duration, image digest, GPU request, or wallet payload."],
  ["401", "identity_required", "No valid Privy-backed Prism session is available."],
  ["403", "invalid_origin / risk_hold", "The mutation is cross-origin or the account is restricted."],
  ["404", "no_match / quote_not_found", "No compatible capacity exists or the quote is absent/expired."],
  ["409", "network_capacity / identity_replay", "A concurrency bound or replay guard rejected the operation."],
  ["413", "request_too_large", "The application API body exceeds 256 KiB."],
  ["415", "unsupported_media_type", "A mutation was not submitted as application/json."],
  ["429", "rate_limited", "The same-origin API budget was exceeded; honor Retry-After."],
  ["503", "service_unavailable", "A required identity, rate-limit, orchestration, or provider service is unavailable."],
] as const;

const quoteExample = `{
  "request": {
    "image": "docker.io/nvidia/cuda@sha256:<64 hex chars>",
    "duration_seconds": 3600,
    "min_vram_mib": 45000,
    "preferred_node_id": null
  }
}`;

const quoteResponse = `{
  "quote_id": "9d417fc0-6f42-4d8b-a44f-9ab3cf1bc41f",
  "node_id": "0x<32-byte node id>",
  "image": "docker.io/nvidia/cuda@sha256:<digest>",
  "duration_seconds": 3600,
  "min_vram_mib": 45000,
  "rate_per_second": 222,
  "maximum_escrow": 799200,
  "expires_at": "2026-07-20T18:00:00Z"
}`;

const fundingExample = `const maximum = BigInt(quote.rate_per_second)
  * BigInt(quote.duration_seconds);
const clientReference = keccak256(toBytes(quote.quote_id));

await wallet.writeContract({
  address: USDG,
  abi: erc20Abi,
  functionName: "approve",
  args: [LEASE_ESCROW, maximum],
});

await wallet.writeContract({
  address: LEASE_ESCROW,
  abi: escrowAbi,
  functionName: "createLease",
  args: [quote.node_id, quote.duration_seconds, clientReference],
});`;

const confirmExample = `{
  "quote_id": "9d417fc0-6f42-4d8b-a44f-9ab3cf1bc41f",
  "transaction_hash": "0x<funding transaction hash>",
  "ssh_authorized_key": "ssh-ed25519 AAAA... workstation"
}`;

const agentExample = `import { PrismAgent, DEFAULT_IMAGE } from "@prism-network/agent-sdk";

const agent = new PrismAgent({
  privateKey: process.env.AGENT_KEY,
  escrow: "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD",
});

await agent.authenticate();
const lease = await agent.lease({ image: DEFAULT_IMAGE, durationSeconds: 900, minVramMib: 16000 });
const out = await agent.run(lease, "nvidia-smi");
console.log(out.stdout);
agent.endLease(lease);`;

export function DeveloperDocs() {
  return (
    <div className="docs-page">
      <header className="docs-header">
        <Link className="landing-brand" href={siteUrl.href} aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Documentation header">
          <a href="https://github.com/prismnetwork-tech/prism" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <Link href={new URL("/proof", siteUrl).href}>Proof</Link>
          <Link className="docs-console-link" href={new URL("/compute", siteUrl).href}>Open console ↗</Link>
        </nav>
      </header>

      <div className="docs-layout">
        <aside className="docs-sidebar">
          <p>Developer documentation</p>
          <nav aria-label="Documentation sections">
            {sections.map(([id, label], index) => (
              <a href={`#${id}`} key={id}><span>{String(index).padStart(2, "0")}</span>{label}</a>
            ))}
          </nav>
          <div className="docs-version">
            <span>API</span><strong>v1</strong>
            <span>Chain</span><strong>4663</strong>
            <span>Stage</span><strong>Live</strong>
          </div>
        </aside>

        <main className="docs-content" id="main-content" tabIndex={-1}>
          <section className="docs-hero" id="overview">
            <p className="docs-kicker">Prism Network / Developer reference</p>
            <h1>Build against metered GPU infrastructure.</h1>
            <p>
              Prism matches digest-pinned container workloads with bonded NVIDIA capacity,
              holds the maximum cost in USDG, starts billing only after runtime admission,
              and resolves the lease through an onchain settlement record.
            </p>
            <div className="docs-hero-actions">
              <a className="landing-button primary" href="#quickstart">Start integration <span>↓</span></a>
              <a className="landing-button secondary" href="https://github.com/prismnetwork-tech/prism" target="_blank" rel="noopener noreferrer">Read source <span>↗</span></a>
            </div>
            <dl className="docs-facts">
              <div><dt>Execution</dt><dd>L40S cloud</dd></div>
              <div><dt>Settlement</dt><dd>Robinhood Chain + USDG</dd></div>
              <div><dt>Access</dt><dd>Temporary, key-only SSH</dd></div>
              <div><dt>Billing unit</dt><dd>Confirmed runtime second</dd></div>
            </dl>
          </section>

          <DocsSection id="architecture" index="01" eyebrow="System model" title="Architecture">
            <p>
              The public web application is the identity boundary. It verifies Privy access
              tokens, establishes an HTTP-only same-origin session, rate-limits requests, and
              signs service-to-service identity assertions. Browsers never receive orchestration
              signing keys, settlement keys, device keys, or provider credentials.
            </p>
            <div className="architecture-flow" aria-label="Prism request architecture">
              <FlowNode label="Browser" detail="Privy + wallet" />
              <FlowArrow label="HTTPS" />
              <FlowNode label="Web boundary" detail="Session + rate limit" />
              <FlowArrow label="Signed identity" />
              <FlowNode label="Control plane" detail="Quote + lifecycle state" />
              <FlowArrow label="Asynchronous processing" />
              <FlowNode label="Workers" detail="Provider + chain" />
            </div>
            <div className="docs-grid two">
              <InfoCard title="Data plane">
                <p>Managed cloud leases receive a temporary direct SSH endpoint. Operator-owned infrastructure uses revocable gateway grants over outbound mTLS tunnels.</p>
              </InfoCard>
              <InfoCard title="Control plane">
                <p>PostgreSQL is the system of record for accounts, quotes, provider instances, lease transitions, settlement transactions, and proof publication.</p>
              </InfoCard>
              <InfoCard title="Settlement plane">
                <p>Robinhood Chain contracts enforce escrow limits, active-lease bounds, dispute timing, provider payment, platform fees, and refunds.</p>
              </InfoCard>
              <InfoCard title="Governance plane">
                <p>The Governance Safe routes routine configuration changes through a 48-hour timelock. Emergency pause and dispute resolution remain immediate Safe actions.</p>
              </InfoCard>
            </div>
          </DocsSection>

          <DocsSection id="quickstart" index="02" eyebrow="Renter integration" title="Quickstart">
            <ol className="docs-steps">
              <li><span>01</span><div><h3>Prepare the workload</h3><p>Publish a Linux/amd64 OCI image to a public registry and address it by its complete immutable <code>sha256</code> digest.</p></div></li>
              <li><span>02</span><div><h3>Prepare access</h3><p>Create a disposable Ed25519 key. Submit only the single-line public key; the private key must never leave the renter machine.</p></div></li>
              <li><span>03</span><div><h3>Authenticate</h3><p>Use the console to create a Privy-backed Prism session and connect the wallet that will fund escrow.</p></div></li>
              <li><span>04</span><div><h3>Quote and fund</h3><p>Request a five-minute quote, approve the exact maximum USDG amount, and call <code>createLease</code> with the quote-derived reference.</p></div></li>
              <li><span>05</span><div><h3>Confirm and connect</h3><p>Confirm the finalized funding transaction, poll the lease until active, retrieve access, verify the host key, and connect over SSH.</p></div></li>
            </ol>
            <Callout kind="warning" title="Data classification">
              Do not place private keys, production credentials, regulated data, confidential
              datasets, or valuable model weights inside a workspace. Provider operators
              remain within the trust boundary.
            </Callout>
          </DocsSection>

          <DocsSection id="authentication" index="03" eyebrow="Identity boundary" title="Authentication">
            <p>
              Interactive access uses Privy. The browser obtains an access token, posts it to
              <code>/api/auth/session</code>, and receives a secure, HTTP-only, same-site cookie
              with a one-hour maximum age. Mutation endpoints require both that session and a
              same-origin request.
            </p>
            <div className="docs-grid two">
              <InfoCard title="Browser clients">
                <ul>
                  <li>Email, passkey, Google, Apple, or EVM wallet login.</li>
                  <li>Embedded wallet creation for accounts without an external wallet.</li>
                  <li>Explicit funding-wallet selection when multiple wallets are linked.</li>
                  <li>Session revocation on logout and server-side identity rejection.</li>
                </ul>
              </InfoCard>
              <InfoCard title="Agent and service clients">
                <p>Autonomous agents authenticate with a wallet signature instead of a browser session; see <a className="docs-inline-link" href="#agent">Agent access</a>. Browser cookies and browser identity assertions are not accepted as service credentials.</p>
              </InfoCard>
            </div>
            <Callout kind="note" title="Service authentication">
              <code>X-Prism-Subject</code>, <code>X-Prism-Session-Id</code>, timestamp, and
              signature headers are generated by Prism&apos;s web identity service. They are
              service-to-service credentials, not a supported integration interface.
            </Callout>
          </DocsSection>

          <DocsSection id="api" index="04" eyebrow="Web application API" title="HTTP API">
            <p>
              Browser integrations use <code>https://prismnetwork.tech/api/app</code>. Responses
              are JSON, never cached, and include <code>X-Request-Id</code>. Mutation bodies must
              be <code>application/json</code> and no larger than 256 KiB.
            </p>
            <div className="endpoint-list">
              <Endpoint method="GET" path="/api/app/offers" auth="Public" description="List currently schedulable, bonded offers." />
              <Endpoint method="POST" path="/api/app/leases/match" auth="Session" description="Create a five-minute quote for an image, runtime, VRAM floor, and optional node." />
              <Endpoint method="POST" path="/api/app/leases/confirm" auth="Session" description="Bind a finalized funding event and Ed25519 public key to a quote." />
              <Endpoint method="GET" path="/api/app/leases" auth="Session" description="List leases owned by the authenticated account." />
              <Endpoint method="GET" path="/api/app/leases/{lease_id}/access" auth="Session" description="Return direct SSH or gateway access only after readiness and chain finality." />
              <Endpoint method="GET" path="/api/proof" auth="Public" description="Read the sanitized finalized/refunded public proof feed." />
            </div>
            <CodeBlock label="POST /api/app/leases/match" code={quoteExample} />
            <CodeBlock label="201 quote response" code={quoteResponse} />
            <h3 className="docs-subheading">Matching constraints</h3>
            <ul className="docs-list">
              <li><code>image</code> must be public, whitespace-free, at most 512 characters, and end in a complete <code>@sha256:</code> digest.</li>
              <li><code>duration_seconds</code> must be between 1 and 21,600 seconds.</li>
              <li><code>min_vram_mib</code> must be a positive integer compatible with an online offer.</li>
              <li><code>preferred_node_id</code> is optional; omit it for deterministic best-match selection.</li>
              <li>The resulting maximum escrow cannot exceed 50 USDG.</li>
            </ul>
          </DocsSection>

          <DocsSection id="funding" index="05" eyebrow="Wallet transaction" title="Funding flow">
            <p>
              A quote does not reserve capacity or move funds. The renter wallet sends two
              sequential transactions: an exact USDG approval followed by
              <code>LeaseEscrowV1.createLease</code>. The client reference is the Keccak-256 hash
              of the UTF-8 quote UUID.
            </p>
            <CodeBlock label="viem reference" code={fundingExample} />
            <p>
              Wait for both receipts and reject any reverted status. Then confirm the funding
              transaction through the application API. Confirmation independently verifies the
              finalized <code>LeaseFunded</code> event, node, duration, renter wallet, deposit,
              and quote-derived client reference.
            </p>
            <CodeBlock label="POST /api/app/leases/confirm" code={confirmExample} />
            <Callout kind="note" title="Approval policy">
              Approve only the quoted maximum. Prism does not require an unlimited USDG allowance.
              Unused escrow is returned during final settlement or refund.
            </Callout>
          </DocsSection>

          <DocsSection id="lifecycle" index="06" eyebrow="State model" title="Lease lifecycle">
            <div className="state-list">
              {states.map(([state, description]) => (
                <div key={state}><code>{state}</code><p>{description}</p></div>
              ))}
            </div>
            <p>
              Transitions are idempotent and persisted before external side effects. Provider
              instance IDs, chain transaction bytes, nonces, hashes, confirmation blocks, and
              final-state evidence survive worker restarts. A ten-minute provision timeout is the
              refund boundary for leases that never reach billable access.
            </p>
          </DocsSection>

          <DocsSection id="runtime" index="07" eyebrow="Execution environments" title="Runtime modes">
            <div className="runtime-table">
              <div className="runtime-head"><span>Property</span><span>Managed L40S</span><span>Operator-owned infrastructure</span></div>
              <RuntimeRow label="Capacity" cloud="Managed NVIDIA L40S capacity" physical="Bonded operator-owned NVIDIA host" />
              <RuntimeRow label="Isolation" cloud="Disposable provider container" physical="Kata sandbox with VFIO GPU assignment" />
              <RuntimeRow label="Access" cloud="Temporary direct root SSH" physical="Revocable SSH/Jupyter grant via mTLS gateway" />
              <RuntimeRow label="Readiness" cloud="Provider state, GPU, VRAM, cost, SSH endpoint" physical="Signed telemetry plus independent active gateway probes" />
              <RuntimeRow label="Evidence" cloud="Provider instance and hourly cost" physical="Device-signed telemetry and gateway timing" />
              <RuntimeRow label="Availability" cloud="Live" physical="Planned; not available for production leases" />
            </div>
            <h3 className="docs-subheading">Container requirements</h3>
            <ul className="docs-list">
              <li>Publicly pullable Linux/amd64 OCI image.</li>
              <li>Immutable registry digest; tags alone are rejected.</li>
              <li>Compatible with the host NVIDIA driver and requested CUDA major version.</li>
              <li>No embedded credentials. Runtime access is injected separately.</li>
              <li>Workspace storage is ephemeral and must be treated as disposable.</li>
            </ul>
          </DocsSection>

          <DocsSection id="contracts" index="08" eyebrow="Robinhood Chain mainnet" title="Contracts">
            <div className="contract-table">
              {contracts.map(([name, address, role]) => (
                <div key={name}>
                  <strong>{name}</strong>
                  <code>{address}</code>
                  <span>{role}</span>
                </div>
              ))}
            </div>
            <dl className="parameter-grid">
              <div><dt>Chain ID</dt><dd>4663</dd></div>
              <div><dt>RPC</dt><dd><code>rpc.mainnet.chain.robinhood.com</code></dd></div>
              <div><dt>Maximum lease</dt><dd>6 hours</dd></div>
              <div><dt>Maximum escrow</dt><dd>50 USDG</dd></div>
              <div><dt>Provision timeout</dt><dd>10 minutes</dd></div>
              <div><dt>Dispute window</dt><dd>24 hours</dd></div>
              <div><dt>Platform fee</dt><dd>10%</dd></div>
              <div><dt>Network concurrency</dt><dd>25 active leases</dd></div>
            </dl>
            <Callout kind="warning" title="Unaudited contracts">
              The deployed contracts are operational software and have not completed an
              independent production audit. Verify contract addresses, bytecode, constructor
              inputs, and current pause state directly before building a financial dependency.
            </Callout>
          </DocsSection>

          <DocsSection id="settlement" index="09" eyebrow="Usage accounting" title="Settlement and proof">
            <p>
              Billing begins only after Prism confirms runtime and access readiness onchain.
              Closing revokes access first, destroys the execution
              environment, and then assembles bounded usage evidence.
            </p>
            <ol className="docs-steps compact">
              <li><span>01</span><div><h3>Observe</h3><p>Clamp confirmed runtime to the funded duration and preserve provider or physical-node execution evidence.</p></div></li>
              <li><span>02</span><div><h3>Propose</h3><p>Submit an EIP-712 settlement carrying usage seconds, receipt hash, nonce, and deadline.</p></div></li>
              <li><span>03</span><div><h3>Dispute</h3><p>Hold finalization for 24 hours. A renter can dispute; the governance Safe resolves disputed outcomes.</p></div></li>
              <li><span>04</span><div><h3>Finalize</h3><p>Pay 90% of the charge to the provider, route the 10% platform fee, and refund unused escrow.</p></div></li>
              <li><span>05</span><div><h3>Publish</h3><p>Verify the final chain event and expose a sanitized, canonical receipt in the public proof feed.</p></div></li>
            </ol>
            <p>
              Public receipts omit renter/provider wallet addresses, precise geography, image
              digests, terminal output, files, and private telemetry. Proof establishes a
              platform-attested usage record paired with a final onchain event; it does not
              prove faithful workload execution or confidential computing.
            </p>
          </DocsSection>

          <DocsSection id="security" index="10" eyebrow="Trust and abuse boundaries" title="Security model">
            <div className="docs-grid two">
              <InfoCard title="Enforced controls">
                <ul>
                  <li>Exact quote-bound funding event verification.</li>
                  <li>Digest-only public image admission.</li>
                  <li>One active lease per node and 25 network-wide.</li>
                  <li>50 USDG and six-hour contract limits.</li>
                  <li>Device signature, freshness, and replay checks.</li>
                  <li>Encrypted stored access credentials.</li>
                  <li>Replay-safe chain submissions with reorg-aware confirmation.</li>
                </ul>
              </InfoCard>
              <InfoCard title="Excluded protections">
                <ul>
                  <li>Host confidentiality or trusted execution.</li>
                  <li>Protection from a malicious provider operator.</li>
                  <li>Durable workspace storage.</li>
                  <li>Uninterrupted infrastructure-provider availability.</li>
                  <li>Independent smart-contract assurance.</li>
                  <li>Faithful execution of arbitrary renter workloads.</li>
                </ul>
              </InfoCard>
            </div>
            <h3 className="docs-subheading">Report a vulnerability</h3>
            <p>
              Do not publish an exploitable vulnerability in a public issue. Use this
              repository&apos;s GitHub private vulnerability reporting or email{" "}
              <a className="docs-inline-link" href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a>.
              Include the affected commit, component, reproduction, impact, and suggested
              containment. Never include live credentials or renter data.
            </p>
          </DocsSection>

          <DocsSection id="operations" index="11" eyebrow="Production behavior" title="Operations">
            <div className="docs-grid two">
              <InfoCard title="Idempotency and recovery">
                <p>Provider launches reconcile by a unique lease label. Chain submissions persist signed bytes before broadcast. Workers retry from persisted state and reject conflicting final-state transitions.</p>
              </InfoCard>
              <InfoCard title="Capacity admission">
                <p>Prism publishes an L40S offer only when available capacity satisfies model, VRAM, reliability, and pricing requirements.</p>
              </InfoCard>
              <InfoCard title="Failure containment">
                <p>Provision failures close or refund rather than starting billing. Destruction is retried before final settlement. Emergency pause blocks new leases without blocking existing refunds.</p>
              </InfoCard>
              <InfoCard title="Observability">
                <p>Use the response request ID to correlate web, control-plane, provider, and chain records. Public proof publication remains decoupled from financial settlement.</p>
              </InfoCard>
            </div>
            <h3 className="docs-subheading">Production availability</h3>
            <p>
              Prism expands public capacity after end-to-end production validation covers quoting,
              funding, provisioning, readiness, teardown, settlement, refunds, provider payment,
              and proof publication. Failed validations preserve diagnostic evidence and pause new
              lease funding until the affected service is restored.
            </p>
          </DocsSection>

          <DocsSection id="errors" index="12" eyebrow="Response handling" title="Errors and retries">
            <div className="error-table">
              <div className="error-head"><span>HTTP</span><span>Code</span><span>Meaning</span></div>
              {errors.map(([status, code, meaning]) => (
                <div key={code}><strong>{status}</strong><code>{code}</code><p>{meaning}</p></div>
              ))}
            </div>
            <ul className="docs-list">
              <li>Retry <code>429</code> only after <code>Retry-After</code>.</li>
              <li>Retry transient <code>503</code> responses with exponential backoff and a maximum delay, without changing the request.</li>
              <li>Before resubmitting a funding transaction, verify the wallet receipt and account lease history.</li>
              <li><code>funding_not_final</code> is expected before the required confirmation threshold and can be polled safely.</li>
              <li>Treat other <code>4xx</code> responses as non-retryable until the request or account state changes.</li>
            </ul>
          </DocsSection>

          <DocsSection id="agent" index="13" eyebrow="Autonomous integration" title="Agent access">
            <p>
              Autonomous agents integrate without a browser or Privy. An agent proves control of
              its funding wallet by signing a short-lived challenge, exchanges the signature for a
              bearer session, and drives the same renter surface — offer discovery and the lease
              lifecycle — over the <code>/api/agent</code> endpoints. Escrow, readiness, metering,
              and settlement are identical to the browser path.
            </p>
            <div className="endpoint-list">
              <Endpoint method="GET" path="/api/agent/challenge" auth="Public" description="Issue a single-use, five-minute challenge for a wallet address." />
              <Endpoint method="POST" path="/api/agent/session" auth="Signature" description="Exchange a wallet-signed challenge for a one-hour bearer session." />
              <Endpoint method="ANY" path="/api/agent/proxy/{path}" auth="Bearer" description="Authenticated passthrough to the renter API. Only offer and lease routes are reachable." />
            </div>
            <CodeBlock label="@prism-network/agent-sdk" code={agentExample} />
            <div className="docs-grid two">
              <InfoCard title="Agent SDK">
                <p>Headless leasing for Node. Authenticate, lease a digest-pinned image, run commands over SSH, and release — funded in USDG with native gas on Robinhood Chain.</p>
              </InfoCard>
              <InfoCard title="MCP server">
                <p>The same leasing exposed as Model Context Protocol tools, so an MCP client can list GPUs, lease and run a command, and release the lease.</p>
              </InfoCard>
              <InfoCard title="x402 one-shot compute">
                <p>Pay-per-job GPU execution over HTTP 402. Submit a command, pay USDG, and poll for the output; the service leases, runs, and releases on your behalf, refunding a failed job.</p>
              </InfoCard>
              <InfoCard title="Wallet as identity">
                <p>The signing wallet is the subject of every request. The agent boundary reaches only renter routes; operator, node, and gateway surfaces are rejected.</p>
              </InfoCard>
            </div>
            <Callout kind="warning" title="Packaging">
              The agent packages are not yet published to npm; install them from the repository.
              The data-classification limits above apply unchanged. An agent workspace is a
              disposable environment, not confidential computing.
            </Callout>
          </DocsSection>

        </main>
      </div>
      <PublicFooter />
    </div>
  );
}

function DocsSection({
  id,
  index,
  eyebrow,
  title,
  children,
}: {
  id: string;
  index: string;
  eyebrow: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="docs-section" id={id}>
      <header>
        <span>{index}</span>
        <div><p>{eyebrow}</p><h2>{title}</h2></div>
      </header>
      <div className="docs-section-body">{children}</div>
    </section>
  );
}

function FlowNode({ label, detail }: { label: string; detail: string }) {
  return <div className="flow-node"><strong>{label}</strong><span>{detail}</span></div>;
}

function FlowArrow({ label }: { label: string }) {
  return <div className="flow-arrow"><span>{label}</span><i /></div>;
}

function InfoCard({ title, children }: { title: string; children: React.ReactNode }) {
  return <article className="docs-card"><h3>{title}</h3>{children}</article>;
}

function Callout({ kind, title, children }: { kind: "note" | "warning"; title: string; children: React.ReactNode }) {
  return <aside className={`docs-callout ${kind}`}><strong>{title}</strong><p>{children}</p></aside>;
}

function Endpoint({ method, path, auth, description }: { method: string; path: string; auth: string; description: string }) {
  return (
    <div className="endpoint">
      <strong>{method}</strong>
      <code>{path}</code>
      <span>{auth}</span>
      <p>{description}</p>
    </div>
  );
}

function CodeBlock({ label, code }: { label: string; code: string }) {
  return (
    <figure className="docs-code">
      <figcaption><span>{label}</span><span>UTF-8 · JSON</span></figcaption>
      <pre><code>{code}</code></pre>
    </figure>
  );
}

function RuntimeRow({ label, cloud, physical }: { label: string; cloud: string; physical: string }) {
  return <div><strong>{label}</strong><span>{cloud}</span><span>{physical}</span></div>;
}
