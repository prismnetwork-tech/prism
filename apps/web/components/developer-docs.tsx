import Link from "next/link";

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
] as const;

const contracts = [
  ["USDG", "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168", "6 decimals"],
  ["NodeRegistryV1", "0xBf83714Ff5d524FA5CD9bdF24495540e979426d7", "Supplier bonds and offers"],
  ["LeaseEscrowV1", "0x4e599D47bA62c2Bb733D41625BF98d6cBbf2dF0f", "Lease funding and settlement"],
  ["AdminTimelockV1", "0x22e2868dCe0E28fb266C5C5BC018Da3145307BBD", "48-hour configuration delay"],
  ["Governance Safe", "0xAF1113cE9E65D79daA87005A729Ab9Bc1A9fc60a", "Emergency and dispute authority"],
] as const;

const states = [
  ["funded", "Escrow event confirmed and associated with a five-minute quote."],
  ["provisioning", "Provider allocation or signed physical-node launch is in progress."],
  ["ready", "GPU and access admission checks passed; access start is pending finality."],
  ["active", "Billable access is available to the authenticated renter."],
  ["closing", "Credentials are revoked and the runtime is being destroyed."],
  ["settlement_pending", "Usage evidence has produced an onchain settlement proposal."],
  ["disputed", "Finalization is blocked pending Safe-controlled resolution."],
  ["finalized", "Provider payment, platform fee, and renter refund are terminal."],
  ["refunded", "The lease ended without a provider charge."],
  ["failed", "Provisioning failed before a terminal onchain transition was indexed."],
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
  ["503", "service_unavailable", "An identity, rate-limit, control-plane, or upstream dependency is unavailable."],
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

export function DeveloperDocs() {
  return (
    <div className="docs-page">
      <header className="docs-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Documentation header">
          <a href="https://github.com/prismnetwork-tech/prism" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <Link href="/proof">Proof</Link>
          <Link className="docs-console-link" href="/compute">Open console ↗</Link>
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
            <span>Stage</span><strong>Beta</strong>
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
              <div><dt>Execution</dt><dd>L40S cloud beta</dd></div>
              <div><dt>Settlement</dt><dd>Robinhood Chain + USDG</dd></div>
              <div><dt>Access</dt><dd>Temporary, key-only SSH</dd></div>
              <div><dt>Billing unit</dt><dd>Confirmed runtime second</dd></div>
            </dl>
          </section>

          <DocsSection id="architecture" index="01" eyebrow="System model" title="Architecture">
            <p>
              The public web application is the identity boundary. It verifies Privy access
              tokens, establishes an HTTP-only same-origin session, rate-limits requests, and
              signs internal control-plane identity assertions. Browsers never receive the
              control-plane HMAC key, settlement keys, device keys, or Vast credentials.
            </p>
            <div className="architecture-flow" aria-label="Prism request architecture">
              <FlowNode label="Browser" detail="Privy + wallet" />
              <FlowArrow label="HTTPS" />
              <FlowNode label="Web boundary" detail="Session + rate limit" />
              <FlowArrow label="Signed identity" />
              <FlowNode label="Control plane" detail="Quote + lifecycle state" />
              <FlowArrow label="Durable jobs" />
              <FlowNode label="Workers" detail="Provider + chain" />
            </div>
            <div className="docs-grid two">
              <InfoCard title="Data plane">
                <p>Cloud beta leases receive a direct Vast SSH endpoint. Physical-node leases use revocable gateway grants over outbound mTLS tunnels.</p>
              </InfoCard>
              <InfoCard title="Control plane">
                <p>PostgreSQL is authoritative for accounts, quotes, provider instances, transaction outboxes, lease transitions, and proof publication jobs.</p>
              </InfoCard>
              <InfoCard title="Settlement plane">
                <p>Robinhood Chain contracts enforce escrow limits, active-lease bounds, dispute timing, provider payment, platform fees, and refunds.</p>
              </InfoCard>
              <InfoCard title="Governance plane">
                <p>A two-owner Safe controls routine changes through a 48-hour timelock. Emergency pause and dispute resolution remain immediate Safe actions.</p>
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
            <Callout kind="warning" title="Beta workload boundary">
              Do not place private keys, production credentials, regulated data, confidential
              datasets, or valuable model weights inside a beta workspace. Provider operators
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
              <InfoCard title="Server-to-server clients">
                <p>A public API-key product is not currently issued. Do not automate by copying browser cookies or reproducing internal identity headers. Dedicated service credentials require a separate supported integration.</p>
              </InfoCard>
            </div>
            <Callout kind="note" title="Internal headers are not an API">
              <code>X-Prism-Subject</code>, <code>X-Prism-Session-Id</code>, timestamp, and
              signature headers are generated only by the web identity boundary. Treat them as
              private protocol internals.
            </Callout>
          </DocsSection>

          <DocsSection id="api" index="04" eyebrow="Same-origin application API" title="HTTP API">
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
              Unused escrow is returned during terminal settlement or refund.
            </Callout>
          </DocsSection>

          <DocsSection id="lifecycle" index="06" eyebrow="Durable state machine" title="Lease lifecycle">
            <div className="state-list">
              {states.map(([state, description]) => (
                <div key={state}><code>{state}</code><p>{description}</p></div>
              ))}
            </div>
            <p>
              Transitions are idempotent and persisted before external side effects. Provider
              instance IDs, chain transaction bytes, nonces, hashes, confirmation blocks, and
              terminal evidence survive worker restarts. A ten-minute provision timeout is the
              refund boundary for leases that never reach billable access.
            </p>
          </DocsSection>

          <DocsSection id="runtime" index="07" eyebrow="Execution environments" title="Runtime modes">
            <div className="runtime-table">
              <div className="runtime-head"><span>Property</span><span>Cloud beta</span><span>Physical supplier track</span></div>
              <RuntimeRow label="Capacity" cloud="Verified Vast L40S below cost ceiling" physical="Bonded operator-owned NVIDIA host" />
              <RuntimeRow label="Isolation" cloud="Disposable provider container" physical="Kata sandbox with VFIO GPU assignment" />
              <RuntimeRow label="Access" cloud="Temporary direct root SSH" physical="Revocable SSH/Jupyter grant via mTLS gateway" />
              <RuntimeRow label="Readiness" cloud="Provider state, GPU, VRAM, cost, SSH endpoint" physical="Signed telemetry plus independent active gateway probes" />
              <RuntimeRow label="Evidence" cloud="Provider instance and hourly cost" physical="Device-signed telemetry and gateway timing" />
              <RuntimeRow label="Launch status" cloud="Initial L40S product path" physical="Release-gated pending hardware matrix" />
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
            <Callout kind="warning" title="Unaudited beta">
              The deployed contracts are operational beta software and have not completed an
              independent production audit. Verify contract addresses, bytecode, constructor
              inputs, and current pause state directly before building a financial dependency.
            </Callout>
          </DocsSection>

          <DocsSection id="settlement" index="09" eyebrow="Usage accounting" title="Settlement and proof">
            <p>
              Billing begins only after the configured gateway authority confirms runtime and
              access readiness onchain. Closing revokes access first, destroys the execution
              environment, and then assembles bounded usage evidence.
            </p>
            <ol className="docs-steps compact">
              <li><span>01</span><div><h3>Observe</h3><p>Clamp confirmed runtime to the funded duration and preserve provider or physical-node execution evidence.</p></div></li>
              <li><span>02</span><div><h3>Propose</h3><p>Submit an EIP-712 settlement carrying usage seconds, receipt hash, nonce, and deadline.</p></div></li>
              <li><span>03</span><div><h3>Dispute</h3><p>Hold finalization for 24 hours. A renter can dispute; the governance Safe resolves disputed outcomes.</p></div></li>
              <li><span>04</span><div><h3>Finalize</h3><p>Pay 90% of the charge to the provider, route the 10% platform fee, and refund unused escrow.</p></div></li>
              <li><span>05</span><div><h3>Publish</h3><p>Verify the terminal chain event and expose a sanitized, canonical receipt in the public proof feed.</p></div></li>
            </ol>
            <p>
              Public receipts omit renter/provider wallet addresses, precise geography, image
              digests, terminal output, files, and private telemetry. Proof establishes a
              platform-attested usage record paired with an onchain terminal event; it does not
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
                  <li>Durable chain outboxes with reorg-aware confirmation.</li>
                </ul>
              </InfoCard>
              <InfoCard title="Not guaranteed">
                <ul>
                  <li>Host confidentiality or trusted execution.</li>
                  <li>Protection from a malicious provider operator.</li>
                  <li>Durable workspace storage.</li>
                  <li>Uninterrupted upstream provider availability.</li>
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
                <p>Provider launches reconcile by a unique lease label. Chain submissions persist signed bytes before broadcast. Workers retry from durable state and refuse conflicting terminal transitions.</p>
              </InfoCard>
              <InfoCard title="Capacity admission">
                <p>The cloud broker advertises one concurrent L40S only while a verified, rentable offer satisfies model, VRAM, reliability, and upstream hourly-cost bounds.</p>
              </InfoCard>
              <InfoCard title="Failure containment">
                <p>Provision failures close or refund rather than starting billing. Destruction is retried before terminal settlement. Emergency pause blocks new leases without blocking existing refunds.</p>
              </InfoCard>
              <InfoCard title="Observability">
                <p>Use the response request ID to correlate web, control-plane, provider, and chain records. Public proof publication remains decoupled from financial settlement.</p>
              </InfoCard>
            </div>
            <h3 className="docs-subheading">Launch gate</h3>
            <p>
              Public capacity remains gated until a funded mainnet canary completes quote,
              funding, provisioning, GPU/access admission, teardown, settlement, refund/payment,
              and proof verification. A failed stage must preserve evidence and return escrow to
              a paused state before another public attempt.
            </p>
          </DocsSection>

          <DocsSection id="errors" index="12" eyebrow="Failure contract" title="Errors and retries">
            <div className="error-table">
              <div className="error-head"><span>HTTP</span><span>Code</span><span>Meaning</span></div>
              {errors.map(([status, code, meaning]) => (
                <div key={code}><strong>{status}</strong><code>{code}</code><p>{meaning}</p></div>
              ))}
            </div>
            <ul className="docs-list">
              <li>Retry <code>429</code> only after <code>Retry-After</code>.</li>
              <li>Retry transient <code>503</code> responses with bounded exponential backoff and the same business intent.</li>
              <li>Do not blindly replay funding transactions; first query the wallet receipt and account leases.</li>
              <li><code>funding_not_final</code> is expected before the required confirmation threshold and can be polled safely.</li>
              <li>Treat other <code>4xx</code> responses as terminal until the request or account state changes.</li>
            </ul>
          </DocsSection>

          <footer className="docs-footer">
            <div>
              <strong>Prism Network developer documentation</strong>
              <p>Source-aligned reference for the current beta protocol.</p>
            </div>
            <nav aria-label="Documentation footer">
              <Link href="/">Home</Link>
              <Link href="/compute">Console</Link>
              <Link href="/proof">Proof</Link>
              <a href="https://github.com/prismnetwork-tech/prism" target="_blank" rel="noopener noreferrer">Source ↗</a>
            </nav>
          </footer>
        </main>
      </div>
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
