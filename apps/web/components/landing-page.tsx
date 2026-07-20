import Link from "next/link";
import { HeroSignal } from "@/components/hero-signal";

const executionSteps = [
  ["01", "Fund", "Maximum lease cost is locked in USDG escrow before provisioning."],
  ["02", "Match", "Compatible independent nodes are ranked by price, performance and reliability."],
  ["03", "Launch", "The GPU enters an isolated Kata VM-backed workspace with temporary access."],
  ["04", "Meter", "Billing begins only after CUDA and interactive access are confirmed ready."],
  ["05", "Settle", "Confirmed runtime becomes an onchain proposal, refund and public receipt."],
] as const;

export function LandingPage() {
  return (
    <div className="landing-page">
      <header className="landing-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="36" height="36" />
          <span>prism.</span>
        </Link>
        <nav className="landing-nav" aria-label="Landing navigation">
          <a href="#network">Network</a>
          <a href="#security">Security</a>
          <a href="#settlement">Settlement</a>
          <Link href="/proof">Proof</Link>
        </nav>
        <Link className="landing-console-link" href="/compute">
          Open console
          <span aria-hidden="true">↗</span>
        </Link>
      </header>

      <main id="main-content" tabIndex={-1}>
        <section className="landing-hero">
          <div className="hero-grid">
            <div className="landing-hero-copy">
              <p className="landing-kicker"><span /> Independent GPU infrastructure</p>
              <h1>GPU compute,<br />settled by the second.</h1>
              <p>
                Prism connects renters to independent NVIDIA capacity through isolated workspaces,
                metered USDG escrow and a public settlement trail.
              </p>
              <div className="landing-actions">
                <Link className="landing-button primary" href="/compute">Find compute <span>↗</span></Link>
                <Link className="landing-button secondary" href="/nodes">Supply a node <span>＋</span></Link>
              </div>
            </div>
            <HeroSignal />
          </div>
          <div className="hero-status" role="status">
            <span><i /> Private beta</span>
            <span>Hardware validation in progress</span>
            <span>Robinhood Chain · USDG</span>
          </div>
        </section>

        <section className="landing-section network-section" id="network">
          <div className="section-intro">
            <p className="section-index">01 / Network</p>
            <h2>Direct access.<br />No black-box meter.</h2>
            <p>
              Raw GPU workspaces come first. Batch containers and managed inference build on the
              same node identity, access and settlement lifecycle.
            </p>
          </div>
          <div className="network-panels">
            <article className="network-panel renter-panel">
              <span className="panel-number">R / 01</span>
              <div>
                <p className="panel-label">Rent compute</p>
                <h3>Launch an isolated NVIDIA workspace.</h3>
                <p>Choose a compatible public OCI image, fund the maximum lease and connect through temporary SSH or Jupyter credentials.</p>
              </div>
              <Link href="/compute">Explore compute <span>↗</span></Link>
            </article>
            <article className="network-panel supplier-panel">
              <span className="panel-number">S / 02</span>
              <div>
                <p className="panel-label">Supply capacity</p>
                <h3>Put independent hardware on the network.</h3>
                <p>Enroll an NVIDIA host, publish a signed offer and receive 90% of confirmed usage after settlement.</p>
              </div>
              <Link href="/nodes">Review requirements <span>↗</span></Link>
            </article>
          </div>
        </section>

        <section className="landing-section settlement-section" id="settlement">
          <div className="section-intro compact">
            <p className="section-index">02 / Settlement</p>
            <h2>One measurable<br />execution path.</h2>
          </div>
          <div className="execution-list">
            {executionSteps.map(([number, title, description]) => (
              <article className="execution-step" key={number}>
                <span>{number}</span>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-section security-section" id="security">
          <div className="security-visual" aria-hidden="true">
            <div className="security-frame outer-frame">
              <span>HOST</span>
              <div className="security-frame middle-frame">
                <span>KATA VM</span>
                <div className="security-frame inner-frame">
                  <span>GPU</span>
                  <strong>VFIO</strong>
                </div>
              </div>
            </div>
            <div className="tunnel-line"><i /><span>OUTBOUND mTLS</span></div>
          </div>
          <div className="security-copy">
            <p className="section-index">03 / Isolation</p>
            <h2>Built around a hostile boundary.</h2>
            <p>
              Each lease receives exclusive GPU passthrough into a VM-backed container. Supplier
              addresses stay private, workspace keys are temporary and host egress policy blocks
              private networks and metadata endpoints.
            </p>
            <div className="security-disclosure">
              <span>Important boundary</span>
              <p>Permissionless suppliers are not trusted computing environments. Prism rejects confidential and sensitive workloads until independently attestable confidential-GPU nodes exist.</p>
            </div>
          </div>
        </section>

        <section className="landing-section proof-section">
          <div className="proof-copy">
            <p className="section-index">04 / Proof</p>
            <h2>Settlement leaves<br />a public trace.</h2>
            <p>
              Finalized receipts connect platform-attested usage records to Robinhood Chain
              settlement events without exposing terminal contents, notebooks or files.
            </p>
            <Link className="landing-button secondary" href="/proof">Open proof feed <span>↗</span></Link>
          </div>
          <div className="receipt-terminal">
            <div className="terminal-bar">
              <span>SETTLEMENT RECEIPT</span>
              <span>AWAITING MAINNET CANARY</span>
            </div>
            <dl>
              <div><dt>STATUS</dt><dd>NO FINALIZED RECEIPTS</dd></div>
              <div><dt>GPU MODEL</dt><dd>—</dd></div>
              <div><dt>RUNTIME</dt><dd>—</dd></div>
              <div><dt>USDG SETTLED</dt><dd>—</dd></div>
              <div><dt>TRANSACTION</dt><dd>—</dd></div>
            </dl>
            <div className="terminal-cursor"><span /> Waiting for verified network activity</div>
          </div>
        </section>

        <section className="landing-cta">
          <p>GPU infrastructure should account for every second.</p>
          <h2>Enter the network.</h2>
          <div>
            <Link className="landing-button primary" href="/compute">Find compute <span>↗</span></Link>
            <Link className="landing-button secondary" href="/nodes">Supply a node <span>＋</span></Link>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <Link className="landing-brand" href="/">
          <img src="/brand/prism-logo.svg" alt="" width="30" height="30" />
          <span>prism.</span>
        </Link>
        <p>Independent GPU infrastructure with metered USDG settlement.</p>
        <div>
          <Link href="/proof">Proof</Link>
          <Link href="/settings">Settings</Link>
          <span>Private beta</span>
        </div>
      </footer>
    </div>
  );
}
