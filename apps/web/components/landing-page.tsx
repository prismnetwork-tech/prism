import Link from "next/link";
import { HeroSignal } from "@/components/hero-signal";

const executionSteps = [
  ["01", "Fund", "Maximum lease cost is locked in USDG escrow before provisioning."],
  ["02", "Match", "Prism selects verified L40S capacity only while the upstream cost stays below its operating ceiling."],
  ["03", "Launch", "A fresh container-isolated workspace starts with temporary direct SSH access."],
  ["04", "Meter", "Billing begins only after GPU, cost and access endpoint admission checks pass."],
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
        <div className="landing-header-actions">
          <SocialLinks />
          <Link className="landing-console-link" href="/compute" aria-label="Open console">
            <span className="landing-console-label">Open console</span>
            <span aria-hidden="true">↗</span>
          </Link>
        </div>
      </header>

      <main id="main-content" tabIndex={-1}>
        <section className="landing-hero">
          <div className="hero-grid">
            <div className="landing-hero-copy">
              <p className="landing-kicker"><span /> L40S cloud beta</p>
              <h1>GPU compute,<br />settled by the second.</h1>
              <p>
                On-demand NVIDIA L40S workspaces at $0.80 per GPU hour, with metered USDG
                escrow, temporary access and a public settlement trail.
              </p>
              <div className="landing-actions">
                <Link className="landing-button primary" href="/compute">Find compute <span>↗</span></Link>
                <Link className="landing-button secondary" href="/nodes">Supply a node <span>＋</span></Link>
              </div>
            </div>
            <HeroSignal />
          </div>
          <div className="hero-status" role="status">
            <span><i /> L40S canary passed</span>
            <span>$0.80 / GPU hour</span>
            <span>Robinhood Chain · USDG</span>
          </div>
        </section>

        <section className="landing-section network-section" id="network">
          <div className="section-intro">
            <p className="section-index">01 / Network</p>
            <h2>One clear product.<br />One honest boundary.</h2>
            <p>
              The launch tier brokers verified cloud capacity. Permissionless hardware remains a
              separate supplier track until its stronger isolation path is ready.
            </p>
          </div>
          <div className="network-panels">
            <article className="network-panel renter-panel">
              <span className="panel-number">R / 01</span>
              <div>
                <p className="panel-label">L40S cloud beta</p>
                <h3>46 GB of GPU memory at $0.80/hour.</h3>
                <p>Launch an ephemeral container workspace with temporary direct SSH access. Capacity is offered only while a qualifying host is available.</p>
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
              <span>CLOUD HOST</span>
              <div className="security-frame middle-frame">
                <span>CONTAINER</span>
                <div className="security-frame inner-frame">
                  <span>GPU</span>
                  <strong>L40S</strong>
                </div>
              </div>
            </div>
            <div className="tunnel-line"><i /><span>TEMPORARY ACCESS</span></div>
          </div>
          <div className="security-copy">
            <p className="section-index">03 / Isolation</p>
            <h2>A clean workspace, not confidential compute.</h2>
            <p>
              Each cloud lease starts in a fresh container with temporary credentials. Workspace
              storage is destroyed when the instance closes, but the upstream host remains inside
              the trust boundary.
            </p>
            <div className="security-disclosure">
              <span>Important boundary</span>
              <p>Do not place private keys, production credentials or confidential data in a beta workspace. Container isolation is not hardware-backed confidential computing.</p>
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
        <p>On-demand L40S compute with metered USDG settlement.</p>
        <div className="landing-footer-links">
          <Link href="/proof">Proof</Link>
          <Link href="/settings">Settings</Link>
          <span>Private beta</span>
          <SocialLinks />
        </div>
      </footer>
    </div>
  );
}

function SocialLinks() {
  return (
    <nav className="landing-social-links" aria-label="Social links">
      <a
        className="landing-social-link"
        href="https://x.com/useprismnetwork"
        target="_blank"
        rel="noopener noreferrer"
        aria-label="Prism on X"
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817-5.966 6.817H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231 5.45-6.231Zm-1.161 17.52h1.833L7.084 4.126H5.117L17.083 19.77Z" />
        </svg>
      </a>
      <a
        className="landing-social-link"
        href="https://github.com/prismnetwork-tech"
        target="_blank"
        rel="noopener noreferrer"
        aria-label="Prism on GitHub"
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            fillRule="evenodd"
            clipRule="evenodd"
            d="M12 .7a11.3 11.3 0 0 0-3.57 22.03c.57.1.77-.25.77-.55v-2.16c-3.15.68-3.81-1.34-3.81-1.34-.52-1.34-1.28-1.7-1.28-1.7-1.04-.72.08-.7.08-.7 1.15.08 1.75 1.18 1.75 1.18 1.03 1.75 2.69 1.25 3.34.96.1-.74.4-1.25.73-1.54-2.51-.29-5.16-1.26-5.16-5.59 0-1.23.44-2.24 1.17-3.03-.12-.29-.51-1.44.11-2.99 0 0 .96-.31 3.11 1.16a10.8 10.8 0 0 1 5.67 0c2.16-1.47 3.11-1.16 3.11-1.16.62 1.55.23 2.7.11 2.99.73.79 1.17 1.8 1.17 3.03 0 4.34-2.65 5.29-5.17 5.58.41.35.77 1.04.77 2.1v3.11c0 .3.21.66.78.55A11.3 11.3 0 0 0 12 .7Z"
          />
        </svg>
      </a>
    </nav>
  );
}
