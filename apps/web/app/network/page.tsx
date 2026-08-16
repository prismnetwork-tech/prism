import type { Metadata } from "next";
import Link from "next/link";
import { NetworkMetrics } from "@/components/network-metrics";
import { PublicFooter } from "@/components/public-footer";
import { docsUrl } from "@/lib/site";
import "./network.css";

export const metadata: Metadata = {
  title: "Network",
  description:
    "What Prism Network has settled and what it can rent right now: GPU hours served, USDG charged and paid to suppliers, refunds, and live capacity by GPU.",
  alternates: { canonical: "/network" },
};

export default function NetworkPage() {
  return (
    <div className="information-page">
      <header className="information-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Public page navigation">
          <Link href="/pricing">Pricing</Link>
          <Link href={docsUrl.href}>Docs</Link>
          <Link className="information-console-link" href="/compute">Open console ↗</Link>
        </nav>
      </header>

      <main className="network-main" id="main-content" tabIndex={-1}>
        <section className="network-hero">
          <p>Network</p>
          <h1>What the network has actually done.</h1>
          <p>
            Every settled figure on this page is the sum of amounts written into settlement transactions on Robinhood
            Chain, read from the same public feed behind the <Link href="/proof">receipts page</Link>. Capacity is what
            the marketplace is advertising right now. Nothing here is an internal counter.
          </p>
        </section>
        <NetworkMetrics />
      </main>

      <PublicFooter />
    </div>
  );
}
