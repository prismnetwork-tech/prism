import Link from "next/link";
import { docsUrl, siteUrl } from "@/lib/site";

const escrowAddress = "0x62C042265991bEa17B07229322A01850974626dA";
const tokenAddress = "0x0A1e0Cc751f77C2C93760FC957CC8E4E779b2bC8";

const explorer = (address: string) =>
  `https://robinhoodchain.blockscout.com/address/${address}`;

// Both live on Robinhood Chain, and the address is the only thing that tells a
// reader which token is actually ours. Publish it where they already are.
const contracts = [
  ["$PRISM", tokenAddress],
  ["Lease escrow", escrowAddress],
] as const;

const columns = [
  {
    title: "Product",
    links: [
      ["Compute", new URL("/compute", siteUrl).href, false],
      ["Pricing", new URL("/pricing", siteUrl).href, false],
      ["Leases", new URL("/leases", siteUrl).href, false],
      ["Activity", new URL("/activity", siteUrl).href, false],
      ["Receipts", new URL("/proof", siteUrl).href, false],
      ["Network", new URL("/network", siteUrl).href, false],
    ],
  },
  {
    title: "Providers",
    links: [
      ["Supply capacity", new URL("/nodes", siteUrl).href, false],
      ["Node fleet", new URL("/nodes", siteUrl).href, false],
      ["Earnings", new URL("/earnings", siteUrl).href, false],
      ["Runtime requirements", new URL("/#runtime", docsUrl).href, false],
    ],
  },
  {
    title: "Developers",
    links: [
      ["Documentation", docsUrl.href, false],
      ["Learn", new URL("/learn", siteUrl).href, false],
      ["Questions", new URL("/faq", siteUrl).href, false],
      ["API reference", new URL("/#api", docsUrl).href, false],
      ["Architecture", new URL("/#architecture", docsUrl).href, false],
      ["Security model", new URL("/#security", docsUrl).href, false],
      ["Source", "https://github.com/winter0x/prism", true],
    ],
  },
  {
    title: "Legal",
    links: [
      ["Terms", new URL("/terms", siteUrl).href, false],
      ["Privacy", new URL("/privacy", siteUrl).href, false],
      ["Security", new URL("/security", siteUrl).href, false],
      ["Status", new URL("/status", siteUrl).href, false],
    ],
  },
  {
    title: "Company",
    links: [
      ["About", new URL("/about", siteUrl).href, false],
      ["Roadmap", new URL("/roadmap", siteUrl).href, false],
      ["Contact", new URL("/contact", siteUrl).href, false],
      ["Follow on X", "https://x.com/useprismnetwork", true],
      ["GitHub", "https://github.com/winter0x", true],
    ],
  },
] as const;

export function PublicFooter() {
  return (
    <footer className="public-footer">
      <div className="public-footer-grid">
        <div className="public-footer-brand">
          <Link className="landing-brand" href={siteUrl.href} aria-label="prism. home">
            <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
            <span>prism.</span>
          </Link>
          <p>Metered GPU compute for autonomous agents, rented with a wallet.</p>
          <span>Live · Robinhood Chain · L40S</span>
        </div>

        {columns.map((column) => (
          <nav key={column.title} aria-label={`${column.title} footer links`}>
            <h2>{column.title}</h2>
            {column.links.map(([label, href, external]) => {
              return external ? (
                <a href={href} key={label} target="_blank" rel="noopener noreferrer">{label}</a>
              ) : (
                <Link href={href} key={label}>{label}</Link>
              );
            })}
          </nav>
        ))}
      </div>

      <div className="public-footer-bottom">
        <div className="public-footer-contracts">
          {contracts.map(([label, address]) => (
            <div className="public-footer-contract" key={label}>
              <span>{label}</span>
              <a href={explorer(address)} target="_blank" rel="noopener noreferrer">
                <code>{address}</code>
                <span>View on Blockscout ↗</span>
              </a>
            </div>
          ))}
        </div>
        <p>© 2026 Prism Network. All rights reserved.</p>
      </div>
    </footer>
  );
}
