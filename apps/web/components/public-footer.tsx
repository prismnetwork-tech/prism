import Link from "next/link";
import { docsUrl, siteUrl } from "@/lib/site";

const escrowAddress = "0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD";

const columns = [
  {
    title: "Product",
    links: [
      ["Compute", new URL("/compute", siteUrl).href, false],
      ["Pricing", new URL("/pricing", siteUrl).href, false],
      ["Leases", new URL("/leases", siteUrl).href, false],
      ["Proof", new URL("/proof", siteUrl).href, false],
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
      ["API reference", new URL("/#api", docsUrl).href, false],
      ["Architecture", new URL("/#architecture", docsUrl).href, false],
      ["Security model", new URL("/#security", docsUrl).href, false],
      ["Source", "https://github.com/prismnetwork-tech/prism", true],
    ],
  },
  {
    title: "Legal",
    links: [
      ["Terms", new URL("/terms", siteUrl).href, false],
      ["Privacy", new URL("/privacy", siteUrl).href, false],
      ["Security", new URL("/security", siteUrl).href, false],
    ],
  },
  {
    title: "Company",
    links: [
      ["About", new URL("/about", siteUrl).href, false],
      ["Contact", new URL("/contact", siteUrl).href, false],
      ["Follow on X", "https://x.com/useprismnetwork", true],
      ["GitHub", "https://github.com/prismnetwork-tech", true],
    ],
  },
] as const;

export function PublicFooter() {
  const explorerUrl = `https://robinhoodchain.blockscout.com/address/${escrowAddress}`;

  return (
    <footer className="public-footer">
      <div className="public-footer-grid">
        <div className="public-footer-brand">
          <Link className="landing-brand" href={siteUrl.href} aria-label="prism. home">
            <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
            <span>prism.</span>
          </Link>
          <p>Metered GPU compute with USDG escrow and public settlement proof.</p>
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
        <div className="public-footer-contract">
          <span>Lease escrow</span>
          <a href={explorerUrl} target="_blank" rel="noopener noreferrer">
            <code>{escrowAddress}</code>
            <span>View on Blockscout ↗</span>
          </a>
        </div>
        <p>© 2026 Prism Network. All rights reserved.</p>
      </div>
    </footer>
  );
}
