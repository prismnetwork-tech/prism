import Link from "next/link";
import { docsUrl, siteUrl } from "@/lib/site";

const escrowAddress = "0x4e599D47bA62c2Bb733D41625BF98d6cBbf2dF0f";

const columns = [
  {
    title: "Product",
    links: [
      ["Compute", new URL("/compute", siteUrl).href],
      ["Pricing", new URL("/pricing", siteUrl).href],
      ["Leases", new URL("/leases", siteUrl).href],
      ["Proof", new URL("/proof", siteUrl).href],
    ],
  },
  {
    title: "Providers",
    links: [
      ["Supply capacity", new URL("/nodes", siteUrl).href],
      ["Node fleet", new URL("/nodes", siteUrl).href],
      ["Earnings", new URL("/earnings", siteUrl).href],
      ["Runtime requirements", new URL("/#runtime", docsUrl).href],
    ],
  },
  {
    title: "Developers",
    links: [
      ["Documentation", docsUrl.href],
      ["API reference", new URL("/#api", docsUrl).href],
      ["Architecture", new URL("/#architecture", docsUrl).href],
      ["Security model", new URL("/#security", docsUrl).href],
      ["Source", "https://github.com/prismnetwork-tech/prism"],
    ],
  },
  {
    title: "Legal",
    links: [
      ["Terms", new URL("/terms", siteUrl).href],
      ["Privacy", new URL("/privacy", siteUrl).href],
      ["Security", new URL("/security", siteUrl).href],
    ],
  },
  {
    title: "Company",
    links: [
      ["About", new URL("/about", siteUrl).href],
      ["Contact", new URL("/contact", siteUrl).href],
      ["Follow on X", "https://x.com/useprismnetwork"],
      ["GitHub", "https://github.com/prismnetwork-tech"],
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
          <span>Robinhood Chain · L40S beta</span>
        </div>

        {columns.map((column) => (
          <nav key={column.title} aria-label={`${column.title} footer links`}>
            <h2>{column.title}</h2>
            {column.links.map(([label, href]) => {
              const external = href.startsWith("https://github.com") || href.startsWith("https://x.com");
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
        <p>© 2026 Prism Network. Open infrastructure, verifiable settlement.</p>
      </div>
    </footer>
  );
}
