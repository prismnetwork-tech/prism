import { headers } from "next/headers";
import { docsUrl, siteUrl } from "@/lib/site";

// Every claim here has to match the site. Structured data that overstates
// availability or price is worse than none: it is the version search engines
// quote back, and we cannot correct it once it is indexed.
function graph() {
  const organization = {
    "@type": "Organization",
    "@id": `${siteUrl.origin}/#organization`,
    name: "prism.",
    alternateName: "Prism Network",
    url: siteUrl.origin,
    logo: `${siteUrl.origin}/brand/prism-logo.svg`,
    description:
      "Open infrastructure for metered GPU compute. Agents rent NVIDIA capacity with a wallet and settle onchain.",
    sameAs: [
      "https://x.com/useprismnetwork",
      "https://github.com/prismnetwork-tech",
    ],
  };

  const website = {
    "@type": "WebSite",
    "@id": `${siteUrl.origin}/#website`,
    url: siteUrl.origin,
    name: "prism.",
    publisher: { "@id": `${siteUrl.origin}/#organization` },
    inLanguage: "en",
  };

  const service = {
    "@type": "SoftwareApplication",
    "@id": `${siteUrl.origin}/#service`,
    name: "prism.",
    applicationCategory: "DeveloperApplication",
    applicationSubCategory: "GPU compute",
    operatingSystem: "Linux",
    url: siteUrl.origin,
    publisher: { "@id": `${siteUrl.origin}/#organization` },
    softwareHelp: docsUrl.href,
    description:
      "Lease NVIDIA GPU capacity per second, pay in USDG, and settle every lease onchain with a public receipt.",
    offers: {
      "@type": "Offer",
      price: "0.80",
      priceCurrency: "USD",
      // Per GPU hour, the rate published on the site.
      unitText: "GPU hour",
      availability: "https://schema.org/InStock",
      url: `${siteUrl.origin}/pricing`,
    },
  };

  return { "@context": "https://schema.org", "@graph": [organization, website, service] };
}

/// Inline JSON-LD is still subject to script-src, so it carries the nonce the
/// middleware issued. Without it the block is dropped and the markup silently
/// does nothing.
export async function StructuredData() {
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <script
      type="application/ld+json"
      nonce={nonce}
      dangerouslySetInnerHTML={{ __html: JSON.stringify(graph()) }}
    />
  );
}
