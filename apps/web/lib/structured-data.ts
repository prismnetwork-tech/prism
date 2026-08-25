import { faq } from "@/lib/faq";
import { docsUrl, siteUrl } from "@/lib/site";

// Every claim here has to match the site. Structured data that overstates
// availability or price is worse than none: it is the version search engines
// quote back, and we cannot correct it once it is indexed.
function graph() {
  const origin = siteUrl.origin;

  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${origin}/#organization`,
        name: "prism.",
        alternateName: "Prism Network",
        url: origin,
        logo: `${origin}/brand/prism-logo.svg`,
        description:
          "Open infrastructure for metered GPU compute. Agents rent NVIDIA capacity with a wallet and settle onchain.",
        sameAs: ["https://x.com/useprismnetwork", "https://github.com/winter0x"],
      },
      {
        "@type": "WebSite",
        "@id": `${origin}/#website`,
        url: origin,
        name: "prism.",
        publisher: { "@id": `${origin}/#organization` },
        inLanguage: "en",
      },
      {
        "@type": "SoftwareApplication",
        "@id": `${origin}/#service`,
        name: "prism.",
        applicationCategory: "DeveloperApplication",
        applicationSubCategory: "GPU compute",
        operatingSystem: "Linux",
        url: origin,
        publisher: { "@id": `${origin}/#organization` },
        softwareHelp: docsUrl.href,
        description:
          "Lease NVIDIA GPU capacity per second, pay in USDG, and settle every lease onchain with a public receipt.",
        offers: {
          "@type": "Offer",
          price: "0.80",
          priceCurrency: "USD",
          unitText: "GPU hour",
          availability: "https://schema.org/InStock",
          url: `${origin}/pricing`,
        },
      },
    ],
  };
}

/// The exact bytes rendered into the page. The CSP allows these blocks by hash,
/// so the string a component prints and the string the hash was taken over have
/// to be the same one, not two that happen to agree today.
export const structuredDataJson = JSON.stringify(graph());

export const faqStructuredDataJson = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "@id": `${siteUrl.origin}/faq#faq`,
  isPartOf: { "@id": `${siteUrl.origin}/#website` },
  mainEntity: faq.map((entry) => ({
    "@type": "Question",
    name: entry.question,
    acceptedAnswer: { "@type": "Answer", text: entry.answer },
  })),
});
