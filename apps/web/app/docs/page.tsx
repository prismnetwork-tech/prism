import type { Metadata } from "next";
import { DeveloperDocs } from "@/components/developer-docs";
import { docsUrl } from "@/lib/site";

export const metadata: Metadata = {
  title: "Developer documentation",
  description: "Architecture, API, contracts, lifecycle, security, and operations documentation for Prism Network.",
  alternates: {
    canonical: docsUrl,
  },
  openGraph: {
    url: docsUrl,
    title: "Developer documentation · Prism Network",
    description: "Architecture, API, contracts, lifecycle, security, and operations documentation for Prism Network.",
  },
};

export default function DocsPage() {
  return <DeveloperDocs />;
}
