import { faqStructuredDataJson, structuredDataJson } from "@/lib/structured-data";

/// Rendered without a nonce on purpose: the CSP allows these exact blocks by
/// hash, so they stay static and do not opt their page into per-request
/// rendering.
function Block({ json }: { json: string }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: json }} />;
}

export function StructuredData() {
  return <Block json={structuredDataJson} />;
}

export function FaqStructuredData() {
  return <Block json={faqStructuredDataJson} />;
}
