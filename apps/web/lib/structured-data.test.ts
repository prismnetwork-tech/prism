import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { STRUCTURED_DATA_HASHES } from "@/proxy";
import { faqStructuredDataJson, structuredDataJson } from "@/lib/structured-data";

describe("structured data", () => {
  // A stale hash does not error anywhere: the browser drops the block and the
  // markup silently stops existing. Recompute it here so editing the graph
  // fails the build instead.
  it.each([
    ["site", structuredDataJson],
    ["faq", faqStructuredDataJson],
  ])("the %s block is allowed by a hash the CSP actually sends", (_name, json) => {
    const digest = createHash("sha256").update(json, "utf8").digest("base64");

    expect(STRUCTURED_DATA_HASHES).toContain(`sha256-${digest}`);
  });

  it("describes the site without claiming more than it does", () => {
    const graph = JSON.parse(structuredDataJson)["@graph"];
    const types = graph.map((node: { "@type": string }) => node["@type"]);

    expect(types).toEqual(["Organization", "WebSite", "SoftwareApplication"]);

    const organization = graph[0];
    expect(organization.name).toBe("prism.");
    expect(organization.url).toMatch(/^https?:\/\//);

    // The price is quoted on /pricing; structured data that disagrees with the
    // page is the version search engines repeat.
    const offer = graph[2].offers;
    expect(offer.price).toBe("0.80");
    expect(offer.priceCurrency).toBe("USD");
  });

  it("renders as a single parseable block", () => {
    expect(() => JSON.parse(structuredDataJson)).not.toThrow();
    expect(structuredDataJson).not.toContain("</script>");
  });
});
