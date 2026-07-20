import { afterEach, describe, expect, it } from "vitest";
import { GET } from "@/app/api/proof/route";

const originalSource = process.env.PRISM_PROOF_INDEX_URL;

afterEach(() => {
  if (originalSource === undefined) {
    delete process.env.PRISM_PROOF_INDEX_URL;
  } else {
    process.env.PRISM_PROOF_INDEX_URL = originalSource;
  }
});

describe("GET /api/proof", () => {
  it("returns an empty public feed before the first publisher is configured", async () => {
    delete process.env.PRISM_PROOF_INDEX_URL;

    const response = await GET();
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("public, max-age=30");
    expect(payload.receipts).toEqual([]);
    expect(Number.isNaN(Date.parse(payload.generated_at))).toBe(false);
  });

  it("reports an invalid configured publisher as unavailable", async () => {
    process.env.PRISM_PROOF_INDEX_URL = "not-a-url";

    const response = await GET();

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "proof_feed_unavailable" });
  });
});
