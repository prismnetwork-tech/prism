import { describe, expect, it } from "vitest";
import { STRUCTURED_DATA_HASHES, contentSecurityPolicy, publicPageRewrite } from "./proxy";

describe("content security policy", () => {
  it("uses a nonce without allowing inline production scripts", () => {
    const policy = contentSecurityPolicy("abc123", false);

    expect(policy).toContain("'nonce-abc123'");
    expect(policy).toContain("'strict-dynamic'");
    // The JSON-LD block is allowed by hash so it can stay static; the nonce
    // still governs everything Next actually executes.
    for (const hash of STRUCTURED_DATA_HASHES) expect(policy).toContain(`'${hash}'`);
    expect(policy).not.toContain("'unsafe-eval'");
    expect(policy).not.toContain("script-src 'unsafe-inline'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain(
      "img-src 'self' data: blob: https://explorer-api.walletconnect.com",
    );
  });

  it("allows eval only for the development runtime", () => {
    expect(contentSecurityPolicy("abc123", true)).toContain("'unsafe-eval'");
  });

  it("serves documentation at the docs subdomain root", () => {
    expect(publicPageRewrite("docs.prismnetwork.tech", "/")).toBe("/docs");
    expect(publicPageRewrite("docs.prismnetwork.tech", "/api/healthz")).toBeNull();
    expect(publicPageRewrite("prismnetwork.tech", "/")).toBeNull();
  });
});
