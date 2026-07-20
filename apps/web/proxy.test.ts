import { describe, expect, it } from "vitest";
import { contentSecurityPolicy, publicPageRewrite } from "./proxy";

describe("content security policy", () => {
  it("uses a nonce without allowing inline production scripts", () => {
    const policy = contentSecurityPolicy("abc123", false);

    expect(policy).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
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
