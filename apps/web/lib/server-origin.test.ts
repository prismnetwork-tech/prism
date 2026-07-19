import { afterEach, describe, expect, it, vi } from "vitest";
import { isSameOriginRequest } from "./server-origin";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("same-origin enforcement", () => {
  it("accepts the configured application origin", () => {
    vi.stubEnv("PRISM_APP_ORIGIN", "https://app.prism.example");
    const headers = new Headers({ origin: "https://app.prism.example" });
    expect(isSameOriginRequest({ headers, nextUrl: new URL("http://internal:3000/api") })).toBe(true);
  });

  it("does not trust forwarded host headers", () => {
    vi.stubEnv("PRISM_APP_ORIGIN", "https://app.prism.example");
    const headers = new Headers({
      origin: "https://attacker.example",
      "x-forwarded-host": "attacker.example",
      "x-forwarded-proto": "https",
    });
    expect(isSameOriginRequest({ headers, nextUrl: new URL("http://internal:3000/api") })).toBe(false);
  });

  it("falls back to the request URL for local development", () => {
    const headers = new Headers({ origin: "http://localhost:3000" });
    expect(isSameOriginRequest({ headers, nextUrl: new URL("http://localhost:3000/api") })).toBe(true);
  });

  it("accepts same-origin browser requests without an Origin header", () => {
    const headers = new Headers({ "sec-fetch-site": "same-origin" });
    expect(isSameOriginRequest({ headers, nextUrl: new URL("http://localhost:3000/api") })).toBe(true);
  });

  it("rejects unattributed requests without an Origin header", () => {
    expect(isSameOriginRequest({
      headers: new Headers(),
      nextUrl: new URL("http://localhost:3000/api"),
    })).toBe(false);
  });

  it("fails closed without a configured production origin", () => {
    vi.stubEnv("NODE_ENV", "production");
    const headers = new Headers({ origin: "https://app.prism.example" });
    expect(isSameOriginRequest({ headers, nextUrl: new URL("https://app.prism.example/api") })).toBe(false);
  });
});
