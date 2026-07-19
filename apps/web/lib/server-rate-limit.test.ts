import { afterEach, describe, expect, it, vi } from "vitest";
import { consumeOneTime, registerOneTime, requestSubject, takeRateLimit } from "./server-rate-limit";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("server rate limiting", () => {
  it("enforces the development fallback window", async () => {
    const subject = `test-${Date.now()}`;
    const first = await takeRateLimit("test", subject, 2, 1_000, 10_000);
    const second = await takeRateLimit("test", subject, 2, 1_000, 10_001);
    const blocked = await takeRateLimit("test", subject, 2, 1_000, 10_002);
    const reset = await takeRateLimit("test", subject, 2, 1_000, 11_001);

    expect(first).toMatchObject({ allowed: true, available: true });
    expect(second.allowed).toBe(true);
    expect(blocked.allowed).toBe(false);
    expect(reset.allowed).toBe(true);
  });

  it("consumes a prepared authorization exactly once", async () => {
    const value = `authorization-${Date.now()}`;
    expect(await registerOneTime("test", value, 1_000)).toEqual({ available: true, stored: true });
    expect(await consumeOneTime("test", value)).toEqual({ available: true, consumed: true });
    expect(await consumeOneTime("test", value)).toEqual({ available: true, consumed: false });
  });

  it("ignores proxy headers unless the trusted edge header is configured", () => {
    const headers = new Headers({
      "cf-connecting-ip": "192.0.2.10",
      "x-forwarded-for": "198.51.100.20",
    });

    expect(requestSubject(headers)).toBe("unattributed");
    vi.stubEnv("PRISM_CLIENT_IP_HEADER", "cf-connecting-ip");
    expect(requestSubject(headers)).toBe("192.0.2.10");
  });

  it("rejects arbitrary client IP header names", () => {
    vi.stubEnv("PRISM_CLIENT_IP_HEADER", "x-client-ip");
    expect(requestSubject(new Headers({ "x-client-ip": "203.0.113.30" }))).toBe("unattributed");
  });
});
