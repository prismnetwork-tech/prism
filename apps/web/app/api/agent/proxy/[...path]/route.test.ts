import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/agent-auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/agent-auth")>("@/lib/agent-auth");
  return { ...actual, verifySession: vi.fn(async () => ({ subject: "wallet:0xa", sessionId: "s1" })) };
});

vi.mock("@/lib/server-rate-limit", () => ({
  takeRateLimit: vi.fn(async () => ({ available: true, allowed: true })),
}));

vi.mock("@/lib/control-plane", async () => {
  const actual = await vi.importActual<typeof import("@/lib/control-plane")>("@/lib/control-plane");
  return {
    ...actual,
    hmacControlIdentity: vi.fn(() => ({
      subject: "wallet:0xa",
      sessionId: "s1",
      timestamp: "1",
      signature: "sig",
    })),
  };
});

const { DELETE, GET, POST, PUT } = await import("./route");

const context = (path: string[]) => ({ params: Promise.resolve({ path }) });
const upstream = () => new Response(JSON.stringify({ ok: true }), { status: 200 });

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  process.env.PRISM_API_BASE_URL = "https://control.test";
  fetchMock = vi.fn(async () => upstream());
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function request(method: string, url: string, init: RequestInit = {}) {
  return new NextRequest(url, {
    method,
    headers: { authorization: "Bearer token", ...(init.headers as Record<string, string>) },
    body: init.body,
  });
}

describe("agent proxy route allowlist", () => {
  it("forwards the renter surface, including the vault", async () => {
    const response = await GET(
      request("GET", "https://prism.test/api/agent/proxy/vault/items"),
      context(["vault", "items"]),
    );

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0][0])).toBe("https://control.test/v1/vault/items");
  });

  it("still refuses operator, node and supplier routes", async () => {
    for (const route of ["operator", "nodes", "supplier", "gateway"]) {
      const response = await GET(
        request("GET", `https://prism.test/api/agent/proxy/${route}/x`),
        context([route, "x"]),
      );
      expect(response.status, route).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("agent proxy request bodies", () => {
  it("accepts a bodyless DELETE, which has no content type to declare", async () => {
    const response = await DELETE(
      request("DELETE", "https://prism.test/api/agent/proxy/vault/items/abc"),
      context(["vault", "items", "abc"]),
    );

    expect(response.status).toBe(200);
    expect(fetchMock.mock.calls[0][1]?.body?.byteLength).toBe(0);
  });

  it("still rejects a non-JSON body", async () => {
    const response = await PUT(
      request("PUT", "https://prism.test/api/agent/proxy/vault/items/abc", {
        headers: { "content-type": "text/plain" },
        body: "not json",
      }),
      context(["vault", "items", "abc"]),
    );

    expect(response.status).toBe(415);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // The size cap has to hold on the bytes actually read, not on a header a
  // client controls, or a chunked body would walk straight past it.
  it("rejects an oversized body that understates its content-length", async () => {
    const response = await POST(
      request("POST", "https://prism.test/api/agent/proxy/vault/items/abc/release", {
        headers: { "content-type": "application/json", "content-length": "2" },
        body: "x".repeat(256 * 1024 + 1),
      }),
      context(["vault", "items", "abc", "release"]),
    );

    expect(response.status).toBe(413);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards a JSON body unchanged", async () => {
    const body = JSON.stringify({ envelope: { ciphertext: "Yw" } });
    const response = await PUT(
      request("PUT", "https://prism.test/api/agent/proxy/vault/items/abc", {
        headers: { "content-type": "application/json" },
        body,
      }),
      context(["vault", "items", "abc"]),
    );

    expect(response.status).toBe(200);
    const forwarded = Buffer.from(fetchMock.mock.calls[0][1].body).toString("utf8");
    expect(forwarded).toBe(body);
  });
});
