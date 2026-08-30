import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadGpuReproStatus } from "./gpu-repro-server";

const token = Buffer.alloc(32, 9).toString("base64url");

beforeEach(() => {
  process.env.PRISM_API_BASE_URL = "https://control.prism.test";
});

afterEach(() => {
  delete process.env.PRISM_API_BASE_URL;
  vi.unstubAllGlobals();
});

describe("GPU repro status client", () => {
  it("uses only the scoped capability and sends no privileged identity", async () => {
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => Response.json({
      version: "prism.gpu-repro.status.v1",
      status: "running",
      executor: "managed",
      spec_hash: "a".repeat(64),
      lease_id: 7,
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(loadGpuReproStatus(token)).resolves.toMatchObject({ status: "running", lease_id: 7 });
    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.has("authorization")).toBe(false);
    expect(headers.has("x-prism-signature")).toBe(false);
    expect(JSON.parse(String(init?.body))).toEqual({ token });
  });

  it("rejects an unknown capability instead of polling forever", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 404 })));
    await expect(loadGpuReproStatus(token)).rejects.toMatchObject({ code: "not_found" });
  });

  it("rejects malformed tokens without a network request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(loadGpuReproStatus("not-a-capability")).rejects.toMatchObject({ code: "invalid_token" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
