import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST } from "./route";

const offer = {
  node_id: `0x${"1".repeat(64)}`,
  gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
  rate_per_second: 222,
  reliability_bps: 9_800,
  benchmark_score: 10_000,
  staker_only: false,
};

beforeEach(() => {
  process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT = "1";
  process.env.PRISM_PUBLIC_API = "https://api.prism.test";
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.pathname === "/v1/offers") return Response.json([offer]);
    if (url.pathname === "/proof/index.json") {
      return Response.json({ generated_at: "2026-08-29T10:26:29.000Z", receipts: [] });
    }
    throw new Error(`unexpected request: ${url}`);
  }));
});

afterEach(() => {
  delete process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT;
  delete process.env.PRISM_PUBLIC_API;
  vi.unstubAllGlobals();
});

describe("Prism MCP endpoint", () => {
  it("advertises scoped tools and returns public capacity", async () => {
    const initialized = await rpc("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "prism-test", version: "1.0.0" },
    });
    expect(initialized.result.serverInfo.name).toBe("prism-network");

    const listed = await rpc("tools/list", {});
    expect(listed.result.tools.map((tool: { name: string }) => tool.name)).toEqual([
      "prism_gpu_capacity",
      "prism_prepare_gpu_repro",
      "prism_gpu_receipts",
    ]);
    expect(listed.result.tools.every((tool: { annotations?: Record<string, boolean> }) => (
      tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint === false
    ))).toBe(true);

    const called = await rpc("tools/call", {
      name: "prism_gpu_capacity",
      arguments: { min_vram_gib: 40 },
    });
    const payload = JSON.parse(called.result.content[0].text);
    expect(payload.capacity[0]).toMatchObject({ model: "L40S", available: 1 });
    expect(called.result.content[0].text).not.toContain(offer.node_id);
  });

  it("prepares a wallet-gated launch without creating a lease", async () => {
    const image = `pytorch/pytorch@sha256:${"a".repeat(64)}`;
    const called = await rpc("tools/call", {
      name: "prism_prepare_gpu_repro",
      arguments: {
        image,
        duration_minutes: 30,
        min_vram_gib: 40,
        ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFgcqV9bxjW5lu0s9eN0589FiHY0vZpg7Yi+mlw73P9h prism-gpu-repro",
      },
    });
    const payload = JSON.parse(called.result.content[0].text);

    expect(payload).toMatchObject({
      duration_minutes: 30,
      maximum_escrow_usdg: "0.3996",
      lease_created: false,
    });
    expect(payload.approval_url).toContain("/compute?intent=prism-gpu-repro-v1");
    expect(payload.approval_url).toContain(encodeURIComponent(image));
    expect(called.result.content[0].text).not.toContain(offer.node_id);
  });

  it("returns the public receipt feed without lease authority", async () => {
    const called = await rpc("tools/call", {
      name: "prism_gpu_receipts",
      arguments: { limit: 5 },
    });
    expect(JSON.parse(called.result.content[0].text)).toEqual({
      generated_at: "2026-08-29T10:26:29.000Z",
      receipts: [],
    });
  });

  it("rejects an oversized body without relying on content-length", async () => {
    const request = new Request("http://localhost/api/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "x".repeat(128 * 1_024 + 1),
    });
    expect(request.headers.has("content-length")).toBe(false);
    expect((await POST(request)).status).toBe(413);
  });
});

let requestId = 0;

async function rpc(method: string, params: unknown) {
  const response = await POST(new Request("http://localhost/api/mcp", {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": "2025-06-18",
      "X-Forwarded-For": "192.0.2.10",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++requestId, method, params }),
  }));
  expect(response.status).toBe(200);
  const body = await response.text();
  const json = response.headers.get("content-type")?.includes("text/event-stream")
    ? body.split("\n").find((line) => line.startsWith("data: "))?.slice(6)
    : body;
  if (!json) throw new Error(`missing MCP response: ${body}`);
  return JSON.parse(json);
}
