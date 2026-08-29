import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST } from "./route";

const offer = {
  node_id: `0x${"1".repeat(64)}`,
  gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
  rate_per_second: 222,
  reliability_bps: 9_800,
  benchmark_score: 10_000,
  staker_only: false,
  managed_batch: true,
};
let proofReceipts: unknown[] = [];

beforeEach(() => {
  proofReceipts = [];
  process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT = "1";
  process.env.PRISM_PUBLIC_API = "https://api.prism.test";
  process.env.PRISM_API_BASE_URL = "https://api.prism.test";
  process.env.PRISM_CONTROL_PLANE_AUTH_KEY = "42".repeat(32);
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.pathname === "/v1/offers") return Response.json([offer]);
    if (url.pathname === "/v1/repros/status") {
      const body = JSON.parse(String(init?.body));
      expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      return Response.json({
        version: "prism.gpu-repro.status.v1",
        status: "completed",
        spec_hash: "a".repeat(64),
        lease_id: 42,
        result: { exit_code: 0, stdout: "ok\n", stderr: "", truncated: false },
        evidence: {
          command: { command_id: "command-1" },
          report: {
            executor: "managed",
            report: {
              signer: `0x${"2".repeat(40)}`,
              provider: "vast",
              provider_instance_id: 42,
              signature: `0x${"3".repeat(130)}`,
            },
          },
        },
        checks: { token_bound: true, spec_hash_valid: true, expected_exit_code: true },
      });
    }
    if (url.pathname === "/proof/index.json") {
      return Response.json({ generated_at: "2026-08-29T10:26:29.000Z", receipts: proofReceipts });
    }
    throw new Error(`unexpected request: ${url}`);
  }));
});

afterEach(() => {
  delete process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT;
  delete process.env.PRISM_PUBLIC_API;
  delete process.env.PRISM_API_BASE_URL;
  delete process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
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
      "prism_gpu_repro_status",
      "prism_gpu_repro_evidence",
      "prism_verify_gpu_repro",
      "prism_gpu_receipts",
    ]);
    expect(listed.result.tools.every((tool: { annotations?: Record<string, boolean> }) => (
      tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint === false
    ))).toBe(true);
    const evidenceTool = listed.result.tools.find((tool: { name: string }) => (
      tool.name === "prism_gpu_repro_evidence"
    ));
    const verifyTool = listed.result.tools.find((tool: { name: string }) => (
      tool.name === "prism_verify_gpu_repro"
    ));
    expect(evidenceTool.description).toContain("enrolled device key");
    expect(evidenceTool.description).toContain("Prism gateway");
    expect(evidenceTool.description).toContain("centrally orchestrated SSH run");
    expect(verifyTool.description).toMatch(/neither signature alone proves faithful computation/i);
    expect(JSON.stringify([evidenceTool, verifyTool])).not.toMatch(/provider-signed|device-attested|verifiable computation/i);

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
    const command = "python -c 'import torch; assert torch.cuda.is_available()'";
    const called = await rpc("tools/call", {
      name: "prism_prepare_gpu_repro",
      arguments: {
        image,
        command,
        duration_minutes: 30,
        min_vram_gib: 40,
        expected_exit_code: 0,
      },
    });
    const payload = JSON.parse(called.result.content[0].text);

    expect(payload).toMatchObject({
      duration_minutes: 30,
      maximum_escrow: "399600",
      maximum_escrow_usdg: "0.3996",
      lease_created: false,
    });
    expect(payload.approval_url).toContain("/compute#repro=");
    expect(payload.repro_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(payload.spec_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.approval_url).not.toContain(payload.repro_token);
    expect(payload.approval_url).not.toContain(command);
    expect(called.result.content[0].text).not.toContain(offer.node_id);
  });

  it("reads status, evidence, and verification through one scoped token", async () => {
    const reproToken = Buffer.alloc(32, 7).toString("base64url");
    const status = await callTool("prism_gpu_repro_status", { repro_token: reproToken });
    expect(status).toMatchObject({ status: "completed", lease_id: 42 });
    expect(status).not.toHaveProperty("evidence");
    expect(status).not.toHaveProperty("checks");

    const evidence = await callTool("prism_gpu_repro_evidence", { repro_token: reproToken });
    expect(evidence.evidence.report).toMatchObject({
      executor: "managed",
      report: {
        signer: `0x${"2".repeat(40)}`,
        provider: "vast",
        provider_instance_id: 42,
        signature: `0x${"3".repeat(130)}`,
      },
    });

    const verified = await callTool("prism_verify_gpu_repro", { repro_token: reproToken });
    expect(verified.checks).toMatchObject({ token_bound: true, expected_exit_code: true });
    expect(verified.assurance).toContain("executor=node");
    expect(verified.assurance).toContain("executor=managed");
    expect(verified.assurance).toContain("does not independently query chain state");
    expect(verified.assurance).toContain("Neither signature alone proves faithful computation");
    expect(verified.assurance).not.toMatch(/provider-signed|device-attested|verifiable computation/i);
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

  it("finds the settlement receipt committed to a repro spec", async () => {
    proofReceipts = [receipt("a".repeat(64)), receipt("b".repeat(64))];
    const payload = await callTool("prism_gpu_receipts", {
      limit: 5,
      repro_spec_hash: "b".repeat(64),
    });
    expect(payload.receipts).toHaveLength(1);
    expect(payload.receipts[0].repro.spec_hash).toBe("b".repeat(64));
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

async function callTool(name: string, args: Record<string, unknown>) {
  const called = await rpc("tools/call", { name, arguments: args });
  expect(called.result.isError).not.toBe(true);
  return JSON.parse(called.result.content[0].text);
}

function receipt(specHash: string) {
  return {
    receipt_id: `receipt-${specHash[0]}`,
    lease_id: "7",
    node_id_hash: `0x${"1".repeat(64)}`,
    gpu_model: "L40S",
    runtime_seconds: 30,
    charged_base_units: 6_660,
    refunded_base_units: 0,
    provider_paid_base_units: 5_994,
    failure_class: null,
    outcome: "finalized",
    repro: {
      executor: "node",
      token_hash: "0".repeat(64),
      spec_hash: specHash,
      image_digest: `sha256:${"2".repeat(64)}`,
      command_hash: "3".repeat(64),
      result_hash: "4".repeat(64),
      stdout_hash: "5".repeat(64),
      stderr_hash: "6".repeat(64),
      report_hash: "7".repeat(64),
      exit_code: 0,
      expected_exit_code: 0,
      succeeded: true,
      truncated: false,
    },
    receipt_hash: "8".repeat(64),
    transaction_hash: `0x${"9".repeat(64)}`,
  };
}
