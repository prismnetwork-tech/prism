import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import {
  GpuCapabilityError,
  maxGpuReproCommandBytes,
  prepareGpuLeasePlan,
  summarizeGpuCapacity,
} from "@/lib/gpu-capability";
import { loadGpuOffers } from "@/lib/gpu-capability-server";
import {
  GpuReproStatusError,
  loadGpuReproStatus,
} from "@/lib/gpu-repro-server";
import { loadPublicProofIndex } from "@/lib/public-proof-server";
import { createReproIntent } from "@/lib/repro-intent";
import { requestSubject, takeRateLimit } from "@/lib/server-rate-limit";
import { siteUrl } from "@/lib/site";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const readOnly = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};
const maxRequestBytes = 128 * 1_024;

const mcpHandler = createMcpHandler((server) => {
  server.registerTool(
    "prism_gpu_capacity",
    {
      title: "List Prism GPU capacity",
      description: "List live Prism GPU capacity and current starting hourly rates. This is read-only and does not reserve a GPU.",
      inputSchema: z.object({
        min_vram_gib: z.number().int().min(1).max(192).optional().describe("Only return GPU classes meeting this memory minimum."),
      }),
      annotations: readOnly,
    },
    async ({ min_vram_gib }) => toolResult(async () => {
      const offers = await loadGpuOffers();
      const eligible = min_vram_gib
        ? offers.filter((offer) => offer.gpu.vram_mib >= min_vram_gib * 1_024)
        : offers;
      return {
        observed_at: new Date().toISOString(),
        reservation_created: false,
        capacity: summarizeGpuCapacity(eligible),
      };
    }),
  );

  server.registerTool(
    "prism_prepare_gpu_repro",
    {
      title: "Prepare a bounded GPU repro",
      description: "Bind an exact command and digest-pinned image into a short-lived approval intent with a live cost ceiling. This tool cannot spend funds, sign a wallet transaction, or create a lease.",
      inputSchema: z.object({
        image: z.string().min(1).max(512).describe("Public OCI image pinned as repository@sha256:<64 lowercase hex characters>."),
        command: z.string().min(1).max(maxGpuReproCommandBytes).describe("Exact command to run on the GPU, up to 2 KiB UTF-8."),
        duration_minutes: z.union([z.literal(30), z.literal(60), z.literal(120), z.literal(360)]),
        min_vram_gib: z.number().int().min(1).max(192),
        expected_exit_code: z.number().int().min(0).max(255).default(0),
      }),
      annotations: readOnly,
    },
    async ({ image, command, duration_minutes, min_vram_gib, expected_exit_code }) => toolResult(async () => {
      const plan = prepareGpuLeasePlan(
        await loadGpuOffers(),
        {
          image,
          command,
          durationMinutes: duration_minutes,
          minVramGib: min_vram_gib,
          expectedExitCode: expected_exit_code,
        },
      );
      const intent = createReproIntent(
        plan,
        plan.estimatedExecutor,
        plan.maximumEscrowBaseUnits,
        siteUrl,
      );
      return {
        intent_version: intent.payload.version,
        approval_url: intent.approvalUrl,
        repro_token: intent.reproToken,
        spec_hash: intent.payload.spec_hash,
        estimated_gpu: {
          model: plan.estimatedGpu.model,
          vram_gib: Math.round(plan.estimatedGpu.vramMib / 1_024),
          cuda_major: plan.estimatedGpu.cudaMajor,
        },
        estimated_executor: plan.estimatedExecutor,
        execution_boundary: plan.estimatedExecutor === "managed"
          ? "Prism centrally orchestrates the digest-pinned job over pinned SSH transport and signs the report with its gateway identity. This is inspectable evidence, not device attestation or proof of faithful computation."
          : "The enrolled node signs the execution report with its device identity. This binds the report to that node; it does not prove faithful computation by itself.",
        duration_minutes,
        expected_exit_code,
        maximum_escrow: intent.payload.maximum_escrow,
        maximum_escrow_usdg: plan.maximumEscrowUsdg,
        lease_created: false,
        approval_required: "Open the URL, sign in, verify the locked command and live quote, then approve the wallet transaction.",
        next: "Keep repro_token private. Use it with the status, evidence, and verify tools after approval.",
        data_boundary: "Use only public images and non-confidential data. Independent providers may operate the assigned GPU.",
      };
    }),
  );

  server.registerTool(
    "prism_gpu_repro_status",
    {
      title: "Read GPU repro status",
      description: "Read the state and bounded result of one GPU repro using its 256-bit read capability. This cannot create or change a lease.",
      inputSchema: z.object({
        repro_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      }),
      annotations: readOnly,
    },
    async ({ repro_token }) => toolResult(async () => {
      const { evidence: _evidence, checks: _checks, ...status } = await loadGpuReproStatus(repro_token);
      return status;
    }),
  );

  server.registerTool(
    "prism_gpu_repro_evidence",
    {
      title: "Read GPU repro evidence",
      description: "Read capability-scoped execution evidence for one GPU repro. A node report is signed by an enrolled device key; a managed report is signed by the Prism gateway for a centrally orchestrated SSH run. Either signature authenticates a report, but neither alone proves faithful computation.",
      inputSchema: z.object({
        repro_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      }),
      annotations: readOnly,
    },
    async ({ repro_token }) => toolResult(async () => {
      const status = await loadGpuReproStatus(repro_token);
      if (status.evidence === undefined) throw new GpuReproStatusError("evidence_not_ready");
      return {
        status: status.status,
        spec_hash: status.spec_hash,
        lease_id: status.lease_id,
        evidence: status.evidence,
      };
    }),
  );

  server.registerTool(
    "prism_verify_gpu_repro",
    {
      title: "Verify GPU repro evidence",
      description: "Return the available token, spec, command, report-signature, result, and settlement checks for a GPU repro. Node means an enrolled device-signed report; managed means a Prism gateway-signed report from central SSH orchestration. Neither signature alone proves faithful computation.",
      inputSchema: z.object({
        repro_token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      }),
      annotations: readOnly,
    },
    async ({ repro_token }) => toolResult(async () => {
      const status = await loadGpuReproStatus(repro_token);
      if (status.checks === undefined) throw new GpuReproStatusError("verification_not_ready");
      return {
        status: status.status,
        spec_hash: status.spec_hash,
        lease_id: status.lease_id,
        checks: status.checks,
        assurance: "For executor=node, an enrolled device key signed the report. For executor=managed, the Prism gateway signed a report from centrally orchestrated SSH execution. Settlement checks the current gateway; this MCP response does not independently query chain state. Neither signature alone proves faithful computation.",
      };
    }),
  );

  server.registerTool(
    "prism_gpu_receipts",
    {
      title: "Read Prism GPU receipts",
      description: "Read public Prism settlement receipts. Receipts link platform-attested metering to an onchain settlement; they are not hardware attestation.",
      inputSchema: z.object({
        limit: z.number().int().min(1).max(100).default(20),
        receipt_id: z.string().min(1).max(128).optional(),
        transaction_hash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
        repro_spec_hash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
      }),
      annotations: readOnly,
    },
    async ({ limit, receipt_id, transaction_hash, repro_spec_hash }) => toolResult(async () => {
      const index = await loadPublicProofIndex();
      const receipts = index.receipts
        .filter((receipt) => !receipt_id || receipt.receipt_id === receipt_id)
        .filter((receipt) => !transaction_hash || receipt.transaction_hash.toLowerCase() === transaction_hash.toLowerCase())
        .filter((receipt) => !repro_spec_hash || receipt.repro?.spec_hash === repro_spec_hash)
        .slice(0, limit);
      return { generated_at: index.generated_at, receipts };
    }),
  );
}, {
  serverInfo: { name: "prism-network", version: "0.2.0" },
  instructions: "Expose read-only Prism GPU availability, bounded repro preparation, capability-scoped status and evidence, verification checks, and public settlement receipts. Wallet signing and lease creation always require a separate human approval in the Prism web application.",
  maxSubscriptions: 0,
});

async function guardedHandler(request: Request) {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > maxRequestBytes) return new Response("request too large", { status: 413 });
  const rateLimit = await takeRateLimit("public-mcp", requestSubject(request.headers), 120, 60_000);
  if (!rateLimit.available) return new Response("service unavailable", { status: 503 });
  if (!rateLimit.allowed) {
    return new Response("rate limited", {
      status: 429,
      headers: { "Retry-After": String(rateLimit.retryAfter) },
    });
  }
  const boundedRequest = await readBoundedRequest(request);
  if (!boundedRequest) return new Response("request too large", { status: 413 });
  const response = await mcpHandler(boundedRequest);
  response.headers.set("Cache-Control", "no-store");
  return response;
}

async function readBoundedRequest(request: Request) {
  if (!request.body) return request;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxRequestBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const headers = new Headers(request.headers);
  headers.delete("transfer-encoding");
  headers.set("content-length", String(size));
  return new Request(request.url, {
    method: request.method,
    headers,
    body,
    signal: request.signal,
  });
}

async function toolResult(load: () => Promise<unknown>) {
  try {
    const payload = await load();
    return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
  } catch (error) {
    const message = error instanceof GpuCapabilityError || error instanceof GpuReproStatusError
      ? error.message
      : "Prism is temporarily unavailable.";
    return {
      isError: true,
      content: [{ type: "text" as const, text: message }],
    };
  }
}

export const GET = guardedHandler;
export const POST = guardedHandler;
