import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import {
  GpuCapabilityError,
  prepareGpuLeasePlan,
  summarizeGpuCapacity,
} from "@/lib/gpu-capability";
import { loadGpuOffers } from "@/lib/gpu-capability-server";
import { loadPublicProofIndex } from "@/lib/public-proof-server";
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
      description: "Validate a reproducible GPU lease intent and return an approval URL with a live cost ceiling. This tool cannot spend funds, sign a wallet transaction, or create a lease.",
      inputSchema: z.object({
        image: z.string().min(1).max(512).describe("Public OCI image pinned as repository@sha256:<64 hex characters>."),
        duration_minutes: z.union([z.literal(30), z.literal(60), z.literal(120), z.literal(360)]),
        min_vram_gib: z.number().int().min(1).max(192),
        ssh_public_key: z.string().min(1).max(16_384).describe("One Ed25519 public key. Never send the private key."),
      }),
      annotations: readOnly,
    },
    async ({ image, duration_minutes, min_vram_gib, ssh_public_key }) => toolResult(async () => {
      const plan = prepareGpuLeasePlan(
        await loadGpuOffers(),
        {
          image,
          durationMinutes: duration_minutes,
          minVramGib: min_vram_gib,
          sshPublicKey: ssh_public_key,
        },
        siteUrl,
      );
      return {
        approval_url: plan.approvalUrl,
        estimated_gpu: {
          model: plan.estimatedGpu.model,
          vram_gib: Math.round(plan.estimatedGpu.vramMib / 1_024),
          cuda_major: plan.estimatedGpu.cudaMajor,
        },
        duration_minutes,
        maximum_escrow_usdg: plan.maximumEscrowUsdg,
        lease_created: false,
        approval_required: "Open the URL, sign in, review the live quote, and approve the wallet transaction.",
        data_boundary: "Use only public images and non-confidential data. Independent providers may operate the assigned GPU.",
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
      }),
      annotations: readOnly,
    },
    async ({ limit, receipt_id, transaction_hash }) => toolResult(async () => {
      const index = await loadPublicProofIndex();
      const receipts = index.receipts
        .filter((receipt) => !receipt_id || receipt.receipt_id === receipt_id)
        .filter((receipt) => !transaction_hash || receipt.transaction_hash.toLowerCase() === transaction_hash.toLowerCase())
        .slice(0, limit);
      return { generated_at: index.generated_at, receipts };
    }),
  );
}, {
  serverInfo: { name: "prism-network", version: "0.1.0" },
  instructions: "Expose read-only Prism GPU availability, bounded launch preparation, and public settlement receipts. Wallet signing and lease creation always require a separate human approval in the Prism web application.",
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
    const message = error instanceof GpuCapabilityError
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
