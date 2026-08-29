import { parseReproToken } from "./repro-intent";

const maxResponseBytes = 512 * 1_024;
const statuses = new Set([
  "quoted",
  "funded",
  "preparing",
  "ready",
  "running",
  "completed",
  "failed",
  "settling",
  "settled",
  "refunded",
  "disputed",
]);

export type GpuReproStatus = {
  version: "prism.gpu-repro.status.v1";
  status: string;
  spec?: unknown;
  spec_hash?: string;
  quote_id?: string;
  maximum_escrow?: number | string;
  lease_id?: number;
  lease_state?: string;
  command_status?: string;
  result?: unknown;
  evidence?: unknown;
  checks?: Record<string, unknown>;
};

export class GpuReproStatusError extends Error {
  constructor(readonly code: "invalid_token" | "unavailable" | "evidence_not_ready" | "verification_not_ready") {
    super(code.replaceAll("_", " "));
  }
}

export async function loadGpuReproStatus(token: string): Promise<GpuReproStatus> {
  try {
    parseReproToken(token);
  } catch {
    throw new GpuReproStatusError("invalid_token");
  }
  const base = process.env.PRISM_API_BASE_URL
    ?? process.env.PRISM_PUBLIC_API
    ?? "https://api.prismnetwork.tech";
  let url: URL;
  try {
    url = new URL("/v1/repros/status", /^https?:\/\//.test(base) ? base : `http://${base}`);
  } catch {
    throw new GpuReproStatusError("unavailable");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new GpuReproStatusError("unavailable");
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GpuReproStatusError("unavailable");
  }
  if (response.status === 404) {
    return { version: "prism.gpu-repro.status.v1", status: "awaiting_approval" };
  }
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (!response.ok || contentLength > maxResponseBytes) throw new GpuReproStatusError("unavailable");
  const body = await response.arrayBuffer();
  if (body.byteLength > maxResponseBytes) throw new GpuReproStatusError("unavailable");

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    throw new GpuReproStatusError("unavailable");
  }
  if (!isGpuReproStatus(payload)) throw new GpuReproStatusError("unavailable");
  return payload;
}

function isGpuReproStatus(value: unknown): value is GpuReproStatus {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Partial<GpuReproStatus>;
  if (record.version !== "prism.gpu-repro.status.v1"
    || typeof record.status !== "string"
    || !statuses.has(record.status)) return false;
  if (record.spec_hash !== undefined && !isHash(record.spec_hash)) return false;
  if (record.lease_id !== undefined && (!Number.isSafeInteger(record.lease_id) || record.lease_id <= 0)) return false;
  if (record.checks !== undefined && (!record.checks || typeof record.checks !== "object" || Array.isArray(record.checks))) {
    return false;
  }
  return true;
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
