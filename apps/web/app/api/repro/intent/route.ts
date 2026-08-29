import { NextRequest, NextResponse } from "next/server";
import { ReproIntentError, verifyReproIntent } from "@/lib/repro-intent";
import { isSameOriginRequest } from "@/lib/server-origin";
import { requestSubject, takeRateLimit } from "@/lib/server-rate-limit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const maxRequestBytes = 12 * 1_024;

export async function POST(request: NextRequest) {
  if (!isSameOriginRequest(request)) return response(403, "invalid_origin");
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return response(415, "unsupported_media_type");
  }
  const limit = await takeRateLimit("repro-intent", requestSubject(request.headers), 120, 60_000);
  if (!limit.available) return response(503, "service_unavailable");
  if (!limit.allowed) return response(429, "rate_limited", limit.retryAfter);

  const raw = await request.arrayBuffer();
  if (raw.byteLength > maxRequestBytes) return response(413, "request_too_large");
  let payload: { envelope?: unknown };
  try {
    payload = JSON.parse(Buffer.from(raw).toString("utf8") || "{}");
  } catch {
    return response(400, "invalid_json");
  }
  if (typeof payload.envelope !== "string") return response(400, "invalid_intent");

  try {
    return NextResponse.json(verifyReproIntent(payload.envelope), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    if (error instanceof ReproIntentError) {
      if (error.code === "configuration") return response(503, "service_unavailable");
      if (error.code === "expired") return response(410, "intent_expired");
      return response(400, "invalid_intent");
    }
    throw error;
  }
}

function response(status: number, error: string, retryAfter?: number) {
  const result = NextResponse.json(
    { error },
    { status, headers: { "Cache-Control": "no-store" } },
  );
  if (retryAfter) result.headers.set("Retry-After", String(retryAfter));
  return result;
}
