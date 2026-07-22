import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { AgentAuthConfigError, AgentAuthError, issueSession } from "@/lib/agent-auth";
import { takeRateLimit } from "@/lib/server-rate-limit";

export const dynamic = "force-dynamic";
const maxRequestBytes = 16 * 1_024;

export async function POST(request: NextRequest) {
  const requestId = request.headers.get("x-request-id") ?? randomUUID();
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return error(415, "unsupported_media_type", requestId);
  }
  if (Number(request.headers.get("content-length") ?? "0") > maxRequestBytes) {
    return error(413, "request_too_large", requestId);
  }
  let payload: { challenge?: unknown; address?: unknown; signature?: unknown };
  try {
    payload = await request.json();
  } catch {
    return error(400, "invalid_json", requestId);
  }
  const { challenge, address, signature } = payload;
  if (typeof challenge !== "string" || typeof address !== "string" || typeof signature !== "string") {
    return error(400, "invalid_request", requestId);
  }
  const limit = await takeRateLimit("agent-session", address.toLowerCase(), 20, 60_000);
  if (!limit.available) return error(503, "rate_limit_unavailable", requestId);
  if (!limit.allowed) return error(429, "rate_limited", requestId, limit.retryAfter);
  try {
    const session = await issueSession(challenge, address, signature);
    return NextResponse.json(session, {
      headers: { "Cache-Control": "no-store", "X-Request-Id": requestId },
    });
  } catch (err) {
    if (err instanceof AgentAuthConfigError) return error(503, "service_unavailable", requestId);
    if (err instanceof AgentAuthError) return error(401, "signature_invalid", requestId);
    throw err;
  }
}

function error(status: number, code: string, requestId: string, retryAfter?: number) {
  const response = NextResponse.json(
    { error: code },
    { status, headers: { "X-Request-Id": requestId, "Cache-Control": "no-store" } },
  );
  if (retryAfter) response.headers.set("Retry-After", String(retryAfter));
  return response;
}
