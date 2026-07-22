import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { AgentAuthConfigError, AgentAuthError, issueChallenge } from "@/lib/agent-auth";
import { requestSubject, takeRateLimit } from "@/lib/server-rate-limit";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const requestId = randomUUID();
  const address = request.nextUrl.searchParams.get("address") ?? "";
  const ipLimit = await takeRateLimit("agent-challenge-ip", requestSubject(request.headers), 60, 60_000);
  if (!ipLimit.available) return error(503, "rate_limit_unavailable", requestId);
  if (!ipLimit.allowed) return error(429, "rate_limited", requestId, ipLimit.retryAfter);
  const limit = await takeRateLimit("agent-challenge", address.toLowerCase() || "anon", 30, 60_000);
  if (!limit.available) return error(503, "rate_limit_unavailable", requestId);
  if (!limit.allowed) return error(429, "rate_limited", requestId, limit.retryAfter);
  try {
    const { wallet, message, challenge } = await issueChallenge(address);
    return NextResponse.json(
      { wallet, message, challenge },
      { headers: { "Cache-Control": "no-store", "X-Request-Id": requestId } },
    );
  } catch (err) {
    if (err instanceof AgentAuthConfigError) return error(503, "service_unavailable", requestId);
    if (err instanceof AgentAuthError) return error(400, "invalid_address", requestId);
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
