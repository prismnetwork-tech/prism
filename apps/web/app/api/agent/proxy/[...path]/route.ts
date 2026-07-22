import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { AgentAuthConfigError, AgentAuthError, verifySession } from "@/lib/agent-auth";
import { controlPlaneUrl, hmacControlIdentity } from "@/lib/control-plane";
import { SessionConfigurationError } from "@/lib/server-auth";
import { takeRateLimit } from "@/lib/server-rate-limit";

export const dynamic = "force-dynamic";
type RouteContext = { params: Promise<{ path: string[] }> };
const maxRequestBytes = 256 * 1_024;

async function proxy(request: NextRequest, context: RouteContext) {
  const requestId = request.headers.get("x-request-id") ?? randomUUID();
  const bearer = request.headers.get("authorization");
  const token = bearer?.toLowerCase().startsWith("bearer ") ? bearer.slice(7).trim() : null;
  if (!token) return error(401, "identity_required", requestId);

  let identity: { subject: string; sessionId: string };
  try {
    identity = await verifySession(token);
  } catch (err) {
    if (err instanceof AgentAuthConfigError) return error(503, "service_unavailable", requestId);
    if (err instanceof AgentAuthError) return error(401, "session_invalid", requestId);
    throw err;
  }

  const limit = await takeRateLimit("agent-api", identity.subject, 120, 60_000);
  if (!limit.available) return error(503, "rate_limit_unavailable", requestId);
  if (!limit.allowed) return error(429, "rate_limited", requestId, limit.retryAfter);

  const base = process.env.PRISM_API_BASE_URL;
  if (!base) return error(503, "service_unavailable", requestId);
  const { path } = await context.params;
  if (path.some((part) => !/^[a-zA-Z0-9_-]+$/.test(part))) return error(400, "invalid_request", requestId);
  const target = controlPlaneUrl(base, path);
  if (!target) return error(503, "service_unavailable", requestId);
  target.search = request.nextUrl.search;

  const isMutation = !["GET", "HEAD"].includes(request.method);
  let body: ArrayBuffer | undefined;
  if (isMutation) {
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
      return error(415, "unsupported_media_type", requestId);
    }
    if (Number(request.headers.get("content-length") ?? "0") > maxRequestBytes) {
      return error(413, "request_too_large", requestId);
    }
    body = await request.arrayBuffer();
    if (body.byteLength > maxRequestBytes) return error(413, "request_too_large", requestId);
  }

  const headers = new Headers({ Accept: "application/json", "x-request-id": requestId });
  try {
    const signed = hmacControlIdentity(
      identity.subject,
      identity.sessionId,
      requestId,
      request.method,
      target.pathname,
      body ? Buffer.from(body) : Buffer.alloc(0),
    );
    headers.set("x-prism-subject", signed.subject);
    headers.set("x-prism-session-id", signed.sessionId);
    headers.set("x-prism-timestamp", signed.timestamp);
    headers.set("x-prism-signature", signed.signature);
  } catch (err) {
    if (err instanceof SessionConfigurationError) return error(503, "service_unavailable", requestId);
    throw err;
  }
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(30_000),
    });
    const output = new Headers({ "Cache-Control": "no-store", "X-Request-Id": requestId });
    const type = response.headers.get("content-type");
    if (type) output.set("content-type", type);
    return new NextResponse(response.body, { status: response.status, headers: output });
  } catch {
    return error(503, "service_unavailable", requestId);
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

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
