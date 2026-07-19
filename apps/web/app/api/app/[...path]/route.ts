import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { controlPlaneUrl, signControlIdentity } from "@/lib/control-plane";
import { SessionConfigurationError, SessionValidationError } from "@/lib/server-auth";
import { isSameOriginRequest } from "@/lib/server-origin";
import { requestSubject, takeRateLimit } from "@/lib/server-rate-limit";

export const dynamic = "force-dynamic";
type RouteContext = { params: Promise<{ path: string[] }> };
const maxRequestBytes = 256 * 1_024;

async function proxy(request: NextRequest, context: RouteContext) {
  const requestId = request.headers.get("x-request-id") ?? randomUUID();
  if (!isSameOriginRequest(request)) return errorResponse(403, "invalid_origin", requestId);
  const session = request.cookies.get("prism-token")?.value;
  const subject = session ?? requestSubject(request.headers);
  const limit = await takeRateLimit("application-api", subject, 120, 60_000);
  if (!limit.available) return errorResponse(503, "rate_limit_unavailable", requestId);
  if (!limit.allowed) return errorResponse(429, "rate_limited", requestId, limit.retryAfter);
  const base = process.env.PRISM_API_BASE_URL;
  if (!base) return errorResponse(503, "service_unavailable", requestId);
  const { path } = await context.params;
  if (path.some((part) => !/^[a-zA-Z0-9_-]+$/.test(part))) return errorResponse(400, "invalid_request", requestId);
  const target = controlPlaneUrl(base, path);
  if (!target) return errorResponse(503, "service_unavailable", requestId);
  target.search = request.nextUrl.search;
  const headers = new Headers({ Accept: "application/json", "x-request-id": requestId });
  const isMutation = !["GET", "HEAD"].includes(request.method);
  let body: ArrayBuffer | undefined;
  if (isMutation) {
    if (!session) return errorResponse(401, "identity_required", requestId);
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
      return errorResponse(415, "unsupported_media_type", requestId);
    }
    if (Number(request.headers.get("content-length") ?? "0") > maxRequestBytes) {
      return errorResponse(413, "request_too_large", requestId);
    }
    body = await request.arrayBuffer();
    if (body.byteLength > maxRequestBytes) return errorResponse(413, "request_too_large", requestId);
  }
  if (session) {
    let identity;
    try {
      identity = await signControlIdentity(
        session,
        requestId,
        request.method,
        target.pathname,
        body ? Buffer.from(body) : Buffer.alloc(0),
      );
    } catch (error) {
      if (error instanceof SessionConfigurationError) return errorResponse(503, "service_unavailable", requestId);
      if (error instanceof SessionValidationError) return errorResponse(401, "identity_required", requestId);
      throw error;
    }
    headers.set("x-prism-subject", identity.subject);
    headers.set("x-prism-session-id", identity.sessionId);
    headers.set("x-prism-timestamp", identity.timestamp);
    headers.set("x-prism-signature", identity.signature);
  }
  for (const name of ["content-type"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
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
    return errorResponse(503, "service_unavailable", requestId);
  }
}

function errorResponse(status: number, code: string, requestId: string, retryAfter?: number) {
  const response = NextResponse.json({ error: code }, { status, headers: { "X-Request-Id": requestId, "Cache-Control": "no-store" } });
  if (retryAfter) response.headers.set("Retry-After", String(retryAfter));
  return response;
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
