import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { controlPlaneUrl, signControlIdentity } from "@/lib/control-plane";
import { SessionConfigurationError, SessionValidationError, verifyPrivySession } from "@/lib/server-auth";
import { isSameOriginRequest } from "@/lib/server-origin";
import { requestSubject, takeRateLimit } from "@/lib/server-rate-limit";

const COOKIE = "prism-token";
const maxBodyBytes = 12 * 1_024;

export async function POST(request: NextRequest) {
  if (!isSameOriginRequest(request)) return NextResponse.json({ error: "invalid_origin" }, { status: 403 });
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return json({ error: "unsupported_media_type" }, 415);
  }
  if (Number(request.headers.get("content-length") ?? "0") > maxBodyBytes) {
    return json({ error: "request_too_large" }, 413);
  }
  const limit = await takeRateLimit("session", requestSubject(request.headers), 20, 60_000);
  if (!limit.available) return json({ error: "rate_limit_unavailable" }, 503);
  if (!limit.allowed) return json({ error: "rate_limited" }, 429, { "Retry-After": String(limit.retryAfter) });
  const text = await request.text();
  if (Buffer.byteLength(text) > maxBodyBytes) return json({ error: "request_too_large" }, 413);
  const body = (() => {
    try {
      return JSON.parse(text) as { token?: unknown };
    } catch {
      return null;
    }
  })();
  if (typeof body?.token !== "string" || body.token.length < 20 || body.token.length > 8_192) {
    return json({ error: "invalid_token" }, 400);
  }
  try {
    await verifyPrivySession(body.token);
  } catch (error) {
    if (error instanceof SessionConfigurationError) return json({ error: "service_unavailable" }, 503);
    if (error instanceof SessionValidationError) return json({ error: "invalid_token" }, 401);
    throw error;
  }
  const response = json({ ok: true }, 200);
  response.cookies.set(COOKIE, body.token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60,
  });
  return response;
}

export async function DELETE(request: NextRequest) {
  if (!isSameOriginRequest(request)) return json({ error: "invalid_origin" }, 403);
  const token = request.cookies.get(COOKIE)?.value;
  let status = 200;
  if (token) {
    const requestId = randomUUID();
    const body = Buffer.from("{}");
    const base = process.env.PRISM_API_BASE_URL;
    const target = base ? controlPlaneUrl(base, ["account", "session", "revoke"]) : null;
    try {
      if (!target) throw new SessionConfigurationError();
      const identity = await signControlIdentity(token, requestId, "POST", target.pathname, body);
      const revoked = await fetch(target, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": requestId,
          "X-Prism-Subject": identity.subject,
          "X-Prism-Session-Id": identity.sessionId,
          "X-Prism-Timestamp": identity.timestamp,
          "X-Prism-Signature": identity.signature,
        },
        body,
        redirect: "manual",
        cache: "no-store",
        signal: AbortSignal.timeout(10_000),
      });
      if (!revoked.ok) status = 503;
    } catch (error) {
      if (!(error instanceof SessionValidationError)) status = 503;
    }
  }
  const response = json(status === 200 ? { ok: true } : { error: "session_revocation_unavailable" }, status);
  response.cookies.set(COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", maxAge: 0 });
  return response;
}

function json(body: Record<string, unknown>, status: number, headers?: Record<string, string>) {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}
