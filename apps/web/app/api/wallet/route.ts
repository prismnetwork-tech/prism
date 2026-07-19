import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { SessionConfigurationError, SessionValidationError, verifyPrivySession } from "@/lib/server-auth";
import { isSameOriginRequest } from "@/lib/server-origin";
import { consumeOneTime, registerOneTime, takeRateLimit } from "@/lib/server-rate-limit";
import { authorizePreparedCalls, injectSponsorship, parseWalletRpc, preparedCallsFingerprint, WalletProxyError } from "@/lib/wallet-proxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
const maxBodyBytes = 256 * 1_024;
const maxResponseBytes = 1_000_000;
const preparedCookie = "prism-prepared";

export async function POST(request: NextRequest) {
  const requestId = request.headers.get("x-request-id") ?? randomUUID();
  try {
    if (!isSameOriginRequest(request)) throw new WalletProxyError(403, "invalid_origin", "Request origin is not allowed.");
    if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new WalletProxyError(415, "unsupported_media_type", "JSON is required.");
    if (Number(request.headers.get("content-length") ?? "0") > maxBodyBytes) throw new WalletProxyError(413, "request_too_large", "Wallet request is too large.");
    const token = request.cookies.get("prism-token")?.value;
    if (!token) throw new WalletProxyError(401, "authentication_required", "Sign in to continue.");
    const session = await verifyPrivySession(token);
    const limit = await takeRateLimit("wallet", session.sessionId, 90, 60_000);
    if (!limit.available) return jsonError(503, "rate_limit_unavailable", "Rate limiting is temporarily unavailable.", requestId);
    if (!limit.allowed) return jsonError(429, "rate_limited", "Too many wallet requests.", requestId, limit.retryAfter);
    const text = await request.text();
    if (Buffer.byteLength(text) > maxBodyBytes) throw new WalletProxyError(413, "request_too_large", "Wallet request is too large.");
    const rpc = parseWalletRpc(JSON.parse(text));
    if (rpc.method === "wallet_sendPreparedCalls") {
      const sendLimit = await takeRateLimit("wallet-send", session.sessionId, 12, 60_000);
      if (!sendLimit.available) return jsonError(503, "rate_limit_unavailable", "Rate limiting is temporarily unavailable.", requestId);
      if (!sendLimit.allowed) return jsonError(429, "rate_limited", "Too many submitted wallet operations.", requestId, sendLimit.retryAfter);
      const preparedAuthorization = request.cookies.get(preparedCookie)?.value;
      verifyPreparedAuthorization(
        preparedAuthorization,
        session.sessionId,
        preparedCallsFingerprint(rpc.params[0]),
      );
      const consumed = await consumeOneTime("wallet-prepared", preparedAuthorization ?? "");
      if (!consumed.available) throw new WalletProxyError(503, "wallet_unavailable", "Wallet authorization is temporarily unavailable.");
      if (!consumed.consumed) throw new WalletProxyError(403, "unprepared_calls", "Prepared wallet calls have already been used.");
    }
    const apiKey = process.env.PRISM_ALCHEMY_API_KEY;
    const policyId = process.env.PRISM_ALCHEMY_POLICY_ID;
    if (!apiKey || !policyId) throw new WalletProxyError(503, "wallet_unavailable", "Sponsored wallet operations are not configured.");
    authorizePreparedCalls(rpc);
    const upstream = injectSponsorship(rpc, policyId);
    const response = await fetch(process.env.PRISM_ALCHEMY_WALLET_RPC_URL ?? `https://api.g.alchemy.com/v2/${apiKey}`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(upstream),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.headers.get("content-type")?.includes("application/json")) throw new WalletProxyError(502, "wallet_provider_error", "Wallet provider returned an invalid response.");
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > maxResponseBytes) throw new WalletProxyError(502, "wallet_provider_error", "Wallet provider response is too large.");
    const responseBody = await response.arrayBuffer();
    if (responseBody.byteLength > maxResponseBytes) throw new WalletProxyError(502, "wallet_provider_error", "Wallet provider response is too large.");
    const output = new NextResponse(responseBody, {
      status: response.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Request-Id": requestId },
    });
    if (rpc.method === "wallet_prepareCalls" && response.ok) {
      let payload: { result?: unknown };
      try {
        payload = JSON.parse(Buffer.from(responseBody).toString("utf8")) as { result?: unknown };
      } catch {
        throw new WalletProxyError(502, "wallet_provider_error", "Wallet provider returned invalid JSON.");
      }
      if (payload.result && typeof payload.result === "object" && (payload.result as { type?: unknown }).type !== "paymaster-permit") {
        const authorization = createPreparedAuthorization(session.sessionId, preparedCallsFingerprint(payload.result));
        const stored = await registerOneTime("wallet-prepared", authorization, 120_000);
        if (!stored.available) throw new WalletProxyError(503, "wallet_unavailable", "Wallet authorization is temporarily unavailable.");
        if (!stored.stored) throw new WalletProxyError(502, "wallet_proxy_error", "Wallet authorization could not be recorded.");
        output.cookies.set(
          preparedCookie,
          authorization,
          cookieOptions(120),
        );
      }
    } else if (rpc.method === "wallet_sendPreparedCalls") {
      output.cookies.set(preparedCookie, "", cookieOptions(0));
    }
    return output;
  } catch (error) {
    const failure = error instanceof WalletProxyError
      ? error
      : error instanceof SessionConfigurationError
        ? new WalletProxyError(503, "authentication_unavailable", "Session verification is not configured.")
        : error instanceof SessionValidationError
          ? new WalletProxyError(401, "invalid_session", "Your session is invalid or expired.")
          : error instanceof SyntaxError
            ? new WalletProxyError(400, "invalid_json", "Wallet request is not valid JSON.")
            : new WalletProxyError(502, "wallet_proxy_error", "Wallet operation could not be completed.");
    console.error(JSON.stringify({ event: "wallet_proxy_failed", requestId, code: failure.code, status: failure.status }));
    return jsonError(failure.status, failure.code, failure.message, requestId);
  }
}

function createPreparedAuthorization(sessionId: string, fingerprint: string) {
  const expires = Math.floor(Date.now() / 1_000) + 120;
  const payload = `${sessionId}.${expires}.${fingerprint}`;
  return `${expires}.${fingerprint}.${signPreparedPayload(payload)}`;
}

function verifyPreparedAuthorization(token: string | undefined, sessionId: string, fingerprint: string) {
  const parts = token?.split(".");
  if (!parts || parts.length !== 3 || !/^[0-9a-f]{64}$/.test(parts[1]) || !/^[0-9a-f]{64}$/.test(parts[2])) {
    throw new WalletProxyError(403, "unprepared_calls", "Wallet calls must be prepared by this session.");
  }
  const expires = Number(parts[0]);
  const now = Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(expires) || expires < now || expires > now + 180 || parts[1] !== fingerprint) {
    throw new WalletProxyError(403, "unprepared_calls", "Prepared wallet calls have expired or changed.");
  }
  const expected = Buffer.from(signPreparedPayload(`${sessionId}.${expires}.${fingerprint}`), "hex");
  const supplied = Buffer.from(parts[2], "hex");
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
    throw new WalletProxyError(403, "unprepared_calls", "Prepared wallet authorization is invalid.");
  }
}

function signPreparedPayload(payload: string) {
  const key = process.env.PRISM_WALLET_AUTH_KEY;
  if (!key || !/^[0-9a-f]{64,}$/i.test(key)) {
    throw new WalletProxyError(503, "wallet_unavailable", "Wallet authorization is not configured.");
  }
  return createHmac("sha256", Buffer.from(key, "hex")).update(payload).digest("hex");
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict" as const,
    path: "/api/wallet",
    maxAge,
  };
}

function jsonError(status: number, code: string, message: string, requestId: string, retryAfter?: number) {
  const response = NextResponse.json({ error: code, message }, { status, headers: { "X-Request-Id": requestId, "Cache-Control": "no-store" } });
  if (retryAfter) response.headers.set("Retry-After", String(retryAfter));
  return response;
}
