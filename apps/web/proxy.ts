import { NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const policy = contentSecurityPolicy(nonce, process.env.NODE_ENV === "development");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("Content-Security-Policy", policy);
  requestHeaders.set("x-nonce", nonce);

  const hostname = request.headers.get("host")?.split(":", 1)[0] || request.nextUrl.hostname;
  const rewrite = publicPageRewrite(hostname, request.nextUrl.pathname);
  const response = rewrite
    ? NextResponse.rewrite(new URL(rewrite, request.url), { request: { headers: requestHeaders } })
    : NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export function publicPageRewrite(hostname: string, pathname: string) {
  return hostname.toLowerCase() === "docs.prismnetwork.tech" && pathname === "/"
    ? "/docs"
    : null;
}

export function contentSecurityPolicy(nonce: string, development: boolean) {
  const script = [
    "'self'",
    `'nonce-${nonce}'`,
    "'strict-dynamic'",
    development ? "'unsafe-eval'" : "",
  ].filter(Boolean).join(" ");

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src ${script}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://explorer-api.walletconnect.com",
    "font-src 'self'",
    "worker-src 'self' blob:",
    "frame-src https://auth.privy.io https://*.privy.io",
    [
      "connect-src 'self'",
      "https://rpc.mainnet.chain.robinhood.com",
      "https://robinhood-mainnet.g.alchemy.com",
      "https://api.g.alchemy.com",
      "https://*.privy.io",
      "wss://*.privy.io",
      "https://*.walletconnect.com",
      "wss://*.walletconnect.com",
    ].join(" "),
    "manifest-src 'self'",
    "media-src 'self' blob:",
    "upgrade-insecure-requests",
  ].join("; ");
}

export const config = {
  matcher: [{
    source: "/((?!_next/static|_next/image|favicon.ico|icons/|brand/).*)",
  }],
};
