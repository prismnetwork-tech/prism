export type OriginRequest = {
  headers: Headers;
  nextUrl: URL;
};

export function isSameOriginRequest(request: OriginRequest) {
  const origin = request.headers.get("origin");
  if (!origin) {
    const fetchSite = request.headers.get("sec-fetch-site");
    return fetchSite === "same-origin" || fetchSite === "none";
  }
  try {
    const supplied = new URL(origin);
    const configured = process.env.PRISM_APP_ORIGIN;
    if (!configured && process.env.NODE_ENV === "production") return false;
    const expected = configured ? new URL(configured) : request.nextUrl;
    return supplied.origin === expected.origin;
  } catch {
    return false;
  }
}
