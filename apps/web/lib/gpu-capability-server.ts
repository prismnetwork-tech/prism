import { isMarketplaceOffer, type MarketplaceOffer } from "./gpu-capability";

const maxOffers = 1_000;
const maxResponseBytes = 1_000_000;

export async function loadGpuOffers(): Promise<MarketplaceOffer[]> {
  const base = process.env.PRISM_PUBLIC_API ?? "https://api.prismnetwork.tech";
  let url: URL;
  try {
    url = new URL("/v1/offers", base);
  } catch {
    throw new Error("GPU capacity is unavailable.");
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error("GPU capacity is unavailable.");
  }

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    redirect: "manual",
    signal: AbortSignal.timeout(5_000),
  });
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (!response.ok || contentLength > maxResponseBytes) throw new Error("GPU capacity is unavailable.");
  const body = await response.arrayBuffer();
  if (body.byteLength > maxResponseBytes) throw new Error("GPU capacity is unavailable.");
  const payload: unknown = JSON.parse(Buffer.from(body).toString("utf8"));
  if (!Array.isArray(payload) || payload.length > maxOffers || !payload.every(isMarketplaceOffer)) {
    throw new Error("GPU capacity returned an invalid response.");
  }
  return payload;
}
