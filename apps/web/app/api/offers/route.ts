import { NextResponse } from "next/server";

export const runtime = "nodejs";
const maxResponseBytes = 200_000;

export type PublicOffer = {
  node_id: string;
  gpu: { model: string; vram_mib: number };
  rate_per_second: number;
  trust_class: string;
  staker_only?: boolean;
  online?: boolean;
};

function isOffer(value: unknown): value is PublicOffer {
  if (typeof value !== "object" || value === null) return false;
  const offer = value as Record<string, unknown>;
  const gpu = offer.gpu as Record<string, unknown> | undefined;
  return (
    typeof offer.node_id === "string" &&
    typeof gpu === "object" &&
    gpu !== null &&
    typeof gpu.model === "string" &&
    gpu.model.length > 0 &&
    gpu.model.length <= 64 &&
    typeof gpu.vram_mib === "number" &&
    typeof offer.rate_per_second === "number" &&
    offer.rate_per_second >= 0 &&
    typeof offer.trust_class === "string"
  );
}

function isOfferList(value: unknown): value is PublicOffer[] {
  return Array.isArray(value) && value.length <= 256 && value.every(isOffer);
}

// The offers list is public on the control plane, so this proxy exists to give
// the browser a same-origin URL and to refuse anything that is not the shape
// the page expects.
export async function GET() {
  const base = process.env.PRISM_PUBLIC_API ?? "https://api.prismnetwork.tech";
  let url: URL;
  try {
    url = new URL("/v1/offers", base);
  } catch {
    return NextResponse.json({ error: "offers_unavailable" }, { status: 503 });
  }
  if (url.protocol !== "https:") {
    return NextResponse.json({ error: "offers_unavailable" }, { status: 503 });
  }

  try {
    const response = await fetch(url, {
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error("invalid offers response");
    const body = await response.arrayBuffer();
    if (body.byteLength > maxResponseBytes) throw new Error("offers response is too large");
    const payload: unknown = JSON.parse(Buffer.from(body).toString("utf8"));
    if (!isOfferList(payload)) throw new Error("invalid offers payload");
    // Capacity turns over on the order of a minute, so a short cache keeps the
    // page current without asking the control plane on every visit.
    return NextResponse.json(payload, { headers: { "Cache-Control": "public, max-age=30" } });
  } catch {
    return NextResponse.json({ error: "offers_unavailable" }, { status: 503 });
  }
}
