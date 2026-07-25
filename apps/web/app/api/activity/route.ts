import { NextResponse } from "next/server";
import { isPublicActivityFeed } from "@/lib/activity";

export const runtime = "nodejs";
const maxResponseBytes = 1_000_000;

export async function GET() {
  const source = process.env.PRISM_ACTIVITY_URL;
  if (!source) {
    return NextResponse.json(
      { generated_at: new Date().toISOString(), activity: [] },
      { headers: { "Cache-Control": "public, max-age=30" } },
    );
  }

  let url: URL;
  try {
    url = new URL(source);
  } catch {
    return NextResponse.json({ error: "activity_feed_unavailable" }, { status: 503 });
  }
  if (url.protocol !== "https:") {
    return NextResponse.json({ error: "activity_feed_unavailable" }, { status: 503 });
  }

  try {
    const response = await fetch(url, {
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(5_000),
    });
    const contentLength = Number(response.headers.get("content-length") ?? 0);
    if (!response.ok || contentLength > maxResponseBytes) throw new Error("invalid activity response");
    const body = await response.arrayBuffer();
    if (body.byteLength > maxResponseBytes) throw new Error("activity response is too large");
    const payload: unknown = JSON.parse(Buffer.from(body).toString("utf8"));
    if (!isPublicActivityFeed(payload)) throw new Error("invalid activity artifact");
    return NextResponse.json(payload, { headers: { "Cache-Control": "public, max-age=30" } });
  } catch {
    return NextResponse.json({ error: "activity_feed_unavailable" }, { status: 503 });
  }
}
