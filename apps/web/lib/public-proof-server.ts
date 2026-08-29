import { isPublicProofIndex, type PublicProofIndex } from "./proof";

const defaultProofIndex = "https://api.prismnetwork.tech/proof/index.json";
const maxResponseBytes = 1_000_000;

export async function loadPublicProofIndex(
  source = process.env.PRISM_PROOF_INDEX_URL ?? defaultProofIndex,
): Promise<PublicProofIndex> {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    throw new Error("Public proof is unavailable.");
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error("Public proof is unavailable.");
  }

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    redirect: "manual",
    signal: AbortSignal.timeout(5_000),
  });
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (!response.ok || contentLength > maxResponseBytes) throw new Error("Public proof is unavailable.");
  const body = await response.arrayBuffer();
  if (body.byteLength > maxResponseBytes) throw new Error("Public proof is unavailable.");
  const payload: unknown = JSON.parse(Buffer.from(body).toString("utf8"));
  if (!isPublicProofIndex(payload)) throw new Error("Public proof returned an invalid response.");
  return payload;
}
