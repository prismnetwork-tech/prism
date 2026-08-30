// What a payer signs on the legacy rail, where the transfer is already on-chain
// and the header only says who made it.
//
// Signing the transaction hash alone proves who paid, not what they paid for.
// Anyone who saw the header in flight could put their own command or prompt in
// front of it and spend someone else's transfer, so the request travels inside
// the signed message and the server checks it against the request that arrived.
//
// The definition lives here because @prismnetwork/x402 depends on this package
// and not the other way round. Its codec re-exports both, so a server and its
// clients read the same two lines.
import { createHash } from "node:crypto";

/// The digest both sides compare: the command for a job, the request bytes for
/// a generation. Text is hashed as UTF-8, which is how it goes on the wire.
export function hashRequest(payload) {
  const bytes = typeof payload === "string" ? Buffer.from(payload, "utf8") : payload;
  return createHash("sha256").update(bytes).digest("hex");
}

export function boundMessage(txHash, requestHash) {
  return `prism-x402:v2\n${String(txHash).toLowerCase()}\n${requestHash}`;
}
