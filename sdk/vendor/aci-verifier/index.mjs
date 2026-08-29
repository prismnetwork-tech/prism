// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// The ACI check layer: the digest constructions (Appendix A, §3.1, §3.2),
// report binding and the hardware quote (§9.1), receipts and body hashes
// (§9.3), and attested sessions (§8, §9.2). Prism's own transcript (which
// checks run, which are honest skips, and what the verdict means) lives in
// ../../attest.mjs; the upstream `transcript.ts` renders a different one and is
// not ported.
export { AciError, AciFormatError } from "./errors.mjs";
export {
  fromBase64,
  fromHex,
  jcsBytes,
  sha256,
  sha256Hex,
  sha256Prefixed,
  sha384,
  toBase64,
  toHex,
  verifyEd25519,
} from "./crypto.mjs";
export { attestationStatement, computeKeysetDigest, computeReportData } from "./digest.mjs";
export {
  quoteReportData,
  replayRtmr3,
  verifyComposeMeasurement,
  verifyQuote,
  verifyRawQuote,
  verifyReportBinding,
} from "./report.mjs";
export { checkRequestBodyHash, checkResponseBodyHash, findEvent, hashBody, verifyReceipt } from "./receipt.mjs";
export { checkSessionApiVersion, checkSessionEvidence, computeSessionId } from "./session.mjs";
