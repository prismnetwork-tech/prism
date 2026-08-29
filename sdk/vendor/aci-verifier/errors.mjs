// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// Errors raised for conditions that are not ordinary verification failures. A
// failed check (bad signature, wrong hash) is reported as `ok: false` in the
// result objects and never thrown, so a caller cannot pass by forgetting a
// try/catch. These errors mean the input is malformed.

export class AciError extends Error {
  constructor(message) {
    super(message);
    this.name = "AciError";
  }
}

/// A value would not parse (hex, base64, JSON) or violates a spec-pinned format.
export class AciFormatError extends AciError {
  constructor(message) {
    super(message);
    this.name = "AciFormatError";
  }
}
