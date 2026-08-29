import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  gpuLeaseDurations,
  isGpuReproCommand,
  isPinnedPublicImage,
  type GpuReproSpec,
} from "./gpu-capability";

const intentVersion = "prism.gpu-repro.intent.v1";
const intentKeyDomain = "prism-gpu-repro-intent-key-v1\0";
const specDomain = "prism-gpu-repro-spec-v1\0";
const tokenBytes = 32;
const intentTtlSeconds = 30 * 60;
const maxEnvelopeBytes = 8 * 1_024;

export type ReproIntentPayload = GpuReproSpec & {
  version: typeof intentVersion;
  maximum_escrow: string;
  token_hash: string;
  spec_hash: string;
  issued_at: number;
  expires_at: number;
};

export class ReproIntentError extends Error {
  constructor(readonly code: "configuration" | "invalid" | "expired") {
    super(code);
  }
}

export function createReproIntent(
  spec: GpuReproSpec,
  maximumEscrow: bigint,
  origin: URL,
  now = new Date(),
) {
  validateSpec(spec);
  if (maximumEscrow <= 0n) throw new ReproIntentError("invalid");

  const token = randomBytes(tokenBytes);
  const issuedAt = Math.floor(now.getTime() / 1_000);
  const payload: ReproIntentPayload = {
    version: intentVersion,
    image: spec.image,
    command: spec.command,
    duration_seconds: spec.duration_seconds,
    min_vram_mib: spec.min_vram_mib,
    expected_exit_code: spec.expected_exit_code,
    maximum_escrow: maximumEscrow.toString(),
    token_hash: hashReproToken(token),
    spec_hash: hashReproSpec(spec),
    issued_at: issuedAt,
    expires_at: issuedAt + intentTtlSeconds,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(encoded);
  const envelope = `${encoded}.${signature}`;
  const approvalUrl = new URL("/compute", origin);
  approvalUrl.hash = `repro=${encodeURIComponent(envelope)}`;

  return {
    approvalUrl: approvalUrl.toString(),
    envelope,
    payload,
    reproToken: token.toString("base64url"),
  };
}

export function verifyReproIntent(envelope: string, now = new Date()): ReproIntentPayload {
  if (!envelope || Buffer.byteLength(envelope, "utf8") > maxEnvelopeBytes) {
    throw new ReproIntentError("invalid");
  }
  const [encoded, supplied, extra] = envelope.split(".");
  if (!encoded || !supplied || extra !== undefined || !isBase64Url(encoded) || !isBase64Url(supplied)) {
    throw new ReproIntentError("invalid");
  }
  const expected = Buffer.from(sign(encoded), "base64url");
  const signature = decodeBase64Url(supplied);
  if (!signature || signature.length !== expected.length || !timingSafeEqual(signature, expected)) {
    throw new ReproIntentError("invalid");
  }

  let value: unknown;
  try {
    const raw = Buffer.from(encoded, "base64url");
    if (raw.length > maxEnvelopeBytes) throw new Error("oversized");
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new ReproIntentError("invalid");
  }
  if (!isReproIntentPayload(value)) throw new ReproIntentError("invalid");
  if (value.expires_at <= Math.floor(now.getTime() / 1_000)) throw new ReproIntentError("expired");
  if (value.issued_at > Math.floor(now.getTime() / 1_000) + 60) throw new ReproIntentError("invalid");
  if (value.spec_hash !== hashReproSpec(value)) throw new ReproIntentError("invalid");
  return value;
}

export function hashReproSpec(spec: GpuReproSpec) {
  const canonical = JSON.stringify({
    image: spec.image,
    command: spec.command,
    duration_seconds: spec.duration_seconds,
    min_vram_mib: spec.min_vram_mib,
    expected_exit_code: spec.expected_exit_code,
  });
  return createHash("sha256").update(specDomain).update(canonical).digest("hex");
}

export function parseReproToken(value: string) {
  const token = decodeBase64Url(value);
  if (!token || token.length !== tokenBytes || token.toString("base64url") !== value) {
    throw new ReproIntentError("invalid");
  }
  return token;
}

export function hashReproToken(value: string | Buffer) {
  const token = typeof value === "string" ? parseReproToken(value) : value;
  if (token.length !== tokenBytes) throw new ReproIntentError("invalid");
  return createHash("sha256").update(token).digest("hex");
}

function sign(encoded: string) {
  return createHmac("sha256", intentKey()).update(encoded).digest("base64url");
}

function intentKey() {
  const configured = process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
  if (!configured || !/^[0-9a-f]{64,}$/i.test(configured) || configured.length % 2 !== 0) {
    throw new ReproIntentError("configuration");
  }
  const root = Buffer.from(configured, "hex");
  return createHmac("sha256", root).update(intentKeyDomain).digest();
}

function isReproIntentPayload(value: unknown): value is ReproIntentPayload {
  if (!value || typeof value !== "object") return false;
  const payload = value as Partial<ReproIntentPayload>;
  const exactKeys = [
    "version",
    "image",
    "command",
    "duration_seconds",
    "min_vram_mib",
    "expected_exit_code",
    "maximum_escrow",
    "token_hash",
    "spec_hash",
    "issued_at",
    "expires_at",
  ];
  if (Object.keys(value).length !== exactKeys.length || exactKeys.some((key) => !Object.hasOwn(value, key))) {
    return false;
  }
  if (payload.version !== intentVersion) return false;
  try {
    validateSpec(payload as GpuReproSpec);
  } catch {
    return false;
  }
  return typeof payload.maximum_escrow === "string"
    && /^[1-9][0-9]{0,19}$/.test(payload.maximum_escrow)
    && isHash(payload.token_hash)
    && isHash(payload.spec_hash)
    && Number.isSafeInteger(payload.issued_at)
    && Number.isSafeInteger(payload.expires_at)
    && Number(payload.expires_at) > Number(payload.issued_at)
    && Number(payload.expires_at) - Number(payload.issued_at) === intentTtlSeconds;
}

function validateSpec(spec: GpuReproSpec) {
  if (!isPinnedPublicImage(spec.image)
    || !isGpuReproCommand(spec.command)
    || !gpuLeaseDurations.includes((spec.duration_seconds / 60) as (typeof gpuLeaseDurations)[number])
    || !Number.isSafeInteger(spec.min_vram_mib)
    || spec.min_vram_mib < 1_024
    || spec.min_vram_mib > 196_608
    || !Number.isSafeInteger(spec.expected_exit_code)
    || spec.expected_exit_code < 0
    || spec.expected_exit_code > 255) {
    throw new ReproIntentError("invalid");
  }
}

function decodeBase64Url(value: string) {
  if (!isBase64Url(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.toString("base64url") === value ? decoded : null;
  } catch {
    return null;
  }
}

function isBase64Url(value: string) {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
