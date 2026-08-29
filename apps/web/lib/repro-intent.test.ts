import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ReproIntentError,
  createReproIntent,
  hashReproSpec,
  hashReproToken,
  verifyReproIntent,
} from "./repro-intent";

const now = new Date("2026-08-29T12:00:00.000Z");
const spec = {
  image: `pytorch/pytorch@sha256:${"a".repeat(64)}`,
  command: "python -c 'import torch; print(torch.cuda.get_device_name())'",
  duration_seconds: 1_800,
  min_vram_mib: 40_960,
  expected_exit_code: 0,
};

beforeEach(() => {
  process.env.PRISM_CONTROL_PLANE_AUTH_KEY = "42".repeat(32);
});

afterEach(() => {
  delete process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
});

describe("GPU repro approval intents", () => {
  it("matches the protocol v1 spec-hash reference vector", () => {
    expect(hashReproSpec({
      image: `registry.example/runtime@sha256:${"a".repeat(64)}`,
      command: "python -c 'print(6 * 7)'",
      duration_seconds: 120,
      min_vram_mib: 1_024,
      expected_exit_code: 0,
    })).toBe("23979781f1379272e8d5c6b036708792e060ac88b3cb78fbd2f8e62bed7a79ed");
  });

  it("hashes the decoded token bytes exactly like the protocol", () => {
    expect(hashReproToken("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"))
      .toBe("4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0");
  });

  it("binds the exact spec, cap, token hash, and expiry", () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("https://prism.example"), now);
    const verified = verifyReproIntent(intent.envelope, new Date(now.getTime() + 60_000));

    expect(verified).toMatchObject({
      ...spec,
      version: "prism.gpu-repro.intent.v2",
      executor: "managed",
      maximum_escrow: "399600",
      spec_hash: hashReproSpec(spec),
      token_hash: hashReproToken(intent.reproToken),
      issued_at: Math.floor(now.getTime() / 1_000),
      expires_at: Math.floor(now.getTime() / 1_000) + 1_800,
    });
    expect(intent.approvalUrl).toContain("/compute#repro=");
    expect(intent.approvalUrl).not.toContain(intent.reproToken);
  });

  it("does not accept the unpublished v1 intent contract", () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("https://prism.example"), now);
    const [encoded] = intent.envelope.split(".");
    const legacy = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    legacy.version = "prism.gpu-repro.intent.v1";
    const legacyEncoded = Buffer.from(JSON.stringify(legacy)).toString("base64url");
    const root = Buffer.from(process.env.PRISM_CONTROL_PLANE_AUTH_KEY!, "hex");
    const legacyKey = createHmac("sha256", root).update("prism-gpu-repro-intent-key-v1\0").digest();
    const legacySignature = createHmac("sha256", legacyKey).update(legacyEncoded).digest("base64url");

    expect(() => verifyReproIntent(`${legacyEncoded}.${legacySignature}`, now)).toThrowError(ReproIntentError);
  });

  it("rejects a payload changed after signing", () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("https://prism.example"), now);
    const [encoded, signature] = intent.envelope.split(".");
    const changed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    changed.command = "curl https://example.invalid";
    const tampered = `${Buffer.from(JSON.stringify(changed)).toString("base64url")}.${signature}`;

    expect(() => verifyReproIntent(tampered, now)).toThrowError(ReproIntentError);
  });

  it("rejects an expired envelope", () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("https://prism.example"), now);
    expect(() => verifyReproIntent(
      intent.envelope,
      new Date(now.getTime() + 30 * 60_000),
    )).toThrowError(expect.objectContaining({ code: "expired" }));
  });

  it("requires a dedicated key derived from the control-plane secret", () => {
    delete process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
    expect(() => createReproIntent(spec, "managed", 399_600n, new URL("https://prism.example"), now))
      .toThrowError(expect.objectContaining({ code: "configuration" }));
  });
});
