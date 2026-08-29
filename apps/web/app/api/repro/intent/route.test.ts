import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createReproIntent } from "@/lib/repro-intent";
import { POST } from "./route";

const spec = {
  image: `pytorch/pytorch@sha256:${"a".repeat(64)}`,
  command: "nvidia-smi --query-gpu=name --format=csv,noheader",
  duration_seconds: 1_800,
  min_vram_mib: 40_960,
  expected_exit_code: 0,
};

beforeEach(() => {
  process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT = "1";
  process.env.PRISM_CONTROL_PLANE_AUTH_KEY = "42".repeat(32);
});

afterEach(() => {
  delete process.env.PRISM_ALLOW_DEVELOPMENT_RATE_LIMIT;
  delete process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
});

describe("POST /api/repro/intent", () => {
  it("returns an immutable verified payload without the raw read token", async () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("http://localhost"));
    const response = await POST(request(intent.envelope));
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(payload).toMatchObject({ ...spec, version: "prism.gpu-repro.intent.v2" });
    expect(JSON.stringify(payload)).not.toContain(intent.reproToken);
  });

  it("rejects a tampered envelope", async () => {
    const intent = createReproIntent(spec, "managed", 399_600n, new URL("http://localhost"));
    const changed = `${intent.envelope.slice(0, -1)}${intent.envelope.endsWith("a") ? "b" : "a"}`;
    const response = await POST(request(changed));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_intent" });
  });
});

function request(envelope: string) {
  return new NextRequest("http://localhost/api/repro/intent", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "http://localhost" },
    body: JSON.stringify({ envelope }),
  });
}
