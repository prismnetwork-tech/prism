import { describe, expect, it } from "vitest";
import {
  GpuCapabilityError,
  isPinnedPublicImage,
  parseGpuLaunchIntent,
  prepareGpuLeasePlan,
  summarizeGpuCapacity,
  type MarketplaceOffer,
} from "./gpu-capability";

const image = `ghcr.io/prism-network/gpu-repro@sha256:${"a".repeat(64)}`;
const sshPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFgcqV9bxjW5lu0s9eN0589FiHY0vZpg7Yi+mlw73P9h prism-repro";
const canonicalSshPublicKey = sshPublicKey.slice(0, sshPublicKey.lastIndexOf(" "));
const offers: MarketplaceOffer[] = [
  {
    node_id: `0x${"1".repeat(64)}`,
    gpu: { model: "RTX A6000", vram_mib: 24_576, cuda_major: 12 },
    rate_per_second: 120,
    reliability_bps: 9_900,
    benchmark_score: 8_000,
  },
  {
    node_id: `0x${"2".repeat(64)}`,
    gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
    rate_per_second: 222,
    reliability_bps: 9_800,
    benchmark_score: 10_000,
  },
  {
    node_id: `0x${"3".repeat(64)}`,
    gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
    rate_per_second: 177,
    reliability_bps: 9_900,
    benchmark_score: 10_100,
    staker_only: true,
  },
];

describe("GPU capability planning", () => {
  it("prepares a bounded approval URL without creating a lease", () => {
    const plan = prepareGpuLeasePlan(offers, {
      image,
      durationMinutes: 30,
      minVramGib: 40,
      sshPublicKey,
    }, new URL("https://prism.example"));

    expect(plan.estimatedGpu.model).toBe("L40S");
    expect(plan.maximumEscrowUsdg).toBe("0.3996");
    expect(parseGpuLaunchIntent(new URL(plan.approvalUrl).searchParams)).toEqual({
      image,
      durationSeconds: 1_800,
      minVramMib: 40_960,
      sshPublicKey: canonicalSshPublicKey,
    });
  });

  it("fails explicitly when matching capacity is unavailable", () => {
    expect(() => prepareGpuLeasePlan(offers, {
      image,
      durationMinutes: 30,
      minVramGib: 80,
      sshPublicKey,
    }, new URL("https://prism.example"))).toThrowError(GpuCapabilityError);
  });

  it("rejects mutable and private-registry images", () => {
    expect(isPinnedPublicImage("ghcr.io/prism-network/gpu-repro:latest")).toBe(false);
    expect(isPinnedPublicImage(`127.0.0.1/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(`https://ghcr.io/prism-network/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(image)).toBe(true);
  });

  it("rejects malformed SSH keys and removes key comments from launch URLs", () => {
    expect(() => prepareGpuLeasePlan(offers, {
      image,
      durationMinutes: 30,
      minVramGib: 40,
      sshPublicKey: "ssh-ed25519 AAAA not-a-key",
    }, new URL("https://prism.example"))).toThrowError(GpuCapabilityError);

    const plan = prepareGpuLeasePlan(offers, {
      image,
      durationMinutes: 30,
      minVramGib: 40,
      sshPublicKey,
    }, new URL("https://prism.example"));
    expect(plan.sshPublicKey).toBe(canonicalSshPublicKey);
    expect(plan.approvalUrl).not.toContain("prism-repro");
  });

  it("summarizes capacity without operational node identifiers", () => {
    const summary = summarizeGpuCapacity(offers);
    expect(summary).toHaveLength(2);
    expect(JSON.stringify(summary)).not.toContain(offers[0].node_id);
    expect(summary[0]).toMatchObject({ model: "RTX A6000", fromUsdgPerHour: "0.432" });
    expect(summary.find((item) => item.model === "L40S")).toMatchObject({
      available: 1,
      fromUsdgPerHour: "0.7992",
    });
  });
});
