import { describe, expect, it } from "vitest";
import {
  GpuCapabilityError,
  isGpuReproCommand,
  isPinnedPublicImage,
  prepareGpuLeasePlan,
  summarizeGpuCapacity,
  type MarketplaceOffer,
} from "./gpu-capability";

const image = `ghcr.io/prism-network/gpu-repro@sha256:${"a".repeat(64)}`;
const command = "python -c 'import torch; assert torch.cuda.is_available()'";
const offers: MarketplaceOffer[] = [
  {
    node_id: `0x${"1".repeat(64)}`,
    gpu: { model: "RTX A6000", vram_mib: 24_576, cuda_major: 12 },
    rate_per_second: 120,
    reliability_bps: 9_900,
    benchmark_score: 8_000,
    managed_batch: true,
  },
  {
    node_id: `0x${"2".repeat(64)}`,
    gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
    rate_per_second: 222,
    reliability_bps: 9_800,
    benchmark_score: 10_000,
    managed_batch: true,
  },
  {
    node_id: `0x${"3".repeat(64)}`,
    gpu: { model: "L40S", vram_mib: 46_068, cuda_major: 12 },
    rate_per_second: 177,
    reliability_bps: 9_900,
    benchmark_score: 10_100,
    staker_only: true,
    managed_batch: true,
  },
];

describe("GPU capability planning", () => {
  it("prepares a bounded immutable repro specification", () => {
    const plan = prepareGpuLeasePlan(offers, {
      image,
      command,
      durationMinutes: 30,
      minVramGib: 40,
      expectedExitCode: 0,
    });

    expect(plan.estimatedGpu.model).toBe("L40S");
    expect(plan.maximumEscrowUsdg).toBe("0.3996");
    expect(plan).toMatchObject({
      image,
      command,
      duration_seconds: 1_800,
      min_vram_mib: 40_960,
      expected_exit_code: 0,
    });
  });

  it("fails explicitly when matching capacity is unavailable", () => {
    expect(() => prepareGpuLeasePlan(offers, {
      image,
      command,
      durationMinutes: 30,
      minVramGib: 80,
      expectedExitCode: 0,
    })).toThrowError(GpuCapabilityError);
  });

  it("does not quote an offer with no executable batch path", () => {
    const interactiveOnly = {
      ...offers[0],
      command_channel: false,
      managed_batch: false,
    };
    expect(() => prepareGpuLeasePlan([interactiveOnly], {
      image,
      command,
      durationMinutes: 30,
      minVramGib: 1,
      expectedExitCode: 0,
    })).toThrowError(/repro-capable/);
  });

  it("rejects mutable and private-registry images", () => {
    expect(isPinnedPublicImage("ghcr.io/prism-network/gpu-repro:latest")).toBe(false);
    expect(isPinnedPublicImage(`127.0.0.1/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(`registry.example/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(`docker.io/library/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(true);
    expect(isPinnedPublicImage(`docker.io/library/gpu-repro@sha256:${"A".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(`https://ghcr.io/prism-network/gpu-repro@sha256:${"a".repeat(64)}`)).toBe(false);
    expect(isPinnedPublicImage(image)).toBe(true);
  });

  it("rejects empty, null-containing, and oversized commands", () => {
    expect(isGpuReproCommand(command)).toBe(true);
    expect(isGpuReproCommand("  ")).toBe(false);
    expect(isGpuReproCommand("echo\0oops")).toBe(false);
    expect(isGpuReproCommand("é".repeat(1_025))).toBe(false);

    expect(() => prepareGpuLeasePlan(offers, {
      image,
      command: " ",
      durationMinutes: 30,
      minVramGib: 40,
      expectedExitCode: 0,
    })).toThrowError(GpuCapabilityError);
  });

  it("summarizes capacity without operational node identifiers", () => {
    const summary = summarizeGpuCapacity(offers);
    expect(summary).toHaveLength(2);
    expect(JSON.stringify(summary)).not.toContain(offers[0].node_id);
    expect(summary[0]).toMatchObject({ model: "RTX A6000", fromUsdgPerHour: "0.432" });
    expect(summary.find((item) => item.model === "L40S")).toMatchObject({
      available: 1,
      fromUsdgPerHour: "0.7992",
      managedRepro: true,
      deviceRepro: false,
    });
  });
});
