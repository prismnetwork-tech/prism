export const gpuLeaseDurations = [30, 60, 120, 360] as const;
export const maxGpuReproCommandBytes = 2 * 1_024;

export type MarketplaceOffer = {
  node_id: `0x${string}`;
  gpu: {
    model: string;
    vram_mib: number;
    cuda_major: number;
  };
  rate_per_second: number;
  reliability_bps: number;
  benchmark_score?: number;
  staker_only?: boolean;
  command_channel?: boolean;
  managed_batch?: boolean;
};

export type GpuReproSpec = {
  image: string;
  command: string;
  duration_seconds: number;
  min_vram_mib: number;
  expected_exit_code: number;
};

export type GpuLeasePlan = GpuReproSpec & {
  estimatedGpu: {
    model: string;
    vramMib: number;
    cudaMajor: number;
  };
  estimatedExecutor: "node" | "managed";
  maximumEscrowBaseUnits: bigint;
  maximumEscrowUsdg: string;
};

export class GpuCapabilityError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export function prepareGpuLeasePlan(
  offers: MarketplaceOffer[],
  input: {
    image: string;
    command: string;
    durationMinutes: number;
    minVramGib: number;
    expectedExitCode: number;
  },
): GpuLeasePlan {
  if (!isPinnedPublicImage(input.image)) {
    throw new GpuCapabilityError(
      "invalid_image",
      "Use a public OCI image pinned to an immutable sha256 digest.",
    );
  }
  if (!gpuLeaseDurations.includes(input.durationMinutes as (typeof gpuLeaseDurations)[number])) {
    throw new GpuCapabilityError(
      "invalid_duration",
      `Duration must be one of ${gpuLeaseDurations.join(", ")} minutes.`,
    );
  }
  if (!Number.isSafeInteger(input.minVramGib) || input.minVramGib < 1 || input.minVramGib > 192) {
    throw new GpuCapabilityError("invalid_vram", "Minimum GPU memory must be between 1 and 192 GiB.");
  }
  if (!isGpuReproCommand(input.command)) {
    throw new GpuCapabilityError(
      "invalid_command",
      `Command must be non-empty and at most ${maxGpuReproCommandBytes / 1_024} KiB.`,
    );
  }
  if (!Number.isSafeInteger(input.expectedExitCode) || input.expectedExitCode < 0 || input.expectedExitCode > 255) {
    throw new GpuCapabilityError("invalid_exit_code", "Expected exit code must be between 0 and 255.");
  }

  const minVramMib = input.minVramGib * 1_024;
  const eligible = offers
    .filter(isGenerallyAvailableOffer)
    .filter(canRunRepro)
    .filter((offer) => offer.gpu.vram_mib >= minVramMib)
    .sort(compareOffers);
  const offer = eligible[0];
  if (!offer) {
    throw new GpuCapabilityError(
      "capacity_unavailable",
      `No live repro-capable GPU offer meets the ${input.minVramGib} GiB minimum.`,
    );
  }

  const durationSeconds = input.durationMinutes * 60;
  const maximumEscrowBaseUnits = BigInt(offer.rate_per_second) * BigInt(durationSeconds);

  return {
    image: input.image,
    command: input.command,
    duration_seconds: durationSeconds,
    min_vram_mib: minVramMib,
    expected_exit_code: input.expectedExitCode,
    estimatedGpu: {
      model: offer.gpu.model,
      vramMib: offer.gpu.vram_mib,
      cudaMajor: offer.gpu.cuda_major,
    },
    estimatedExecutor: offer.managed_batch === true ? "managed" : "node",
    maximumEscrowBaseUnits,
    maximumEscrowUsdg: formatUsdg(maximumEscrowBaseUnits),
  };
}

export function summarizeGpuCapacity(offers: MarketplaceOffer[]) {
  const groups = new Map<string, {
    model: string;
    vramGib: number;
    cudaMajor: number;
    available: number;
    minimumRatePerSecond: number;
    maximumReliabilityBps: number;
    managedRepro: boolean;
    deviceRepro: boolean;
  }>();
  for (const offer of offers) {
    if (!isGenerallyAvailableOffer(offer)) continue;
    const key = [offer.gpu.model, offer.gpu.vram_mib, offer.gpu.cuda_major].join("\0");
    const current = groups.get(key);
    if (current) {
      current.available += 1;
      current.minimumRatePerSecond = Math.min(current.minimumRatePerSecond, offer.rate_per_second);
      current.maximumReliabilityBps = Math.max(current.maximumReliabilityBps, offer.reliability_bps);
      current.managedRepro ||= offer.managed_batch === true;
      current.deviceRepro ||= offer.command_channel === true;
      continue;
    }
    groups.set(key, {
      model: offer.gpu.model,
      vramGib: Math.round(offer.gpu.vram_mib / 1_024),
      cudaMajor: offer.gpu.cuda_major,
      available: 1,
      minimumRatePerSecond: offer.rate_per_second,
      maximumReliabilityBps: offer.reliability_bps,
      managedRepro: offer.managed_batch === true,
      deviceRepro: offer.command_channel === true,
    });
  }
  return [...groups.values()]
    .sort((left, right) => left.minimumRatePerSecond - right.minimumRatePerSecond)
    .map(({ minimumRatePerSecond, maximumReliabilityBps, ...group }) => ({
      ...group,
      fromUsdgPerHour: formatUsdg(BigInt(minimumRatePerSecond) * 3_600n),
      bestReliabilityPercent: maximumReliabilityBps / 100,
    }));
}

export function isMarketplaceOffer(value: unknown): value is MarketplaceOffer {
  if (!value || typeof value !== "object") return false;
  const offer = value as Partial<MarketplaceOffer>;
  return isBytes32(offer.node_id)
    && isPositiveInteger(offer.rate_per_second)
    && Boolean(offer.gpu)
    && typeof offer.gpu?.model === "string"
    && offer.gpu.model.length > 0
    && offer.gpu.model.length <= 128
    && isPositiveInteger(offer.gpu?.vram_mib)
    && isPositiveInteger(offer.gpu?.cuda_major)
    && isBasisPoints(offer.reliability_bps)
    && (
      offer.benchmark_score === undefined
      || (Number.isSafeInteger(offer.benchmark_score) && offer.benchmark_score >= 0)
    )
    && (offer.staker_only === undefined || typeof offer.staker_only === "boolean")
    && (offer.command_channel === undefined || typeof offer.command_channel === "boolean")
    && (offer.managed_batch === undefined || typeof offer.managed_batch === "boolean");
}

export function isPinnedPublicImage(image: string) {
  if (!image || image.length > 512 || /\s/.test(image) || image.includes("..")) return false;
  const marker = image.lastIndexOf("@sha256:");
  if (marker < 1 || !/^[0-9a-f]{64}$/i.test(image.slice(marker + 8))) return false;
  const reference = image.slice(0, marker);
  if (!/^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?\/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$/.test(reference)) {
    return false;
  }
  const registry = reference.split("/")[0]?.toLowerCase();
  if (!registry || (!registry.includes(".") && !registry.includes(":") && registry !== "localhost")) return true;
  const port = registry.split(":")[1];
  if (port && Number(port) > 65_535) return false;
  return !isPrivateRegistry(registry);
}

export function isSshPublicKey(value: string) {
  return canonicalSshPublicKey(value) !== null;
}

export function isGpuReproCommand(value: string) {
  return typeof value === "string"
    && value.trim().length > 0
    && !value.includes("\0")
    && new TextEncoder().encode(value).byteLength <= maxGpuReproCommandBytes;
}

export function formatUsdg(baseUnits: number | bigint) {
  const value = BigInt(baseUnits);
  const whole = value / 1_000_000n;
  const fraction = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function compareOffers(left: MarketplaceOffer, right: MarketplaceOffer) {
  return left.rate_per_second - right.rate_per_second
    || right.reliability_bps - left.reliability_bps
    || (right.benchmark_score ?? 0) - (left.benchmark_score ?? 0);
}

function isGenerallyAvailableOffer(offer: MarketplaceOffer) {
  return offer.staker_only !== true;
}

function canRunRepro(offer: MarketplaceOffer) {
  return offer.command_channel === true || offer.managed_batch === true;
}

function canonicalSshPublicKey(value: string) {
  const match = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\r\n]{1,256})?$/.exec(value.trim());
  if (!match || match[1].length > 128) return null;

  let blob: Uint8Array;
  try {
    blob = Uint8Array.from(atob(match[1]), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
  if (
    blob.length !== 51
    || readUint32(blob, 0) !== 11
    || String.fromCharCode(...blob.slice(4, 15)) !== "ssh-ed25519"
    || readUint32(blob, 15) !== 32
  ) {
    return null;
  }
  return `ssh-ed25519 ${match[1]}`;
}

function readUint32(bytes: Uint8Array, offset: number) {
  return bytes[offset] * 0x1000000
    + bytes[offset + 1] * 0x10000
    + bytes[offset + 2] * 0x100
    + bytes[offset + 3];
}

function isPrivateRegistry(registry: string) {
  const host = registry.startsWith("[")
    ? registry.slice(1).split("]")[0] ?? registry
    : registry.split(":")[0] ?? registry;
  const normalized = host.replace(/\.$/, "");
  if (normalized === "localhost" || normalized.endsWith(".local") || normalized.endsWith(".internal")) {
    return true;
  }
  const octets = normalized.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return normalized === "::1" || normalized === "::" || /^f[cd][0-9a-f:]+$/i.test(normalized) || /^fe[89ab][0-9a-f:]+$/i.test(normalized);
  }
  const [first, second] = octets;
  return first === 0
    || first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
    || first >= 224;
}

function isBytes32(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isBasisPoints(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
}
