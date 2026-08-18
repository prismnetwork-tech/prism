const DEFAULT_DURATION = 600;
const DEFAULT_MAX_USDG = 0.5;
const DEFAULT_MIN_VRAM = 16000;

export function readCanaryConfig(env = process.env) {
  const duration = integer(env.CANARY_DURATION, DEFAULT_DURATION, "CANARY_DURATION");
  const maxUsdg = decimal(env.CANARY_MAX_USDG, DEFAULT_MAX_USDG, "CANARY_MAX_USDG");
  const minVram = integer(env.CANARY_MIN_VRAM, DEFAULT_MIN_VRAM, "CANARY_MIN_VRAM");
  const node = env.CANARY_NODE || null;
  // Brokered capacity hands the renter SSH on the host, so any image runs.
  // A physical node runs the renter's image as the workspace and expects it to
  // carry sshd and a notebook, so checking that path needs a different one.
  const image = env.CANARY_IMAGE || null;

  if (duration > 3600) throw new Error("duration is capped at 1 hour");
  if (maxUsdg > 5) throw new Error("spend is capped at 5 USDG");
  if (node && !/^0x[0-9a-fA-F]{64}$/.test(node)) {
    throw new Error("CANARY_NODE must be a 32-byte hex node id");
  }
  if (image && !/@sha256:[0-9a-f]{64}$/.test(image)) {
    throw new Error("CANARY_IMAGE must be pinned to a sha256 digest");
  }

  const capMicros = Math.round(maxUsdg * 1e6);
  if (capMicros < 1) throw new Error("CANARY_MAX_USDG must be at least 0.000001");

  return {
    duration,
    maxUsdg,
    minVram,
    node,
    image,
    capMicros,
  };
}

function integer(value, fallback, name) {
  if (value == null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function decimal(value, fallback, name) {
  if (value == null) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return parsed;
}
