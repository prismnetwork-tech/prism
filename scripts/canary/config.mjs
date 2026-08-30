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

export function reviewQuote(quote, request, capMicros, now = Date.now()) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(quote?.quote_id)) {
    throw new Error("quote has an invalid quote_id");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(quote.node_id)) throw new Error("quote has an invalid node_id");
  if (quote.image !== request.image) throw new Error("quote image does not match the request");
  if (quote.duration_seconds !== request.durationSeconds) throw new Error("quote duration does not match the request");
  if (quote.min_vram_mib !== request.minVramMib) throw new Error("quote VRAM does not match the request");
  if (request.preferredNodeId && quote.node_id !== request.preferredNodeId) {
    throw new Error("quote node does not match the requested node");
  }
  if (quote.command != null || quote.repro != null) throw new Error("quote is not an interactive managed lease");

  const rate = baseUnits(quote.rate_per_second, "rate_per_second");
  const maximumEscrow = baseUnits(quote.maximum_escrow, "maximum_escrow");
  if (maximumEscrow !== rate * BigInt(request.durationSeconds)) {
    throw new Error("quote escrow does not match its rate and duration");
  }
  if (maximumEscrow > BigInt(capMicros)) throw new Error("quote exceeds the configured cap");

  const expiresAt = Date.parse(quote.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now + 60_000) {
    throw new Error("quote expires too soon to fund safely");
  }
  return { maximumEscrow, rate, expiresAt };
}

export function selectManagedOffer(offers, { minVramMib, preferredNodeId = null }) {
  const candidates = offers.filter((offer) => {
    return offer?.managed_batch === true
      && offer.online === true
      && offer.bonded === true
      && offer.public_image_only === true
      && Number.isSafeInteger(offer.gpu?.vram_mib)
      && offer.gpu.vram_mib >= minVramMib
      && (!preferredNodeId || offer.node_id === preferredNodeId);
  });
  candidates.sort((left, right) => {
    const rate = Number(left.rate_per_second) - Number(right.rate_per_second);
    if (rate !== 0) return rate;
    return Number(right.reliability_bps) - Number(left.reliability_bps);
  });
  if (!candidates.length) throw new Error("no managed Vast offer satisfies the canary request");
  return candidates[0];
}

export function fundedFailure(error) {
  const body = error?.body;
  if (!body || typeof body !== "object") return { fundingHash: null, leaseId: null };

  const fundingHash = /^0x[0-9a-fA-F]{64}$/.test(body.funding_hash) ? body.funding_hash : null;
  const leaseId = Number.isSafeInteger(body.lease_id) && body.lease_id >= 0 ? body.lease_id : null;
  return { fundingHash, leaseId };
}

function baseUnits(value, field) {
  if ((typeof value !== "string" && typeof value !== "number") || !/^[0-9]+$/.test(String(value))) {
    throw new Error(`quote has an invalid ${field}`);
  }
  return BigInt(value);
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
