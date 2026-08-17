// Translates between the two live shapes of the protocol and the one internal
// form the verifier works in.
//
// v1 puts requirements in a JSON body with an `accepts` array and carries the
// payment in `X-PAYMENT`. v2 moves both into headers (`PAYMENT-REQUIRED`,
// `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`) and names networks in CAIP-2 form.
// Underneath they carry the same EIP-3009 authorization, so the difference is
// packaging and belongs in one place rather than in every endpoint.

/// v1 predates CAIP-2 and names chains, so a v1 client sending "base" and a v2
/// client sending "eip155:8453" mean the same one. Only chains with a name the
/// ecosystem already uses belong here: Robinhood Chain has none, we have always
/// advertised it to v1 callers in CAIP-2 form, and inventing a name now would
/// break the clients already integrated against it to no purpose.
const V1_NETWORK_NAMES = {
  "eip155:8453": "base",
  "eip155:84532": "base-sepolia",
};

export function v1Network(caip2) {
  return V1_NETWORK_NAMES[caip2] ?? caip2;
}

const decode = (value) => JSON.parse(Buffer.from(value, "base64").toString("utf8"));
const encode = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64");

/**
 * Which version a request speaks, from its headers alone. A caller sending
 * neither payment header gets `null`, which is the unpaid first request.
 */
export function detect(headers) {
  const lower = {};
  for (const [k, v] of Object.entries(headers ?? {})) lower[k.toLowerCase()] = v;
  if (lower["payment-signature"]) return { version: 2, header: lower["payment-signature"] };
  if (lower["x-payment"]) return { version: 1, header: lower["x-payment"] };
  return null;
}

/**
 * A payment header to the internal payload shape. Both versions decode to the
 * same `{ x402Version, accepted, payload }`, so the verifier sees one form.
 *
 * Returns null when the header is not decodable, which the caller reports as
 * `invalid_payload` rather than treating as absent: a malformed payment is a
 * failed payment, not an unpaid request.
 */
export function parsePayment(header) {
  let decoded;
  try {
    decoded = decode(header);
  } catch {
    return null;
  }
  if (!decoded || typeof decoded !== "object") return null;
  // v1 nests the scheme fields at the top level; v2 groups them under
  // `accepted`. Normalising here keeps the verifier free of version checks.
  const accepted = decoded.accepted ?? {
    scheme: decoded.scheme,
    network: decoded.network,
    asset: decoded.asset,
    payTo: decoded.payTo,
  };
  return { x402Version: decoded.x402Version ?? 1, accepted, payload: decoded.payload, raw: decoded };
}

/**
 * Payment requirements in the shape a given version expects. `requirements` is
 * always written in v2 terms (CAIP-2 network, `amount`); this renames for v1.
 */
export function requirementsFor(version, requirements) {
  if (version === 2) return requirements;
  const { amount, network, ...rest } = requirements;
  return { ...rest, network: v1Network(network), maxAmountRequired: String(amount) };
}

/**
 * The 402 a server sends. v1 answers with a JSON body; v2 answers with a
 * base64 `PAYMENT-REQUIRED` header and leaves the body to the application.
 */
export function paymentRequired(version, { accepts, error, resource }) {
  if (version === 2) {
    const body = { x402Version: 2, error, accepts: accepts.map((a) => requirementsFor(2, a)) };
    if (resource) body.resource = resource;
    return { headers: { "PAYMENT-REQUIRED": encode(body) }, body };
  }
  return {
    headers: {},
    body: {
      x402Version: 1,
      error,
      accepts: accepts.map((a) => requirementsFor(1, a)),
    },
  };
}

/**
 * The settlement result a server returns alongside a paid response. v2 defines
 * a `PAYMENT-RESPONSE` header for it; v1 has no equivalent, so the caller puts
 * it in the body if it wants to report it at all.
 */
export function paymentResponse(version, settlement) {
  if (version !== 2) return { headers: {} };
  return {
    headers: {
      "PAYMENT-RESPONSE": encode({
        success: settlement.success,
        transaction: settlement.transaction,
        network: settlement.network,
        payer: settlement.payer,
        ...(settlement.errorReason ? { errorReason: settlement.errorReason } : {}),
      }),
    },
  };
}
