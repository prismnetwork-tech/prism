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

const CANONICAL_NETWORKS = Object.fromEntries(
  Object.entries(V1_NETWORK_NAMES).map(([caip2, name]) => [name, caip2]),
);

/**
 * Any spelling of a network to its CAIP-2 form, so the two versions can be
 * compared. A client that read a v1 quote echoes back "base" while the server
 * holds "eip155:8453", and treating those as different chains refuses payments
 * that are perfectly good.
 */
export function canonicalNetwork(network) {
  const key = String(network ?? "");
  return CANONICAL_NETWORKS[key.toLowerCase()] ?? key;
}

export function sameNetwork(a, b) {
  return canonicalNetwork(a).toLowerCase() === canonicalNetwork(b).toLowerCase();
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

/// v2 keeps the accepts entry to payment terms alone. Everything describing the
/// resource moved up a level in v2, and sending the v1 spelling alongside makes
/// the entry fail schema validation rather than being ignored.
const V2_ENTRY_FIELDS = ["scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds", "extra"];

/**
 * Payment requirements in the shape a given version expects. Entries are always
 * written in v2 terms (CAIP-2 network, `amount`); this renames for v1 and
 * strips the v1-only fields for v2.
 */
export function requirementsFor(version, requirements) {
  if (version === 2) {
    const entry = {};
    for (const field of V2_ENTRY_FIELDS) {
      if (requirements[field] !== undefined) entry[field] = requirements[field];
    }
    return entry;
  }
  const { amount, network, ...rest } = requirements;
  return { ...rest, network: v1Network(network), maxAmountRequired: String(amount) };
}

/// The bazaar extension is how a v2 challenge says what the call looks like.
///
/// The nesting is not obvious and is not in the prose spec: readers descend to
/// `schema.properties.input.properties.body` for the request and to
/// `schema.properties.output.properties.example` for the response. `input`
/// describes the whole request, of which the JSON body is one part, so the
/// wrapper is where query parameters and headers would go too.
export function bazaar({ input, output, example, inputExample, method = "POST" }) {
  // Mirrors the shape listed services actually publish: a declared JSON Schema
  // draft, and every field `info` carries declared here. A field present in the
  // instance but absent from the schema is what makes a parser report the
  // instance as incomplete.
  const shape = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    type: "object",
    properties: {
      input: {
        type: "object",
        additionalProperties: false,
        properties: {
          type: { type: "string", enum: ["http"] },
          method: { type: "string", enum: [method] },
          body: input,
        },
        required: ["body"],
      },
      output: {
        type: "object",
        additionalProperties: false,
        properties: { example: output },
      },
    },
    required: ["input"],
  };
  // `schema` describes the call for readers that walk properties; `info` is the
  // filled-in instance of it. They are not interchangeable: `info.input` needs
  // the transport (`type`, `method`) that a schema has no place for, and
  // `info.output.example` wants a literal sample rather than another schema.
  return {
    bazaar: {
      info: {
        // `info` is the instance, so both halves carry samples rather than
        // schemas. Putting the schema here reads as a body that is missing its
        // fields, because a schema has none of them at the top level.
        input: { type: "http", method, body: inputExample ?? input },
        output: example ? { example } : { example: output },
      },
      schema: shape,
    },
  };
}

/**
 * The 402 a server sends. v1 answers with a JSON body; v2 answers with a
 * base64 `PAYMENT-REQUIRED` header and leaves the body to the application.
 */
export function paymentRequired(version, { accepts, error, resource, schemas, extra = {} }) {
  if (version === 2) {
    const body = {
      x402Version: 2,
      ...(error ? { error } : {}),
      // Required in v2, and an object rather than the v1 path string.
      ...(resource ? { resource } : {}),
      accepts: accepts.map((a) => requirementsFor(2, a)),
      ...(schemas ? { extensions: bazaar(schemas) } : {}),
      ...extra,
    };
    return { headers: { "PAYMENT-REQUIRED": encode(body) }, body };
  }
  return {
    headers: {},
    body: {
      x402Version: 1,
      ...(error ? { error } : {}),
      accepts: accepts.map((a) => requirementsFor(1, a)),
      ...extra,
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
