// The confidential tier as a model catalogue, in the shape an aggregator's
// provider monitor polls: one document per model under `data`, with limits,
// pricing and capacity declared on the modality that owns them.
//
// Only the confidential tier is listed. The open tier leases a GPU per request
// and answers `warming_up` until one lands, and a cold start reads as
// unavailability to anything scoring the endpoint, so listing it would trade a
// real uptime figure for capacity nobody could rely on.
//
// Built from the same numbers `/v1/models` publishes, so the catalogue cannot
// quote a price the 402 will not.

// What the document declares itself against. Bumping it is a migration, not a
// value change: the field vocabulary moves with it.
const SCHEMA_VERSION = "2.4";

// `cost_usd` is the price of one unit of `unit`, so a per-token rate is the
// price of one token and a micro is six decimal places down. Strings, because
// a price that has been through a float is not the price any more.
const usd = (micros) => (Number(micros) / 1e6).toFixed(6);

const DESCRIPTION =
  "Served inside an Intel TDX enclave in front of a GPU that NVIDIA attests directly. Every " +
  "completion carries a signed receipt over the exact request and response bytes it was served " +
  "with, and the enclave's attestation is free to fetch, so an answer can be checked rather than " +
  "taken on trust. Message content can be encrypted to the enclave's attested key, which leaves " +
  "the relay in front of it carrying ciphertext. The price is a per-request charge plus a " +
  "per-token rate over the max_tokens the caller asks for, quoted in full before payment.";

/// "Vendor: model", the shape a catalogue lists under. The model segment stays
/// exactly as the upstream spells it: a tidier name would be a claim about
/// which weights sit behind the id, and what the attestation binds is the
/// workload serving it rather than the weights.
function displayName(id) {
  const [vendor, ...rest] = id.split("/");
  if (!rest.length) return id;
  return `${vendor.charAt(0).toUpperCase()}${vendor.slice(1)}: ${rest.join("/")}`;
}

/// How many requests the day's budget covers, counted in the most expensive
/// request any listed model allows so the figure is a floor rather than a hope.
/// The budget is one pot across the whole class rather than one per model, so
/// counting each model against its own cap would let a cheap model declare a
/// day's worth of requests the pot cannot fund once a dearer one takes its
/// share. An operator who sets the cap below one full-cap call gets 1, which is
/// the smallest a declared limit is allowed to be; the gateway's own
/// configuration note asks for a cap above that price for the same reason.
function requestsPerDay(dailyUsd, fullCapUsd) {
  return Math.max(1, Math.floor(dailyUsd / fullCapUsd));
}

function modelDocument(id, card, { maxTokens, maxBodyBytes, dailyUsd, priciestUsd }) {
  return {
    schema_version: SCHEMA_VERSION,
    id,
    name: displayName(id),
    description: DESCRIPTION,
    input_modalities: [
      {
        type: "text",
        // What the route enforces is a byte limit over the whole request, so
        // that is what it declares. A token figure would be a guess at an
        // encoder this gateway does not run, and end-to-end encryption roughly
        // doubles the envelope without changing the limit.
        supported_inputs: { max_prompt_length: { value: maxBodyBytes, unit: "byte" } },
        // No pricing entry: prompt tokens are not billed, and an unbilled SKU
        // belongs out of the document rather than in it priced at zero.
      },
    ],
    output_modalities: [
      {
        type: "text",
        max_length: { value: maxTokens, unit: "token" },
        streaming: true,
        supported_parameters: {
          // Required, and declared as such rather than left to a default: the
          // request reaches the enclave as the bytes the caller sent, so a cap
          // the gateway cannot write into the body is a cap the caller has to
          // state, and the route refuses a request that omits it.
          max_tokens: { type: "integer", min: 1, max: maxTokens, unit: "token", required: true },
          // Forwarded to the enclave untouched and never read here, so its
          // range is the served model's to state and not ours.
          temperature: { type: "unknown" },
        },
        pricing: [{ type: "completion", unit: "token", cost_usd: usd(card.per_token_micros) }],
      },
    ],
    pricing: [{ type: "request", unit: "request", cost_usd: usd(card.base_micros) }],
    capacity: [
      {
        type: "request",
        unit: "request",
        per: "day",
        value: requestsPerDay(dailyUsd, priciestUsd),
      },
    ],
    // Prompts are relayed and never written down: no disk, no log line, and
    // under end-to-end encryption never in the clear in this process at all.
    // What stops this being zero retention is the other half of the exchange.
    // A served answer is held in memory against the payment that bought it, so
    // a caller whose connection dropped can collect what they already paid for
    // instead of paying twice, and that is retained content however short its
    // life. Turn this on when that buffer is gone or bounded by a stated TTL,
    // not before.
    compliance: { zdr: false },
    // No `datacenters` and no `deployment_region`: the upstream publishes
    // neither, and nothing in the attestation names a location. A country code
    // guessed off a hostname would be a fact this document does not have.
  };
}

/// The catalogue. `confidential` is the block `/v1/models` publishes and
/// `dailyUsd` is the relay's daily spend cap, the two places every number here
/// comes from.
///
/// An unconfigured confidential class lists nothing rather than answering an
/// error: there is genuinely nothing to serve, and a catalogue saying so is a
/// true answer where a 404 would read as a broken endpoint.
export function providerModels({ confidential, dailyUsd } = {}) {
  if (!confidential) return { data: [] };
  const cards = Object.entries(confidential.models);
  const limits = {
    maxTokens: confidential.max_tokens,
    maxBodyBytes: confidential.max_body_bytes,
    dailyUsd,
    priciestUsd: Math.max(...cards.map(([, card]) => Number(card.full_cap_micros) / 1e6)),
  };
  return { data: cards.map(([id, card]) => modelDocument(id, card, limits)) };
}
