#!/usr/bin/env node
// Runs the verification against the real attested service. Everything here is
// read-only and free: a fresh nonce to the attestation endpoint, Intel's
// collateral for the quote, and NVIDIA's attestation of the GPU. Nothing is
// paid for and no prompt is sent.
//
//   node attest.live.mjs                  through the Prism relay
//   node attest.live.mjs --upstream       straight at the attested service
//   node attest.live.mjs --receipt <id>   the whole transcript for a call already made
//
// A receipt only exists for a generation someone paid for, so the receipt half
// of the transcript needs an id from a real call (examples/confidential makes
// one). Without it this checks the workload and the GPU behind it. The bytes of
// that call are the caller's to keep, so --receipt takes --request-hash and
// --response-hash (and --e2ee, which makes the request hash the restored one).
import {
  appraiseWorkload,
  gateGpuBinding,
  gateNrasClaims,
  observeTlsSpki,
  renderChecks,
  sameTd,
  verifyConfidential,
} from "./attest.mjs";
import {
  computeReportData,
  quoteReportData,
  toHex,
  verifyComposeMeasurement,
  verifyQuote,
  verifyRawQuote,
  verifyReportBinding,
} from "./vendor/aci-verifier/index.mjs";

const args = process.argv.slice(2);
const value = (flag) => (args.includes(flag) ? args[args.indexOf(flag) + 1] : null);
const upstream = args.includes("--upstream");
const receiptId = value("--receipt");
const relay = (process.env.PRISM_INFERENCE_URL ?? "https://api.prismnetwork.tech/inference").replace(/\/$/, "");
const model = process.env.PRISM_CONFIDENTIAL_MODEL ?? "phala/gemma-4-26b-a4b-uncensored";

const endpoints = upstream
  ? {
      attestation: (nonce) => `https://tee.redpill.ai/v1/aci/attestation?nonce=${nonce}`,
      gpu: () => `https://api.redpill.ai/v1/attestation/report?model=${encodeURIComponent(model)}`,
    }
  : {
      attestation: (nonce) => `${relay}/v1/attestation?nonce=${nonce}`,
      gpu: () => `${relay}/v1/gpu-evidence?model=${encodeURIComponent(model)}`,
    };

const mark = { pass: "ok  ", fail: "FAIL", skip: "skip" };
const line = (status, title, detail) => console.log(`${mark[status]} ${title}\n       ${detail}`);

if (receiptId) {
  const e2ee = args.includes("--e2ee");
  const requestHash = value("--request-hash");
  const result = await verifyConfidential({
    base: relay,
    model,
    receiptId,
    e2ee,
    requestHash: e2ee ? null : requestHash,
    restoredRequestHash: e2ee ? requestHash : null,
    responseHash: value("--response-hash"),
  });
  console.log(renderChecks(result));

  // A receipt this run has no bytes for still proves what the workload signed.
  // It does not prove that it signed this exchange, and the two are worth
  // different words rather than the same failure.
  const unbound = result.checks.filter((c) => c.status === "skip" && ["request-hash", "response-hash"].includes(c.id));
  const missing = result.checks.filter(
    (c) => c.status === "skip" && !["request-hash", "response-hash", "key-custody", "tls-spki"].includes(c.id),
  );
  if (unbound.length > 0 && missing.length === 0 && result.verdict === "incomplete") {
    console.log(
      `\nthe bytes of that call were not supplied, so ${unbound.length} of the checks could not run.\n` +
        "pass --request-hash and --response-hash to bind the receipt to them.",
    );
    process.exit(0);
  }
  process.exit(result.verdict === "verified" ? 0 : 1);
}

const nonce = toHex(crypto.getRandomValues(new Uint8Array(32)));
const report = await (await fetch(endpoints.attestation(nonce), { headers: { accept: "application/json" } })).json();
console.log(`${upstream ? "attested service" : "prism relay"}: nonce ${nonce}\n`);

const binding = await verifyReportBinding(report, nonce);
const bad = binding.checks.find((c) => !c.ok);
line(
  binding.ok ? "pass" : "fail",
  "workload key set recomputed from the served report",
  binding.ok ? binding.workloadKeysetDigest : (bad.detail ?? bad.name),
);

const quote = await verifyQuote(report);
line(
  quote.ok && quote.status === "UpToDate" ? "pass" : "fail",
  "TDX quote verifies to Intel's root",
  quote.ok ? `platform TCB ${quote.status}${quote.advisoryIds?.length ? ` (${quote.advisoryIds.join(", ")})` : ""}` : quote.detail,
);

const slot = quote.ok ? quote.report.reportData : quoteReportData(report.attestation.evidence.quote);
const expected = await computeReportData(binding.workloadKeysetDigest, nonce);
line(
  toHex(slot.slice(0, 32)) === expected ? "pass" : "fail",
  "the quote commits to that key set and to our nonce",
  `report data ${toHex(slot.slice(0, 32))}`,
);

const compose = await verifyComposeMeasurement(report, { statedRtmr3: quote.ok ? quote.report.rtMr3 : null });
line(compose.checks[0].ok ? "pass" : "fail", "boot event log replays to the quote's RTMR3", toHex(compose.rtmr3));
line(compose.checks[1].ok ? "pass" : "fail", "the running compose is the one measured into the quote", compose.composeHash);

const identity = await appraiseWorkload(report, compose);
line(identity.ok ? "pass" : "fail", "the measured compose runs the pinned launcher and source", identity.detail);

const evidence = await (await fetch(endpoints.gpu(), { headers: { accept: "application/json" } })).json();
const payload = evidence.nvidia_payload;
const gpuNonce = JSON.parse(payload).nonce;
const nras = await (
  await fetch("https://nras.attestation.nvidia.com/v3/attest/gpu", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
  })
).json();
const { createRemoteJWKSet, jwtVerify } = await import("jose");
const jwks = createRemoteJWKSet(new URL("https://nras.attestation.nvidia.com/.well-known/jwks.json"));
const open = async (token) =>
  (await jwtVerify(token, jwks, { issuer: "https://nras.attestation.nvidia.com", algorithms: ["ES384"] })).payload;
const overall = await open(nras[0][1]);
const gpus = Object.fromEntries(await Promise.all(Object.entries(nras[1]).map(async ([k, v]) => [k, await open(v)])));
const claims = gateNrasClaims({ overall, gpus, nonce: gpuNonce });
line(claims.ok ? "pass" : "fail", "GPU attested by NVIDIA", claims.detail);

const gpuQuote = await verifyRawQuote(evidence.intel_quote);
const tie = gpuQuote.ok && quote.ok ? sameTd(quote.report, gpuQuote.report) : { ok: false, differing: [] };
const bound = gpuQuote.ok
  ? gateGpuBinding({ reportData: toHex(gpuQuote.report.reportData), signingAddress: evidence.signing_address, nonce: gpuNonce })
  : { ok: false, detail: gpuQuote.detail };
const sameWorkload = evidence.workload_keyset_digest === binding.workloadKeysetDigest;
line(
  bound.ok && tie.ok && sameWorkload ? "pass" : "fail",
  "the GPU attestation nonce is bound to the workload's quote",
  tie.ok
    ? `${bound.detail}, quoted by the TD that carried our nonce`
    : `${bound.detail}; the GPU evidence's quote comes from a different TD (${tie.differing.join(", ") || "no verified quote to compare"})`,
);

// Against the attested service itself the pin is checkable, because the
// certificate this client sees is the one the key set names. Through a relay it
// is not: the relay terminates TLS with a certificate of its own.
if (upstream) {
  const observed = await observeTlsSpki("https://tee.redpill.ai");
  const pinned = (binding.keyset.tls_public_keys ?? []).some(
    (k) => k.domain === "tee.redpill.ai" && k.spki_sha256.toLowerCase() === observed,
  );
  line(pinned ? "pass" : "fail", "the TLS key this client spoke to is in the attested key set", observed);
} else {
  console.log("\nskip the TLS key this client spoke to is in the attested key set");
  console.log("       the relay terminates TLS with its own certificate; end-to-end encryption is what protects a prompt");
}
console.log("skip private-key custody appraised");
console.log("       no verifier appraises the KMS custody chain yet");
console.log("\nreceipt checks need a paid generation: node attest.live.mjs --receipt <id>");
