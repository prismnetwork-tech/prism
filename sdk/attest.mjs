// Agent-side verification of a confidential generation: the checks an agent
// runs itself, after the fact, over the answer it just paid for.
//
// The chain it establishes, in order: the TDX quote verifies to Intel's root;
// that quote commits to the workload's key set and to a nonce this client
// chose; the boot event log replays to the RTMR3 the quote states, and the
// compose it measures is the code this SDK pins; the per-request receipt is
// signed by a key in that same key set and commits to the exact request and
// response bytes; the upstream that ran the model was itself verified and the
// session it cites is the document it claims to be; the GPU is attested by
// NVIDIA under a nonce bound into a quote from the same TD.
//
// Two things this cannot prove, and reports as skips rather than dressing up:
// nobody outside the enclave holds the signing keys (the report publishes
// custody evidence, but no verifier in the protocol appraises the KMS chain
// today), and where TLS terminates. End-to-end encryption is what removes the
// second one from the trust path: with it on, the relay carries ciphertext.
//
// Two checks reach outside Web Crypto and load their library when they run:
// the TDX quote needs @phala/dcap-qvl (^0.6.1, the pure-JS package) and the
// NVIDIA tokens need jose (^6). Without them those checks report what is
// missing instead of passing.
import {
  checkSessionEvidence,
  computeReportData,
  computeSessionId,
  findEvent,
  fromHex,
  hashBody,
  quoteReportData,
  sha384,
  toHex,
  verifyComposeMeasurement,
  verifyQuote,
  verifyRawQuote,
  verifyReceipt,
  verifyReportBinding,
} from "./vendor/aci-verifier/index.mjs";

export const DEFAULT_CONFIDENTIAL_BASE = "https://api.prismnetwork.tech/inference";

/// The deployment the confidential tier is pinned to, read off the live
/// known-good report. The launcher image digest is the root of it: the launcher
/// is measured into the quote, and it is the thing that clones and runs the
/// gateway source, so its digest pins the code that ends up holding the E2EE
/// private key. `repoUrl` is the human-readable half of the same fact, and
/// `osImageHash` is the dstack guest image the whole stack booted under.
/// `repoCommit` pins the source revision the launcher builds, so a compose that
/// names another revision of the same repo does not pass.
///
/// This is a snapshot of one known-good deployment. It has to be updated when
/// Phala rebuilds the launcher or advances the gateway source, and it does not
/// establish that the launcher image was built from the source it names.
export const EXPECTED_WORKLOAD = {
  launcherImage:
    "ghcr.io/redpill-ai/private-ai-launcher@sha256:c083ff9e6a5ddf10f6c9e9bb1f74cc618deebecfea5208b563c574399db4637c",
  repoUrl: "https://github.com/Dstack-TEE/private-ai-gateway.git",
  osImageHash: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
  repoCommit: "b6b5c1b82f6fc59490db5a5255bf4493805e66c6",
};

const NRAS_ATTEST_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
const NRAS_ISSUER = "https://nras.attestation.nvidia.com";
const FETCH_TIMEOUT_MS = 30_000;

// A verified verdict tolerates only these two skips, and only for the reason
// each names. Anything else that could not run means evidence the verdict would
// have rested on was missing, which is `incomplete` rather than `verified`.
const CUSTODY = "key-custody";
const CHANNEL = "tls-spki";
const WORKLOAD = "workload-identity";

const CHECKS = {
  "keyset-digest": "workload key set recomputed from the served report",
  "report-data-binding": "the quote commits to that key set and to our nonce",
  "tdx-quote": "TDX quote verifies to Intel's root",
  "rtmr3-replay": "boot event log replays to the quote's RTMR3",
  "compose-hash": "the running compose is the one measured into the quote",
  "workload-identity": "the measured compose runs the pinned launcher and source",
  "receipt-signature": "receipt signed by an attested receipt key",
  "receipt-keyset-binding": "receipt binds to the verified key set",
  "request-hash": "the request bytes match the signed receipt",
  "response-hash": "the response bytes match the signed receipt",
  "upstream-verified": "the serving upstream was verified, and verification was required",
  "session-id": "the cited attestation session is the document it claims to be",
  "session-evidence": "the session's evidence hashes to its digest",
  "gpu-nras": "GPU attested by NVIDIA",
  "gpu-binding": "the GPU attestation nonce is bound to the workload's quote",
  "tls-spki": "the TLS key this client spoke to is in the attested key set",
  "key-custody": "private-key custody appraised",
};

class Transcript {
  constructor() {
    this.checks = [];
  }

  add(id, status, detail) {
    this.checks.push({ id, title: CHECKS[id] ?? id, status, detail });
    return status === "pass";
  }

  pass(id, detail) {
    return this.add(id, "pass", detail);
  }

  fail(id, detail) {
    return this.add(id, "fail", detail);
  }

  skip(id, detail) {
    return this.add(id, "skip", detail);
  }
}

const unixTime = (seconds) => new Date(seconds * 1000).toISOString();

function randomNonce() {
  return toHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/// A JSON document, or a reason it is not one. Only a host this client cannot
/// reach at all throws: an endpoint that answers with an error status or with
/// something that is not JSON has said something about itself, and the caller
/// turns that into a failed check rather than an exception.
async function getJson(fetchImpl, url, what) {
  let res;
  try {
    res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new Error(`${what} unreachable: ${err?.message ?? err}`);
  }
  if (!res.ok) return { ok: false, detail: `${what} answered HTTP ${res.status}` };
  try {
    return { ok: true, body: await res.json() };
  } catch {
    return { ok: false, detail: `${what} answered with something that is not JSON` };
  }
}

// dstack writes its runtime events with this type, and the RTMR3 replay chains
// each event's `digest`, never its payload. So a payload only counts once it
// reproduces the digest that was measured.
const DSTACK_RUNTIME_EVENT = 0x08000001;
const IMAGE_PIN = /image:\s*([^\s"\\]+)@sha256:([0-9a-f]{64})/g;
const REPO_URL = /REPO_URL=([^\s"\\]+)/g;
const REPO_COMMIT = /REPO_COMMIT=([0-9a-fA-F]{7,40})/g;

const short = (hex) => String(hex ?? "").slice(0, 12);

/// The payload of the one pre-system-ready dstack event called `name`, or null
/// when there is not exactly one or its digest does not reproduce.
export async function measuredEvent(events, name) {
  const found = [];
  for (const e of events ?? []) {
    if (e?.imr !== 3 || e?.event_type !== DSTACK_RUNTIME_EVENT) continue;
    if (e.event === "system-ready") break;
    if (e.event === name) found.push(e);
  }
  if (found.length !== 1) return null;
  const [event] = found;
  const label = new TextEncoder().encode(`:${event.event}:`);
  let payload;
  try {
    payload = fromHex(String(event.event_payload ?? ""));
  } catch {
    return null;
  }
  const buf = new Uint8Array(4 + label.length + payload.length);
  new DataView(buf.buffer).setUint32(0, DSTACK_RUNTIME_EVENT, true);
  buf.set(label, 4);
  buf.set(payload, 4 + label.length);
  const digest = toHex(await sha384(buf));
  return digest === String(event.digest ?? "").toLowerCase() ? String(event.event_payload).toLowerCase() : null;
}

/// What the measured compose says it runs: the image digests it pins and the
/// source the launcher clones. Every value here is inside the bytes that hash to
/// the measured compose-hash, so none of it is the report's word for it.
function measuredWorkload(appCompose) {
  const compose = String(appCompose ?? "");
  const only = (pattern) => {
    const hits = [...compose.matchAll(pattern)].map((m) => m[1]);
    return hits.length === 1 ? hits[0] : null;
  };
  return {
    images: [...compose.matchAll(IMAGE_PIN)].map((m) => ({ repository: m[1], digest: m[2].toLowerCase() })),
    repoUrl: only(REPO_URL),
    repoCommit: only(REPO_COMMIT)?.toLowerCase() ?? null,
  };
}

const sourceOf = (measured) =>
  measured.repoUrl && measured.repoCommit ? `${measured.repoUrl} @ ${measured.repoCommit}` : null;

/// §9.1 check 4 as a policy rather than a printout. `appCompose` is the measured
/// compose text, `osImageHash` the measured dstack image, `provenance` the
/// report's own `source_provenance` (which §4.1 says is not bound into the
/// quote, so it counts only where the measured compose agrees with it).
export function gateWorkloadIdentity({ appCompose, osImageHash, provenance, expected }) {
  const measured = measuredWorkload(appCompose);
  const problems = [];
  const [wantRepository, wantDigest] = String(expected?.launcherImage ?? "").split("@sha256:");
  const running = measured.images.filter((i) => i.repository === wantRepository);
  if (running.length !== 1) {
    problems.push(
      running.length === 0
        ? `the measured compose runs no ${wantRepository} image`
        : `the measured compose names ${running.length} ${wantRepository} images`,
    );
  } else if (running[0].digest !== String(wantDigest).toLowerCase()) {
    problems.push(`the measured launcher is sha256:${running[0].digest}, this SDK pins sha256:${wantDigest}`);
  }

  if (measured.repoUrl === null) {
    problems.push("the measured compose names no single source repository");
  } else if (measured.repoUrl !== expected?.repoUrl) {
    problems.push(`the measured source is ${measured.repoUrl}, this SDK pins ${expected?.repoUrl}`);
  }
  if (measured.repoCommit === null) {
    problems.push("the measured compose pins no single source commit");
  } else if (expected?.repoCommit && measured.repoCommit !== String(expected.repoCommit).toLowerCase()) {
    problems.push(`the measured commit is ${measured.repoCommit}, this SDK pins ${expected.repoCommit}`);
  }

  const stated = provenance ?? {};
  if (measured.repoUrl !== null && stated.repo_url != null && stated.repo_url !== measured.repoUrl) {
    problems.push(`the report declares source ${stated.repo_url}, the measured compose clones ${measured.repoUrl}`);
  }
  if (
    measured.repoCommit !== null &&
    stated.repo_commit != null &&
    String(stated.repo_commit).toLowerCase() !== measured.repoCommit
  ) {
    problems.push(`the report declares commit ${stated.repo_commit}, the measured compose pins ${measured.repoCommit}`);
  }

  if (expected?.osImageHash) {
    if (typeof osImageHash !== "string") {
      problems.push("the boot log carries no os-image-hash that reproduces its measured digest");
    } else if (osImageHash !== String(expected.osImageHash).toLowerCase()) {
      problems.push(`the measured OS image is ${osImageHash}, this SDK pins ${expected.osImageHash}`);
    }
  }

  return {
    ok: problems.length === 0,
    detail: problems.length
      ? problems.join("; ")
      : `launcher ${wantRepository}@sha256:${short(wantDigest)}, dstack OS ${short(expected?.osImageHash)}, ` +
        `source ${sourceOf(measured)}. The pin is a snapshot of a known-good deployment, so it needs updating ` +
        "when the launcher is rebuilt, and it does not establish that the image was built from that source.",
    provenance: sourceOf(measured),
  };
}

/// The identity appraisal over a report whose compose measurement already holds.
/// `verifyConfidential` runs it after the fact and the SDK's pre-send gate runs
/// it before it encrypts anything, so both establish which code holds the key.
/// `expected` of null is an explicit caller downgrade and reports itself as one.
export async function appraiseWorkload(report, compose, expected = EXPECTED_WORKLOAD) {
  const evidence = report?.attestation?.evidence ?? {};
  let events;
  try {
    events = JSON.parse(evidence.event_log);
  } catch {
    return { ok: false, detail: "the report's boot event log is not readable" };
  }
  const measuredCompose = await measuredEvent(events, "compose-hash");
  if (measuredCompose === null || measuredCompose !== compose?.composeHash) {
    return { ok: false, detail: "the compose-hash event does not reproduce the digest the RTMR3 replay chains" };
  }
  const measured = measuredWorkload(evidence.app_compose);
  if (expected === null) {
    return {
      ok: true,
      skipped: true,
      detail: "workload identity not pinned by caller, so the transcript establishes a TDX enclave and not which code runs in it",
      provenance: sourceOf(measured),
    };
  }
  return gateWorkloadIdentity({
    appCompose: evidence.app_compose,
    osImageHash: await measuredEvent(events, "os-image-hash"),
    provenance: report?.attestation?.source_provenance,
    expected,
  });
}

/// The claim gate over an NVIDIA attestation (NRAS) result. Kept apart from the
/// JWT signature check so the policy is readable and testable on its own: a
/// signed token saying the GPU failed its measurements is still a failure.
export function gateNrasClaims({ overall, gpus, nonce, now = Math.floor(Date.now() / 1000) }) {
  const problems = [];
  if (overall?.["x-nvidia-overall-att-result"] !== true) problems.push("overall attestation result is not true");
  if (typeof overall?.eat_nonce !== "string" || overall.eat_nonce.toLowerCase() !== nonce.toLowerCase()) {
    problems.push("the overall token answers a different nonce");
  }
  if (typeof overall?.exp === "number" && now >= overall.exp) problems.push("the overall token has expired");

  const entries = Object.entries(gpus ?? {});
  if (entries.length === 0) problems.push("no per-GPU token");
  const models = [];
  for (const [name, claims] of entries) {
    const say = (text) => problems.push(`${name}: ${text}`);
    if (claims?.measres !== "success") say("measurements do not match the reference values");
    if (claims?.secboot !== true) say("secure boot is off");
    if (claims?.dbgstat !== "disabled") say("debug mode is not disabled");
    if (claims?.["x-nvidia-gpu-attestation-report-nonce-match"] !== true) say("attestation report answers a different nonce");
    if (claims?.["x-nvidia-attestation-warning"] !== null) {
      say(`attestation warning: ${JSON.stringify(claims?.["x-nvidia-attestation-warning"] ?? null)}`);
    }
    if (typeof claims?.eat_nonce === "string" && claims.eat_nonce.toLowerCase() !== nonce.toLowerCase()) {
      say("token answers a different nonce");
    }
    if (typeof claims?.hwmodel === "string") models.push(`${name} ${claims.hwmodel}`);
  }

  return {
    ok: problems.length === 0,
    detail: problems.length
      ? problems.join("; ")
      : `${models.join(", ")}: measurements match, secure boot on, debug disabled`,
  };
}

/// The legacy attestation report binds the GPU nonce into the CPU quote's
/// report-data slot as signing_address(20) || zeros(12) || nvidia_nonce(32).
/// Both halves have to hold: the address half proves the quote belongs to the
/// workload that signs its answers, the nonce half proves the GPU evidence was
/// produced for this quote and not replayed from another machine.
export function gateGpuBinding({ reportData, signingAddress, nonce }) {
  const slot = String(reportData ?? "").toLowerCase();
  const address = String(signingAddress ?? "").replace(/^0x/, "").toLowerCase();
  const want = `${address}${"0".repeat(24)}${String(nonce ?? "").toLowerCase()}`;
  if (slot.length !== 128 || address.length !== 40) {
    return { ok: false, detail: "the report does not carry a 64-byte report-data slot and a signing address" };
  }
  if (slot !== want) {
    return {
      ok: false,
      detail: slot.slice(0, 40) === address
        ? "the quote binds a different GPU nonce than the evidence carries"
        : "the quote binds a different signing address",
    };
  }
  return { ok: true, detail: `report data binds ${signingAddress} and GPU nonce ${nonce}` };
}

async function verifyNrasTokens(payload, { fetchImpl, nonce, now }) {
  let res;
  try {
    res = await fetchImpl(NRAS_ATTEST_URL, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: payload,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    return { ok: false, detail: `NVIDIA attestation unreachable: ${err?.message ?? err}` };
  }
  if (!res.ok) return { ok: false, detail: `NVIDIA attestation answered HTTP ${res.status}` };
  const body = await res.json().catch(() => null);
  const overallToken = Array.isArray(body?.[0]) ? body[0][1] : null;
  const gpuTokens = body?.[1];
  if (typeof overallToken !== "string" || gpuTokens === null || typeof gpuTokens !== "object") {
    return { ok: false, detail: "NVIDIA attestation returned an unexpected shape" };
  }

  let jose;
  try {
    jose = await import("jose");
  } catch {
    return { ok: false, detail: "NVIDIA's tokens cannot be checked here: install jose (^6)" };
  }
  // NVIDIA rotates these keys every couple of days, which is why the tokens are
  // verified now and the decoded claims are what gets kept.
  const jwks = jose.createRemoteJWKSet(new URL(NRAS_JWKS_URL));
  const open = async (token) => {
    const { payload: claims } = await jose.jwtVerify(token, jwks, {
      issuer: NRAS_ISSUER,
      algorithms: ["ES384"],
    });
    return claims;
  };

  let overall;
  const gpus = {};
  try {
    overall = await open(overallToken);
    for (const [name, token] of Object.entries(gpuTokens)) gpus[name] = await open(token);
  } catch (err) {
    return { ok: false, detail: `an NVIDIA token did not verify: ${err?.message ?? err}` };
  }
  return { ...gateNrasClaims({ overall, gpus, nonce, now }), claims: { overall, gpus } };
}

/// Verify one confidential generation end to end. `receiptId` comes from the
/// `x-receipt-id` header of the response; `requestBytes` and `responseBytes`
/// are the exact bytes this client sent and received (pass `requestHash` /
/// `responseHash` instead when only the digests were kept). Under E2EE the
/// receipt covers the restored plaintext request, so pass
/// `restoredRequestBytes` (or `restoredRequestHash`) as well.
///
/// `expectedWorkload` is the code the enclave must be running; `null` downgrades
/// that check to a skip and says so. `expectedKeysetDigest` is the key set a
/// prompt was actually sealed to, which is what ties this transcript to the call
/// it describes rather than to whatever the endpoint serves now.
///
/// The verdict is `verified` when every check that ran passed and every skip is
/// one of the documented ones, `failed` when a check failed, and `incomplete`
/// when nothing failed but evidence the verdict would have rested on was
/// missing. No verification outcome is ever thrown; the one thing that throws is
/// a gateway this client cannot reach at all, which is not a statement about the
/// workload.
export async function verifyConfidential({
  base = DEFAULT_CONFIDENTIAL_BASE,
  model,
  receiptId,
  receipt = null,
  requestBytes = null,
  responseBytes = null,
  requestHash = null,
  responseHash = null,
  restoredRequestBytes = null,
  restoredRequestHash = null,
  e2ee = false,
  expectedWorkload = EXPECTED_WORKLOAD,
  expectedKeysetDigest = null,
  nonce = randomNonce(),
  now = Math.floor(Date.now() / 1000),
  observedSpki = null,
  collateralUrl = undefined,
  fetchImpl = fetch,
} = {}) {
  if (!receiptId && !receipt) {
    throw new Error("no receipt to verify: the response carried no x-receipt-id header");
  }
  const t = new Transcript();
  const root = String(base).replace(/\/+$/, "");
  const expectedSkips = new Set([CUSTODY]);
  if (!observedSpki) expectedSkips.add(CHANNEL);
  const settle = (extra) => verdict(t, expectedSkips, { nonce, receiptId, model: model ?? null, ...extra });

  const fetched = await getJson(fetchImpl, `${root}/v1/attestation?nonce=${nonce}`, "the attestation endpoint");
  if (!fetched.ok) {
    // Without a report there is nothing to establish anything against, and the
    // two checks that are never a pass keep saying why they are not.
    for (const id of Object.keys(CHECKS)) {
      if (id !== CUSTODY && id !== CHANNEL) t.fail(id, fetched.detail);
    }
    channelCheck(t, null, observedSpki, root);
    t.skip(CUSTODY, CUSTODY_DETAIL);
    return settle({ keysetDigest: null, provenance: null });
  }
  const report = fetched.body;

  const binding = await verifyReportBinding(report, nonce, { now });
  const digest = binding.workloadKeysetDigest;
  const keyset = binding.keyset;
  const badBinding = binding.checks.find((c) => !c.ok);
  if (badBinding) {
    t.fail("keyset-digest", badBinding.detail ?? `${badBinding.name} failed`);
  } else if (expectedKeysetDigest && digest !== expectedKeysetDigest) {
    // The report is sound, but it describes a different key set than the one
    // the prompt was sealed to, so it is not this call's report.
    t.fail("keyset-digest", `the endpoint now serves ${digest}, this call was sealed to ${expectedKeysetDigest}`);
  } else {
    t.pass("keyset-digest", `${digest}, aci/1, valid until ${unixTime(keyset.not_after)}`);
  }

  const quote = await verifyQuote(report, { collateralUrl, now });
  if (!quote.ok) {
    t.fail("tdx-quote", quote.detail ?? "quote verification failed");
  } else if (quote.status !== "UpToDate") {
    const advisories = quote.advisoryIds?.length ? ` (${quote.advisoryIds.join(", ")})` : "";
    t.fail("tdx-quote", `verified to Intel's root, but the platform TCB is ${quote.status}${advisories}`);
  } else {
    t.pass("tdx-quote", "verified to Intel's root, platform TCB up to date");
  }

  // The 32 bytes the enclave asked the CPU to sign, read out of the verified
  // quote rather than off the report's own copy of them. A quote too malformed
  // to read at all leaves nothing to compare, which the check below says.
  const slot = quote.ok ? quote.report.reportData : readReportData(report.attestation?.evidence?.quote);
  const unverified = quote.ok ? "" : " (read off an unverified quote)";
  if (!digest) {
    t.fail("report-data-binding", "no key set was established, so nothing can be recomputed against the quote");
  } else {
    const expected = await computeReportData(digest, nonce);
    const bound = slot.length === 64 ? toHex(slot.slice(0, 32)) : "nothing: the quote carries no report-data slot";
    const padded = slot.length === 64 && slot.slice(32).every((b) => b === 0);
    if (bound === expected && padded) {
      t.pass("report-data-binding", `the quote's report data is sha256 of our nonce over ${digest}${unverified}`);
    } else {
      t.fail("report-data-binding", `the quote binds ${bound}, this nonce and key set produce ${expected}`);
    }
  }

  let measurement = null;
  try {
    measurement = await verifyComposeMeasurement(report, { statedRtmr3: quote.ok ? quote.report.rtMr3 : null });
    const rtmr3 = measurement.checks.find((c) => c.name === "rtmr3");
    t.add("rtmr3-replay", rtmr3.ok ? "pass" : "fail", rtmr3.ok ? `${toHex(measurement.rtmr3)}${unverified}` : rtmr3.detail);
    const composeHash = measurement.checks.find((c) => c.name === "compose_hash");
    t.add(
      "compose-hash",
      composeHash.ok ? "pass" : "fail",
      composeHash.ok
        ? `sha256(app_compose)=${measurement.composeHash} measured before system-ready`
        : composeHash.detail,
    );
    if (!measurement.ok) measurement = null;
  } catch (err) {
    t.fail("rtmr3-replay", `the report's boot evidence could not be replayed: ${err?.message ?? err}`);
    t.fail("compose-hash", "no replayable boot evidence to measure the compose against");
  }

  // §9.1 check 4. Everything above establishes a genuine TDX enclave; this is
  // the check that says which code is running inside it.
  let provenance = null;
  if (!measurement) {
    t.fail(WORKLOAD, "no measured compose to read the workload identity out of");
  } else {
    const identity = await appraiseWorkload(report, measurement, expectedWorkload);
    provenance = identity.provenance ?? null;
    t.add(WORKLOAD, identity.skipped ? "skip" : identity.ok ? "pass" : "fail", identity.detail);
  }

  // A receipt lives in the workload's memory only, so a caller that fetched it
  // when the answer arrived passes it in rather than hoping it is still there.
  const document = receipt ?? (await receiptDocument(fetchImpl, root, receiptId));
  if (!document) {
    for (const id of ["receipt-signature", "receipt-keyset-binding", "request-hash", "response-hash"]) {
      t.fail(id, "the receipt for this call could not be read");
    }
    t.fail("upstream-verified", "no receipt to read an upstream verification out of");
    t.skip("session-id", "no session is cited");
    t.skip("session-evidence", "no session is cited");
    await gpuChecks(t, { root, fetchImpl, model, digest, quote, collateralUrl, now });
    channelCheck(t, keyset, observedSpki, root);
    t.skip(CUSTODY, CUSTODY_DETAIL);
    return settle({ keysetDigest: digest ?? null, provenance });
  }
  const verified = keyset ? await verifyReceipt(document, keyset, digest) : null;
  const signature = verified?.checks.find((c) => c.name === "signature");
  t.add(
    "receipt-signature",
    signature?.ok ? "pass" : "fail",
    signature?.ok ? `key "${document.key_id}"` : (signature?.detail ?? "no key set to verify the receipt against"),
  );
  const version = verified?.checks.find((c) => c.name === "api_version");
  const bound = verified?.checks.find((c) => c.name === "workload_keyset_digest");
  if (version?.ok === false) {
    t.fail("receipt-keyset-binding", version.detail);
  } else {
    t.add(
      "receipt-keyset-binding",
      bound?.ok ? "pass" : "fail",
      bound?.ok ? `${digest}, served at ${unixTime(document.served_at)}` : (bound?.detail ?? "the receipt binds no key set"),
    );
  }

  await bodyCheck(t, "request-hash", document, "request.received", {
    bytes: e2ee ? restoredRequestBytes : requestBytes,
    hash: e2ee ? restoredRequestHash : requestHash,
  });
  await bodyCheck(t, "response-hash", document, "response.returned", { bytes: responseBytes, hash: responseHash });

  const sessionId = await upstreamCheck(t, document);
  if (sessionId) await sessionChecks(t, { root, fetchImpl, sessionId, servedAt: document.served_at });

  await gpuChecks(t, { root, fetchImpl, model, digest, quote, collateralUrl, now });

  channelCheck(t, keyset, observedSpki, root);

  // §9.1 check 5. The report does publish dstack-kms custody evidence, but
  // appraising it needs the KMS root key and chain rules no verifier in this
  // protocol implements yet, so this is reported as unproven rather than
  // waved through.
  t.skip(CUSTODY, CUSTODY_DETAIL);

  return settle({ model: document.model ?? model ?? null, keysetDigest: digest ?? null, provenance });
}

const CUSTODY_DETAIL =
  "no verifier appraises the KMS custody chain yet; encrypt end to end rather than rely on it";

/// The verdict rule over a finished check list. `failed` means a check actually
/// failed. `incomplete` means nothing failed but evidence the verdict would have
/// rested on was missing, which is a different thing to say and is said with a
/// different word.
export function verdictOf(checks, expectedSkips = [CUSTODY, CHANNEL]) {
  const tolerated = new Set(expectedSkips);
  if (checks.some((c) => c.status === "fail")) return "failed";
  return checks.some((c) => c.status === "skip" && !tolerated.has(c.id)) ? "incomplete" : "verified";
}

function verdict(t, expectedSkips, rest) {
  return { verdict: verdictOf(t.checks, expectedSkips), checks: t.checks, ...rest };
}

function readReportData(quoteHex) {
  try {
    return quoteReportData(String(quoteHex ?? ""));
  } catch {
    return new Uint8Array(0);
  }
}

async function receiptDocument(fetchImpl, root, receiptId) {
  const fetched = await getJson(fetchImpl, `${root}/v1/receipts/${encodeURIComponent(receiptId)}`, "the receipt endpoint");
  return fetched.ok ? fetched.body : null;
}

async function bodyCheck(t, id, receipt, event, { bytes, hash }) {
  const recorded = findEvent(receipt, event)?.body_hash;
  if (typeof recorded !== "string") return t.fail(id, `the receipt carries no ${event} body hash`);
  const computed = bytes ? await hashBody(bytes) : hash;
  if (!computed) {
    return t.skip(id, `no ${event === "request.received" ? "request" : "response"} bytes were kept to compare`);
  }
  if (computed === recorded) return t.pass(id, recorded);
  return t.fail(id, `the bytes hash to ${computed}, the receipt records ${recorded}`);
}

async function upstreamCheck(t, receipt) {
  const events = Array.isArray(receipt.event_log) ? receipt.event_log.filter((e) => e.type === "upstream.verified") : [];
  if (events.length === 0) {
    t.fail("upstream-verified", "the receipt records no upstream verification");
    t.skip("session-id", "no session is cited");
    t.skip("session-evidence", "no session is cited");
    return null;
  }
  const verified = events.find((e) => e.result === "verified");
  if (!verified) {
    const why = events[0].reason ?? "no reason given";
    t.fail("upstream-verified", `the receipt records serving through an unverified upstream: ${why}`);
    t.skip("session-id", "no session is cited");
    t.skip("session-evidence", "no session is cited");
    return null;
  }
  if (verified.required !== true) {
    t.fail("upstream-verified", "the upstream verified, but verification was not required for this request");
  } else if (typeof verified.session_id !== "string") {
    t.fail("upstream-verified", "the upstream verified but the receipt cites no session");
  } else {
    t.pass("upstream-verified", `${verified.model_id ?? "the model"} served through session ${verified.session_id}`);
  }
  return typeof verified.session_id === "string" ? verified.session_id : null;
}

async function sessionChecks(t, { root, fetchImpl, sessionId, servedAt }) {
  let fetched;
  try {
    fetched = await getJson(fetchImpl, `${root}/v1/sessions/${encodeURIComponent(sessionId)}`, "the sessions endpoint");
  } catch (err) {
    fetched = { ok: false, detail: err?.message ?? String(err) };
  }
  if (!fetched.ok) {
    t.skip("session-id", `the cited session could not be fetched: ${fetched.detail}`);
    t.skip("session-evidence", "no session record to hash");
    return;
  }
  const session = fetched.body;
  const problems = [];
  if ((await computeSessionId(session)) !== sessionId) problems.push("the record does not hash to the cited id");
  if (session.api_version !== "aci/1") problems.push(`api_version "${session.api_version}" is not "aci/1"`);
  if (!(servedAt >= session.established_at && servedAt <= session.expires_at)) {
    problems.push("the request was served outside the session's validity window");
  }
  t.add("session-id", problems.length === 0 ? "pass" : "fail", problems.length === 0
    ? `${session.upstream_name}, valid ${unixTime(session.established_at)} to ${unixTime(session.expires_at)}`
    : problems.join("; "));

  const evidenceOk = await checkSessionEvidence(session.evidence);
  t.add("session-evidence", evidenceOk ? "pass" : "fail", evidenceOk
    ? session.evidence.digest
    : "the session's evidence does not hash to the digest it records");
}

async function gpuChecks(t, { root, fetchImpl, model, digest, quote, collateralUrl, now }) {
  let fetched;
  try {
    // Name the instance we need. The model runs on several, and the endpoint
    // answers from whichever the upstream picks, so asking blind returns a
    // sibling most of the time: same image, same compose, different RTMR3.
    const params = new URLSearchParams();
    if (model) params.set("model", model);
    if (digest) params.set("keyset_digest", digest);
    const query = params.size ? `?${params}` : "";
    fetched = await getJson(fetchImpl, `${root}/v1/gpu-evidence${query}`, "the GPU evidence endpoint");
  } catch (err) {
    fetched = { ok: false, detail: err?.message ?? String(err) };
  }
  if (!fetched.ok) {
    t.skip("gpu-nras", `the GPU evidence could not be fetched: ${fetched.detail}`);
    t.skip("gpu-binding", "no GPU evidence to bind");
    return;
  }
  const report = fetched.body;
  const payload = report?.nvidia_payload;
  if (typeof payload !== "string") {
    t.fail("gpu-nras", "the GPU evidence carries no NVIDIA attestation payload");
    t.fail("gpu-binding", "no GPU evidence to bind");
    return;
  }
  let nonce;
  try {
    nonce = JSON.parse(payload).nonce;
  } catch {
    nonce = null;
  }
  if (typeof nonce !== "string") {
    t.fail("gpu-nras", "the NVIDIA attestation payload carries no nonce");
    t.fail("gpu-binding", "no GPU nonce to bind");
    return;
  }

  const nras = await verifyNrasTokens(payload, { fetchImpl, nonce, now });
  t.add("gpu-nras", nras.ok ? "pass" : "fail", nras.detail);

  // The GPU evidence is only worth anything once it is tied to the workload we
  // verified. Its own quote is verified here, the report-data slot is read out
  // of that verified structure, and the TD it came from is held against the TD
  // whose quote carried our nonce. The plaintext key-set field the same
  // response supplies is a label, not a binding, so a label that disagrees is
  // reported and then ignored: the evidence endpoint is served by one replica
  // and completions by another, so the label routinely names a sibling even
  // when the quotes below prove the evidence came from the TD that served us.
  // Failing on it here would reject evidence that binds cryptographically.
  const labelled = report.workload_keyset_digest;
  const mislabelled = labelled !== digest;
  if (typeof report.intel_quote !== "string") {
    return t.fail("gpu-binding", "the GPU evidence carries no CPU quote to bind against");
  }
  if (!quote?.ok) {
    return t.fail("gpu-binding", "the workload's own quote did not verify, so the GPU evidence cannot be tied to it");
  }
  const gpuQuote = await verifyRawQuote(report.intel_quote, { collateralUrl, now });
  if (!gpuQuote.ok) return t.fail("gpu-binding", `the GPU evidence's own quote did not verify: ${gpuQuote.detail}`);
  const tie = sameTd(quote.report, gpuQuote.report);
  if (!tie.ok) {
    return t.fail(
      "gpu-binding",
      `the GPU evidence's quote comes from a different TD: ${tie.differing.join(", ")} do not match the workload's quote`,
    );
  }
  const gate = gateGpuBinding({
    reportData: toHex(gpuQuote.report.reportData),
    signingAddress: report.signing_address,
    nonce,
  });
  const aside = mislabelled ? `; the evidence labels itself key set ${labelled}, which the quotes above override` : "";
  t.add(
    "gpu-binding",
    gate.ok ? "pass" : "fail",
    gate.ok ? `${gate.detail}, quoted by the TD that carried our nonce${aside}` : gate.detail,
  );
}

const TD_MEASUREMENTS = ["mrTd", "rtMr0", "rtMr1", "rtMr2", "rtMr3"];

/// Whether two verified TD reports describe the same TD. RTMR3 covers the
/// instance id, so this is a per-instance tie and not merely "another box
/// running the same image".
export function sameTd(a, b) {
  const differing = TD_MEASUREMENTS.filter((f) => toHex(a?.[f] ?? []) !== toHex(b?.[f] ?? []));
  return { ok: differing.length === 0, differing };
}

/// §9.1 check 6. The pin says the connection terminated at a key the enclave
/// published. It does not say TLS terminates inside the enclave: no evidence in
/// this protocol establishes that, which is why the honest answer without an
/// observed certificate is a skip and why E2EE is the mechanism that does not
/// depend on the answer.
function channelCheck(t, keyset, observedSpki, root) {
  if (!observedSpki) {
    return t.skip(
      CHANNEL,
      "no TLS certificate was observed from here; a prompt's protection rests on end-to-end encryption, not on this pin",
    );
  }
  const entries = Array.isArray(keyset?.tls_public_keys) ? keyset.tls_public_keys : [];
  if (entries.length === 0) return t.fail(CHANNEL, "the attested key set publishes no TLS key to pin against");
  const host = (() => {
    try {
      return new URL(root).hostname.toLowerCase();
    } catch {
      return null;
    }
  })();
  const observed = observedSpki.toLowerCase();
  // §3.1 makes `domain` optional, and the same report shape uses explicit nulls
  // for unknown values, so anything that is not a string is an unscoped entry.
  const candidates = entries.filter((k) => typeof k.domain !== "string" || host === null || k.domain.toLowerCase() === host);
  return candidates.some((k) => String(k.spki_sha256).toLowerCase() === observed)
    ? t.pass(CHANNEL, `the observed TLS key ${observed} is in the attested key set`)
    : t.fail(CHANNEL, `the observed TLS key ${observed} is not in the attested key set`);
}

/// The SHA-256 of the SPKI the TLS server at `url` actually presented, for the
/// channel check. `fetch` does not expose the peer certificate, so this opens
/// its own connection; the pin is only meaningful against a host that serves
/// the attested workload directly, not through a relay that terminates TLS of
/// its own.
export async function observeTlsSpki(url) {
  const { connect } = await import("node:tls");
  const { X509Certificate, createHash } = await import("node:crypto");
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const socket = connect(
      { host: target.hostname, port: Number(target.port || 443), servername: target.hostname },
      () => {
        const peer = socket.getPeerCertificate();
        socket.end();
        if (!peer?.raw) return reject(new Error("the TLS peer presented no certificate"));
        // getPeerCertificate().pubkey is the raw EC point, not the SPKI the
        // keyset pins, so the key is re-exported from the certificate itself.
        const spki = new X509Certificate(peer.raw).publicKey.export({ type: "spki", format: "der" });
        resolve(createHash("sha256").update(spki).digest("hex"));
      },
    );
    socket.on("error", reject);
  });
}

/// The checks table as a few lines of text, for a terminal or a tool result.
export function renderChecks(result) {
  const mark = { pass: "ok  ", fail: "FAIL", skip: "skip" };
  const lines = result.checks.map((c) => `${mark[c.status]} ${c.title}${c.detail ? `\n       ${c.detail}` : ""}`);
  const counts = ["pass", "fail", "skip"].map((s) => `${result.checks.filter((c) => c.status === s).length} ${s}`);
  return `${lines.join("\n")}\n\n${result.verdict} (${counts.join(", ")})`;
}
