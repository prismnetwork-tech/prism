import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  appraiseWorkload,
  EXPECTED_WORKLOAD,
  gateGpuBinding,
  gateNrasClaims,
  gateWorkloadIdentity,
  measuredEvent,
  renderChecks,
  sameTd,
  verdictOf,
  verifyConfidential,
} from "./attest.mjs";
import {
  attestationStatement,
  computeKeysetDigest,
  computeReportData,
  computeSessionId,
  fromHex,
  hashBody,
  jcsBytes,
  quoteReportData,
  replayRtmr3,
  toHex,
  verifyComposeMeasurement,
  verifyReceipt,
  verifyReportBinding,
} from "./vendor/aci-verifier/index.mjs";

const utf8 = (bytes) => Buffer.from(bytes).toString("utf8");
const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

// spec/test-vectors.md §1-4 of the ACI specification, reproduced byte for byte.
// The keys below are the vector document's fixed seeds, not anything live.
const KEYSET_JCS =
  '{"e2ee_public_keys":[{"algo":"x25519-aes-256-gcm-hkdf-sha256","key_id":"e2ee-1","public_key":"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"}],"not_after":1800000000,"receipt_signing_keys":[{"algo":"ed25519","key_id":"receipt-1","public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"}],"subject":"dstack-app://example-app","tls_public_keys":[{"domain":"api.example.com","spki_sha256":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}]}';
const KEYSET_DIGEST = "sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371";
const VECTOR_NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SESSION_JCS =
  '{"api_version":"aci/1","channel_binding":[{"origin":"https://upstream.example.com","spki_sha256":"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1","type":"tls_spki_sha256"}],"claims":{"extra":{"gpu_arch":"HOPPER","tcb_status":"UpToDate"},"gpu_attested":{"status":"unknown"},"model_weights_provenance":{"status":"unknown"},"os_known_good":{"status":"unknown"},"serving_software_known_good":{"status":"unknown"},"tcb_up_to_date":{"status":"unknown"},"tee_attested":{"reason":"example quote verified","source":"hardware_proven","status":"asserted"}},"endpoint":"https://upstream.example.com","established_at":1750000000,"evidence":{"data":"data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZQ==","digest":"sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d"},"expires_at":1750003600,"upstream_name":"demo-upstream","verifier_id":"example/1"}';
const SESSION_ID = "95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f";
const RECEIPT_JCS =
  '{"api_version":"aci/1","chat_id":"chatcmpl-123","endpoint":"/v1/chat/completions","event_log":[{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.received"},{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.forwarded"},{"model_id":"demo-model","required":true,"result":"verified","session_id":"95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f","type":"upstream.verified"},{"body_hash":"sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61","type":"response.returned"}],"key_id":"receipt-1","method":"POST","model":"demo-model","receipt_id":"rcpt-0001","served_at":1750000000,"workload_keyset_digest":"sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371"}';
const RECEIPT_SIGNATURE =
  "d5b005e093bde3b577faf270b7184b09e169cacb0ecb206b103bd2581f997db03da616175454b063323a23ac1dc68f1ce506c2a6eba8aa0561d5e724f0b80c03";
const REQUEST_BODY = '{"messages":[{"content":"hi","role":"user"}],"model":"demo-model"}';
const RESPONSE_BODY = '{"choices":[],"id":"chatcmpl-123"}';

const specKeyset = JSON.parse(KEYSET_JCS);
const specReceipt = { ...JSON.parse(RECEIPT_JCS), signature: RECEIPT_SIGNATURE };

// One live report from the public attestation endpoint, kept as the offline
// fixture for the replay and binding checks. Its app_compose travels base64 in
// the fixture (the measured compose is a shell script whose paths the secret
// scanner reads as leaked local ones) and is restored here byte for byte,
// because the whole point of the check is that those bytes hash to the
// measurement.
const capture = JSON.parse(readFileSync(new URL("./fixtures/aci-attestation.json", import.meta.url), "utf8"));
capture.report.attestation.evidence.app_compose = Buffer.from(
  capture.report.attestation.evidence.app_compose_b64,
  "base64",
).toString("utf8");
const binding = JSON.parse(readFileSync(new URL("./fixtures/gpu-evidence-binding.json", import.meta.url), "utf8"));

test("canonicalization is member order independent and reproduces the vector digest", async () => {
  // Deliberately shuffled: the digest is over the JCS form, never over the
  // encoding a service happened to serve.
  const shuffled = {
    tls_public_keys: [{ spki_sha256: specKeyset.tls_public_keys[0].spki_sha256, domain: "api.example.com" }],
    not_after: 1800000000,
    subject: "dstack-app://example-app",
    e2ee_public_keys: [
      {
        public_key: specKeyset.e2ee_public_keys[0].public_key,
        key_id: "e2ee-1",
        algo: "x25519-aes-256-gcm-hkdf-sha256",
      },
    ],
    receipt_signing_keys: [
      { public_key: specKeyset.receipt_signing_keys[0].public_key, algo: "ed25519", key_id: "receipt-1" },
    ],
  };
  assert.equal(utf8(jcsBytes(shuffled)), KEYSET_JCS);
  assert.equal(await computeKeysetDigest(shuffled), KEYSET_DIGEST);
});

test("the attestation statement and report_data match the vectors", async () => {
  assert.equal(
    utf8(attestationStatement(KEYSET_DIGEST, VECTOR_NONCE)),
    `{"keyset_digest":"${KEYSET_DIGEST}","nonce":"${VECTOR_NONCE}","purpose":"aci.report_data.v1"}`,
  );
  assert.equal(
    await computeReportData(KEYSET_DIGEST, VECTOR_NONCE),
    "df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e",
  );
  // A missing nonce is the JSON literal null, and proves binding but not freshness.
  assert.equal(
    utf8(attestationStatement(KEYSET_DIGEST, null)),
    `{"keyset_digest":"${KEYSET_DIGEST}","nonce":null,"purpose":"aci.report_data.v1"}`,
  );
  assert.equal(
    await computeReportData(KEYSET_DIGEST, null),
    "0633919ca3f00e97bafaa3304278eb22420cc3ff0d19f87dfca2d3f7508150bc",
  );
});

test("a session id is the hash of the document, and body hashes are the wire bytes", async () => {
  assert.equal(await computeSessionId(JSON.parse(SESSION_JCS)), SESSION_ID);
  assert.equal(await hashBody(REQUEST_BODY), "sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b");
  assert.equal(await hashBody(RESPONSE_BODY), "sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61");
});

test("the vector receipt verifies under the vector key", async () => {
  assert.equal(sha256Hex(Buffer.from(RECEIPT_JCS, "utf8")), "1bd328e6880a5a12b3915af95ea32111310e04ab9e21ac3d71ce268e33b965c9");
  const result = await verifyReceipt(specReceipt, specKeyset, KEYSET_DIGEST);
  assert.equal(result.ok, true, JSON.stringify(result.checks));
});

test("a receipt signed for another key set, or altered after signing, does not verify", async () => {
  const foreign = await verifyReceipt(specReceipt, specKeyset, "sha256:" + "0".repeat(64));
  assert.equal(foreign.ok, false);
  assert.equal(foreign.checks.find((c) => c.name === "workload_keyset_digest").ok, false);
  assert.equal(foreign.checks.find((c) => c.name === "signature").ok, true);

  const altered = await verifyReceipt({ ...specReceipt, served_at: 1750000001 }, specKeyset, KEYSET_DIGEST);
  assert.equal(altered.checks.find((c) => c.name === "signature").ok, false);
});

test("the captured report binds its key set to the nonce it was fetched with", async () => {
  const result = await verifyReportBinding(capture.report, capture.nonce, { now: 1787600000 });
  assert.equal(result.ok, true, JSON.stringify(result.checks));
  assert.equal(result.workloadKeysetDigest, capture.report.workload_keyset_digest);

  // The report's own copy of report_data is never what a verifier trusts: these
  // 32 bytes come out of the quote itself, at the v4 TDX report-data offset.
  const slot = quoteReportData(capture.report.attestation.evidence.quote);
  assert.equal(toHex(slot.slice(0, 32)), await computeReportData(result.workloadKeysetDigest, capture.nonce));
  assert.ok(slot.slice(32).every((b) => b === 0));
});

test("a report answering a different nonce fails the binding", async () => {
  const result = await verifyReportBinding(capture.report, "0".repeat(64), { now: 1787600000 });
  assert.equal(result.checks.find((c) => c.name === "report_data").ok, false);
  assert.equal(result.checks.find((c) => c.name === "workload_keyset_digest").ok, true);
});

test("the captured event log replays to the quote's RTMR3 and measures the compose", async () => {
  const events = JSON.parse(capture.report.attestation.evidence.event_log);
  const quote = fromHex(capture.report.attestation.evidence.quote);
  assert.equal(toHex(await replayRtmr3(events)), toHex(quote.slice(520, 568)));

  const compose = await verifyComposeMeasurement(capture.report);
  assert.equal(compose.ok, true, JSON.stringify(compose.checks));
  assert.equal(compose.composeHash, sha256Hex(Buffer.from(capture.report.attestation.evidence.app_compose, "utf8")));
});

test("a second compose-hash event before system-ready fails the measurement", async () => {
  const events = JSON.parse(capture.report.attestation.evidence.event_log);
  const at = events.findIndex((e) => e.imr === 3 && e.event === "compose-hash");
  const second = { ...events[at], event_payload: "0".repeat(64) };
  const tampered = {
    ...capture.report,
    attestation: {
      ...capture.report.attestation,
      evidence: {
        ...capture.report.attestation.evidence,
        event_log: JSON.stringify(events.toSpliced(at + 1, 0, second)),
      },
    },
  };
  const compose = await verifyComposeMeasurement(tampered);
  assert.equal(compose.checks.find((c) => c.name === "compose_hash").ok, false);
  // The replay covers every imr==3 event, so the added one moves RTMR3 too.
  assert.equal(compose.checks.find((c) => c.name === "rtmr3").ok, false);
});

test("an app_compose that does not hash to the measured value fails", async () => {
  const tampered = {
    ...capture.report,
    attestation: {
      ...capture.report.attestation,
      evidence: { ...capture.report.attestation.evidence, app_compose: "services: {}\n" },
    },
  };
  const compose = await verifyComposeMeasurement(tampered);
  assert.equal(compose.checks.find((c) => c.name === "compose_hash").ok, false);
  assert.equal(compose.checks.find((c) => c.name === "rtmr3").ok, true);
});

test("the shipped pin is the deployment the captured report describes", async () => {
  const compose = await verifyComposeMeasurement(capture.report);
  const identity = await appraiseWorkload(capture.report, compose);
  assert.equal(identity.ok, true, identity.detail);
  assert.equal(identity.provenance, `${EXPECTED_WORKLOAD.repoUrl} @ ${capture.report.attestation.source_provenance.repo_commit}`);
  assert.match(identity.detail, /private-ai-launcher@sha256:c083ff9e6a5d/);
  // The pin appraises the deployment behind a known-good snapshot, and the
  // detail has to keep saying so.
  assert.match(identity.detail, /snapshot of a known-good deployment/);
});

test("a payload that does not reproduce its measured digest is not measured evidence", async () => {
  const events = JSON.parse(capture.report.attestation.evidence.event_log);
  assert.equal(await measuredEvent(events, "os-image-hash"), EXPECTED_WORKLOAD.osImageHash);

  // RTMR3 chains each event's digest, never its payload, so a rewritten payload
  // under an untouched digest counts for nothing.
  const at = events.findIndex((e) => e.imr === 3 && e.event === "os-image-hash");
  const rewritten = events.with(at, { ...events[at], event_payload: "ee".repeat(32) });
  assert.equal(await measuredEvent(rewritten, "os-image-hash"), null);
  assert.equal(await measuredEvent(events, "no-such-event"), null);
});

test("the workload identity pin refuses a launcher, a source or an OS image it does not name", () => {
  const compose = JSON.stringify({
    docker_compose_file:
      `services:\n  launcher:\n    image: ${EXPECTED_WORKLOAD.launcherImage}\n` +
      `    environment:\n      REPO_URL=${EXPECTED_WORKLOAD.repoUrl}\n      REPO_COMMIT=${EXPECTED_WORKLOAD.repoCommit}\n`,
  });
  const provenance = { repo_url: EXPECTED_WORKLOAD.repoUrl, repo_commit: EXPECTED_WORKLOAD.repoCommit, image_digest: null };
  const input = { appCompose: compose, osImageHash: EXPECTED_WORKLOAD.osImageHash, provenance, expected: EXPECTED_WORKLOAD };

  const clean = gateWorkloadIdentity(input);
  assert.equal(clean.ok, true, clean.detail);
  assert.equal(clean.provenance, `${EXPECTED_WORKLOAD.repoUrl} @ ${EXPECTED_WORKLOAD.repoCommit}`);

  const otherCommit = gateWorkloadIdentity({
    ...input,
    appCompose: compose.replace(EXPECTED_WORKLOAD.repoCommit, "a1".repeat(20)),
    provenance: { repo_url: EXPECTED_WORKLOAD.repoUrl, repo_commit: "a1".repeat(20) },
  });
  assert.equal(otherCommit.ok, false);
  assert.match(otherCommit.detail, /the measured commit is a1a1/);

  const otherLauncher = gateWorkloadIdentity({
    ...input,
    appCompose: compose.replace(/@sha256:[0-9a-f]{64}/, `@sha256:${"9c".repeat(32)}`),
  });
  assert.equal(otherLauncher.ok, false);
  assert.match(otherLauncher.detail, /the measured launcher is sha256:9c9c/);

  const otherRepo = gateWorkloadIdentity({
    ...input,
    appCompose: compose.replace(EXPECTED_WORKLOAD.repoUrl, "https://github.com/attacker/gateway.git"),
  });
  assert.equal(otherRepo.ok, false);
  assert.match(otherRepo.detail, /the measured source is https:..github.com.attacker/);

  const otherOs = gateWorkloadIdentity({ ...input, osImageHash: "cc".repeat(32) });
  assert.equal(otherOs.ok, false);
  assert.match(otherOs.detail, /the measured OS image is cccc/);

  // §4.1: the report's own provenance is not bound into the quote, so a report
  // claiming a source the measured compose does not clone is refused.
  const lying = gateWorkloadIdentity({
    ...input,
    provenance: { repo_url: EXPECTED_WORKLOAD.repoUrl, repo_commit: "ff".repeat(20) },
  });
  assert.equal(lying.ok, false);
  assert.match(lying.detail, /the report declares commit ffff/);

  const noLauncher = gateWorkloadIdentity({ ...input, appCompose: '{"docker_compose_file":"services: {}"}' });
  assert.equal(noLauncher.ok, false);
  assert.match(noLauncher.detail, /runs no ghcr.io\/redpill-ai\/private-ai-launcher image/);
});

test("two verified TD reports tie only when every measurement matches", () => {
  const td = (rtMr3) => ({
    mrTd: Buffer.alloc(48, 1),
    rtMr0: Buffer.alloc(48, 2),
    rtMr1: Buffer.alloc(48, 3),
    rtMr2: Buffer.alloc(48, 4),
    rtMr3: Buffer.alloc(48, rtMr3),
  });
  assert.deepEqual(sameTd(td(5), td(5)), { ok: true, differing: [] });
  // RTMR3 covers the instance id, so a bundle lifted from another box running
  // the same image still fails the tie.
  assert.deepEqual(sameTd(td(5), td(6)), { ok: false, differing: ["rtMr3"] });
  assert.equal(sameTd(td(5), { ...td(5), mrTd: Buffer.alloc(48, 9) }).ok, false);
});

// The claim shape NVIDIA's attestation service returns for a Hopper GPU.
const nrasNonce = "bae90a941e72817cc7c2a18c100f0e8fe8f5dd53d27f2af20578bf857fa1fa95";
const overallClaims = { "x-nvidia-overall-att-result": true, eat_nonce: nrasNonce, exp: 1787616107 };
const gpuOk = {
  measres: "success",
  secboot: true,
  dbgstat: "disabled",
  hwmodel: "GH100",
  eat_nonce: nrasNonce,
  "x-nvidia-gpu-attestation-report-nonce-match": true,
  "x-nvidia-attestation-warning": null,
};

test("the GPU claim gate passes a clean attestation and names the hardware", () => {
  const gate = gateNrasClaims({ overall: overallClaims, gpus: { "GPU-0": gpuOk }, nonce: nrasNonce, now: 1787612600 });
  assert.equal(gate.ok, true, gate.detail);
  assert.match(gate.detail, /GPU-0 GH100/);
});

test("the GPU claim gate refuses every way an attestation can be weak", () => {
  const cases = {
    "overall attestation result": { overall: { ...overallClaims, "x-nvidia-overall-att-result": false } },
    "different nonce": { overall: { ...overallClaims, eat_nonce: "0".repeat(64) } },
    expired: { now: 1787616108 },
    measurements: { gpus: { "GPU-0": { ...gpuOk, measres: "failure" } } },
    "secure boot": { gpus: { "GPU-0": { ...gpuOk, secboot: false } } },
    debug: { gpus: { "GPU-0": { ...gpuOk, dbgstat: "enabled" } } },
    warning: { gpus: { "GPU-0": { ...gpuOk, "x-nvidia-attestation-warning": "certificate expiring" } } },
    "no per-GPU token": { gpus: {} },
  };
  for (const [name, override] of Object.entries(cases)) {
    const gate = gateNrasClaims({
      overall: overallClaims,
      gpus: { "GPU-0": gpuOk },
      nonce: nrasNonce,
      now: 1787612600,
      ...override,
    });
    assert.equal(gate.ok, false, `${name} should not pass`);
  }
});

test("the GPU nonce is bound to the workload quote's report data", () => {
  const gate = gateGpuBinding({
    reportData: binding.quote_report_data,
    signingAddress: binding.signing_address,
    nonce: binding.nvidia_nonce,
  });
  assert.equal(gate.ok, true, gate.detail);

  const replayed = gateGpuBinding({
    reportData: binding.quote_report_data,
    signingAddress: binding.signing_address,
    nonce: "0".repeat(64),
  });
  assert.equal(replayed.ok, false);
  assert.match(replayed.detail, /different GPU nonce/);

  const foreign = gateGpuBinding({
    reportData: binding.quote_report_data,
    signingAddress: "0x" + "ab".repeat(20),
    nonce: binding.nvidia_nonce,
  });
  assert.equal(foreign.ok, false);
  assert.match(foreign.detail, /different signing address/);
});

// The workload this file's fake gateway claims to be, and the pin held against
// it. Same shape as the deployment the SDK ships pinned, different values.
const TEST_COMMIT = "a1".repeat(20);
const TEST_WORKLOAD = {
  launcherImage: `ghcr.io/example/launcher@sha256:${"5c".repeat(32)}`,
  repoUrl: "https://example.test/gateway.git",
  osImageHash: "3e".repeat(32),
  repoCommit: null,
};

const DSTACK_RUNTIME_EVENT = 0x08000001;

/// One dstack runtime event, with the digest RTMR3 chains computed the way the
/// guest computes it: SHA-384 over the little-endian event type, the event name
/// and the payload bytes.
function dstackEvent(event, payloadHex) {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(DSTACK_RUNTIME_EVENT);
  const body = Buffer.concat([type, Buffer.from(`:${event}:`, "utf8"), Buffer.from(payloadHex, "hex")]);
  return {
    imr: 3,
    event_type: DSTACK_RUNTIME_EVENT,
    digest: createHash("sha384").update(body).digest("hex"),
    event,
    event_payload: payloadHex,
  };
}

function composeFile({ launcher = TEST_WORKLOAD.launcherImage, repo = TEST_WORKLOAD.repoUrl, commit = TEST_COMMIT } = {}) {
  return JSON.stringify({
    docker_compose_file: [
      "services:",
      "  launcher:",
      `    image: ${launcher}`,
      "    environment:",
      `      REPO_URL=${repo}`,
      `      REPO_COMMIT=${commit}`,
      "",
    ].join("\n"),
  });
}

/// A gateway serving a report whose key set this test holds the signing key
/// for, with a boot log that replays to the RTMR3 its quote states and measures
/// a compose naming a launcher and a source. Everything except Intel's signature
/// over that quote can be checked offline this way.
function fakeGateway({
  receipt,
  session,
  now,
  compose = composeFile(),
  osImageHash = TEST_WORKLOAD.osImageHash,
  provenance,
  tlsDomain = "gateway.test",
}) {
  const key = generateKeyPairSync("ed25519");
  const publicKey = key.publicKey.export({ type: "spki", format: "der" }).subarray(12);
  const keyset = {
    subject: null,
    not_after: now + 3600,
    receipt_signing_keys: [{ key_id: "test-1", algo: "ed25519", public_key: toHex(publicKey) }],
    e2ee_public_keys: [],
    tls_public_keys: [{ spki_sha256: "aa".repeat(32), domain: tlsDomain }],
  };
  const events = [
    dstackEvent("compose-hash", sha256Hex(Buffer.from(compose, "utf8"))),
    dstackEvent("os-image-hash", osImageHash),
    dstackEvent("system-ready", ""),
  ];
  const signed = (document) => ({
    ...document,
    signature: toHex(sign(null, jcsBytes(document), key.privateKey)),
  });
  return {
    keyset,
    async fetch(url) {
      const target = new URL(url);
      if (target.pathname.endsWith("/v1/attestation")) {
        const nonce = target.searchParams.get("nonce");
        const digest = await computeKeysetDigest(keyset);
        // A v4 TDX quote shaped only where a verifier reads it: RTMR3 at 520,
        // the 64-byte report-data slot at 568.
        const quote = Buffer.alloc(632);
        Buffer.from(await replayRtmr3(events)).copy(quote, 520);
        Buffer.from(await computeReportData(digest, nonce), "hex").copy(quote, 568);
        return json({
          api_version: "aci/1",
          workload_keyset_digest: digest,
          attestation: {
            tee_type: "tdx",
            workload_keyset: keyset,
            report_data: await computeReportData(digest, nonce),
            source_provenance: provenance ?? { repo_url: TEST_WORKLOAD.repoUrl, repo_commit: TEST_COMMIT },
            evidence: { quote: quote.toString("hex"), event_log: JSON.stringify(events), app_compose: compose },
          },
        });
      }
      if (target.pathname.includes("/v1/receipts/")) {
        return json(signed({ ...receipt, workload_keyset_digest: await computeKeysetDigest(keyset), key_id: "test-1" }));
      }
      if (target.pathname.includes("/v1/sessions/")) return json(session);
      if (target.pathname.endsWith("/v1/gpu-evidence")) return json({ error: "not_found" }, 404);
      throw new Error(`unexpected request ${url}`);
    },
  };
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const NOW = 1790000000;
const REQUEST = Buffer.from('{"model":"demo","messages":[{"role":"user","content":"hi"}]}', "utf8");
const RESPONSE = Buffer.from('{"id":"chatcmpl-1","choices":[]}', "utf8");
const SESSION = {
  api_version: "aci/1",
  upstream_name: "demo-upstream",
  endpoint: "https://upstream.test",
  verifier_id: "test/1",
  established_at: NOW - 60,
  expires_at: NOW + 3600,
  channel_binding: [],
  claims: {},
  evidence: {
    digest: "sha256:80d70e44d0ae1e829fd5f37c3ee4a60dfbea8d3aa18407ea3f34cf7ec91da34d",
    data: "data:text/plain;base64,ZXhhbXBsZS1ldmlkZW5jZQ==",
  },
};

/// One served call: the gateway, the receipt it signs over these bytes, and the
/// verification of it. Overrides go to the gateway; `verify` goes to the client.
async function servedCall({ verify = {}, ...gatewayOptions } = {}) {
  const gateway = fakeGateway({
    now: NOW,
    session: SESSION,
    receipt: {
      api_version: "aci/1",
      receipt_id: "rcpt-test",
      chat_id: "chatcmpl-1",
      model: "demo",
      endpoint: "/v1/chat/completions",
      method: "POST",
      served_at: NOW,
      event_log: [
        { type: "request.received", body_hash: await hashBody(REQUEST) },
        {
          type: "upstream.verified",
          result: "verified",
          required: true,
          model_id: "demo",
          session_id: await computeSessionId(SESSION),
        },
        { type: "response.returned", body_hash: await hashBody(RESPONSE) },
      ],
    },
    ...gatewayOptions,
  });
  const result = await verifyConfidential({
    base: "https://gateway.test/inference",
    receiptId: "rcpt-test",
    requestBytes: REQUEST,
    responseBytes: RESPONSE,
    expectedWorkload: TEST_WORKLOAD,
    now: NOW,
    fetchImpl: gateway.fetch,
    ...verify,
  });
  return { gateway, result, status: Object.fromEntries(result.checks.map((c) => [c.id, c.status])) };
}

test("the transcript reports what it checked, what it could not, and refuses to call that verified", async () => {
  const { result, status } = await servedCall();

  assert.equal(status["keyset-digest"], "pass");
  assert.equal(status["report-data-binding"], "pass");
  assert.equal(status["rtmr3-replay"], "pass");
  assert.equal(status["compose-hash"], "pass");
  assert.equal(status["workload-identity"], "pass");
  assert.equal(status["receipt-signature"], "pass");
  assert.equal(status["receipt-keyset-binding"], "pass");
  assert.equal(status["request-hash"], "pass");
  assert.equal(status["response-hash"], "pass");
  assert.equal(status["upstream-verified"], "pass");
  assert.equal(status["session-id"], "pass");
  assert.equal(status["session-evidence"], "pass");
  // Custody has no appraiser in the protocol, and no TLS certificate was
  // observed from here. Neither is ever reported as a pass.
  assert.equal(status["key-custody"], "skip");
  assert.equal(status["tls-spki"], "skip");
  // This gateway has no real quote and no GPU evidence, and a verdict never
  // rounds that up.
  assert.equal(status["tdx-quote"], "fail");
  assert.equal(result.verdict, "failed");
  assert.equal(result.provenance, `${TEST_WORKLOAD.repoUrl} @ ${TEST_COMMIT}`);
  assert.match(renderChecks(result), /failed \(12 pass, 1 fail, 4 skip\)/);
});

test("a measured compose running another launcher or another source fails the verdict", async () => {
  const swapped = await servedCall({
    compose: composeFile({ launcher: `ghcr.io/attacker/launcher@sha256:${"7f".repeat(32)}` }),
  });
  assert.equal(swapped.status["compose-hash"], "pass", "the attacker's own compose measures consistently");
  assert.equal(swapped.status["workload-identity"], "fail");
  assert.equal(swapped.result.verdict, "failed");
  assert.match(swapped.result.checks.find((c) => c.id === "workload-identity").detail, /runs no ghcr.io\/example\/launcher/);

  const forked = await servedCall({
    compose: composeFile({ repo: "https://example.test/fork.git" }),
    provenance: { repo_url: "https://example.test/fork.git", repo_commit: TEST_COMMIT },
  });
  assert.equal(forked.status["workload-identity"], "fail");
  assert.equal(forked.result.verdict, "failed");
  assert.match(forked.result.checks.find((c) => c.id === "workload-identity").detail, /the measured source is/);
});

test("a caller who pins no workload gets an explicit incomplete, never a quiet pass", async () => {
  const { result, status } = await servedCall({ verify: { expectedWorkload: null } });
  assert.equal(status["workload-identity"], "skip");
  assert.match(result.checks.find((c) => c.id === "workload-identity").detail, /not pinned by caller/);
  // The measured source still comes back: it is inside the bytes that hash to
  // the measured compose, whatever policy the caller declined to apply.
  assert.equal(result.provenance, `${TEST_WORKLOAD.repoUrl} @ ${TEST_COMMIT}`);
});

test("incomplete says evidence was missing, and failed is kept for a check that failed", () => {
  const check = (id, status) => ({ id, title: id, status, detail: "" });
  const documented = [check("key-custody", "skip"), check("tls-spki", "skip")];

  assert.equal(verdictOf([check("tdx-quote", "pass"), ...documented]), "verified");
  // A receipt nobody kept the bytes for proves what the workload signed, not
  // that it signed this exchange, and the verdict says which of the two it is.
  assert.equal(verdictOf([check("request-hash", "skip"), ...documented]), "incomplete");
  assert.equal(verdictOf([check("workload-identity", "skip"), ...documented]), "incomplete");
  assert.equal(verdictOf([check("tdx-quote", "fail"), check("request-hash", "skip"), ...documented]), "failed");
});

test("a request the client cannot bind to the receipt leaves the verdict incomplete", async () => {
  const { result, status } = await servedCall({ verify: { requestBytes: null, e2ee: true } });
  assert.equal(status["request-hash"], "skip");
  // E2EE is no longer an excuse for tolerating that skip: the reproduction rule
  // is defined, so an unestablished request binding lowers the verdict.
  assert.equal(verdictOf(result.checks.filter((c) => c.id !== "tdx-quote")), "incomplete");
});

test("restored request bytes that do not reproduce the receipt hash fail, they do not skip", async () => {
  const { result, status } = await servedCall({
    verify: { e2ee: true, restoredRequestBytes: Buffer.from('{"model":"demo","messages":[]}', "utf8") },
  });
  assert.equal(status["request-hash"], "fail");
  assert.equal(result.verdict, "failed");
  assert.match(result.checks.find((c) => c.id === "request-hash").detail, /the receipt records sha256:/);
});

test("a transcript is bound to the key set the prompt was sealed to", async () => {
  const { result, status } = await servedCall({ verify: { expectedKeysetDigest: `sha256:${"0".repeat(64)}` } });
  assert.equal(status["keyset-digest"], "fail");
  assert.equal(result.verdict, "failed");
  assert.match(result.checks.find((c) => c.id === "keyset-digest").detail, /this call was sealed to sha256:0000/);

  const served = await servedCall();
  const bound = await verifyConfidential({
    base: "https://gateway.test/inference",
    receiptId: "rcpt-test",
    requestBytes: REQUEST,
    responseBytes: RESPONSE,
    expectedWorkload: TEST_WORKLOAD,
    expectedKeysetDigest: served.result.keysetDigest,
    now: NOW,
    fetchImpl: served.gateway.fetch,
  });
  assert.equal(bound.checks.find((c) => c.id === "keyset-digest").status, "pass");
});

test("a malformed quote comes back as a verdict, not as an exception", async () => {
  const gateway = {
    async fetch(url) {
      const target = new URL(url);
      if (target.pathname.endsWith("/v1/attestation")) {
        return json({
          api_version: "aci/1",
          workload_keyset_digest: "sha256:" + "0".repeat(64),
          attestation: {
            tee_type: "tdx",
            workload_keyset: { not_after: NOW + 60, receipt_signing_keys: [], e2ee_public_keys: [] },
            report_data: "ab".repeat(32),
            // Odd-length hex: every hex reader in the chain refuses it.
            evidence: { quote: "abc", event_log: "[]", app_compose: "{}" },
          },
        });
      }
      if (target.pathname.includes("/v1/receipts/")) return json({ api_version: "aci/1", receipt_id: "rcpt-test" });
      return json({ error: "not_found" }, 404);
    },
  };
  const result = await verifyConfidential({
    base: "https://gateway.test/inference",
    receiptId: "rcpt-test",
    now: NOW,
    fetchImpl: gateway.fetch,
  });
  assert.equal(result.verdict, "failed");
  assert.equal(result.checks.find((c) => c.id === "tdx-quote").status, "fail");
  assert.equal(result.checks.find((c) => c.id === "report-data-binding").status, "fail");
});

test("an endpoint that answers with something that is not a report fails every check", async () => {
  const result = await verifyConfidential({
    base: "https://gateway.test/inference",
    receiptId: "rcpt-test",
    now: NOW,
    fetchImpl: async () => new Response("<html>gateway timeout</html>", { status: 200 }),
  });
  assert.equal(result.verdict, "failed");
  assert.match(result.checks[0].detail, /not JSON/);
  // Nothing was established, and the two checks that are never a pass still say
  // why rather than joining in as failures.
  const status = Object.fromEntries(result.checks.map((c) => [c.id, c.status]));
  assert.equal(status["key-custody"], "skip");
  assert.equal(status["tls-spki"], "skip");
  assert.ok(result.checks.filter((c) => !["key-custody", "tls-spki"].includes(c.id)).every((c) => c.status === "fail"));
});

test("a TLS entry with an explicit null domain is unscoped, not a crash", async () => {
  const { result, status } = await servedCall({ tlsDomain: null, verify: { observedSpki: "aa".repeat(32) } });
  assert.equal(status["tls-spki"], "pass", JSON.stringify(result.checks.find((c) => c.id === "tls-spki")));
});

test("response bytes that do not match the receipt fail the check", async () => {
  const now = 1790000000;
  const request = Buffer.from("{}", "utf8");
  const gateway = fakeGateway({
    now,
    session: null,
    receipt: {
      api_version: "aci/1",
      receipt_id: "rcpt-test",
      served_at: now,
      event_log: [
        { type: "request.received", body_hash: await hashBody(request) },
        { type: "response.returned", body_hash: await hashBody("{}") },
      ],
    },
  });
  const result = await verifyConfidential({
    base: "https://gateway.test/inference",
    receiptId: "rcpt-test",
    requestBytes: request,
    responseBytes: Buffer.from('{"tampered":true}', "utf8"),
    now,
    fetchImpl: gateway.fetch,
  });
  const status = Object.fromEntries(result.checks.map((c) => [c.id, c.status]));
  assert.equal(status["response-hash"], "fail");
  // No upstream.verified event at all is a receipt that proves nothing about
  // where the model ran.
  assert.equal(status["upstream-verified"], "fail");
  assert.equal(result.verdict, "failed");
});
