#!/usr/bin/env node
// Checks a running gateway's confidential surface against the real upstream.
// Everything here is free: the quote, the attestation report, the session list,
// and the GPU evidence. Nothing in this script buys a generation.
//
//   node inference/confidential.live.mjs [base-url]
//
// Not part of the test suite; it needs a gateway and the network.
import { randomBytes } from "node:crypto";

const base = (process.argv[2] ?? "http://127.0.0.1:8500").replace(/\/$/, "");
const failures = [];

async function check(name, fn) {
  try {
    const detail = await fn();
    console.log(`ok    ${name}${detail ? `: ${detail}` : ""}`);
  } catch (err) {
    failures.push(name);
    console.log(`FAIL  ${name}: ${err.message}`);
  }
}

const get = async (path) => {
  const res = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(30_000) });
  return { res, text: await res.text() };
};

const models = await fetch(`${base}/v1/models`).then((r) => r.json());
const confidential = models.confidential;
if (!confidential) {
  console.error(`${base} serves no confidential class; set INFERENCE_CONFIDENTIAL and an upstream key`);
  process.exit(1);
}
const model = Object.keys(confidential.models)[0];
console.log(`gateway ${base}`);
console.log(`upstream ${confidential.upstream}, models ${Object.keys(confidential.models).join(", ")}\n`);

await check("an unpaid completion quotes a price", async () => {
  const { res, text } = await get("/v1/chat/completions");
  if (res.status !== 402) throw new Error(`status ${res.status}`);
  const body = JSON.parse(text);
  const amount = body.accepts?.[0]?.amount;
  if (!amount || BigInt(amount) <= 0n) throw new Error("no payable amount");
  return `${(Number(amount) / 1e6).toFixed(6)} USDG at the full cap`;
});

await check("the attestation report answers for a fresh nonce", async () => {
  const nonce = randomBytes(32).toString("hex");
  const { res, text } = await get(`/v1/attestation?nonce=${nonce}`);
  if (res.status !== 200) throw new Error(`status ${res.status}`);
  if (!res.headers.get("x-aci-keyset-digest")) throw new Error("no keyset digest header");
  const body = JSON.parse(text);
  // The nonce is bound inside report_data, not echoed as a field. Checking that
  // binding is the SDK verifier's job; this only proves the relay works.
  if (!/^[0-9a-f]{64}$/.test(body.attestation?.report_data ?? "")) throw new Error("no report data");
  if (!body.attestation?.workload_keyset) throw new Error("no workload keyset");
  return `keyset ${body.workload_keyset_digest}, source ${body.attestation.source_provenance?.repo_commit ?? "unstated"}`;
});

await check("a malformed nonce is refused here, not upstream", async () => {
  const { res, text } = await get("/v1/attestation?nonce=NOPE");
  if (res.status !== 400) throw new Error(`status ${res.status}`);
  if (JSON.parse(text).error !== "invalid_nonce") throw new Error("wrong error");
  return "400 invalid_nonce";
});

await check("the attested sessions are listed", async () => {
  const { res, text } = await get("/v1/sessions");
  if (res.status !== 200) throw new Error(`status ${res.status}`);
  const body = JSON.parse(text);
  if (!Array.isArray(body.sessions)) throw new Error("no sessions array");
  return `${body.sessions.length} sessions`;
});

await check("the GPU evidence is reachable", async () => {
  const { res, text } = await get(`/v1/gpu-evidence?model=${encodeURIComponent(model)}`);
  if (res.status !== 200) throw new Error(`status ${res.status}`);
  const body = JSON.parse(text);
  if (!body.nvidia_payload) throw new Error("no nvidia payload to send to NRAS");
  return "carries the NRAS request body";
});

await check("an unknown model is refused", async () => {
  const { res } = await get("/v1/gpu-evidence?model=gpt-4");
  if (res.status !== 400) throw new Error(`status ${res.status}`);
  return "400 unknown_model";
});

console.log(failures.length ? `\n${failures.length} failed` : "\nall clear");
process.exit(failures.length ? 1 : 0);
