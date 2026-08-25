// Ported from Dstack-TEE/private-ai-gateway clients/verifier-ts @ b6b5c1b, Apache-2.0.
//
// Report binding: §9.1 check 2 (keyset bytes -> digest -> statement ->
// report_data), check 3 (expiry) and the aci/1 protocol gate; check 4 (the
// booted compose is the measured one); check 1 (the quote verifies to the Intel
// root) through @phala/dcap-qvl.
//
// The departures from the TypeScript original all exist so the caller can
// apply its own policy to material the original keeps private: the verified TD
// report and its advisory ids are returned rather than reduced to a boolean,
// `verifyRawQuote`, `replayRtmr3` and `quoteReportData` are exported, and the
// collateral URL is always passed explicitly (the library's no-URL default
// silently uses a third-party PCCS).
import { computeKeysetDigest, computeReportData } from "./digest.mjs";
import { fromHex, sha256Hex, sha384 } from "./crypto.mjs";
import { AciFormatError } from "./errors.mjs";

// Byte offsets into a v4 TDX quote: 48-byte header, then the TDReport10 fields
// up to rt_mr3 (472 bytes) and the 64-byte report-data slot behind it.
const TDX_RTMR3_OFFSET = 520;
const TDX_REPORT_DATA_OFFSET = 568;

/// Verify the report's cryptographic bindings for `nonce`, the value this
/// client sent to `GET /v1/aci/attestation`, or null when it sent none (§3.2).
/// One recomputation establishes that the keyset is exactly what the quote
/// bound and that the quote postdates the challenge (§9.1 check 2).
export async function verifyReportBinding(report, nonce, { now = Math.floor(Date.now() / 1000) } = {}) {
  const checks = [];

  const versionOk = report.api_version === "aci/1";
  checks.push({
    name: "api_version",
    ok: versionOk,
    ...(versionOk ? {} : { detail: `api_version "${report.api_version}" is not "aci/1"` }),
  });

  const keysetValue = report.attestation?.workload_keyset;
  if (keysetValue === null || typeof keysetValue !== "object" || Array.isArray(keysetValue)) {
    const detail = "workload_keyset is not a JSON object";
    for (const name of ["workload_keyset_digest", "report_data", "not_after"]) {
      checks.push({ name, ok: false, detail });
    }
    return { ok: false, checks };
  }

  // The recomputed digest is authoritative (Appendix A): the report's restated
  // copy is checked for consistency but never feeds the statement.
  const digest = await computeKeysetDigest(keysetValue);
  pushEqual(checks, "workload_keyset_digest", report.workload_keyset_digest, digest);
  pushEqual(checks, "report_data", report.attestation.report_data, await computeReportData(digest, nonce));

  if (typeof keysetValue.not_after !== "number") {
    checks.push({ name: "not_after", ok: false, detail: "keyset has no numeric not_after" });
  } else {
    const ok = now < keysetValue.not_after;
    checks.push({
      name: "not_after",
      ok,
      ...(ok ? {} : { detail: `now ${now} >= not_after ${keysetValue.not_after}` }),
    });
  }

  return { ok: checks.every((c) => c.ok), checks, workloadKeysetDigest: digest, keyset: keysetValue };
}

function pushEqual(checks, name, actual, expected) {
  const ok = actual === expected;
  checks.push({ name, ok, ...(ok ? {} : { detail: `report ${actual} != recomputed ${expected}` }) });
}

/// §9.1 check 4 (dstack policy): the booted docker-compose is the one measured
/// into RTMR3. Replays `evidence.event_log` to RTMR3, compares it to the RTMR3
/// the quote states, then checks `sha256(app_compose)` equals the measured
/// `compose-hash`. Pass `statedRtmr3` to compare against a verified quote's
/// field instead of the raw bytes at the v4 offset.
export async function verifyComposeMeasurement(report, { statedRtmr3 = null } = {}) {
  const ev = report.attestation?.evidence ?? {};
  const { event_log: eventLog, app_compose: appCompose, quote } = ev;
  if (typeof eventLog !== "string" || typeof appCompose !== "string" || typeof quote !== "string") {
    throw new AciFormatError("evidence needs string event_log, app_compose, and quote");
  }
  const events = JSON.parse(eventLog);

  const replayed = await replayRtmr3(events);
  const stated = statedRtmr3 ?? fromHex(quote).slice(TDX_RTMR3_OFFSET, TDX_RTMR3_OFFSET + 48);
  const rtmrOk = stated.length === 48 && replayed.every((b, i) => b === stated[i]);

  // sha256(app_compose) must equal the compose-hash measured before
  // system-ready. Two pre-system-ready compose-hash events are the tampering
  // shape this lookup exists to catch.
  const preSystemReady = [];
  for (const e of events) {
    if (e.imr !== 3) continue;
    if (e.event === "system-ready") break;
    if (e.event === "compose-hash") preSystemReady.push(e);
  }
  const duplicated = preSystemReady.length > 1;
  const measured = duplicated ? undefined : preSystemReady[0]?.event_payload;
  const recomputed = (await sha256Hex(new TextEncoder().encode(appCompose))).toLowerCase();
  const composeOk = !duplicated && measured?.toLowerCase() === recomputed;

  return {
    ok: rtmrOk && composeOk,
    rtmr3: replayed,
    composeHash: recomputed,
    checks: [
      { name: "rtmr3", ok: rtmrOk, ...(rtmrOk ? {} : { detail: "event log RTMR3 != quote RTMR3" }) },
      {
        name: "compose_hash",
        ok: composeOk,
        ...(composeOk
          ? {}
          : {
              detail: duplicated
                ? "multiple pre-system-ready compose-hash events"
                : `sha256(app_compose)=${recomputed} != measured ${measured ?? "(none)"}`,
            }),
      },
    ],
  };
}

/// Replay the dstack event log's `imr==3` events to RTMR3: a SHA-384 chain over
/// each digest zero-padded to 48 bytes, from 48 zero bytes.
export async function replayRtmr3(events) {
  let mr = new Uint8Array(48);
  for (const e of events) {
    if (e.imr !== 3) continue;
    const digest = fromHex(e.digest);
    const buf = new Uint8Array(48 + Math.max(digest.length, 48));
    buf.set(mr);
    buf.set(digest, 48);
    mr = await sha384(buf);
  }
  return mr;
}

/// The 64-byte report-data slot as it sits in a raw v4 TDX quote (§3.2).
export function quoteReportData(quoteHex) {
  return fromHex(quoteHex).slice(TDX_REPORT_DATA_OFFSET, TDX_REPORT_DATA_OFFSET + 64);
}

/// A TDX quote against the Intel vendor root, with the collateral fetched from
/// `collateralUrl`. Returns the verified TD report so a caller reads RTMR3 and
/// report_data out of the verified structure rather than off the raw bytes.
export async function verifyRawQuote(quoteHex, { collateralUrl, now = Math.floor(Date.now() / 1000) } = {}) {
  // Loaded on demand: everything else here is Web Crypto, and a caller running
  // the offline checks should not have to install a quote verifier to do it.
  // The pure-JS package is the only one to use: the wasm bindings published as
  // @phala/dcap-qvl-node and @topnod/dcap-qvl-node accept a forged QE identity
  // (GHSA-796p-j2gh-9m2q).
  let qvl;
  try {
    qvl = await import("@phala/dcap-qvl");
  } catch {
    return { ok: false, detail: "the quote cannot be checked here: install @phala/dcap-qvl (^0.6.1)" };
  }
  let verified;
  try {
    const raw = fromHex(quoteHex);
    const collateral = await qvl.getCollateral(collateralUrl ?? qvl.INTEL_PCS_URL, raw);
    verified = qvl.verify(raw, collateral, now);
  } catch (e) {
    return { ok: false, detail: `quote did not verify: ${e?.message ?? e}` };
  }
  // A verified SGX quote must not satisfy a tdx report: bind the report type
  // before anyone reads a TD field off it.
  const td = verified.report.asTd10();
  if (!td) {
    return {
      ok: false,
      status: verified.status,
      detail: `verified quote is ${verified.report.type}, not a TDX TD report`,
    };
  }
  return { ok: true, status: verified.status, advisoryIds: verified.advisory_ids ?? [], report: td };
}

/// §9.1 check 1: the TDX quote verifies to the Intel vendor root, and the
/// verified quote's report_data equals the report's `report_data` zero-padded
/// to 64 bytes (§3.2). A pass here is what makes the RTMR3 that
/// {@link verifyComposeMeasurement} replays against authentic.
export async function verifyQuote(report, options = {}) {
  // §4.2: tee_type selects the evidence format; this verifier implements tdx.
  if (report.attestation?.tee_type !== "tdx") {
    const type = JSON.stringify(report.attestation?.tee_type);
    return { ok: false, detail: `tee_type ${type} needs a verifier this library does not implement (§4.2)` };
  }
  const quote = report.attestation.evidence?.quote;
  if (typeof quote !== "string") return { ok: false, detail: "report evidence carries no quote" };
  const reportDataHex = report.attestation.report_data;
  if (!/^[0-9a-f]{64}$/.test(reportDataHex)) {
    return { ok: false, detail: "report_data is not 32 bytes of lowercase hex" };
  }

  const verified = await verifyRawQuote(quote, options);
  if (!verified.ok) return verified;

  const slot = new Uint8Array(64);
  slot.set(fromHex(reportDataHex));
  const rd = verified.report.reportData;
  if (!rd || rd.length !== 64 || !slot.every((b, i) => b === rd[i])) {
    return { ok: false, status: verified.status, detail: "quote report_data does not bind the report" };
  }
  return verified;
}
