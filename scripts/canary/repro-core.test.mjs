import assert from "node:assert/strict";
import test from "node:test";

import {
  CHAIN_ID,
  CHAIN_NAME,
  MAX_TRANSACTION_FEE_WEI,
  MCP_TOOLS,
  REPRO_SPEC,
  SUCCESS_MARKER,
  USDG,
  assertExpectedResult,
  assertMcpSurface,
  formatUsdg,
  hashReproSpec,
  hashReproToken,
  readVastInstance,
  selectRunReceipt,
  validateIntent,
  validatePreparedRepro,
  validateQuote,
  validateQuotedStatus,
  validateTransactionFee,
} from "./repro-core.mjs";

const now = Date.parse("2030-01-01T00:00:00Z");
const token = Buffer.alloc(32, 7).toString("base64url");
const intent = {
  version: "prism.gpu-repro.intent.v2",
  executor: "managed",
  ...REPRO_SPEC,
  maximum_escrow: "399600",
  token_hash: hashReproToken(token),
  spec_hash: hashReproSpec(REPRO_SPEC),
  issued_at: Math.floor(now / 1_000),
  expires_at: Math.floor(now / 1_000) + 1_800,
};
const envelope = `${Buffer.from(JSON.stringify(intent)).toString("base64url")}.signature`;
const prepared = {
  intent_version: intent.version,
  approval_url: `https://prism.test/compute#repro=${encodeURIComponent(envelope)}`,
  repro_token: token,
  spec_hash: intent.spec_hash,
  estimated_executor: "managed",
  duration_minutes: 30,
  expected_exit_code: 0,
  maximum_escrow: intent.maximum_escrow,
  maximum_escrow_usdg: "0.3996",
  lease_created: false,
  settlement: {
    network: CHAIN_NAME,
    chain_id: CHAIN_ID,
    asset: "USDG",
    asset_contract: USDG,
    asset_decimals: 6,
  },
};
const quote = {
  quote_id: "01993aa4-5772-7f30-bcb7-7d38f59310e8",
  node_id: `0x${"ab".repeat(32)}`,
  image: REPRO_SPEC.image,
  command: REPRO_SPEC.command,
  duration_seconds: REPRO_SPEC.duration_seconds,
  min_vram_mib: REPRO_SPEC.min_vram_mib,
  rate_per_second: 222,
  maximum_escrow: 399_600,
  trust_class: "open",
  repro: {
    token_hash: intent.token_hash,
    spec_hash: intent.spec_hash,
    expected_exit_code: 0,
    executor: "managed",
  },
  expires_at: "2030-01-01T00:05:00Z",
};

test("pins the small NVIDIA vector-add image and its canonical success marker", () => {
  assert.equal(
    REPRO_SPEC.image,
    "registry.prismnetwork.tech/prism-cuda-vectoradd:vast-base-20260826@sha256:2e6d1873c8abd20d50dd311ac76324ef432c0a0396bd71b201b34c633e005930",
  );
  assert.match(REPRO_SPEC.command, /^output=\$\(\/usr\/local\/bin\/prism-vectoradd 2>&1\)/);
  assert.match(REPRO_SPEC.command, /printf '%s\\n' \"\$output\"/);
  assert.match(REPRO_SPEC.command, /\*\"Test PASSED\"\*/);
  assert.doesNotMatch(REPRO_SPEC.command, /python|torch|nvidia-smi/);
});

test("accepts only the exact audited read-only MCP surface", () => {
  assert.doesNotThrow(() => assertMcpSurface(
    { serverInfo: { name: "prism-network", version: "0.2.0" } },
    {
      tools: MCP_TOOLS.map((name) => ({
        name,
        annotations: { readOnlyHint: true, destructiveHint: false },
      })),
    },
  ));
  assert.throws(() => assertMcpSurface(
    { serverInfo: { name: "prism-network", version: "0.2.0" } },
    { tools: [] },
  ), /six audited tools/);
});

test("binds the prepared capability, signed intent, and live quote", () => {
  assert.equal(validatePreparedRepro(prepared, "https://prism.test").envelope, envelope);
  assert.deepEqual(validateIntent(prepared, envelope, intent, now), {
    maximum: 399_600n,
    tokenHash: intent.token_hash,
    specHash: intent.spec_hash,
  });
  assert.deepEqual(validateQuote(quote, intent, now), {
    maximum: 399_600n,
    rate: 222n,
    expiresAt: Date.parse(quote.expires_at),
  });
  validateQuotedStatus({
    version: "prism.gpu-repro.status.v1",
    status: "quoted",
    executor: "managed",
    spec: REPRO_SPEC,
    spec_hash: intent.spec_hash,
    quote_id: quote.quote_id,
    maximum_escrow: quote.maximum_escrow,
    checks: { token_bound: true, spec_hash_valid: true },
  }, intent, quote);
});

test("rejects drift in workload, cost, executor, and token binding", () => {
  assert.throws(() => validateQuote({ ...quote, command: "nvidia-smi" }, intent, now), /command changed/);
  assert.throws(() => validateQuote({ ...quote, maximum_escrow: 500_001 }, intent, now), /rate times duration/);
  assert.throws(() => validateQuote({ ...quote, repro: { ...quote.repro, executor: "node" } }, intent, now), /executor changed/);
  assert.throws(() => validateIntent(
    { ...prepared, repro_token: Buffer.alloc(32, 8).toString("base64url") },
    envelope,
    intent,
    now,
  ), /token commitment mismatch/);
});

test("formats USDG base units without floating point", () => {
  assert.equal(formatUsdg(399_600n), "0.3996");
  assert.equal(formatUsdg(500_000n), "0.5");
});

test("requires the CUDA success marker in an exit-zero result", () => {
  const passing = { exit_code: 0, stdout: `[Vector addition of 50000 elements]\n${SUCCESS_MARKER}\n`, stderr: "", truncated: false };
  assert.doesNotThrow(() => assertExpectedResult(passing));
  assert.throws(() => assertExpectedResult({ ...passing, stdout: "" }), /success marker/);
  assert.throws(() => assertExpectedResult({ ...passing, exit_code: 1 }), /exit-zero/);
  assert.throws(() => assertExpectedResult({ ...passing, truncated: true }), /untruncated/);
});

test("matches only this run's public receipt", () => {
  const mine = { chain_lease_id: "1207", repro: { token_hash: intent.token_hash } };
  const earlierRun = { chain_lease_id: "1188", repro: { token_hash: `${"c".repeat(64)}` } };
  const sameSpecOtherLease = { chain_lease_id: "1206", repro: { token_hash: intent.token_hash } };
  const feed = { receipts: [earlierRun, sameSpecOtherLease, mine] };
  assert.equal(selectRunReceipt(feed, { tokenHash: intent.token_hash, chainLeaseId: 1207n }), mine);
  assert.equal(selectRunReceipt({ receipts: [earlierRun] }, { tokenHash: intent.token_hash, chainLeaseId: 1207n }), null);
  assert.throws(
    () => selectRunReceipt({ receipts: [mine, { ...mine }] }, { tokenHash: intent.token_hash, chainLeaseId: 1207n }),
    /more than one public receipt/,
  );
});

test("refuses to sign above the transaction fee ceiling", () => {
  // Chain 4663 quoted 0.206 gwei while this runner was written; a lease funding
  // call at 400k gas is about 8e13 wei.
  const funding = { gas: 400_000n, maxFeePerGas: 206_143_168n };
  assert.equal(validateTransactionFee(funding, MAX_TRANSACTION_FEE_WEI, "funding"), 82_457_267_200_000n);
  assert.doesNotThrow(() => validateTransactionFee({ gas: 60_000n, gasPrice: 206_143_168n }, MAX_TRANSACTION_FEE_WEI, "approve"));
  assert.throws(() => validateTransactionFee({ gas: 400_000n, maxFeePerGas: 50_000_000_000n }, MAX_TRANSACTION_FEE_WEI, "funding"), /above the/);
  assert.throws(() => validateTransactionFee({ gas: 400_000n }, MAX_TRANSACTION_FEE_WEI, "funding"), /no fee price/);
  assert.throws(() => validateTransactionFee({ gas: 0n, maxFeePerGas: 1n }, MAX_TRANSACTION_FEE_WEI, "funding"), /not positive/);
});

test("reads Vast absence from the payload, not the status code", () => {
  // Vast answers 200 with a null body for an instance the account no longer
  // owns; a 404 only shows up for a malformed id.
  assert.equal(readVastInstance(200, '{"instances": null}', 46011038), null);
  assert.equal(readVastInstance(404, "", 46011038), null);
  assert.equal(readVastInstance(200, '{"instances":{"id":46011038,"actual_status":"exited"}}', 46011038), "exited");
  assert.equal(readVastInstance(200, '{"instances":{"id":46011038}}', 46011038), "present");
  assert.equal(readVastInstance(200, '{"instances":{"id":9,"actual_status":"running"}}', 46011038), null);
  assert.throws(() => readVastInstance(401, "", 46011038), /rejected the credential/);
  assert.throws(() => readVastInstance(500, "", 46011038), /HTTP 500/);
  assert.throws(() => readVastInstance(200, "not json", 46011038), /invalid JSON/);
});
