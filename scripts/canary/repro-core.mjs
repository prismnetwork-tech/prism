import { createHash } from "node:crypto";

import {
  decodeEventLog,
  getAddress,
  keccak256,
  recoverAddress,
  stringToBytes,
} from "viem";

export const MCP_PROTOCOL_VERSION = "2025-06-18";
export const MCP_SERVER_VERSION = "0.2.0";
export const CHAIN_ID = 4663;
export const CHAIN_NAME = "Robinhood Chain";
export const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
export const CURRENT_ESCROW = "0xfd4228eeefc49e4b76a0cd40af9fdd546220b2fd";
export const CAP_MICROS = 500_000n;
export const CONFIRMATIONS = 12;
// Asserted by the runner as well as the container command, so an exit-zero
// report that never printed a result cannot pass as a successful run.
export const SUCCESS_MARKER = "Test PASSED";
// Chain 4663 quotes about 0.21 gwei and funding costs under 400k gas, so this
// leaves wide headroom and still stops a fee spike or a broken estimate.
export const MAX_TRANSACTION_FEE_WEI = 2_000_000_000_000_000n;
export const REPRO_SPEC = Object.freeze({
  image: "registry.prismnetwork.tech/prism-cuda-vectoradd:vast-base-20260826@sha256:2e6d1873c8abd20d50dd311ac76324ef432c0a0396bd71b201b34c633e005930",
  command: "output=$(/usr/local/bin/prism-vectoradd 2>&1) || { code=$?; printf '%s\\n' \"$output\"; exit \"$code\"; }; printf '%s\\n' \"$output\"; case \"$output\" in *\"Test PASSED\"*) ;; *) exit 1 ;; esac",
  duration_seconds: 1_800,
  min_vram_mib: 45_056,
  expected_exit_code: 0,
});
export const MCP_TOOLS = Object.freeze([
  "prism_gpu_capacity",
  "prism_prepare_gpu_repro",
  "prism_gpu_repro_status",
  "prism_gpu_repro_evidence",
  "prism_verify_gpu_repro",
  "prism_gpu_receipts",
]);

const intentKeys = [
  "version",
  "executor",
  "image",
  "command",
  "duration_seconds",
  "min_vram_mib",
  "expected_exit_code",
  "maximum_escrow",
  "token_hash",
  "spec_hash",
  "issued_at",
  "expires_at",
];
const escrowAbi = [
  {
    type: "event",
    name: "LeaseFunded",
    inputs: [
      { indexed: true, name: "leaseId", type: "uint256" },
      { indexed: true, name: "nodeId", type: "bytes32" },
      { indexed: true, name: "renter", type: "address" },
      { indexed: false, name: "deposit", type: "uint256" },
      { indexed: false, name: "duration", type: "uint32" },
      { indexed: false, name: "clientReference", type: "bytes32" },
    ],
  },
  {
    type: "event",
    name: "LeaseFinalized",
    inputs: [
      { indexed: true, name: "leaseId", type: "uint256" },
      { indexed: false, name: "charged", type: "uint256" },
      { indexed: false, name: "fee", type: "uint256" },
      { indexed: false, name: "providerPaid", type: "uint256" },
      { indexed: false, name: "refunded", type: "uint256" },
      { indexed: false, name: "receiptHash", type: "bytes32" },
    ],
  },
];

export class ReproRunError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ReproRunError";
    this.code = code;
  }
}

export function assertMcpSurface(initialized, listed) {
  requireRecord(initialized, "MCP initialize response");
  requireRecord(initialized.serverInfo, "MCP server info");
  equal(initialized.serverInfo.name, "prism-network", "unexpected MCP server");
  equal(initialized.serverInfo.version, MCP_SERVER_VERSION, "unexpected MCP server version");
  requireRecord(listed, "MCP tools response");
  if (!Array.isArray(listed.tools)) fail("invalid_mcp", "MCP tools response is invalid");
  const names = listed.tools.map((tool) => tool?.name);
  if (JSON.stringify(names) !== JSON.stringify(MCP_TOOLS)) {
    fail("invalid_mcp", "MCP did not advertise the exact six audited tools");
  }
  if (listed.tools.some((tool) => (
    tool?.annotations?.readOnlyHint !== true || tool?.annotations?.destructiveHint !== false
  ))) {
    fail("invalid_mcp", "MCP advertised a tool outside the read-only boundary");
  }
}

export function decodeToolResult(result, toolName) {
  requireRecord(result, `${toolName} result`);
  if (result.isError === true) fail("mcp_tool_failed", `${toolName} returned an error`);
  if (!Array.isArray(result.content) || result.content.length !== 1) {
    fail("invalid_mcp", `${toolName} returned an invalid content envelope`);
  }
  const block = result.content[0];
  if (block?.type !== "text" || typeof block.text !== "string" || Buffer.byteLength(block.text) > 512 * 1_024) {
    fail("invalid_mcp", `${toolName} returned invalid text content`);
  }
  try {
    return JSON.parse(block.text);
  } catch {
    fail("invalid_mcp", `${toolName} returned invalid JSON`);
  }
}

export function validatePreparedRepro(prepared, origin) {
  requireRecord(prepared, "prepared repro");
  equal(prepared.intent_version, "prism.gpu-repro.intent.v2", "unexpected repro intent version");
  equal(prepared.estimated_executor, "managed", "prepared repro did not select the managed executor");
  equal(prepared.duration_minutes, 30, "prepared repro duration changed");
  equal(prepared.expected_exit_code, REPRO_SPEC.expected_exit_code, "prepared expected exit code changed");
  equal(prepared.lease_created, false, "MCP unexpectedly created a lease");
  if (!isToken(prepared.repro_token)) fail("invalid_intent", "MCP returned an invalid repro token");
  if (!isDigest(prepared.spec_hash)) fail("invalid_intent", "MCP returned an invalid spec hash");

  const maximum = baseUnits(prepared.maximum_escrow, "prepared maximum escrow");
  if (maximum > CAP_MICROS) fail("cost_exceeds_cap", "prepared repro exceeds the 0.5 USDG cap");
  if (prepared.maximum_escrow_usdg !== formatUsdg(maximum)) {
    fail("invalid_intent", "prepared USDG display does not match its base-unit ceiling");
  }
  requireRecord(prepared.settlement, "prepared settlement");
  equal(prepared.settlement.network, CHAIN_NAME, "prepared settlement network changed");
  equal(prepared.settlement.chain_id, CHAIN_ID, "prepared settlement chain changed");
  equal(prepared.settlement.asset, "USDG", "prepared settlement asset changed");
  if (!sameAddress(prepared.settlement.asset_contract, USDG) || prepared.settlement.asset_decimals !== 6) {
    fail("invalid_intent", "prepared settlement token changed");
  }

  let approval;
  try {
    approval = new URL(prepared.approval_url);
  } catch {
    fail("invalid_intent", "MCP returned an invalid approval URL");
  }
  if (approval.origin !== origin || approval.pathname !== "/compute" || approval.search || approval.username || approval.password) {
    fail("invalid_intent", "approval URL is outside the expected origin or path");
  }
  const params = new URLSearchParams(approval.hash.slice(1));
  const envelope = params.get("repro");
  if (params.size !== 1 || !envelope || approval.href.includes(prepared.repro_token)) {
    fail("invalid_intent", "approval URL did not contain one private signed envelope");
  }
  return { envelope, maximum };
}

export function validateIntent(prepared, envelope, intent, now = Date.now()) {
  requireExactKeys(intent, intentKeys, "repro intent");
  equal(intent.version, "prism.gpu-repro.intent.v2", "unexpected repro intent version");
  equal(intent.executor, "managed", "repro intent is not managed");
  assertExactSpec(intent);
  if (!isDigest(intent.token_hash) || !isDigest(intent.spec_hash)) {
    fail("invalid_intent", "repro intent has an invalid commitment");
  }
  equal(intent.token_hash, hashReproToken(prepared.repro_token), "repro token commitment mismatch");
  equal(intent.spec_hash, hashReproSpec(REPRO_SPEC), "repro spec commitment mismatch");
  equal(intent.spec_hash, prepared.spec_hash, "MCP and intent spec commitments differ");
  const maximum = baseUnits(intent.maximum_escrow, "intent maximum escrow");
  equal(maximum, baseUnits(prepared.maximum_escrow, "prepared maximum escrow"), "MCP and intent ceilings differ");
  if (maximum > CAP_MICROS) fail("cost_exceeds_cap", "intent exceeds the 0.5 USDG cap");
  if (!Number.isSafeInteger(intent.issued_at) || !Number.isSafeInteger(intent.expires_at)) {
    fail("invalid_intent", "intent timestamps are invalid");
  }
  if (intent.expires_at - intent.issued_at !== 1_800 || intent.issued_at > Math.floor(now / 1_000) + 60) {
    fail("invalid_intent", "intent validity window is invalid");
  }
  if (intent.expires_at <= Math.floor(now / 1_000) + 60) {
    fail("intent_expired", "intent expires too soon to review safely");
  }
  const decoded = decodeEnvelopePayload(envelope);
  if (JSON.stringify(decoded) !== JSON.stringify(intent)) {
    fail("invalid_intent", "verified intent does not match its signed envelope payload");
  }
  return { maximum, tokenHash: intent.token_hash, specHash: intent.spec_hash };
}

export function validateQuote(quote, intent, now = Date.now()) {
  requireRecord(quote, "lease quote");
  if (!isUuid(quote.quote_id)) fail("invalid_quote", "quote id is invalid");
  if (!isBytes32(quote.node_id)) fail("invalid_quote", "quote node id is invalid");
  assertExactSpec(quote);
  if (quote.command !== REPRO_SPEC.command) fail("invalid_quote", "quote command changed");
  requireRecord(quote.repro, "quote repro capability");
  equal(quote.repro.token_hash, intent.token_hash, "quote token commitment changed");
  equal(quote.repro.spec_hash, intent.spec_hash, "quote spec commitment changed");
  equal(quote.repro.expected_exit_code, REPRO_SPEC.expected_exit_code, "quote expected exit code changed");
  equal(quote.repro.executor, "managed", "quote executor changed");
  const rate = baseUnits(quote.rate_per_second, "quote rate");
  const maximum = baseUnits(quote.maximum_escrow, "quote maximum escrow");
  if (maximum !== rate * BigInt(REPRO_SPEC.duration_seconds)) {
    fail("invalid_quote", "quote escrow does not equal rate times duration");
  }
  if (maximum > baseUnits(intent.maximum_escrow, "intent maximum escrow") || maximum > CAP_MICROS) {
    fail("cost_exceeds_cap", "live quote exceeds the signed or local ceiling");
  }
  const expiresAt = Date.parse(quote.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= now + 60_000) {
    fail("quote_expired", "quote expires too soon to fund safely");
  }
  return { maximum, rate, expiresAt };
}

export function validateReproStatus(status, intent, quote, expectedStatuses = null) {
  requireRecord(status, "repro status");
  equal(status.version, "prism.gpu-repro.status.v1", "unexpected repro status version");
  equal(status.executor, "managed", "repro status executor changed");
  equal(status.spec_hash, intent.spec_hash, "repro status spec commitment changed");
  equal(status.quote_id, quote.quote_id, "repro status quote changed");
  equal(baseUnits(status.maximum_escrow, "status maximum escrow"), baseUnits(quote.maximum_escrow, "quote maximum escrow"), "repro status ceiling changed");
  requireRecord(status.spec, "repro status spec");
  assertExactSpec(status.spec);
  if (expectedStatuses && !expectedStatuses.includes(status.status)) {
    fail("unexpected_status", `repro entered unexpected status ${String(status.status)}`);
  }
  return status;
}

export function validateQuotedStatus(status, intent, quote) {
  validateReproStatus(status, intent, quote, ["quoted"]);
  if (status.lease_id !== undefined || status.lease_state !== undefined || status.result !== undefined) {
    fail("invalid_status", "quoted repro already contains lease or result data");
  }
}

export function validateLeaseRecord(record, { quote, intent, wallet, fundingHash, chainLeaseId }) {
  requireRecord(record, "lease confirmation");
  if (!Number.isSafeInteger(record.lease_id) || record.lease_id <= 0) {
    fail("invalid_confirmation", "confirmation returned an invalid internal lease id");
  }
  equal(BigInt(record.chain_lease_id), BigInt(chainLeaseId), "confirmation chain lease id changed");
  if (!sameAddress(record.escrow_address, CURRENT_ESCROW)) fail("invalid_confirmation", "confirmation escrow changed");
  equal(record.quote_id, quote.quote_id, "confirmation quote changed");
  equal(record.node_id, quote.node_id, "confirmation node changed");
  if (!sameAddress(record.renter_wallet, wallet)) fail("invalid_confirmation", "confirmation renter changed");
  equal(record.image, REPRO_SPEC.image, "confirmation image changed");
  equal(record.duration_seconds, REPRO_SPEC.duration_seconds, "confirmation duration changed");
  equal(record.rate_per_second, quote.rate_per_second, "confirmation rate changed");
  equal(baseUnits(record.maximum_escrow, "confirmation maximum escrow"), baseUnits(quote.maximum_escrow, "quote maximum escrow"), "confirmation escrow amount changed");
  equal(record.funding_transaction_hash.toLowerCase(), fundingHash.toLowerCase(), "confirmation funding hash changed");
  equal(record.command, REPRO_SPEC.command, "confirmation command changed");
  requireRecord(record.repro, "confirmed repro capability");
  equal(record.repro.token_hash, intent.token_hash, "confirmation token commitment changed");
  equal(record.repro.spec_hash, intent.spec_hash, "confirmation spec commitment changed");
  equal(record.repro.expected_exit_code, intent.expected_exit_code, "confirmation expected exit code changed");
  equal(record.repro.executor, "managed", "confirmation executor changed");
  return record;
}

export function decodeLeaseFunded(receipt, { quote, wallet, fundingHash }) {
  requireSuccessfulReceipt(receipt, fundingHash, "funding");
  const events = decodeEvents(receipt, "LeaseFunded");
  if (events.length !== 1) fail("funding_mismatch", "funding transaction did not emit exactly one LeaseFunded event");
  const event = events[0];
  const clientReference = keccak256(stringToBytes(quote.quote_id));
  if (event.args.nodeId.toLowerCase() !== quote.node_id.toLowerCase()
    || !sameAddress(event.args.renter, wallet)
    || event.args.deposit !== baseUnits(quote.maximum_escrow, "quote maximum escrow")
    || event.args.duration !== REPRO_SPEC.duration_seconds
    || event.args.clientReference.toLowerCase() !== clientReference.toLowerCase()
    || event.args.leaseId <= 0n) {
    fail("funding_mismatch", "LeaseFunded event does not match the reviewed quote");
  }
  return { leaseId: event.args.leaseId, clientReference };
}

export async function validateManagedEvidence(payload, { intent, lease, gateway }) {
  requireRecord(payload, "managed evidence response");
  equal(payload.status, "settled", "managed evidence is not settled");
  equal(payload.spec_hash, intent.spec_hash, "managed evidence spec changed");
  equal(payload.lease_id, lease.lease_id, "managed evidence lease changed");
  requireRecord(payload.evidence, "managed evidence");
  requireRecord(payload.evidence.command, "managed command evidence");
  requireRecord(payload.evidence.report, "managed report envelope");
  equal(payload.evidence.report.executor, "managed", "evidence executor changed");
  const report = payload.evidence.report.report;
  requireRecord(report, "managed report");
  if (!sameAddress(report.signer, gateway)) fail("invalid_evidence", "managed report signer is not the escrow gateway");
  equal(report.command_id, payload.evidence.command.command_id, "managed report command changed");
  equal(report.lease_id, lease.lease_id, "managed report lease changed");
  equal(report.provider, "vast", "managed report provider changed");
  if (!Number.isSafeInteger(report.provider_instance_id) || report.provider_instance_id <= 0) {
    fail("invalid_evidence", "managed report has an invalid provider instance id");
  }
  if (!Number.isSafeInteger(report.gpu_vram_mib) || report.gpu_vram_mib < REPRO_SPEC.min_vram_mib) {
    fail("invalid_evidence", "managed report GPU memory is below the approved floor");
  }
  if (!isDigest(report.transport_host_key_sha256)) {
    fail("invalid_evidence", "managed report host-key commitment is invalid");
  }
  if (report.outcome !== "completed" || report.error !== null) {
    fail("repro_failed", "managed report did not complete successfully");
  }
  assertExpectedResult(report.result);
  if (typeof report.signature !== "string" || !/^0x[0-9a-f]{130}$/.test(report.signature)) {
    fail("invalid_evidence", "managed report signature is invalid");
  }
  const digest = managedReportDigest(report);
  let recovered;
  try {
    recovered = await recoverAddress({ hash: digest, signature: report.signature });
  } catch {
    fail("invalid_evidence", "managed report signature could not be recovered");
  }
  if (!sameAddress(recovered, report.signer) || !sameAddress(recovered, gateway)) {
    fail("invalid_evidence", "managed report signature does not recover the escrow gateway");
  }
  return report;
}

export function validateVerification(payload, { intent, lease }) {
  requireRecord(payload, "verification response");
  equal(payload.status, "settled", "verification is not settled");
  equal(payload.spec_hash, intent.spec_hash, "verification spec changed");
  equal(payload.lease_id, lease.lease_id, "verification lease changed");
  requireRecord(payload.checks, "verification checks");
  for (const check of [
    "token_bound",
    "spec_hash_valid",
    "command_bound",
    "report_signature_valid",
    "report_bound",
    "receipt_hash_valid",
    "receipt_bound",
    "expected_exit_code",
  ]) {
    if (payload.checks[check] !== true) fail("verification_failed", `verification check ${check} did not pass`);
  }
  if (payload.checks.executor_identity_valid !== null) {
    fail("verification_failed", "managed executor identity must be resolved independently onchain");
  }
}

export function validatePublicReceipt(receipt, { intent, quote, lease, chainLeaseId }) {
  requireRecord(receipt, "public receipt");
  if (receipt.outcome !== "finalized") fail("invalid_receipt", "public receipt is not finalized");
  const chainId = BigInt(chainLeaseId).toString();
  equal(receipt.lease_id, chainId, "public receipt chain lease id changed");
  equal(receipt.chain_lease_id, chainId, "public receipt chain identity changed");
  if (!sameAddress(receipt.escrow_address, CURRENT_ESCROW)) fail("invalid_receipt", "public receipt escrow changed");
  requireRecord(receipt.repro, "public repro receipt");
  equal(receipt.repro.executor, "managed", "public receipt executor changed");
  equal(receipt.repro.token_hash, intent.token_hash, "public receipt token commitment changed");
  equal(receipt.repro.spec_hash, intent.spec_hash, "public receipt spec commitment changed");
  equal(receipt.repro.image_digest, REPRO_SPEC.image.split("@").at(-1), "public receipt image digest changed");
  equal(receipt.repro.exit_code, REPRO_SPEC.expected_exit_code, "public receipt exit code changed");
  equal(receipt.repro.expected_exit_code, REPRO_SPEC.expected_exit_code, "public receipt expected exit code changed");
  equal(receipt.repro.succeeded, true, "public receipt marks the repro unsuccessful");
  equal(receipt.repro.truncated, false, "public receipt marks the result truncated");
  for (const field of ["command_hash", "result_hash", "stdout_hash", "stderr_hash", "report_hash"]) {
    if (!isDigest(receipt.repro[field])) fail("invalid_receipt", `public receipt ${field} is invalid`);
  }
  if (!isDigest(receipt.receipt_hash) || receipt.receipt_hash !== hashReceipt(receipt)) {
    fail("invalid_receipt", "public receipt hash does not match its canonical payload");
  }
  if (!isHash(receipt.transaction_hash)) fail("invalid_receipt", "public receipt transaction hash is invalid");
  const charged = baseUnits(receipt.charged_base_units, "receipt charged amount");
  const refunded = baseUnits(receipt.refunded_base_units, "receipt refunded amount");
  const providerPaid = baseUnits(receipt.provider_paid_base_units, "receipt provider payment");
  if (charged + refunded !== baseUnits(quote.maximum_escrow, "quote maximum escrow") || providerPaid > charged) {
    fail("invalid_receipt", "public receipt amounts do not reconcile to the funded deposit");
  }
  if (lease.chain_lease_id !== undefined && BigInt(lease.chain_lease_id) !== BigInt(chainLeaseId)) {
    fail("invalid_receipt", "confirmed and public chain lease ids differ");
  }
  return receipt;
}

export function validateFinalizationReceipt(chainReceipt, publicReceipt, chainLeaseId) {
  requireSuccessfulReceipt(chainReceipt, publicReceipt.transaction_hash, "finalization");
  const events = decodeEvents(chainReceipt, "LeaseFinalized");
  if (events.length !== 1) fail("invalid_receipt", "settlement transaction did not emit exactly one LeaseFinalized event");
  const event = events[0];
  if (event.args.leaseId !== BigInt(chainLeaseId)
    || event.args.charged !== BigInt(publicReceipt.charged_base_units)
    || event.args.providerPaid !== BigInt(publicReceipt.provider_paid_base_units)
    || event.args.refunded !== BigInt(publicReceipt.refunded_base_units)
    || event.args.receiptHash.toLowerCase() !== `0x${publicReceipt.receipt_hash}`
    || event.args.fee + event.args.providerPaid !== event.args.charged) {
    fail("invalid_receipt", "LeaseFinalized event does not match the public receipt");
  }
}

export function assertExpectedResult(result) {
  requireRecord(result, "repro result");
  if (result.exit_code !== REPRO_SPEC.expected_exit_code
    || typeof result.stdout !== "string"
    || typeof result.stderr !== "string"
    || result.truncated !== false) {
    fail("repro_failed", "GPU repro result did not match the expected untruncated exit-zero result");
  }
  if (!result.stdout.includes(SUCCESS_MARKER)) {
    fail("repro_failed", `GPU repro stdout does not contain the CUDA success marker ${SUCCESS_MARKER}`);
  }
}

// Spec hash alone would hand a repeated run the receipt of an earlier one, so
// the run's own token commitment and chain lease id decide the match.
export function selectRunReceipt(payload, { tokenHash, chainLeaseId }) {
  requireRecord(payload, "public receipt feed");
  if (!Array.isArray(payload.receipts)) fail("invalid_receipt", "public receipt feed is invalid");
  const wanted = BigInt(chainLeaseId).toString();
  const matches = payload.receipts.filter((receipt) => receipt
    && typeof receipt === "object"
    && !Array.isArray(receipt)
    && receipt.repro?.token_hash === tokenHash
    && String(receipt.chain_lease_id) === wanted);
  if (matches.length > 1) fail("ambiguous_receipt", "more than one public receipt claims this run");
  return matches[0] ?? null;
}

// Enforced against whichever fee fields the transaction type carries, so a
// legacy gas price cannot slip past an EIP-1559 check.
export function validateTransactionFee(request, capWei, label) {
  const gas = feeField(request.gas, `${label} gas limit`);
  const price = request.maxFeePerGas ?? request.gasPrice;
  if (price === undefined || price === null) {
    fail("gas_cap_exceeded", `${label} transaction declares no fee price`);
  }
  const cost = gas * feeField(price, `${label} fee price`);
  if (cost > capWei) {
    fail("gas_cap_exceeded", `${label} transaction may cost up to ${cost} wei, above the ${capWei} wei ceiling`);
  }
  return cost;
}

function feeField(value, label) {
  if (typeof value === "bigint") {
    if (value <= 0n) fail("gas_cap_exceeded", `${label} is not positive`);
    return value;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return BigInt(value);
  if (typeof value === "string" && /^(?:[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)) {
    const parsed = BigInt(value);
    if (parsed > 0n) return parsed;
  }
  fail("gas_cap_exceeded", `${label} is invalid`);
}

// Vast answers an instance the account no longer owns with 200 and a null
// body, not 404, so absence has to be read from the payload.
export function readVastInstance(status, text, instanceId) {
  if (status === 404) return null;
  if (status === 401 || status === 403) fail("vast_unauthorized", "Vast rejected the credential");
  if (status !== 200) fail("vast_unavailable", `Vast instance read returned HTTP ${status}`);
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    fail("vast_unavailable", "Vast instance read returned invalid JSON");
  }
  const instance = payload?.instances;
  if (!instance || typeof instance !== "object" || Array.isArray(instance)) return null;
  if (Number(instance.id) !== instanceId) return null;
  return typeof instance.actual_status === "string" ? instance.actual_status : "present";
}

export function hashReproSpec(spec) {
  const canonical = JSON.stringify({
    image: spec.image,
    command: spec.command,
    duration_seconds: spec.duration_seconds,
    min_vram_mib: spec.min_vram_mib,
    expected_exit_code: spec.expected_exit_code,
  });
  return createHash("sha256").update("prism-gpu-repro-spec-v1\0").update(canonical).digest("hex");
}

export function hashReproToken(token) {
  if (!isToken(token)) fail("invalid_token", "repro token is invalid");
  const decoded = Buffer.from(token, "base64url");
  if (decoded.toString("base64url") !== token || decoded.length !== 32) {
    fail("invalid_token", "repro token is not canonical base64url");
  }
  return createHash("sha256").update(decoded).digest("hex");
}

export function managedReportDigest(report) {
  const payload = {
    report_id: report.report_id,
    signer: report.signer,
    command_id: report.command_id,
    lease_id: report.lease_id,
    provider: report.provider,
    provider_instance_id: report.provider_instance_id,
    gpu_model: report.gpu_model,
    gpu_vram_mib: report.gpu_vram_mib,
    transport_host_key_sha256: report.transport_host_key_sha256,
    started_at: report.started_at,
    finished_at: report.finished_at,
    outcome: report.outcome,
    error: report.error,
    ...(report.result === undefined ? {} : { result: report.result }),
  };
  const bytes = Buffer.concat([
    Buffer.from("prism-managed-command-report-v1\0"),
    Buffer.from(JSON.stringify(payload)),
  ]);
  return keccak256(bytes);
}

export function hashReceipt(receipt) {
  const payload = {
    receipt_id: receipt.receipt_id,
    lease_id: receipt.lease_id,
    node_id_hash: receipt.node_id_hash,
    gpu_model: receipt.gpu_model,
    runtime_seconds: receipt.runtime_seconds,
    charged_base_units: receipt.charged_base_units,
    refunded_base_units: receipt.refunded_base_units,
    provider_paid_base_units: receipt.provider_paid_base_units,
    failure_class: receipt.failure_class ?? null,
  };
  payload.outcome = receipt.outcome;
  if (receipt.trust_class !== undefined) payload.trust_class = receipt.trust_class;
  if (receipt.attestation !== undefined) payload.attestation = receipt.attestation;
  if (receipt.credited_seconds !== undefined) payload.credited_seconds = receipt.credited_seconds;
  if (receipt.repro !== undefined) {
    payload.repro = {
      executor: receipt.repro.executor,
      token_hash: receipt.repro.token_hash,
      spec_hash: receipt.repro.spec_hash,
      image_digest: receipt.repro.image_digest,
      command_hash: receipt.repro.command_hash,
      result_hash: receipt.repro.result_hash,
      stdout_hash: receipt.repro.stdout_hash,
      stderr_hash: receipt.repro.stderr_hash,
      report_hash: receipt.repro.report_hash,
      exit_code: receipt.repro.exit_code,
      expected_exit_code: receipt.repro.expected_exit_code,
      succeeded: receipt.repro.succeeded,
      truncated: receipt.repro.truncated,
    };
  }
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

export function formatUsdg(value) {
  const micros = BigInt(value);
  const whole = micros / 1_000_000n;
  const fraction = (micros % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

export function sameAddress(left, right) {
  try {
    return getAddress(left).toLowerCase() === getAddress(right).toLowerCase();
  } catch {
    return false;
  }
}

export function isHash(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function decodeEnvelopePayload(envelope) {
  if (typeof envelope !== "string" || Buffer.byteLength(envelope) > 8 * 1_024) {
    fail("invalid_intent", "signed intent envelope is invalid");
  }
  const parts = envelope.split(".");
  if (parts.length !== 2 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) {
    fail("invalid_intent", "signed intent envelope is invalid");
  }
  let decoded;
  try {
    const bytes = Buffer.from(parts[0], "base64url");
    if (bytes.toString("base64url") !== parts[0]) throw new Error("noncanonical");
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("invalid_intent", "signed intent payload is invalid");
  }
  return decoded;
}

function decodeEvents(receipt, eventName) {
  if (!Array.isArray(receipt.logs)) fail("chain_receipt_invalid", "transaction receipt has no logs");
  const events = [];
  for (const log of receipt.logs) {
    if (!sameAddress(log.address, CURRENT_ESCROW)) continue;
    try {
      const decoded = decodeEventLog({ abi: escrowAbi, data: log.data, topics: log.topics, strict: true });
      if (decoded.eventName === eventName) events.push(decoded);
    } catch {
      // Other escrow events in the same transaction are outside this check.
    }
  }
  return events;
}

function requireSuccessfulReceipt(receipt, hash, label) {
  requireRecord(receipt, `${label} transaction receipt`);
  if (receipt.status !== "success" || receipt.transactionHash?.toLowerCase() !== hash.toLowerCase()) {
    fail(`${label}_reverted`, `${label} transaction did not succeed under the persisted hash`);
  }
}

function assertExactSpec(value) {
  equal(value.image, REPRO_SPEC.image, "repro image changed");
  equal(value.command ?? REPRO_SPEC.command, REPRO_SPEC.command, "repro command changed");
  equal(value.duration_seconds, REPRO_SPEC.duration_seconds, "repro duration changed");
  equal(value.min_vram_mib, REPRO_SPEC.min_vram_mib, "repro VRAM floor changed");
  equal(value.expected_exit_code ?? REPRO_SPEC.expected_exit_code, REPRO_SPEC.expected_exit_code, "repro expected exit code changed");
}

function requireExactKeys(value, keys, label) {
  requireRecord(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail("invalid_intent", `${label} fields changed`);
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("invalid_response", `${label} is invalid`);
  }
}

function baseUnits(value, label) {
  if ((typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint")
    || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
    fail("invalid_amount", `${label} is invalid`);
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) fail("invalid_amount", `${label} is unsafe`);
  return BigInt(value);
}

function isUuid(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isBytes32(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isDigest(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function equal(actual, expected, message) {
  if (actual !== expected) fail("binding_mismatch", message);
}

function fail(code, message) {
  throw new ReproRunError(code, message);
}
