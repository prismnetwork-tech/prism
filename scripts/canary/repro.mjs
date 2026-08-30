import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, isAbsolute, join } from "node:path";

import {
  createPublicClient,
  encodeFunctionData,
  http,
  isAddress,
  keccak256,
  parseAbi,
  parseTransaction,
  recoverTransactionAddress,
  stringToBytes,
  zeroAddress,
} from "viem";
import { PrismAgent, robinhoodChain } from "@prismnetwork/agent-sdk";

import {
  CAP_MICROS,
  CHAIN_ID,
  CHAIN_NAME,
  CONFIRMATIONS,
  CURRENT_ESCROW,
  MAX_TRANSACTION_FEE_WEI,
  MCP_PROTOCOL_VERSION,
  REPRO_SPEC,
  ReproRunError,
  USDG,
  assertExpectedResult,
  assertMcpSurface,
  decodeLeaseFunded,
  decodeToolResult,
  formatUsdg,
  isHash,
  readVastInstance,
  sameAddress,
  selectRunReceipt,
  validateFinalizationReceipt,
  validateIntent,
  validateLeaseRecord,
  validateManagedEvidence,
  validatePreparedRepro,
  validatePublicReceipt,
  validateQuote,
  validateQuotedStatus,
  validateReproStatus,
  validateTransactionFee,
  validateVerification,
} from "./repro-core.mjs";

const stateVersion = "prism.paid-repro-run.v1";
const explorer = "https://robinhoodchain.blockscout.com";
const maxResponseBytes = 1024 * 1024;
const defaultApiBase = "https://prismnetwork.tech";
const retryableConfirmCodes = new Set(["funding_not_final", "chain_unavailable"]);
const terminalFailures = new Set(["failed", "refunded", "disputed"]);
const erc20Abi = parseAbi([
  "function approve(address spender, uint256 value) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address owner) view returns (uint256)",
]);
const escrowAbi = parseAbi([
  "function createLease(bytes32 nodeId, uint32 duration, bytes32 clientReference) returns (uint256)",
  "function paused() view returns (bool)",
  "function usd() view returns (address)",
  "function gateway() view returns (address)",
]);

const mode = process.argv[2];
const modes = new Set(["--review", "--execute", "--inspect", "--verify-cleanup"]);
if (!modes.has(mode) || process.argv.length !== 3) {
  abort("usage", "use exactly one of --review, --execute, --inspect, or --verify-cleanup");
}

const statePath = stateFile();
const apiBase = apiUrl(process.env.PRISM_API_BASE ?? defaultApiBase);
const readOnlyMode = mode === "--inspect" || mode === "--verify-cleanup";
const rpcUrl = readOnlyMode ? null : requiredUrl("PRISM_RPC_URL");
const broadcastUrl = readOnlyMode || !process.env.PRISM_BROADCAST_URL
  ? null
  : requiredUrl("PRISM_BROADCAST_URL");

async function review() {
  assertNewStatePath(statePath);
  const agent = createAgent();
  const mcp = new McpClient(new URL("/api/mcp", apiBase));
  const initialized = await mcp.call("initialize", {
    protocolVersion: MCP_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "prism-paid-repro", version: "1.0.0" },
  });
  const listed = await mcp.call("tools/list", {});
  assertMcpSurface(initialized, listed);

  const prepared = await mcp.tool("prism_prepare_gpu_repro", {
    image: REPRO_SPEC.image,
    command: REPRO_SPEC.command,
    duration_minutes: 30,
    min_vram_gib: 44,
    expected_exit_code: REPRO_SPEC.expected_exit_code,
  });
  const { envelope } = validatePreparedRepro(prepared, apiBase.origin);
  const intent = await jsonRequest(new URL("/api/repro/intent", apiBase), {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: apiBase.origin },
    body: { envelope },
    expected: [200],
    label: "repro intent",
  });
  validateIntent(prepared, envelope, intent);

  await authenticate(agent);
  const balances = await readBalances(agent);
  const quote = await proxyJson(agent, "/api/agent/proxy/leases/match", {
    request: {
      image: REPRO_SPEC.image,
      duration_seconds: REPRO_SPEC.duration_seconds,
      min_vram_mib: REPRO_SPEC.min_vram_mib,
      preferred_node_id: null,
      command: REPRO_SPEC.command,
      repro: {
        token_hash: intent.token_hash,
        spec_hash: intent.spec_hash,
        expected_exit_code: REPRO_SPEC.expected_exit_code,
        executor: "managed",
      },
    },
  });
  const reviewed = validateQuote(quote, intent);
  if (balances.usdg < reviewed.maximum) stop("wallet_unfunded", "wallet USDG is below the reviewed escrow");
  if (balances.eth === 0n) stop("wallet_unfunded", `wallet has no gas on ${CHAIN_NAME}`);

  const quotedStatus = await mcp.tool("prism_gpu_repro_status", { repro_token: prepared.repro_token });
  validateQuotedStatus(quotedStatus, intent, quote);
  const state = {
    version: stateVersion,
    stage: "reviewed",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    api_origin: apiBase.origin,
    wallet: agent.address.toLowerCase(),
    escrow: CURRENT_ESCROW,
    prepared,
    envelope,
    intent,
    quote,
    transactions: {},
    lease: null,
    final: null,
  };
  writeState(statePath, state);

  console.log("PAID GPU REPRO QUOTE — REVIEWED, NO FUNDS SPENT");
  console.log(`cost ceiling: ${formatUsdg(reviewed.maximum)} USDG (${reviewed.maximum} base units)`);
  console.log(`network: ${CHAIN_NAME} (${CHAIN_ID})`);
  console.log("executor: managed Vast");
  console.log(`duration: ${REPRO_SPEC.duration_seconds / 60} minutes`);
  console.log(`image: ${REPRO_SPEC.image}`);
  console.log(`node: ${quote.node_id}`);
  console.log(`rate: ${reviewed.rate} micro-USDG/second`);
  console.log(`quote: ${quote.quote_id}`);
  console.log(`expires: ${quote.expires_at}`);
  console.log(`local hard cap: ${formatUsdg(CAP_MICROS)} USDG`);
  console.log(`execute only this quote with REPRO_CONFIRM='CONFIRM ${quote.quote_id}' npm run repro:execute`);
}

async function execute() {
  // Two runners sharing one state file would sign against the same nonce and
  // could fund the same quote twice, so execution takes an exclusive lock.
  acquireRunLock(statePath);
  const state = readState(statePath);
  validateState(
    state,
    state.transactions?.funding ? state.intent.issued_at * 1_000 : Date.now(),
  );
  if (state.stage === "complete") {
    printComplete(state);
    return;
  }
  if (state.stage === "settled") {
    printSettled(state);
    return;
  }

  const agent = createAgent();
  if (!sameAddress(agent.address, state.wallet)) stop("wallet_mismatch", "configured wallet does not own the reviewed quote");
  await authenticate(agent);
  if (!state.transactions?.funding && process.env.REPRO_CONFIRM !== `CONFIRM ${state.quote.quote_id}`) {
    stop("confirmation_required", `set REPRO_CONFIRM to CONFIRM ${state.quote.quote_id} for this exact reviewed quote`);
  }

  const contract = await verifyChain(agent);
  const deposit = BigInt(state.quote.maximum_escrow);
  const balances = await readBalances(agent);
  if (!state.transactions?.funding && balances.usdg < deposit) {
    stop("wallet_unfunded", "wallet USDG is below the reviewed escrow");
  }
  if (!state.transactions?.funding && balances.eth === 0n) {
    stop("wallet_unfunded", `wallet has no gas on ${CHAIN_NAME}`);
  }

  const fundingData = encodeFunctionData({
    abi: escrowAbi,
    functionName: "createLease",
    args: [state.quote.node_id, REPRO_SPEC.duration_seconds, keccak256(stringToBytes(state.quote.quote_id))],
  });
  let fundingReceipt;
  if (state.transactions.funding) {
    fundingReceipt = await sendPersisted(agent, state, "funding", {
      to: CURRENT_ESCROW,
      data: fundingData,
      confirmations: CONFIRMATIONS,
    });
  } else {
    await setExactAllowance(agent, state, deposit);
    try {
      await agent.publicClient.call({ account: agent.address, to: CURRENT_ESCROW, data: fundingData });
    } catch (error) {
      stop("funding_simulation_failed", `reviewed createLease simulation failed: ${safeDetail(error)}`);
    }
    await persistSignedTransaction(agent, state, "funding", CURRENT_ESCROW, fundingData);
    fundingReceipt = await sendPersisted(agent, state, "funding", {
      to: CURRENT_ESCROW,
      data: fundingData,
      confirmations: CONFIRMATIONS,
    });
  }

  const funding = decodeLeaseFunded(fundingReceipt, {
    quote: state.quote,
    wallet: agent.address,
    fundingHash: state.transactions.funding.hash,
  });
  const allowanceAfterFunding = await allowance(agent);
  if (allowanceAfterFunding !== 0n) stop("allowance_not_consumed", "USDG allowance was not zero after funding");
  state.chain_lease_id = funding.leaseId.toString();
  state.stage = "funded";
  save(state);
  console.log(`funding finalized: ${explorer}/tx/${state.transactions.funding.hash}`);

  if (!state.lease) {
    state.lease = await confirmLease(agent, state);
    validateLeaseRecord(state.lease, {
      quote: state.quote,
      intent: state.intent,
      wallet: agent.address,
      fundingHash: state.transactions.funding.hash,
      chainLeaseId: funding.leaseId,
    });
    state.stage = "confirmed";
    save(state);
  } else {
    validateLeaseRecord(state.lease, {
      quote: state.quote,
      intent: state.intent,
      wallet: agent.address,
      fundingHash: state.transactions.funding.hash,
      chainLeaseId: funding.leaseId,
    });
  }
  console.log(`lease confirmed: internal ${state.lease.lease_id}, chain ${state.chain_lease_id}`);

  const mcp = new McpClient(new URL("/api/mcp", apiBase));
  const settled = await waitForSettled(mcp, state);
  assertExpectedResult(settled.result);
  const evidence = await mcp.tool("prism_gpu_repro_evidence", { repro_token: state.prepared.repro_token });
  const gateway = await agent.publicClient.readContract({
    address: CURRENT_ESCROW,
    abi: escrowAbi,
    functionName: "gateway",
  });
  if (!sameAddress(gateway, contract.gateway)) stop("gateway_changed", "escrow gateway changed during the repro");
  const report = await validateManagedEvidence(evidence, { intent: state.intent, lease: state.lease, gateway });
  const verification = await mcp.tool("prism_verify_gpu_repro", { repro_token: state.prepared.repro_token });
  validateVerification(verification, { intent: state.intent, lease: state.lease });

  const publicReceipt = await waitForPublicReceipt(mcp, state);
  validatePublicReceipt(publicReceipt, {
    intent: state.intent,
    quote: state.quote,
    lease: state.lease,
    chainLeaseId: funding.leaseId,
  });
  let finalization;
  try {
    finalization = await agent.publicClient.waitForTransactionReceipt({
      hash: publicReceipt.transaction_hash,
      confirmations: CONFIRMATIONS,
    });
  } catch (error) {
    stop("finalization_not_final", `receipt settlement transaction is not final: ${safeDetail(error)}`);
  }
  validateFinalizationReceipt(finalization, publicReceipt, funding.leaseId);

  // Nothing on the audited read-only surface reports whether the provider
  // machine is gone, so the run stops short of claiming a destruction it never
  // checked. --verify-cleanup finishes it.
  state.stage = "settled";
  state.final = {
    settled_at: new Date().toISOString(),
    receipt_id: publicReceipt.receipt_id,
    receipt_hash: publicReceipt.receipt_hash,
    settlement_transaction_hash: publicReceipt.transaction_hash.toLowerCase(),
    report_id: report.report_id,
    provider_instance_id: report.provider_instance_id,
    gpu_model: report.gpu_model,
  };
  save(state);
  printSettled(state);

  function save(next) {
    next.updated_at = new Date().toISOString();
    writeState(statePath, next);
  }
}

function inspect() {
  const state = readState(statePath);
  validateState(state, state.transactions?.funding ? 0 : Date.now());
  console.log(`stage: ${state.stage}`);
  console.log(`quote: ${state.quote.quote_id}`);
  console.log(`cost ceiling: ${formatUsdg(BigInt(state.quote.maximum_escrow))} USDG`);
  console.log(`node: ${state.quote.node_id}`);
  console.log(`expires: ${state.quote.expires_at}`);
  if (state.transactions?.funding?.hash) console.log(`funding: ${explorer}/tx/${state.transactions.funding.hash}`);
  if (state.chain_lease_id) console.log(`chain lease: ${state.chain_lease_id}`);
  if (state.final) console.log(`receipt: ${state.final.receipt_id}`);
  if (state.final?.provider_instance_id) console.log(`provider instance: ${state.final.provider_instance_id}`);
  if (state.cleanup) {
    console.log(`provider destroyed: ${state.cleanup.verified_at}`);
    console.log(`vast account: ${state.cleanup.vast_account_id} (${state.cleanup.account_binding})`);
  }
}

// Destruction is the one claim the audited MCP surface cannot make, so it is
// proven directly against the provider account. This mode never signs.
async function verifyCleanup() {
  acquireRunLock(statePath);
  const state = readState(statePath);
  validateState(state, 0);
  if (state.stage === "complete") {
    printComplete(state);
    return;
  }
  if (state.stage !== "settled") {
    stop("not_settled", `run is at stage ${state.stage}; settle it before verifying destruction`);
  }
  const instanceId = state.final?.provider_instance_id;
  if (!Number.isSafeInteger(instanceId) || instanceId <= 0) {
    stop("invalid_state", "settled state carries no provider instance id");
  }

  const key = required("VAST_API_KEY");
  const account = await vastJson("/api/v0/users/current/", key, "Vast account");
  const accountId = account?.id;
  if (!Number.isSafeInteger(accountId) || accountId <= 0) {
    stop("vast_unavailable", "Vast did not identify the account behind this credential");
  }
  const expectedAccount = process.env.VAST_ACCOUNT_ID;
  let binding = "account not pinned; compare this id with the lifecycle worker's Vast account";
  if (expectedAccount) {
    if (String(accountId) !== expectedAccount.trim()) {
      stop("wrong_vast_account", "VAST_API_KEY belongs to a different Vast account than VAST_ACCOUNT_ID");
    }
    binding = "matches VAST_ACCOUNT_ID";
  }

  const listed = await vastJson("/api/v1/instances/", key, "Vast instance list");
  const instances = Array.isArray(listed?.instances) ? listed.instances : null;
  if (!instances) stop("vast_unavailable", "Vast returned no readable instance list");
  if (instances.some((instance) => Number(instance?.id) === instanceId)) {
    stop("provider_not_destroyed", `Vast instance ${instanceId} is still on the account`);
  }
  const direct = await vastInstance(instanceId, key);
  if (direct !== null) {
    stop("provider_not_destroyed", `Vast still reports instance ${instanceId} as ${direct}`);
  }

  state.stage = "complete";
  state.cleanup = {
    verified_at: new Date().toISOString(),
    provider_instance_id: instanceId,
    vast_account_id: accountId,
    account_binding: binding,
    live_instances: instances.length,
  };
  state.updated_at = state.cleanup.verified_at;
  writeState(statePath, state);
  printComplete(state);
}

async function vastJson(path, key, label) {
  const response = await fetchBounded(new URL(path, "https://console.vast.ai"), {
    method: "GET",
    headers: { Accept: "application/json", Authorization: `Bearer ${key}` },
  }, label);
  if (response.status === 401 || response.status === 403) stop("vast_unauthorized", `${label} rejected the credential`);
  if (response.status !== 200) stop("vast_unavailable", `${label} returned HTTP ${response.status}`);
  try {
    return JSON.parse(response.text);
  } catch {
    stop("vast_unavailable", `${label} returned invalid JSON`);
  }
}

// A stopped instance still bills, so anything Vast still names counts as alive.
async function vastInstance(instanceId, key) {
  const response = await fetchBounded(new URL(`/api/v0/instances/${instanceId}/`, "https://console.vast.ai"), {
    method: "GET",
    headers: { Accept: "application/json", Authorization: `Bearer ${key}` },
  }, "Vast instance");
  return readVastInstance(response.status, response.text, instanceId);
}

async function verifyChain(agent) {
  let chainId;
  let code;
  let paused;
  let token;
  let gateway;
  try {
    [chainId, code, paused, token, gateway] = await Promise.all([
      agent.publicClient.getChainId(),
      agent.publicClient.getCode({ address: CURRENT_ESCROW }),
      agent.publicClient.readContract({ address: CURRENT_ESCROW, abi: escrowAbi, functionName: "paused" }),
      agent.publicClient.readContract({ address: CURRENT_ESCROW, abi: escrowAbi, functionName: "usd" }),
      agent.publicClient.readContract({ address: CURRENT_ESCROW, abi: escrowAbi, functionName: "gateway" }),
    ]);
  } catch (error) {
    stop("chain_unavailable", `could not verify the audited escrow: ${safeDetail(error)}`);
  }
  if (chainId !== CHAIN_ID) stop("wrong_chain", `RPC reports chain ${chainId}, expected ${CHAIN_ID}`);
  if (!code || code === "0x") stop("wrong_escrow", "audited escrow has no deployed code");
  if (paused !== false) stop("escrow_paused", "audited escrow is paused");
  if (!sameAddress(token, USDG)) stop("wrong_asset", "audited escrow does not use USDG");
  if (!isAddress(gateway) || sameAddress(gateway, zeroAddress)) {
    stop("wrong_gateway", "audited escrow reports no settlement gateway");
  }
  return { gateway };
}

async function setExactAllowance(agent, state, deposit) {
  const zeroData = encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [CURRENT_ESCROW, 0n] });
  const exactData = encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [CURRENT_ESCROW, deposit] });

  if (state.transactions.approve_exact) {
    await sendPersisted(agent, state, "approve_exact", { to: USDG, data: exactData, confirmations: 1 });
    if (await allowance(agent) !== deposit) stop("allowance_mismatch", "persisted exact USDG approval is no longer exact");
    return;
  }

  const current = await allowance(agent);
  if (current !== 0n || state.transactions.approve_zero) {
    if (!state.transactions.approve_zero) await persistSignedTransaction(agent, state, "approve_zero", USDG, zeroData);
    await sendPersisted(agent, state, "approve_zero", { to: USDG, data: zeroData, confirmations: 1 });
    if (await allowance(agent) !== 0n) stop("allowance_reset_failed", "USDG allowance did not reset to zero");
  }

  await persistSignedTransaction(agent, state, "approve_exact", USDG, exactData);
  await sendPersisted(agent, state, "approve_exact", { to: USDG, data: exactData, confirmations: 1 });
  if (await allowance(agent) !== deposit) stop("allowance_mismatch", "USDG allowance does not equal the reviewed deposit");
}

async function persistSignedTransaction(agent, state, name, to, data) {
  if (state.transactions[name]) {
    await validatePersistedTransaction(state.transactions[name], { to, data, wallet: agent.address });
    return state.transactions[name];
  }
  let request;
  let serialized;
  try {
    request = await agent.walletClient.prepareTransactionRequest({
      account: agent.account,
      to,
      data,
      value: 0n,
    });
  } catch (error) {
    stop("transaction_signing_failed", `could not prepare the ${name} transaction: ${safeDetail(error)}`);
  }
  validateTransactionFee(request, feeCap(), name);
  try {
    serialized = await agent.account.signTransaction(request);
  } catch (error) {
    stop("transaction_signing_failed", `could not sign the ${name} transaction: ${safeDetail(error)}`);
  }
  const hash = keccak256(serialized);
  state.transactions[name] = {
    hash,
    serialized,
    status: "signed",
    signed_at: new Date().toISOString(),
  };
  state.updated_at = new Date().toISOString();
  writeState(statePath, state);
  await validatePersistedTransaction(state.transactions[name], { to, data, wallet: agent.address });
  return state.transactions[name];
}

async function validatePersistedTransaction(transaction, { to, data, wallet }) {
  if (!transaction || typeof transaction !== "object"
    || !isHash(transaction.hash)
    || typeof transaction.serialized !== "string"
    || !/^0x[0-9a-fA-F]+$/.test(transaction.serialized)
    || keccak256(transaction.serialized).toLowerCase() !== transaction.hash.toLowerCase()) {
    stop("invalid_persisted_transaction", "persisted signed transaction is malformed");
  }
  let parsed;
  let signer;
  try {
    parsed = parseTransaction(transaction.serialized);
    signer = await recoverTransactionAddress({ serializedTransaction: transaction.serialized });
  } catch {
    stop("invalid_persisted_transaction", "persisted signed transaction cannot be decoded");
  }
  if (!sameAddress(signer, wallet)
    || !sameAddress(parsed.to, to)
    || parsed.chainId !== CHAIN_ID
    || (parsed.value ?? 0n) !== 0n
    || parsed.data?.toLowerCase() !== data.toLowerCase()) {
    stop("invalid_persisted_transaction", "persisted signed transaction changed its chain, signer, target, value, or calldata");
  }
  validateTransactionFee(parsed, feeCap(), "persisted");
}

async function sendPersisted(agent, state, name, { to, data, confirmations }) {
  const transaction = state.transactions[name];
  await validatePersistedTransaction(transaction, { to, data, wallet: agent.address });
  let receipt = await existingReceipt(agent, transaction.hash);
  if (!receipt) {
    try {
      const broadcaster = broadcastUrl
        ? createPublicClient({ chain: robinhoodChain, transport: http(broadcastUrl) })
        : agent.publicClient;
      const returned = await broadcaster.sendRawTransaction({ serializedTransaction: transaction.serialized });
      if (returned.toLowerCase() !== transaction.hash.toLowerCase()) {
        stop("transaction_hash_mismatch", `${name} broadcast returned a different transaction hash`);
      }
    } catch {
      // The RPC can accept a raw transaction and lose the response. Waiting on
      // the locally persisted hash is safer than signing or broadcasting a new one.
    }
  }
  try {
    receipt = await agent.publicClient.waitForTransactionReceipt({ hash: transaction.hash, confirmations });
  } catch (error) {
    stop("transaction_not_final", `${name} is not final under its persisted hash: ${safeDetail(error)}`);
  }
  if (receipt.status !== "success") stop("transaction_reverted", `${name} transaction reverted`);
  transaction.status = "final";
  transaction.block_number = receipt.blockNumber.toString();
  transaction.finalized_at = new Date().toISOString();
  state.updated_at = new Date().toISOString();
  writeState(statePath, state);
  return receipt;
}

async function existingReceipt(agent, hash) {
  try {
    return await agent.publicClient.getTransactionReceipt({ hash });
  } catch {
    return null;
  }
}

async function allowance(agent) {
  try {
    return await agent.publicClient.readContract({
      address: USDG,
      abi: erc20Abi,
      functionName: "allowance",
      args: [agent.address, CURRENT_ESCROW],
    });
  } catch (error) {
    stop("chain_unavailable", `could not read USDG allowance: ${safeDetail(error)}`);
  }
}

async function confirmLease(agent, state) {
  const url = new URL("/api/agent/proxy/leases/confirm", apiBase);
  const body = {
    quote_id: state.quote.quote_id,
    transaction_hash: state.transactions.funding.hash,
  };
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const response = await rawJsonRequest(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${agent.session}`,
        "Content-Type": "application/json",
      },
      body,
      label: "lease confirmation",
    });
    if (response.status === 200 || response.status === 201) return response.payload;
    const code = response.payload?.code ?? response.payload?.error;
    if (response.status < 500 && !retryableConfirmCodes.has(code)) {
      stop("confirmation_failed", `lease confirmation refused with ${String(code || response.status)}`);
    }
    await sleep(5_000);
  }
  stop("confirmation_timeout", "lease confirmation did not accept the finalized funding hash");
}

async function waitForSettled(mcp, state) {
  const deadline = Date.now() + pollTimeout();
  let previous = null;
  while (Date.now() < deadline) {
    const status = await mcp.tool("prism_gpu_repro_status", { repro_token: state.prepared.repro_token });
    validateReproStatus(status, state.intent, state.quote);
    if (status.lease_id !== state.lease.lease_id) stop("lease_mismatch", "repro status internal lease id changed");
    if (terminalFailures.has(status.status)) stop("repro_failed", `repro entered terminal status ${status.status}`);
    if (status.result) assertExpectedResult(status.result);
    if (status.status !== previous) {
      console.log(`repro status: ${status.status}`);
      previous = status.status;
    }
    if (status.status === "settled") return status;
    await sleep(pollInterval());
  }
  stop("repro_timeout", "repro did not settle before the polling deadline");
}

async function waitForPublicReceipt(mcp, state) {
  const deadline = Date.now() + pollTimeout();
  while (Date.now() < deadline) {
    // The feed keeps every run against this spec, so ask for enough rows that a
    // repeated run can still see its own among the earlier ones.
    const payload = await mcp.tool("prism_gpu_receipts", {
      limit: 100,
      repro_spec_hash: state.intent.spec_hash,
    });
    const receipt = selectRunReceipt(payload, {
      tokenHash: state.intent.token_hash,
      chainLeaseId: state.chain_lease_id,
    });
    if (receipt) return receipt;
    await sleep(pollInterval());
  }
  stop("receipt_timeout", "settled repro did not appear in the public receipt feed");
}

async function authenticate(agent) {
  try {
    const authenticated = await agent.authenticate();
    if (typeof agent.session !== "string" || !agent.session || authenticated?.session !== agent.session) {
      stop("authentication_failed", "wallet authentication returned no usable bearer session");
    }
  } catch (error) {
    if (error instanceof ReproRunError) throw error;
    stop("authentication_failed", `wallet authentication failed: ${safeDetail(error)}`);
  }
}

async function readBalances(agent) {
  try {
    const [usdg, eth] = await Promise.all([
      agent.publicClient.readContract({ address: USDG, abi: erc20Abi, functionName: "balanceOf", args: [agent.address] }),
      agent.publicClient.getBalance({ address: agent.address }),
    ]);
    return { usdg, eth };
  } catch (error) {
    stop("chain_unavailable", `could not read wallet balances: ${safeDetail(error)}`);
  }
}

async function proxyJson(agent, path, body) {
  return jsonRequest(new URL(path, apiBase), {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${agent.session}`,
      "Content-Type": "application/json",
    },
    body,
    expected: [200],
    label: path,
  });
}

class McpClient {
  constructor(url) {
    this.url = url;
    this.id = 0;
  }

  async call(method, params) {
    const id = ++this.id;
    const response = await fetchBounded(this.url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    }, "MCP");
    if (response.status !== 200) stop("mcp_unavailable", `MCP returned HTTP ${response.status}`);
    const message = parseMcpResponse(response, id);
    if (message.error) stop("mcp_failed", `MCP ${method} failed with code ${String(message.error.code)}`);
    if (!("result" in message)) stop("invalid_mcp", `MCP ${method} returned no result`);
    return message.result;
  }

  async tool(name, args) {
    const result = await this.call("tools/call", { name, arguments: args });
    return decodeToolResult(result, name);
  }
}

function parseMcpResponse(response, id) {
  const contentType = response.headers.get("content-type") ?? "";
  const candidates = [];
  if (contentType.includes("text/event-stream")) {
    for (const event of response.text.split(/\r?\n\r?\n/)) {
      const data = event.split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart())
        .join("\n");
      if (data && data !== "[DONE]") candidates.push(data);
    }
  } else {
    candidates.push(response.text);
  }
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed?.jsonrpc === "2.0" && parsed.id === id) return parsed;
    } catch {
      // Keep looking for the response carrying this JSON-RPC id.
    }
  }
  stop("invalid_mcp", "MCP response was not valid JSON-RPC or SSE");
}

async function jsonRequest(url, options) {
  const response = await rawJsonRequest(url, options);
  if (!options.expected.includes(response.status)) {
    const code = response.payload?.code ?? response.payload?.error ?? response.status;
    stop("http_error", `${options.label} returned ${String(code)}`);
  }
  return response.payload;
}

async function rawJsonRequest(url, { method, headers, body, label }) {
  const response = await fetchBounded(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }, label);
  let payload = null;
  if (response.text) {
    try {
      payload = JSON.parse(response.text);
    } catch {
      if (response.status >= 200 && response.status < 300) stop("invalid_response", `${label} returned invalid JSON`);
    }
  }
  return { status: response.status, payload };
}

async function fetchBounded(url, init, label) {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    stop("network_unavailable", `${label} request failed: ${safeDetail(error)}`);
  }
  const announced = Number(response.headers.get("content-length") ?? 0);
  if (announced > maxResponseBytes) stop("response_too_large", `${label} response is too large`);
  const body = await response.arrayBuffer();
  if (body.byteLength > maxResponseBytes) stop("response_too_large", `${label} response is too large`);
  return {
    status: response.status,
    headers: response.headers,
    text: Buffer.from(body).toString("utf8"),
  };
}

function createAgent() {
  const configuredEscrow = process.env.PRISM_ESCROW;
  if (configuredEscrow && !sameAddress(configuredEscrow, CURRENT_ESCROW)) {
    stop("wrong_escrow", "PRISM_ESCROW is not the audited current escrow");
  }
  return new PrismAgent({
    privateKey: required("PRISM_AGENT_KEY"),
    escrow: CURRENT_ESCROW,
    apiBase: apiBase.origin,
    rpcUrl,
  });
}

function validateState(state, now) {
  if (!state || typeof state !== "object" || Array.isArray(state) || state.version !== stateVersion) {
    stop("invalid_state", "paid repro state has an unsupported format");
  }
  if (state.api_origin !== apiBase.origin || !sameAddress(state.escrow, CURRENT_ESCROW)) {
    stop("invalid_state", "paid repro state is bound to another API origin or escrow");
  }
  if (!isAddress(state.wallet)) stop("invalid_state", "paid repro state has an invalid wallet");
  const { envelope } = validatePreparedRepro(state.prepared, apiBase.origin);
  if (envelope !== state.envelope) stop("invalid_state", "paid repro state envelope changed");
  validateIntent(state.prepared, state.envelope, state.intent, now);
  validateQuote(state.quote, state.intent, now);
  if (!state.transactions || typeof state.transactions !== "object" || Array.isArray(state.transactions)) {
    stop("invalid_state", "paid repro transaction state is invalid");
  }
}

function stateFile() {
  const value = required("REPRO_STATE_FILE");
  if (!isAbsolute(value)) abort("invalid_state_path", "REPRO_STATE_FILE must be an absolute path outside the repository");
  return value;
}

function assertNewStatePath(path) {
  if (existsSync(path)) abort("state_exists", "REPRO_STATE_FILE already exists; use a new path for a fresh capability");
  const parent = dirname(path);
  let info;
  try {
    info = statSync(parent);
  } catch {
    abort("invalid_state_path", "REPRO_STATE_FILE parent directory does not exist");
  }
  if (!info.isDirectory()) abort("invalid_state_path", "REPRO_STATE_FILE parent is not a directory");
}

function readState(path) {
  let info;
  try {
    info = lstatSync(path);
  } catch {
    abort("state_missing", "REPRO_STATE_FILE does not exist");
  }
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) {
    abort("insecure_state", "REPRO_STATE_FILE must be a regular file readable only by its owner");
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    abort("insecure_state", "REPRO_STATE_FILE is owned by another user");
  }
  if (info.size > maxResponseBytes) abort("invalid_state", "REPRO_STATE_FILE is too large");
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    abort("invalid_state", "REPRO_STATE_FILE does not contain valid JSON");
  }
}

function writeState(path, state) {
  if (existsSync(path)) {
    const current = lstatSync(path);
    if (!current.isFile() || current.isSymbolicLink()
      || (typeof process.getuid === "function" && current.uid !== process.getuid())) {
      abort("insecure_state", "refusing to replace an unsafe REPRO_STATE_FILE");
    }
  }
  const serialized = `${JSON.stringify(state, null, 2)}\n`;
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let descriptor;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeSync(descriptor, serialized);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    chmodSync(path, 0o600);
    const directory = openSync(dirname(path), "r");
    fsyncSync(directory);
    closeSync(directory);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // The temp file may not have been created or may already have been renamed.
    }
    abort("state_write_failed", `could not persist paid repro state: ${safeDetail(error)}`);
  }
}

function printSettled(state) {
  console.log("PAID GPU REPRO SETTLED — PROVIDER DESTRUCTION NOT VERIFIED");
  printRun(state);
  console.log(`provider instance: ${state.final.provider_instance_id} (Vast)`);
  console.log("verified: CUDA result, gateway-signed evidence, onchain settlement, public receipt");
  console.log("not verified: the provider machine is destroyed");
  console.log("run VAST_API_KEY=... npm run repro:verify-cleanup to finish this run");
}

function printComplete(state) {
  console.log("PAID GPU REPRO COMPLETE");
  printRun(state);
  console.log(`provider instance ${state.cleanup.provider_instance_id} absent from Vast account ${state.cleanup.vast_account_id}`);
  console.log(`vast account binding: ${state.cleanup.account_binding}`);
  console.log(`destruction verified: ${state.cleanup.verified_at}`);
}

function printRun(state) {
  console.log(`funding: ${explorer}/tx/${state.transactions.funding.hash}`);
  console.log(`settlement: ${explorer}/tx/${state.final.settlement_transaction_hash}`);
  console.log(`receipt: ${state.final.receipt_id}`);
  console.log(`receipt hash: ${state.final.receipt_hash}`);
  console.log(`GPU: ${state.final.gpu_model}`);
}

// Removed on every exit path this process controls, so a leftover lock means an
// execution died mid-flight and the chain has to be read before another run
// touches the same nonce.
function acquireRunLock(path) {
  const lockPath = `${path}.lock`;
  let descriptor;
  try {
    descriptor = openSync(lockPath, "wx", 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") {
      abort(
        "run_locked",
        `${lockPath} exists; another paid repro run holds this state file, or a previous one died and needs review`,
      );
    }
    abort("run_lock_failed", `could not take the paid repro run lock: ${safeDetail(error)}`);
  }
  try {
    writeSync(descriptor, `${JSON.stringify({ pid: process.pid, mode, started_at: new Date().toISOString() })}\n`);
  } finally {
    closeSync(descriptor);
  }
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    try {
      unlinkSync(lockPath);
    } catch {
      // A lock removed by hand is not worth failing a finished run over.
    }
  };
  process.on("exit", release);
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => {
      release();
      process.exit(1);
    });
  }
}

function feeCap() {
  const raw = process.env.REPRO_MAX_FEE_WEI;
  if (raw === undefined) return MAX_TRANSACTION_FEE_WEI;
  if (!/^[1-9][0-9]{0,30}$/.test(raw)) abort("invalid_configuration", "REPRO_MAX_FEE_WEI must be a positive integer in wei");
  return BigInt(raw);
}

function apiUrl(value) {
  const url = parseUrl(value, "PRISM_API_BASE");
  if (url.pathname !== "/" || url.search || url.hash) abort("invalid_api", "PRISM_API_BASE must be an origin without a path");
  return url;
}

function requiredUrl(name) {
  return parseUrl(required(name), name).toString();
}

function parseUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    abort("invalid_url", `${name} must be a valid HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    abort("invalid_url", `${name} must be an HTTPS URL without embedded credentials or a fragment`);
  }
  return url;
}

function required(name) {
  const value = process.env[name];
  if (!value) abort("missing_configuration", `missing ${name}`);
  return value;
}

function pollInterval() {
  return boundedSeconds("REPRO_POLL_SECONDS", 15, 5, 300) * 1_000;
}

function pollTimeout() {
  return boundedSeconds("REPRO_TIMEOUT_SECONDS", 7_200, 300, 14_400) * 1_000;
}

function boundedSeconds(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    abort("invalid_configuration", `${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeDetail(error) {
  const detail = error?.shortMessage ?? error?.message;
  if (typeof detail !== "string" || !detail) return "operation failed";
  return detail
    .replace(/https:\/\/[^\s/]+[^\s]*/gi, "[redacted-url]")
    .replace(/\b(?:0x)?[0-9a-f]{64}\b/gi, "[redacted-secret]")
    .replace(/\b[A-Za-z0-9_-]{43}\b/g, "[redacted-token]")
    .slice(0, 300);
}

function stop(code, message) {
  throw new ReproRunError(code, message);
}

function abort(code, message) {
  console.error(`paid repro stopped [${code}]: ${message}`);
  process.exit(1);
}

async function main() {
  try {
    if (mode === "--review") await review();
    if (mode === "--execute") await execute();
    if (mode === "--inspect") inspect();
    if (mode === "--verify-cleanup") await verifyCleanup();
  } catch (error) {
    if (error instanceof ReproRunError) {
      console.error(`paid repro stopped [${error.code}]: ${error.message}`);
    } else {
      console.error(`paid repro stopped [unexpected]: ${safeDetail(error)}`);
    }
    process.exitCode = 1;
  }
}

await main();
