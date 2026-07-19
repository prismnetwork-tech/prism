import { createHash } from "node:crypto";
import { decodeFunctionData, getAddress, parseAbi, type Address, type Hex } from "viem";
import { robinhoodChain, usdgAddress } from "@/lib/chain";

const tokenAbi = parseAbi(["function approve(address spender,uint256 amount) returns (bool)"]);
const escrowAbi = parseAbi(["function createLease(bytes32 nodeId,uint32 duration,bytes32 clientReference) returns (uint256 leaseId)"]);
const maxEscrow = 50_000_000n;
const maxDuration = 21_600;

export type WalletRpcRequest = {
  jsonrpc: "2.0";
  id: string | number | null;
  method: "wallet_prepareCalls" | "wallet_sendPreparedCalls" | "wallet_getCallsStatus" | "eth_getTransactionReceipt";
  params: unknown[];
};

type RpcCall = { to: Address; data: Hex; value: bigint };

export class WalletProxyError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

export function parseWalletRpc(input: unknown): WalletRpcRequest {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new WalletProxyError(400, "invalid_rpc", "A single JSON-RPC request is required.");
  const request = input as Record<string, unknown>;
  const methods = new Set(["wallet_prepareCalls", "wallet_sendPreparedCalls", "wallet_getCallsStatus", "eth_getTransactionReceipt"]);
  if (request.jsonrpc !== "2.0" || !methods.has(String(request.method)) || !Array.isArray(request.params)) {
    throw new WalletProxyError(403, "rpc_method_denied", "This wallet operation is not allowed.");
  }
  if (!(typeof request.id === "string" || typeof request.id === "number" || request.id === null)) {
    throw new WalletProxyError(400, "invalid_rpc", "The JSON-RPC request ID is invalid.");
  }
  return request as WalletRpcRequest;
}

export function injectSponsorship(request: WalletRpcRequest, policyId: string): WalletRpcRequest {
  if (request.method !== "wallet_prepareCalls" && request.method !== "wallet_sendPreparedCalls") return request;
  const first = request.params[0];
  if (!first || typeof first !== "object" || Array.isArray(first)) throw new WalletProxyError(400, "invalid_rpc", "Wallet call parameters are invalid.");
  const firstRecord = first as Record<string, unknown>;
  const capabilities = firstRecord.capabilities;
  const safeCapabilities = capabilities && typeof capabilities === "object" && !Array.isArray(capabilities)
    ? Object.fromEntries(Object.entries(capabilities).filter(([key]) => key !== "paymasterService" && key !== "paymaster"))
    : {};
  return {
    ...request,
    params: [{ ...firstRecord, capabilities: { ...safeCapabilities, paymasterService: { policyId } } }, ...request.params.slice(1)],
  };
}

export function authorizePreparedCalls(request: WalletRpcRequest) {
  if (request.method !== "wallet_prepareCalls") return;
  const input = request.params[0] as Record<string, unknown> | undefined;
  if (!isApplicationChain(input?.chainId)) {
    throw new WalletProxyError(400, "invalid_chain", "Wallet calls must target Robinhood Chain.");
  }
  const escrow = configuredAddress("PRISM_ESCROW_ADDRESS");
  const calls = rpcCalls(input?.calls);
  if (calls.length !== 2 || !sameAddress(calls[0].to, usdgAddress) || !sameAddress(calls[1].to, escrow)) {
    throw new WalletProxyError(403, "call_not_authorized", "Only a USDG approval followed by a lease escrow call can be sponsored.");
  }
  if (calls.some((call) => call.value !== 0n)) throw new WalletProxyError(403, "call_not_authorized", "Native-value transfers are not sponsored.");
  let approval;
  let lease;
  try {
    approval = decodeFunctionData({ abi: tokenAbi, data: calls[0].data });
    lease = decodeFunctionData({ abi: escrowAbi, data: calls[1].data });
  } catch {
    throw new WalletProxyError(403, "call_not_authorized", "The wallet batch does not match the lease contract interface.");
  }
  if (approval.functionName !== "approve" || lease.functionName !== "createLease") {
    throw new WalletProxyError(403, "call_not_authorized", "The wallet batch is not a lease funding operation.");
  }
  const spender = approval.args[0] as Address;
  const amount = approval.args[1] as bigint;
  const duration = Number(lease.args[1]);
  const clientReference = lease.args[2] as Hex;
  if (
    !sameAddress(spender, escrow)
    || amount <= 0n
    || amount > maxEscrow
    || duration < 1
    || duration > maxDuration
    || !/^0x[0-9a-fA-F]{64}$/.test(clientReference)
    || /^0x0{64}$/.test(clientReference)
  ) {
    throw new WalletProxyError(403, "call_not_authorized", "The lease funding limits are invalid.");
  }
}

export function preparedCallsFingerprint(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new WalletProxyError(400, "invalid_prepared_calls", "Prepared wallet calls are invalid.");
  }
  const record = value as Record<string, unknown>;
  if (!["user-operation-v060", "user-operation-v070", "authorization", "array"].includes(String(record.type))) {
    throw new WalletProxyError(400, "invalid_prepared_calls", "Prepared wallet call type is not supported.");
  }
  assertPreparedChains(record);
  const normalized = normalizePrepared(record);
  return createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
}

function rpcCalls(value: unknown): RpcCall[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) throw new WalletProxyError(400, "invalid_call", "A lease funding batch must contain one or two calls.");
  return value.map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new WalletProxyError(400, "invalid_call", "A wallet call is invalid.");
    const call = raw as Record<string, unknown>;
    const to = address(call.to);
    if (!to || typeof call.data !== "string" || !/^0x[0-9a-fA-F]*$/.test(call.data)) {
      throw new WalletProxyError(400, "invalid_call", "A wallet call target or calldata is invalid.");
    }
    try {
      return { to, data: call.data as Hex, value: BigInt(String(call.value ?? "0")) };
    } catch {
      throw new WalletProxyError(400, "invalid_call", "A wallet call value is invalid.");
    }
  });
}

function configuredAddress(key: string): Address {
  const value = process.env[key];
  const parsed = address(value);
  if (!parsed) throw new WalletProxyError(503, "wallet_unavailable", `${key} is not configured.`);
  return parsed;
}

function isApplicationChain(value: unknown) {
  try {
    return typeof value === "string" ? Number(BigInt(value)) === robinhoodChain.id : value === robinhoodChain.id;
  } catch {
    return false;
  }
}

function address(value: unknown): Address | null {
  if (typeof value !== "string") return null;
  try {
    return getAddress(value);
  } catch {
    return null;
  }
}

function sameAddress(left: string, right: string) {
  return left.toLowerCase() === right.toLowerCase();
}

function assertPreparedChains(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertPreparedChains);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  if ("chainId" in record && !isApplicationChain(record.chainId)) {
    throw new WalletProxyError(400, "invalid_chain", "Prepared calls must target Robinhood Chain.");
  }
  Object.values(record).forEach(assertPreparedChains);
}

function normalizePrepared(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizePrepared);
  if (!value || typeof value !== "object") return value;
  const excluded = new Set(["signature", "signatureRequest", "feePayment", "details", "capabilities", "callId"]);
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([key]) => !excluded.has(key))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalizePrepared(entry)]),
  );
}
