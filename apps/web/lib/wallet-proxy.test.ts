import { beforeEach, describe, expect, it } from "vitest";
import { encodeFunctionData } from "viem";
import { escrowAbi, usdgAbi, usdgAddress } from "./chain";
import { authorizePreparedCalls, parseWalletRpc, preparedCallsFingerprint, WalletProxyError } from "./wallet-proxy";

const escrow = "0x1111111111111111111111111111111111111111" as const;
const nodeId = "0x65ee796729d5b3b8a9b43864e8c76955e33c2f06ad6637d5b8c9e18d2616ea8b" as const;
const reference = `0x${"12".repeat(32)}` as const;

describe("wallet sponsorship boundary", () => {
  beforeEach(() => {
    process.env.PRISM_ESCROW_ADDRESS = escrow;
  });

  it("allows a bounded USDG approval followed by lease creation", () => {
    const request = parseWalletRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "wallet_prepareCalls",
      params: [{
        chainId: 4663,
        calls: [
          { to: usdgAddress, data: encodeFunctionData({ abi: usdgAbi, functionName: "approve", args: [escrow, 50_000_000n] }) },
          { to: escrow, data: encodeFunctionData({ abi: escrowAbi, functionName: "createLease", args: [nodeId, 21_600, reference] }) },
        ],
      }],
    });
    expect(() => authorizePreparedCalls(request)).not.toThrow();
  });

  it("rejects an approval over the mainnet escrow cap", () => {
    const request = parseWalletRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "wallet_prepareCalls",
      params: [{
        chainId: 4663,
        calls: [
          { to: usdgAddress, data: encodeFunctionData({ abi: usdgAbi, functionName: "approve", args: [escrow, 50_000_001n] }) },
          { to: escrow, data: encodeFunctionData({ abi: escrowAbi, functionName: "createLease", args: [nodeId, 60, reference] }) },
        ],
      }],
    });
    expect(() => authorizePreparedCalls(request)).toThrow(WalletProxyError);
  });

  it("rejects arbitrary sponsored contract calls", () => {
    const request = parseWalletRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "wallet_prepareCalls",
      params: [{ chainId: 4663, calls: [{ to: escrow, data: "0x12345678" }] }],
    });
    expect(() => authorizePreparedCalls(request)).toThrow(WalletProxyError);
  });

  it("binds submission to the exact prepared operation", () => {
    const prepared = {
      type: "user-operation-v070",
      chainId: "0x1237",
      data: { sender: escrow, nonce: "0x1", callData: "0x1234" },
      signatureRequest: { type: "personal_sign", rawPayload: "0xab" },
      feePayment: { sponsored: true },
      details: { type: "user-operation" },
    };
    const signed = {
      type: "user-operation-v070",
      chainId: "0x1237",
      data: { sender: escrow, nonce: "0x1", callData: "0x1234" },
      signature: { type: "secp256k1", data: "0xcd" },
      capabilities: { paymasterService: { policyId: "hidden" } },
    };

    expect(preparedCallsFingerprint(signed)).toBe(preparedCallsFingerprint(prepared));
    expect(preparedCallsFingerprint({
      ...signed,
      data: { ...signed.data, callData: "0x5678" },
    })).not.toBe(preparedCallsFingerprint(prepared));
  });
});
