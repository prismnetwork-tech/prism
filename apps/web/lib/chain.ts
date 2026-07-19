import { defineChain } from "viem";

export const robinhoodChain = defineChain({
  id: 4663,
  name: "Robinhood Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: { http: [process.env.NEXT_PUBLIC_PRISM_RPC_URL || "https://rpc.mainnet.chain.robinhood.com"] },
  },
  blockExplorers: {
    default: { name: "Blockscout", url: "https://robinhoodchain.blockscout.com" },
  },
});

export const usdgAddress = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168" as const;
const configuredEscrow = process.env.NEXT_PUBLIC_PRISM_ESCROW_ADDRESS;
export const escrowAddress = configuredEscrow && /^0x[0-9a-fA-F]{40}$/.test(configuredEscrow)
  ? configuredEscrow as `0x${string}`
  : undefined;

export const escrowAbi = [
  {
    type: "function",
    name: "createLease",
    stateMutability: "nonpayable",
    inputs: [
      { name: "nodeId", type: "bytes32" },
      { name: "duration", type: "uint32" },
      { name: "clientReference", type: "bytes32" },
    ],
    outputs: [{ name: "leaseId", type: "uint256" }],
  },
] as const;

export const usdgAbi = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;
