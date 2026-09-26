/// Prism Chain: the Layer 3 for GPU compute, settled on Robinhood Chain.
///
/// Assets reach it through the canonical Arbitrum token bridge. A deposit lands
/// on Prism Chain in about a minute. A withdrawal starts on Prism Chain,
/// finalizes on Robinhood Chain after the rollup's confirmation window (about a
/// day), and is then claimed there; https://bridge.prismnetwork.tech does the
/// claim. Leases still settle on Robinhood Chain today.
import { createPublicClient, defineChain, encodeAbiParameters, erc20Abi, http, parseAbi } from "viem";

// Kept here rather than imported from prism.mjs, which pulls in Node modules;
// this file stays usable in a browser.
const robinhoodChain = defineChain({
  id: 4663,
  name: "Robinhood Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["https://rpc.mainnet.chain.robinhood.com"] } },
});

export const prismChain = defineChain({
  id: 77476,
  name: "Prism Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://rpc.prismnetwork.tech"], webSocket: ["wss://ws.prismnetwork.tech"] },
  },
  blockExplorers: { default: { name: "Prism Chain explorer", url: "https://explorer.prismnetwork.tech" } },
  sourceId: robinhoodChain.id,
});

export const PRISM_CHAIN_BRIDGE_URL = "https://bridge.prismnetwork.tech";

/// The rollup on Robinhood Chain and both halves of the token bridge.
export const prismChainContracts = {
  rollup: "0x8232Ce617E7F1031F5B7bdcD72678dbdF2fDafeB",
  inbox: "0x2FbD2fF90f56C58A8789Fc56e8b31F26e660438f",
  outbox: "0x8cC14bF09cE7a1bf2415C70E5E4B9f50cD4a889d",
  parentRouter: "0x52f5aF48C1DF13E0e1ABbe04F99622aabF6B2CD2",
  parentStandardGateway: "0x1274b56aE5566014bB73dfE0A2247ab5BbC96470",
  childRouter: "0x12d1c6c0b4b97278A7E2961eF16105Ba2dd2e859",
  arbSys: "0x0000000000000000000000000000000000000064",
};

const inboxAbi = parseAbi([
  "function depositEth() payable returns (uint256)",
  "function calculateRetryableSubmissionFee(uint256 dataLength, uint256 baseFee) view returns (uint256)",
]);
const parentRouterAbi = parseAbi([
  "function getGateway(address token) view returns (address)",
  "function outboundTransferCustomRefund(address token, address refundTo, address to, uint256 amount, uint256 maxGas, uint256 gasPriceBid, bytes data) payable returns (bytes)",
]);
const childRouterAbi = parseAbi([
  "function calculateL2TokenAddress(address l1Token) view returns (address)",
  "function outboundTransfer(address l1Token, address to, uint256 amount, bytes data) payable returns (bytes)",
]);
const arbSysAbi = parseAbi(["function withdrawEth(address destination) payable returns (uint256)"]);

const parent = (rpcUrl) => createPublicClient({ chain: robinhoodChain, transport: http(rpcUrl) });
const child = (rpcUrl) => createPublicClient({ chain: prismChain, transport: http(rpcUrl) });

/// Where a Robinhood Chain token lives on Prism Chain. Its contract exists once
/// the first deposit of that token has landed.
export function prismChainToken(token, { rpcUrl } = {}) {
  return child(rpcUrl).readContract({
    address: prismChainContracts.childRouter,
    abi: childRouterAbi,
    functionName: "calculateL2TokenAddress",
    args: [token],
  });
}

/// What a token deposit prepays for its call on Prism Chain, in wei of ETH on
/// Robinhood Chain. The first deposit of a token also deploys its contract
/// there, which needs more gas. Whatever goes unused is refunded to the sender
/// on Prism Chain, so this is a ceiling, not a price.
export async function tokenDepositFees(token, { parentRpcUrl, childRpcUrl } = {}) {
  const [block, childGasPrice, deployed] = await Promise.all([
    parent(parentRpcUrl).getBlock(),
    child(childRpcUrl).getGasPrice(),
    prismChainToken(token, { rpcUrl: childRpcUrl }).then((address) => child(childRpcUrl).getCode({ address })),
  ]);
  const maxGas = deployed && deployed !== "0x" ? 300_000n : 1_200_000n;
  const gasPriceBid = childGasPrice * 2n;
  const submission = await parent(parentRpcUrl).readContract({
    address: prismChainContracts.inbox,
    abi: inboxAbi,
    functionName: "calculateRetryableSubmissionFee",
    args: [2_000n, block.baseFeePerGas ?? 0n],
  });
  const maxSubmissionCost = submission * 4n;
  return { maxGas, gasPriceBid, maxSubmissionCost, value: maxSubmissionCost + maxGas * gasPriceBid };
}

/// Move ETH from Robinhood Chain to the same address on Prism Chain. `wallet`
/// is a viem wallet client on Robinhood Chain. Returns the Robinhood Chain
/// transaction hash.
export function depositEth(wallet, amount) {
  return wallet.writeContract({
    chain: robinhoodChain,
    address: prismChainContracts.inbox,
    abi: inboxAbi,
    functionName: "depositEth",
    value: amount,
  });
}

/// Move an ERC-20 such as USDG from Robinhood Chain to the same address on
/// Prism Chain. Approves the token's gateway first when the allowance is short.
export async function depositToken(wallet, token, amount, { parentRpcUrl, childRpcUrl } = {}) {
  const account = wallet.account.address;
  const reader = parent(parentRpcUrl);
  const gateway = await reader.readContract({
    address: prismChainContracts.parentRouter,
    abi: parentRouterAbi,
    functionName: "getGateway",
    args: [token],
  });
  const allowance = await reader.readContract({ address: token, abi: erc20Abi, functionName: "allowance", args: [account, gateway] });
  if (allowance < amount) {
    const approval = await wallet.writeContract({
      chain: robinhoodChain,
      address: token,
      abi: erc20Abi,
      functionName: "approve",
      args: [gateway, amount],
    });
    await reader.waitForTransactionReceipt({ hash: approval });
  }
  const fees = await tokenDepositFees(token, { parentRpcUrl, childRpcUrl });
  const data = encodeAbiParameters([{ type: "uint256" }, { type: "bytes" }], [fees.maxSubmissionCost, "0x"]);
  return wallet.writeContract({
    chain: robinhoodChain,
    address: prismChainContracts.parentRouter,
    abi: parentRouterAbi,
    functionName: "outboundTransferCustomRefund",
    args: [token, account, account, amount, fees.maxGas, fees.gasPriceBid, data],
    value: fees.value,
  });
}

/// Start moving ETH, or a bridged token given by its Robinhood Chain address,
/// back to Robinhood Chain. `wallet` is a viem wallet client on Prism Chain.
/// The withdrawal is claimable on Robinhood Chain after about a day, at
/// PRISM_CHAIN_BRIDGE_URL. Returns the Prism Chain transaction hash.
export function withdraw(wallet, amount, { token = null } = {}) {
  const account = wallet.account.address;
  if (!token) {
    return wallet.writeContract({
      chain: prismChain,
      address: prismChainContracts.arbSys,
      abi: arbSysAbi,
      functionName: "withdrawEth",
      args: [account],
      value: amount,
    });
  }
  return wallet.writeContract({
    chain: prismChain,
    address: prismChainContracts.childRouter,
    abi: childRouterAbi,
    functionName: "outboundTransfer",
    args: [token, account, amount, "0x"],
  });
}
