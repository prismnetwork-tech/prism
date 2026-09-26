import type { Address, Chain, Hash, WalletClient } from "viem";

export declare const prismChain: Chain;
export declare const PRISM_CHAIN_BRIDGE_URL: string;
export declare const prismChainContracts: {
  rollup: Address;
  inbox: Address;
  outbox: Address;
  parentRouter: Address;
  parentStandardGateway: Address;
  childRouter: Address;
  arbSys: Address;
};

export interface TokenDepositFees {
  maxGas: bigint;
  gasPriceBid: bigint;
  maxSubmissionCost: bigint;
  /** Wei of ETH sent with the deposit; the unused part is refunded on Prism Chain. */
  value: bigint;
}

interface RpcOptions {
  parentRpcUrl?: string;
  childRpcUrl?: string;
}

export declare function prismChainToken(token: Address, options?: { rpcUrl?: string }): Promise<Address>;
export declare function tokenDepositFees(token: Address, options?: RpcOptions): Promise<TokenDepositFees>;
export declare function depositEth(wallet: WalletClient, amount: bigint): Promise<Hash>;
export declare function depositToken(wallet: WalletClient, token: Address, amount: bigint, options?: RpcOptions): Promise<Hash>;
export declare function withdraw(wallet: WalletClient, amount: bigint, options?: { token?: Address | null }): Promise<Hash>;
