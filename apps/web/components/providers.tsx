"use client";

import {
  PrivyProvider,
  toViemAccount,
  usePrivy,
  useWallets,
} from "@privy-io/react-auth";
import { alchemyWalletTransport, createSmartWalletClient } from "@alchemy/wallet-apis";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { stringToHex, type Address, type Hex } from "viem";
import { robinhoodChain } from "@/lib/chain";
import { ThemeProvider } from "@/components/theme-provider";

export type ConnectedAccount = {
  address: Address;
  label: string;
  embedded: boolean;
};

export type TransactionCall = {
  to: Address;
  data: Hex;
  value?: bigint;
};

type AuthContextValue = {
  configured: boolean;
  ready: boolean;
  authenticated: boolean;
  userId: string | null;
  hasRecovery: boolean;
  accounts: ConnectedAccount[];
  embeddedAddress: Address | null;
  login: () => void;
  logout: () => Promise<void>;
  linkWallet: () => void;
  linkEmail: () => void;
  linkPasskey: () => void;
  signWalletMessage: (address: Address, message: string) => Promise<Hex>;
  getAccessToken: () => Promise<string | null>;
};

type SmartWalletContextValue = {
  pending: boolean;
  executeCalls: (calls: TransactionCall[], signerAddress?: Address, onSubmitted?: (id: Hex) => void) => Promise<{
    id: Hex;
    transactionHash: Hex;
  }>;
};

const AuthContext = createContext<AuthContextValue | null>(null);
const SmartWalletContext = createContext<SmartWalletContextValue | null>(null);

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } },
  }));
  const appId = process.env.NEXT_PUBLIC_PRISM_PRIVY_APP_ID;
  const content = appId ? (
    <PrivyProvider
      appId={appId}
      config={{
        loginMethods: ["email", "passkey", "google", "apple", "wallet"],
        supportedChains: [robinhoodChain],
        defaultChain: robinhoodChain,
        embeddedWallets: { ethereum: { createOnLogin: "users-without-wallets" } },
        appearance: { theme: "dark", accentColor: "#ccff00" },
      }}
    >
      <LiveSession>{children}</LiveSession>
    </PrivyProvider>
  ) : <UnconfiguredSession>{children}</UnconfiguredSession>;

  return <QueryClientProvider client={queryClient}><ThemeProvider>{content}</ThemeProvider></QueryClientProvider>;
}

function LiveSession({ children }: { children: React.ReactNode }) {
  const privy = usePrivy();
  const privyRef = useRef(privy);
  privyRef.current = privy;
  const { wallets, ready: walletsReady } = useWallets();
  const [pending, setPending] = useState(false);
  const [sessionReady, setSessionReady] = useState(false);
  const embedded = wallets.find((wallet) => wallet.walletClientType === "privy") ?? null;
  const getAccessToken = useCallback(() => privyRef.current.getAccessToken(), []);

  const accounts = useMemo(() => wallets.map((wallet) => ({
    address: wallet.address as Address,
    label: wallet.walletClientType === "privy" ? "Prism embedded wallet" : wallet.meta.name,
    embedded: wallet.walletClientType === "privy",
  })), [wallets]);
  const hasRecovery = Boolean(privy.user?.linkedAccounts.some((account) => account.type === "email" || account.type === "passkey"));

  useEffect(() => {
    if (!privy.ready) return;
    let cancelled = false;
    if (!privy.authenticated) {
      setSessionReady(false);
      void fetch("/api/auth/session", { method: "DELETE" });
      return () => { cancelled = true; };
    }
    setSessionReady(false);
    void synchronizeSession(getAccessToken).then((ok) => {
      if (cancelled) return;
      if (ok) {
        setSessionReady(true);
        return;
      }
      void privyRef.current.logout();
    });
    return () => { cancelled = true; };
  }, [getAccessToken, privy.authenticated, privy.ready, privy.user?.id]);

  useEffect(() => {
    const expire = () => { void privy.logout(); };
    window.addEventListener("prism:session-expired", expire);
    return () => window.removeEventListener("prism:session-expired", expire);
  }, [privy]);

  const executeCalls = useCallback(async (calls: TransactionCall[], signerAddress?: Address, onSubmitted?: (id: Hex) => void) => {
    const wallet = signerAddress
      ? wallets.find((candidate) => candidate.address.toLowerCase() === signerAddress.toLowerCase())
      : embedded;
    if (!wallet) throw new Error("The selected wallet is not connected in this browser.");
    setPending(true);
    try {
      const signer = await toViemAccount({ wallet });
      const client = createSmartWalletClient({
        signer,
        chain: robinhoodChain,
        transport: alchemyWalletTransport({ url: "/api/wallet" }),
      });
      const result = await client.sendCalls({
        calls: calls.map((call) => ({ to: call.to, data: call.data, value: call.value ?? 0n })),
      });
      onSubmitted?.(result.id);
      const status = await client.waitForCallsStatus({ id: result.id });
      if (status.status !== "success") throw new Error("The onchain operation did not complete.");
      const transactionHash = status.receipts?.at(-1)?.transactionHash;
      if (!transactionHash) throw new Error("The wallet provider returned no funding transaction receipt.");
      return { id: result.id, transactionHash };
    } finally {
      setPending(false);
    }
  }, [embedded, wallets]);

  const signWalletMessage = useCallback(async (address: Address, message: string) => {
    const wallet = wallets.find((candidate) => candidate.address.toLowerCase() === address.toLowerCase());
    if (!wallet) throw new Error("The selected wallet is not connected in this browser.");
    const provider = await wallet.getEthereumProvider();
    const signature = await provider.request({
      method: "personal_sign",
      params: [stringToHex(message), address],
    });
    if (typeof signature !== "string" || !/^0x[0-9a-f]{130}$/i.test(signature)) {
      throw new Error("The wallet returned an invalid ownership signature.");
    }
    return signature as Hex;
  }, [wallets]);

  const auth = useMemo<AuthContextValue>(() => ({
    configured: true,
    ready: privy.ready && walletsReady && (!privy.authenticated || sessionReady),
    authenticated: privy.authenticated && sessionReady,
    userId: privy.user?.id ?? null,
    hasRecovery,
    accounts,
    embeddedAddress: embedded ? embedded.address as Address : null,
    login: () => privy.login(),
    logout: () => privy.logout(),
    linkWallet: () => privy.linkWallet({ walletChainType: "ethereum-only" }),
    linkEmail: () => privy.linkEmail(),
    linkPasskey: () => privy.linkPasskey({ name: "Prism recovery" }),
    signWalletMessage,
    getAccessToken,
  }), [accounts, embedded, getAccessToken, hasRecovery, privy, sessionReady, signWalletMessage, walletsReady]);

  return <SessionContexts auth={auth} smartWallet={{ pending, executeCalls }}>{children}</SessionContexts>;
}

async function synchronizeSession(getAccessToken: () => Promise<string | null>) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const token = await getAccessToken();
      if (!token) return false;
      const response = await fetch("/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
        signal: AbortSignal.timeout(10_000),
      });
      if (response.ok) return true;
      if (response.status >= 400 && response.status < 500 && response.status !== 429) return false;
    } catch {
      // A short retry absorbs transient identity-provider and network failures.
    }
    await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
  }
  return false;
}

function UnconfiguredSession({ children }: { children: React.ReactNode }) {
  const auth = useMemo<AuthContextValue>(() => ({
    configured: false,
    ready: true,
    authenticated: false,
    userId: null,
    hasRecovery: false,
    accounts: [],
    embeddedAddress: null,
    login: () => undefined,
    logout: async () => undefined,
    linkWallet: () => undefined,
    linkEmail: () => undefined,
    linkPasskey: () => undefined,
    signWalletMessage: async () => { throw new Error("Prism authentication is not configured."); },
    getAccessToken: async () => null,
  }), []);
  const smartWallet = useMemo<SmartWalletContextValue>(() => ({
    pending: false,
    executeCalls: async () => { throw new Error("Prism authentication is not configured."); },
  }), []);
  return <SessionContexts auth={auth} smartWallet={smartWallet}>{children}</SessionContexts>;
}

function SessionContexts({ auth, smartWallet, children }: { auth: AuthContextValue; smartWallet: SmartWalletContextValue; children: React.ReactNode }) {
  return <AuthContext.Provider value={auth}><SmartWalletContext.Provider value={smartWallet}>{children}</SmartWalletContext.Provider></AuthContext.Provider>;
}

export function usePrismAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("usePrismAuth must be used inside Providers.");
  return context;
}

export function useSmartWallet() {
  const context = useContext(SmartWalletContext);
  if (!context) throw new Error("useSmartWallet must be used inside Providers.");
  return context;
}
