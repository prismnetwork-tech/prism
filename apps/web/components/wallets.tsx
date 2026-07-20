"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Address } from "viem";
import { usePrismAuth } from "@/components/providers";
import { useSupplierSummary } from "@/components/use-supplier-summary";

type WalletChallenge = {
  challenge_id: string;
  wallet_address: string;
  message: string;
  expires_at: string;
};

export function Wallets() {
  const auth = usePrismAuth();
  const summary = useSupplierSummary();
  const queryClient = useQueryClient();
  const [pending, setPending] = useState<Address | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const verified = new Set(summary.data?.linked_wallets.map((address) => address.toLowerCase()) ?? []);
  const action = !auth.configured
    ? null
    : auth.authenticated
      ? <button className="button primary" type="button" onClick={auth.linkWallet}>Connect another wallet</button>
      : <button className="button primary" type="button" onClick={auth.login}>Sign in to connect</button>;

  async function verify(address: Address) {
    setPending(address);
    setNotice(null);
    try {
      const challenge = await requestChallenge(address);
      const signature = await auth.signWalletMessage(address, challenge.message);
      const response = await fetch("/api/app/account/wallets/link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge_id: challenge.challenge_id,
          wallet_address: address,
          signature,
        }),
      });
      if (!response.ok) throw new Error("The ownership proof was rejected.");
      await queryClient.invalidateQueries({ queryKey: ["supplier-summary", auth.userId] });
      setNotice("Wallet ownership verified for provider inventory and payouts.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Wallet ownership could not be verified.");
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="page-stack">
      <div className="page-heading"><div><p className="eyebrow">Account and billing</p><h1>Wallets</h1></div>{action}</div>
      {!auth.configured && <p className="form-notice" role="status">Account access and wallet linking are temporarily unavailable.</p>}
      {notice && <p className="form-notice" role="status">{notice}</p>}
      {auth.accounts.length ? (
        <article className="panel settings-list">
          {auth.accounts.map((account) => {
            const isVerified = verified.has(account.address.toLowerCase());
            return (
              <div key={account.address}>
                <div><h2>{account.embedded ? "Embedded wallet" : account.label}</h2><p className="mono">{account.address}</p></div>
                <div className="setting-actions">
                  <span className={`chip ${isVerified ? "success" : ""}`}>{isVerified ? "Ownership verified" : "Verification required"}</span>
                  {!isVerified && auth.authenticated && (
                    <button className="button secondary" type="button" disabled={pending !== null} onClick={() => void verify(account.address)}>
                      {pending === account.address ? "Check wallet…" : "Verify ownership"}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </article>
      ) : (
        <article className="panel empty-state"><span className="empty-icon">◇</span><h2>No wallet connected</h2><p>Connect an EVM wallet or create an embedded wallet through your Prism account. Signature verification is required before a wallet can access provider nodes or earnings.</p>{auth.configured && !auth.authenticated && <button className="button secondary" type="button" onClick={auth.login}>Sign in to continue</button>}</article>
      )}
      <article className="panel proof-disclosure"><p className="eyebrow">Wallet security</p><h2>Signature-based verification</h2><p>Prism verifies wallet ownership through a short-lived, single-use message signed by that wallet. The signature cannot authorize a transaction or transfer funds.</p></article>
    </section>
  );
}

async function requestChallenge(address: Address): Promise<WalletChallenge> {
  const response = await fetch(`/api/app/account/wallets/challenge?address=${encodeURIComponent(address.toLowerCase())}`, {
    cache: "no-store",
  });
  if (!response.ok) throw new Error("A wallet ownership challenge could not be created.");
  const payload: unknown = await response.json();
  if (!isWalletChallenge(payload, address)) throw new Error("The ownership challenge response was invalid.");
  return payload;
}

function isWalletChallenge(value: unknown, address: Address): value is WalletChallenge {
  if (!value || typeof value !== "object") return false;
  const challenge = value as Partial<WalletChallenge>;
  return typeof challenge.challenge_id === "string"
    && /^[0-9a-f-]{36}$/i.test(challenge.challenge_id)
    && challenge.wallet_address?.toLowerCase() === address.toLowerCase()
    && typeof challenge.message === "string"
    && challenge.message.length > 0
    && challenge.message.length <= 1_024
    && typeof challenge.expires_at === "string";
}
