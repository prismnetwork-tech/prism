"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { http, type Address, createPublicClient, encodeFunctionData } from "viem";
import { usePrismAuth, useSmartWallet } from "@/components/providers";
import { robinhoodChain } from "@/lib/chain";
import {
  PRISM_STAKE,
  PRISM_TOKEN,
  TIERS,
  discountBps,
  erc20Abi,
  formatTokens,
  nextTier,
  parseTokens,
  stakeAbi,
  stakeCalls,
  untilLabel,
  wholeTokens,
} from "@/lib/staking";

const client = createPublicClient({ chain: robinhoodChain, transport: http() });

const PUBLISHED_RATE = 222;
const hourly = (rate: number) => ((rate * 3600) / 1e6).toFixed(4);

type Position = {
  balance: bigint;
  allowance: bigint;
  staked: bigint;
  unbonding: bigint;
  eligible: bigint;
  maturesAt: bigint;
  withdrawableAt: bigint;
  totalStaked: bigint;
};

async function readPosition(account: Address | null): Promise<Position> {
  const [totalStaked] = await Promise.all([
    client.readContract({ address: PRISM_STAKE, abi: stakeAbi, functionName: "totalStaked" }),
  ]);
  if (!account) {
    return {
      balance: 0n, allowance: 0n, staked: 0n, unbonding: 0n, eligible: 0n,
      maturesAt: 0n, withdrawableAt: 0n, totalStaked,
    };
  }
  const [balance, allowance, position, eligible] = await Promise.all([
    client.readContract({ address: PRISM_TOKEN, abi: erc20Abi, functionName: "balanceOf", args: [account] }),
    client.readContract({ address: PRISM_TOKEN, abi: erc20Abi, functionName: "allowance", args: [account, PRISM_STAKE] }),
    client.readContract({ address: PRISM_STAKE, abi: stakeAbi, functionName: "positionOf", args: [account] }),
    client.readContract({ address: PRISM_STAKE, abi: stakeAbi, functionName: "eligibleStakeOf", args: [account] }),
  ]);
  return {
    balance, allowance, eligible, totalStaked,
    staked: position[0], unbonding: position[1], maturesAt: position[2], withdrawableAt: position[3],
  };
}

export function Stake() {
  const auth = usePrismAuth();
  const smartWallet = useSmartWallet();
  const wallet = useMemo<Address | null>(() => auth.accounts[0]?.address ?? null, [auth.accounts]);
  const [position, setPosition] = useState<Position | null>(null);
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setPosition(await readPosition(wallet));
    } catch {
      setNotice("Could not read the chain. Your position is unchanged.");
    }
  }, [wallet]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const parsed = parseTokens(amount);
  const currentBps = position ? discountBps(position.eligible) : 0;
  const afterBps = position && parsed ? discountBps(position.staked + parsed) : currentBps;
  const upcoming = position ? nextTier(position.staked) : null;
  const maturing = position && position.staked > 0n ? untilLabel(position.maturesAt) : null;
  const cooling = position && position.unbonding > 0n ? untilLabel(position.withdrawableAt) : null;

  async function run(task: string, calls: { to: Address; data: `0x${string}` }[]) {
    if (!wallet) return;
    setBusy(task);
    setNotice(null);
    try {
      await smartWallet.executeCalls(calls, wallet);
      setAmount("");
      await refresh();
      setNotice("Done. The chain has your position.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The transaction did not go through.");
    } finally {
      setBusy(null);
    }
  }

  const stake = () => {
    if (!position || !parsed || parsed <= 0n) return;
    void run("stake", stakeCalls(parsed, position.allowance) as { to: Address; data: `0x${string}` }[]);
  };

  const unstake = () => {
    if (!position || !parsed || parsed <= 0n) return;
    void run("unstake", [{
      to: PRISM_STAKE,
      data: encodeFunctionData({ abi: stakeAbi, functionName: "unstake", args: [parsed] }),
    }]);
  };

  const withdraw = () =>
    void run("withdraw", [{
      to: PRISM_STAKE,
      data: encodeFunctionData({ abi: stakeAbi, functionName: "withdraw" }),
    }]);

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Token</p><h1>Stake</h1></div>
        <span className="chip">Robinhood Chain</span>
      </div>

      <div className="metric-grid">
        <article className="metric-card">
          <p>Your discount</p>
          <strong>{(currentBps / 100).toFixed(0)}%</strong>
          <span>{currentBps > 0 ? `${hourly(Math.floor((PUBLISHED_RATE * (10_000 - currentBps)) / 10_000))} USDG per GPU hour` : `${hourly(PUBLISHED_RATE)} USDG per GPU hour`}</span>
        </article>
        <article className="metric-card">
          <p>Counting toward it</p>
          <strong>{position ? formatTokens(position.eligible, 0) : "—"}</strong>
          <span>{maturing ? `${formatTokens(position!.staked - position!.eligible, 0)} matures in ${maturing}` : "PRISM locked and mature"}</span>
        </article>
        <article className="metric-card">
          <p>Leaving</p>
          <strong>{position ? formatTokens(position.unbonding, 0) : "—"}</strong>
          <span>{cooling ? `withdrawable in ${cooling}` : position && position.unbonding > 0n ? "ready to withdraw" : "nothing unbonding"}</span>
        </article>
        <article className="metric-card">
          <p>Locked network-wide</p>
          <strong>{position ? formatTokens(position.totalStaked, 0) : "—"}</strong>
          <span>PRISM across every staker</span>
        </article>
      </div>

      {notice && <p className="form-notice" role="status">{notice}</p>}

      <div className="compute-layout">
        <article className="panel launch-form">
          <h2>Lock PRISM</h2>
          <p className="muted">
            Locking gives you access to capacity priced below the published rate. It pays no
            rewards and issues nothing: the whole benefit is cheaper compute.
          </p>

          <label>
            Amount
            <input
              inputMode="decimal"
              placeholder="0"
              value={amount}
              onChange={(event) => setAmount(event.target.value)}
            />
            <small>
              Balance {position ? formatTokens(position.balance) : "—"} PRISM
              {position && position.balance > 0n && (
                <>
                  {" · "}
                  <button className="text-link" type="button" onClick={() => setAmount(formatTokens(position.balance).replace(/,/g, ""))}>
                    Use max
                  </button>
                </>
              )}
            </small>
          </label>

          {parsed && parsed > 0n && (
            <div className="quote-line">
              <span>Discount after this</span>
              <strong>{(afterBps / 100).toFixed(0)}%</strong>
            </div>
          )}

          <button className="button primary full" type="button" disabled={!wallet || busy !== null || !parsed || parsed <= 0n} onClick={stake}>
            {busy === "stake" ? "Confirm in your wallet…" : wallet ? "Lock PRISM" : "Connect a wallet"}
          </button>

          <div className="setting-actions">
            <button className="button secondary" type="button" disabled={!wallet || busy !== null || !parsed || parsed <= 0n} onClick={unstake}>
              {busy === "unstake" ? "Starting…" : "Start unlocking"}
            </button>
            <button className="button secondary" type="button" disabled={!wallet || busy !== null || !position || position.unbonding === 0n || Boolean(cooling)} onClick={withdraw}>
              {busy === "withdraw" ? "Withdrawing…" : "Withdraw"}
            </button>
          </div>

          <div className="safety-note">
            <strong>Locking takes a day to count and a week to leave.</strong>
            Stake becomes eligible 24 hours after it lands, and adding more restarts that. Unlocking
            stops the discount straight away and returns the tokens 7 days later.
          </div>
        </article>

        <article className="panel quote-card">
          <h2>Tiers</h2>
          {TIERS.map((tier) => {
            const reached = position ? wholeTokens(position.eligible) >= tier.tokens : false;
            return (
              <div className="quote-line" key={tier.tokens.toString()}>
                <span>{tier.tokens.toLocaleString("en-US")} PRISM</span>
                <strong className={reached ? "" : "muted"}>{tier.discountBps / 100}%</strong>
              </div>
            );
          })}
          {upcoming && position && (
            <p className="muted">
              {(upcoming.tokens - wholeTokens(position.staked)).toLocaleString("en-US")} more PRISM
              reaches {upcoming.discountBps / 100}%.
            </p>
          )}
          <p className="muted">
            The scheduler decides which machines you can match against. A discount applies when a
            lease is quoted, so it shows up in what you pay rather than as a rebate later.
          </p>
        </article>
      </div>
    </section>
  );
}
