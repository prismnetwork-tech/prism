import { type Address, encodeFunctionData, parseAbi } from "viem";

export const PRISM_TOKEN = "0x0A1e0Cc751f77C2C93760FC957CC8E4E779b2bC8" as Address;
export const PRISM_STAKE = "0x7c4060e0b1f6954a90ea92Ee81C14b3b70D1be7c" as Address;

export const PRISM_DECIMALS = 18;

/// Mirrors `STAKE_DISCOUNT_TIERS` in prism-protocol. The scheduler is the
/// authority; this exists so the page can show what a stake is worth before
/// somebody commits to it.
export const TIERS = [
  { tokens: 1_000n, discountBps: 500 },
  { tokens: 10_000n, discountBps: 1_000 },
  { tokens: 50_000n, discountBps: 1_500 },
  { tokens: 250_000n, discountBps: 2_000 },
] as const;

export const stakeAbi = parseAbi([
  "function stake(uint256 amount)",
  "function unstake(uint256 amount)",
  "function withdraw()",
  "function eligibleStakeOf(address account) view returns (uint256)",
  "function positionOf(address account) view returns (uint256 staked, uint256 unbonding, uint64 maturesAt, uint64 withdrawableAt)",
  "function totalStaked() view returns (uint256)",
  "function MATURITY() view returns (uint64)",
  "function COOLDOWN() view returns (uint64)",
]);

export const erc20Abi = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 value) returns (bool)",
]);

export function wholeTokens(raw: bigint) {
  return raw / 10n ** BigInt(PRISM_DECIMALS);
}

export function discountBps(staked: bigint) {
  const whole = wholeTokens(staked);
  let bps = 0;
  for (const tier of TIERS) {
    if (whole >= tier.tokens) bps = tier.discountBps;
  }
  return bps;
}

export function nextTier(staked: bigint) {
  const whole = wholeTokens(staked);
  return TIERS.find((tier) => whole < tier.tokens) ?? null;
}

/// Approve only when the allowance falls short, so a returning staker signs
/// once instead of twice.
export function stakeCalls(amount: bigint, allowance: bigint) {
  const calls = [];
  if (allowance < amount) {
    calls.push({
      to: PRISM_TOKEN,
      data: encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [PRISM_STAKE, amount] }),
    });
  }
  calls.push({
    to: PRISM_STAKE,
    data: encodeFunctionData({ abi: stakeAbi, functionName: "stake", args: [amount] }),
  });
  return calls;
}

export function formatTokens(raw: bigint, maximumFractionDigits = 2) {
  const whole = raw / 10n ** BigInt(PRISM_DECIMALS);
  const fraction = raw % 10n ** BigInt(PRISM_DECIMALS);
  const value = Number(whole) + Number(fraction) / 10 ** PRISM_DECIMALS;
  return value.toLocaleString("en-US", { maximumFractionDigits });
}

export function parseTokens(input: string) {
  const trimmed = input.trim();
  if (!/^\d*\.?\d*$/.test(trimmed) || trimmed === "" || trimmed === ".") return null;
  const [whole, fraction = ""] = trimmed.split(".");
  const padded = (fraction + "0".repeat(PRISM_DECIMALS)).slice(0, PRISM_DECIMALS);
  return BigInt(whole || "0") * 10n ** BigInt(PRISM_DECIMALS) + BigInt(padded || "0");
}

/// Seconds until a timestamp, floored at zero, rendered for a countdown.
export function untilLabel(timestamp: bigint | number) {
  const seconds = Number(timestamp) - Math.floor(Date.now() / 1000);
  if (seconds <= 0) return null;
  const hours = Math.floor(seconds / 3600);
  if (hours >= 24) return `${Math.floor(hours / 24)}d ${hours % 24}h`;
  if (hours >= 1) return `${hours}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.max(1, Math.floor(seconds / 60))}m`;
}
