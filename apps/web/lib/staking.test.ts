import { describe, expect, it } from "vitest";
import {
  PRISM_STAKE,
  PRISM_TOKEN,
  discountBps,
  formatTokens,
  nextTier,
  parseTokens,
  stakeCalls,
  wholeTokens,
} from "@/lib/staking";

const tokens = (n: string) => parseTokens(n)!;

describe("staking", () => {
  // These have to agree with STAKE_DISCOUNT_TIERS in prism-protocol, or the
  // page promises a discount the scheduler will not give.
  it("matches the tiers the scheduler enforces", () => {
    expect(discountBps(tokens("0"))).toBe(0);
    expect(discountBps(tokens("999"))).toBe(0);
    expect(discountBps(tokens("1000"))).toBe(500);
    expect(discountBps(tokens("10000"))).toBe(1_000);
    expect(discountBps(tokens("50000"))).toBe(1_500);
    expect(discountBps(tokens("250000"))).toBe(2_000);
    expect(discountBps(tokens("100000000"))).toBe(2_000);
  });

  it("points at the next threshold until there is none", () => {
    expect(nextTier(tokens("0"))?.tokens).toBe(1_000n);
    expect(nextTier(tokens("1000"))?.tokens).toBe(10_000n);
    expect(nextTier(tokens("250000"))).toBeNull();
  });

  it("round trips amounts without losing precision", () => {
    expect(parseTokens("1")).toBe(10n ** 18n);
    expect(parseTokens("0.5")).toBe(5n * 10n ** 17n);
    expect(parseTokens("1234.5678")).toBe(1_234_567_800_000_000_000_000n);
    expect(wholeTokens(tokens("999.99"))).toBe(999n);
    expect(formatTokens(tokens("1234.5"))).toBe("1,234.5");
  });

  it("rejects input that is not an amount", () => {
    for (const bad of ["", ".", "abc", "-1", "1e5", "1.2.3"]) {
      expect(parseTokens(bad)).toBeNull();
    }
  });

  // Approving every time is a second signature for no reason, and approving
  // when short would make the stake revert.
  it("only approves when the allowance falls short", () => {
    const amount = tokens("100");

    const fresh = stakeCalls(amount, 0n);
    expect(fresh).toHaveLength(2);
    expect(fresh[0].to).toBe(PRISM_TOKEN);
    expect(fresh[1].to).toBe(PRISM_STAKE);

    const covered = stakeCalls(amount, tokens("500"));
    expect(covered).toHaveLength(1);
    expect(covered[0].to).toBe(PRISM_STAKE);

    expect(stakeCalls(amount, amount)).toHaveLength(1);
  });
});
