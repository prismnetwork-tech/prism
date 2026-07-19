import { describe, expect, it } from "vitest";
import { robinhoodChain, usdgAddress } from "./chain";

describe("Robinhood Chain configuration", () => {
  it("pins the mainnet chain and canonical USDG contract", () => {
    expect(robinhoodChain.id).toBe(4663);
    expect(usdgAddress).toBe("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168");
  });
});
