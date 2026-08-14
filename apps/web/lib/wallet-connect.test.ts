import { describe, expect, it } from "vitest";
import { resolveWalletConnectProjectId } from "./wallet-connect";

describe("WalletConnect project id", () => {
  it("accepts a well-formed id and trims surrounding whitespace", () => {
    const id = "0123456789abcdef0123456789abcdef";
    expect(resolveWalletConnectProjectId(id)).toBe(id);
    expect(resolveWalletConnectProjectId(`  ${id}  `)).toBe(id);
  });

  it("accepts uppercase hex", () => {
    expect(resolveWalletConnectProjectId("0123456789ABCDEF0123456789ABCDEF"))
      .toBe("0123456789ABCDEF0123456789ABCDEF");
  });

  it("drops unset, empty and malformed values so sign-in still works", () => {
    for (const value of [
      undefined,
      "",
      "   ",
      "replace-me",
      "0123456789abcdef0123456789abcde", // 31 chars
      "0123456789abcdef0123456789abcdef0", // 33 chars
      "0123456789abcdef0123456789abcdeg", // non-hex
    ]) {
      expect(resolveWalletConnectProjectId(value)).toBeUndefined();
    }
  });
});
