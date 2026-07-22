import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import {
  AgentAuthConfigError,
  AgentAuthError,
  issueChallenge,
  issueSession,
  verifySession,
} from "@/lib/agent-auth";

const SECRET = "0".repeat(64);
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const other = privateKeyToAccount(`0x${"22".repeat(32)}`);

async function signedChallenge(signer = account, subject = account.address) {
  const { challenge, message } = await issueChallenge(subject);
  const signature = await signer.signMessage({ message });
  return { challenge, signature };
}

beforeEach(() => {
  process.env.PRISM_AGENT_SESSION_SECRET = SECRET;
});
afterEach(() => {
  delete process.env.PRISM_AGENT_SESSION_SECRET;
});

describe("agent auth", () => {
  it("issues a session for a valid wallet signature and verifies it", async () => {
    const { challenge, signature } = await signedChallenge();
    const session = await issueSession(challenge, account.address, signature);
    expect(session.subject).toBe(`wallet:${account.address}`);
    expect(session.expiresIn).toBe(3600);
    const verified = await verifySession(session.session);
    expect(verified.subject).toBe(`wallet:${account.address}`);
    expect(verified.sessionId).toBe(session.sessionId);
  });

  it("rejects a replayed challenge (single-use nonce)", async () => {
    const { challenge, signature } = await signedChallenge();
    await issueSession(challenge, account.address, signature);
    await expect(issueSession(challenge, account.address, signature)).rejects.toBeInstanceOf(AgentAuthError);
  });

  it("rejects a signature from a different wallet", async () => {
    const { challenge } = await issueChallenge(account.address);
    const message = (await issueChallenge(account.address)).message; // same statement shape
    const signature = await other.signMessage({ message });
    await expect(issueSession(challenge, account.address, signature)).rejects.toBeInstanceOf(AgentAuthError);
  });

  it("rejects a tampered challenge token", async () => {
    const { challenge, signature } = await signedChallenge();
    await expect(issueSession(`${challenge}x`, account.address, signature)).rejects.toBeInstanceOf(AgentAuthError);
  });

  it("rejects a session token signed with a different secret", async () => {
    const { challenge, signature } = await signedChallenge();
    const session = await issueSession(challenge, account.address, signature);
    process.env.PRISM_AGENT_SESSION_SECRET = "1".repeat(64);
    await expect(verifySession(session.session)).rejects.toBeInstanceOf(AgentAuthError);
  });

  it("requires a high-entropy session secret", async () => {
    process.env.PRISM_AGENT_SESSION_SECRET = "short";
    await expect(issueChallenge(account.address)).rejects.toBeInstanceOf(AgentAuthConfigError);
  });

  it("rejects a malformed address", async () => {
    await expect(issueChallenge("not-an-address")).rejects.toBeInstanceOf(AgentAuthError);
  });
});
