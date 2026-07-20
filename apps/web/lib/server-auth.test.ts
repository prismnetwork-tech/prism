import { afterEach, describe, expect, it } from "vitest";
import { exportSPKI, generateKeyPair, SignJWT } from "jose";
import { verifyPrivySession } from "./server-auth";

const originalEnv = { ...process.env };

afterEach(() => {
  process.env = { ...originalEnv };
});

describe("verifyPrivySession", () => {
  it("verifies a Privy access token with a configured public key", async () => {
    const fixture = await tokenFixture("app-direct", "session-direct", "did:privy:direct");
    process.env.PRISM_PRIVY_APP_ID = fixture.appId;
    process.env.PRISM_PRIVY_VERIFICATION_KEY = fixture.publicKey;

    await expect(verifyPrivySession(fixture.token)).resolves.toEqual({
      did: "did:privy:direct",
      sessionId: "session-direct",
    });
  });
});

async function tokenFixture(appId: string, sessionId: string, subject: string) {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const token = await new SignJWT({ sid: sessionId })
    .setProtectedHeader({ alg: "ES256", typ: "JWT" })
    .setAudience(appId)
    .setIssuer("privy.io")
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
  return { appId, publicKey: await exportSPKI(publicKey), token };
}
