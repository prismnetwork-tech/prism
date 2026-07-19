import { importSPKI, jwtVerify } from "jose";

export type PrivySession = {
  did: string;
  sessionId: string;
};

let cachedKey: { pem: string; key: ReturnType<typeof importSPKI> } | undefined;

export async function verifyPrivySession(token: string): Promise<PrivySession> {
  const appId = process.env.PRISM_PRIVY_APP_ID ?? process.env.NEXT_PUBLIC_PRISM_PRIVY_APP_ID;
  const rawKey = process.env.PRISM_PRIVY_VERIFICATION_KEY;
  if (!appId || !rawKey) throw new SessionConfigurationError();
  if (token.length < 20 || token.length > 8_192) throw new SessionValidationError();

  const pem = rawKey.replaceAll("\\n", "\n");
  if (!cachedKey || cachedKey.pem !== pem) {
    cachedKey = { pem, key: importSPKI(pem, "ES256") };
  }

  try {
    const { payload } = await jwtVerify(token, await cachedKey.key, {
      algorithms: ["ES256"],
      audience: appId,
      issuer: "privy.io",
    });
    if (typeof payload.sub !== "string" || !payload.sub || typeof payload.sid !== "string" || !payload.sid) {
      throw new SessionValidationError();
    }
    return { did: payload.sub, sessionId: payload.sid };
  } catch (error) {
    if (error instanceof SessionValidationError) throw error;
    throw new SessionValidationError();
  }
}

export class SessionConfigurationError extends Error {}
export class SessionValidationError extends Error {}
