import { createHash, createHmac } from "node:crypto";
import { SessionConfigurationError, verifyPrivySession } from "./server-auth";

export async function signControlIdentity(
  token: string,
  requestId: string,
  method: string,
  path: string,
  body: Buffer,
) {
  const key = process.env.PRISM_CONTROL_PLANE_AUTH_KEY;
  if (!key || !/^[0-9a-f]{64,}$/i.test(key)) throw new SessionConfigurationError();
  const session = await verifyPrivySession(token);
  const timestamp = String(Math.floor(Date.now() / 1_000));
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const signature = createHmac("sha256", Buffer.from(key, "hex"))
    .update(["v2", session.did, session.sessionId, timestamp, requestId, method, path, bodyHash].join("\n"))
    .digest("hex");
  return { subject: session.did, sessionId: session.sessionId, timestamp, signature };
}

export function controlPlaneUrl(base: string, path: string[]) {
  try {
    const origin = new URL(/^https?:\/\//.test(base) ? base : `http://${base}`);
    if (!["http:", "https:"].includes(origin.protocol) || origin.username || origin.password) return null;
    return new URL(`/v1/${path.join("/")}`, origin);
  } catch {
    return null;
  }
}
