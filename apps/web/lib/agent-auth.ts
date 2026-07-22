import { randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { getAddress, isAddress, recoverMessageAddress } from "viem";

const CHALLENGE_TTL = "5m";
const SESSION_TTL_SECONDS = 3_600;

function secret() {
  const raw = process.env.PRISM_AGENT_SESSION_SECRET;
  if (!raw || raw.length < 32) throw new AgentAuthConfigError();
  return new TextEncoder().encode(raw);
}

function challengeStatement(address: string, nonce: string, issued: string) {
  return [
    "Prism Network agent authentication.",
    `wallet: ${address}`,
    `nonce: ${nonce}`,
    `issued: ${issued}`,
    "Signing proves control of this wallet. It authorizes no transaction.",
  ].join("\n");
}

export async function issueChallenge(address: string) {
  if (!isAddress(address)) throw new AgentAuthError();
  const wallet = getAddress(address);
  const nonce = randomUUID();
  const issued = new Date().toISOString();
  const statement = challengeStatement(wallet, nonce, issued);
  const challenge = await new SignJWT({ wallet, statement, kind: "agent-challenge" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(CHALLENGE_TTL)
    .sign(secret());
  return { wallet, message: statement, challenge };
}

export async function issueSession(challenge: string, address: string, signature: string) {
  if (!isAddress(address) || !/^0x[0-9a-fA-F]+$/.test(signature)) throw new AgentAuthError();
  const wallet = getAddress(address);
  let payload;
  try {
    ({ payload } = await jwtVerify(challenge, secret(), { algorithms: ["HS256"] }));
  } catch {
    throw new AgentAuthError();
  }
  if (payload.kind !== "agent-challenge" || payload.wallet !== wallet || typeof payload.statement !== "string") {
    throw new AgentAuthError();
  }
  let recovered: string;
  try {
    recovered = await recoverMessageAddress({
      message: payload.statement,
      signature: signature as `0x${string}`,
    });
  } catch {
    throw new AgentAuthError();
  }
  if (getAddress(recovered) !== wallet) throw new AgentAuthError();

  const sessionId = randomUUID();
  const session = await new SignJWT({ kind: "agent-session", sid: sessionId })
    .setSubject(`wallet:${wallet}`)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(secret());
  return { session, subject: `wallet:${wallet}`, sessionId, expiresIn: SESSION_TTL_SECONDS };
}

export async function verifySession(token: string) {
  let payload;
  try {
    ({ payload } = await jwtVerify(token, secret(), { algorithms: ["HS256"] }));
  } catch {
    throw new AgentAuthError();
  }
  if (payload.kind !== "agent-session" || typeof payload.sub !== "string" || typeof payload.sid !== "string") {
    throw new AgentAuthError();
  }
  return { subject: payload.sub, sessionId: payload.sid };
}

export class AgentAuthConfigError extends Error {}
export class AgentAuthError extends Error {}
