// Where a gateway listens, and what it costs to listen anywhere but here.
//
// These gateways hold a funded wallet, broadcast transactions and hand back the
// output of jobs, and none of that is behind an account. So the default address
// is loopback: reaching one from another machine is something an operator has
// to choose, and choosing it means naming a credential that every request then
// has to carry. Behind a reverse proxy the proxy holds the credential, which is
// what makes the front door the only way in.
import { timingSafeEqual } from "node:crypto";

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"]);
const MIN_TOKEN = 16;

export function isLoopback(host) {
  return LOOPBACK.has(String(host).trim().toLowerCase());
}

/// The address and credential for one gateway, from `<prefix>_HOST` and
/// `<prefix>_TOKEN`. Throws rather than widening quietly, because a listener
/// that came up on the wrong address has already been reachable by the time
/// anyone reads the warning.
export function listener(env, prefix) {
  const host = env[`${prefix}_HOST`]?.trim() || "127.0.0.1";
  const token = env[`${prefix}_TOKEN`]?.trim() || null;
  if (isLoopback(host)) return { host, token };
  if (!token) {
    throw new Error(
      `${prefix}_HOST is ${host}, so anything that can route to this machine can reach every route. ` +
        `Set ${prefix}_TOKEN to a secret of at least ${MIN_TOKEN} characters, or bind to 127.0.0.1.`,
    );
  }
  if (token.length < MIN_TOKEN) {
    throw new Error(`${prefix}_TOKEN must be at least ${MIN_TOKEN} characters to guard a listener on ${host}.`);
  }
  return { host, token };
}

/// Constant time, and tolerant of the two strings differing in length.
function matches(offered, expected) {
  const a = Buffer.from(offered);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/// Without a token every caller is already on this machine, so there is nothing
/// to check. The bare value is accepted as well as `Bearer <value>`, because a
/// probe configured with one and not the other is not a security event.
export function authorized(req, token) {
  if (!token) return "ok";
  const header = req.headers.authorization ?? "";
  const offered = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (offered === "") return "missing";
  return matches(offered, token) ? "ok" : "mismatch";
}
