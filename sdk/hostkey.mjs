// Checking which machine answered.
//
// A lease hands the renter an address and a private key. Until the host key on
// the other end is checked, anything that can reach that address can take the
// session, read the work and answer as if it were the GPU. What the network can
// say about that key differs by where the capacity came from, so the decision is
// made here rather than defaulted:
//
//   - the grant names a fingerprint, so the key is checked before the session
//     opens and a mismatch ends the attempt;
//   - the grant names none, so the key is recorded the first time it is seen and
//     held for the rest of the lease. That catches a substitution partway
//     through and cannot catch one that was there from the start.
//
// The record lives beside the lease's private key and goes when the lease does.
// Nothing here touches the caller's own ~/.ssh/known_hosts.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const SCAN_TIMEOUT_SECONDS = 10;

export class HostKeyError extends Error {
  constructor(code, detail) {
    super(code);
    this.name = "HostKeyError";
    this.code = code;
    this.detail = detail ?? null;
  }
}

/// What the network is willing to say about the machine behind a grant, in the
/// terms a renter would use to decide whether to send it anything.
///
/// `attested` is the only one that survives a hostile operator: the fingerprint
/// comes out of a report the processor signed. `reported` is the operator's word
/// under their bonded device key, which rules out everyone between them and the
/// renter. `unverified` means nobody published a key and the first connection
/// decides.
export function hostKeyPolicy(access) {
  const fingerprint = access?.channel_key_fingerprint ?? null;
  if (!fingerprint) return { mode: "unverified", fingerprint: null, source: null };
  return {
    mode: access.channel_key_source === "snp_report" ? "attested" : "reported",
    fingerprint,
    source: access.channel_key_source ?? null,
  };
}

export function knownHostsPath(keyPath) {
  return join(dirname(keyPath), "known_hosts");
}

/// The `ssh-keygen -lf` form of the key in a `known_hosts` line, or null if the
/// line does not hold one. The control plane publishes fingerprints in exactly
/// this form, so the two are compared as strings.
export function knownHostsFingerprint(line) {
  const blob = line.trim().split(/\s+/)[2];
  if (!blob) return null;
  const raw = Buffer.from(blob, "base64");
  if (raw.length === 0) return null;
  return `SHA256:${createHash("sha256").update(raw).digest("base64").replace(/=+$/, "")}`;
}

/// How `ssh` and `ssh-keyscan` both name a host in `known_hosts`. Anything off
/// the default port is bracketed, and an entry under the wrong name is an entry
/// `ssh` will not find.
function hostField(host, port) {
  return Number(port) === 22 ? String(host) : `[${host}]:${port}`;
}

/// A relayed session has no address of its own: the tunnel opens on whatever
/// local port is free and closes with the command, so the name `ssh` would file
/// the key under is gone before the next one runs and a record made on first
/// sight would never be read again. `HostKeyAlias` files it under the lease
/// instead, which is what makes first-use pinning worth anything there. Capacity
/// with a real endpoint keeps its own host and port, which is stable and says
/// something true about where the session went.
function hostKeyAlias(access) {
  if (access?.mode !== "gateway") return null;
  return access.lease_id ? `prism-lease-${access.lease_id}` : "prism-lease";
}

function scan(host, port) {
  return new Promise((resolve) => {
    execFile(
      "ssh-keyscan",
      ["-T", String(SCAN_TIMEOUT_SECONDS), "-p", String(port), host],
      { timeout: (SCAN_TIMEOUT_SECONDS + 5) * 1_000 },
      (err, stdout) => resolve({ err, lines: (stdout ?? "").split("\n").filter((l) => l && !l.startsWith("#")) }),
    );
  });
}

// A record that names the right key under a name `ssh` will not look up is a
// record `ssh` will refuse to use. Both halves have to match for the scan to be
// worth skipping.
function alreadyPinned(path, name, fingerprint) {
  try {
    return readFileSync(path, "utf8")
      .split("\n")
      .some((line) => line.trim().split(/\s+/)[0] === name && knownHostsFingerprint(line) === fingerprint);
  } catch {
    return false;
  }
}

/// Reads the host key off the wire and records it only if it is the one the
/// grant named.
///
/// Done as a separate exchange before ssh runs, because a fingerprint cannot be
/// turned into a `known_hosts` entry without the key itself, and letting ssh
/// learn the key first would mean trusting it to find out whether it should
/// have. Nothing is sent here that the machine could use: `ssh-keyscan` reads
/// the key the server offers and hangs up.
async function pin(host, port, fingerprint, path, name) {
  if (alreadyPinned(path, name, fingerprint)) return;
  const { err, lines } = await scan(host, port);
  if (lines.length === 0) {
    throw new HostKeyError("host_key_unavailable", err?.message ?? `${host}:${port} offered no host key`);
  }
  const match = lines.find((line) => knownHostsFingerprint(line) === fingerprint);
  if (!match) {
    throw new HostKeyError("host_key_mismatch", {
      expected: fingerprint,
      offered: lines.map(knownHostsFingerprint).filter(Boolean),
      hint: "the machine answering is not the one the lease names; nothing was sent to it",
    });
  }
  // Only the key that matched. Writing everything the machine offered would pin
  // keys nobody vouched for alongside the one that was checked, and the name is
  // rewritten to the one `ssh` will look the key up under.
  writeFileSync(path, `${name} ${match.trim().split(/\s+/).slice(1).join(" ")}\n`, { mode: 0o600 });
}

/// The `ssh` arguments that make the connection check the machine it reaches.
///
/// `requireHostKey` turns the unverified case into a refusal instead of a first
/// sighting, for callers who would rather not run at all than run somewhere they
/// cannot name.
export async function hostKeyArgs(target, access, { requireHostKey = false } = {}) {
  const path = knownHostsPath(target.keyPath);
  const alias = hostKeyAlias(access);
  const where = ["-o", `UserKnownHostsFile=${path}`, ...(alias ? ["-o", `HostKeyAlias=${alias}`] : [])];
  const policy = hostKeyPolicy(access);
  if (policy.fingerprint === null) {
    if (requireHostKey) {
      throw new HostKeyError("host_key_unpublished", {
        mode: access?.mode ?? null,
        hint: "this lease publishes no host key, so which machine answers cannot be checked",
      });
    }
    return [...where, "-o", "StrictHostKeyChecking=accept-new"];
  }
  await pin(target.host, target.port, policy.fingerprint, path, alias ?? hostField(target.host, target.port));
  return [...where, "-o", "StrictHostKeyChecking=yes"];
}
