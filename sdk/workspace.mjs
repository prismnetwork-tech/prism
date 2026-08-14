// Durable storage for a renter. A lease destroys its machine, so anything worth
// keeping is archived off it, sealed here on the renter's own machine, and
// pushed to object storage as ciphertext. Prism records how large a snapshot is
// and which version it is, and holds nothing that opens it.
//
// The bulk path runs through this process rather than through the leased box on
// purpose. A presigned URL is a bearer capability with a fifteen minute life;
// handing one to a rented machine would put it in that host's process table and
// give its operator read and write on the object for the rest of the window.
import { vaultWallet } from "./vault.mjs";

const { subtle } = globalThis.crypto;

export const WORKSPACE_ENVELOPE_DOMAIN = "prism.workspace.v1\0";

// A signature over this exact string is the workspace key. It is not the vault
// statement and it does not salt the same way, so a wallet that has opened a
// vault has not opened its workspaces, and neither signature derives the other.
export const WORKSPACE_KEY_STATEMENT = [
  "Prism Network workspace key",
  "",
  "Signing this derives the key that encrypts your Prism workspaces. It is computed",
  "on this machine and never sent. Anyone who gets this signature can read every",
  "snapshot you have stored, so only sign it in software you trust.",
  "",
  "domain: prism.workspace.kdf.v1",
].join("\n");

// A workspace holds the working files a renter is already handing to a rented
// machine. The vault's default of a class no live capacity meets would mean a
// workspace could never be restored, so this one starts at the floor and is
// raised per workspace when the contents deserve it.
export const DEFAULT_WORKSPACE_TRUST_FLOOR = "open";

const TRUST_ORDER = ["open", "isolated", "attested", "confidential"];

// The protocol allows 64 GiB per snapshot. This client carries the archive over
// the lease's SSH channel and holds it in memory to seal it, so it stops well
// short of that and says so rather than dying of a failed allocation.
const MAX_TRANSFER_BYTES = 64 * 1024 * 1024;
const MAX_NAME_BYTES = 64;

// Matches the presigned URL's own life: a transfer that has not finished by
// then cannot finish at all.
const TRANSFER_TIMEOUT_MS = 900_000;
const REMOTE_TIMEOUT_MS = 900_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const encoder = new TextEncoder();

// Chunked because a large archive would otherwise spread into more arguments
// than an engine will accept in one call.
function base64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function b64url(bytes) {
  return base64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Takes both alphabets: the control plane sends base64url, and `base64` on the
// leased machine wraps standard base64 across lines.
function fromB64(value) {
  const binary = atob(value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function fromHex(value) {
  const digits = value.replace(/^0x/, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(digits)) {
    throw new WorkspaceError("invalid_signature_encoding");
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(digits.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/// Mirrors `workspace_associated_data` in prism-protocol byte for byte. A
/// shared test vector pins both; if they drift, stored snapshots stop opening.
export function workspaceAssociatedData(wallet, workspaceId, version, trustFloor) {
  return encoder.encode(
    `${WORKSPACE_ENVELOPE_DOMAIN}${wallet}\0${workspaceId}\0${version}\0${trustFloor}\0`,
  );
}

function assertTrustFloor(value) {
  if (!TRUST_ORDER.includes(value)) {
    throw new WorkspaceError("invalid_trust_floor", { expected: TRUST_ORDER });
  }
  return value;
}

function meetsFloor(floor, leaseClass) {
  return TRUST_ORDER.indexOf(leaseClass) >= TRUST_ORDER.indexOf(floor);
}

// Accepts a workspace record or a bare id. Lowercased because the Rust side
// builds the associated data from a hyphenated lowercase UUID.
function workspaceIdOf(value) {
  const id = typeof value === "string" ? value : value?.workspace_id;
  if (typeof id !== "string" || !UUID.test(id.toLowerCase())) {
    throw new WorkspaceError("invalid_workspace_id");
  }
  return id.toLowerCase();
}

// Single quotes so nothing in a caller's path reaches the remote shell as
// syntax. A path containing one has no safe quoting, so it is refused.
function quote(path) {
  if (typeof path !== "string" || path.trim() === "" || /['\n]/.test(path)) {
    throw new WorkspaceError("invalid_remote_path", {
      hint: "a path without single quotes or newlines",
    });
  }
  return `'${path}'`;
}

// HKDF over the wallet signature. Ethereum's ECDSA is deterministic (RFC 6979),
// so the same wallet reproduces the same key on any machine and a workspace
// survives a lost laptop without Prism holding an escrow copy. A passphrase,
// when given, is mixed into the salt, so a leaked signature alone is not enough.
async function deriveRootKey(signature, wallet, passphrase) {
  const material = await subtle.importKey("raw", fromHex(signature), "HKDF", false, ["deriveKey"]);
  const salt = await subtle.digest(
    "SHA-256",
    encoder.encode(`prism.workspace.kdf.v1\0${wallet}\0${passphrase ?? ""}`),
  );
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: encoder.encode("root") },
    material,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

// Per-snapshot data key, wrapped under the root. Storage holds the wrapped 40
// bytes next to the object; the root key that opens it never leaves here.
async function seal(rootKey, plaintext, aad) {
  const dataKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const [ciphertext, wrapped] = await Promise.all([
    subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, dataKey, plaintext),
    subtle.wrapKey("raw", dataKey, rootKey, "AES-KW"),
  ]);
  return {
    nonce,
    ciphertext: new Uint8Array(ciphertext),
    wrappedKey: new Uint8Array(wrapped),
  };
}

async function unseal(rootKey, wrappedKey, nonce, ciphertext, aad) {
  let dataKey;
  try {
    dataKey = await subtle.unwrapKey(
      "raw",
      wrappedKey,
      rootKey,
      "AES-KW",
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  } catch {
    throw new WorkspaceError("workspace_key_mismatch", {
      hint: "this workspace key does not open that snapshot; check the wallet and passphrase used to unlock",
    });
  }
  try {
    return new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, dataKey, ciphertext),
    );
  } catch {
    throw new WorkspaceError("workspace_authentication_failed", {
      hint: "the stored snapshot does not match the account, workspace, version and trust floor it was sealed with",
    });
  }
}

// Straight between this process and storage. The URL is never logged and never
// reported in an error, because for the next fifteen minutes it is the object.
async function transfer(url, init, code, workspaceId) {
  let res;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS) });
  } catch (err) {
    // The cause code rather than the message: a fetch failure can quote the
    // request URL back at you.
    throw new WorkspaceError(code, {
      workspace_id: workspaceId,
      cause: err?.cause?.code ?? err?.name ?? "fetch_failed",
    });
  }
  if (!res.ok) throw new WorkspaceError(code, { workspace_id: workspaceId, status: res.status });
  return res;
}

export class PrismWorkspace {
  #agent;
  #rootKey = null;
  #wallet = null;

  constructor(agent) {
    this.#agent = agent;
  }

  get unlocked() {
    return this.#rootKey !== null;
  }

  /// Derives the workspace key from a wallet signature. Nothing leaves this
  /// process; the signature itself is discarded once the key exists.
  async unlock({ passphrase = null } = {}) {
    if (!this.#agent.session) await this.#agent.authenticate();
    const wallet = vaultWallet(this.#agent.address);
    const signature = await this.#agent.signVaultStatement(WORKSPACE_KEY_STATEMENT);
    this.#rootKey = await deriveRootKey(signature, wallet, passphrase);
    this.#wallet = wallet;
    return this;
  }

  /// The wallet whose workspaces are open. One wallet, one set of workspaces,
  /// whether they are reached from a browser or from an agent.
  get wallet() {
    return this.#wallet;
  }

  lock() {
    this.#rootKey = null;
    this.#wallet = null;
  }

  /// Names, versions and sizes. The contents are ciphertext in object storage
  /// and are not part of a listing.
  async list() {
    return this.#agent.workspaceRequest("GET", []);
  }

  async get(workspaceId) {
    return this.#record(workspaceIdOf(workspaceId));
  }

  /// Creates an empty workspace. The name is stored unencrypted, like a vault
  /// label, and is the one thing a listing discloses.
  async create(name, { minTrustClass = DEFAULT_WORKSPACE_TRUST_FLOOR } = {}) {
    assertTrustFloor(minTrustClass);
    if (typeof name !== "string" || name.trim() === "" || encoder.encode(name).length > MAX_NAME_BYTES) {
      throw new WorkspaceError("invalid_workspace_name", {
        hint: `a name of 1 to ${MAX_NAME_BYTES} bytes`,
      });
    }
    return this.#agent.workspaceRequest("POST", [], {
      body: { name, min_trust_class: minTrustClass },
    });
  }

  /// Drops the workspace and every snapshot stored under it.
  async remove(workspaceId) {
    return this.#agent.workspaceRequest("DELETE", [workspaceIdOf(workspaceId)]);
  }

  /// Archives `remotePath` on the leased machine and stores it as a new
  /// version. The archive is sealed here before it is uploaded, so the object
  /// storage that serves it and the control plane that indexes it both hold
  /// ciphertext they cannot open.
  async save(lease, workspaceId, remotePath, { timeoutMs = REMOTE_TIMEOUT_MS } = {}) {
    this.#require();
    const id = workspaceIdOf(workspaceId);
    this.#requireMachine(lease);
    const archive = await this.#archive(lease, id, remotePath, timeoutMs);

    // Read rather than remembered: the floor is authenticated into the
    // ciphertext, so sealing against a stale copy of it stores a snapshot that
    // will not open.
    const floor = assertTrustFloor((await this.#record(id)).min_trust_class);
    // Storage signs the length, so the size is declared before the ciphertext
    // exists. GCM adds a 16 byte tag and nothing else.
    const grant = await this.#agent.workspaceRequest("POST", [id, "upload"], {
      body: { size_bytes: archive.length + 16 },
    });
    if (typeof grant?.url !== "string" || !Number.isInteger(grant?.version) || grant.version < 1) {
      throw new WorkspaceError("invalid_upload_grant");
    }
    const aad = workspaceAssociatedData(this.#wallet, id, grant.version, floor);
    const { nonce, ciphertext, wrappedKey } = await seal(this.#rootKey, archive, aad);
    const digest = await sha256Hex(ciphertext);

    // Signed into the URL, so it has to be sent. It makes the object
    // write-once: a stalled upload that lands after a retry has already
    // committed is refused rather than replacing bytes the metadata describes.
    await transfer(
      grant.url,
      { method: "PUT", body: ciphertext, headers: { "If-None-Match": "*" } },
      "workspace_upload_failed",
      id,
    );

    return this.#agent.workspaceRequest("POST", [id, "commit"], {
      body: {
        version: grant.version,
        wrapped_key: b64url(wrappedKey),
        nonce: b64url(nonce),
        ciphertext_digest: digest,
        size_bytes: ciphertext.length,
      },
    });
  }

  /// Fetches a snapshot, checks it hashes to what was stored, opens it here,
  /// and unpacks it into `remotePath` on the leased machine. Pass the version
  /// you last saved as `expectVersion` to refuse an older one.
  async restore(
    lease,
    workspaceId,
    remotePath,
    { expectVersion = null, expectTrustClass = null, timeoutMs = REMOTE_TIMEOUT_MS } = {},
  ) {
    this.#require();
    const id = workspaceIdOf(workspaceId);
    this.#requireMachine(lease);
    const workspace = await this.#record(id);
    if (workspace.version < 1) {
      throw new WorkspaceError("workspace_empty", { hint: "nothing has been saved here yet" });
    }
    const floor = assertTrustFloor(workspace.min_trust_class);
    if (expectTrustClass !== null && floor !== expectTrustClass) {
      throw new WorkspaceError("workspace_trust_floor_changed", {
        expected: expectTrustClass,
        served: floor,
      });
    }

    const grant = await this.#agent.workspaceRequest("POST", [id, "download"], {
      body: { lease_id: lease.leaseId },
    });
    if (typeof grant?.url !== "string" || !Number.isInteger(grant?.version)) {
      throw new WorkspaceError("invalid_download_grant");
    }
    const { url, version, ...snapshot } = grant;
    // The record said which version is current. A grant for anything else is a
    // rollback, and it decrypts cleanly because an older snapshot's associated
    // data is genuine for its own version, so nothing downstream would notice.
    if (version !== workspace.version) {
      throw new WorkspaceError("workspace_version_rollback", {
        expected: workspace.version,
        served: version,
      });
    }
    if (expectVersion !== null && version !== expectVersion) {
      throw new WorkspaceError("workspace_version_rollback", { expected: expectVersion, served: version });
    }

    const res = await transfer(url, { method: "GET" }, "workspace_download_failed", id);
    const ciphertext = new Uint8Array(await res.arrayBuffer());
    // Checked before anything is decrypted. Bytes that hash to something else
    // were altered in storage, and that deserves a clear answer rather than an
    // authentication failure that reads like a wrong key.
    const digest = await sha256Hex(ciphertext);
    if (digest !== snapshot.ciphertext_digest) {
      throw new WorkspaceError("workspace_digest_mismatch", {
        expected: snapshot.ciphertext_digest,
        computed: digest,
        expected_bytes: snapshot.size_bytes,
        served_bytes: ciphertext.length,
      });
    }

    const aad = workspaceAssociatedData(this.#wallet, id, version, floor);
    const archive = await unseal(
      this.#rootKey,
      fromB64(snapshot.wrapped_key),
      fromB64(snapshot.nonce),
      ciphertext,
      aad,
    );
    await this.#extract(lease, archive, remotePath, timeoutMs);
    return { ...workspace, version, snapshot };
  }

  /// Whether a workspace at this floor may be restored onto a lease of that
  /// trust class, without asking the control plane.
  static permits(trustFloor, leaseTrustClass) {
    return meetsFloor(assertTrustFloor(trustFloor), assertTrustFloor(leaseTrustClass));
  }

  #require() {
    if (!this.#rootKey) throw new WorkspaceError("workspace_locked", { hint: "call unlock() first" });
  }

  // The control plane lists workspaces and does not serve one on its own, so
  // this is where a single record comes from.
  async #record(id) {
    const workspaces = await this.#agent.workspaceRequest("GET", []);
    const found = workspaces?.find?.((workspace) => workspace?.workspace_id?.toLowerCase() === id);
    if (!found) throw new WorkspaceError("workspace_not_found", { workspace_id: id });
    return found;
  }

  #requireMachine(lease) {
    if (typeof this.#agent.run !== "function") {
      throw new WorkspaceError("no_lease_transport", {
        hint: "save and restore need an agent that can reach the machine over SSH",
      });
    }
    // What `run` needs. A batch lease reports its output and keeps no key, so
    // it cannot carry a workspace either way.
    if (!lease?.access?.ssh_host || !lease.keyPath) {
      throw new WorkspaceError("invalid_lease_handle", {
        hint: "the handle from an interactive lease(), which a batch lease does not produce",
      });
    }
  }

  // tar and base64 are all this needs from the machine. The archive is staged
  // to a file first so its size is known before it crosses the wire: storage
  // signs the length of the upload, and a directory too large to carry should
  // fail on the machine rather than halfway through a transfer.
  async #archive(lease, id, remotePath, timeoutMs) {
    const staged = `/tmp/prism-workspace-${id}.tar.gz`;
    const res = await this.#agent.run(
      lease,
      [
        "set -e",
        `f='${staged}'`,
        `trap 'rm -f "$f"' EXIT`,
        // tar exits 1 for "file changed as we read it" and still writes a
        // complete archive. A training job that has not stopped writing hits
        // that on almost every save, and under set -e it would throw away a
        // good snapshot. Only a fatal tar, exit 2, aborts.
        `tar -C ${quote(remotePath)} -czf "$f" . || [ "$?" -le 1 ]`,
        'n=$(wc -c < "$f")',
        `[ "$n" -le ${MAX_TRANSFER_BYTES} ] || { echo "prism_snapshot_too_large:$n" >&2; exit 3; }`,
        // Redirected rather than named: every base64 reads stdin, and not all
        // of them take a file argument.
        'base64 < "$f"',
      ].join("\n"),
      { timeoutMs },
    );
    if (res.code !== 0 || res.timedOut) {
      // Some wc implementations pad their output, so the count is not
      // necessarily flush against the marker.
      const oversize = /prism_snapshot_too_large:\s*(\d+)/.exec(res.stderr);
      if (oversize) {
        throw new WorkspaceError("workspace_snapshot_too_large", {
          bytes: Number(oversize[1]),
          limit: MAX_TRANSFER_BYTES,
        });
      }
      throw new WorkspaceError("workspace_archive_failed", {
        code: res.code,
        stderr: res.stderr,
        timed_out: res.timedOut,
      });
    }
    return fromB64(res.stdout);
  }

  // Over stdin rather than in the command, so the plaintext archive is not in
  // the machine's process table or its shell history.
  async #extract(lease, archive, remotePath, timeoutMs) {
    const path = quote(remotePath);
    const res = await this.#agent.run(
      lease,
      ["set -e", `mkdir -p ${path}`, `base64 -d | tar -C ${path} -xzf -`].join("\n"),
      { timeoutMs, stdin: base64(archive) },
    );
    if (res.code !== 0 || res.timedOut) {
      throw new WorkspaceError("workspace_extract_failed", {
        code: res.code,
        stderr: res.stderr,
        timed_out: res.timedOut,
      });
    }
  }
}

export class WorkspaceError extends Error {
  constructor(code, body) {
    super(`prism workspace: ${code}`);
    this.code = code;
    this.body = body;
  }
}
