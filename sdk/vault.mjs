// Renter-held storage. Everything in this file runs on the renter's machine:
// the vault key is derived here, items are sealed here, and only ciphertext is
// handed to Prism. There is no code path that sends a key anywhere, which is
// the entire reason an agent can keep a card or an identity document in a
// service it does not trust.
//
// Runs unchanged in Node and in the browser, so an agent and the person who
// owns it seal items identically. Two implementations would be two chances to
// disagree, and disagreeing here means a vault that will not open.
const { subtle } = globalThis.crypto;

export const VAULT_ENVELOPE_DOMAIN = "prism.vault.v1\0";

// A signature over this exact string is the vault key. Nothing else Prism ever
// asks a wallet to sign resembles it, and no other message derives the same
// key, so approving a lease cannot hand anyone the vault.
export const VAULT_KEY_STATEMENT = [
  "Prism Network vault key",
  "",
  "Signing this derives the key that encrypts your Prism vault. It is computed on",
  "this machine and never sent. Anyone who gets this signature can read every item",
  "in the vault, so only sign it in software you trust.",
  "",
  "domain: prism.vault.kdf.v1",
].join("\n");

// New items are sealed against every trust class the network can serve today.
// Storing and reading back is unaffected; only handing an item to a rented box
// is blocked, and that is the operation worth blocking by default.
export const DEFAULT_TRUST_FLOOR = "confidential";

const TRUST_ORDER = ["open", "isolated", "attested", "confidential"];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Chunked because a 160 KiB item would otherwise spread into more arguments
// than an engine will accept in one call.
function b64url(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(value) {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function fromHex(value) {
  const digits = value.replace(/^0x/, "");
  if (digits.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(digits)) {
    throw new VaultError("invalid_signature_encoding");
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(digits.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/// The wallet address, lowercased. Casing varies by source: a checksummed
/// address from one wallet and a lowercase one from another must not derive
/// two different keys for the same vault.
export function vaultWallet(address) {
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new VaultError("invalid_wallet_address", { address });
  }
  return address.toLowerCase();
}

/// Mirrors `vault_associated_data` in prism-protocol byte for byte. A shared
/// test vector pins both; if they drift, stored items stop opening.
export function associatedData(wallet, itemId, version, trustFloor) {
  return encoder.encode(
    `${VAULT_ENVELOPE_DOMAIN}${wallet}\0${itemId}\0${version}\0${trustFloor}\0`,
  );
}

function assertTrustFloor(value) {
  if (!TRUST_ORDER.includes(value)) {
    throw new VaultError("invalid_trust_floor", { expected: TRUST_ORDER });
  }
  return value;
}

function meetsFloor(floor, leaseClass) {
  return TRUST_ORDER.indexOf(leaseClass) >= TRUST_ORDER.indexOf(floor);
}

// HKDF over the wallet signature. Ethereum's ECDSA is deterministic (RFC 6979),
// so the same wallet and message reproduce the same key on any machine: the
// vault survives a lost laptop without Prism holding an escrow copy. A
// passphrase, when given, is mixed into the salt, so a leaked signature alone
// is not enough to open the vault.
async function deriveRootKey(signature, wallet, passphrase) {
  const material = await subtle.importKey("raw", fromHex(signature), "HKDF", false, ["deriveKey"]);
  const salt = await subtle.digest(
    "SHA-256",
    encoder.encode(`prism.vault.kdf.v1\0${wallet}\0${passphrase ?? ""}`),
  );
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt), info: encoder.encode("root") },
    material,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

async function gcm(usages) {
  return subtle.generateKey({ name: "AES-GCM", length: 256 }, true, usages);
}

// Per-item data key, wrapped under the root. The indirection is what makes
// re-keying cheap: changing the wallet or passphrase rewraps 40 bytes per item
// instead of re-encrypting every card and passport in the vault.
async function seal(rootKey, plaintext, aad) {
  const dataKey = await gcm(["encrypt", "decrypt"]);
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
    throw new VaultError("vault_key_mismatch", {
      hint: "this vault key does not open that item; check the wallet and passphrase used to unlock",
    });
  }
  try {
    return new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, dataKey, ciphertext),
    );
  } catch {
    throw new VaultError("vault_authentication_failed", {
      hint: "the stored item does not match the account, slot, version and trust floor it was sealed with",
    });
  }
}

export class PrismVault {
  #agent;
  #rootKey = null;
  #wallet = null;

  constructor(agent) {
    this.#agent = agent;
  }

  get unlocked() {
    return this.#rootKey !== null;
  }

  /// Derives the vault key from a wallet signature. Nothing leaves this
  /// process; the signature itself is discarded once the key exists.
  async unlock({ passphrase = null } = {}) {
    if (!this.#agent.session) await this.#agent.authenticate();
    const wallet = vaultWallet(this.#agent.address);
    const signature = await this.#agent.signVaultStatement(VAULT_KEY_STATEMENT);
    this.#rootKey = await deriveRootKey(signature, wallet, passphrase);
    this.#wallet = wallet;
    return this;
  }

  /// The wallet whose vault is open. One wallet, one vault, whether it is
  /// reached from a browser or from an agent.
  get wallet() {
    return this.#wallet;
  }

  lock() {
    this.#rootKey = null;
    this.#wallet = null;
  }

  #require() {
    if (!this.#rootKey) throw new VaultError("vault_locked", { hint: "call unlock() first" });
  }

  /// Item ids and trust floors only. Names live inside the ciphertext unless
  /// the caller passed a label, so a listing does not disclose what is stored.
  async list() {
    return this.#agent.vaultRequest("GET", ["items"]);
  }

  async releases() {
    return this.#agent.vaultRequest("GET", ["releases"]);
  }

  /// Seals `value` and stores it. Pass the item returned by a previous put or
  /// get as `replaces` to update it; omitting that creates a new item and
  /// fails rather than overwriting an existing one.
  async put(value, { itemId = null, replaces = null, trustFloor = DEFAULT_TRUST_FLOOR, label = "" } = {}) {
    this.#require();
    assertTrustFloor(trustFloor);
    const id = replaces?.item_id ?? itemId ?? globalThis.crypto.randomUUID();
    const version = replaces ? replaces.version + 1 : 1;
    const plaintext = encoder.encode(typeof value === "string" ? value : JSON.stringify(value));
    const aad = associatedData(this.#wallet, id, version, trustFloor);
    const { nonce, ciphertext, wrappedKey } = await seal(this.#rootKey, plaintext, aad);
    return this.#agent.vaultRequest("PUT", ["items", id], {
      body: {
        envelope: {
          wrapped_key: b64url(wrappedKey),
          nonce: b64url(nonce),
          ciphertext: b64url(ciphertext),
        },
        min_trust_class: trustFloor,
        label,
        ...(replaces ? { previous_version: replaces.version } : {}),
      },
    });
  }

  /// Fetches and opens an item. Throws if the service returned anything other
  /// than what this account sealed into that slot at that version.
  async get(itemId, { json = false } = {}) {
    this.#require();
    const item = await this.#agent.vaultRequest("GET", ["items", itemId]);
    const value = await this.open(item);
    return json ? JSON.parse(value) : value;
  }

  /// Opens an item you already hold. Separate from `get` so a caller can pin a
  /// version they recorded earlier and detect being served an older copy.
  async open(item, { expectVersion = null } = {}) {
    this.#require();
    if (expectVersion !== null && item.version !== expectVersion) {
      throw new VaultError("vault_version_rollback", {
        expected: expectVersion,
        served: item.version,
      });
    }
    const aad = associatedData(
      this.#wallet,
      item.item_id,
      item.version,
      item.min_trust_class,
    );
    const plaintext = await unseal(
      this.#rootKey,
      fromB64url(item.envelope.wrapped_key),
      fromB64url(item.envelope.nonce),
      fromB64url(item.envelope.ciphertext),
      aad,
    );
    return decoder.decode(plaintext);
  }

  async remove(itemId) {
    return this.#agent.vaultRequest("DELETE", ["items", itemId]);
  }

  /// Authorizes an item into a running lease and returns its plaintext. The
  /// control plane refuses when the lease's trust class is below the floor the
  /// item was sealed with, so an agent cannot post its owner's card to a host
  /// that can read it by getting a policy check wrong.
  async releaseInto(lease, itemId, { json = false } = {}) {
    this.#require();
    const leaseId = lease?.leaseId ?? lease?.lease_id ?? lease;
    if (!Number.isInteger(leaseId)) throw new VaultError("invalid_lease_handle");
    const item = await this.#agent.vaultRequest("GET", ["items", itemId]);
    await this.#agent.vaultRequest("POST", ["items", itemId, "release"], {
      body: { lease_id: leaseId },
    });
    const value = await this.open(item);
    return json ? JSON.parse(value) : value;
  }

  /// Whether `releaseInto` would be allowed, without recording a release.
  /// Useful for an agent choosing capacity before it commits to a lease.
  static permits(trustFloor, leaseTrustClass) {
    return meetsFloor(assertTrustFloor(trustFloor), assertTrustFloor(leaseTrustClass));
  }
}

export class VaultError extends Error {
  constructor(code, body) {
    super(`prism vault: ${code}`);
    this.code = code;
    this.body = body;
  }
}
