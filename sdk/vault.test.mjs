import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { test } from "node:test";

import {
  DEFAULT_TRUST_FLOOR,
  PrismVault,
  VAULT_KEY_STATEMENT,
  VaultError,
  associatedData,
} from "./vault.mjs";

// Stands in for the control plane: it stores exactly what a real deployment
// stores, so a test that reads a secret out of `items` proves the service could
// have read it too.
class FakeService {
  constructor() {
    this.items = new Map();
    this.releases = [];
    this.leases = new Map();
    this.sent = [];
  }

  request(method, segments, { body = null } = {}) {
    this.sent.push({ method, segments, body });
    const [collection, id, action] = segments;
    if (collection === "releases") return [...this.releases];
    if (collection !== "items") throw new Error(`unexpected route ${segments.join("/")}`);
    if (method === "GET" && !id) return [...this.items.values()];
    if (method === "GET") {
      const item = this.items.get(id);
      if (!item) throw new VaultError("vault_item_not_found");
      return item;
    }
    if (method === "PUT") return this.#put(id, body);
    if (method === "DELETE") {
      this.items.delete(id);
      return null;
    }
    if (method === "POST" && action === "release") return this.#release(id, body.lease_id);
    throw new Error(`unexpected ${method} ${segments.join("/")}`);
  }

  #put(id, body) {
    const existing = this.items.get(id);
    if (existing && body.previous_version !== existing.version) {
      throw new VaultError("vault_version_conflict");
    }
    const item = {
      item_id: id,
      version: body.previous_version ? body.previous_version + 1 : 1,
      envelope: body.envelope,
      min_trust_class: body.min_trust_class,
      label: body.label,
    };
    this.items.set(id, item);
    return item;
  }

  #release(id, leaseId) {
    const item = this.items.get(id);
    const order = ["open", "isolated", "attested", "confidential"];
    const leaseClass = this.leases.get(leaseId);
    if (!leaseClass) throw new VaultError("vault_lease_unavailable");
    if (order.indexOf(leaseClass) < order.indexOf(item.min_trust_class)) {
      throw new VaultError("vault_trust_floor_unmet");
    }
    const release = { item_id: id, lease_id: leaseId, lease_trust_class: leaseClass };
    this.releases.push(release);
    return release;
  }
}

// A deterministic stand-in for a wallet. Real secp256k1 signing is deterministic
// per RFC 6979, which is what lets the same wallet re-derive the same vault key.
function fakeAgent(service, { address = "0xabc0000000000000000000000000000000000001" } = {}) {
  return {
    address,
    session: "session",
    async authenticate() {},
    async signVaultStatement(statement) {
      const digest = await webcrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`${address}\0${statement}`),
      );
      return `0x${Buffer.from(digest).toString("hex")}`;
    },
    async vaultRequest(method, segments, options) {
      return service.request(method, segments, options);
    },
  };
}

async function unlockedVault(service, options) {
  return new PrismVault(fakeAgent(service, options)).unlock();
}

test("the service never receives the plaintext or anything that reveals it", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const card = "4111111111111111|09/29|Mizuki Hayashi";

  const stored = await vault.put(card, { label: "primary card" });

  const onTheWire = JSON.stringify(service.sent);
  assert.ok(!onTheWire.includes(card), "the card reached the service in the clear");
  assert.ok(!onTheWire.includes("4111"), "part of the card reached the service");
  assert.ok(!onTheWire.includes("Mizuki"), "the cardholder reached the service");

  const held = JSON.stringify([...service.items.values()]);
  assert.ok(!held.includes("4111"), "the service is storing readable card data");
  // Only what the renter chose to make listable is legible.
  assert.equal(stored.label, "primary card");
  assert.equal(await vault.get(stored.item_id), card);
});

test("a different wallet cannot open another wallet's item", async () => {
  const service = new FakeService();
  const owner = await unlockedVault(service);
  const stored = await owner.put("passport MZ8817264");

  const intruder = await unlockedVault(service, {
    address: "0xdef0000000000000000000000000000000000002",
  });
  await assert.rejects(() => intruder.get(stored.item_id), (err) => {
    assert.ok(err instanceof VaultError);
    assert.equal(err.code, "vault_key_mismatch");
    return true;
  });
});

test("a passphrase is required to reopen an item stored with one", async () => {
  const service = new FakeService();
  const guarded = new PrismVault(fakeAgent(service));
  await guarded.unlock({ passphrase: "correct horse" });
  const stored = await guarded.put("seed phrase");

  assert.equal(await guarded.get(stored.item_id), "seed phrase");

  const withoutPassphrase = await unlockedVault(service);
  await assert.rejects(() => withoutPassphrase.get(stored.item_id), /vault_key_mismatch/);

  const wrongPassphrase = new PrismVault(fakeAgent(service));
  await wrongPassphrase.unlock({ passphrase: "wrong horse" });
  await assert.rejects(() => wrongPassphrase.get(stored.item_id), /vault_key_mismatch/);
});

test("the same wallet re-derives the same vault on another machine", async () => {
  const service = new FakeService();
  const stored = await (await unlockedVault(service)).put("recovery code 7781");

  // A fresh client with no local state, the wallet being the only input.
  const elsewhere = await unlockedVault(service);
  assert.equal(await elsewhere.get(stored.item_id), "recovery code 7781");
});

test("moving an item into another account's slot makes it unreadable, not misread", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const stored = await vault.put("bank token");

  const smuggled = { ...stored, item_id: webcrypto.randomUUID() };
  await assert.rejects(() => vault.open(smuggled), /vault_authentication_failed/);
});

test("a downgraded trust floor breaks the seal instead of leaking the item", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const stored = await vault.put("api key", { trustFloor: "confidential" });

  // What a compromised control plane would do to get an item into a host it
  // controls: rewrite the policy field and serve it back.
  const tampered = { ...stored, min_trust_class: "open" };
  await assert.rejects(() => vault.open(tampered), /vault_authentication_failed/);
});

test("being served a superseded version is detectable", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const first = await vault.put("old address");
  const second = await vault.put("new address", { replaces: first });

  assert.equal(second.version, 2);
  assert.equal(await vault.open(second, { expectVersion: 2 }), "new address");
  await assert.rejects(
    () => vault.open(first, { expectVersion: 2 }),
    /vault_version_rollback/,
  );
});

test("an item defaults to a floor no live capacity can clear", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const stored = await vault.put("identity document");

  assert.equal(stored.min_trust_class, DEFAULT_TRUST_FLOOR);
  service.leases.set(9, "open");
  await assert.rejects(() => vault.releaseInto(9, stored.item_id), /vault_trust_floor_unmet/);
  assert.deepEqual(service.releases, []);
});

test("a release into qualifying capacity returns the plaintext and is recorded", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const stored = await vault.put({ token: "hf_live_9912" }, { trustFloor: "isolated" });
  service.leases.set(9, "attested");

  const value = await vault.releaseInto({ leaseId: 9 }, stored.item_id, { json: true });

  assert.deepEqual(value, { token: "hf_live_9912" });
  assert.equal(service.releases.length, 1);
  assert.equal(service.releases[0].lease_trust_class, "attested");
});

test("locking discards the key", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);
  const stored = await vault.put("secret");

  assert.equal(vault.unlocked, true);
  vault.lock();
  assert.equal(vault.unlocked, false);
  await assert.rejects(() => vault.get(stored.item_id), /vault_locked/);
  await assert.rejects(() => vault.put("another"), /vault_locked/);
});

test("an unknown trust floor is refused rather than coerced", async () => {
  const service = new FakeService();
  const vault = await unlockedVault(service);

  await assert.rejects(() => vault.put("x", { trustFloor: "private" }), /invalid_trust_floor/);
  assert.throws(() => PrismVault.permits("open", "sgx"), /invalid_trust_floor/);
  assert.equal(PrismVault.permits("isolated", "attested"), true);
  assert.equal(PrismVault.permits("attested", "isolated"), false);
});

// Pinned against the identical vector in prism-protocol's Rust test. These two
// implementations must agree byte for byte or every stored item stops opening.
test("associated data matches the protocol vector", () => {
  const aad = associatedData(
    "did:privy:cm123",
    "018f3a2b-4c5d-7e8f-9012-3456789abcde",
    7,
    "confidential",
  );

  assert.equal(
    Buffer.from(aad).toString("binary"),
    // Explicit \u0000 escapes: "\0" before a digit is an octal escape, which
    // would quietly change the vector.
    "prism.vault.v1\u0000did:privy:cm123\u0000018f3a2b-4c5d-7e8f-9012-3456789abcde\u00007\u0000confidential\u0000",
  );
});

test("the key statement names its domain and warns what signing it grants", () => {
  assert.match(VAULT_KEY_STATEMENT, /prism\.vault\.kdf\.v1/);
  assert.match(VAULT_KEY_STATEMENT, /never sent/);
});
