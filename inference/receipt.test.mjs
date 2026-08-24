import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { batchReceipt, canonicalItem, digest, leafHash, merkleProof, merkleRoot, verifyItem } from "./receipt.mjs";

const item = (index, response = "hello") => ({
  index,
  model: "llama3.2:3b",
  prompt: digest(`prompt ${index}`),
  response: digest(response),
  prompt_tokens: 5,
  completion_tokens: 7,
  lease_id: 1000 + index,
});

const sha = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

test("a leaf commits to the fields under a prefix that no interior node can reuse", () => {
  const one = item(0);
  assert.deepEqual(leafHash(one), sha(LEAF, Buffer.from(canonicalItem(one), "utf8")));
});

test("a one-item batch roots at its own leaf", () => {
  const leaves = [leafHash(item(0))];
  assert.deepEqual(merkleRoot(leaves), leaves[0]);
  assert.deepEqual(merkleProof(leaves, 0), []);
});

test("a two-item root is the pair hashed under the node prefix", () => {
  const leaves = [item(0), item(1)].map(leafHash);
  assert.deepEqual(merkleRoot(leaves), sha(NODE, leaves[0], leaves[1]));
});

test("an odd leaf is promoted, not hashed against a copy of itself", () => {
  const leaves = [item(0), item(1), item(2)].map(leafHash);
  const pair = sha(NODE, leaves[0], leaves[1]);
  assert.deepEqual(merkleRoot(leaves), sha(NODE, pair, leaves[2]));
  assert.notDeepEqual(merkleRoot(leaves), sha(NODE, pair, sha(NODE, leaves[2], leaves[2])));
});

test("every item in a batch proves its own membership without the others", () => {
  for (const count of [1, 2, 3, 5, 8, 17]) {
    const items = Array.from({ length: count }, (_, i) => item(i));
    const { receipt, proofs } = batchReceipt({ items, model: "llama3.2:3b", issuedAt: 1_700_000_000_000 });
    assert.equal(receipt.count, count);
    for (let i = 0; i < count; i += 1) {
      assert.ok(verifyItem(items[i], proofs[i], receipt.merkle_root), `item ${i} of ${count} failed`);
    }
  }
});

test("a changed response no longer proves against the root it was issued under", () => {
  const items = [item(0), item(1), item(2)];
  const { receipt, proofs } = batchReceipt({ items, model: "llama3.2:3b", issuedAt: 1_700_000_000_000 });
  const tampered = { ...items[1], response: digest("not what was served") };
  assert.equal(verifyItem(tampered, proofs[1], receipt.merkle_root), false);
});

test("an item cannot be moved to another position in the same batch", () => {
  const items = [item(0), item(1), item(2), item(3)];
  const { receipt, proofs } = batchReceipt({ items, model: "llama3.2:3b", issuedAt: 1_700_000_000_000 });
  assert.equal(verifyItem(items[2], proofs[1], receipt.merkle_root), false);
});

test("a malformed proof is refused rather than thrown out of the verifier", () => {
  const items = [item(0), item(1)];
  const { receipt } = batchReceipt({ items, model: "llama3.2:3b", issuedAt: 1_700_000_000_000 });
  assert.equal(verifyItem(items[0], [{ side: "right", hash: "sha256:zz" }], receipt.merkle_root), false);
  assert.equal(verifyItem(items[0], [], "not-a-digest"), false);
});

test("the receipt names every lease that did the work, once and in order", () => {
  const items = [
    { ...item(0), lease_id: 1042 },
    { ...item(1), lease_id: 1041 },
    { ...item(2), lease_id: 1042 },
  ];
  const { receipt } = batchReceipt({
    items,
    model: "llama3.2:3b",
    payer: "0x0000000000000000000000000000000000000001",
    paidMicros: 18_000n,
    settlement: { transaction: `0x${"ab".repeat(32)}` },
    issuedAt: 1_700_000_000_000,
  });
  assert.deepEqual(receipt.lease_ids, [1041, 1042]);
  assert.equal(receipt.paid_micros, "18000");
  assert.equal(receipt.settlement_tx, `0x${"ab".repeat(32)}`);
  assert.equal(receipt.issued_at, "2023-11-14T22:13:20.000Z");
});

test("an empty batch has nothing to commit to", () => {
  assert.throws(() => batchReceipt({ items: [], model: "llama3.2:3b", issuedAt: 1 }), /at least one leaf/);
});
