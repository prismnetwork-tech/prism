// The batch receipt: what a caller gets back when one payment buys many
// generations spread across several rented GPUs.
//
// A batch is not one job split across machines. Every prompt runs whole on one
// box, exactly as a single request does, so nothing about how a generation is
// produced or attested changes. What the receipt adds is a commitment over the
// set: a Merkle root over one leaf per prompt, where each leaf names the model,
// the prompt and response digests, the token counts, and the lease that served
// it. Anyone holding a single item and its audit path can prove that item was
// in the batch the root commits to, without seeing any of the other prompts.
//
// The tree is the RFC 6962 construction: leaves and interior nodes are hashed
// under different prefixes, so no interior node can be replayed as a leaf, and
// an odd node is promoted to the next level rather than hashed with a copy of
// itself, which is the duplication that lets two different trees share a root.
import { createHash } from "node:crypto";

export const RECEIPT_VERSION = 1;
export const MERKLE_ALGORITHM = "rfc6962-sha256";

const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
};

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export const digest = (text) => `sha256:${sha256(Buffer.from(text, "utf8")).toString("hex")}`;

/// Field order is fixed here rather than left to whatever object a caller
/// happens to build, because the leaf hash is only reproducible if everyone
/// serialises the same bytes.
export function canonicalItem(item) {
  return JSON.stringify({
    index: item.index,
    model: item.model,
    prompt: item.prompt,
    response: item.response,
    prompt_tokens: item.prompt_tokens ?? null,
    completion_tokens: item.completion_tokens ?? null,
    lease_id: item.lease_id ?? null,
  });
}

export const leafHash = (item) => sha256(LEAF_PREFIX, Buffer.from(canonicalItem(item), "utf8"));

const nodeHash = (left, right) => sha256(NODE_PREFIX, left, right);

function levels(leaves) {
  if (!leaves.length) throw new Error("a batch receipt needs at least one leaf");
  const all = [leaves];
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    all.push(next);
    level = next;
  }
  return all;
}

export function merkleRoot(leaves) {
  const all = levels(leaves);
  return all[all.length - 1][0];
}

/// The audit path for one leaf: the sibling at each level, and which side it
/// sat on. A promoted odd node has no sibling at that level and contributes
/// nothing to the path.
export function merkleProof(leaves, index) {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new Error("no such leaf in this batch");
  }
  const path = [];
  let i = index;
  for (const level of levels(leaves)) {
    if (level.length === 1) break;
    const sibling = i % 2 === 0 ? i + 1 : i - 1;
    if (sibling < level.length) {
      path.push({ side: i % 2 === 0 ? "right" : "left", hash: `sha256:${level[sibling].toString("hex")}` });
    }
    i = Math.floor(i / 2);
  }
  return path;
}

const unhex = (value) => {
  const hex = String(value).replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error("a digest must be 32 hex bytes");
  return Buffer.from(hex, "hex");
};

/// The whole point of the root: hand this one item, its path, and the root to
/// anyone, and they can check membership without the rest of the batch.
export function verifyItem(item, path, root) {
  let node;
  try {
    node = leafHash(item);
    for (const step of path ?? []) {
      const sibling = unhex(step.hash);
      node = step.side === "left" ? nodeHash(sibling, node) : nodeHash(node, sibling);
    }
    return node.equals(unhex(root));
  } catch {
    return false;
  }
}

/// `items` are the per-prompt records in request order. The receipt names the
/// leases that did the work, and those leases settle on-chain with their own
/// public receipts, so the chain runs batch root -> item -> lease -> settlement.
export function batchReceipt({ items, model, payer = null, paidMicros = null, settlement = null, issuedAt }) {
  const leaves = items.map((item) => leafHash(item));
  const root = `sha256:${merkleRoot(leaves).toString("hex")}`;
  const leases = [...new Set(items.map((item) => item.lease_id).filter((id) => id != null))].sort((a, b) => a - b);
  return {
    receipt: {
      version: RECEIPT_VERSION,
      algorithm: MERKLE_ALGORITHM,
      model,
      count: items.length,
      merkle_root: root,
      lease_ids: leases,
      payer,
      paid_micros: paidMicros == null ? null : paidMicros.toString(),
      settlement_tx: settlement?.transaction ?? null,
      issued_at: new Date(issuedAt).toISOString(),
    },
    proofs: items.map((_, i) => merkleProof(leaves, i)),
  };
}
