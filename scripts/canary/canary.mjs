// Capped mainnet canary: fund one reviewed GPU quote, verify nvidia-smi over
// SSH, then leave settlement, proof publication and provider cleanup to the
// independently monitored production workers.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";

import { fundedFailure, readCanaryConfig, reviewQuote, selectManagedOffer } from "./config.mjs";

let config;
try {
  config = readCanaryConfig();
} catch (err) {
  abort(err.message);
}

const {
  duration: DURATION,
  maxUsdg: MAX_USDG,
  minVram: MIN_VRAM,
  node: NODE,
  image: IMAGE,
  capMicros,
} = config;
const TX = "https://robinhoodchain.blockscout.com/tx/";

if (process.argv.includes("--dry-run")) {
  log(`canary configuration OK: ${MIN_VRAM} MiB for ${DURATION}s, capped at ${MAX_USDG} USDG`);
  log("dry run complete: no wallet, network, or transaction used");
  process.exit(0);
}

const { DEFAULT_IMAGE, PrismAgent } = await import("@prismnetwork/agent-sdk");
const agent = new PrismAgent({
  privateKey: env("PRISM_AGENT_KEY"),
  escrow: env("PRISM_ESCROW"),
  apiBase: process.env.PRISM_API_BASE || undefined,
  rpcUrl: process.env.PRISM_RPC_URL || undefined,
});

const { subject } = await agent.authenticate();
log(`authenticated ${subject} (${agent.address})`);

const { usdg, eth } = await agent.balances();
log(`balance ${Number(usdg) / 1e6} USDG · ${Number(eth) / 1e18} ETH gas`);
if (BigInt(usdg) < BigInt(capMicros)) abort(`USDG below the ${MAX_USDG} cap; top up ${agent.address}`);
if (BigInt(eth) === 0n) abort(`no gas on ${agent.address}`);

const offers = await agent.offers();
if (!offers.length) abort("no GPU offers online");
log(`${offers.length} offer(s): ${offers.map((offer) => offer.gpu?.model || "unknown").join(", ")}`);
const selectedOffer = selectManagedOffer(offers, { minVramMib: MIN_VRAM, preferredNodeId: NODE });

const leaseRequest = {
  image: IMAGE || DEFAULT_IMAGE,
  durationSeconds: DURATION,
  minVramMib: MIN_VRAM,
  preferredNodeId: selectedOffer.node_id,
};
const quote = await agent.quote(leaseRequest);
const reviewed = reviewQuote(quote, leaseRequest, capMicros);
log(`quote id: ${quote.quote_id}`);
log(`cost: ${formatUsdg(reviewed.maximumEscrow)} USDG on Robinhood Chain (4663); hard cap ${MAX_USDG} USDG`);
log(`executor: managed Vast · duration: ${DURATION}s · min VRAM: ${MIN_VRAM} MiB · trust: ${quote.trust_class}`);
log(`image: ${leaseRequest.image}`);
log(`node: ${quote.node_id} · rate: ${reviewed.rate} micro-USDG/s · expires: ${quote.expires_at}`);

if (process.env.CANARY_CONFIRM === "prompt") {
  await confirmQuote(quote.quote_id);
} else if (process.env.CANARY_CONFIRM !== "1") {
  log("\npreflight OK. Set CANARY_CONFIRM=1 for a pre-authorized run, or use prompt for this exact quote.");
  process.exit(0);
}

if (Date.parse(quote.expires_at) <= Date.now() + 60_000) {
  abort("reviewed quote expires too soon to fund safely; request a new quote");
}

const key = generateSshKey();
let lease;
let fundingHash = null;
let leaseId = null;
let failure;
try {
  log(`funding reviewed quote ${quote.quote_id}...`);
  const funded = await agent.fund(quote);
  fundingHash = funded.hash;
  log(`funded on-chain: ${TX}${fundingHash}`);

  const record = await agent.confirm({
    quoteId: quote.quote_id,
    transactionHash: fundingHash,
    sshAuthorizedKey: key.publicKey,
  });
  if (!Number.isSafeInteger(record?.lease_id)) throw new Error("confirm returned no valid lease id");
  leaseId = record.lease_id;
  log(`lease id: ${leaseId}`);

  const access = await agent.waitForAccess(leaseId);
  lease = {
    leaseId,
    access,
    keyPath: key.keyPath,
    keyDir: key.dir,
    publicKey: key.publicKey,
    fundingHash,
    quote,
  };
  log(`access mode: ${access.mode || "direct_ssh"}`);

  // A machine is handed over when its port is allocated, not when sshd inside
  // it has finished starting, so the first probe of a healthy lease can be
  // refused. That warmup is not a failure; a real fault is still refused two
  // minutes in.
  const deadline = Date.now() + 120_000;
  let smi;
  for (;;) {
    smi = await agent.run(
      lease,
      "nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader",
    );
    if (smi.code === 0) break;
    const text = `${smi.stderr || ""}${smi.stdout || ""}`;
    const warming = /Connection refused|Connection reset|Connection timed out|Connection closed by remote host/i.test(text);
    if (!warming || Date.now() >= deadline) {
      throw new Error(`nvidia-smi exited ${smi.code}: ${smi.stderr || smi.stdout}`);
    }
    log("ssh not up yet; retrying");
    await new Promise((resolve) => setTimeout(resolve, 10_000));
  }
  log(`GPU verified: ${smi.stdout}`);
} catch (err) {
  failure = err;
  const evidence = fundedFailure(err);
  fundingHash ||= evidence.fundingHash;
  leaseId ??= evidence.leaseId;
  if (fundingHash) log(`funding tx retained after failure: ${TX}${fundingHash}`);
  if (leaseId !== null) log(`lease id retained after failure: ${leaseId}`);
} finally {
  agent.endLease(lease || { keyDir: key.dir });
}

if (failure) abort(failure.message);

log("");
log("execution canary OK; settlement, proof publication, and provider destruction are still pending.");
log(`funding tx: ${TX}${fundingHash}`);
log(`lease id:   ${leaseId}`);
log("settlement is proposed after the lease window; finalization unlocks after the dispute window.");

async function confirmQuote(quoteId) {
  const input = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await input.question(`type CONFIRM ${quoteId} to fund this exact quote: `);
  input.close();
  if (answer.trim() !== `CONFIRM ${quoteId}`) abort("exact quote was not confirmed");
}

function generateSshKey() {
  const dir = mkdtempSync(join(tmpdir(), "prism-canary-"));
  const keyPath = join(dir, "id_ed25519");
  try {
    execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-q", "-f", keyPath, "-C", "prism-canary"]);
    return { dir, keyPath, publicKey: readFileSync(`${keyPath}.pub`, "utf8").trim() };
  } catch (err) {
    agent.endLease({ keyDir: dir });
    throw err;
  }
}

function env(name) {
  const value = process.env[name];
  if (!value) abort(`missing ${name}`);
  return value;
}

function formatUsdg(micros) {
  const whole = micros / 1_000_000n;
  const fraction = (micros % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function log(...args) {
  console.log(...args);
}

function abort(message) {
  console.error(`canary aborted: ${message}`);
  process.exit(1);
}
