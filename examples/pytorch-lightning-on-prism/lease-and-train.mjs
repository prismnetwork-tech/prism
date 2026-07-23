// Lease a Prism GPU with a wallet signature, then run a real PyTorch Lightning
// training job on it over SSH and read the result.
//
//   PRISM_AGENT_KEY=0x<agent wallet private key> \
//   PRISM_ESCROW=0x71Df0eF3bc81022cB3bec0b1a05f52f12bAfcDeD \
//   PRISM_IMAGE=<digest-pinned CUDA + PyTorch image, repo@sha256:...> \
//   node lease-and-train.mjs
//
// PRISM_IMAGE must be an immutable digest reference — Prism rejects plain tags.
// Resolve one, e.g.:
//   docker buildx imagetools inspect pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
// The wallet needs USDG and native Robinhood-Chain gas. Prism is pre-production
// and unaudited — run against a development deployment.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PrismAgent } from "@prism-network/agent-sdk";

const here = dirname(fileURLToPath(import.meta.url));
const trainScript = readFileSync(join(here, "train.py")).toString("base64");

const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: requireEnv("PRISM_ESCROW"),
});
const image = requireEnv("PRISM_IMAGE");

await agent.authenticate();

console.log("leasing a GPU for a PyTorch Lightning job (provisioning takes a few minutes)...");
const lease = await agent.lease({ image, durationSeconds: 1800, minVramMib: 16000 });
console.log("leased", lease.leaseId, "on", lease.access.ssh_host);

// Write train.py onto the box, install Lightning (torch comes from the image), and run it.
const remote = [
  `printf %s ${trainScript} | base64 -d > /tmp/train.py`,
  "python -m pip install --quiet 'lightning>=2.2'",
  "python /tmp/train.py",
].join(" && ");

console.log("running the training job...");
const result = await agent.run(lease, remote, { timeoutMs: 900_000 });
console.log(`\n--- remote output (exit ${result.code}) ---\n${result.stdout || result.stderr}`);

agent.endLease(lease);
console.log("\nlease released. Settlement and a public receipt follow on chain.");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing ${name} — see the header of this file for the required environment.`);
    process.exit(1);
  }
  return value;
}
