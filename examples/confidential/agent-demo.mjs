// Confidential inference on Prism, start to finish, with no human in the loop:
// the agent reads the confidential catalog, pays USDG for one generation served
// from a Phala GPU TEE, then verifies the chain itself, from Intel's root down to
// a signed receipt over the exact bytes it sent and received.
//
//   PRISM_AGENT_KEY=0x<agent wallet private key> \
//   PRISM_INFERENCE_URL=https://api.prismnetwork.tech/inference \
//   node agent-demo.mjs
//
// This spends USDG on Robinhood Chain. PRISM_MAX_USDG caps what one run may pay
// (default 0.05). PRISM_DEMO_PACE sets the pause between sections in ms; set it
// to 0 to run flat out.
import { PrismAgent } from "../../sdk/prism.mjs";

const ESCROW = "0x62C042265991bEa17B07229322A01850974626dA";
const MAX_USDG = Number(process.env.PRISM_MAX_USDG ?? 0.05);
const PACE = Number(process.env.PRISM_DEMO_PACE ?? 1200);

// Fictional book, chosen because it is the kind of thing nobody wants sitting in
// a relay's logs.
const PROMPT =
  "Review this book before I size up. 40% of the fund is long SOL perps at 12x, " +
  "hedged with a three-month put spread we roll every Friday, and the rest sits " +
  "in USDG. Name the two risks that actually end this position, and what you " +
  "would change first.";

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (color ? `\x1b[${code}m${text}\x1b[0m` : text);
const dim = (text) => paint("2", text);
const green = (text) => paint("32", text);
const amber = (text) => paint("33", text);
const red = (text) => paint("31", text);

// Everything printed here fits an 80-column recording. Check details hang under
// their row at this indent.
const COLUMNS = 76;
const HANG = " ".repeat(8);

// USDG carries six decimals, and the catalog quotes micros.
const usdg = (micros) => (Number(micros) / 1e6).toFixed(6);
const amount = (value) => (typeof value === "number" ? value.toFixed(6) : String(value));

const base = requireEnv("PRISM_INFERENCE_URL").replace(/\/$/, "");
const agent = new PrismAgent({
  privateKey: requireEnv("PRISM_AGENT_KEY"),
  escrow: process.env.PRISM_ESCROW ?? ESCROW,
});
if (!Number.isFinite(MAX_USDG) || MAX_USDG <= 0) {
  exit("PRISM_MAX_USDG must be a positive number of USDG.");
}

heading("Confidential models on this endpoint");
const catalog = await json(`${base}/v1/models`);
// The confidential class is published under its own card, apart from the models
// this gateway serves on its own GPUs.
const confidential = Object.entries(catalog.confidential?.models ?? {});
if (confidential.length === 0) exit(`${base} advertises no confidential models.`);
for (const [name, rate] of confidential) {
  console.log(`  ${name}`);
  console.log(dim(`    ${usdg(rate.full_cap_micros)} USDG a call   ${rate.tee}   served by ${rate.provider}`));
  console.log(dim(`    attestation ${rate.attestation}`));
}
const model = process.env.PRISM_MODEL ?? confidential[0][0];
await pause();

// Everything checkable is checked before any money moves. From here on the SDK
// does the work, and anything it refuses to do arrives as a PrismError whose
// readable part sits in the body.
try {
  const { address, usdg: held, eth } = await agent.balances();
  if (BigInt(held) < BigInt(Math.round(MAX_USDG * 1e6))) {
    exit(`${address} holds ${usdg(held)} USDG, under the ${MAX_USDG} cap this run may spend.`);
  }
  if (BigInt(eth) === 0n) exit(`${address} has no Robinhood Chain gas.`);

  heading("Paying and running");
  console.log(dim("  prompt"));
  console.log(wrap(PROMPT));
  console.log("");
  console.log(dim(wrap("encrypted to the enclave key named in the attested keyset, so the relay carries ciphertext")));
  const run = await agent.confidentialInfer({ prompt: PROMPT, model, maxUsdg: MAX_USDG, e2ee: true, endpoint: base });
  const paid = amount(run.priceUsdg);
  console.log(dim(`  paid ${paid} USDG`));
  console.log(dim(`  tx ${run.tx}`));
  await pause();

  heading("Answer");
  console.log(wrap(String(run.content ?? "").trim()));
  console.log(
    dim(
      `\n  ${run.usage?.prompt_tokens ?? "?"} tokens in, ${run.usage?.completion_tokens ?? "?"} out` +
        `   receipt ${run.receiptId}`,
    ),
  );
  await pause();

  heading("What the agent checked");
  const verification = await run.verify();
  const checks = verification.checks ?? [];
  for (const check of checks) {
    console.log(`  ${status(check.status)}  ${wrap(check.title ?? check.id, COLUMNS, HANG).trimStart()}`);
    const detail = String(check.detail ?? "").trim();
    if (detail) console.log(dim(wrap(detail, COLUMNS, HANG)));
  }
  await pause();

  console.log("\n  measured source");
  console.log(dim(wrap(verification.provenance ?? "the verifier reported none", COLUMNS, HANG)));
  console.log(`  verdict ${verdict(verification.verdict)}   total cost ${paid} USDG`);
  if (verification.verdict === "failed") {
    const failed = checks.filter((check) => check.status === "fail").map((check) => check.id);
    exit(`verification failed: ${failed.join(", ") || "the verifier named no failing check"}`);
  }
  if (verification.verdict === "incomplete") {
    const missing = checks.filter((check) => check.status === "skip").map((check) => check.id);
    console.log(dim(wrap(`no check failed. These had no evidence to run against: ${missing.join(", ")}`)));
  }
} catch (err) {
  const cause = err.body?.cause;
  exit(err.body?.hint ?? (typeof cause === "string" ? cause : cause?.message) ?? err.message);
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) exit(`missing ${name}. The header of this file lists the environment this run needs.`);
  return value;
}

async function json(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) exit(`${url} answered ${res.status}`);
  return res.json();
}

function exit(message) {
  console.error(`\n${message}`);
  process.exit(1);
}

function heading(text) {
  console.log(`\n${paint("1", text)}`);
}

function status(value) {
  if (value === "pass") return green("pass");
  if (value === "fail") return red("fail");
  return dim("skip");
}

// `incomplete` means a check had no evidence to run against. That gets its own
// colour: nothing failed.
function verdict(value) {
  if (value === "verified") return green("verified");
  if (value === "incomplete") return amber("incomplete");
  return red(value ?? "unreported");
}

function wrap(text, columns = COLUMNS, indent = "  ") {
  const width = Math.max(24, columns - indent.length);
  const lines = [];
  let line = "";
  for (const word of String(text).split(/\s+/).flatMap((w) => cut(w, width))) {
    if (!word) continue;
    if (line && line.length + word.length + 1 > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => `${indent}${l}`).join("\n");
}

// A 64-character digest is one word, and no line break falls inside it.
function cut(word, width) {
  const parts = [];
  for (let i = 0; i < word.length; i += width) parts.push(word.slice(i, i + width));
  return parts.length ? parts : [word];
}

function pause() {
  return PACE > 0 ? new Promise((resolve) => setTimeout(resolve, PACE)) : Promise.resolve();
}
