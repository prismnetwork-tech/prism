// An agent that rents a Prism GPU to research Robinhood Chain stock tokens,
// then executes the trade it picks on Uniswap v4, all on chain id 4663.
//
//   node agent.mjs                # research locally, print the decision (free)
//   PRISM_AGENT_KEY=0x... \
//   PRISM_IMAGE=<cuda+torch image digest> \
//   node agent.mjs --gpu          # run the analysis on a rented Prism GPU
//   ... EXECUTE=1 node agent.mjs --gpu   # and place the chosen swap on-chain
//
// What it does, end to end:
//   1. Reads real market state: Chainlink stock feeds (price history), Uniswap
//      v4 pool spot, the USDG/USD feed, and the Robinhood Earn (Morpho
//      steakUSDG) share rate, printed for context.
//   2. Ships the dataset to a GPU it leases on Prism (paid on-chain in USDG)
//      and runs a Monte Carlo momentum study there (gpu_job.py).
//   3. If the best token's expected edge clears trading costs with better than
//      even odds, and its pool price agrees with the oracle, swaps SPEND_USDG
//      (default 2) into it through the Universal Router.
//
// EXECUTE=1 without --gpu trades on the downscaled local study; the agent says
// so when it does. Needs Node 20+. Environment variables are documented in
// README.md.
//
// Stock tokens are ERC-20s on Robinhood Chain; check your own eligibility to
// hold them. Prism is pre-production and unaudited. Keys used here should hold
// only what you are prepared to lose.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeAbiParameters,
  http,
  keccak256,
  parseAbi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { PrismAgent } from "@prismnetwork/agent-sdk";

const RPC = process.env.PRISM_RPC_URL ?? "https://rpc.mainnet.chain.robinhood.com";
const USDG = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
const STATE_VIEW = "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b";
const UNIVERSAL_ROUTER = "0x8876789976decbfcbbbe364623c63652db8c0904";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const STEAK_USDG = "0xBeEff033F34C046626B8D0A041844C5d1A5409dd";
const USDG_FEED = "0x61B7e5650328764B076A108EFF5fa7282a1B9aD2";
const ZERO = "0x0000000000000000000000000000000000000000";

// Stock tokens with a live USDG pool at the 0.3% fee tier and a Chainlink feed
// on Robinhood Chain. Addresses from docs.robinhood.com/chain and the Chainlink
// feed directory.
const TOKENS = {
  NVDA: { token: "0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC", feed: "0x379EC4f7C378F34a1B47E4F3cbeBCbAC3E8E9F15" },
  AAPL: { token: "0xaF3D76f1834A1d425780943C99Ea8A608f8a93f9", feed: "0x6B22A786bAa607d76728168703a39Ea9C99f2cD0" },
  TSLA: { token: "0x322F0929c4625eD5bAd873c95208D54E1c003b2d", feed: "0x4A1166a659A55625345e9515b32adECea5547C38" },
  SPY: { token: "0x117cc2133c37B721F49dE2A7a74833232B3B4C0C", feed: "0x319724394D3A0e3669269846abE664Cd621f9f6A" },
};
const FEE = 3000;
const TICK_SPACING = 60;
const HISTORY_ROUNDS = 400;
const SPEND_USDG = Number(process.env.SPEND_USDG ?? 2);
const SLIPPAGE_BPS = 100n;
// A pool this far from the oracle means a wrong pool, a stale feed, or a
// market dislocated enough that a momentum toy has no business trading it.
const BASIS_LIMIT_BPS = 300;
// A fifth of the rounds missing skews the return distribution enough to
// change the ranking.
const DROPPED_LIMIT = 0.2;

const robinhoodChain = defineChain({
  id: 4663,
  name: "Robinhood Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});

const feedAbi = parseAbi([
  "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
  "function getRoundData(uint80) view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
]);
const stateViewAbi = parseAbi([
  "function getSlot0(bytes32) view returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)",
]);
const erc20Abi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function allowance(address,address) view returns (uint256)",
  "function decimals() view returns (uint8)",
]);
const vaultAbi = parseAbi(["function convertToAssets(uint256) view returns (uint256)"]);
const permit2Abi = parseAbi([
  "function approve(address token, address spender, uint160 amount, uint48 expiration)",
  "function allowance(address, address, address) view returns (uint160 amount, uint48 expiration, uint48 nonce)",
]);
const routerAbi = parseAbi(["function execute(bytes commands, bytes[] inputs, uint256 deadline) payable"]);

const client = createPublicClient({ chain: robinhoodChain, transport: http(RPC) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function poolKey(token) {
  const [c0, c1] = USDG.toLowerCase() < token.toLowerCase() ? [USDG, token] : [token, USDG];
  return { currency0: c0, currency1: c1, fee: FEE, tickSpacing: TICK_SPACING, hooks: ZERO };
}

function poolId(key) {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "address" }, { type: "uint24" }, { type: "int24" }, { type: "address" }],
      [key.currency0, key.currency1, key.fee, key.tickSpacing, key.hooks],
    ),
  );
}

// Pool price of one whole stock token in USDG, from slot0. USDG has 6 decimals
// and stock tokens 18, so the raw ratio is rescaled by 1e12.
function tokenPriceUsdg(sqrtPriceX96, usdgIsCurrency0) {
  const ratio = (Number(sqrtPriceX96) / 2 ** 96) ** 2;
  const price = usdgIsCurrency0 ? 1e12 / ratio : ratio * 1e12;
  if (!Number.isFinite(price) || price <= 0) {
    throw new Error("the pool returned no usable price; it may be uninitialized");
  }
  return price;
}

async function readPoolPrice(token) {
  const key = poolKey(token);
  const [sqrtPriceX96] = await client.readContract({
    address: STATE_VIEW,
    abi: stateViewAbi,
    functionName: "getSlot0",
    args: [poolId(key)],
  });
  return tokenPriceUsdg(sqrtPriceX96, key.currency0.toLowerCase() === USDG.toLowerCase());
}

async function feedHistory(feed, rounds) {
  const [latestId, answer, , updatedAt] = await client.readContract({
    address: feed,
    abi: feedAbi,
    functionName: "latestRoundData",
  });
  if (answer <= 0n) throw new Error("the feed's latest round has no valid answer");
  const phase = latestId >> 64n;
  const aggRound = latestId & ((1n << 64n) - 1n);
  const span = aggRound - 1n < BigInt(rounds) ? aggRound - 1n : BigInt(rounds);
  const ids = [];
  for (let back = span; back >= 1n; back--) ids.push((phase << 64n) | (aggRound - back));

  // Small batches with a retry pass: the default public RPC rate-limits, and a
  // silently thinned history would change the study without saying so.
  const rows = new Map();
  const read = async (pending) => {
    const failed = [];
    for (let i = 0; i < pending.length; i += 10) {
      const chunk = pending.slice(i, i + 10);
      const results = await Promise.all(
        chunk.map((id) =>
          client
            .readContract({ address: feed, abi: feedAbi, functionName: "getRoundData", args: [id] })
            .catch(() => null),
        ),
      );
      results.forEach((row, j) => {
        if (row && row[1] > 0n) rows.set(chunk[j], { t: Number(row[3]), price: Number(row[1]) / 1e8 });
        else failed.push(chunk[j]);
      });
    }
    return failed;
  };
  let failed = await read(ids);
  if (failed.length) {
    await sleep(2_000);
    failed = await read(failed);
  }
  const history = ids.filter((id) => rows.has(id)).map((id) => rows.get(id));
  history.push({ t: Number(updatedAt), price: Number(answer) / 1e8 });
  return { history, dropped: failed.length, updatedAt: Number(updatedAt) };
}

async function gatherMarketData() {
  console.log("reading Robinhood Chain: Chainlink feeds, Uniswap v4 pools, Robinhood Earn vault...");
  const [usdgRound, earnRate] = await Promise.all([
    client.readContract({ address: USDG_FEED, abi: feedAbi, functionName: "latestRoundData" }),
    client.readContract({ address: STEAK_USDG, abi: vaultAbi, functionName: "convertToAssets", args: [10n ** 18n] }),
  ]);
  if (usdgRound[1] <= 0n) throw new Error("the USDG/USD feed has no valid answer");
  const usdgUsd = Number(usdgRound[1]) / 1e8;

  const tickers = {};
  let droppedTotal = 0;
  for (const [symbol, { token, feed }] of Object.entries(TOKENS)) {
    const [poolPrice, { history, dropped, updatedAt }] = await Promise.all([
      readPoolPrice(token),
      feedHistory(feed, HISTORY_ROUNDS),
    ]);
    droppedTotal += dropped;
    const oracle = history[history.length - 1].price;
    tickers[symbol] = {
      history,
      pool_price_usdg: poolPrice,
      oracle_price_usd: oracle,
      basis_bps: ((poolPrice * usdgUsd) / oracle - 1) * 10_000,
      dropped,
    };
    const notes = [];
    if (dropped > 0) notes.push(`${dropped} rounds dropped by the RPC`);
    if (Date.now() / 1000 - updatedAt > 86_400) notes.push("feed idle over a day; stock feeds run 24/5");
    console.log(
      `  ${symbol}: oracle $${oracle.toFixed(2)}, pool ${poolPrice.toFixed(2)} USDG ` +
        `(basis ${tickers[symbol].basis_bps.toFixed(1)} bps), ${history.length} history points` +
        (notes.length ? ` [${notes.join("; ")}]` : ""),
    );
  }

  // Printed for context: what idle USDG earns in Robinhood Earn. Deposits into
  // that vault are gated on-chain, so it stays a reference figure.
  console.log(`  Robinhood Earn steakUSDG share rate: ${(Number(earnRate) / 1e6).toFixed(6)} USDG/share`);
  const requested = Object.keys(TOKENS).length * HISTORY_ROUNDS;
  return {
    generated_at: new Date().toISOString(),
    usdg_usd: usdgUsd,
    fee_bps: FEE / 100,
    degraded: droppedTotal / requested > DROPPED_LIMIT,
    tickers,
  };
}

async function analyzeOnGpu(dataset) {
  const prism = new PrismAgent({
    privateKey: process.env.PRISM_AGENT_KEY,
    escrow: process.env.PRISM_ESCROW ?? "0x62C042265991bEa17B07229322A01850974626dA",
  });
  await prism.authenticate();
  console.log("\nleasing a GPU on Prism (provisioning usually takes 1-4 minutes)...");
  const lease = await prism.lease({ image: process.env.PRISM_IMAGE, durationSeconds: 1200, minVramMib: 16000 });
  console.log(`leased #${lease.leaseId}, funded on-chain: ${lease.fundingHash}`);
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const job = readFileSync(join(here, "gpu_job.py")).toString("base64");
    const payload = Buffer.from(JSON.stringify(dataset)).toString("base64");
    const remote = [
      `printf %s ${job} | base64 -d > /tmp/gpu_job.py`,
      "base64 -d > /tmp/market.json",
      "python /tmp/gpu_job.py /tmp/market.json",
    ].join(" && ");
    const result = await prism.run(lease, remote, { timeoutMs: 240_000, stdin: payload });
    const line = result.stdout.split("\n").findLast((l) => l.startsWith("{"));
    if (result.code !== 0 || !line) {
      throw new Error(
        `gpu job exit ${result.code}; stdout tail: ${JSON.stringify(result.stdout.slice(-400))}; ` +
          `stderr tail: ${JSON.stringify(result.stderr.slice(-400))}`,
      );
    }
    return JSON.parse(line);
  } finally {
    prism.endLease(lease);
    console.log("local key material discarded; the lease settles on-chain at the end of its window.");
  }
}

// Log returns with feed artifacts removed: a 30% move between consecutive
// rounds is data noise on a stock feed, not a market move.
function cleanReturns(prices) {
  const returns = [];
  for (let i = 1; i < prices.length; i++) {
    const r = Math.log(prices[i] / prices[i - 1]);
    if (Math.abs(r) < 0.3) returns.push(r);
  }
  return returns;
}

// The feeds post on a market schedule, not a fixed cadence, so the forward
// horizon in rounds comes from the observed spacing rather than a constant.
function stepsForHorizon(history, horizonDays) {
  const gaps = [];
  for (let i = 1; i < history.length; i++) gaps.push(history[i].t - history[i - 1].t);
  gaps.sort((a, b) => a - b);
  const median = gaps[Math.floor(gaps.length / 2)] || 86_400;
  return Math.max(4, Math.min(200, Math.round((horizonDays * 86_400) / median)));
}

// The same study as gpu_job.py, downscaled to run anywhere. The GPU run uses
// 200k bootstrap paths; this uses 2k, enough to demo the pipeline for free.
function analyzeLocally(dataset) {
  console.log("\nanalyzing locally (small sample; use --gpu for the full study)...");
  const horizon = 5;
  const paths = 2000;
  const report = { device: "local cpu", paths, horizon_days: horizon, tickers: {} };
  for (const [symbol, data] of Object.entries(dataset.tickers)) {
    const returns = cleanReturns(data.history.map((h) => h.price));
    if (returns.length < 20) {
      report.tickers[symbol] = {
        momentum: 0, bootstrap_mean: 0, expected_return: 0, var_95: 0, p_positive: 0,
        insufficient_history: true,
      };
      continue;
    }
    const steps = stepsForHorizon(data.history, horizon);
    const lookback = Math.min(20, returns.length);
    const momentum = returns.slice(-lookback).reduce((a, b) => a + b, 0);
    const tilt = momentum * 0.35;
    const outcomes = [];
    for (let p = 0; p < paths; p++) {
      let sum = 0;
      for (let d = 0; d < steps; d++) sum += returns[Math.floor(Math.random() * returns.length)];
      outcomes.push(sum + tilt);
    }
    outcomes.sort((a, b) => a - b);
    report.tickers[symbol] = {
      momentum,
      bootstrap_mean: outcomes.reduce((a, b) => a + b, 0) / paths - tilt,
      expected_return: outcomes.reduce((a, b) => a + b, 0) / paths,
      var_95: outcomes[Math.floor(paths * 0.05)],
      p_positive: outcomes.filter((o) => o > 0).length / paths,
      returns_used: returns.length,
    };
  }
  return report;
}

function decide(dataset, analysis) {
  const feeCost = dataset.fee_bps / 10_000;
  const ranked = Object.entries(analysis.tickers)
    .map(([symbol, a]) => ({ symbol, ...a, edge: a.expected_return - feeCost }))
    .sort((a, b) => b.edge - a.edge);
  console.log(`\nanalysis (${analysis.device}, ${analysis.paths} paths, ${analysis.horizon_days}d horizon):`);
  for (const r of ranked) {
    if (r.insufficient_history) {
      console.log(`  ${r.symbol}: not enough clean history to study`);
      continue;
    }
    console.log(
      `  ${r.symbol}: expected ${(r.expected_return * 100).toFixed(2)}% ` +
        `(bootstrap ${(r.bootstrap_mean * 100).toFixed(2)}% + momentum tilt ${(r.momentum * 35).toFixed(2)}%), ` +
        `VaR95 ${(r.var_95 * 100).toFixed(2)}%, p(gain) ${(r.p_positive * 100).toFixed(0)}%, ` +
        `edge after fees ${(r.edge * 100).toFixed(2)}%, ${r.returns_used} returns`,
    );
  }
  const best = ranked[0];
  if (best.insufficient_history || best.edge <= 0 || best.p_positive < 0.5) {
    console.log("\ndecision: stay in USDG. No token clears fees with better-than-even odds.");
    return null;
  }
  const basis = dataset.tickers[best.symbol].basis_bps;
  if (Math.abs(basis) > BASIS_LIMIT_BPS) {
    console.log(
      `\ndecision: stay in USDG. ${best.symbol}'s pool is ${basis.toFixed(0)} bps from the oracle, ` +
        `past the ${BASIS_LIMIT_BPS} bps sanity bound.`,
    );
    return null;
  }
  console.log(`\ndecision: buy ${best.symbol} with ${SPEND_USDG} USDG (edge ${(best.edge * 100).toFixed(2)}%).`);
  return best.symbol;
}

async function executeSwap(symbol) {
  const account = privateKeyToAccount(process.env.PRISM_AGENT_KEY);
  const wallet = createWalletClient({ account, chain: robinhoodChain, transport: http(RPC) });
  const token = TOKENS[symbol].token;
  const key = poolKey(token);
  const usdgIsCurrency0 = key.currency0.toLowerCase() === USDG.toLowerCase();
  const amountIn = BigInt(Math.round(SPEND_USDG * 1e6));

  const tokenDecimals = await client.readContract({
    address: token, abi: erc20Abi, functionName: "decimals",
  });
  if (tokenDecimals !== 18) {
    throw new Error(`${symbol} has ${tokenDecimals} decimals; this example's price math assumes 18`);
  }

  // Re-read the pool immediately before the swap: the analysis price is
  // minutes old by now, and the slippage floor must anchor to the market the
  // order actually meets.
  const freshPrice = await readPoolPrice(token);
  const expectedOut = BigInt(Math.floor((SPEND_USDG / freshPrice) * 1e18));
  const minOut = (expectedOut * (10_000n - SLIPPAGE_BPS)) / 10_000n;
  if (minOut <= 0n) throw new Error("the computed slippage floor is zero; refusing to swap unprotected");

  const usdgAllowance = await client.readContract({
    address: USDG, abi: erc20Abi, functionName: "allowance", args: [account.address, PERMIT2],
  });
  if (usdgAllowance < amountIn) {
    console.log("approving USDG for Permit2...");
    const hash = await wallet.writeContract({
      address: USDG, abi: erc20Abi, functionName: "approve", args: [PERMIT2, 2n ** 160n - 1n],
    });
    await client.waitForTransactionReceipt({ hash });
  }
  // Exactly this swap's amount, expiring in an hour: an example has no
  // business leaving the router a standing right to the wallet's balance.
  console.log("granting the Universal Router a Permit2 allowance for this swap...");
  const permitHash = await wallet.writeContract({
    address: PERMIT2,
    abi: permit2Abi,
    functionName: "approve",
    args: [USDG, UNIVERSAL_ROUTER, amountIn, Math.floor(Date.now() / 1000) + 3600],
  });
  await client.waitForTransactionReceipt({ hash: permitHash });

  // Universal Router command 0x10 = V4_SWAP; v4 actions: swap exact-in single,
  // settle the input in full, take the whole output. Robinhood Chain's router
  // vendors a forked v4-periphery whose swap params carry an extra
  // minHopPriceX36 field between amountOutMinimum and hookData; omit it and
  // the calldata mis-decodes and reverts on every ERC-20 pool.
  const actions = "0x060c0f";
  const swapParams = encodeAbiParameters(
    [
      {
        type: "tuple",
        components: [
          {
            type: "tuple",
            name: "poolKey",
            components: [
              { type: "address", name: "currency0" },
              { type: "address", name: "currency1" },
              { type: "uint24", name: "fee" },
              { type: "int24", name: "tickSpacing" },
              { type: "address", name: "hooks" },
            ],
          },
          { type: "bool", name: "zeroForOne" },
          { type: "uint128", name: "amountIn" },
          { type: "uint128", name: "amountOutMinimum" },
          { type: "uint256", name: "minHopPriceX36" },
          { type: "bytes", name: "hookData" },
        ],
      },
    ],
    [
      {
        poolKey: key,
        zeroForOne: usdgIsCurrency0,
        amountIn,
        amountOutMinimum: minOut,
        minHopPriceX36: 0n,
        hookData: "0x",
      },
    ],
  );
  const settleParams = encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [USDG, amountIn]);
  const takeParams = encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [token, minOut]);
  const input = encodeAbiParameters(
    [{ type: "bytes" }, { type: "bytes[]" }],
    [actions, [swapParams, settleParams, takeParams]],
  );
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 600);

  const before = await client.readContract({
    address: token, abi: erc20Abi, functionName: "balanceOf", args: [account.address],
  });
  console.log(`swapping ${SPEND_USDG} USDG -> ${symbol} (min out ${Number(minOut) / 1e18})...`);
  const { request } = await client.simulateContract({
    account,
    address: UNIVERSAL_ROUTER,
    abi: routerAbi,
    functionName: "execute",
    args: ["0x10", [input], deadline],
  });
  const hash = await wallet.writeContract(request);
  const receipt = await client.waitForTransactionReceipt({ hash });
  const after = await client.readContract({
    address: token, abi: erc20Abi, functionName: "balanceOf", args: [account.address],
  });
  console.log(`swap ${receipt.status}: ${hash}`);
  console.log(`received ${(Number(after - before) / 1e18).toFixed(6)} ${symbol}`);
}

function requireEnv(...names) {
  const missing = names.filter((name) => !process.env[name]);
  if (missing.length) {
    console.error(`missing ${missing.join(", ")}. The README explains what each one is.`);
    process.exit(1);
  }
}

const args = process.argv.slice(2);
const useGpu = args.includes("--gpu");
const unknown = args.filter((a) => a !== "--gpu");
if (unknown.length) {
  console.error(`unknown argument ${unknown.join(", ")}; usage: node agent.mjs [--gpu]`);
  process.exit(1);
}
const willExecute = process.env.EXECUTE === "1";
if (useGpu) requireEnv("PRISM_AGENT_KEY", "PRISM_IMAGE");
if (willExecute) requireEnv("PRISM_AGENT_KEY");

const dataset = await gatherMarketData();
const analysis = useGpu ? await analyzeOnGpu(dataset) : analyzeLocally(dataset);
const pick = decide(dataset, analysis);
if (pick && willExecute && dataset.degraded) {
  console.log("not executing: too much of the price history was dropped by the RPC this run.");
} else if (pick && willExecute) {
  if (!useGpu) console.log("executing on the downscaled local study rather than a full GPU run.");
  await executeSwap(pick);
} else if (pick) {
  console.log("dry run: set EXECUTE=1 to place the swap on-chain.");
}
