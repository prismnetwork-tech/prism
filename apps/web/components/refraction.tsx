"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PublicFooter } from "@/components/public-footer";
import { docsUrl, siteUrl } from "@/lib/site";
import { EXPLORER, REFRACTION_PRIZE, STAGES, type Stage, digestOf, normalise } from "@/lib/refraction";

const RPC = "https://rpc.mainnet.chain.robinhood.com";
const AWARDS = [0.05, 0.03, 0.02];
const PLACES = ["1st", "2nd", "3rd"];

type Winner = { solver: string; award: number };
type Board = { winners: Winner[]; commitments: number; pool: number; closesAt: number };

async function rpc(method: string, params: unknown[]) {
  const response = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    cache: "no-store",
  });
  const answer = await response.json();
  if (answer.error) throw new Error(answer.error.message);
  return answer.result as string;
}

const call = (data: string) => rpc("eth_call", [{ to: REFRACTION_PRIZE, data }, "latest"]);

/// 0.1, not 0.10. Trailing zeros make a prize look like an accounting entry.
const eth = (value: number) => String(Number(value.toFixed(4)));

/// Read straight from the contract. A scoreboard the operator could edit would
/// say nothing about who actually won.
async function readBoard(): Promise<Board> {
  const [rawBoard, rawCommits, rawPool, rawDeadline] = await Promise.all([
    call("0xeb56b740"),
    call("0xd28d5bda"),
    rpc("eth_getBalance", [REFRACTION_PRIZE, "latest"]),
    call("0x29dcb0cf"),
  ]);
  const body = rawBoard.slice(2 + 64);
  const count = Number(BigInt("0x" + body.slice(0, 64)));
  const winners: Winner[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = 64 + index * 192;
    winners.push({
      solver: "0x" + body.slice(base + 24, base + 64),
      award: Number(BigInt("0x" + body.slice(base + 128, base + 192))) / 1e18,
    });
  }
  return {
    winners,
    commitments: Number(BigInt(rawCommits)),
    pool: Number(BigInt(rawPool)) / 1e18,
    closesAt: Number(BigInt(rawDeadline)) * 1000,
  };
}

function remaining(closesAt: number, now: number) {
  const left = Math.max(0, closesAt - now);
  const days = Math.floor(left / 86_400_000);
  const hours = Math.floor((left % 86_400_000) / 3_600_000);
  if (days > 0) return `${days}d ${hours}h left`;
  const minutes = Math.floor((left % 3_600_000) / 60_000);
  return `${hours}h ${minutes}m left`;
}

export function Refraction() {
  const [answers, setAnswers] = useState<(string | null)[]>(() => STAGES.map(() => null));
  const [board, setBoard] = useState<Board | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let live = true;
    const load = () => readBoard().then((next) => live && setBoard(next)).catch(() => {});
    load();
    const poll = setInterval(load, 20_000);
    const clock = setInterval(() => setNow(Date.now()), 30_000);
    return () => {
      live = false;
      clearInterval(poll);
      clearInterval(clock);
    };
  }, []);

  const solvedCount = answers.filter(Boolean).length;
  const complete = solvedCount === STAGES.length;
  const solution = answers.map((answer) => answer ?? "").join("-");
  const claimed = board?.winners.length ?? 0;
  const over = claimed >= AWARDS.length;

  return (
    <div className="refraction">
      <header className="information-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Public page navigation">
          <Link href="/pricing">Pricing</Link>
          <Link href={docsUrl.href}>Docs</Link>
          <Link className="information-console-link" href="/compute">Open console ↗</Link>
        </nav>
      </header>

      <main id="main-content" tabIndex={-1} className="refraction-inner">
        <div className="status-row">
          <span className={`status-pill ${over ? "over" : "open"}`}>
            <i />
            {over ? "All prizes claimed" : "Open now"}
          </span>
          <span className="status-fact">
            {AWARDS.length - claimed} of {AWARDS.length} prizes unclaimed
          </span>
          {board && <span className="status-fact">{remaining(board.closesAt, now)}</span>}
        </div>

        <p className="refraction-kicker">Solve it first. The contract pays you.</p>
        <h1>
          {board ? eth(board.pool) : "0.1"} <span className="unit">ETH</span>
        </h1>

        <div className="podium">
          {AWARDS.map((award, place) => {
            const winner = board?.winners[place];
            return (
              <div className={`slot ${winner ? "taken" : "open"}`} key={award}>
                <span className="slot-place">{PLACES[place]}</span>
                <span className="slot-amount">
                  {eth(award)} <em>ETH</em>
                </span>
                <span className="slot-holder">
                  {winner ? (
                    <a href={`${EXPLORER}/address/${winner.solver}`} target="_blank" rel="noreferrer">
                      won by {winner.solver.slice(0, 6)}…{winner.solver.slice(-4)}
                    </a>
                  ) : (
                    "up for grabs"
                  )}
                </span>
              </div>
            );
          })}
        </div>

        <p className="refraction-lede">
          Four questions. Every answer is somewhere real: a settlement receipt, a block explorer, a
          contract, and one that wants a GPU you can rent for pennies. Nobody judges your entry and
          nobody can pay late. The money sits in a contract that pays the first three solvers itself.
        </p>

        <div className="beam" aria-hidden="true">
          <div className="beam-in" />
          <div className="beam-out">
            {STAGES.map((stage, index) => (
              <span key={stage.index} className={`beam-band ${answers[index] ? "lit" : ""}`} />
            ))}
          </div>
        </div>
        <div className="beam-caption">
          <span>
            {solvedCount} of {STAGES.length} solved
          </span>
          <span>
            {board === null
              ? "reading the chain…"
              : board.commitments === 0
                ? "no one holds the answer yet"
                : `${board.commitments} ${board.commitments === 1 ? "solver holds" : "solvers hold"} the answer`}
          </span>
        </div>

        <h2>The four</h2>
        {STAGES.map((stage, index) => (
          <StageRow
            key={stage.index}
            stage={stage}
            answer={answers[index]}
            onSolved={(value) =>
              setAnswers((prior) => prior.map((was, at) => (at === index ? value : was)))
            }
          />
        ))}

        {complete && (
          <section className="claim">
            <p className="claim-flag">You have all four</p>
            <p className="solution">{solution}</p>
            <p>
              Claim it in two transactions. <code>commit</code> a hash of the solution, your address
              and any salt you like, then <code>reveal</code> the solution and that salt. The
              commitment is bound to your address, so nobody watching the chain can take your place
              with your own answer.
            </p>
            <a
              className="button primary"
              href={`${EXPLORER}/address/${REFRACTION_PRIZE}?tab=write_contract`}
              target="_blank"
              rel="noreferrer"
            >
              Claim your prize ↗
            </a>
          </section>
        )}

        <div className="refraction-foot">
          <span>
            Prize pool held at{" "}
            <a href={`${EXPLORER}/address/${REFRACTION_PRIZE}`} target="_blank" rel="noreferrer">
              {REFRACTION_PRIZE.slice(0, 10)}…{REFRACTION_PRIZE.slice(-6)} ↗
            </a>
          </span>
          <Link href={new URL("/proof", siteUrl).href}>Settlement receipts</Link>
        </div>
      </main>
      <PublicFooter />
    </div>
  );
}

function StageRow({
  stage,
  answer,
  onSolved,
}: {
  stage: Stage;
  answer: string | null;
  onSolved: (value: string) => void;
}) {
  const [value, setValue] = useState("");
  const [wrong, setWrong] = useState(false);
  const [hint, setHint] = useState(false);

  const check = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      const cleaned = normalise(value);
      if (!cleaned) return;
      if ((await digestOf(value)) === stage.digest) onSolved(cleaned);
      else setWrong(true);
    },
    [onSolved, stage.digest, value],
  );

  return (
    <article className={`stage ${answer ? "solved" : ""}`}>
      <span className="stage-index">{String(stage.index).padStart(2, "0")}</span>
      <div>
        <h3>{stage.title}</h3>
        <p>{stage.prompt}</p>
        {answer ? (
          <p className="stage-solved">✓ {answer}</p>
        ) : (
          <>
            <form onSubmit={check}>
              <input
                value={value}
                onChange={(event) => {
                  setValue(event.target.value);
                  setWrong(false);
                }}
                placeholder="your answer"
                aria-label={`Answer for question ${stage.index}`}
                spellCheck={false}
                autoComplete="off"
              />
              <button className="stage-submit" type="submit">Check</button>
            </form>
            {wrong && <p className="stage-wrong">Not that one.</p>}
            <button className="stage-hint" type="button" onClick={() => setHint((was) => !was)}>
              {hint ? stage.hint : "Need a nudge?"}
            </button>
          </>
        )}
      </div>
    </article>
  );
}
