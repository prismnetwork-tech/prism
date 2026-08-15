"use client";

import { useCallback, useEffect, useState } from "react";
import {
  EXPLORER,
  REFRACTION_PRIZE,
  STAGES,
  type Stage,
  digestOf,
  normalise,
} from "@/lib/refraction";

const RPC = "https://rpc.mainnet.chain.robinhood.com";
const AWARDS = [3_000_000, 2_000_000, 1_000_000];

type Winner = { solver: string; revealedAt: number; award: number };
type Board = { winners: Winner[]; commitments: number; pool: number | null };

async function ethCall(to: string, data: string) {
  const response = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
    cache: "no-store",
  });
  const answer = await response.json();
  if (answer.error) throw new Error(answer.error.message);
  return answer.result as string;
}

const word = (hex: string, index: number) => hex.slice(2 + index * 64, 2 + (index + 1) * 64);
const toNumber = (hex: string) => Number(BigInt("0x" + hex));

/// Reads the board straight from the contract rather than from us. A leaderboard
/// the operator could edit would say nothing about who actually solved it.
async function readBoard(): Promise<Board> {
  const [rawBoard, rawCommits, rawPool] = await Promise.all([
    ethCall(REFRACTION_PRIZE, "0xeb56b740"),
    ethCall(REFRACTION_PRIZE, "0xd28d5bda"),
    ethCall("0x0A1e0Cc751f77C2C93760FC957CC8E4E779b2bC8", "0x70a08231" + REFRACTION_PRIZE.slice(2).toLowerCase().padStart(64, "0")),
  ]);
  const body = rawBoard.slice(2 + 64);
  const count = Number(BigInt("0x" + body.slice(0, 64)));
  const winners: Winner[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = 64 + index * 64 * 3;
    winners.push({
      solver: "0x" + body.slice(base + 24, base + 64),
      revealedAt: Number(BigInt("0x" + body.slice(base + 64, base + 128))),
      award: Number(BigInt("0x" + body.slice(base + 128, base + 192)) / 10n ** 18n),
    });
  }
  return {
    winners,
    commitments: toNumber(word(rawCommits, 0)),
    pool: Number(BigInt("0x" + word(rawPool, 0)) / 10n ** 18n),
  };
}

export function Refraction() {
  const [solved, setSolved] = useState<boolean[]>(() => STAGES.map(() => false));
  const [board, setBoard] = useState<Board | null>(null);
  const [boardError, setBoardError] = useState(false);

  useEffect(() => {
    let live = true;
    const load = () =>
      readBoard()
        .then((next) => live && (setBoard(next), setBoardError(false)))
        .catch(() => live && setBoardError(true));
    load();
    const timer = setInterval(load, 30_000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);

  const complete = solved.every(Boolean);

  return (
    <div className="refraction">
      <section className="refraction-hero">
        <p className="eyebrow">Bounty</p>
        <h1>Refraction</h1>
        <p>
          Four questions about how this network actually works. The first three people to answer all
          four take 3,000,000, 2,000,000 and 1,000,000 PRISM. The prize sits in a contract that pays
          out by itself, so nobody here decides who wins.
        </p>
        <div className="refraction-pool">
          <span>{board?.pool !== null && board?.pool !== undefined ? `${board.pool.toLocaleString()} PRISM` : "6,000,000 PRISM"} in the pool</span>
          <a href={`${EXPLORER}/address/${REFRACTION_PRIZE}`} target="_blank" rel="noreferrer">
            Check it yourself ↗
          </a>
        </div>
      </section>

      <section className="refraction-stages">
        {STAGES.map((stage, index) => (
          <StageCard
            key={stage.index}
            stage={stage}
            solved={solved[index]}
            onSolved={() => setSolved((prior) => prior.map((was, at) => (at === index ? true : was)))}
          />
        ))}
      </section>

      {complete && (
        <section className="refraction-done">
          <h2>All four. Now claim it.</h2>
          <p>
            Join your four answers with hyphens, lowercase, letters and digits only. That string is
            the solution. Claiming takes two transactions: a commitment first, which proves you have
            the answer without revealing it, then the reveal.
          </p>
          <p className="refraction-note">
            The commitment is bound to your wallet, so nobody who is watching the chain can copy your
            answer and take your place with it.
          </p>
          <a className="button primary" href={`${EXPLORER}/address/${REFRACTION_PRIZE}?tab=write_contract`} target="_blank" rel="noreferrer">
            Claim on the contract ↗
          </a>
        </section>
      )}

      <section className="refraction-board">
        <h2>Leaderboard</h2>
        {boardError && <p className="refraction-note">The chain could not be reached just now.</p>}
        {board && (
          <>
            <ol>
              {AWARDS.map((award, place) => {
                const winner = board.winners[place];
                return (
                  <li key={award} className={winner ? "taken" : ""}>
                    <span className="place">{place + 1}</span>
                    <span className="award">{award.toLocaleString()} PRISM</span>
                    {winner ? (
                      <a href={`${EXPLORER}/address/${winner.solver}`} target="_blank" rel="noreferrer" className="mono">
                        {winner.solver.slice(0, 10)}…{winner.solver.slice(-6)}
                      </a>
                    ) : (
                      <span className="open">unclaimed</span>
                    )}
                  </li>
                );
              })}
            </ol>
            <p className="refraction-note">
              {board.commitments === 0
                ? "Nobody has committed an answer yet."
                : `${board.commitments} ${board.commitments === 1 ? "person has" : "people have"} committed an answer. A commitment cannot be made without already having it.`}
            </p>
          </>
        )}
      </section>
    </div>
  );
}

function StageCard({ stage, solved, onSolved }: { stage: Stage; solved: boolean; onSolved: () => void }) {
  const [value, setValue] = useState("");
  const [state, setState] = useState<"idle" | "wrong">("idle");
  const [showHint, setShowHint] = useState(false);

  const check = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!normalise(value)) return;
      const digest = await digestOf(value);
      if (digest === stage.digest) onSolved();
      else setState("wrong");
    },
    [onSolved, stage.digest, value],
  );

  return (
    <article className={`refraction-stage ${solved ? "solved" : ""}`}>
      <header>
        <span className="index">{String(stage.index).padStart(2, "0")}</span>
        <h3>{stage.title}</h3>
        {solved && <span className="tick">solved</span>}
      </header>
      <p>{stage.prompt}</p>
      {solved ? (
        <p className="refraction-answer mono">{normalise(value) || "solved"}</p>
      ) : (
        <form onSubmit={check}>
          <input
            value={value}
            onChange={(event) => {
              setValue(event.target.value);
              setState("idle");
            }}
            placeholder="your answer"
            aria-label={`Answer for stage ${stage.index}`}
            spellCheck={false}
          />
          <button className="button secondary" type="submit">Check</button>
        </form>
      )}
      {state === "wrong" && !solved && <p className="refraction-wrong">Not that. Try again.</p>}
      {!solved && (
        <button className="refraction-hint" type="button" onClick={() => setShowHint((was) => !was)}>
          {showHint ? stage.hint : "Need a nudge?"}
        </button>
      )}
    </article>
  );
}
