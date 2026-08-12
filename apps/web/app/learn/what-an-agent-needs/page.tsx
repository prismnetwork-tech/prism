import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";
import { explainer } from "@/lib/explainers";
import { docsUrl } from "@/lib/site";

const entry = explainer("what-an-agent-needs")!;

export const metadata: Metadata = {
  title: entry.title,
  description: entry.description,
  alternates: { canonical: "/learn/what-an-agent-needs" },
};

export default function WhatAnAgentNeedsPage() {
  return (
    <InformationPage eyebrow="Learn / Agents" title={entry.title} description={entry.dek}>
      <InformationSection index="01" title="Why the usual path breaks">
        <p>
          Cloud GPUs assume a person. Someone signs up, verifies an email, adds a card, generates
          an API key, and stores it somewhere the software can reach. Every step wants a human, and
          the key that comes out the other end belongs to whoever holds it.
        </p>
        <p>
          An agent that has to wake a person up to rent a GPU is not autonomous. It is a script
          with a queue.
        </p>
      </InformationSection>

      <InformationSection index="02" title="An identity">
        <p>
          The wallet is the account. An agent signs a short challenge, proves it controls the key,
          and gets a session. Nothing to provision, nothing to rotate, and no shared secret sitting
          in a config file waiting to leak.
        </p>
        <p>
          The same wallet is what pays, so spending and identity are the same fact. You can see
          what an agent did by looking at what its wallet did.
        </p>
      </InformationSection>

      <InformationSection index="03" title="A balance">
        <p>
          Leases are funded in USDG on Robinhood Chain, and the wallet needs a little native ETH
          there for gas. Fund it once and the agent works until the balance runs out.
        </p>
        <p>
          For a single job, x402 skips the lease entirely: submit a command, pay per request, read
          the output. That path accepts USDC on Base as well, which is what most agents already
          hold.
        </p>
      </InformationSection>

      <InformationSection index="04" title="A workload">
        <p>
          Images are referenced by digest. A tag can be repointed at different bytes after you
          approved it, so a tag is a promise and a digest is an address. The quote names the exact
          image before any money moves.
        </p>
        <p>
          Access arrives as a temporary SSH credential scoped to the lease, and the workspace is
          destroyed when the lease closes.
        </p>
      </InformationSection>

      <InformationSection index="05" title="Three ways in">
        <p>
          The <Link href={docsUrl.href}>SDK</Link> handles the full lifecycle in a few lines:
          quote, fund, wait for readiness, run a command over SSH, release. The MCP server exposes
          the same operations as tools, so an agent leases a GPU the way it calls anything else.
          x402 covers one-shot jobs with no lease to manage.
        </p>
        <p>
          What none of them need: a browser, a signup form, or a card. If you want to watch what
          your agent is doing, there is a console, and the agent never touches it.
        </p>
      </InformationSection>

      <InformationSection index="06" title="Before you hand one a wallet">
        <p>
          Give an agent its own wallet and fund it with what you are willing to lose. Escrow is
          capped at 50 USDG per lease and a lease runs at most six funded hours, so a runaway loop
          has a bounded cost.
        </p>
        <p>
          Anything the agent must keep private belongs in the <Link href="/vault">vault</Link>.
          Items there carry the weakest class of machine they may be released into, and today that
          floor stops a card or a credential from ever reaching a rented box.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
