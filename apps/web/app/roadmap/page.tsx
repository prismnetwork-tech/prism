import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Roadmap",
  description:
    "What Prism Network runs today and where the work is headed. Direction is stated here; the onchain receipts mark what has shipped.",
  alternates: { canonical: "/roadmap" },
};

export default function RoadmapPage() {
  return (
    <InformationPage
      eyebrow="Product / Roadmap"
      title="What is live, and what comes next."
      description="Prism is metered GPU compute that an autonomous agent rents with a wallet and settles onchain. This page tracks what the network does today and where the work is headed. We state direction here and let the onchain receipts mark what has shipped."
    >
      <InformationSection index="01" title="Available now">
        <p>
          These capabilities run on Robinhood Chain today. Because every lease and settlement is
          recorded onchain, the record of what works is public rather than asserted.
        </p>
        <h3>Wallet-native access</h3>
        <p>
          An agent proves control of a wallet with a signed challenge and replay protection. No
          account, password, or human console stands between it and a machine.
        </p>
        <h3>Python and TypeScript SDKs</h3>
        <p>
          Price capacity, fund a lease, provision a machine, and open a session in a few lines.
          Published on PyPI and npm.
        </p>
        <h3>Model Context Protocol server</h3>
        <p>
          Any MCP client, Claude included, can list capacity, rent a GPU, and run a command through
          Prism. Listed in the official MCP registry.
        </p>
        <h3>Prism inside the agent frameworks people already use</h3>
        <p>
          An agent running Hermes gets three skills, rent a GPU, reproduce a CUDA run and read
          the receipts, from{" "}
          <code>hermes plugins install prismnetwork-tech/hermes-plugin-prism</code>. The published
          Python package is a version behind and carries the terminal backend without those
          skills, so the plugin install is the one to use. The Coinbase AgentKit action provider
          is published and installable, so an agent built on AgentKit, LangGraph, or the Vercel AI
          SDK reaches the same capacity with no custom code.
        </p>
        <h3>Spend caps an agent cannot cross</h3>
        <p>
          Every paid call states the most it can cost before the agent pays it, and the SDK keeps a
          running ledger against a session budget. An agent left to run unattended has a ceiling,
          and the receipt afterwards separates what was charged from what came back.
        </p>
        <h3>Onchain lease escrow and settlement</h3>
        <p>
          Funding, metered billing, and refunds execute through deployed contracts, bounded by a
          maximum deposit, a maximum duration, and a dispute window. Routine administration of
          those contracts sits behind an enforced 48-hour timelock, so a change to who signs
          settlements or where fees go is scheduled in public two days before it can execute.
        </p>
        <h3>Ending a lease early</h3>
        <p>
          A renter closes the session the moment the work is done and the meter stops there.
          Settlement charges the time the machine was actually open and returns the rest of the
          escrow. One recent lease held a workstation GPU for twenty-eight seconds, charged 0.006216
          USDG and returned the remaining 0.126984 on the same receipt.
        </p>
        <h3>Verifiable receipts</h3>
        <p>
          Every finalized lease publishes a settlement receipt that anyone can confirm on a block
          explorer.
        </p>
        <h3>Concurrent multi-class GPU capacity</h3>
        <p>
          Supply is sourced from vetted providers across several NVIDIA classes, including L40S,
          RTX A6000, RTX 6000 Ada and RTX 5880 Ada, and matched to a lease on demand. Leases run
          alongside each other rather than one at a time. How many machines are on offer at any
          moment is a small number, usually one to three. Raising it is the first item below.
        </p>
        <h3>Managed and confidential inference</h3>
        <p>
          Text generation paid per call over x402, in USDG on Robinhood Chain or USDC on Base, with
          no account or API key. Two models on the open tier and nine on the confidential tier,
          which runs the model inside a hardware enclave with an attested GPU. The client checks the
          enclave&apos;s attestation before the prompt is sent, so the prompt is readable only
          inside the enclave.
        </p>
        <h3>Findable by an agent that already pays over x402</h3>
        <p>
          Pay-per-job GPU execution and the inference endpoint are both indexed in Coinbase&apos;s
          x402 Bazaar and on agentic.market. An agent that speaks the payment protocol can find the
          endpoint, read the price, and pay it without anyone integrating Prism first.
        </p>
        <h3>A pinned session key per lease</h3>
        <p>
          Clients pin the SSH host key of the machine they rent for the life of the lease. Where no
          honest key can be published, because a third-party cloud generated it, the lease says so
          and a client can refuse it, rather than being told a check happened that did not.
        </p>
        <h3>An availability commitment on every lease</h3>
        <p>
          A machine that stops answering is billed only to the moment it was last observed. The
          receipt names the lease interrupted and states the seconds held but not charged, publicly,
          on the same receipt anyone can verify.
        </p>
        <h3>An encrypted vault that outlives a lease</h3>
        <p>
          Credentials and small artifacts persist across leases, encrypted to the owning wallet.
          Each item names the weakest workspace class it may enter, and a release below that floor
          is refused rather than logged.
        </p>
        <h3>A stated trust class per offer</h3>
        <p>
          Every offer, quote, lease, and receipt carries what the supplier protects, derived by the
          network from evidence it can check rather than asserted by the host. An agent can require
          a minimum class instead of reading a disclaimer. All capacity live today is the weakest
          one, and the <Link href="/security">security page</Link> states what that does and does
          not cover.
        </p>
      </InformationSection>

      <InformationSection index="02" title="In progress, through September">
        <p>
          The constraint on Prism right now is how much capacity is on offer at once, and what a
          lease costs to run. That is where the work is.
        </p>
        <h3>More machines on offer</h3>
        <p>
          The filter that decides which rented machines qualify asks for more memory than most of
          the market has. On 7 September, nine machines across the supplier marketplace passed it.
          Lowering the floor to 24 GB and accepting more card models takes that pool to about
          sixty. You will see it as ten or more distinct offers on the public offers endpoint and
          on this site, held for a week, with at least one settled receipt from a 24 GB card in the
          public feed. Confidential inference keeps its current hardware floor, because the enclave
          needs hardware consumer cards do not have.
        </p>
        <h3>A quote that resolves to a machine</h3>
        <p>
          A funded lease reaches a shell inside four minutes when a host is there to take it. The
          work now is confirming a rentable host at quote time, so a lease is only opened against
          capacity that has already been checked. Escrow is still funded before anything is
          provisioned, and that does not change.
        </p>
        <h3>A LangChain package</h3>
        <p>
          The LangChain integration is finished and its last dependency is now on PyPI. It ships as
          a standalone open source package, installable with <code>pip</code>. The name{" "}
          <code>langchain-prism</code> on PyPI belongs to an unrelated project, so Prism&apos;s
          package publishes under a different one and this page will carry it the day it is up.
          LangChain stopped taking integrations into its own project in March, so a standalone
          package is the only shape this can take.
        </p>
        <h3>Prism in the tool catalogs</h3>
        <p>
          A listing on skills.sh, a listing on ClawHub, and an entry in the community Hermes plugin
          index. One package reaches Hermes, Claude Code, Cursor, Codex, Copilot, Windsurf,
          Gemini, Cline and about twenty more clients through the same install path.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Next, before the end of the year">
        <h3>Twenty offers, held for two weeks</h3>
        <p>
          Twenty or more distinct online offers on the public offers endpoint, continuously, for
          fourteen days, with at least 95% of advertised capacity provisioning successfully when
          leased. Advertised capacity counts only if it is there when a lease arrives for it.
        </p>
        <h3>Cheaper settlement per lease</h3>
        <p>
          Robinhood Chain fees rose ninefold in eleven days while the lease price stayed fixed,
          which makes short leases expensive to settle. Two options are on the table: settle on
          Base, or batch the writes on Robinhood Chain. The choice and its date go in the
          documentation, and the target is under five cents of chain cost per settled lease, held
          for thirty days. Receipts stay on Robinhood Chain either way, so the public trail does
          not move.
        </p>
        <h3>Spend controls, written down</h3>
        <p>
          A public page stating the per-call and per-session caps an agent can set, what happens
          when one is hit, and how to export receipts for accounting.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Later, 2027">
        <p>
          Directional commitments that widen what the network can be trusted to run. Each ships only
          when it meets the same onchain, verifiable standard as the rest of Prism.
        </p>
        <h3>A second supplier</h3>
        <p>
          One broker supplies all of Prism&apos;s capacity today. The goal is offers sourced from
          two independent brokers and a published drill showing at least five offers still served
          with the first supplier switched off. The reason is continuity: capacity a customer can
          rent should not depend on one company staying available.
        </p>
        <h3>Receipts a stranger can check without us</h3>
        <p>
          A published verifier that takes a receipt, checks the settlement records on chain and the
          enclave attestation behind them, and fails on a mismatch. It states which parts of a
          receipt it verified and which parts the supplier reported, so the difference is visible
          to whoever is reading it.
        </p>
        <h3>Own hardware, once usage earns it</h3>
        <p>
          Independent nodes with exclusive GPU passthrough are the only route to the isolation that
          rented capacity cannot promise. They are also a fixed cost that does not care whether
          anything is leased, so they start when the network books 400 leased GPU hours a month for
          two consecutive months. Until then all capacity is brokered and this site says so.
        </p>
        <h3>Attested and confidential workspaces</h3>
        <p>
          The two classes above what rented workspaces can verify today: a launch measurement
          checked against vendor roots, then hardware-backed trusted execution with encrypted GPU
          memory, so a workload and its data stay private from the infrastructure provider.
          Confidential inference already runs this way. Extending it to a workspace a renter
          controls waits on the hardware above.
        </p>
        <h3>Durable workspaces</h3>
        <p>
          Workspace storage that survives across leases. The vault carries credentials and small
          artifacts today; a full working disk that a new lease can resume is not built.
        </p>
      </InformationSection>

      <InformationSection index="05" title="What is not on the list">
        <h3>More framework integrations</h3>
        <p>
          Six surfaces already reach Prism. Another wrapper does not change what a customer can do,
          so a seventh is not scheduled.
        </p>
        <h3>Stronger service-level remedies</h3>
        <p>
          The live commitment is not being charged for an interrupted machine. Performance
          guarantees, and remedies beyond withholding payment, are not built and are not scheduled.
        </p>
        <h3>Interruptible leases in 2026</h3>
        <p>
          Preemptible capacity is roughly a third of the price and it breaks the duration a lease
          commits to. It needs its own product class before it can be sold, and that is a 2027
          conversation.
        </p>
      </InformationSection>

      <InformationSection index="06" title="How we prioritize">
        <h3>Verifiable over asserted</h3>
        <p>
          Settlement is recorded onchain, so a claim about what the network did is checkable rather
          than taken on faith.
        </p>
        <h3>Agent-native by default</h3>
        <p>A wallet in, a machine out. Nothing on the critical path requires a dashboard, a card, or a person.</p>
        <h3>Honest boundaries</h3>
        <p>
          The <Link href="/security">security page</Link> states plainly what the network does not
          yet protect. This roadmap holds to the same standard.
        </p>
        <p>
          Track what has shipped in the live <Link href="/proof">receipts</Link> and in the{" "}
          <a href="https://docs.prismnetwork.tech" target="_blank" rel="noopener noreferrer">
            documentation
          </a>
          .
        </p>
      </InformationSection>
    </InformationPage>
  );
}
