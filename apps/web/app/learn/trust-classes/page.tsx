import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";
import { explainer } from "@/lib/explainers";

const entry = explainer("trust-classes")!;

export const metadata: Metadata = {
  title: entry.title,
  description: entry.description,
  alternates: { canonical: "/learn/trust-classes" },
};

export default function TrustClassesPage() {
  return (
    <InformationPage eyebrow="Learn / Trust" title={entry.title} description={entry.dek}>
      <InformationSection index="01" title="One sentence hiding three problems">
        <p>
          People call a rented machine untrusted and stop there. Underneath that word sit three
          separate problems, and each one needs a different control.
        </p>
        <p>
          Can the operator read what your workload touches? Did the machine run what you asked?
          Can your money be taken while the work happens? A GPU can be excellent at one of these
          and useless at another. One label cannot describe it.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Four grades, weakest first">
        <h3>Open</h3>
        <p>
          A bonded supplier identity and metered billing against escrow. The operator can read
          memory, disk and GPU memory. You know who they are and what you will be charged. That is
          the extent of it.
        </p>
        <h3>Isolated</h3>
        <p>
          The card is proven. A report signed by the GPU itself says which physical device answered
          and what firmware it runs, and the network checks it against NVIDIA's root before the
          grade is given. The virtual machine around it is the supplier's word, backed by their
          bond, because a card cannot vouch for the software that booted beside it. A host that
          decides to look inside the guest still can.
        </p>
        <h3>Attested</h3>
        <p>
          The machine proves which software it started, and the chip maker&apos;s keys sign that
          proof. It covers the machine your own work ran on: the key your session connects to is
          created inside it, so the proof describes your session and not a machine that started
          correctly yesterday.
        </p>
        <p>
          It does not stop the operator watching. Work on its way to the GPU leaves the protected
          part of memory, so this grade tells you what ran. Who could see it is the next grade up.
          No rented machine is served at this grade yet. The{" "}
          <a href="https://docs.prismnetwork.tech" target="_blank" rel="noopener noreferrer">
            documentation
          </a>{" "}
          covers how the proof is checked and what it leaves open.
        </p>
        <h3>Confidential</h3>
        <p>
          Guest memory and GPU memory are encrypted against the host. Here the operator genuinely
          cannot read the workload, and reaching this grade takes particular silicon.
        </p>
        <p>
          Inference is served at this grade today. Nine models run inside an Intel TDX enclave in
          front of a GPU that NVIDIA attests directly, among them DeepSeek, Llama 3.3 70B, GPT-OSS,
          Qwen and GLM. The prompt is encrypted to a key the enclave&apos;s attestation quote
          commits to, and the quote is checked before the prompt is sent. Every generation returns
          a signed receipt over the exact request and response bytes, and an answer whose
          attestation does not verify is withheld rather than returned. The{" "}
          <a
            href="https://api.prismnetwork.tech/inference/v1/models"
            target="_blank"
            rel="noopener noreferrer"
          >
            live model list
          </a>{" "}
          carries the current prices.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Where the grade comes from">
        <p>
          A supplier does not choose its own grade. The network computes it from a device-signed
          report about the machine. When a node claims a grade its hardware cannot support, that
          claim is a signed statement the dispute process can act on.
        </p>
        <p>
          Above <code>open</code>, that report comes from the GPU and is signed by NVIDIA&apos;s own
          keys. The network checks the signature chain against a root it ships with, and checks
          that the report answers a challenge it issued to that exact machine, so a report copied
          from somewhere else does not pass. A machine that fails the check keeps the weakest
          grade.
        </p>
        <p>
          The grade is also capped at what the network can check today. Every offer is served at
          open, whatever a machine reports about itself. The hardware the higher grades need is in
          the fleet, so what is left is the checking: the network has to record what a correct
          report from that hardware looks like, then confirm a real one against it. An unchecked
          report earns nothing.
        </p>
      </InformationSection>

      <InformationSection index="04" title="What today's capacity gives you">
        <p>
          Every machine available right now is open class. The company hosting it can read what
          runs there. The grade rises when the network can confirm the evidence for a stronger one,
          which is a different date from the day the hardware landed.
        </p>
        <p>
          Two things follow. Anything that has to stay private belongs in your{" "}
          <Link href="/vault">vault</Link>, encrypted under a key derived on your own machine and
          never sent to us. And a request can require a minimum grade, so an agent handling
          something sensitive refuses weak capacity on its own. When nothing in the fleet meets
          the grade you ask for, the quote is refused and no funds move.
        </p>
        <p>
          <Link href="/learn/confidential-gpu-compute">
            Why the top grade needs specific hardware
          </Link>{" "}
          covers what has to change before it exists.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
