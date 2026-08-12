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
          A virtual machine with the GPU passed through exclusively, running an image pinned to a
          digest. It narrows what a mistake can reach. A host that decides to look inside the guest
          still can.
        </p>
        <h3>Attested</h3>
        <p>
          The machine proves what it booted, checked against the hardware vendor&apos;s signing
          keys. This tells you what ran. It says nothing about who was watching.
        </p>
        <h3>Confidential</h3>
        <p>
          Guest memory and GPU memory are encrypted against the host. Here the operator genuinely
          cannot read the workload, and reaching this grade takes particular silicon.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Where the grade comes from">
        <p>
          A supplier does not choose its own grade. The network computes it from a device-signed
          report about the machine. When a node claims a grade its hardware cannot support, that
          claim is a signed statement the dispute process can act on.
        </p>
        <p>
          The grade is also capped at what the network can check today. Attestation evidence
          travels end to end but nothing verifies it yet, so no offer is served above{" "}
          <code>isolated</code> whatever a machine reports. Lifting that ceiling takes a verifier
          in code.
        </p>
      </InformationSection>

      <InformationSection index="04" title="What today's capacity gives you">
        <p>
          Every machine available right now is open class. The company hosting it can read what
          runs there. This follows from the hardware in the fleet, so it will hold until different
          hardware arrives.
        </p>
        <p>
          Two things follow. Anything that has to stay private belongs in your{" "}
          <Link href="/vault">vault</Link>, encrypted under a key derived on your own machine and
          never sent to us. And a request can require a minimum grade, so an agent handling
          something sensitive refuses weak capacity on its own.
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
