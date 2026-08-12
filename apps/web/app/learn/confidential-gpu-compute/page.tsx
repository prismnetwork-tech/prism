import type { Metadata } from "next";
import Link from "next/link";
import { InformationPage, InformationSection } from "@/components/information-page";
import { explainer } from "@/lib/explainers";

const entry = explainer("confidential-gpu-compute")!;

export const metadata: Metadata = {
  title: entry.title,
  description: entry.description,
  alternates: { canonical: "/learn/confidential-gpu-compute" },
};

export default function ConfidentialComputePage() {
  return (
    <InformationPage eyebrow="Learn / Hardware" title={entry.title} description={entry.dek}>
      <InformationSection index="01" title="The question people are really asking">
        <p>
          Can the company running the machine read my model and my data? For rented GPUs the answer
          is usually yes, and the usual reassurances do not change it.
        </p>
        <p>
          Encryption in transit protects the trip. Encryption at rest protects the disk. Neither
          helps in the middle, because the machine has to decrypt the data to compute on it, and at
          that moment it sits in memory the host administers.
        </p>
      </InformationSection>

      <InformationSection index="02" title="It takes hardware on both sides">
        <p>
          Hiding a workload from its own host means the silicon has to enforce it. That is a
          trusted execution environment: memory encrypted with keys the host cannot reach, plus a
          signed report proving which code got those keys.
        </p>
        <p>
          A GPU workload needs this twice. AMD SEV-SNP or Intel TDX covers the CPU side, which
          protects the virtual machine. NVIDIA Confidential Computing covers the GPU, which
          protects the memory the model actually runs in. Do only the first and the GPU remains an
          open window.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Which GPUs can do it">
        <p>
          NVIDIA Confidential Computing begins with the Hopper generation: H100, H200, and the
          Blackwell parts after them. Everything earlier lacks the capability in silicon, so no
          driver or firmware release adds it later.
        </p>
        <p>
          That rules out most of what the rental market runs on today. L40S, RTX 6000 Ada, RTX A6000
          and A40 are all Ada or Ampere. They are excellent for training and inference, and they
          cannot hide a workload from the machine they sit in.
        </p>
        <p>
          Renting a confidential GPU therefore means renting particular hardware from an operator
          who controls the host firmware. It is a supply question before it is a software question.
        </p>
      </InformationSection>

      <InformationSection index="04" title="Why proofs do not fill the gap">
        <p>
          Zero-knowledge proofs come up here often, and they solve a different problem. A proof
          establishes that a computation was performed correctly. It does not hide the input from
          the party doing the computing, and on a rented GPU that party is the host you are trying
          to hide from.
        </p>
        <p>
          Homomorphic encryption and secure multi-party computation do address secrecy. Both are
          orders of magnitude too slow for training or transformer inference, which is why nobody
          sells them as GPU rental.
        </p>
        <p>
          Proofs do have a place one step away from the workload: checking an attestation report
          cheaply, so a machine&apos;s claim about itself can be settled onchain.
        </p>
      </InformationSection>

      <InformationSection index="05" title="Where this leaves you today">
        <p>
          Every machine on the network right now is open class, and its operator can read what runs
          there. We would rather write that down than imply otherwise.
        </p>
        <p>
          Two things are true alongside it. Your stored data does not have to live on a rented
          machine at all: the <Link href="/vault">vault</Link> keeps cards, documents and
          credentials encrypted under a key derived on your own machine, and we hold only
          ciphertext. And every offer carries a{" "}
          <Link href="/learn/trust-classes">trust class</Link>, so when hardware that can do better
          arrives, a workload can require it and refuse the rest.
        </p>
      </InformationSection>
    </InformationPage>
  );
}
