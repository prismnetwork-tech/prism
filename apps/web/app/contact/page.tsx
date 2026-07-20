import type { Metadata } from "next";
import { InformationPage, InformationSection } from "@/components/information-page";

export const metadata: Metadata = {
  title: "Contact",
  description: "Contact Prism Network for product, technical, security, and conduct matters.",
  alternates: { canonical: "/contact" },
};

export default function ContactPage() {
  return (
    <InformationPage
      eyebrow="Company / Contact"
      title="Contact Prism Network."
      description="Select the appropriate channel for product questions, technical support, security reports, and conduct concerns."
    >
      <InformationSection index="01" title="Product and network">
        <p>
          For launch updates, capacity announcements, and general product questions, contact{" "}
          <a href="https://x.com/useprismnetwork" target="_blank" rel="noopener noreferrer">
            @useprismnetwork on X
          </a>.
        </p>
      </InformationSection>

      <InformationSection index="02" title="Technical support">
        <p>
          For reproducible bugs, documentation corrections, integration questions, and feature
          proposals, open an issue in the{" "}
          <a href="https://github.com/prismnetwork-tech/prism/issues" target="_blank" rel="noopener noreferrer">
            Prism repository
          </a>. Remove wallet secrets, access credentials, private workload data, and personal
          information before posting.
        </p>
      </InformationSection>

      <InformationSection index="03" title="Security and conduct">
        <h3>Security</h3>
        <p>
          Report vulnerabilities privately to{" "}
          <a href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a>.
        </p>
        <h3>Conduct</h3>
        <p>
          Report community conduct issues to{" "}
          <a href="mailto:conduct@prismnetwork.tech">conduct@prismnetwork.tech</a>.
        </p>
        <p>Never send a seed phrase, private key, production credential, or confidential workload artifact.</p>
      </InformationSection>
    </InformationPage>
  );
}
