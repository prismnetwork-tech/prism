import type { Metadata } from "next";
import { LegalPage, LegalSection } from "@/components/legal-page";

export const metadata: Metadata = {
  title: "Privacy policy",
  description: "How Prism Network processes account, wallet, usage, and infrastructure data.",
  alternates: { canonical: "/privacy" },
};

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacy policy"
      description="How Prism processes data when you use the website, console, compute marketplace, contracts, and support channels."
      effective="July 20, 2026"
    >
      <LegalSection index="01" title="Scope">
        <p>
          This policy applies to Prism Network&apos;s public website, authenticated console,
          compute marketplace, application APIs, public proof feed, and related support
          communications. Independent GPU providers, wallet software, identity providers,
          public blockchains, and linked third-party services may process data under their own
          policies.
        </p>
      </LegalSection>

      <LegalSection index="02" title="Data we process">
        <h3>Account and identity data</h3>
        <p>
          Prism receives the minimum identity assertions needed to operate your account,
          including a Privy user identifier, session identifier, authentication method, linked
          email or passkey status, and linked wallet metadata. Authentication providers process
          the credentials used to sign in; Prism does not receive your OAuth password, passkey
          private material, wallet seed phrase, or wallet private key.
        </p>
        <h3>Wallet and blockchain data</h3>
        <p>
          We process linked wallet addresses, signatures used to prove wallet control,
          transaction hashes, lease events, escrow deposits, refunds, settlement events, and
          other public-chain data necessary to provide the service. Public blockchain records
          are independently visible and cannot be erased by Prism.
        </p>
        <h3>Compute and usage data</h3>
        <p>
          We process quote parameters, selected image reference, requested GPU capacity,
          duration, provider and node identifiers, runtime state, workspace-readiness timestamps,
          metered seconds, provider pricing records, service failure categories, and settlement
          outcomes. Public proof records are intentionally pseudonymous and omit wallet
          addresses, precise location, image digest, files, terminal output, and private
          telemetry.
        </p>
        <h3>Technical and security data</h3>
        <p>
          We process request IDs, timestamps, network address or edge-provided client identifier,
          browser and device metadata, abuse-prevention signals, service logs, security events, and
          diagnostic records required to prevent abuse, investigate failures, and maintain
          availability.
        </p>
        <h3>Support data</h3>
        <p>
          We process information you send through security, conduct, support, or partnership
          channels. Do not include wallet secrets, production credentials, confidential
          workload data, or information that is not necessary to resolve the request.
        </p>
      </LegalSection>

      <LegalSection index="03" title="How we use data">
        <ul>
          <li>Authenticate users, maintain sessions, and link verified wallets.</li>
          <li>Match workloads to capacity and operate the lease lifecycle.</li>
          <li>Verify escrow funding, meter admitted runtime, settle usage, and issue refunds.</li>
          <li>Provide temporary workspace access and revoke it at lease close.</li>
          <li>Publish sanitized proof artifacts after final chain confirmation.</li>
          <li>Enforce rate, concurrency, fraud, risk, and platform-abuse controls.</li>
          <li>Investigate incidents, restore interrupted operations, and secure Prism infrastructure.</li>
          <li>Meet accounting, compliance, dispute, and legal obligations.</li>
        </ul>
      </LegalSection>

      <LegalSection index="04" title="Processing grounds">
        <p>
          Depending on your jurisdiction, processing is necessary to provide the service you
          request, protect Prism and its users from abuse, satisfy legal obligations, or pursue
          legitimate interests in operating and securing infrastructure. Where consent is
          required, it may be withdrawn prospectively without affecting prior lawful
          processing. Prism does not sell personal information or use workspace data for
          advertising.
        </p>
      </LegalSection>

      <LegalSection index="05" title="Service providers and disclosure">
        <p>
          Prism uses infrastructure and specialist providers for authentication, hosting,
          content delivery and DNS, databases and key management, GPU capacity, monitoring,
          support, and public-chain access. Current production categories include Privy,
          Render, AWS, Cloudflare, Vast.ai, wallet providers, and Robinhood Chain RPC/indexing
          services. They receive only the data reasonably required for their function.
        </p>
        <p>
          Data may also be disclosed when required by law, to investigate security incidents
          or abuse, to protect users or infrastructure, in connection with a corporate
          transaction, or at your direction. Independent GPU operators may observe or control
          data processed on their hosts; do not use beta workspaces for confidential data.
        </p>
      </LegalSection>

      <LegalSection index="06" title="Retention">
        <p>
          Session cookies expire after at most one hour. Quotes expire after five minutes.
          Temporary access credentials expire or are revoked when the lease closes. Operational,
          security, accounting, dispute, and settlement records are retained only as long as
          reasonably required for service integrity, legal obligations, and incident response.
          Backup deletion may lag primary deletion. Public blockchain records and published
          immutable proof artifacts cannot be removed by Prism.
        </p>
      </LegalSection>

      <LegalSection index="07" title="Security">
        <p>
          Prism uses secure same-site HTTP-only sessions, same-origin mutation checks,
          least-privilege service credentials, encrypted stored access credentials,
          non-exportable production signing keys, replay protection, request limits,
          persistent transaction records, and governance-controlled emergency pause. No system is
          completely secure. The beta does not provide confidential computing and the deployed
          contracts are unaudited.
        </p>
      </LegalSection>

      <LegalSection index="08" title="Your choices and rights">
        <p>
          You may disconnect linked wallets, revoke sessions, stop using the service, or ask
          about account data. Depending on applicable law, you may have rights to access,
          correct, delete, restrict, object to, or receive a portable copy of personal data, and
          to complain to a supervisory authority. These rights do not override public-chain
          immutability, fraud prevention, security evidence, or legally required retention.
        </p>
      </LegalSection>

      <LegalSection index="09" title="International processing">
        <p>
          Prism and its service providers may process data in multiple countries. Where
          required, transfers rely on recognized legal mechanisms and appropriate safeguards.
          Provider location may also depend on the GPU capacity selected for a lease.
        </p>
      </LegalSection>

      <LegalSection index="10" title="Contact and changes">
        <p>
          Send privacy or security questions to{" "}
          <a href="mailto:security@prismnetwork.tech">security@prismnetwork.tech</a>. We may
          update this policy as the service, providers, or law changes. Material changes will
          be identified by a revised effective date and, when appropriate, an in-product
          notice.
        </p>
      </LegalSection>
    </LegalPage>
  );
}
