import Link from "next/link";
import { PublicFooter } from "@/components/public-footer";
import { docsUrl } from "@/lib/site";

export function InformationPage({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="information-page">
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
      <main id="main-content" tabIndex={-1}>
        <header className="information-hero">
          <p>{eyebrow}</p>
          <h1>{title}</h1>
          <p>{description}</p>
        </header>
        <div className="information-content">{children}</div>
      </main>
      <PublicFooter />
    </div>
  );
}

export function InformationSection({
  index,
  title,
  children,
}: {
  index: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="information-section">
      <header><span>{index}</span><h2>{title}</h2></header>
      <div>{children}</div>
    </section>
  );
}
