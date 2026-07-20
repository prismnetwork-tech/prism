import Link from "next/link";
import { docsUrl } from "@/lib/site";

export function LegalPage({
  title,
  description,
  effective,
  children,
}: {
  title: string;
  description: string;
  effective: string;
  children: React.ReactNode;
}) {
  return (
    <div className="legal-page">
      <header className="legal-header">
        <Link className="landing-brand" href="/" aria-label="prism. home">
          <img src="/brand/prism-logo.svg" alt="" width="32" height="32" />
          <span>prism.</span>
        </Link>
        <nav aria-label="Legal page navigation">
          <Link href="/">Home</Link>
          <Link href={docsUrl}>Docs</Link>
          <Link className="legal-console-link" href="/compute">Open console ↗</Link>
        </nav>
      </header>
      <main className="legal-main" id="main-content" tabIndex={-1}>
        <header className="legal-hero">
          <p>Prism Network / Legal</p>
          <h1>{title}</h1>
          <div>
            <p>{description}</p>
            <span>Effective {effective}</span>
          </div>
        </header>
        <article className="legal-document">{children}</article>
      </main>
      <footer className="legal-footer">
        <span>Prism Network</span>
        <nav aria-label="Legal footer">
          <Link href="/privacy">Privacy</Link>
          <Link href="/terms">Terms</Link>
          <a href="mailto:security@prismnetwork.tech">Security</a>
          <Link href={docsUrl}>Docs</Link>
        </nav>
      </footer>
    </div>
  );
}

export function LegalSection({
  index,
  title,
  children,
}: {
  index: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <header><span>{index}</span><h2>{title}</h2></header>
      <div>{children}</div>
    </section>
  );
}
