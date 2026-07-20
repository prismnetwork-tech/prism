"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { usePrismAuth } from "@/components/providers";
import { docsUrl } from "@/lib/site";

const navigation = [
  ["Compute", "/compute"],
  ["Leases", "/leases"],
  ["Nodes", "/nodes"],
  ["Earnings", "/earnings"],
  ["Wallets", "/wallets"],
  ["Proof", "/proof"],
  ["Docs", docsUrl.href],
  ["Settings", "/settings"],
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);

  if (
    pathname === "/"
    || pathname.startsWith("/docs")
    || pathname === "/privacy"
    || pathname === "/terms"
  ) return <>{children}</>;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link className="brand" href="/">
          <img className="brand-mark" src="/brand/prism-logo.svg" alt="" width="28" height="28" />
          <span>prism.</span>
        </Link>
        <nav className="desktop-nav" aria-label="Primary navigation">
          {navigation.map(([label, href]) => (
            <Link className={pathname === href ? "nav-link active" : "nav-link"} href={href} key={href}>
              {label}
            </Link>
          ))}
        </nav>
        <details className="mobile-nav" open={menuOpen} onToggle={(event) => setMenuOpen(event.currentTarget.open)}>
          <summary>Menu</summary>
          <div className="mobile-menu-panel">
            <nav aria-label="Primary navigation">
              {navigation.map(([label, href]) => (
                <Link className={pathname === href ? "nav-link active" : "nav-link"} href={href} key={href} onClick={() => setMenuOpen(false)}>
                  {label}
                </Link>
              ))}
            </nav>
            <div className="mobile-account"><AccountControl /></div>
          </div>
        </details>
        <div className="desktop-account"><AccountControl /></div>
        <div className="sidebar-note">
          <span className="status-dot" />
          Robinhood Chain · USDG
        </div>
      </aside>
      <main className="main-content" id="main-content" tabIndex={-1}>{children}</main>
    </div>
  );
}

function AccountControl() {
  const auth = usePrismAuth();

  if (!auth.configured) {
    return <span className="account-status" title="Configure Privy before opening beta accounts.">Authentication unavailable</span>;
  }

  if (!auth.ready) {
    return <span className="account-status">Loading account…</span>;
  }

  if (auth.authenticated) {
    return (
      <div className="account-control">
        <span className="account-status success">Signed in</span>
        <button className="account-button" type="button" onClick={() => void auth.logout()}>Sign out</button>
      </div>
    );
  }

  return <button className="account-button primary" type="button" onClick={auth.login}>Sign in or create account</button>;
}
