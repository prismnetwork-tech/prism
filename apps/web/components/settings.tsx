"use client";

import { usePrismAuth } from "@/components/providers";

export function Settings() {
  const auth = usePrismAuth();

  return (
    <section className="page-stack">
      <div className="page-heading"><div><p className="eyebrow">Account controls</p><h1>Settings</h1></div></div>
      <article className="panel settings-list">
        <div><div><h2>Session security</h2><p>Browser API access uses a verified, HTTP-only session. Allowlisted operators can revoke active account sessions.</p></div><span className="chip">{auth.authenticated ? "Protected" : "Signed out"}</span></div>
        <div>
          <div><h2>Recovery methods</h2><p>Add an email address or passkey so this account is not dependent on one wallet.</p></div>
          {auth.authenticated ? (
            <div className="setting-actions">
              {!auth.hasRecovery && <button className="button secondary" type="button" onClick={auth.linkEmail}>Add email</button>}
              <button className="button secondary" type="button" onClick={auth.linkPasskey}>Add passkey</button>
            </div>
          ) : <span className="chip">Sign in required</span>}
        </div>
        <div><div><h2>Account mode</h2><p>Use the same identity to rent compute and operate nodes.</p></div><span className="chip">Renter + supplier</span></div>
        <div><div><h2>Risk controls</h2><p>Allowlisted operators can place risk holds, revoke sessions, suspend nodes and revoke node certificates. Every action is append-only audited.</p></div><span className="chip success">Enabled</span></div>
      </article>
    </section>
  );
}
