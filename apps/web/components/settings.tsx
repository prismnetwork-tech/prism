"use client";

import { usePrismAuth } from "@/components/providers";

export function Settings() {
  const auth = usePrismAuth();

  return (
    <section className="page-stack">
      <div className="page-heading"><div><p className="eyebrow">Account controls</p><h1>Settings</h1></div></div>
      <article className="panel settings-list">
        <div><div><h2>Session security</h2><p>Browser access uses a verified, HTTP-only session. Authorized administrators can revoke active sessions.</p></div><span className="chip">{auth.authenticated ? "Protected" : "Signed out"}</span></div>
        <div>
          <div><h2>Recovery methods</h2><p>Add an email address or passkey so this account is not dependent on one wallet.</p></div>
          {auth.authenticated ? (
            <div className="setting-actions">
              {!auth.hasRecovery && <button className="button secondary" type="button" onClick={auth.linkEmail}>Add email</button>}
              <button className="button secondary" type="button" onClick={auth.linkPasskey}>Add passkey</button>
            </div>
          ) : <span className="chip">Sign in required</span>}
        </div>
        <div><div><h2>Account roles</h2><p>Use one account to purchase compute and operate provider nodes.</p></div><span className="chip">Customer + provider</span></div>
        <div><div><h2>Risk controls</h2><p>Authorized administrators can apply risk holds, revoke sessions, suspend nodes, and revoke certificates. Administrative actions are recorded in an immutable audit trail.</p></div><span className="chip success">Enabled</span></div>
      </article>
    </section>
  );
}
