"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { Address } from "viem";
import type { PrismVault, TrustFloor, VaultItem, VaultRelease } from "@prismnetwork/agent-sdk/vault";
import { usePrismAuth } from "@/components/providers";
import { VaultRequestError, openVault } from "@/lib/vault-session";

const TRUST_FLOORS: { value: TrustFloor; label: string; note: string }[] = [
  { value: "confidential", label: "Confidential", note: "Storage only. No workspace on the network can receive it." },
  { value: "attested", label: "Attested", note: "Releasable once launch measurement is verified." },
  { value: "isolated", label: "Isolated", note: "Releasable into a Kata VM with exclusive GPU passthrough." },
  { value: "open", label: "Open", note: "Releasable into any workspace, where the host operator can read it." },
];

const messageFor = (error: unknown) => {
  if (error instanceof VaultRequestError) {
    if (error.code === "vault_version_conflict") return "This item changed elsewhere. Reload and apply the edit again.";
    if (error.code === "vault_full") return "This vault is at its item limit. Delete an item to store another.";
    if (error.code === "vault_item_not_found") return "That item is no longer in this vault.";
    if (error.status === 401) return "The vault session expired. Unlock again to continue.";
  }
  if (error instanceof Error && error.message.includes("rejected")) return "The wallet declined the signature.";
  return error instanceof Error && error.message ? error.message : "The vault could not complete that request.";
};

export function Vault() {
  const auth = usePrismAuth();
  const [vault, setVault] = useState<PrismVault | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [releases, setReleases] = useState<VaultRelease[]>([]);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});

  const [label, setLabel] = useState("");
  const [value, setValue] = useState("");
  const [floor, setFloor] = useState<TrustFloor>("confidential");

  const wallet = useMemo<Address | null>(() => auth.accounts[0]?.address ?? null, [auth.accounts]);

  const refresh = useCallback(async (open: PrismVault) => {
    const [storedItems, storedReleases] = await Promise.all([open.list(), open.releases()]);
    setItems(storedItems);
    setReleases(storedReleases);
  }, []);

  // The key lives only in this tab's memory. Navigating away or reloading
  // discards it, and the vault has to be unlocked again.
  useEffect(() => {
    if (!auth.authenticated) {
      setVault(null);
      setItems([]);
      setRevealed({});
    }
  }, [auth.authenticated]);

  async function run(task: string, work: () => Promise<void>) {
    setBusy(task);
    setNotice(null);
    try {
      await work();
    } catch (error) {
      setNotice(messageFor(error));
    } finally {
      setBusy(null);
    }
  }

  const unlock = () =>
    run("unlock", async () => {
      if (!wallet) throw new Error("Connect a wallet before opening a vault.");
      const open = await openVault(wallet, auth.signWalletMessage, passphrase.trim() || null);
      setPassphrase("");
      setVault(open);
      await refresh(open);
    });

  const store = () =>
    run("store", async () => {
      if (!vault) return;
      if (!value.trim()) throw new Error("Enter the data to seal.");
      await vault.put(value, { label: label.trim(), trustFloor: floor });
      setValue("");
      setLabel("");
      await refresh(vault);
      setNotice("Sealed. Prism holds the ciphertext and cannot read it.");
    });

  const reveal = (item: VaultItem) =>
    run(`reveal:${item.item_id}`, async () => {
      if (!vault) return;
      const plaintext = await vault.open(item);
      setRevealed((current) => ({ ...current, [item.item_id]: plaintext }));
    });

  const remove = (item: VaultItem) =>
    run(`remove:${item.item_id}`, async () => {
      if (!vault) return;
      await vault.remove(item.item_id);
      setRevealed(({ [item.item_id]: _discarded, ...rest }) => rest);
      await refresh(vault);
    });

  if (!auth.configured) {
    return (
      <Shell>
        <article className="panel empty-state">
          <span className="empty-icon">◇</span>
          <h2>Vault unavailable</h2>
          <p>Account access is temporarily unavailable. Stored items are unaffected.</p>
        </article>
      </Shell>
    );
  }

  if (!auth.authenticated || !wallet) {
    return (
      <Shell>
        <article className="panel empty-state">
          <span className="empty-icon">◇</span>
          <h2>Connect a wallet</h2>
          <p>
            Your vault key is derived from a wallet signature on this device. The same wallet opens
            the same vault anywhere, including from an agent using the SDK.
          </p>
          {!auth.authenticated
            ? <button className="button primary" type="button" onClick={auth.login}>Sign in</button>
            : <button className="button primary" type="button" onClick={auth.linkWallet}>Connect a wallet</button>}
        </article>
      </Shell>
    );
  }

  if (!vault) {
    return (
      <Shell wallet={wallet}>
        <article className="panel vault-unlock">
          <h2>Unlock your vault</h2>
          <p>
            Signing derives the encryption key on this device. It is never sent to Prism, so only
            this wallet can read what is stored here.
          </p>
          <label>
            Passphrase
            <input
              type="password"
              autoComplete="off"
              value={passphrase}
              placeholder="Optional"
              onChange={(event) => setPassphrase(event.target.value)}
            />
            <small>
              Adds a second factor beyond the wallet. Items stored with a passphrase need the same
              one to open, and it cannot be reset.
            </small>
          </label>
          {notice && <p className="form-notice" role="status">{notice}</p>}
          <button className="button primary" type="button" disabled={busy !== null} onClick={unlock}>
            {busy === "unlock" ? "Check your wallet…" : "Sign to unlock"}
          </button>
        </article>
      </Shell>
    );
  }

  return (
    <Shell wallet={wallet} onLock={() => { vault.lock(); setVault(null); setRevealed({}); }}>
      {notice && <p className="form-notice" role="status">{notice}</p>}
      <div className="vault-layout">
        <article className="panel">
          <h2>Stored items</h2>
          {items.length === 0 ? (
            <p className="muted">Nothing stored yet. Sealed items appear here with the label you give them.</p>
          ) : (
            <div className="vault-items">
              {items.map((item) => (
                <div className="vault-item" key={item.item_id}>
                  <div>
                    <strong>{item.label || "Unlabelled item"}</strong>
                    <p className="mono">{item.item_id}</p>
                    <span className="muted">
                      Version {item.version} · Releasable at {item.min_trust_class} and above
                    </span>
                  </div>
                  <div className="setting-actions">
                    <button
                      className="button secondary"
                      type="button"
                      disabled={busy !== null}
                      onClick={() => (revealed[item.item_id] ? setRevealed(({ [item.item_id]: _hidden, ...rest }) => rest) : void reveal(item))}
                    >
                      {revealed[item.item_id] ? "Hide" : busy === `reveal:${item.item_id}` ? "Opening…" : "Reveal"}
                    </button>
                    <button className="button secondary" type="button" disabled={busy !== null} onClick={() => void remove(item)}>
                      Delete
                    </button>
                  </div>
                  {revealed[item.item_id] !== undefined && (
                    <code className="vault-plaintext">{revealed[item.item_id]}</code>
                  )}
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="panel launch-form vault-compose">
          <h2>Seal an item</h2>
          <label>
            Label
            <input value={label} maxLength={64} placeholder="Billing card" onChange={(event) => setLabel(event.target.value)} />
            <small>Stored unencrypted so the list is navigable. Keep it descriptive, not revealing.</small>
          </label>
          <label>
            Data
            <textarea value={value} onChange={(event) => setValue(event.target.value)} placeholder="Card number, document, credential" />
            <small>Encrypted in this browser before it is sent.</small>
          </label>
          <label>
            Release floor
            <select value={floor} onChange={(event) => setFloor(event.target.value as TrustFloor)}>
              {TRUST_FLOORS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <small>{TRUST_FLOORS.find((option) => option.value === floor)?.note}</small>
          </label>
          <button className="button primary full" type="button" disabled={busy !== null} onClick={store}>
            {busy === "store" ? "Sealing…" : "Seal and store"}
          </button>
          <div className="safety-note">
            <strong>All capacity today is open class.</strong>
            An item kept at confidential stays in storage: no workspace on the network can receive
            it, so an agent cannot expose it by mistake.
          </div>
        </article>
      </div>

      <article className="panel">
        <h2>Release history</h2>
        {releases.length === 0 ? (
          <p className="muted">No item has been released into a workspace. Refused attempts are not recorded.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Item</th><th>Lease</th><th>Version</th><th>Workspace class</th><th>Released</th></tr>
              </thead>
              <tbody>
                {releases.map((release) => (
                  <tr key={`${release.item_id}-${release.released_at}`}>
                    <td className="mono">{release.item_id.slice(0, 8)}</td>
                    <td>{release.lease_id}</td>
                    <td>{release.item_version}</td>
                    <td>{release.lease_trust_class}</td>
                    <td>{new Date(release.released_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </article>
    </Shell>
  );
}

function Shell({ children, wallet, onLock }: { children: React.ReactNode; wallet?: Address | null; onLock?: () => void }) {
  return (
    <section className="page-stack">
      <div className="page-heading">
        <div><p className="eyebrow">Private data</p><h1>Vault</h1></div>
        {wallet && (
          <div className="setting-actions">
            <span className="chip success">Sealed to {wallet.slice(0, 6)}…{wallet.slice(-4)}</span>
            {onLock && <button className="button secondary" type="button" onClick={onLock}>Lock</button>}
          </div>
        )}
      </div>
      {children}
    </section>
  );
}
