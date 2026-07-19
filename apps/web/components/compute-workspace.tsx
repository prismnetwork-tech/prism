"use client";

import { useEffect, useMemo, useState } from "react";
import { createWalletClient, custom, encodeFunctionData, keccak256, toBytes, type EIP1193Provider, type Hex } from "viem";
import { usePrismAuth, useSmartWallet } from "@/components/providers";
import { escrowAbi, escrowAddress, robinhoodChain, usdgAbi, usdgAddress } from "@/lib/chain";

type MarketplaceOffer = {
  node_id: `0x${string}`;
  gpu: { model: string; vram_mib: number; cuda_major: number };
  rate_per_second: number;
  reliability_bps: number;
};

type LeaseQuote = {
  quote_id: string;
  node_id: `0x${string}`;
  image: string;
  duration_seconds: number;
  rate_per_second: number;
};

export function ComputeWorkspace() {
  const auth = usePrismAuth();
  const smartWallet = useSmartWallet();
  const [duration, setDuration] = useState(3_600);
  const [mode, setMode] = useState<"auto" | "manual">("auto");
  const [image, setImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [offers, setOffers] = useState<MarketplaceOffer[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [loadingOffers, setLoadingOffers] = useState(true);
  const [offerError, setOfferError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const offer = offers.find((item) => item.node_id === selected) ?? offers[0];
  const maximum = useMemo(
    () => offer ? formatUsdg(BigInt(offer.rate_per_second) * BigInt(duration)) : "—",
    [duration, offer],
  );
  let launchLabel = mode === "auto" ? "Match and fund escrow" : "Approve USDG and fund escrow";
  if (!auth.authenticated) launchLabel = "Sign in to launch";
  if (!auth.configured) launchLabel = "Authentication unavailable";
  if (!offer) launchLabel = "No GPUs available";
  if (loadingOffers) launchLabel = "Loading live offers…";

  useEffect(() => {
    const controller = new AbortController();
    void loadOffers(controller.signal)
      .then((nextOffers) => {
        setOffers(nextOffers);
        setSelected((current) => nextOffers.some((item) => item.node_id === current) ? current : nextOffers[0]?.node_id ?? null);
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setOfferError("Live GPU offers are temporarily unavailable.");
      })
      .finally(() => setLoadingOffers(false));
    return () => controller.abort();
  }, []);

  async function fundEscrow() {
    if (!auth.authenticated) {
      if (auth.configured) {
        auth.login();
        return;
      }
      setNotice("Authentication is not configured in this environment.");
      return;
    }
    if (!escrowAddress) {
      setNotice("Escrow deployment address has not been configured.");
      return;
    }
    if (!offer) {
      setNotice("No bonded GPU offers are available.");
      return;
    }
    if (!image.includes("@sha256:")) {
      setNotice("Use a public OCI image pinned to an immutable sha256 digest.");
      return;
    }
    if (!/^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$/.test(sshKey.trim())) {
      setNotice("Add one Ed25519 SSH public key for workspace access.");
      return;
    }

    try {
      const lease = await requestMatch(
        image,
        duration,
        offer.gpu.vram_mib,
        mode === "manual" ? offer.node_id : null,
      );
      const maximumBaseUnits = BigInt(lease.rate_per_second) * BigInt(duration);
      const clientReference = keccak256(toBytes(lease.quote_id));
      const calls = [
        {
          to: usdgAddress,
          data: encodeFunctionData({ abi: usdgAbi, functionName: "approve", args: [escrowAddress, maximumBaseUnits] }),
        },
        {
          to: escrowAddress,
          data: encodeFunctionData({
            abi: escrowAbi,
            functionName: "createLease",
            args: [lease.node_id, duration, clientReference],
          }),
        },
      ] as const;
      if (auth.authenticated && auth.embeddedAddress) {
        const result = await smartWallet.executeCalls([...calls]);
        await confirmLease(lease.quote_id, result.transactionHash, sshKey.trim());
        setNotice(`Lease funded and indexed: ${result.transactionHash.slice(0, 10)}…`);
        return;
      }
      const ethereum = window.ethereum as EIP1193Provider | undefined;
      if (!ethereum) {
        setNotice("Sign in with Prism or connect an EVM wallet to fund this lease.");
        return;
      }
      const accounts = (await ethereum.request({ method: "eth_requestAccounts" })) as `0x${string}`[];
      const account = accounts[0];
      if (!account) throw new Error("No wallet account was returned.");
      await ensureChain(ethereum);
      const client = createWalletClient({ account, chain: robinhoodChain, transport: custom(ethereum) });
      await client.sendTransaction({ to: calls[0].to, data: calls[0].data });
      const transactionHash = await client.sendTransaction({ to: calls[1].to, data: calls[1].data });
      await confirmLease(lease.quote_id, transactionHash, sshKey.trim());
      setNotice(`Lease funded and indexed: ${transactionHash.slice(0, 10)}…`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Wallet transaction was not completed.");
    }
  }

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Interactive workspace</p>
          <h1>Launch GPU compute</h1>
        </div>
        <span className="chip">Public OCI only</span>
      </div>

      <div className="compute-layout">
        <form className="panel launch-form" onSubmit={(event) => { event.preventDefault(); void fundEscrow(); }}>
          <label>
            Container image
            <input
              value={image}
              onChange={(event) => setImage(event.target.value)}
              placeholder={`registry.example/runtime@sha256:${"a".repeat(64)}`}
              maxLength={512}
              required
              spellCheck="false"
            />
            <small>Images must be public, immutable and compatible with the workspace probe.</small>
          </label>
          <label>
            SSH public key
            <input
              value={sshKey}
              onChange={(event) => setSshKey(event.target.value)}
              placeholder="ssh-ed25519 AAAA…"
              maxLength={16_384}
              required
              spellCheck="false"
              autoComplete="off"
            />
            <small>Only the public key is sent to the assigned workspace. Keep the private key on your machine.</small>
          </label>
          <fieldset className="form-fieldset">
            <legend>Runtime</legend>
            <div className="duration-picker">
              {[30, 60, 120, 360].map((minutes) => (
                <button className={duration === minutes * 60 ? "duration active" : "duration"} type="button" onClick={() => setDuration(minutes * 60)} key={minutes}>
                  {minutes < 60 ? `${minutes}m` : `${minutes / 60}h`}
                </button>
              ))}
            </div>
          </fieldset>
          <div className="segmented" role="group" aria-label="Offer selection mode">
            <button type="button" className={mode === "auto" ? "active" : ""} onClick={() => setMode("auto")}>Auto-match</button>
            <button type="button" className={mode === "manual" ? "active" : ""} onClick={() => setMode("manual")}>Choose offer</button>
          </div>
          {mode === "manual" && (
            <label>
              GPU offer
              <select value={selected ?? ""} onChange={(event) => setSelected(event.target.value)} disabled={!offers.length}>
                {!offers.length && <option value="">No schedulable offers</option>}
                {offers.map((item) => <option value={item.node_id} key={item.node_id}>{item.gpu.model} · {formatVram(item.gpu.vram_mib)} · {formatRate(item.rate_per_second)} USDG/sec</option>)}
              </select>
            </label>
          )}
          <div className="safety-note">
            <strong>Workspace boundary</strong>
            <span>Node providers are independent. Do not use this service for confidential data or credentials.</span>
          </div>
          <button className="button primary full" type="submit" disabled={!offer || !auth.configured || loadingOffers || smartWallet.pending}>
            {launchLabel}
          </button>
          {offerError && <p className="form-notice" role="status">{offerError}</p>}
          {notice && <p className="form-notice" role="status">{notice}</p>}
        </form>

        <aside className="panel quote-card">
          <p className="eyebrow">Lease estimate</p>
          <h2>{offer ? mode === "auto" ? "Best available match" : offer.gpu.model : "No schedulable GPUs"}</h2>
          <div className="quote-line"><span>GPU memory</span><strong>{offer ? formatVram(offer.gpu.vram_mib) : "—"}</strong></div>
          <div className="quote-line"><span>Reliability</span><strong>{offer ? `${(offer.reliability_bps / 100).toFixed(1)}%` : "—"}</strong></div>
          <div className="quote-line"><span>Rate</span><strong>{offer ? `${formatRate(offer.rate_per_second)} USDG/sec` : "—"}</strong></div>
          <div className="quote-total"><span>Maximum escrow</span><strong>{maximum} <small>USDG</small></strong></div>
          <p className="muted">Billing starts after CUDA and access readiness are confirmed. Unused funds refund at settlement.</p>
        </aside>
      </div>
    </section>
  );
}

async function loadOffers(signal: AbortSignal): Promise<MarketplaceOffer[]> {
  const response = await fetch("/api/app/offers", { signal, cache: "no-store" });
  if (!response.ok) throw new Error("offers unavailable");
  const payload: unknown = await response.json();
  return Array.isArray(payload) ? payload.filter(isMarketplaceOffer) : [];
}

async function requestMatch(
  image: string,
  duration_seconds: number,
  min_vram_mib: number,
  preferred_node_id: string | null,
): Promise<LeaseQuote> {
  const response = await fetch("/api/app/leases/match", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request: { image, duration_seconds, min_vram_mib, preferred_node_id } }),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: unknown } | null;
    throw new Error(typeof payload?.error === "string" ? payload.error.replaceAll("_", " ") : "No compatible GPU is available.");
  }
  const payload: unknown = await response.json();
  if (!isLeaseQuote(payload)) throw new Error("The match response was invalid.");
  return payload;
}

function isMarketplaceOffer(value: unknown): value is MarketplaceOffer {
  if (!value || typeof value !== "object") return false;
  const offer = value as Partial<MarketplaceOffer>;
  return isBytes32(offer.node_id)
    && isPositiveInteger(offer.rate_per_second)
    && Boolean(offer.gpu)
    && typeof offer.gpu?.model === "string"
    && offer.gpu.model.length > 0
    && offer.gpu.model.length <= 128
    && isPositiveInteger(offer.gpu?.vram_mib)
    && typeof offer.gpu?.cuda_major === "number"
    && Number.isInteger(offer.gpu.cuda_major)
    && offer.gpu.cuda_major > 0
    && typeof offer.reliability_bps === "number"
    && Number.isInteger(offer.reliability_bps)
    && offer.reliability_bps >= 0
    && offer.reliability_bps <= 10_000;
}

function isLeaseQuote(value: unknown): value is LeaseQuote {
  if (!value || typeof value !== "object") return false;
  const quote = value as Partial<LeaseQuote>;
  return typeof quote.quote_id === "string"
    && /^[0-9a-f-]{36}$/i.test(quote.quote_id)
    && isBytes32(quote.node_id)
    && typeof quote.image === "string"
    && isPositiveInteger(quote.duration_seconds)
    && isPositiveInteger(quote.rate_per_second);
}

async function confirmLease(quoteId: string, transactionHash: Hex, sshAuthorizedKey: string) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const response = await fetch("/api/app/leases/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quote_id: quoteId,
        transaction_hash: transactionHash,
        ssh_authorized_key: sshAuthorizedKey,
      }),
    });
    if (response.ok) return;
    const payload = await response.json().catch(() => null) as { code?: unknown; error?: unknown; message?: unknown } | null;
    const code = typeof payload?.code === "string"
      ? payload.code
      : typeof payload?.error === "string"
        ? payload.error
        : "funding_confirmation_failed";
    if (code !== "funding_not_final") {
      const message = typeof payload?.message === "string" ? payload.message : code.replaceAll("_", " ");
      throw new Error(message);
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error("Funding confirmation timed out. The transaction is safe; check Leases shortly.");
}

function isBytes32(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function formatUsdg(value: bigint) {
  const whole = value / 1_000_000n;
  const fraction = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function formatRate(ratePerSecond: number) {
  return formatUsdg(BigInt(ratePerSecond));
}

function formatVram(vramMib: number) {
  return `${Math.round(vramMib / 1_024)} GB`;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

async function ensureChain(provider: EIP1193Provider) {
  const chainId = `0x${robinhoodChain.id.toString(16)}`;
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  } catch (error) {
    const code = typeof error === "object" && error && "code" in error ? Number(error.code) : null;
    if (code !== 4902) throw error;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [{
        chainId,
        chainName: robinhoodChain.name,
        nativeCurrency: robinhoodChain.nativeCurrency,
        rpcUrls: robinhoodChain.rpcUrls.default.http,
        blockExplorerUrls: [robinhoodChain.blockExplorers.default.url],
      }],
    });
  }
}
