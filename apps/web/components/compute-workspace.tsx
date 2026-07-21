"use client";

import { useEffect, useMemo, useState } from "react";
import { encodeFunctionData, keccak256, toBytes, type Address, type Hex } from "viem";
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

const apps = [
  { id: "ollama", name: "Ollama", blurb: "Run open LLMs like Llama and Mistral", image: "docker.io/ollama/ollama@sha256:a61a8fd395dbb931cc8cb1b5da7a2510746575c87113fdc45b647ee59ef7f808" },
  { id: "pytorch", name: "PyTorch", blurb: "Notebooks, training and fine-tuning", image: "docker.io/pytorch/pytorch@sha256:c8268a92a69bd500f8be0e665b2630ee006dadaf7bfbc24249141b15ff622755" },
  { id: "tensorflow", name: "TensorFlow", blurb: "GPU machine learning", image: "docker.io/tensorflow/tensorflow@sha256:61fe1ce25bd26b0a38e310463a5588d4067d2d01b6bdb058a3ca4f5cf2e18f15" },
  { id: "cuda", name: "CUDA workspace", blurb: "A clean CUDA box to build on", image: "docker.io/nvidia/cuda@sha256:cff3a0d82d2c2b47bab252d67fa9b34a20ef4c50781d98501b5c7367ea9afd10" },
] as const;

export function ComputeWorkspace() {
  const auth = usePrismAuth();
  const smartWallet = useSmartWallet();
  const [duration, setDuration] = useState(3_600);
  const [mode, setMode] = useState<"auto" | "manual">("auto");
  const [appId, setAppId] = useState<string>(apps[0].id);
  const [advanced, setAdvanced] = useState(false);
  const [customImage, setCustomImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const image = (advanced ? customImage.trim() : apps.find((app) => app.id === appId)?.image) ?? "";
  const [offers, setOffers] = useState<MarketplaceOffer[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [fundingAddress, setFundingAddress] = useState<Address | null>(null);
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
  if (!auth.configured) launchLabel = "Account access unavailable";
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
        setOfferError("GPU availability could not be loaded. Try again shortly.");
      })
      .finally(() => setLoadingOffers(false));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!auth.authenticated) {
      setFundingAddress(null);
      return;
    }
    setFundingAddress((current) => (
      auth.accounts.some((account) => account.address === current)
        ? current
        : auth.embeddedAddress ?? auth.accounts[0]?.address ?? null
    ));
  }, [auth.accounts, auth.authenticated, auth.embeddedAddress]);

  async function fundEscrow() {
    if (!auth.authenticated) {
      if (auth.configured) {
        auth.login();
        return;
      }
      setNotice("Account access is temporarily unavailable.");
      return;
    }
    if (!escrowAddress) {
      setNotice("Lease funding is temporarily unavailable.");
      return;
    }
    if (!offer) {
      setNotice("No compatible GPU offers are currently available.");
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
      if (!fundingAddress) {
        setNotice("Connect a funding wallet before launching compute.");
        return;
      }
      const result = await smartWallet.executeCalls([...calls], fundingAddress);
      await confirmLease(lease.quote_id, result.transactionHash, sshKey.trim());
      setNotice(`Funding confirmed: ${result.transactionHash.slice(0, 10)}…`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Wallet transaction was not completed.");
    }
  }

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GPU compute</p>
          <h1>Launch GPU compute</h1>
        </div>
        <span className="chip">Digest-pinned images</span>
      </div>

      <div className="compute-layout">
        <form className="panel launch-form" onSubmit={(event) => { event.preventDefault(); void fundEscrow(); }}>
          <fieldset className="form-fieldset">
            <legend>What do you want to run?</legend>
            <div className="app-picker">
              {apps.map((app) => (
                <button
                  type="button"
                  key={app.id}
                  className={!advanced && appId === app.id ? "app-tile active" : "app-tile"}
                  onClick={() => { setAdvanced(false); setAppId(app.id); }}
                >
                  <strong>{app.name}</strong>
                  <span>{app.blurb}</span>
                </button>
              ))}
              <button
                type="button"
                className={advanced ? "app-tile active" : "app-tile"}
                onClick={() => setAdvanced(true)}
              >
                <strong>Custom image</strong>
                <span>Advanced · bring your own pinned image</span>
              </button>
            </div>
            {advanced && (
              <label className="app-custom">
                Container image
                <input
                  value={customImage}
                  onChange={(event) => setCustomImage(event.target.value)}
                  placeholder={`registry.example/runtime@sha256:${"a".repeat(64)}`}
                  maxLength={512}
                  required
                  spellCheck="false"
                />
                <small>Public, immutable, sha256-pinned and CUDA-compatible.</small>
              </label>
            )}
          </fieldset>
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
          {auth.authenticated && (
            <label>
              Funding wallet
              <select
                value={fundingAddress ?? ""}
                onChange={(event) => setFundingAddress(event.target.value as Address)}
                disabled={!auth.accounts.length || smartWallet.pending}
              >
                {!auth.accounts.length && <option value="">No connected wallet</option>}
                {auth.accounts.map((account) => (
                  <option value={account.address} key={account.address}>
                    {account.label} · {account.address.slice(0, 6)}…{account.address.slice(-4)}
                  </option>
                ))}
              </select>
              <small>The selected wallet must hold enough USDG for escrow and ETH for Robinhood Chain gas.</small>
            </label>
          )}
          <div className="safety-note">
            <strong>Data handling notice</strong>
            <span>Infrastructure providers are independent. Do not process confidential data or credentials in beta workspaces.</span>
          </div>
          <button
            className="button primary full"
            type={auth.authenticated ? "submit" : "button"}
            disabled={!offer || !auth.configured || loadingOffers || smartWallet.pending}
            onClick={!auth.authenticated && auth.configured ? auth.login : undefined}
          >
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
          <p className="muted">Charges begin after GPU and access readiness are confirmed. Unused escrow is returned after settlement.</p>
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
    const payload = await response.json().catch(() => null) as { error?: unknown; message?: unknown } | null;
    const message = typeof payload?.message === "string"
      ? payload.message
      : typeof payload?.error === "string"
        ? payload.error.replaceAll("_", " ")
        : "No compatible GPU is available.";
    throw new Error(message);
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
  throw new Error("Funding confirmation timed out. Check the Leases page for the latest transaction status.");
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
