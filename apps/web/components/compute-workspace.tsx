"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { createPublicClient, encodeFunctionData, http, keccak256, toBytes, type Address, type Hex } from "viem";
import { usePrismAuth, useSmartWallet } from "@/components/providers";
import { escrowAbi, escrowAddress, robinhoodChain, usdgAbi, usdgAddress } from "@/lib/chain";
import { isGpuReproCommand, isPinnedPublicImage, isSshPublicKey } from "@/lib/gpu-capability";

type TrustClass = "open" | "isolated" | "attested" | "confidential";

type MarketplaceOffer = {
  node_id: `0x${string}`;
  gpu: { model: string; vram_mib: number; cuda_major: number };
  rate_per_second: number;
  reliability_bps: number;
  trust_class: TrustClass;
  staker_only?: boolean;
};

// What the renter can actually rely on, stated per offer rather than as one
// blanket warning that applies equally to every supplier.
const trustCopy: Record<TrustClass, { label: string; detail: string }> = {
  open: {
    label: "Open",
    detail: "The host operator can read anything this workload touches. Keep credentials in your vault, where they stay sealed, rather than on the box. The settled receipt records this lease as open.",
  },
  isolated: {
    label: "Isolated",
    detail: "A specific physical GPU, proven by a report checked against NVIDIA's root and bound to this node. The VM and the exclusive passthrough are the supplier's claim, backed by their bond, not by that report. A privileged host can still reach the workload. The settled receipt carries the verdict's digest.",
  },
  attested: {
    label: "Attested",
    detail: "Requires a launch measurement of the virtual machine the work ran in, signed by the chip maker's keys and bound to the key your session terminates on, so you can check what booted rather than take our word for it. No capacity can produce that evidence yet.",
  },
  confidential: {
    label: "Confidential",
    detail: "Requires guest memory and GPU memory encrypted against the host, on top of everything attested requires. No capacity can produce that evidence yet.",
  },
};

type LeaseQuote = {
  quote_id: string;
  node_id: `0x${string}`;
  image: string;
  duration_seconds: number;
  min_vram_mib: number;
  rate_per_second: number;
  maximum_escrow: number;
  command?: string;
  repro?: {
    token_hash: string;
    spec_hash: string;
    expected_exit_code: number;
    executor: "node" | "managed";
  };
};

type ReproIntent = {
  version: "prism.gpu-repro.intent.v2";
  executor: "node" | "managed";
  image: string;
  command: string;
  duration_seconds: number;
  min_vram_mib: number;
  expected_exit_code: number;
  maximum_escrow: string;
  token_hash: string;
  spec_hash: string;
  issued_at: number;
  expires_at: number;
};

type CommandResult = {
  exit_code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
};

type ReproProgress = {
  leaseState: string;
  result: CommandResult | null;
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
  const router = useRouter();
  const [duration, setDuration] = useState(3_600);
  const [minVramMib, setMinVramMib] = useState(24 * 1_024);
  const [mode, setMode] = useState<"auto" | "manual">("auto");
  const [appId, setAppId] = useState<string>(apps[0].id);
  const [advanced, setAdvanced] = useState(false);
  const [customImage, setCustomImage] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [generatedKey, setGeneratedKey] = useState(false);
  const [confirmed, setConfirmed] = useState<{ model: string; vram: number; escrow: string; hash: string; leaseId: number; repro: boolean } | null>(null);
  const [reproIntent, setReproIntent] = useState<ReproIntent | null>(null);
  const [reproLoad, setReproLoad] = useState<"none" | "loading" | "ready" | "invalid">("none");
  const [reproProgress, setReproProgress] = useState<ReproProgress | null>(null);
  const image = reproIntent?.image ?? ((advanced ? customImage.trim() : apps.find((app) => app.id === appId)?.image) ?? "");
  const [offers, setOffers] = useState<MarketplaceOffer[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [fundingAddress, setFundingAddress] = useState<Address | null>(null);
  const [loadingOffers, setLoadingOffers] = useState(true);
  const [offerError, setOfferError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const eligibleOffers = useMemo(
    () => offers.filter((item) => item.gpu.vram_mib >= minVramMib && item.staker_only !== true),
    [minVramMib, offers],
  );
  const offer = eligibleOffers.find((item) => item.node_id === selected) ?? eligibleOffers[0];
  const maximum = useMemo(
    () => offer ? formatUsd(BigInt(offer.rate_per_second) * BigInt(duration)) : "—",
    [duration, offer],
  );
  let launchLabel = reproIntent
    ? "Approve and run repro"
    : mode === "auto" ? "Match and fund escrow" : "Approve USDG and fund escrow";
  if (!auth.authenticated) launchLabel = "Sign in to launch";
  if (!auth.configured) launchLabel = "Account access unavailable";
  if (!offer) launchLabel = "No GPUs available";
  if (loadingOffers) launchLabel = "Loading live offers…";
  if (reproLoad === "loading") launchLabel = "Verifying repro…";
  if (reproLoad === "invalid") launchLabel = "Invalid repro link";

  useEffect(() => {
    const controller = new AbortController();
    void loadOffers(controller.signal)
      .then((nextOffers) => {
        setOffers(nextOffers);
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setOfferError("GPU availability could not be loaded. Try again shortly.");
      })
      .finally(() => setLoadingOffers(false));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const envelope = new URLSearchParams(window.location.hash.slice(1)).get("repro");
    if (!envelope) return;
    const controller = new AbortController();
    setReproLoad("loading");
    void loadReproIntent(envelope, controller.signal)
      .then((intent) => {
        setReproIntent(intent);
        setDuration(intent.duration_seconds);
        setMinVramMib(intent.min_vram_mib);
        setMode("auto");
        setReproLoad("ready");
        setNotice("GPU repro loaded. Verify the locked command and live quote before approving your wallet.");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setReproLoad("invalid");
        setNotice(error instanceof Error ? error.message : "This GPU repro approval link is invalid.");
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!confirmed?.repro) {
      setReproProgress(null);
      return;
    }
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const progress = await loadReproProgress(confirmed.leaseId);
        if (stopped) return;
        setReproProgress(progress);
        if (progress.result || isTerminalLeaseState(progress.leaseState)) return;
      } catch {
        if (stopped) return;
      }
      timer = setTimeout(() => void poll(), 5_000);
    };
    void poll();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [confirmed?.leaseId, confirmed?.repro]);

  useEffect(() => {
    setSelected((current) => (
      eligibleOffers.some((item) => item.node_id === current)
        ? current
        : eligibleOffers[0]?.node_id ?? null
    ));
  }, [eligibleOffers]);

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
    if (!isPinnedPublicImage(image)) {
      setNotice("Use a public OCI image pinned to an immutable lowercase sha256 digest.");
      return;
    }
    if (!reproIntent && !isSshPublicKey(sshKey)) {
      setNotice("Add one Ed25519 SSH public key for workspace access.");
      return;
    }
    if (reproLoad === "loading") {
      setNotice("The GPU repro is still being verified.");
      return;
    }
    if (reproLoad === "invalid") {
      setNotice("This GPU repro approval link is invalid or expired.");
      return;
    }

    try {
      const lease = await requestMatch(
        image,
        duration,
        mode === "auto" ? minVramMib : offer.gpu.vram_mib,
        mode === "manual" ? offer.node_id : null,
        reproIntent,
      );
      const maximumBaseUnits = BigInt(lease.maximum_escrow);
      if (reproIntent) assertReproQuote(lease, reproIntent);
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
            args: [lease.node_id, lease.duration_seconds, clientReference],
          }),
        },
      ] as const;
      if (!fundingAddress) {
        setNotice("Connect a funding wallet before launching compute.");
        return;
      }
      // Leases are paid in USDG. A wallet with gas and no USDG gets through the
      // approval and then reverts inside createLease, which reads as a broken
      // site rather than an empty balance.
      const held = await readUsdgBalance(fundingAddress);
      if (held < maximumBaseUnits) {
        setNotice(
          `This lease escrows ${formatUsdg(maximumBaseUnits)} USDG and this wallet holds ${formatUsdg(held)}. ` +
            "USDG is the stablecoin leases are paid in; the ETH in your wallet only covers gas.",
        );
        return;
      }
      const result = await smartWallet.executeCalls([...calls], fundingAddress);
      const record = await confirmLease(
        lease.quote_id,
        result.transactionHash,
        reproIntent ? undefined : sshKey.trim(),
      );
      const matchedOffer = offers.find((candidate) => candidate.node_id === lease.node_id) ?? offer;
      setNotice(null);
      setConfirmed({
        model: matchedOffer.gpu.model,
        vram: matchedOffer.gpu.vram_mib,
        escrow: formatUsd(maximumBaseUnits),
        hash: result.transactionHash,
        leaseId: record.lease_id,
        repro: Boolean(reproIntent),
      });
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Wallet transaction was not completed.");
    }
  }

  async function generateKey() {
    try {
      const key = await sshKeygen();
      setSshKey(key.publicKey);
      setGeneratedKey(true);
      downloadText("prism_key", key.privateKey);
      setNotice("Created an SSH key. Your private key downloaded as \"prism_key\" — keep it to connect.");
    } catch {
      setNotice("This browser can't generate a key. Paste an existing SSH public key instead.");
    }
  }

  if (reproLoad === "loading" || reproLoad === "invalid") {
    return (
      <section className="page-stack">
        <div className="page-heading">
          <div><p className="eyebrow">GPU repro</p><h1>Review GPU repro</h1></div>
          <span className="chip">Signed intent</span>
        </div>
        <article className="panel empty-state" role="status">
          <span className="empty-icon">◇</span>
          <h2>{reproLoad === "loading" ? "Verifying approval intent" : "Approval link unavailable"}</h2>
          <p>{reproLoad === "loading" ? "Checking the exact workload and cost ceiling…" : notice}</p>
        </article>
      </section>
    );
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

      {confirmed ? (
        <div className="panel lease-confirmed" role="status">
          <span className="lease-confirmed-check" aria-hidden="true">✓</span>
          <h2>{confirmed.repro ? "GPU repro funded" : "Lease confirmed"}</h2>
          <p>
            {confirmed.repro
              ? reproProgress?.result
                ? `The command finished with exit code ${reproProgress.result.exit_code}.`
                : `Lease #${confirmed.leaseId} is ${reproProgress?.leaseState.replaceAll("_", " ") ?? "preparing"}. The result will appear here.`
              : `Your ${confirmed.model} workspace is provisioning. It will be ready to connect in about a minute.`}
          </p>
          <dl className="lease-confirmed-facts">
            <div><dt>Lease</dt><dd>#{confirmed.leaseId}</dd></div>
            <div><dt>GPU</dt><dd>{confirmed.model} · {formatVram(confirmed.vram)}</dd></div>
            <div><dt>Escrow held</dt><dd>{confirmed.escrow}</dd></div>
            <div><dt>Funding tx</dt><dd>{confirmed.hash.slice(0, 10)}…{confirmed.hash.slice(-6)}</dd></div>
          </dl>
          {confirmed.repro && reproProgress?.result && reproIntent && (
            <section className="access-panel" aria-label="GPU repro result">
              <p className="eyebrow">
                {reproProgress.result.exit_code === reproIntent.expected_exit_code ? "Expected result" : "Unexpected exit code"}
              </p>
              <h3>Command output</h3>
              {reproProgress.result.stdout && <pre>{reproProgress.result.stdout}</pre>}
              {reproProgress.result.stderr && <pre>{reproProgress.result.stderr}</pre>}
              {reproProgress.result.truncated && <p className="muted">Output exceeded the capture limit; only its tail is shown.</p>}
              <p className="muted">Grok can retrieve the signed evidence and settlement checks with the read token returned when this repro was prepared.</p>
            </section>
          )}
          <button type="button" className="button primary full" onClick={() => router.push("/leases")}>
            View your leases
          </button>
        </div>
      ) : (
      <div className="compute-layout">
        <form className="panel launch-form" onSubmit={(event) => { event.preventDefault(); void fundEscrow(); }}>
          {reproIntent ? (
            <fieldset className="form-fieldset">
              <legend>Locked repro specification</legend>
              <dl className="lease-confirmed-facts">
                <div><dt>Image</dt><dd className="mono">{shortImageDigest(reproIntent.image)}</dd></div>
                <div><dt>Runtime</dt><dd>{formatDuration(reproIntent.duration_seconds)}</dd></div>
                <div><dt>Minimum VRAM</dt><dd>{formatVram(reproIntent.min_vram_mib)}</dd></div>
                <div><dt>Expected exit</dt><dd>{reproIntent.expected_exit_code}</dd></div>
                <div><dt>Executor</dt><dd>{reproIntent.executor === "managed" ? "Prism-managed GPU" : "Provider node"}</dd></div>
                <div><dt>Cost ceiling</dt><dd>{formatUsd(BigInt(reproIntent.maximum_escrow))}</dd></div>
                <div><dt>Spec hash</dt><dd className="mono">{shortDigest(reproIntent.spec_hash)}</dd></div>
              </dl>
              <label>
                Exact command
                <textarea value={reproIntent.command} readOnly rows={5} spellCheck="false" />
              </label>
              <small>This signed specification cannot be edited. Reject it if the command is not exactly what you expected.</small>
              <small>Execution may use a Prism-managed GPU. Managed evidence is gateway-signed central SSH orchestration; node evidence is device-signed. Neither signature alone proves faithful computation.</small>
            </fieldset>
          ) : <fieldset className="form-fieldset">
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
          </fieldset>}
          {!reproIntent && <fieldset className="form-fieldset">
            <legend>Workspace access</legend>
            <div className="keygen-row">
              <input
                value={sshKey}
                onChange={(event) => { setSshKey(event.target.value); setGeneratedKey(false); }}
                placeholder="ssh-ed25519 AAAA…"
                maxLength={16_384}
                spellCheck="false"
                autoComplete="off"
                aria-label="SSH public key"
              />
              <button type="button" onClick={() => void generateKey()}>Generate for me</button>
            </div>
            <small>
              {generatedKey
                ? "Key created and public key filled. Your private key downloaded as \"prism_key\" — keep it to connect."
                : "No SSH key? Let us make one. Only the public key ever reaches the workspace."}
            </small>
          </fieldset>}
          {!reproIntent && <fieldset className="form-fieldset">
            <legend>Runtime</legend>
            <div className="duration-picker">
              {[30, 60, 120, 360].map((minutes) => (
                <button className={duration === minutes * 60 ? "duration active" : "duration"} type="button" onClick={() => setDuration(minutes * 60)} key={minutes}>
                  {minutes < 60 ? `${minutes}m` : `${minutes / 60}h`}
                </button>
              ))}
            </div>
          </fieldset>}
          {!reproIntent && <fieldset className="form-fieldset">
            <legend>Minimum GPU memory</legend>
            <div className="duration-picker">
              {[16, 24, 40, 44].map((gib) => (
                <button
                  className={minVramMib === gib * 1_024 ? "duration active" : "duration"}
                  type="button"
                  onClick={() => setMinVramMib(gib * 1_024)}
                  key={gib}
                >
                  {gib} GB
                </button>
              ))}
            </div>
          </fieldset>}
          {!reproIntent && <div className="segmented" role="group" aria-label="Offer selection mode">
            <button type="button" className={mode === "auto" ? "active" : ""} onClick={() => setMode("auto")}>Auto-match</button>
            <button type="button" className={mode === "manual" ? "active" : ""} onClick={() => setMode("manual")}>Choose offer</button>
          </div>}
          {!reproIntent && mode === "manual" && (
            <label>
              GPU offer
              <select value={selected ?? ""} onChange={(event) => setSelected(event.target.value)} disabled={!eligibleOffers.length}>
                {!eligibleOffers.length && <option value="">No schedulable offers</option>}
                {eligibleOffers.map((item) => <option value={item.node_id} key={item.node_id}>{item.gpu.model} · {formatVram(item.gpu.vram_mib)} · {formatUsdPerHour(item.rate_per_second)} · {trustCopy[item.trust_class]?.label ?? item.trust_class}</option>)}
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
            <strong>Trust class · {offer ? trustCopy[offer.trust_class]?.label ?? offer.trust_class : "—"}</strong>
            <span>{offer ? trustCopy[offer.trust_class]?.detail ?? trustCopy.open.detail : trustCopy.open.detail}</span>
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
          <div className="quote-line"><span>Rate</span><strong>{offer ? formatUsdPerHour(offer.rate_per_second) : "—"}</strong></div>
          <div className="quote-line"><span>Trust class</span><strong>{offer ? trustCopy[offer.trust_class]?.label ?? offer.trust_class : "—"}</strong></div>
          <div className="quote-total"><span>Max escrow · USDG</span><strong>{maximum}</strong></div>
          {reproIntent && <div className="quote-line"><span>Signed ceiling</span><strong>{formatUsd(BigInt(reproIntent.maximum_escrow))}</strong></div>}
          <p className="muted">Charges begin after GPU readiness is confirmed. Unused escrow is returned after settlement.</p>
        </aside>
      </div>
      )}
    </section>
  );
}

async function readUsdgBalance(address: Address): Promise<bigint> {
  const client = createPublicClient({ chain: robinhoodChain, transport: http() });
  return client.readContract({ address: usdgAddress, abi: usdgAbi, functionName: "balanceOf", args: [address] });
}

function formatUsdg(baseUnits: bigint): string {
  return (Number(baseUnits) / 1_000_000).toFixed(6);
}

async function loadOffers(signal: AbortSignal): Promise<MarketplaceOffer[]> {
  const response = await fetch("/api/app/offers", { signal, cache: "no-store" });
  if (!response.ok) throw new Error("offers unavailable");
  const payload: unknown = await response.json();
  if (!Array.isArray(payload)) return [];
  // An unrecognised class reads as the weakest one, so a stale API can never
  // make a supplier look safer than it is.
  return payload.filter(isMarketplaceOffer).map((offer) => ({
    ...offer,
    trust_class: offer.trust_class in trustCopy ? offer.trust_class : "open",
  }));
}

async function requestMatch(
  image: string,
  duration_seconds: number,
  min_vram_mib: number,
  preferred_node_id: string | null,
  repro: ReproIntent | null,
): Promise<LeaseQuote> {
  const request = {
    image,
    duration_seconds,
    min_vram_mib,
    preferred_node_id,
    ...(repro ? {
      command: repro.command,
      repro: {
        token_hash: repro.token_hash,
        spec_hash: repro.spec_hash,
        expected_exit_code: repro.expected_exit_code,
        executor: repro.executor,
      },
    } : {}),
  };
  const response = await fetch("/api/app/leases/match", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request }),
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
    && offer.reliability_bps <= 10_000
    && (offer.staker_only === undefined || typeof offer.staker_only === "boolean");
}

function isLeaseQuote(value: unknown): value is LeaseQuote {
  if (!value || typeof value !== "object") return false;
  const quote = value as Partial<LeaseQuote>;
  return typeof quote.quote_id === "string"
    && /^[0-9a-f-]{36}$/i.test(quote.quote_id)
    && isBytes32(quote.node_id)
    && typeof quote.image === "string"
    && isPositiveInteger(quote.duration_seconds)
    && isPositiveInteger(quote.min_vram_mib)
    && isPositiveInteger(quote.rate_per_second)
    && isPositiveInteger(quote.maximum_escrow);
}

function assertReproQuote(quote: LeaseQuote, intent: ReproIntent) {
  if (quote.image !== intent.image
    || quote.command !== intent.command
    || quote.duration_seconds !== intent.duration_seconds
    || quote.min_vram_mib !== intent.min_vram_mib
    || BigInt(quote.maximum_escrow) > BigInt(intent.maximum_escrow)
    || quote.repro?.token_hash !== intent.token_hash
    || quote.repro?.spec_hash !== intent.spec_hash
    || quote.repro?.expected_exit_code !== intent.expected_exit_code
    || quote.repro?.executor !== intent.executor) {
    throw new Error("The live quote does not match the signed GPU repro or exceeds its cost ceiling.");
  }
}

async function confirmLease(quoteId: string, transactionHash: Hex, sshAuthorizedKey?: string) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const response = await fetch("/api/app/leases/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quote_id: quoteId,
        transaction_hash: transactionHash,
        ...(sshAuthorizedKey ? { ssh_authorized_key: sshAuthorizedKey } : {}),
      }),
    });
    if (response.ok) {
      const record: unknown = await response.json();
      if (!isLeaseConfirmation(record)) throw new Error("The lease confirmation response was invalid.");
      return record;
    }
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

async function loadReproIntent(envelope: string, signal: AbortSignal): Promise<ReproIntent> {
  const response = await fetch("/api/repro/intent", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ envelope }),
    cache: "no-store",
    signal,
  });
  if (!response.ok) {
    if (response.status === 410) throw new Error("This GPU repro approval link has expired. Ask Grok to prepare a new one.");
    throw new Error("This GPU repro approval link is invalid.");
  }
  const payload: unknown = await response.json();
  if (!isReproIntent(payload)) throw new Error("This GPU repro approval payload is invalid.");
  return payload;
}

async function loadReproProgress(leaseId: number): Promise<ReproProgress> {
  const leasesResponse = await fetch("/api/app/leases", { cache: "no-store" });
  if (!leasesResponse.ok) throw new Error("lease status unavailable");
  const leases: unknown = await leasesResponse.json();
  if (!Array.isArray(leases)) throw new Error("invalid lease status");
  const lease = leases.find((value) => (
    value && typeof value === "object" && (value as { lease_id?: unknown }).lease_id === leaseId
  ));
  if (!lease || typeof (lease as { state?: unknown }).state !== "string") {
    throw new Error("lease status unavailable");
  }

  const resultResponse = await fetch(`/api/app/leases/${leaseId}/result`, { cache: "no-store" });
  let result: CommandResult | null = null;
  if (resultResponse.ok) {
    const payload: unknown = await resultResponse.json();
    if (!isCommandResult(payload)) throw new Error("invalid repro result");
    result = payload;
  } else if (resultResponse.status !== 404) {
    throw new Error("repro result unavailable");
  }
  return { leaseState: (lease as { state: string }).state, result };
}

function isReproIntent(value: unknown): value is ReproIntent {
  if (!value || typeof value !== "object") return false;
  const intent = value as Partial<ReproIntent>;
  return intent.version === "prism.gpu-repro.intent.v2"
    && (intent.executor === "node" || intent.executor === "managed")
    && isPinnedPublicImage(intent.image ?? "")
    && isGpuReproCommand(intent.command ?? "")
    && isPositiveInteger(intent.duration_seconds)
    && isPositiveInteger(intent.min_vram_mib)
    && Number.isSafeInteger(intent.expected_exit_code)
    && Number(intent.expected_exit_code) >= 0
    && Number(intent.expected_exit_code) <= 255
    && typeof intent.maximum_escrow === "string"
    && /^[1-9][0-9]{0,19}$/.test(intent.maximum_escrow)
    && isDigest(intent.token_hash)
    && isDigest(intent.spec_hash)
    && Number.isSafeInteger(intent.issued_at)
    && Number.isSafeInteger(intent.expires_at);
}

function isCommandResult(value: unknown): value is CommandResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<CommandResult>;
  return Number.isSafeInteger(result.exit_code)
    && typeof result.stdout === "string"
    && typeof result.stderr === "string"
    && typeof result.truncated === "boolean";
}

function isLeaseConfirmation(value: unknown): value is { lease_id: number } {
  return Boolean(value)
    && typeof value === "object"
    && isPositiveInteger((value as { lease_id?: unknown }).lease_id);
}

function isTerminalLeaseState(state: string) {
  return ["closing", "settlement_pending", "disputed", "finalized", "refunded", "failed"].includes(state);
}

function isBytes32(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function formatUsd(baseUnits: bigint) {
  const cents = (baseUnits + 5_000n) / 10_000n;
  return `$${cents / 100n}.${(cents % 100n).toString().padStart(2, "0")}`;
}

function formatUsdPerHour(ratePerSecond: number) {
  return `${formatUsd(BigInt(ratePerSecond) * 3_600n)} / hour`;
}

async function sshKeygen(): Promise<{ publicKey: string; privateKey: string }> {
  const comment = "prism";
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32);
  const enc = new TextEncoder();
  const keytype = enc.encode("ssh-ed25519");
  const pubBlob = concatBytes(sshField(keytype), sshField(pub));
  const publicKey = `ssh-ed25519 ${base64(pubBlob)} ${comment}`;
  const check = crypto.getRandomValues(new Uint8Array(4));
  let priv = concatBytes(check, check, sshField(keytype), sshField(pub), sshField(concatBytes(seed, pub)), sshField(enc.encode(comment)));
  for (let pad = 1; priv.length % 8 !== 0; pad += 1) priv = concatBytes(priv, new Uint8Array([pad]));
  const blob = concatBytes(enc.encode("openssh-key-v1\0"), sshField(enc.encode("none")), sshField(enc.encode("none")), sshField(new Uint8Array(0)), uint32be(1), sshField(pubBlob), sshField(priv));
  const body = base64(blob).replace(/(.{70})/g, "$1\n");
  const label = "OPENSSH PRIVATE KEY";
  return { publicKey, privateKey: `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n` };
}

function uint32be(value: number) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function sshField(bytes: Uint8Array) {
  return concatBytes(uint32be(bytes.length), bytes);
}

function concatBytes(...parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function formatVram(vramMib: number) {
  return `${Math.round(vramMib / 1_024)} GB`;
}

function formatDuration(seconds: number) {
  const minutes = seconds / 60;
  return minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hours`;
}

function shortImageDigest(image: string) {
  const [repository, digest] = image.split("@sha256:");
  return `${repository}@sha256:${digest?.slice(0, 12)}…`;
}

function shortDigest(value: string) {
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}
