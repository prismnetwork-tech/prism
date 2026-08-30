use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use k256::ecdsa::{
    RecoveryId, Signature as EthereumSignature, VerifyingKey as EthereumVerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use thiserror::Error;
use uuid::Uuid;

pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const ROBINHOOD_TESTNET_CHAIN_ID: u64 = 46_630;
pub const USDG_MAINNET: &str = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
pub const MAX_ESCROW_BASE_UNITS: u64 = 50_000_000;
pub const MAX_LEASE_SECONDS: u32 = 21_600;
pub const MAX_NETWORK_LEASES: usize = 25;

/// PRISM staked long enough to count, mapped to what it takes off the quoted
/// rate. Locking the token is what earns cheaper compute; nothing else about a
/// lease changes, and a node is never paid less because a renter staked.
///
/// Thresholds are in whole tokens. The ceiling is deliberate: the discount is
/// funded out of the network's own margin, so it has to stay well inside it.
pub const STAKE_DISCOUNT_TIERS: [(u64, u16); 4] = [
    (1_000, 500),
    (10_000, 1_000),
    (50_000, 1_500),
    (250_000, 2_000),
];

/// No amount of stake may take more than this off a quote.
pub const MAX_STAKE_DISCOUNT_BPS: u16 = 2_000;

/// The published rate every renter can reach without staking, in USDG micros
/// per second. Capacity registered below this is reserved for stakers.
pub const STANDARD_RATE_PER_SECOND: u64 = 222;

/// What a staked balance takes off the quoted rate, in basis points.
pub fn stake_discount_bps(staked_whole_tokens: u64) -> u16 {
    let mut discount = 0;
    for (threshold, bps) in STAKE_DISCOUNT_TIERS {
        if staked_whole_tokens >= threshold {
            discount = bps;
        }
    }
    discount.min(MAX_STAKE_DISCOUNT_BPS)
}

/// Applies a discount to a rate, rounding in the renter's favour but never to
/// zero: a free lease still has to reserve a machine, and a rate of zero would
/// make the escrow's maximum meaningless.
pub fn discounted_rate(rate_per_second: u64, discount_bps: u16) -> u64 {
    let discount_bps = discount_bps.min(MAX_STAKE_DISCOUNT_BPS) as u64;
    if discount_bps == 0 || rate_per_second == 0 {
        return rate_per_second;
    }
    let reduced = rate_per_second.saturating_mul(10_000 - discount_bps) / 10_000;
    reduced.max(1)
}
const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-enrollment.v1\0";
const TELEMETRY_SIGNATURE_DOMAIN: &[u8] = b"prism.node-telemetry.v1\0";
const TUNNEL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-tunnel.v1\0";
const CERTIFICATE_SIGNATURE_DOMAIN: &[u8] = b"prism.node-certificate.v1\0";
const COMMAND_POLL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-poll.v1\0";
const COMMAND_REPORT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-report.v1\0";
const ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"prism.node-attestation.v1\0";
const GUEST_ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"prism.guest-attestation.v1\0";
const TDX_LEASE_ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"prism.tdx-lease-attestation.v1\0";
const GPU_CC_ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"prism.gpu-cc-attestation.v1\0";
const GPU_REPRO_SPEC_HASH_DOMAIN: &[u8] = b"prism-gpu-repro-spec-v1\0";
const GPU_REPRO_COMMAND_HASH_DOMAIN: &[u8] = b"prism-gpu-repro-command-v1\0";
const GPU_REPRO_RESULT_HASH_DOMAIN: &[u8] = b"prism-gpu-repro-result-v1\0";
const GPU_REPRO_REPORT_HASH_DOMAIN: &[u8] = b"prism-gpu-repro-report-v1\0";
const MANAGED_COMMAND_REPORT_SIGNATURE_DOMAIN: &[u8] = b"prism-managed-command-report-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub usd_token: String,
    pub rpc_url: String,
    pub explorer_url: String,
}

impl ChainConfig {
    pub fn mainnet(rpc_url: impl Into<String>) -> Self {
        Self {
            chain_id: ROBINHOOD_CHAIN_ID,
            usd_token: USDG_MAINNET.to_owned(),
            rpc_url: rpc_url.into(),
            explorer_url: "https://robinhoodchain.blockscout.com".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub subject: String,
    pub linked_wallets: Vec<String>,
    pub risk_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuSpec {
    pub model: String,
    pub vram_mib: u32,
    pub cuda_major: u16,
}

/// What a renter can rely on for a given offer, ordered from weakest to
/// strongest. Every level above `Open` must be earned from evidence the
/// control plane can check itself; a node cannot talk its way up.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Bonded identity and metered billing. The operator can read anything the
    /// workload touches.
    #[default]
    Open,
    /// Kata VM with exclusive VFIO passthrough and a digest-pinned public
    /// image. Narrows the attack surface; the host is still privileged.
    Isolated,
    /// The launch measurement of the renter's own guest, reported by that guest
    /// rather than by the machine hosting it: SNP assumes a hostile host and
    /// gives it no way to attest, so this says what the VM booted and nothing
    /// about who ran it.
    Attested,
    /// Guest memory and VRAM are encrypted against the host.
    Confidential,
}

/// The strongest class the network serves, whatever a node claims and whatever
/// a verifier grants. Moving it to `Attested` takes three things holding at
/// once: a reference launch measurement computed from inputs recorded with
/// their digests, a genuine Genoa report verifying as a checked-in vector, and
/// an access gate that hands out no credentials for a lease quoted above
/// `Isolated` without a lease-bound verdict. All three now hold. The reference
/// measurement is computed by `sev-snp-measure` from the firmware, kernel,
/// command line and vCPU count recorded beside it, and equals what the hardware
/// reported; `a_genuine_lease_report_earns_attested` verifies a real report from
/// the Genoa node, bound to a lease through REPORT_DATA and to the workload
/// through HOST_DATA; and the gateway refuses a grant above `Open` unless a
/// verdict for that lease on that node says the hardware earned it.
///
/// `Confidential` is the guest and the GPU together, and both halves now
/// verify. The guest half is a SEV-SNP or TDX report proving memory the host
/// cannot read. The GPU half is an NVIDIA CC attestation proving the card
/// holds VRAM in a single-GPU confidential mode, its confidential-mode flag
/// signed by the device and chaining to NVIDIA's Device Identity CA. A real
/// H100 CC report, captured from confidential silicon, verifies its signature
/// chain and its confidential-mode flag as a checked-in vector, short only of
/// a lease-bound nonce and a driver-exact measurement match, the same way the
/// genuine Genoa report earns everything but its lease binding.
/// [`class_for_lease`] grants `Confidential` only with both verdicts present,
/// and the clamp below is what stops either half being served past what the
/// evidence earns.
pub const MAX_VERIFIABLE_TRUST_CLASS: TrustClass = TrustClass::Confidential;

impl TrustClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Isolated => "isolated",
            Self::Attested => "attested",
            Self::Confidential => "confidential",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationMode {
    #[default]
    Shared,
    KataVfio,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    SevSnp,
    Tdx,
    NvidiaCc,
    /// An H100 device report: it proves which GPU signed and what firmware it
    /// runs, and says nothing about the host software that booted.
    NvidiaGpu,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationRef {
    pub kind: AttestationKind,
    pub quote_sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodePosture {
    pub isolation: IsolationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationRef>,
}

impl NodePosture {
    /// The strongest class this posture could ever back, before any evidence is
    /// checked. Attestation deliberately does not lift it: a quote digest the
    /// control plane never receives is a claim, and a claim must not reach past
    /// `Isolated`. Anything above comes from [`class_for_verdict`].
    pub fn claimed_class(&self) -> TrustClass {
        match self.isolation {
            IsolationMode::Shared => TrustClass::Open,
            IsolationMode::KataVfio => TrustClass::Isolated,
        }
    }

    #[deprecated(note = "use class_for_verdict")]
    pub fn effective_class(&self) -> TrustClass {
        self.claimed_class().min(MAX_VERIFIABLE_TRUST_CLASS)
    }
}

/// What the host's TEE stack can actually do, reported as it is found rather
/// than collapsed into a single flag. Kernel 6.8 has SEV and SEV-ES but no
/// SEV-SNP host support, and that has to be distinguishable from a machine with
/// no TEE at all: one is a rung away, the other is not.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostTeeCapability {
    pub sev: bool,
    pub sev_es: bool,
    pub sev_snp: bool,
    pub sev_guest_device: bool,
    pub kata_runtime: bool,
    pub kata_confidential_runtime: bool,
}

/// A one-shot nonce the control plane hands out and consumes. Without it a node
/// could replay a report it captured once, or relay one taken from a machine it
/// does not own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationChallenge {
    pub challenge_id: Uuid,
    pub node_id: String,
    /// 32 random bytes, hex.
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Base64 of an SPDM measurement response and its opaque data. Comfortably
/// above an H100 report and far below the 256 KiB request body limit.
pub const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 64 * 1_024;
pub const MAX_ATTESTATION_CERTIFICATE_BYTES: usize = 16 * 1_024;
/// NVIDIA's device chain is leaf to root in four hops. Bounding the count is
/// what keeps evidence plus certificates inside the body limit.
pub const MAX_ATTESTATION_CERTIFICATES: usize = 8;

/// One entry of a dstack runtime event log, carried beside a TDX quote in the
/// wire shape the guest agent reports it. The verifier judges it (the fold
/// across digests has to land on the registers the quote signed), so nothing
/// here is trusted as received; the caps below only bound what a body may
/// cost to look at.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TdxEventEntry {
    pub imr: u32,
    pub event_type: u32,
    pub event: String,
    /// 48 bytes, hex.
    pub digest: String,
    /// Hex; empty for events that carry no payload.
    pub event_payload: String,
}

/// A dstack boot logs around thirty events; the cap leaves room for runtime
/// extensions without letting a log become the expensive part of a request.
pub const MAX_TDX_EVENT_LOG_ENTRIES: usize = 256;
pub const MAX_TDX_EVENT_PAYLOAD_BYTES: usize = 4 * 1_024;
/// A full Intel collateral bundle runs around 25 KiB; the cap bounds a body
/// well before the request limit without ever pinching a real one.
pub const MAX_TDX_COLLATERAL_BYTES: usize = 128 * 1_024;

pub const TDX_REPORT_DATA_DOMAIN: &[u8] = b"prism.tdx.report-data.v1\0";
pub const TDX_LEASE_REPORT_DATA_DOMAIN: &[u8] = b"prism.tdx.lease-report-data.v1\0";

/// The `REPORT_DATA` a TD quotes for one lease. The lease id is in the digest
/// because a quote taken for one renter's session must not be presentable for
/// another's; the guest channel key is in it for the reason it is in the
/// SEV-SNP report data, so the quote proves the renter's own session
/// terminates inside the measured TD rather than that some measured TD merely
/// booted on the node. SHA-512 fills all 64 bytes.
pub fn tdx_lease_report_data(
    challenge_nonce: &[u8],
    lease_id: u64,
    node_id: &str,
    guest_channel_key: &str,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(TDX_LEASE_REPORT_DATA_DOMAIN);
    hasher.update(challenge_nonce);
    hasher.update(lease_id.to_be_bytes());
    hasher.update(node_id.as_bytes());
    hasher.update(guest_channel_key.as_bytes());
    let mut report_data = [0_u8; 64];
    report_data.copy_from_slice(&hasher.finalize());
    report_data
}

/// REPORT_DATA is the only field of a TDX quote the guest chooses. Binding the
/// control plane's nonce to the node id and the device key ties the quote to
/// one enrollment the way [`attestation_report_nonce`] ties a GPU report to
/// one: a quote relayed from another TD, or taken for another challenge,
/// hashes to something else and fails. SHA-512 fills all 64 bytes.
pub fn tdx_report_data(challenge_nonce: &[u8], node_id: &str, device_public_key: &str) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(TDX_REPORT_DATA_DOMAIN);
    hasher.update(challenge_nonce);
    hasher.update(node_id.as_bytes());
    hasher.update(device_public_key.as_bytes());
    let mut report_data = [0_u8; 64];
    report_data.copy_from_slice(&hasher.finalize());
    report_data
}

/// The value the GPU signs over. Binding the control plane's nonce to the node
/// id and the device key is the only thing tying a vendor signature to one
/// identity: a report relayed from another machine hashes to something else and
/// fails. The node and the verifier both call this, so it lives in one place.
pub fn attestation_report_nonce(
    challenge_nonce: &[u8],
    node_id: &str,
    device_public_key: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge_nonce);
    hasher.update(node_id.as_bytes());
    hasher.update(device_public_key.as_bytes());
    hasher.finalize().into()
}

/// Attestation evidence travels here, on its own signed envelope against a
/// challenge, and never on telemetry: the heartbeat's canonical bytes are
/// already signed by deployed nodes, and a multi-kilobyte chain has no business
/// on a thirty-second loop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeAttestation {
    pub node_id: String,
    pub challenge_id: Uuid,
    pub kind: AttestationKind,
    pub evidence_base64: String,
    pub certificate_chain_base64: Vec<String>,
    /// TDX evidence only: the runtime event log the verifier replays against
    /// the quoted registers. Empty for every other kind, and absent from the
    /// canonical payload when empty, so attestations signed before the field
    /// existed still verify.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tdx_event_log: Vec<TdxEventEntry>,
    /// TDX evidence only: the Intel collateral (TCB info, QE identity, CRLs)
    /// the quote verifies against, fetched by the node from a PCCS. Nothing
    /// in it is taken on the node's word: every piece is Intel-signed and the
    /// verifier enforces its validity windows, so the most a node choosing
    /// its own collateral can do is present the newest material Intel had
    /// already published, which is the same exposure a caching fetcher has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_collateral_json: Option<String>,
    pub capability: HostTeeCapability,
    pub pci_address: String,
    pub collected_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNodeAttestation {
    pub node_id: String,
    pub challenge_id: Uuid,
    pub kind: AttestationKind,
    pub evidence_base64: String,
    pub certificate_chain_base64: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tdx_event_log: Vec<TdxEventEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_collateral_json: Option<String>,
    pub capability: HostTeeCapability,
    pub pci_address: String,
    pub collected_at: DateTime<Utc>,
}

impl NodeAttestation {
    pub fn sign(
        unsigned: UnsignedNodeAttestation,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(ATTESTATION_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        let attestation = Self {
            node_id: unsigned.node_id,
            challenge_id: unsigned.challenge_id,
            kind: unsigned.kind,
            evidence_base64: unsigned.evidence_base64,
            certificate_chain_base64: unsigned.certificate_chain_base64,
            tdx_event_log: unsigned.tdx_event_log,
            tdx_collateral_json: unsigned.tdx_collateral_json,
            capability: unsigned.capability,
            pci_address: unsigned.pci_address,
            collected_at: unsigned.collected_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeAttestation {
                node_id: self.node_id.clone(),
                challenge_id: self.challenge_id,
                kind: self.kind,
                evidence_base64: self.evidence_base64.clone(),
                certificate_chain_base64: self.certificate_chain_base64.clone(),
                tdx_event_log: self.tdx_event_log.clone(),
                tdx_collateral_json: self.tdx_collateral_json.clone(),
                capability: self.capability,
                pci_address: self.pci_address.clone(),
                collected_at: self.collected_at,
            },
            &self.signature,
            key,
            ATTESTATION_SIGNATURE_DOMAIN,
        )
    }

    /// Checked before a signature is even looked at, so a body that would cost
    /// more to parse than to reject never gets that far.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.node_id.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.evidence_base64.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.evidence_base64.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self.certificate_chain_base64.len() > MAX_ATTESTATION_CERTIFICATES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .certificate_chain_base64
            .iter()
            .any(|certificate| certificate.len() > MAX_ATTESTATION_CERTIFICATE_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self.tdx_event_log.len() > MAX_TDX_EVENT_LOG_ENTRIES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .tdx_collateral_json
            .as_ref()
            .is_some_and(|collateral| collateral.len() > MAX_TDX_COLLATERAL_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .tdx_event_log
            .iter()
            .any(|entry| entry.event_payload.len() > MAX_TDX_EVENT_PAYLOAD_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        Ok(())
    }
}

/// What the control plane concluded after walking the chain itself. A node
/// never produces one of these.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationVerdict {
    pub node_id: String,
    pub kind: AttestationKind,
    /// The attested device as the verifier read it off the leaf certificate,
    /// subject plus board serial. Indexed uniquely, so one physical GPU cannot
    /// back two node ids.
    pub device_identity: String,
    pub measurement_digest: String,
    /// What the node said about its own TEE support, carried for diagnostics
    /// and named for what it is. Nothing verifies it and nothing may grant a
    /// class from it: a host that lies here is caught by no check in this
    /// crate.
    pub claimed_capability: HostTeeCapability,
    pub granted_class: TrustClass,
    pub verifier_version: String,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn verdict_digest(verdict: &AttestationVerdict) -> Result<String, ProtocolError> {
    Ok(hex::encode(Sha256::digest(canonical_json(verdict)?)))
}

/// The class a node is served at. Every input is something the control plane
/// checked: a live tunnel it registered, a posture it confirmed, and a verdict
/// it reached by verifying evidence against a pinned vendor root. Nothing a
/// node asserts about itself is consulted, and the answer is clamped to what
/// the network can substantiate today.
pub fn class_for_verdict(
    node_id: &str,
    tunneled: bool,
    posture: Option<&NodePosture>,
    verdict: Option<&AttestationVerdict>,
    now: DateTime<Utc>,
) -> TrustClass {
    let class = match (tunneled, verdict) {
        (false, _) | (_, None) => TrustClass::Open,
        // A verdict names the node it was reached for. Checking that here, in
        // the one function that turns evidence into a class, means a caller
        // that pairs the wrong verdict with a node grants nothing rather than
        // granting someone else's.
        (true, Some(verdict)) if verdict.node_id != node_id => TrustClass::Open,
        (true, Some(verdict)) if verdict.expires_at <= now => TrustClass::Open,
        (true, Some(verdict)) => {
            let isolated =
                posture.is_some_and(|posture| posture.isolation == IsolationMode::KataVfio);
            match verdict.kind {
                AttestationKind::NvidiaGpu
                    if isolated && verdict.granted_class >= TrustClass::Isolated =>
                {
                    TrustClass::Isolated
                }
                // A TDX verdict needs no posture beside it: the boundary it
                // earns Isolated for is the TD itself, proven by the quote,
                // not a host-side claim about a runtime. The verifier only
                // mints one after the event log bound the node's compose
                // file, so what runs inside that boundary is pinned the way
                // the Kata image is.
                AttestationKind::Tdx if verdict.granted_class >= TrustClass::Isolated => {
                    TrustClass::Isolated
                }
                _ => TrustClass::Open,
            }
        }
    };
    class.min(MAX_VERIFIABLE_TRUST_CLASS)
}

pub const SNP_REPORT_DATA_DOMAIN: &[u8] = b"prism.snp.report-data.v1\0";

/// REPORT_DATA is the only field of an SNP report the guest chooses; the host
/// picks or influences the rest. The lease id is in here because a report taken
/// for one renter must not be presentable for another's session, and the
/// channel key is in here because a correctly measured VM somewhere on the
/// machine proves nothing about the box the renter's client actually terminates
/// on. SHA-512 fills all 64 bytes, which leaves the host no room to choose any
/// of them.
pub fn snp_report_data(challenge_nonce: &[u8], lease_id: u64, guest_channel_key: &str) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(SNP_REPORT_DATA_DOMAIN);
    hasher.update(challenge_nonce);
    hasher.update(lease_id.to_be_bytes());
    hasher.update(guest_channel_key.as_bytes());
    let mut report_data = [0_u8; 64];
    report_data.copy_from_slice(&hasher.finalize());
    report_data
}

/// An SNP report is 1184 bytes, so base64 of one lands near 1.6 KiB. The cap is
/// well clear of that and nowhere near the request body limit.
pub const MAX_SNP_REPORT_BYTES: usize = 4 * 1_024;

/// A report the guest running a lease took of itself, carried to the control
/// plane by the host. The envelope is signed by the node's device key rather
/// than by anything inside the guest: the host is a courier here, and it cannot
/// forge the report it is carrying, so its signature only has to say which node
/// is presenting this one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub kind: AttestationKind,
    pub report_base64: String,
    pub certificate_chain_base64: Vec<String>,
    /// The OpenSSH public key line the guest generated for this lease.
    pub guest_channel_key: String,
    pub collected_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedGuestAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub kind: AttestationKind,
    pub report_base64: String,
    pub certificate_chain_base64: Vec<String>,
    pub guest_channel_key: String,
    pub collected_at: DateTime<Utc>,
}

impl GuestAttestation {
    pub fn sign(
        unsigned: UnsignedGuestAttestation,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(GUEST_ATTESTATION_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        let attestation = Self {
            node_id: unsigned.node_id,
            lease_id: unsigned.lease_id,
            challenge_id: unsigned.challenge_id,
            kind: unsigned.kind,
            report_base64: unsigned.report_base64,
            certificate_chain_base64: unsigned.certificate_chain_base64,
            guest_channel_key: unsigned.guest_channel_key,
            collected_at: unsigned.collected_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedGuestAttestation {
                node_id: self.node_id.clone(),
                lease_id: self.lease_id,
                challenge_id: self.challenge_id,
                kind: self.kind,
                report_base64: self.report_base64.clone(),
                certificate_chain_base64: self.certificate_chain_base64.clone(),
                guest_channel_key: self.guest_channel_key.clone(),
                collected_at: self.collected_at,
            },
            &self.signature,
            key,
            GUEST_ATTESTATION_SIGNATURE_DOMAIN,
        )
    }

    /// Checked before a signature is even looked at, so a body that would cost
    /// more to parse than to reject never gets that far.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.node_id.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        // A report that names no lease binds to no session, which is the whole
        // point of taking it inside the guest.
        if self.lease_id == 0 {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.report_base64.is_empty() || self.guest_channel_key.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.report_base64.len() > MAX_SNP_REPORT_BYTES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self.certificate_chain_base64.len() > MAX_ATTESTATION_CERTIFICATES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .certificate_chain_base64
            .iter()
            .any(|certificate| certificate.len() > MAX_ATTESTATION_CERTIFICATE_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        Ok(())
    }
}

/// A TDX quote a leased CVM took of itself, carried to the control plane by the
/// host beside the runtime event log and Intel collateral the verifier needs to
/// judge it. Like `GuestAttestation`, the host signs only as the courier that
/// says which node is presenting this; it cannot forge a quote the TD sealed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TdxLeaseAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub quote_base64: String,
    pub tdx_event_log: Vec<TdxEventEntry>,
    /// Intel PCS collateral bundle as JSON, so the verifier need not fetch it.
    pub tdx_collateral_json: String,
    /// The OpenSSH public key line the TD generated for this lease, bound into
    /// the quote's report data so the renter can pin the session's endpoint.
    pub guest_channel_key: String,
    pub collected_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedTdxLeaseAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub quote_base64: String,
    pub tdx_event_log: Vec<TdxEventEntry>,
    pub tdx_collateral_json: String,
    pub guest_channel_key: String,
    pub collected_at: DateTime<Utc>,
}

impl TdxLeaseAttestation {
    pub fn sign(
        unsigned: UnsignedTdxLeaseAttestation,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(TDX_LEASE_ATTESTATION_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        let attestation = Self {
            node_id: unsigned.node_id,
            lease_id: unsigned.lease_id,
            challenge_id: unsigned.challenge_id,
            quote_base64: unsigned.quote_base64,
            tdx_event_log: unsigned.tdx_event_log,
            tdx_collateral_json: unsigned.tdx_collateral_json,
            guest_channel_key: unsigned.guest_channel_key,
            collected_at: unsigned.collected_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedTdxLeaseAttestation {
                node_id: self.node_id.clone(),
                lease_id: self.lease_id,
                challenge_id: self.challenge_id,
                quote_base64: self.quote_base64.clone(),
                tdx_event_log: self.tdx_event_log.clone(),
                tdx_collateral_json: self.tdx_collateral_json.clone(),
                guest_channel_key: self.guest_channel_key.clone(),
                collected_at: self.collected_at,
            },
            &self.signature,
            key,
            TDX_LEASE_ATTESTATION_SIGNATURE_DOMAIN,
        )
    }

    /// Checked before a signature is even looked at, so a body that would cost
    /// more to parse than to reject never gets that far.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.node_id.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        // A quote that names no lease binds to no session, which is the whole
        // point of taking it inside the guest.
        if self.lease_id == 0 {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.quote_base64.is_empty() || self.guest_channel_key.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.quote_base64.len() > MAX_ATTESTATION_EVIDENCE_BYTES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self.tdx_event_log.len() > MAX_TDX_EVENT_LOG_ENTRIES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .tdx_event_log
            .iter()
            .any(|entry| entry.event_payload.len() > MAX_TDX_EVENT_PAYLOAD_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self.tdx_collateral_json.len() > MAX_TDX_COLLATERAL_BYTES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        Ok(())
    }
}

/// An NVIDIA confidential-computing report is a GPU attestation report plus its
/// device certificate chain, so the ceiling has to clear a real one without
/// letting a body run away. A CC report runs a few kilobytes.
pub const MAX_GPU_CC_REPORT_BYTES: usize = 32 * 1_024;

/// A GPU confidential-computing report a leased node took of its accelerators,
/// carried to the control plane by the host. Same courier model as the other
/// lease attestations: the host says which node is presenting the report, the
/// device signs the report itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuCcAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub report_base64: String,
    pub certificate_chain_base64: Vec<String>,
    pub collected_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedGpuCcAttestation {
    pub node_id: String,
    pub lease_id: u64,
    pub challenge_id: Uuid,
    pub report_base64: String,
    pub certificate_chain_base64: Vec<String>,
    pub collected_at: DateTime<Utc>,
}

impl GpuCcAttestation {
    pub fn sign(
        unsigned: UnsignedGpuCcAttestation,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(GPU_CC_ATTESTATION_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        let attestation = Self {
            node_id: unsigned.node_id,
            lease_id: unsigned.lease_id,
            challenge_id: unsigned.challenge_id,
            report_base64: unsigned.report_base64,
            certificate_chain_base64: unsigned.certificate_chain_base64,
            collected_at: unsigned.collected_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedGpuCcAttestation {
                node_id: self.node_id.clone(),
                lease_id: self.lease_id,
                challenge_id: self.challenge_id,
                report_base64: self.report_base64.clone(),
                certificate_chain_base64: self.certificate_chain_base64.clone(),
                collected_at: self.collected_at,
            },
            &self.signature,
            key,
            GPU_CC_ATTESTATION_SIGNATURE_DOMAIN,
        )
    }

    /// Checked before a signature is even looked at, so a body that would cost
    /// more to parse than to reject never gets that far.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.node_id.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.lease_id == 0 {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.report_base64.is_empty() {
            return Err(ProtocolError::InvalidAttestation);
        }
        if self.report_base64.len() > MAX_GPU_CC_REPORT_BYTES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        // NVIDIA's device chain is five hops; the shared ceiling leaves headroom
        // without letting a chain become the expensive part of a request.
        if self.certificate_chain_base64.len() > MAX_ATTESTATION_CERTIFICATES {
            return Err(ProtocolError::AttestationTooLarge);
        }
        if self
            .certificate_chain_base64
            .iter()
            .any(|certificate| certificate.len() > MAX_ATTESTATION_CERTIFICATE_BYTES)
        {
            return Err(ProtocolError::AttestationTooLarge);
        }
        Ok(())
    }
}

/// The TCB the VCEK that signed a report was issued against. Kept as four
/// numbers rather than one packed word because the encoding is per product
/// line: Turin packs these differently, so a second CPU generation needs its
/// own floor rather than a widened one.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnpTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// What the verifier read out of a report it walked to the AMD root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestedGuest {
    /// The launch digest over the initial image, its guest physical layout,
    /// page types and per-vCPU VMSA. It is only meaningful against a reference
    /// value computed from published inputs, never against one read off the
    /// machine being attested.
    pub measurement: String,
    pub host_data: String,
    /// sha256 of CHIP_ID. The raw value names a physical machine and receipts
    /// are pseudonymous, so it stays in the verifier.
    pub chip_id_digest: String,
    pub reported_tcb: SnpTcb,
    pub policy_debug: bool,
    pub vmpl: u32,
    pub channel_key_fingerprint: String,
    /// The container digest the measured guest agent will run, taken from
    /// HOST_DATA. The host fixes this at launch and cannot change it after, but
    /// it is still a host input: it means something only because the agent
    /// inside the measured image refuses to run anything else.
    pub image_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseAttestationVerdict {
    pub lease_id: u64,
    pub node_id: String,
    pub kind: AttestationKind,
    pub guest: AttestedGuest,
    pub granted_class: TrustClass,
    pub verifier_version: String,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn lease_verdict_digest(verdict: &LeaseAttestationVerdict) -> Result<String, ProtocolError> {
    Ok(hex::encode(Sha256::digest(canonical_json(verdict)?)))
}

/// What the control plane concluded about the GPU serving one lease: a real
/// NVIDIA CC attestation, verified against the device root, said the card
/// holds VRAM in a single-GPU confidential mode for this lease. It is kept
/// apart from [`LeaseAttestationVerdict`] rather than folded into it because
/// the guest report and the GPU report answer different questions and carry
/// different fields; conflating them would mean a GPU verdict carrying empty
/// SEV-SNP columns nobody set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseGpuCcVerdict {
    pub lease_id: u64,
    pub node_id: String,
    pub kind: AttestationKind,
    /// The device as the verifier read it off the leaf certificate, its common
    /// name and the firmware identity the report is bound to.
    pub device_identity: String,
    pub measurement_digest: String,
    pub granted_class: TrustClass,
    pub verifier_version: String,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn lease_gpu_cc_verdict_digest(verdict: &LeaseGpuCcVerdict) -> Result<String, ProtocolError> {
    Ok(hex::encode(Sha256::digest(canonical_json(verdict)?)))
}

/// What the control plane concluded about the guest of one lease from a TDX
/// quote: the lease runs inside a genuine TD, launched from a known image,
/// bound to this lease through the quote's report data. It is the TDX
/// counterpart of the SEV-SNP guest half of [`LeaseAttestationVerdict`], kept
/// as its own type because a TD's evidence is an image measurement and a
/// runtime-register binding, not the SEV-SNP chip and VMSA columns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseTdxGuestVerdict {
    pub lease_id: u64,
    pub node_id: String,
    pub kind: AttestationKind,
    /// The instance identity the TD extended into RTMR3, unique per deployment.
    pub device_identity: String,
    /// The compose file the event log bound the TD to.
    pub compose_hash: String,
    /// The fingerprint of the guest channel key bound into the quote, so the
    /// renter can pin the endpoint their session terminates on.
    pub channel_key_fingerprint: String,
    pub measurement_digest: String,
    pub granted_class: TrustClass,
    pub verifier_version: String,
    pub verified_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn lease_tdx_guest_verdict_digest(
    verdict: &LeaseTdxGuestVerdict,
) -> Result<String, ProtocolError> {
    Ok(hex::encode(Sha256::digest(canonical_json(verdict)?)))
}

/// The class one lease is served at. A guest report is evidence about a single
/// VM, so it lifts a single lease and never the node: an operator who boots the
/// blessed image once and serves everyone else from a bare container gets
/// nothing out of it.
///
/// The two verdicts are two different claims, and the split is the point.
/// `guest_verdict` is the measured, memory-encrypted guest itself, reported
/// from inside (SEV-SNP or TDX); it carries a lease to `Attested`.
/// `gpu_cc_verdict` is an NVIDIA CC report saying the GPU serving this lease
/// holds VRAM in confidential mode; it means nothing alone, because encrypted
/// VRAM behind an unmeasured host is a locked door in an open wall.
/// `Confidential` is what both claims earn together, and only together:
/// guest memory and VRAM, which is what the word promises.
pub fn class_for_lease(
    lease_id: u64,
    node_id: &str,
    node_class: TrustClass,
    guest_verdict: Option<&LeaseAttestationVerdict>,
    tdx_guest_verdict: Option<&LeaseTdxGuestVerdict>,
    gpu_cc_verdict: Option<&LeaseGpuCcVerdict>,
    now: DateTime<Utc>,
) -> TrustClass {
    let guest_bound = |verdict: &&LeaseAttestationVerdict| {
        verdict.lease_id == lease_id && verdict.node_id == node_id && verdict.expires_at > now
    };
    let tdx_bound = |verdict: &&LeaseTdxGuestVerdict| {
        verdict.lease_id == lease_id && verdict.node_id == node_id && verdict.expires_at > now
    };
    let gpu_bound = |verdict: &&LeaseGpuCcVerdict| {
        verdict.lease_id == lease_id && verdict.node_id == node_id && verdict.expires_at > now
    };

    // The node must already stand at `Isolated`, because a guest report says
    // nothing about the bonded identity, the live tunnel or the GPU
    // underneath it and cannot stand in for them. Either guest kind proves the
    // same thing on its own silicon: a SEV-SNP guest report or a TDX quote,
    // each bound to this lease and each earning Attested.
    let snp_attested = guest_verdict.filter(guest_bound).is_some_and(|verdict| {
        verdict.kind == AttestationKind::SevSnp && verdict.granted_class >= TrustClass::Attested
    });
    let tdx_attested = tdx_guest_verdict.filter(tdx_bound).is_some_and(|verdict| {
        verdict.kind == AttestationKind::Tdx && verdict.granted_class >= TrustClass::Attested
    });
    let guest_attested = (snp_attested || tdx_attested) && node_class >= TrustClass::Isolated;
    let vram_confidential = gpu_cc_verdict.filter(gpu_bound).is_some_and(|verdict| {
        verdict.kind == AttestationKind::NvidiaCc
            && verdict.granted_class >= TrustClass::Confidential
    });

    let class = if guest_attested && vram_confidential {
        TrustClass::Confidential
    } else if guest_attested {
        TrustClass::Attested
    } else {
        node_class
    };
    class.min(MAX_VERIFIABLE_TRUST_CLASS)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeOffer {
    pub node_id: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub device_public_key: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub reliability_bps: u16,
    pub benchmark_score: u32,
    pub bonded: bool,
    pub online: bool,
    pub public_image_only: bool,
    #[serde(default)]
    pub trust_class: TrustClass,
    /// Capacity set aside for renters who stake PRISM. Marked explicitly by
    /// whoever enrolls it rather than inferred from price, so an independent
    /// operator who simply prices low is never hidden from ordinary renters.
    #[serde(default)]
    pub staker_only: bool,
    /// Whether the node is polling the signed command channel. Derived on every
    /// read from the polls the node itself made, never from what it enrolled
    /// with, so a node that goes quiet stops taking batch work on its own.
    #[serde(default)]
    pub command_channel: bool,
    /// Whether this offer currently has brokered capacity behind the managed
    /// repro runner. Like `command_channel`, callers must treat this as a
    /// short-lived observation rather than an enrollment claim.
    #[serde(default)]
    pub managed_batch: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEnrollment {
    pub node_id: String,
    pub device_public_key: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub benchmark_score: u32,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNodeEnrollment {
    pub node_id: String,
    pub device_public_key: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub benchmark_score: u32,
    pub issued_at: DateTime<Utc>,
}

impl NodeEnrollment {
    pub fn sign(unsigned: UnsignedNodeEnrollment, key: &SigningKey) -> Result<Self, ProtocolError> {
        let payload = signature_payload(ENROLLMENT_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            operator_wallet: unsigned.operator_wallet,
            payout_wallet: unsigned.payout_wallet,
            gpu: unsigned.gpu,
            rate_per_second: unsigned.rate_per_second,
            benchmark_score: unsigned.benchmark_score,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeEnrollment {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                operator_wallet: self.operator_wallet.clone(),
                payout_wallet: self.payout_wallet.clone(),
                gpu: self.gpu.clone(),
                rate_per_second: self.rate_per_second,
                benchmark_score: self.benchmark_score,
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            ENROLLMENT_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeTelemetry {
    pub node_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub gpu_utilization_bps: u16,
    pub gpu_memory_used_mib: u32,
    pub active_lease: Option<String>,
    pub tunnel_connected: bool,
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<NodePosture>,
    pub signature: String,
}

/// Skipping `posture` when absent keeps the canonical payload byte-identical
/// to the pre-posture format, so nodes running older builds still verify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedTelemetry {
    pub node_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub gpu_utilization_bps: u16,
    pub gpu_memory_used_mib: u32,
    pub active_lease: Option<String>,
    pub tunnel_connected: bool,
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<NodePosture>,
}

impl NodeTelemetry {
    pub fn sign(unsigned: UnsignedTelemetry, key: &SigningKey) -> Result<Self, ProtocolError> {
        let payload = signature_payload(TELEMETRY_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            sequence: unsigned.sequence,
            observed_at: unsigned.observed_at,
            gpu_utilization_bps: unsigned.gpu_utilization_bps,
            gpu_memory_used_mib: unsigned.gpu_memory_used_mib,
            active_lease: unsigned.active_lease,
            tunnel_connected: unsigned.tunnel_connected,
            image_digest: unsigned.image_digest,
            posture: unsigned.posture,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedTelemetry {
                node_id: self.node_id.clone(),
                sequence: self.sequence,
                observed_at: self.observed_at,
                gpu_utilization_bps: self.gpu_utilization_bps,
                gpu_memory_used_mib: self.gpu_memory_used_mib,
                active_lease: self.active_lease.clone(),
                tunnel_connected: self.tunnel_connected,
                image_digest: self.image_digest.clone(),
                posture: self.posture.clone(),
            },
            &self.signature,
            key,
            TELEMETRY_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelRegistration {
    pub node_id: String,
    pub device_public_key: String,
    pub connection_id: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedTunnelRegistration {
    pub node_id: String,
    pub device_public_key: String,
    pub connection_id: String,
    pub issued_at: DateTime<Utc>,
}

impl TunnelRegistration {
    pub fn sign(
        unsigned: UnsignedTunnelRegistration,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(TUNNEL_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            connection_id: unsigned.connection_id,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedTunnelRegistration {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                connection_id: self.connection_id.clone(),
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            TUNNEL_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCertificateRequest {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub csr_pem: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNodeCertificateRequest {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub csr_pem: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCertificateBundle {
    pub certificate_id: Uuid,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub fingerprint_sha256: String,
    pub expires_at: DateTime<Utc>,
}

impl NodeCertificateRequest {
    pub fn sign(
        unsigned: UnsignedNodeCertificateRequest,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let signature = key.sign(&signature_payload(CERTIFICATE_SIGNATURE_DOMAIN, &unsigned)?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            csr_pem: unsigned.csr_pem,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeCertificateRequest {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                csr_pem: self.csr_pem.clone(),
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            CERTIFICATE_SIGNATURE_DOMAIN,
        )
    }
}

/// The exact workload a repro capability authorizes. Its field order is part
/// of the v1 hash contract and must not change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuReproSpec {
    pub image: String,
    pub command: String,
    pub duration_seconds: u32,
    pub min_vram_mib: u32,
    pub expected_exit_code: i32,
}

impl GpuReproSpec {
    pub fn hash(&self) -> Result<String, ProtocolError> {
        gpu_repro_spec_hash(self)
    }
}

/// A bearer capability reduced to public commitments. The token itself never
/// enters a quote, lease record, settlement artifact or proof feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproCapability {
    pub token_hash: String,
    pub spec_hash: String,
    pub expected_exit_code: i32,
    pub executor: ReproExecutor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRequest {
    pub image: String,
    pub duration_seconds: u32,
    pub min_vram_mib: u32,
    pub preferred_node_id: Option<String>,
    #[serde(default)]
    pub min_trust_class: TrustClass,
    /// Present when the renter wants one command run instead of a session they
    /// log into. A batch lease is priced, escrowed and settled exactly like an
    /// interactive one; only what happens on the node differs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<ReproCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseQuote {
    pub quote_id: Uuid,
    pub node_id: String,
    pub image: String,
    pub duration_seconds: u32,
    pub min_vram_mib: u32,
    pub rate_per_second: u64,
    pub maximum_escrow: u64,
    #[serde(default)]
    pub trust_class: TrustClass,
    /// Carried from the request so the command a renter is quoted for is the
    /// command that actually runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<ReproCapability>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Funded,
    Provisioning,
    Ready,
    Active,
    Closing,
    SettlementPending,
    Disputed,
    Finalized,
    Refunded,
    Failed,
}

impl LeaseState {
    /// Whether a lease standing here could still hand out credentials. False
    /// once it is closing or settled, which is what lets a caller stop waiting
    /// for access that is never coming rather than poll until its own timeout.
    pub fn can_still_open_access(&self) -> bool {
        matches!(
            self,
            Self::Funded | Self::Provisioning | Self::Ready | Self::Active
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRecord {
    pub lease_id: u64,
    /// What the escrow numbered this lease. A counter restarts whenever the
    /// escrow is replaced, so it is only unique alongside `escrow_address`, and
    /// `lease_id` is what everything internal keys on. Every chain call about
    /// this lease has to use this value, never `lease_id`.
    #[serde(default)]
    pub chain_lease_id: u64,
    #[serde(default)]
    pub escrow_address: String,
    pub quote_id: Uuid,
    pub node_id: String,
    pub renter_wallet: String,
    pub image: String,
    pub duration_seconds: u32,
    pub rate_per_second: u64,
    pub maximum_escrow: u64,
    #[serde(default)]
    pub trust_class: TrustClass,
    pub funding_transaction_hash: String,
    pub state: LeaseState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<ReproCapability>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommand {
    pub command_id: Uuid,
    pub node_id: String,
    pub lease_id: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub kind: NodeCommandKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeCommandKind {
    Launch {
        image: String,
        duration_seconds: u32,
        ssh_authorized_key: String,
        jupyter_token: String,
    },
    /// Run one command to completion and report what it printed. No credentials
    /// are issued: nobody gets a shell, and the operator never holds a key to
    /// the renter's workspace, which is the property a server-side executor
    /// would have had to give up.
    Batch {
        image: String,
        command: String,
        duration_seconds: u32,
    },
    Stop,
}

/// What a batch command left behind. Output is captured on the node and bounded
/// there: a command that prints a gigabyte should cost the renter its tail, not
/// take out the control plane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Set when either stream hit `MAX_CAPTURED_OUTPUT_BYTES` and lost its head.
    pub truncated: bool,
}

/// Per stream. Held small enough that a report stays a single ordinary request.
pub const MAX_CAPTURED_OUTPUT_BYTES: usize = 64 * 1024;

impl CommandResult {
    /// Keep the tail rather than the head. A failing command explains itself in
    /// its last lines, not its first.
    pub fn capture(exit_code: i32, stdout: &str, stderr: &str) -> Self {
        let (stdout, out_cut) = tail(stdout);
        let (stderr, err_cut) = tail(stderr);
        Self {
            exit_code,
            stdout,
            stderr,
            truncated: out_cut || err_cut,
        }
    }

    pub fn within_limits(&self) -> bool {
        self.stdout.len() <= MAX_CAPTURED_OUTPUT_BYTES
            && self.stderr.len() <= MAX_CAPTURED_OUTPUT_BYTES
    }
}

fn tail(stream: &str) -> (String, bool) {
    if stream.len() <= MAX_CAPTURED_OUTPUT_BYTES {
        return (stream.to_owned(), false);
    }
    // Cutting by bytes can land inside a character, so step forward to the next
    // boundary rather than hand back something that is not a string.
    let mut start = stream.len() - MAX_CAPTURED_OUTPUT_BYTES;
    while start < stream.len() && !stream.is_char_boundary(start) {
        start += 1;
    }
    (stream[start..].to_owned(), true)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandPoll {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedNodeCommandPoll {
    node_id: String,
    device_public_key: String,
    request_id: Uuid,
    issued_at: DateTime<Utc>,
}

impl NodeCommandPoll {
    pub fn sign(
        node_id: String,
        device_public_key: String,
        request_id: Uuid,
        issued_at: DateTime<Utc>,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let unsigned = UnsignedNodeCommandPoll {
            node_id,
            device_public_key,
            request_id,
            issued_at,
        };
        let signature = key.sign(&signature_payload(
            COMMAND_POLL_SIGNATURE_DOMAIN,
            &unsigned,
        )?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeCommandPoll {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            COMMAND_POLL_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeCommandOutcome {
    Ready,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandReport {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub command_id: Uuid,
    pub outcome: NodeCommandOutcome,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandReportPayload {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub command_id: Uuid,
    pub outcome: NodeCommandOutcome,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
    /// Skipped when absent, so a Launch or Stop report signs exactly the bytes
    /// it signed before batch existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
}

impl NodeCommandReport {
    pub fn sign(
        unsigned: NodeCommandReportPayload,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let signature = key.sign(&signature_payload(
            COMMAND_REPORT_SIGNATURE_DOMAIN,
            &unsigned,
        )?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            command_id: unsigned.command_id,
            outcome: unsigned.outcome,
            observed_at: unsigned.observed_at,
            error: unsigned.error,
            result: unsigned.result,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &NodeCommandReportPayload {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                command_id: self.command_id,
                outcome: self.outcome.clone(),
                observed_at: self.observed_at,
                error: self.error.clone(),
                result: self.result.clone(),
            },
            &self.signature,
            key,
            COMMAND_REPORT_SIGNATURE_DOMAIN,
        )
    }
}

/// Private settlement input for a capability-scoped batch run. The signed
/// report is retained in full so an independent verifier can check the node's
/// assertion instead of trusting a result copied out of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproExecutionEvidence {
    pub capability: ReproCapability,
    pub spec: GpuReproSpec,
    pub command: NodeCommand,
    pub report: ReproExecutionReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "executor", rename_all = "snake_case")]
pub enum ReproExecutionReport {
    Node { report: NodeCommandReport },
    Managed { report: ManagedCommandReport },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReproExecutor {
    Node,
    Managed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProvider {
    Vast,
}

/// The signed portion of a centrally orchestrated execution report. Field
/// order is part of the v1 signature contract and must not change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedCommandReportPayload {
    pub report_id: Uuid,
    pub signer: String,
    pub command_id: Uuid,
    pub lease_id: u64,
    pub provider: ManagedProvider,
    pub provider_instance_id: u64,
    pub gpu_model: String,
    pub gpu_vram_mib: u32,
    pub transport_host_key_sha256: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: NodeCommandOutcome,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedCommandReport {
    pub report_id: Uuid,
    pub signer: String,
    pub command_id: Uuid,
    pub lease_id: u64,
    pub provider: ManagedProvider,
    pub provider_instance_id: u64,
    pub gpu_model: String,
    pub gpu_vram_mib: u32,
    pub transport_host_key_sha256: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub outcome: NodeCommandOutcome,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CommandResult>,
    pub signature: String,
}

impl ManagedCommandReport {
    pub fn payload(&self) -> ManagedCommandReportPayload {
        ManagedCommandReportPayload {
            report_id: self.report_id,
            signer: self.signer.clone(),
            command_id: self.command_id,
            lease_id: self.lease_id,
            provider: self.provider,
            provider_instance_id: self.provider_instance_id,
            gpu_model: self.gpu_model.clone(),
            gpu_vram_mib: self.gpu_vram_mib,
            transport_host_key_sha256: self.transport_host_key_sha256.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            outcome: self.outcome.clone(),
            error: self.error.clone(),
            result: self.result.clone(),
        }
    }

    pub fn digest(&self) -> Result<[u8; 32], ProtocolError> {
        managed_command_report_digest(&self.payload())
    }

    pub fn recover_signer(&self) -> Result<String, ProtocolError> {
        recover_managed_command_report_signer(&self.payload(), &self.signature)
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        let recovered = self.recover_signer()?;
        if recovered != self.signer || !is_lower_ethereum_address(&self.signer) {
            return Err(ProtocolError::InvalidSignature);
        }
        Ok(())
    }
}

/// Public commitments extracted from verified repro evidence. These establish
/// what an enrolled node or the onchain gateway signed and what settlement
/// anchored, not that the result was computed faithfully.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproReceiptEvidence {
    pub executor: ReproExecutor,
    pub token_hash: String,
    pub spec_hash: String,
    pub image_digest: String,
    pub command_hash: String,
    pub result_hash: String,
    pub stdout_hash: String,
    pub stderr_hash: String,
    pub report_hash: String,
    pub exit_code: i32,
    pub expected_exit_code: i32,
    pub succeeded: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReceipt {
    pub receipt_id: Uuid,
    pub lease_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_lease_id: Option<String>,
    pub node_id_hash: String,
    pub gpu_model: String,
    pub runtime_seconds: u64,
    pub charged_base_units: u64,
    pub refunded_base_units: u64,
    pub provider_paid_base_units: u64,
    pub failure_class: Option<String>,
    pub outcome: ReceiptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_class: Option<TrustClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<ReceiptAttestation>,
    /// Seconds the renter held but was not charged for, because the machine had
    /// already stopped answering when the lease was cut short. Present only on
    /// a lease that ended early, and zero is a real answer: it says the machine
    /// was still responding at the moment access closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credited_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<ReproReceiptEvidence>,
    pub receipt_hash: String,
    pub transaction_hash: String,
}

/// What the receipt commits to about attestation: a digest of the verdict, not
/// the verdict. A board serial would name the host, and the published receipt
/// is pseudonymous on purpose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAttestation {
    pub kind: AttestationKind,
    pub verdict_digest: String,
    pub verifier_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementEvidence {
    /// Internal id. Use it for storage and joins, never for a chain call.
    pub lease_id: u64,
    /// The id the escrow issued, which is what the settlement signature is
    /// bound to and what `proposeSettlement` must carry.
    #[serde(default)]
    pub chain_lease_id: u64,
    pub lease_nonce: u128,
    pub node_id: String,
    pub device_public_key: String,
    pub gpu_model: String,
    pub image_digest: String,
    pub rate_per_second: u64,
    pub deposit_base_units: u64,
    pub duration_seconds: u32,
    pub access_started_at: u64,
    pub access_ended_at: u64,
    pub cuda_ready_at: u64,
    pub interactive_access_ready_at: u64,
    pub gateway_closed_at: u64,
    /// The last moment the machine was seen working. A lease is closed when the
    /// machine stops being observed, which is necessarily after it went away,
    /// so metering stops here rather than at the moment we noticed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_class: Option<TrustClass>,
    #[serde(default)]
    pub execution: ExecutionEvidence,
    pub node_telemetry: Vec<NodeTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<ReproExecutionEvidence>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ExecutionEvidence {
    #[default]
    Physical,
    Vast {
        instance_id: u64,
        hourly_cost_micros: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiptPayload {
    receipt_id: Uuid,
    lease_id: String,
    node_id_hash: String,
    gpu_model: String,
    runtime_seconds: u64,
    charged_base_units: u64,
    refunded_base_units: u64,
    provider_paid_base_units: u64,
    failure_class: Option<String>,
    outcome: ReceiptOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_class: Option<TrustClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation: Option<ReceiptAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credited_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repro: Option<ReproReceiptEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Finalized,
    Refunded,
    Disputed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessGrant {
    pub token_id: Uuid,
    pub lease_id: String,
    pub node_id: String,
    pub connection_id: String,
    pub ssh_user: String,
    pub jupyter_path: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum LeaseAccess {
    Gateway {
        lease_id: u64,
        token: String,
        gateway_host: String,
        relay_port: u16,
        ssh_user: String,
        jupyter_path: String,
        jupyter_token: String,
        /// The root the relay's certificate chains to, in PEM. The relay is
        /// served under a private CA, so without this a renter has nothing to
        /// verify it against and is left choosing between trusting whatever
        /// answers and not connecting at all. It travels inside a response the
        /// caller already authenticated, which is what makes it worth pinning.
        /// Defaulted so a client reading an older response still parses.
        #[serde(default)]
        gateway_ca: String,
        expires_at: DateTime<Utc>,
    },
    DirectSsh {
        lease_id: u64,
        ssh_host: String,
        ssh_port: u16,
        ssh_user: String,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub nonce: String,
    pub ciphertext: String,
}

/// Envelope-encrypted renter data. The control plane stores these and can read
/// none of them: the key that unwraps `wrapped_key` is derived on the renter's
/// machine and is never sent, so there is no column, cache or log line here that
/// could hold it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEnvelope {
    /// The item's data key, sealed to the renter's vault root key.
    pub wrapped_key: String,
    /// AES-256-GCM nonce for `ciphertext`, base64url, 12 bytes.
    pub nonce: String,
    pub ciphertext: String,
}

pub const VAULT_ENVELOPE_DOMAIN: &[u8] = b"prism.vault.v1\0";
/// Ciphertext cap. The web boundary already caps a request body at 256 KiB and
/// base64 costs a third, so this is what survives the round trip.
pub const MAX_VAULT_CIPHERTEXT_BYTES: usize = 160 * 1_024;
pub const MAX_VAULT_ITEMS_PER_ACCOUNT: usize = 512;
pub const MAX_VAULT_LABEL_BYTES: usize = 64;

/// New items are sealed to the strongest class the network serves, so an agent
/// can hand one only to a lease that proved both a confidential guest and a
/// confidential GPU. Nothing weaker clears it, and storing or reading back on
/// the renter's own machine is unaffected.
pub const DEFAULT_VAULT_TRUST_FLOOR: TrustClass = TrustClass::Confidential;

/// Whether a lease is allowed to be shown an item's plaintext.
pub fn vault_release_permitted(floor: TrustClass, lease: TrustClass) -> bool {
    lease >= floor
}

/// The bytes authenticated alongside every vault ciphertext. Binding the
/// wallet, the slot, the version and the trust floor into GCM's associated
/// data is what stops this service from moving an item between vaults,
/// rolling one back to a superseded version, or quietly lowering the floor to
/// leak it into an open box: any of those makes the renter's decrypt fail
/// instead of succeeding with the wrong answer.
///
/// `wallet` is the lowercase address, because casing varies by source and two
/// spellings of one address must not derive two keys. Byte-for-byte identical
/// in the SDK, and a shared test vector pins both.
pub fn vault_associated_data(
    wallet: &str,
    item_id: Uuid,
    version: u32,
    floor: TrustClass,
) -> Vec<u8> {
    let mut aad = Vec::from(VAULT_ENVELOPE_DOMAIN);
    for field in [
        wallet,
        &item_id.hyphenated().to_string(),
        &version.to_string(),
        floor.label(),
    ] {
        aad.extend_from_slice(field.as_bytes());
        aad.push(0);
    }
    aad
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultItem {
    pub item_id: Uuid,
    /// Increments on every write. The renter compares it against what they last
    /// stored, so a served-you-an-older-copy answer is visible rather than silent.
    pub version: u32,
    /// Opaque to everyone but the renter's client.
    pub envelope: VaultEnvelope,
    pub min_trust_class: TrustClass,
    /// Unencrypted, because the renter chose it as the one thing they are happy
    /// to be listable by. Empty is fine.
    #[serde(default)]
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultWrite {
    pub envelope: VaultEnvelope,
    #[serde(default = "default_vault_floor")]
    pub min_trust_class: TrustClass,
    #[serde(default)]
    pub label: String,
    /// The version the writer believes it is replacing. Absent creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<u32>,
}

fn default_vault_floor() -> TrustClass {
    DEFAULT_VAULT_TRUST_FLOOR
}

/// Recorded whenever an item is authorized into a lease, so a renter can see
/// after the fact exactly what an agent exposed and where.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRelease {
    pub item_id: Uuid,
    pub lease_id: u64,
    pub item_version: u32,
    pub lease_trust_class: TrustClass,
    pub released_at: DateTime<Utc>,
}

/// A renter's durable storage, which outlives the machines it is restored onto.
///
/// The vault holds small secrets inline; a workspace holds however many
/// gigabytes a training run leaves behind, so the ciphertext lives in object
/// storage and only its shape is recorded here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Workspace {
    pub workspace_id: Uuid,
    /// Chosen by the renter and unencrypted, like a vault label: the one thing
    /// they accept being listable by.
    pub name: String,
    /// Increments on every stored snapshot. A restore names the version it
    /// wants, so being served an older copy is visible rather than silent.
    pub version: u32,
    /// Absent until the first snapshot lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<WorkspaceSnapshot>,
    pub min_trust_class: TrustClass,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    /// The snapshot's data key, sealed to the renter's workspace root key.
    pub wrapped_key: String,
    /// AES-256-GCM nonce for the stored object, base64url, 12 bytes.
    pub nonce: String,
    /// SHA-256 of the ciphertext, recorded by the renter. A restore that hashes
    /// to anything else was altered in storage, and the renter learns that
    /// before decrypting rather than after.
    pub ciphertext_digest: String,
    pub size_bytes: u64,
}

/// Bound into the ciphertext so storage cannot serve one renter's snapshot to
/// another, nor an older version in place of the one that was asked for.
pub const WORKSPACE_ENVELOPE_DOMAIN: &[u8] = b"prism.workspace.v1\0";

pub fn workspace_associated_data(
    wallet: &str,
    workspace_id: Uuid,
    version: u32,
    floor: TrustClass,
) -> Vec<u8> {
    let mut aad = Vec::from(WORKSPACE_ENVELOPE_DOMAIN);
    for field in [
        wallet,
        &workspace_id.hyphenated().to_string(),
        &version.to_string(),
        floor.label(),
    ] {
        aad.extend_from_slice(field.as_bytes());
        aad.push(0);
    }
    aad
}

/// Per snapshot. Large enough for a checkpoint directory, small enough that one
/// account cannot quietly become the storage bill.
pub const MAX_WORKSPACE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_WORKSPACES_PER_ACCOUNT: usize = 16;
pub const MAX_WORKSPACE_NAME_BYTES: usize = 64;
/// Unlike the vault, a workspace defaults to the weakest floor. Its contents
/// are the working files a renter is already handing to a rented machine, and
/// defaulting to a floor no live capacity meets would mean the feature could
/// never be used.
pub const DEFAULT_WORKSPACE_TRUST_FLOOR: TrustClass = TrustClass::Open;

#[derive(Clone)]
pub struct CredentialCipher(Aes256Gcm);

impl CredentialCipher {
    pub fn from_hex(value: &str) -> Result<Self, ProtocolError> {
        let bytes = hex::decode(value).map_err(|_| ProtocolError::InvalidEncryptionKey)?;
        if bytes.len() != 32 {
            return Err(ProtocolError::InvalidEncryptionKey);
        }
        Ok(Self(
            Aes256Gcm::new_from_slice(&bytes).map_err(|_| ProtocolError::InvalidEncryptionKey)?,
        ))
    }

    pub fn encrypt(&self, value: &str) -> Result<EncryptedSecret, ProtocolError> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_value = nonce.into();
        let ciphertext = self
            .0
            .encrypt(&nonce_value, value.as_bytes())
            .map_err(|_| ProtocolError::Encryption)?;
        Ok(EncryptedSecret {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, secret: &EncryptedSecret) -> Result<String, ProtocolError> {
        let nonce = URL_SAFE_NO_PAD
            .decode(&secret.nonce)
            .map_err(|_| ProtocolError::Encryption)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&secret.ciphertext)
            .map_err(|_| ProtocolError::Encryption)?;
        if nonce.len() != 12 {
            return Err(ProtocolError::Encryption);
        }
        let nonce_value: [u8; 12] = nonce.try_into().map_err(|_| ProtocolError::Encryption)?;
        let nonce_value = Nonce::from(nonce_value);
        let plaintext = self
            .0
            .decrypt(&nonce_value, ciphertext.as_ref())
            .map_err(|_| ProtocolError::Encryption)?;
        String::from_utf8(plaintext).map_err(|_| ProtocolError::Encryption)
    }
}

/// The commit a service was built from, stamped into its image by CI. Services
/// record this on startup so a host running behind the repository is visible in
/// one query rather than by inspecting image digests by hand.
pub fn build_version() -> String {
    std::env::var("PRISM_BUILD_SHA")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Kept here rather than repeated per service: three services record their
/// version, and a fix applied to one copy of a duplicated statement is how a
/// settlement worker ended up signing transactions the chain would not take.
pub const RECORD_SERVICE_VERSION_SQL: &str = "INSERT INTO service_versions (service, version, started_at) \
     VALUES ($1, $2, NOW()) \
     ON CONFLICT (service) DO UPDATE \
     SET version = EXCLUDED.version, started_at = EXCLUDED.started_at";

pub fn node_id(device_public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(device_public_key.as_bytes());
    format!("0x{}", hex::encode(digest))
}

pub fn verifying_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidPublicKey)?,
    )
    .map_err(|_| ProtocolError::InvalidPublicKey)
}

pub fn receipt_hash(receipt: &PublicReceipt) -> Result<String, ProtocolError> {
    let payload = ReceiptPayload {
        receipt_id: receipt.receipt_id,
        lease_id: receipt.lease_id.clone(),
        node_id_hash: receipt.node_id_hash.clone(),
        gpu_model: receipt.gpu_model.clone(),
        runtime_seconds: receipt.runtime_seconds,
        charged_base_units: receipt.charged_base_units,
        refunded_base_units: receipt.refunded_base_units,
        provider_paid_base_units: receipt.provider_paid_base_units,
        failure_class: receipt.failure_class.clone(),
        outcome: receipt.outcome.clone(),
        trust_class: receipt.trust_class,
        attestation: receipt.attestation.clone(),
        credited_seconds: receipt.credited_seconds,
        repro: receipt.repro.clone(),
    };
    Ok(hex::encode(Sha256::digest(canonical_json(&payload)?)))
}

pub fn receipt_hash_matches(receipt: &PublicReceipt) -> Result<bool, ProtocolError> {
    Ok(receipt.receipt_hash == receipt_hash(receipt)?)
}

pub fn validate_receipt_identity(receipt: &PublicReceipt) -> Result<(), ProtocolError> {
    match (&receipt.escrow_address, &receipt.chain_lease_id) {
        (None, None) => Ok(()),
        (Some(escrow_address), Some(chain_lease_id))
            if is_canonical_address(escrow_address)
                && is_canonical_chain_id(chain_lease_id)
                && receipt.lease_id == *chain_lease_id =>
        {
            Ok(())
        }
        _ => Err(ProtocolError::InvalidReceiptIdentity),
    }
}

fn is_canonical_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_chain_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0')
        && value.parse::<u64>().is_ok_and(|value| value > 0)
}

/// Hashes the exact v1 workload contract. This is deliberately domain
/// separated from every other JSON hash in the protocol.
pub fn gpu_repro_spec_hash(spec: &GpuReproSpec) -> Result<String, ProtocolError> {
    canonical_domain_hash(GPU_REPRO_SPEC_HASH_DOMAIN, spec)
}

/// Turns a 256-bit, unpadded base64url bearer token into the commitment carried
/// by the capability. The token bytes, not their textual encoding, are hashed.
pub fn repro_token_hash(token: &str) -> Result<String, ProtocolError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ProtocolError::InvalidReproToken)?;
    if decoded.len() != 32 {
        return Err(ProtocolError::InvalidReproToken);
    }
    Ok(hex::encode(Sha256::digest(decoded)))
}

pub fn repro_command_hash(command: &NodeCommand) -> Result<String, ProtocolError> {
    canonical_domain_hash(GPU_REPRO_COMMAND_HASH_DOMAIN, command)
}

pub fn repro_result_hash(result: &CommandResult) -> Result<String, ProtocolError> {
    canonical_domain_hash(GPU_REPRO_RESULT_HASH_DOMAIN, result)
}

pub fn repro_report_hash(report: &NodeCommandReport) -> Result<String, ProtocolError> {
    canonical_domain_hash(GPU_REPRO_REPORT_HASH_DOMAIN, report)
}

pub fn managed_repro_report_hash(report: &ManagedCommandReport) -> Result<String, ProtocolError> {
    canonical_domain_hash(GPU_REPRO_REPORT_HASH_DOMAIN, report)
}

pub fn managed_command_report_digest(
    payload: &ManagedCommandReportPayload,
) -> Result<[u8; 32], ProtocolError> {
    let encoded = canonical_json(payload)?;
    let mut input =
        Vec::with_capacity(MANAGED_COMMAND_REPORT_SIGNATURE_DOMAIN.len() + encoded.len());
    input.extend_from_slice(MANAGED_COMMAND_REPORT_SIGNATURE_DOMAIN);
    input.extend_from_slice(encoded.as_bytes());
    Ok(Keccak256::digest(input).into())
}

pub fn recover_managed_command_report_signer(
    payload: &ManagedCommandReportPayload,
    encoded_signature: &str,
) -> Result<String, ProtocolError> {
    let encoded = encoded_signature
        .strip_prefix("0x")
        .filter(|value| {
            value.len() == 130
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(ProtocolError::InvalidSignature)?;
    let bytes = hex::decode(encoded).map_err(|_| ProtocolError::InvalidSignature)?;
    let signature =
        EthereumSignature::from_slice(&bytes[..64]).map_err(|_| ProtocolError::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(ProtocolError::InvalidSignature);
    }
    let recovery_id = match bytes[64] {
        value @ 0..=1 => RecoveryId::from_byte(value),
        value @ 27..=28 => RecoveryId::from_byte(value - 27),
        _ => None,
    }
    .ok_or(ProtocolError::InvalidSignature)?;
    let key = EthereumVerifyingKey::recover_from_prehash(
        &managed_command_report_digest(payload)?,
        &signature,
        recovery_id,
    )
    .map_err(|_| ProtocolError::InvalidSignature)?;
    let point = key.to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&digest[12..])))
}

pub fn repro_stream_hash(stream: &str) -> String {
    hex::encode(Sha256::digest(stream.as_bytes()))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_string(value).map_err(ProtocolError::Serialization)
}

fn canonical_domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ProtocolError> {
    Ok(hex::encode(Sha256::digest(signature_payload(
        domain, value,
    )?)))
}

fn is_lower_ethereum_address(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|address| {
        address.len() == 40
            && address
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn signature_payload<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, ProtocolError> {
    let encoded = canonical_json(value)?;
    let mut payload = Vec::with_capacity(domain.len() + encoded.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(encoded.as_bytes());
    Ok(payload)
}

fn verify_signature<T: Serialize>(
    value: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
    domain: &[u8],
) -> Result<(), ProtocolError> {
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| ProtocolError::InvalidSignature)?;
    let payload = signature_payload(domain, value)?;
    key.verify(&payload, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid repro capability token")]
    InvalidReproToken,
    #[error("serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("credential encryption key is invalid")]
    InvalidEncryptionKey,
    #[error("credential encryption failed")]
    Encryption,
    #[error("attestation evidence exceeds the accepted size")]
    AttestationTooLarge,
    #[error("attestation is malformed")]
    InvalidAttestation,
    #[error("public receipt chain identity is invalid")]
    InvalidReceiptIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey as ManagedSigningKey, signature::hazmat::PrehashSigner};

    fn signed_managed_report() -> ManagedCommandReport {
        let mut key_bytes = [0_u8; 32];
        key_bytes[31] = 1;
        let key = ManagedSigningKey::from_slice(&key_bytes).unwrap();
        let payload = ManagedCommandReportPayload {
            report_id: Uuid::parse_str("019f0000-0000-7000-8000-000000000003").unwrap(),
            signer: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".to_owned(),
            command_id: Uuid::parse_str("019f0000-0000-7000-8000-000000000004").unwrap(),
            lease_id: 129,
            provider: ManagedProvider::Vast,
            provider_instance_id: 42,
            gpu_model: "NVIDIA L40S".to_owned(),
            gpu_vram_mib: 46_068,
            transport_host_key_sha256: "a".repeat(64),
            started_at: DateTime::parse_from_rfc3339("2026-08-29T20:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            finished_at: DateTime::parse_from_rfc3339("2026-08-29T20:01:00Z")
                .unwrap()
                .with_timezone(&Utc),
            outcome: NodeCommandOutcome::Completed,
            error: None,
            result: Some(CommandResult {
                exit_code: 0,
                stdout: "42\n".to_owned(),
                stderr: String::new(),
                truncated: false,
            }),
        };
        let digest = managed_command_report_digest(&payload).unwrap();
        let signature: EthereumSignature = key.sign_prehash(&digest).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        let recovery_id = [0_u8, 1]
            .into_iter()
            .filter_map(RecoveryId::from_byte)
            .find(|recovery_id| {
                EthereumVerifyingKey::recover_from_prehash(&digest, &signature, *recovery_id)
                    .is_ok_and(|recovered| recovered == *key.verifying_key())
            })
            .unwrap();
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = 27 + recovery_id.to_byte();
        ManagedCommandReport {
            report_id: payload.report_id,
            signer: payload.signer,
            command_id: payload.command_id,
            lease_id: payload.lease_id,
            provider: payload.provider,
            provider_instance_id: payload.provider_instance_id,
            gpu_model: payload.gpu_model,
            gpu_vram_mib: payload.gpu_vram_mib,
            transport_host_key_sha256: payload.transport_host_key_sha256,
            started_at: payload.started_at,
            finished_at: payload.finished_at,
            outcome: payload.outcome,
            error: payload.error,
            result: payload.result,
            signature: format!("0x{}", hex::encode(encoded)),
        }
    }

    #[test]
    fn telemetry_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let telemetry = NodeTelemetry::sign(
            UnsignedTelemetry {
                node_id: node_id(&key.verifying_key()),
                sequence: 1,
                observed_at: Utc::now(),
                gpu_utilization_bps: 4_200,
                gpu_memory_used_mib: 1_024,
                active_lease: None,
                tunnel_connected: true,
                image_digest: Some("sha256:abc".to_owned()),
                posture: None,
            },
            &key,
        )
        .unwrap();

        assert!(telemetry.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn telemetry_without_posture_signs_the_legacy_payload() {
        let unsigned = UnsignedTelemetry {
            node_id: "0xabc".to_owned(),
            sequence: 1,
            observed_at: Utc::now(),
            gpu_utilization_bps: 0,
            gpu_memory_used_mib: 0,
            active_lease: None,
            tunnel_connected: true,
            image_digest: None,
            posture: None,
        };

        assert!(!canonical_json(&unsigned).unwrap().contains("posture"));
    }

    #[test]
    fn telemetry_posture_is_covered_by_the_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut telemetry = NodeTelemetry::sign(
            UnsignedTelemetry {
                node_id: node_id(&key.verifying_key()),
                sequence: 1,
                observed_at: Utc::now(),
                gpu_utilization_bps: 0,
                gpu_memory_used_mib: 0,
                active_lease: None,
                tunnel_connected: true,
                image_digest: None,
                posture: Some(NodePosture {
                    isolation: IsolationMode::KataVfio,
                    attestation: None,
                }),
            },
            &key,
        )
        .unwrap();

        assert!(telemetry.verify(&key.verifying_key()).is_ok());
        telemetry.posture = None;
        assert!(telemetry.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn trust_classes_order_weakest_first() {
        assert!(TrustClass::Open < TrustClass::Isolated);
        assert!(TrustClass::Isolated < TrustClass::Attested);
        assert!(TrustClass::Attested < TrustClass::Confidential);
        assert_eq!(TrustClass::default(), TrustClass::Open);
    }

    #[test]
    fn offers_without_a_trust_class_default_to_open() {
        let document = serde_json::json!({
            "node_id": "0xabc",
            "operator_wallet": "0x1111111111111111111111111111111111111111",
            "payout_wallet": "0x2222222222222222222222222222222222222222",
            "device_public_key": "key",
            "gpu": {"model": "NVIDIA L40S", "vram_mib": 46_068, "cuda_major": 12},
            "rate_per_second": 222,
            "reliability_bps": 10_000,
            "benchmark_score": 10_000,
            "bonded": true,
            "online": true,
            "public_image_only": true,
            "updated_at": "2026-07-24T00:00:00Z",
        });
        let offer: NodeOffer = serde_json::from_value(document).unwrap();

        assert_eq!(offer.trust_class, TrustClass::Open);
    }

    /// The flag is derived by the control plane on every read, so an offer that
    /// arrives without it is a node nobody has heard poll yet.
    #[test]
    fn an_offer_without_a_command_channel_flag_reads_false() {
        let document = serde_json::json!({
            "node_id": "0xabc",
            "operator_wallet": "0x1111111111111111111111111111111111111111",
            "payout_wallet": "0x2222222222222222222222222222222222222222",
            "device_public_key": "key",
            "gpu": {"model": "NVIDIA L40S", "vram_mib": 46_068, "cuda_major": 12},
            "rate_per_second": 222,
            "reliability_bps": 10_000,
            "benchmark_score": 10_000,
            "bonded": true,
            "online": true,
            "public_image_only": true,
            "updated_at": "2026-07-24T00:00:00Z",
        });
        let offer: NodeOffer = serde_json::from_value(document).unwrap();

        assert!(!offer.command_channel);
        assert!(!offer.managed_batch);
    }

    #[test]
    fn posture_claims_are_clamped_to_what_the_network_can_verify() {
        let claimed = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: Some(AttestationRef {
                kind: AttestationKind::NvidiaCc,
                quote_sha256: "0".repeat(64),
            }),
        };

        assert_eq!(claimed.claimed_class(), TrustClass::Isolated);

        let shared = NodePosture::default();
        assert_eq!(shared.claimed_class(), TrustClass::Open);
    }

    /// The reason the attestation arm was removed: a node that names a kind
    /// nobody checked must not reach past the rung its isolation alone earns.
    #[test]
    fn a_posture_alone_never_exceeds_isolated() {
        for kind in [
            AttestationKind::SevSnp,
            AttestationKind::Tdx,
            AttestationKind::NvidiaCc,
            AttestationKind::NvidiaGpu,
        ] {
            let posture = NodePosture {
                isolation: IsolationMode::KataVfio,
                attestation: Some(AttestationRef {
                    kind,
                    quote_sha256: "0".repeat(64),
                }),
            };
            assert_eq!(posture.claimed_class(), TrustClass::Isolated, "{kind:?}");
        }
    }

    #[test]
    fn enrollment_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let enrollment = NodeEnrollment::sign(
            UnsignedNodeEnrollment {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                operator_wallet: "0x1111111111111111111111111111111111111111".to_owned(),
                payout_wallet: "0x2222222222222222222222222222222222222222".to_owned(),
                gpu: GpuSpec {
                    model: "NVIDIA L4".to_owned(),
                    vram_mib: 24_576,
                    cuda_major: 12,
                },
                rate_per_second: 1_000,
                benchmark_score: 10_000,
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(enrollment.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn receipt_hash_excludes_the_hash_field() {
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: "lease-1".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000,
            refunded_base_units: 0,
            provider_paid_base_units: 900,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: "0x5678".to_owned(),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.runtime_seconds = 61;
        assert!(!receipt_hash_matches(&receipt).unwrap());
        receipt.runtime_seconds = 60;
        receipt.transaction_hash = "0x9999".to_owned();
        assert!(receipt_hash_matches(&receipt).unwrap());
    }

    #[test]
    fn receipt_identity_is_additive_and_exact() {
        let mut receipt = receipt_at("17", Uuid::now_v7());
        let legacy_hash = receipt_hash(&receipt).unwrap();
        receipt.escrow_address = Some(format!("0x{}", "a".repeat(40)));
        receipt.chain_lease_id = Some("17".to_owned());

        validate_receipt_identity(&receipt).unwrap();
        assert_eq!(receipt_hash(&receipt).unwrap(), legacy_hash);

        receipt.chain_lease_id = Some("18".to_owned());
        assert!(validate_receipt_identity(&receipt).is_err());
        receipt.chain_lease_id = Some("17".to_owned());
        receipt.escrow_address = Some(format!("0x{}", "A".repeat(40)));
        assert!(validate_receipt_identity(&receipt).is_err());
        receipt.escrow_address = None;
        assert!(validate_receipt_identity(&receipt).is_err());
    }

    /// Receipts already published on chain carry no trust class. Their hashes
    /// are committed by settlement transactions, so the payload must still
    /// serialize exactly as it did before the field existed.
    #[test]
    fn receipts_without_a_trust_class_keep_their_published_hash() {
        let receipt_id = Uuid::now_v7();
        let receipt = PublicReceipt {
            receipt_id,
            lease_id: "11".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L40S".to_owned(),
            runtime_seconds: 300,
            charged_base_units: 66_600,
            refunded_base_units: 0,
            provider_paid_base_units: 59_940,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: "0x3669fa89".to_owned(),
        };
        let legacy = format!(
            r#"{{"receipt_id":"{receipt_id}","lease_id":"11","node_id_hash":"0x1234","gpu_model":"NVIDIA L40S","runtime_seconds":300,"charged_base_units":66600,"refunded_base_units":0,"provider_paid_base_units":59940,"failure_class":null,"outcome":"finalized"}}"#
        );

        assert_eq!(
            receipt_hash(&receipt).unwrap(),
            hex::encode(Sha256::digest(legacy))
        );
    }

    #[test]
    fn receipt_hashes_cover_the_trust_class() {
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: "12".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L40S".to_owned(),
            runtime_seconds: 300,
            charged_base_units: 66_600,
            refunded_base_units: 0,
            provider_paid_base_units: 59_940,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Open),
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: "0x3669fa89".to_owned(),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.trust_class = Some(TrustClass::Confidential);
        assert!(!receipt_hash_matches(&receipt).unwrap());
    }

    fn receipt_at(lease_id: &str, receipt_id: Uuid) -> PublicReceipt {
        PublicReceipt {
            receipt_id,
            lease_id: lease_id.to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA H100 PCIe".to_owned(),
            runtime_seconds: 300,
            charged_base_units: 66_600,
            refunded_base_units: 0,
            provider_paid_base_units: 59_940,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Isolated),
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: "0x3669fa89".to_owned(),
        }
    }

    /// Receipts settled before attestation existed carry a trust class and no
    /// attestation. Their hashes are committed on chain, so the payload has to
    /// serialize exactly as it did then.
    #[test]
    fn receipts_without_attestation_keep_their_published_hash() {
        let receipt_id = Uuid::now_v7();
        let receipt = receipt_at("13", receipt_id);
        let legacy = format!(
            r#"{{"receipt_id":"{receipt_id}","lease_id":"13","node_id_hash":"0x1234","gpu_model":"NVIDIA H100 PCIe","runtime_seconds":300,"charged_base_units":66600,"refunded_base_units":0,"provider_paid_base_units":59940,"failure_class":null,"outcome":"finalized","trust_class":"isolated"}}"#
        );

        assert_eq!(
            receipt_hash(&receipt).unwrap(),
            hex::encode(Sha256::digest(legacy))
        );
    }

    #[test]
    fn receipt_hashes_cover_the_attestation() {
        let mut receipt = receipt_at("14", Uuid::now_v7());
        receipt.attestation = Some(ReceiptAttestation {
            kind: AttestationKind::NvidiaGpu,
            verdict_digest: "a".repeat(64),
            verifier_version: "prism-attestation/0.1.0".to_owned(),
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.attestation.as_mut().unwrap().verdict_digest = "b".repeat(64);
        assert!(!receipt_hash_matches(&receipt).unwrap());
    }

    /// An empty event log must vanish from the canonical payload, because an
    /// attestation signed before the field existed has to keep verifying, and
    /// the canonical form is exactly what the signature covers.
    #[test]
    fn an_empty_event_log_leaves_the_signed_payload_unchanged() {
        let unsigned = unsigned_attestation("0xabc");
        let serialized = serde_json::to_string(&unsigned).expect("canonical form");
        assert!(!serialized.contains("tdx_event_log"));
        assert!(!serialized.contains("tdx_collateral_json"));

        let mut with_log = unsigned_attestation("0xabc");
        with_log.tdx_event_log.push(TdxEventEntry {
            imr: 3,
            event_type: 134_217_729,
            event: "compose-hash".to_owned(),
            digest: "ab".repeat(48),
            event_payload: "cd".repeat(32),
        });
        let serialized = serde_json::to_string(&with_log).expect("canonical form");
        assert!(serialized.contains("tdx_event_log"));
    }

    #[test]
    fn repro_spec_hash_matches_the_v1_reference_vector() {
        let spec = GpuReproSpec {
            image: format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
            command: "python -c 'print(6 * 7)'".to_owned(),
            duration_seconds: 120,
            min_vram_mib: 1_024,
            expected_exit_code: 0,
        };

        assert_eq!(
            gpu_repro_spec_hash(&spec).unwrap(),
            "23979781f1379272e8d5c6b036708792e060ac88b3cb78fbd2f8e62bed7a79ed"
        );
        assert_eq!(spec.hash().unwrap(), gpu_repro_spec_hash(&spec).unwrap());
    }

    #[test]
    fn repro_token_hashes_the_decoded_256_bit_secret() {
        assert_eq!(
            repro_token_hash("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap(),
            "4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
        assert!(repro_token_hash("too-short").is_err());
        assert!(repro_token_hash("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=").is_err());
    }

    #[test]
    fn managed_report_recovers_and_verifies_its_gateway_signer() {
        let mut report = signed_managed_report();

        assert_eq!(report.recover_signer().unwrap(), report.signer);
        assert!(report.verify().is_ok());
        report.result.as_mut().unwrap().stdout = "43\n".to_owned();
        assert!(report.verify().is_err());
    }

    #[test]
    fn managed_report_digest_matches_the_v1_reference_vector() {
        let report = signed_managed_report();

        assert_eq!(
            hex::encode(report.digest().unwrap()),
            "9177afcd30525f8328cff37aabc5acd9769a954ac4ad4ee45b8e55db0082985d"
        );
    }

    #[test]
    fn managed_report_rejects_noncanonical_signatures_and_claimed_signers() {
        let mut report = signed_managed_report();
        report.signature = report.signature.to_ascii_uppercase();
        assert!(report.verify().is_err());

        let mut report = signed_managed_report();
        report.signer = "0x0000000000000000000000000000000000000001".to_owned();
        assert!(report.verify().is_err());
    }

    #[test]
    fn managed_repro_hash_commits_to_the_recoverable_signature() {
        let mut report = signed_managed_report();
        let original = managed_repro_report_hash(&report).unwrap();
        report.signature.push('0');

        assert_ne!(managed_repro_report_hash(&report).unwrap(), original);
    }

    #[test]
    fn receipt_hashes_cover_repro_commitments() {
        let mut receipt = receipt_at("15", Uuid::now_v7());
        receipt.repro = Some(ReproReceiptEvidence {
            executor: ReproExecutor::Node,
            token_hash: "0".repeat(64),
            spec_hash: "1".repeat(64),
            image_digest: format!("sha256:{}", "2".repeat(64)),
            command_hash: "3".repeat(64),
            result_hash: "4".repeat(64),
            stdout_hash: "5".repeat(64),
            stderr_hash: "6".repeat(64),
            report_hash: "7".repeat(64),
            exit_code: 0,
            expected_exit_code: 0,
            succeeded: true,
            truncated: false,
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.repro.as_mut().unwrap().stdout_hash = "8".repeat(64);
        assert!(!receipt_hash_matches(&receipt).unwrap());
    }

    #[test]
    fn repro_receipt_hash_matches_the_publisher_reference_vector() {
        let receipt = PublicReceipt {
            receipt_id: Uuid::parse_str("019f0000-0000-7000-8000-000000000002").unwrap(),
            lease_id: "129".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: format!("0x{}", "b".repeat(64)),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 13_320,
            refunded_base_units: 0,
            provider_paid_base_units: 11_988,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Open),
            attestation: None,
            credited_seconds: None,
            repro: Some(ReproReceiptEvidence {
                executor: ReproExecutor::Node,
                token_hash: "0".repeat(64),
                spec_hash: "1".repeat(64),
                image_digest: format!("sha256:{}", "2".repeat(64)),
                command_hash: "3".repeat(64),
                result_hash: "4".repeat(64),
                stdout_hash: "5".repeat(64),
                stderr_hash: "6".repeat(64),
                report_hash: "7".repeat(64),
                exit_code: 0,
                expected_exit_code: 0,
                succeeded: true,
                truncated: false,
            }),
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", "d".repeat(64)),
        };

        assert_eq!(
            receipt_hash(&receipt).unwrap(),
            "947448674b4c449999cf2106d7cd55f7a3e3041f3f4534086e8e9466fc6d395d"
        );
    }

    #[test]
    fn legacy_lease_requests_have_no_repro_capability() {
        let request: LeaseRequest = serde_json::from_value(serde_json::json!({
            "image": format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
            "duration_seconds": 120,
            "min_vram_mib": 1024,
            "preferred_node_id": null,
            "command": "nvidia-smi"
        }))
        .unwrap();

        assert!(request.repro.is_none());
    }

    #[test]
    fn repro_capabilities_require_an_explicit_executor() {
        let capability = serde_json::from_value::<ReproCapability>(serde_json::json!({
            "token_hash": "0".repeat(64),
            "spec_hash": "1".repeat(64),
            "expected_exit_code": 0
        }));

        assert!(capability.is_err());
    }

    fn unsigned_attestation(node_id: &str) -> UnsignedNodeAttestation {
        UnsignedNodeAttestation {
            tdx_event_log: Vec::new(),
            tdx_collateral_json: None,
            node_id: node_id.to_owned(),
            challenge_id: Uuid::now_v7(),
            kind: AttestationKind::NvidiaGpu,
            evidence_base64: URL_SAFE_NO_PAD.encode("spdm measurement response"),
            certificate_chain_base64: vec![URL_SAFE_NO_PAD.encode("leaf der")],
            capability: HostTeeCapability {
                sev: true,
                sev_es: true,
                sev_snp: false,
                sev_guest_device: true,
                kata_runtime: true,
                kata_confidential_runtime: false,
            },
            pci_address: "0000:01:00.0".to_owned(),
            collected_at: Utc::now(),
        }
    }

    #[test]
    fn attestation_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut attestation =
            NodeAttestation::sign(unsigned_attestation(&node_id(&key.verifying_key())), &key)
                .unwrap();

        assert!(attestation.verify(&key.verifying_key()).is_ok());
        attestation.pci_address = "0000:02:00.0".to_owned();
        assert!(attestation.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn attestation_rejects_a_foreign_key() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let attestation =
            NodeAttestation::sign(unsigned_attestation(&node_id(&key.verifying_key())), &key)
                .unwrap();

        assert!(attestation.verify(&other.verifying_key()).is_err());
    }

    #[test]
    fn attestation_rejects_oversized_evidence() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut unsigned = unsigned_attestation("0xabc");
        unsigned.evidence_base64 = "A".repeat(MAX_ATTESTATION_EVIDENCE_BYTES + 1);

        assert!(matches!(
            NodeAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.evidence_base64 = URL_SAFE_NO_PAD.encode("report");
        unsigned.certificate_chain_base64 = vec!["A".repeat(MAX_ATTESTATION_CERTIFICATE_BYTES + 1)];
        assert!(matches!(
            NodeAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.certificate_chain_base64 =
            vec![URL_SAFE_NO_PAD.encode("der"); MAX_ATTESTATION_CERTIFICATES + 1];
        assert!(matches!(
            NodeAttestation::sign(unsigned, &key),
            Err(ProtocolError::AttestationTooLarge)
        ));
    }

    // Two nodes sharing one challenge would otherwise be able to swap reports.
    #[test]
    fn attestation_report_nonce_binds_the_device_key() {
        let challenge = [7_u8; 32];
        assert_ne!(
            attestation_report_nonce(&challenge, "0xabc", "key-one"),
            attestation_report_nonce(&challenge, "0xabc", "key-two")
        );
        assert_ne!(
            attestation_report_nonce(&challenge, "0xabc", "key-one"),
            attestation_report_nonce(&challenge, "0xdef", "key-one")
        );
    }

    fn verdict_at(
        kind: AttestationKind,
        granted: TrustClass,
        expires_at: DateTime<Utc>,
    ) -> AttestationVerdict {
        AttestationVerdict {
            node_id: "0xabc".to_owned(),
            kind,
            device_identity: "CN=NVIDIA GH100 / serial 1323824012345".to_owned(),
            measurement_digest: "c".repeat(64),
            claimed_capability: HostTeeCapability {
                sev: true,
                sev_es: true,
                ..HostTeeCapability::default()
            },
            granted_class: granted,
            verifier_version: "prism-attestation/0.1.0".to_owned(),
            verified_at: expires_at - chrono::Duration::hours(1),
            expires_at,
        }
    }

    #[test]
    fn a_served_class_needs_a_tunnel_a_posture_and_a_live_verdict() {
        let now = Utc::now();
        let fresh = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Isolated,
            now + chrono::Duration::hours(12),
        );
        let expired = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Isolated,
            now - chrono::Duration::minutes(1),
        );
        let overreaching = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Confidential,
            now + chrono::Duration::hours(12),
        );
        let kata = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: None,
        };
        let shared = NodePosture::default();

        let cases = [
            (
                "untunneled",
                false,
                Some(&kata),
                Some(&fresh),
                TrustClass::Open,
            ),
            (
                "expired verdict",
                true,
                Some(&kata),
                Some(&expired),
                TrustClass::Open,
            ),
            (
                "shared host",
                true,
                Some(&shared),
                Some(&fresh),
                TrustClass::Open,
            ),
            ("no posture", true, None, Some(&fresh), TrustClass::Open),
            (
                "verified",
                true,
                Some(&kata),
                Some(&fresh),
                TrustClass::Isolated,
            ),
            (
                "clamped",
                true,
                Some(&kata),
                Some(&overreaching),
                TrustClass::Isolated,
            ),
        ];

        for (name, tunneled, posture, verdict, expected) in cases {
            assert_eq!(
                class_for_verdict("0xabc", tunneled, posture, verdict, now),
                expected,
                "{name}"
            );
        }

        assert_eq!(
            class_for_verdict("0xabc", true, Some(&kata), None, now),
            TrustClass::Open
        );
    }

    /// A TDX verdict earns Isolated with no posture beside it, because the
    /// boundary it attests is the TD itself rather than a host-side runtime
    /// claim. Everything else about the derivation stays load-bearing: the
    /// tunnel, the expiry and the node binding refuse exactly as they do for
    /// GPU evidence, and a GPU verdict on a shared posture still earns
    /// nothing, so the TDX arm widened one path and not the gate.
    #[test]
    fn a_tdx_verdict_earns_isolated_without_a_posture() {
        let now = Utc::now();
        let shared = NodePosture {
            isolation: IsolationMode::Shared,
            attestation: None,
        };
        let tdx = verdict_at(
            AttestationKind::Tdx,
            TrustClass::Attested,
            now + chrono::Duration::hours(12),
        );
        let expired_tdx = verdict_at(
            AttestationKind::Tdx,
            TrustClass::Attested,
            now - chrono::Duration::minutes(1),
        );
        let gpu = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Isolated,
            now + chrono::Duration::hours(12),
        );

        assert_eq!(
            class_for_verdict("0xabc", true, Some(&shared), Some(&tdx), now),
            TrustClass::Isolated
        );
        assert_eq!(
            class_for_verdict("0xabc", true, None, Some(&tdx), now),
            TrustClass::Isolated
        );
        assert_eq!(
            class_for_verdict("0xabc", false, Some(&shared), Some(&tdx), now),
            TrustClass::Open
        );
        assert_eq!(
            class_for_verdict("0xabc", true, Some(&shared), Some(&expired_tdx), now),
            TrustClass::Open
        );
        assert_eq!(
            class_for_verdict("0xdef", true, Some(&shared), Some(&tdx), now),
            TrustClass::Open
        );
        assert_eq!(
            class_for_verdict("0xabc", true, Some(&shared), Some(&gpu), now),
            TrustClass::Open
        );
    }

    // A verdict is a statement about one node. Pairing it with another grants
    // nothing, so a lookup that returns the wrong row cannot promote a node
    // that never attested.
    #[test]
    fn a_verdict_does_not_class_a_node_it_does_not_name() {
        let now = Utc::now();
        let kata = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: None,
        };
        let verdict = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Isolated,
            now + chrono::Duration::hours(1),
        );
        assert_eq!(verdict.node_id, "0xabc");
        assert_eq!(
            class_for_verdict("0xabc", true, Some(&kata), Some(&verdict), now),
            TrustClass::Isolated,
            "its own node is classed"
        );
        assert_eq!(
            class_for_verdict("0xdef", true, Some(&kata), Some(&verdict), now),
            TrustClass::Open,
            "another node is not"
        );
    }

    // A kind is only as good as the verifier behind it. GPU and TDX verdicts
    // come from chains this workspace actually walks; SEV-SNP is lease-level
    // evidence and grants nothing at the node, and NvidiaCc has no verifier,
    // so a verdict claiming either kind at node level derives Open however it
    // got minted.
    #[test]
    fn only_verified_kinds_grant_a_node_class() {
        let now = Utc::now();
        let kata = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: None,
        };
        for kind in [AttestationKind::SevSnp, AttestationKind::NvidiaCc] {
            let verdict = verdict_at(kind, TrustClass::Isolated, now + chrono::Duration::hours(1));
            assert_eq!(
                class_for_verdict("0xabc", true, Some(&kata), Some(&verdict), now),
                TrustClass::Open,
                "{kind:?}"
            );
        }
        let tdx = verdict_at(
            AttestationKind::Tdx,
            TrustClass::Isolated,
            now + chrono::Duration::hours(1),
        );
        assert_eq!(
            class_for_verdict("0xabc", true, Some(&kata), Some(&tdx), now),
            TrustClass::Isolated,
            "Tdx"
        );
    }

    const GUEST_CHANNEL_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-guest";

    #[test]
    fn snp_report_data_fills_the_whole_field() {
        let nonce = [0x11_u8; 32];
        assert_eq!(
            hex::encode(snp_report_data(&nonce, 42, GUEST_CHANNEL_KEY)),
            "f45d37bedc45ef6d6bf57b93f8e246cddd406331fb767c93781a7aefc867d256\
             17e6bca59720cf3e0d0c7919cd44dd3a3d4df2ffe72a52b1bacdfb9b22ed6fda"
        );
    }

    // The TD's quote is bound to the session's endpoint the same way the SNP
    // report is: drop or change the channel key and the report data changes, so
    // a quote proving some measured TD booted cannot answer a lease whose
    // renter terminates on a different key.
    #[test]
    fn tdx_lease_report_data_binds_the_channel_key() {
        let nonce = [0x22_u8; 32];
        let bound = tdx_lease_report_data(&nonce, 7, "0xnode", GUEST_CHANNEL_KEY);
        assert_ne!(
            bound,
            tdx_lease_report_data(&nonce, 7, "0xnode", "ssh-ed25519 AAAAother key")
        );
        assert_ne!(
            bound,
            tdx_lease_report_data(&nonce, 8, "0xnode", GUEST_CHANNEL_KEY)
        );
        assert_ne!(
            bound,
            tdx_lease_report_data(&nonce, 7, "0xother", GUEST_CHANNEL_KEY)
        );
        assert_ne!(
            bound,
            tdx_lease_report_data(&[0x23_u8; 32], 7, "0xnode", GUEST_CHANNEL_KEY)
        );
    }

    // Drop any one of the three and the report stops being about this guest, on
    // this lease, reachable at this key.
    #[test]
    fn snp_report_data_binds_the_nonce_the_lease_and_the_channel_key() {
        let nonce = [0x11_u8; 32];
        let bound = snp_report_data(&nonce, 42, GUEST_CHANNEL_KEY);

        assert_ne!(
            bound,
            snp_report_data(&[0x12_u8; 32], 42, GUEST_CHANNEL_KEY)
        );
        assert_ne!(bound, snp_report_data(&nonce, 43, GUEST_CHANNEL_KEY));
        assert_ne!(
            bound,
            snp_report_data(&nonce, 42, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 other-guest")
        );
    }

    fn unsigned_guest_attestation(node_id: &str, lease_id: u64) -> UnsignedGuestAttestation {
        UnsignedGuestAttestation {
            node_id: node_id.to_owned(),
            lease_id,
            challenge_id: Uuid::now_v7(),
            kind: AttestationKind::SevSnp,
            report_base64: URL_SAFE_NO_PAD.encode("snp attestation report"),
            certificate_chain_base64: vec![URL_SAFE_NO_PAD.encode("vcek der")],
            guest_channel_key: GUEST_CHANNEL_KEY.to_owned(),
            collected_at: Utc::now(),
        }
    }

    #[test]
    fn guest_attestation_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut attestation = GuestAttestation::sign(
            unsigned_guest_attestation(&node_id(&key.verifying_key()), 7),
            &key,
        )
        .unwrap();

        assert!(attestation.verify(&key.verifying_key()).is_ok());
        attestation.guest_channel_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 swapped".to_owned();
        assert!(attestation.verify(&key.verifying_key()).is_err());

        attestation.guest_channel_key = GUEST_CHANNEL_KEY.to_owned();
        attestation.lease_id = 8;
        assert!(attestation.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn guest_attestation_rejects_an_unbound_or_oversized_body() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut unsigned = unsigned_guest_attestation("0xabc", 0);
        assert!(matches!(
            GuestAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::InvalidAttestation)
        ));

        unsigned.lease_id = 7;
        unsigned.report_base64 = "A".repeat(MAX_SNP_REPORT_BYTES + 1);
        assert!(matches!(
            GuestAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.report_base64 = URL_SAFE_NO_PAD.encode("report");
        unsigned.certificate_chain_base64 = vec!["A".repeat(MAX_ATTESTATION_CERTIFICATE_BYTES + 1)];
        assert!(matches!(
            GuestAttestation::sign(unsigned, &key),
            Err(ProtocolError::AttestationTooLarge)
        ));
    }

    // Flips one byte of a decoded signature so it still parses as 64 bytes but
    // no longer matches the payload, which is what a mangled signature looks
    // like on the wire.
    fn tamper_signature(encoded: &str) -> String {
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        bytes[0] ^= 0x01;
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn unsigned_tdx_lease_attestation(node_id: &str, lease_id: u64) -> UnsignedTdxLeaseAttestation {
        UnsignedTdxLeaseAttestation {
            node_id: node_id.to_owned(),
            lease_id,
            challenge_id: Uuid::now_v7(),
            quote_base64: URL_SAFE_NO_PAD.encode("tdx quote"),
            tdx_event_log: vec![TdxEventEntry {
                imr: 1,
                event_type: 0x0000_0007,
                event: "boot".to_owned(),
                digest: "00".repeat(48),
                event_payload: String::new(),
            }],
            tdx_collateral_json: "{\"pck\":\"...\"}".to_owned(),
            guest_channel_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-lease".to_owned(),
            collected_at: Utc::now(),
        }
    }

    #[test]
    fn tdx_lease_attestation_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut attestation = TdxLeaseAttestation::sign(
            unsigned_tdx_lease_attestation(&node_id(&key.verifying_key()), 7),
            &key,
        )
        .unwrap();

        assert!(attestation.verify(&key.verifying_key()).is_ok());

        let good = attestation.signature.clone();
        attestation.signature = tamper_signature(&good);
        assert!(attestation.verify(&key.verifying_key()).is_err());

        attestation.signature = good;
        attestation.lease_id = 8;
        assert!(attestation.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn tdx_lease_attestation_rejects_an_unbound_or_oversized_body() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut unsigned = unsigned_tdx_lease_attestation("0xabc", 0);
        assert!(matches!(
            TdxLeaseAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::InvalidAttestation)
        ));

        unsigned.lease_id = 7;
        unsigned.quote_base64 = "A".repeat(MAX_ATTESTATION_EVIDENCE_BYTES + 1);
        assert!(matches!(
            TdxLeaseAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.quote_base64 = URL_SAFE_NO_PAD.encode("quote");
        unsigned.tdx_collateral_json = "A".repeat(MAX_TDX_COLLATERAL_BYTES + 1);
        assert!(matches!(
            TdxLeaseAttestation::sign(unsigned, &key),
            Err(ProtocolError::AttestationTooLarge)
        ));
    }

    fn unsigned_gpu_cc_attestation(node_id: &str, lease_id: u64) -> UnsignedGpuCcAttestation {
        UnsignedGpuCcAttestation {
            node_id: node_id.to_owned(),
            lease_id,
            challenge_id: Uuid::now_v7(),
            report_base64: URL_SAFE_NO_PAD.encode("gpu cc report"),
            // The NVIDIA device chain is five hops; sign one shaped like the real thing.
            certificate_chain_base64: vec![URL_SAFE_NO_PAD.encode("device cert"); 5],
            collected_at: Utc::now(),
        }
    }

    #[test]
    fn gpu_cc_attestation_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut attestation = GpuCcAttestation::sign(
            unsigned_gpu_cc_attestation(&node_id(&key.verifying_key()), 7),
            &key,
        )
        .unwrap();

        assert!(attestation.verify(&key.verifying_key()).is_ok());

        let good = attestation.signature.clone();
        attestation.signature = tamper_signature(&good);
        assert!(attestation.verify(&key.verifying_key()).is_err());

        attestation.signature = good;
        attestation.node_id = "0xdifferent".to_owned();
        assert!(attestation.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn gpu_cc_attestation_rejects_an_unbound_or_oversized_body() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut unsigned = unsigned_gpu_cc_attestation("0xabc", 0);
        assert!(matches!(
            GpuCcAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::InvalidAttestation)
        ));

        unsigned.lease_id = 7;
        unsigned.report_base64 = "A".repeat(MAX_GPU_CC_REPORT_BYTES + 1);
        assert!(matches!(
            GpuCcAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.report_base64 = URL_SAFE_NO_PAD.encode("report");
        unsigned.certificate_chain_base64 =
            vec![URL_SAFE_NO_PAD.encode("der"); MAX_ATTESTATION_CERTIFICATES + 1];
        assert!(matches!(
            GpuCcAttestation::sign(unsigned.clone(), &key),
            Err(ProtocolError::AttestationTooLarge)
        ));

        unsigned.certificate_chain_base64 = vec!["A".repeat(MAX_ATTESTATION_CERTIFICATE_BYTES + 1)];
        assert!(matches!(
            GpuCcAttestation::sign(unsigned, &key),
            Err(ProtocolError::AttestationTooLarge)
        ));
    }

    fn lease_verdict_at(
        lease_id: u64,
        kind: AttestationKind,
        granted: TrustClass,
        expires_at: DateTime<Utc>,
    ) -> LeaseAttestationVerdict {
        LeaseAttestationVerdict {
            lease_id,
            node_id: "0xabc".to_owned(),
            kind,
            guest: AttestedGuest {
                measurement: "d".repeat(96),
                host_data: "e".repeat(64),
                chip_id_digest: "f".repeat(64),
                reported_tcb: SnpTcb {
                    bootloader: 4,
                    tee: 0,
                    snp: 22,
                    microcode: 213,
                },
                policy_debug: false,
                vmpl: 0,
                channel_key_fingerprint: "SHA256:0000000000000000000000000000000000000000000"
                    .to_owned(),
                image_digest: "sha256:".to_owned() + &"a".repeat(64),
            },
            granted_class: granted,
            verifier_version: "prism-attestation/0.1.0".to_owned(),
            verified_at: expires_at - chrono::Duration::hours(1),
            expires_at,
        }
    }

    // Expectations are written unclamped and clamped on the way into the
    // assertion. While the ceiling sits at `Isolated` the bound case collapses
    // onto the rest; the day it moves, this starts discriminating without being
    // rewritten.
    #[test]
    fn a_lease_class_needs_a_live_verdict_naming_that_lease_on_that_node() {
        let now = Utc::now();
        let fresh = lease_verdict_at(
            7,
            AttestationKind::SevSnp,
            TrustClass::Attested,
            now + chrono::Duration::hours(2),
        );
        let expired = lease_verdict_at(
            7,
            AttestationKind::SevSnp,
            TrustClass::Attested,
            now - chrono::Duration::minutes(1),
        );
        let other_lease = lease_verdict_at(
            8,
            AttestationKind::SevSnp,
            TrustClass::Attested,
            now + chrono::Duration::hours(2),
        );
        let gpu_only = lease_verdict_at(
            7,
            AttestationKind::NvidiaGpu,
            TrustClass::Attested,
            now + chrono::Duration::hours(2),
        );

        let cases = [
            (
                "bound",
                "0xabc",
                TrustClass::Isolated,
                Some(&fresh),
                TrustClass::Attested,
            ),
            (
                "another node",
                "0xdef",
                TrustClass::Isolated,
                Some(&fresh),
                TrustClass::Isolated,
            ),
            (
                "another lease",
                "0xabc",
                TrustClass::Isolated,
                Some(&other_lease),
                TrustClass::Isolated,
            ),
            (
                "expired",
                "0xabc",
                TrustClass::Isolated,
                Some(&expired),
                TrustClass::Isolated,
            ),
            (
                "no verdict",
                "0xabc",
                TrustClass::Isolated,
                None,
                TrustClass::Isolated,
            ),
            (
                "open node",
                "0xabc",
                TrustClass::Open,
                Some(&fresh),
                TrustClass::Open,
            ),
            (
                "gpu verdict",
                "0xabc",
                TrustClass::Isolated,
                Some(&gpu_only),
                TrustClass::Isolated,
            ),
        ];

        for (name, node, node_class, verdict, expected) in cases {
            assert_eq!(
                class_for_lease(7, node, node_class, verdict, None, None, now),
                expected.min(MAX_VERIFIABLE_TRUST_CLASS),
                "{name}"
            );
        }
    }

    #[test]
    fn a_lease_class_never_exceeds_what_the_network_substantiates() {
        let now = Utc::now();
        let overreaching = lease_verdict_at(
            7,
            AttestationKind::SevSnp,
            TrustClass::Confidential,
            now + chrono::Duration::hours(2),
        );

        for node_class in [
            TrustClass::Open,
            TrustClass::Isolated,
            TrustClass::Attested,
            TrustClass::Confidential,
        ] {
            for verdict in [None, Some(&overreaching)] {
                assert!(
                    class_for_lease(7, "0xabc", node_class, verdict, None, None, now)
                        <= MAX_VERIFIABLE_TRUST_CLASS
                );
            }
        }
    }

    /// Confidential is two claims or nothing. A guest verdict alone carries
    /// the lease to Attested; a CC verdict alone carries it nowhere, because
    /// encrypted VRAM behind an unmeasured host is a locked door in an open
    /// wall. Together they derive Confidential, and the ceiling then says
    /// whether the network can serve what the evidence earned: today it
    /// clamps to Attested, and this test states both facts so moving the
    /// ceiling flips the second assertion and not the derivation.
    fn tdx_guest_verdict_at(
        lease_id: u64,
        granted: TrustClass,
        expires_at: DateTime<Utc>,
    ) -> LeaseTdxGuestVerdict {
        LeaseTdxGuestVerdict {
            lease_id,
            node_id: "0xabc".to_owned(),
            kind: AttestationKind::Tdx,
            device_identity: "tdx/instance".to_owned(),
            compose_hash: "a".repeat(64),
            channel_key_fingerprint: "SHA256:0000000000000000000000000000000000000000000"
                .to_owned(),
            measurement_digest: "c".repeat(64),
            granted_class: granted,
            verifier_version: "intel-tdx-guest/1".to_owned(),
            verified_at: expires_at - chrono::Duration::hours(1),
            expires_at,
        }
    }

    fn gpu_cc_verdict_at(
        lease_id: u64,
        kind: AttestationKind,
        granted: TrustClass,
        expires_at: DateTime<Utc>,
    ) -> LeaseGpuCcVerdict {
        LeaseGpuCcVerdict {
            lease_id,
            node_id: "0xabc".to_owned(),
            kind,
            device_identity: "NVIDIA GH100 / fwid".to_owned(),
            measurement_digest: "c".repeat(64),
            granted_class: granted,
            verifier_version: "nvidia-cc/1".to_owned(),
            verified_at: expires_at - chrono::Duration::hours(1),
            expires_at,
        }
    }

    #[test]
    fn confidential_takes_the_guest_and_the_gpu_together() {
        let now = Utc::now();
        let fresh = now + chrono::Duration::hours(2);
        let snp = lease_verdict_at(7, AttestationKind::SevSnp, TrustClass::Attested, fresh);
        let tdx = tdx_guest_verdict_at(7, TrustClass::Attested, fresh);
        let cc = gpu_cc_verdict_at(
            7,
            AttestationKind::NvidiaCc,
            TrustClass::Confidential,
            fresh,
        );
        let stale_cc = gpu_cc_verdict_at(
            7,
            AttestationKind::NvidiaCc,
            TrustClass::Confidential,
            now - chrono::Duration::minutes(1),
        );
        let cc_wrong_kind = gpu_cc_verdict_at(
            7,
            AttestationKind::NvidiaGpu,
            TrustClass::Confidential,
            fresh,
        );

        // Either guest half plus the GPU half reaches Confidential: SNP in the
        // guest slot, TDX in its own slot.
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                Some(&snp),
                None,
                Some(&cc),
                now
            ),
            TrustClass::Confidential
        );
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                None,
                Some(&tdx),
                Some(&cc),
                now
            ),
            TrustClass::Confidential
        );

        assert_eq!(
            class_for_lease(7, "0xabc", TrustClass::Isolated, None, None, Some(&cc), now),
            TrustClass::Isolated,
            "a CC verdict alone lifts nothing"
        );
        // Either guest half alone earns Attested.
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                Some(&snp),
                None,
                None,
                now
            ),
            TrustClass::Attested
        );
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                None,
                Some(&tdx),
                None,
                now
            ),
            TrustClass::Attested
        );
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                Some(&snp),
                None,
                Some(&stale_cc),
                now
            ),
            TrustClass::Attested,
            "a stale CC verdict subtracts the confidential half only"
        );
        // A CC verdict of the wrong attestation kind is not the VRAM claim.
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Isolated,
                Some(&snp),
                None,
                Some(&cc_wrong_kind),
                now
            ),
            TrustClass::Attested
        );
        // The guest half still needs the node standing at Isolated.
        assert_eq!(
            class_for_lease(
                7,
                "0xabc",
                TrustClass::Open,
                None,
                Some(&tdx),
                Some(&cc),
                now
            ),
            TrustClass::Open
        );
    }

    #[test]
    fn a_lease_verdict_digest_covers_every_field() {
        let now = Utc::now();
        let verdict = lease_verdict_at(
            7,
            AttestationKind::SevSnp,
            TrustClass::Attested,
            now + chrono::Duration::hours(2),
        );
        let mut relaunched = verdict.clone();
        relaunched.guest.measurement = "9".repeat(96);

        assert_ne!(
            lease_verdict_digest(&verdict).unwrap(),
            lease_verdict_digest(&relaunched).unwrap()
        );
        assert_eq!(lease_verdict_digest(&verdict).unwrap().len(), 64);
    }

    #[test]
    fn a_verdict_digest_covers_every_field() {
        let now = Utc::now();
        let verdict = verdict_at(
            AttestationKind::NvidiaGpu,
            TrustClass::Isolated,
            now + chrono::Duration::hours(12),
        );
        let mut moved = verdict.clone();
        moved.device_identity = "CN=NVIDIA GH100 / serial 1323824099999".to_owned();

        assert_ne!(
            verdict_digest(&verdict).unwrap(),
            verdict_digest(&moved).unwrap()
        );
        assert_eq!(verdict_digest(&verdict).unwrap().len(), 64);
    }

    /// Adding attestation types must not move a byte of the heartbeat payload:
    /// deployed nodes are already signing this exact string.
    #[test]
    fn telemetry_signing_payload_is_unchanged_by_attestation_types() {
        let observed_at = DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let unsigned = UnsignedTelemetry {
            node_id: "0xabc".to_owned(),
            sequence: 7,
            observed_at,
            gpu_utilization_bps: 4_200,
            gpu_memory_used_mib: 1_024,
            active_lease: Some("11".to_owned()),
            tunnel_connected: true,
            image_digest: Some("sha256:abc".to_owned()),
            posture: None,
        };

        assert_eq!(
            canonical_json(&unsigned).unwrap(),
            r#"{"node_id":"0xabc","sequence":7,"observed_at":"2026-07-24T00:00:00Z","gpu_utilization_bps":4200,"gpu_memory_used_mib":1024,"active_lease":"11","tunnel_connected":true,"image_digest":"sha256:abc"}"#
        );

        let with_posture = UnsignedTelemetry {
            posture: Some(NodePosture {
                isolation: IsolationMode::KataVfio,
                attestation: None,
            }),
            ..unsigned
        };

        assert_eq!(
            canonical_json(&with_posture).unwrap(),
            r#"{"node_id":"0xabc","sequence":7,"observed_at":"2026-07-24T00:00:00Z","gpu_utilization_bps":4200,"gpu_memory_used_mib":1024,"active_lease":"11","tunnel_connected":true,"image_digest":"sha256:abc","posture":{"isolation":"kata_vfio"}}"#
        );
    }

    // Kernel 6.8 has SEV and SEV-ES but no SNP host support. That has to read
    // differently from a box with no TEE at all, or the gap is invisible.
    #[test]
    fn a_host_without_snp_is_not_a_host_without_a_tee() {
        let genoa = HostTeeCapability {
            sev: true,
            sev_es: true,
            sev_snp: false,
            sev_guest_device: true,
            kata_runtime: true,
            kata_confidential_runtime: false,
        };

        assert_ne!(genoa, HostTeeCapability::default());
        assert!(!genoa.sev_snp);
    }

    #[test]
    fn credential_cipher_rejects_tampering() {
        let cipher = CredentialCipher::from_hex(&"11".repeat(32)).unwrap();
        let mut secret = cipher.encrypt("temporary credential").unwrap();
        assert_eq!(cipher.decrypt(&secret).unwrap(), "temporary credential");
        secret.ciphertext.push('A');
        assert!(cipher.decrypt(&secret).is_err());
    }

    #[test]
    fn tunnel_registration_is_bound_to_the_connection() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut registration = TunnelRegistration::sign(
            UnsignedTunnelRegistration {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                connection_id: "connection-1".to_owned(),
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(registration.verify(&key.verifying_key()).is_ok());
        registration.connection_id = "connection-2".to_owned();
        assert!(registration.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn certificate_request_is_bound_to_the_csr() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut request = NodeCertificateRequest::sign(
            UnsignedNodeCertificateRequest {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                request_id: Uuid::now_v7(),
                csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----"
                    .to_owned(),
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(request.verify(&key.verifying_key()).is_ok());
        request.csr_pem.push('x');
        assert!(request.verify(&key.verifying_key()).is_err());
    }

    fn signed_report(key: &SigningKey, result: Option<CommandResult>) -> NodeCommandReport {
        NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                request_id: Uuid::now_v7(),
                command_id: Uuid::now_v7(),
                outcome: NodeCommandOutcome::Completed,
                observed_at: Utc::now(),
                error: None,
                result,
            },
            key,
        )
        .unwrap()
    }

    /// A node that can edit the exit code after signing could bill a failure as
    /// a success, so the result has to sit inside the signature.
    #[test]
    fn a_batch_result_cannot_be_edited_after_signing() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut report = signed_report(&key, Some(CommandResult::capture(1, "out", "boom")));
        assert!(report.verify(&key.verifying_key()).is_ok());

        report.result.as_mut().unwrap().exit_code = 0;
        assert!(report.verify(&key.verifying_key()).is_err());
    }

    /// Launch and Stop predate batch and must keep signing the bytes they
    /// always signed, which only holds while an absent result is skipped
    /// rather than encoded as null.
    #[test]
    fn a_report_without_a_result_signs_the_same_bytes_as_before() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let report = signed_report(&key, None);
        let encoded = canonical_json(&NodeCommandReportPayload {
            node_id: report.node_id.clone(),
            device_public_key: report.device_public_key.clone(),
            request_id: report.request_id,
            command_id: report.command_id,
            outcome: report.outcome.clone(),
            observed_at: report.observed_at,
            error: None,
            result: None,
        })
        .unwrap();
        assert!(!encoded.contains("result"), "{encoded}");
        assert!(report.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn capture_keeps_the_tail_and_says_so() {
        let short = CommandResult::capture(0, "all of it", "");
        assert_eq!(short.stdout, "all of it");
        assert!(!short.truncated);

        let long = "x".repeat(MAX_CAPTURED_OUTPUT_BYTES + 500);
        let cut = CommandResult::capture(0, &long, "");
        assert!(cut.truncated);
        assert_eq!(cut.stdout.len(), MAX_CAPTURED_OUTPUT_BYTES);
        assert!(cut.within_limits());
    }

    /// Cutting a byte count out of the middle of a character would leave a
    /// string that will not serialize.
    #[test]
    fn capture_cuts_on_a_character_boundary() {
        let long = "é".repeat(MAX_CAPTURED_OUTPUT_BYTES);
        let cut = CommandResult::capture(0, &long, "");
        assert!(cut.truncated);
        assert!(cut.stdout.len() <= MAX_CAPTURED_OUTPUT_BYTES);
        assert!(cut.stdout.chars().all(|character| character == 'é'));
    }

    #[test]
    fn command_reports_are_bound_to_the_command_and_outcome() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let command_id = Uuid::now_v7();
        let mut report = NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                request_id: Uuid::now_v7(),
                command_id,
                outcome: NodeCommandOutcome::Ready,
                observed_at: Utc::now(),
                error: None,
                result: None,
            },
            &key,
        )
        .unwrap();

        assert!(report.verify(&key.verifying_key()).is_ok());
        report.command_id = Uuid::now_v7();
        assert!(report.verify(&key.verifying_key()).is_err());
    }

    // The SDK reproduces this exact byte string in JavaScript. If either side
    // drifts, every stored item stops opening, so pin it with a literal rather
    // than by calling the function twice.
    #[test]
    fn vault_associated_data_matches_the_published_vector() {
        let aad = vault_associated_data(
            "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
            Uuid::parse_str("018f3a2b-4c5d-7e8f-9012-3456789abcde").unwrap(),
            7,
            TrustClass::Confidential,
        );

        // Separators are spelled `\x00`: a `\0` before a digit reads as an
        // octal escape and would quietly change the vector.
        assert_eq!(
            aad,
            b"prism.vault.v1\x000x1f9840a85d5af5bf1d1762f925bdaddc4201f984\x00018f3a2b-4c5d-7e8f-9012-3456789abcde\x007\x00confidential\x00"
        );
    }

    #[test]
    fn vault_associated_data_separates_every_field() {
        let item = Uuid::now_v7();
        let base = vault_associated_data("a", item, 1, TrustClass::Open);

        assert_ne!(base, vault_associated_data("b", item, 1, TrustClass::Open));
        assert_ne!(
            base,
            vault_associated_data("a", Uuid::now_v7(), 1, TrustClass::Open)
        );
        assert_ne!(base, vault_associated_data("a", item, 2, TrustClass::Open));
        assert_ne!(
            base,
            vault_associated_data("a", item, 1, TrustClass::Isolated)
        );
    }

    // Concatenation without the separator would let a crafted subject absorb the
    // next field and collide with a different account's binding.
    #[test]
    fn vault_associated_data_resists_field_smuggling() {
        let item = Uuid::now_v7();
        assert_ne!(
            vault_associated_data(&format!("a\0{item}"), item, 1, TrustClass::Open),
            vault_associated_data("a", item, 1, TrustClass::Open)
        );
    }

    #[test]
    fn vault_release_needs_a_lease_at_or_above_the_floor() {
        assert!(vault_release_permitted(TrustClass::Open, TrustClass::Open));
        assert!(vault_release_permitted(
            TrustClass::Isolated,
            TrustClass::Attested
        ));
        assert!(!vault_release_permitted(
            TrustClass::Isolated,
            TrustClass::Open
        ));
        assert!(!vault_release_permitted(
            TrustClass::Confidential,
            TrustClass::Attested
        ));
    }

    // The default floor has to sit above anything the network can actually
    // serve, or a stored card could reach a host that reads it.
    #[test]
    fn the_default_floor_is_met_only_by_confidential_capacity() {
        // The floor is the top of what the network can serve, so a confidential
        // lease clears it and every weaker class is refused.
        assert_eq!(DEFAULT_VAULT_TRUST_FLOOR, MAX_VERIFIABLE_TRUST_CLASS);
        assert!(vault_release_permitted(
            DEFAULT_VAULT_TRUST_FLOOR,
            TrustClass::Confidential
        ));
        for lease in [TrustClass::Open, TrustClass::Isolated, TrustClass::Attested] {
            assert!(!vault_release_permitted(DEFAULT_VAULT_TRUST_FLOOR, lease));
        }
    }

    #[test]
    fn stake_tiers_rise_with_the_stake_and_stop_at_the_ceiling() {
        assert_eq!(stake_discount_bps(0), 0);
        assert_eq!(stake_discount_bps(999), 0);
        assert_eq!(stake_discount_bps(1_000), 500);
        assert_eq!(stake_discount_bps(9_999), 500);
        assert_eq!(stake_discount_bps(10_000), 1_000);
        assert_eq!(stake_discount_bps(50_000), 1_500);
        assert_eq!(stake_discount_bps(250_000), 2_000);
        assert_eq!(stake_discount_bps(u64::MAX), MAX_STAKE_DISCOUNT_BPS);
    }

    // The tiers are read in order and the last match wins, so an unsorted or
    // duplicated table would silently mis-price every quote.
    #[test]
    fn stake_tiers_are_sorted_and_within_the_ceiling() {
        let mut previous = (0, 0);
        for (threshold, bps) in STAKE_DISCOUNT_TIERS {
            assert!(threshold > previous.0, "thresholds must ascend");
            assert!(bps > previous.1, "discounts must ascend");
            assert!(bps <= MAX_STAKE_DISCOUNT_BPS, "tier exceeds the ceiling");
            previous = (threshold, bps);
        }
    }

    #[test]
    fn a_discount_never_reaches_zero_or_exceeds_the_ceiling() {
        assert_eq!(discounted_rate(222, 0), 222);
        assert_eq!(discounted_rate(222, 500), 210);
        assert_eq!(discounted_rate(222, 2_000), 177);
        // Asking for more than the ceiling gets the ceiling, not more.
        assert_eq!(
            discounted_rate(222, 9_000),
            discounted_rate(222, MAX_STAKE_DISCOUNT_BPS)
        );
        assert_eq!(discounted_rate(1, 2_000), 1, "a rate must stay payable");
        assert_eq!(discounted_rate(0, 2_000), 0);
    }

    // A discount that could ever raise a price would be a pricing bug pointed
    // at the customer, so pin the direction across the whole range.
    #[test]
    fn a_credited_receipt_hashes_the_credit_last() {
        let receipt = PublicReceipt {
            receipt_id: Uuid::parse_str("019f0000-0000-7000-8000-000000000001").unwrap(),
            lease_id: "128".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: format!("0x{}", "a".repeat(64)),
            gpu_model: "NVIDIA L40S".to_owned(),
            runtime_seconds: 200,
            charged_base_units: 44_400,
            refunded_base_units: 155_400,
            provider_paid_base_units: 39_960,
            failure_class: Some("interrupted".to_owned()),
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Open),
            attestation: None,
            credited_seconds: Some(150),
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", "c".repeat(64)),
        };
        // Pinned so the browser-side verifier in apps/web/lib/proof.ts can be
        // checked against this, not against itself. The credit is the last
        // field in the payload, which is what keeps every receipt settled
        // before it hashing exactly as it did.
        assert_eq!(
            receipt_hash(&receipt).unwrap(),
            "c63e4690f2e6be23ecf474e2f5e813b3eecce5b36a3d4a2b39b3c6e87e7de135"
        );
    }

    #[test]
    fn a_discount_only_ever_lowers_a_rate() {
        for rate in [1_u64, 2, 7, 222, 1_000, 999_999, u64::MAX / 10_000] {
            for bps in [0_u16, 1, 500, 1_000, 1_500, 2_000, u16::MAX] {
                let out = discounted_rate(rate, bps);
                assert!(out <= rate, "rate {rate} at {bps}bps went up to {out}");
                assert!(out >= 1, "rate {rate} at {bps}bps hit zero");
            }
        }
    }
}
