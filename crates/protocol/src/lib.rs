use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const ROBINHOOD_TESTNET_CHAIN_ID: u64 = 46_630;
pub const USDG_MAINNET: &str = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
pub const MAX_ESCROW_BASE_UNITS: u64 = 50_000_000;
pub const MAX_LEASE_SECONDS: u32 = 21_600;
pub const MAX_NETWORK_LEASES: usize = 25;
const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-enrollment.v1\0";
const TELEMETRY_SIGNATURE_DOMAIN: &[u8] = b"prism.node-telemetry.v1\0";
const TUNNEL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-tunnel.v1\0";
const CERTIFICATE_SIGNATURE_DOMAIN: &[u8] = b"prism.node-certificate.v1\0";
const COMMAND_POLL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-poll.v1\0";
const COMMAND_REPORT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-report.v1\0";

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
    /// Launch measurement and GPU device identity verified against vendor
    /// roots, so the renter can check what booted.
    Attested,
    /// Guest memory and VRAM are encrypted against the host.
    Confidential,
}

/// The strongest class the network can currently substantiate. Attestation
/// evidence is carried end to end but not yet verified, so nothing is served
/// above `Isolated` no matter what a node claims. Raise this only when a
/// verifier is wired in.
pub const MAX_VERIFIABLE_TRUST_CLASS: TrustClass = TrustClass::Isolated;

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
    /// The class this posture would justify if every piece of evidence in it
    /// checked out. Callers must clamp it with [`MAX_VERIFIABLE_TRUST_CLASS`].
    pub fn claimed_class(&self) -> TrustClass {
        match (self.isolation, self.attestation.as_ref()) {
            (IsolationMode::Shared, _) => TrustClass::Open,
            (IsolationMode::KataVfio, None) => TrustClass::Isolated,
            (IsolationMode::KataVfio, Some(attestation)) => match attestation.kind {
                AttestationKind::NvidiaCc => TrustClass::Confidential,
                AttestationKind::SevSnp | AttestationKind::Tdx => TrustClass::Attested,
            },
        }
    }

    pub fn effective_class(&self) -> TrustClass {
        self.claimed_class().min(MAX_VERIFIABLE_TRUST_CLASS)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRecord {
    pub lease_id: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReceipt {
    pub receipt_id: Uuid,
    pub lease_id: String,
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
    pub receipt_hash: String,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementEvidence {
    pub lease_id: u64,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_class: Option<TrustClass>,
    #[serde(default)]
    pub execution: ExecutionEvidence,
    pub node_telemetry: Vec<NodeTelemetry>,
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

/// New items are sealed against every trust class the network can serve today,
/// so an agent cannot hand one to a rented box until attested capacity exists.
/// Storing and reading back on the renter's own machine is unaffected.
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
    };
    Ok(hex::encode(Sha256::digest(canonical_json(&payload)?)))
}

pub fn receipt_hash_matches(receipt: &PublicReceipt) -> Result<bool, ProtocolError> {
    Ok(receipt.receipt_hash == receipt_hash(receipt)?)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_string(value).map_err(ProtocolError::Serialization)
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
    #[error("serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("credential encryption key is invalid")]
    InvalidEncryptionKey,
    #[error("credential encryption failed")]
    Encryption,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn posture_claims_are_clamped_to_what_the_network_can_verify() {
        let confidential = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: Some(AttestationRef {
                kind: AttestationKind::NvidiaCc,
                quote_sha256: "0".repeat(64),
            }),
        };

        assert_eq!(confidential.claimed_class(), TrustClass::Confidential);
        assert_eq!(confidential.effective_class(), MAX_VERIFIABLE_TRUST_CLASS);

        let shared = NodePosture::default();
        assert_eq!(shared.claimed_class(), TrustClass::Open);
        assert_eq!(shared.effective_class(), TrustClass::Open);
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
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000,
            refunded_base_units: 0,
            provider_paid_base_units: 900,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
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

    /// Receipts already published on chain carry no trust class. Their hashes
    /// are committed by settlement transactions, so the payload must still
    /// serialize exactly as it did before the field existed.
    #[test]
    fn receipts_without_a_trust_class_keep_their_published_hash() {
        let receipt_id = Uuid::now_v7();
        let receipt = PublicReceipt {
            receipt_id,
            lease_id: "11".to_owned(),
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L40S".to_owned(),
            runtime_seconds: 300,
            charged_base_units: 66_600,
            refunded_base_units: 0,
            provider_paid_base_units: 59_940,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
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
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L40S".to_owned(),
            runtime_seconds: 300,
            charged_base_units: 66_600,
            refunded_base_units: 0,
            provider_paid_base_units: 59_940,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Open),
            receipt_hash: String::new(),
            transaction_hash: "0x3669fa89".to_owned(),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.trust_class = Some(TrustClass::Confidential);
        assert!(!receipt_hash_matches(&receipt).unwrap());
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
    fn the_default_floor_is_out_of_reach_of_servable_capacity() {
        assert!(DEFAULT_VAULT_TRUST_FLOOR > MAX_VERIFIABLE_TRUST_CLASS);
        assert!(!vault_release_permitted(
            DEFAULT_VAULT_TRUST_FLOOR,
            MAX_VERIFIABLE_TRUST_CLASS
        ));
    }
}
