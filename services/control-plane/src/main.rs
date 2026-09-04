use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::Path as FilePath,
    sync::{Arc, OnceLock},
};

mod amd_kds;
mod workspaces;

use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use prism_protocol::{
    Account, AttestationChallenge, AttestationKind, AttestationVerdict, CommandResult,
    CredentialCipher, DEFAULT_WORKSPACE_TRUST_FLOOR, EncryptedSecret, GpuCcAttestation,
    GpuReproSpec, GuestAttestation, LeaseAccess, LeaseAttestationVerdict, LeaseGpuCcVerdict,
    LeaseQuote, LeaseRecord, LeaseRequest, LeaseState, LeaseTdxGuestVerdict, MAX_ESCROW_BASE_UNITS,
    MAX_LEASE_SECONDS, MAX_NETWORK_LEASES, MAX_VAULT_CIPHERTEXT_BYTES, MAX_VAULT_ITEMS_PER_ACCOUNT,
    MAX_VAULT_LABEL_BYTES, MAX_WORKSPACE_BYTES, MAX_WORKSPACE_NAME_BYTES,
    MAX_WORKSPACES_PER_ACCOUNT, ManagedCommandReport, ManagedProvider, NodeAttestation,
    NodeCertificateBundle, NodeCertificateRequest, NodeCommand, NodeCommandKind,
    NodeCommandOutcome, NodeCommandPoll, NodeCommandReport, NodeCommandReportAck, NodeEnrollment,
    NodeOffer, NodePosture, NodeTelemetry, PublicReceipt, ReceiptOutcome, ReproExecutionReport,
    ReproExecutor, STANDARD_RATE_PER_SECOND, SettlementEvidence, TdxEventEntry,
    TdxLeaseAttestation, TrustClass, VaultEnvelope, VaultItem, VaultRelease, VaultWrite, Workspace,
    WorkspaceSnapshot, attestation_report_nonce, class_for_lease, class_for_verdict,
    discounted_rate, managed_repro_report_hash, node_id, receipt_hash_matches, repro_command_hash,
    repro_report_hash, repro_result_hash, repro_stream_hash, repro_token_hash, snp_report_data,
    stake_discount_bps, tdx_lease_report_data, tdx_report_data, vault_release_permitted,
    verifying_key,
};
use rand::RngCore;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    Error as SqlError,
    migrate::{Migration, MigrationType, Migrator},
    query::query,
    query_as::query_as,
    query_scalar::query_scalar,
    transaction::Transaction,
    types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions, Postgres};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const SCHEDULER_LOCK_KEY: i64 = 4_663;
/// Stands in for a deployed escrow when the store runs without a chain, so a
/// development lease still carries the same shape of identity as a real one.
const DEVELOPMENT_ESCROW_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
/// Internal lease ids start here so they can never be mistaken for, or collide
/// with, an id a superseded escrow handed out. Kept in step with the sequence
/// floor in `0014_escrow_generation.sql`.
const INTERNAL_LEASE_ID_FLOOR: u64 = 1_000;
const AUTH_MAX_AGE_SECONDS: i64 = 60;
const NODE_MESSAGE_MAX_AGE_SECONDS: i64 = 300;
const OFFER_MAX_AGE_SECONDS: i64 = 90;
/// How long a quote holds its node against other renters. A quote stays valid
/// for five minutes, but the hold only has to cover the funding round trip:
/// approve, createLease, confirm. Holding for the whole five minutes means one
/// renter who changes their mind takes a small network out of service, and
/// losing the race afterwards costs gas rather than the deposit, because
/// createLease reverts as a whole when the node is no longer schedulable.
const QUOTE_HOLD_SECONDS: i64 = 90;
/// Mirrors the node's own limit, so the two agree on what it will accept.
const MAX_BATCH_COMMAND_BYTES: usize = 8 * 1024;
const MAX_REPRO_STATUS_RESPONSE_BYTES: usize = 512 * 1_024;
const REPRO_STATUS_VERSION: &str = "prism.gpu-repro.status.v1";
const REPRO_STATUS_LEASE_QUERY: &str = "SELECT q.document, l.lease_id, l.chain_lease_id, l.state, \
        l.document->>'node_id', l.document #>> '{repro,token_hash}', \
        l.document #>> '{repro,spec_hash}', nc.status, nc.document, nc.verified_report, nc.result, \
        mj.status, mj.command, mj.report, pr.document, o.document->>'device_public_key' \
    FROM leases l \
    JOIN lease_quotes q ON q.quote_id = l.quote_id \
    JOIN node_offers o ON o.node_id = l.document->>'node_id' \
    LEFT JOIN node_commands nc ON nc.lease_id = l.lease_id \
    LEFT JOIN managed_repro_jobs mj ON mj.lease_id = l.lease_id \
    LEFT JOIN proof_receipts pr ON pr.lease_id = l.lease_id \
    WHERE l.document #>> '{repro,token_hash}' = $1 \
    ORDER BY l.created_at DESC LIMIT 1";
const REPRO_STATUS_QUOTE_QUERY: &str = "SELECT document FROM lease_quotes \
    WHERE document #>> '{repro,token_hash}' = $1 \
    ORDER BY created_at DESC LIMIT 1";
const REPRO_STATUS_CLAIM_COUNT_QUERY: &str = "SELECT COUNT(*) FROM ( \
        SELECT quote_id FROM lease_quotes \
        WHERE document #>> '{repro,token_hash}' = $1 \
        UNION \
        SELECT quote_id FROM leases \
        WHERE document #>> '{repro,token_hash}' = $1 \
    ) claims";
const QUOTE_TTL_MINUTES: i64 = 5;
/// How long a node's command poll is remembered. It started as the replay
/// guard's retention window and now also decides who can be handed batch work:
/// an offer matches a command request only while one of its polls is still
/// inside this window. Shortening it narrows the batch fleet, so change it
/// against `a_node_that_stopped_polling_falls_out_of_batch_matching`, not on
/// replay grounds alone.
const NODE_REQUEST_TTL_MINUTES: i64 = 5;
/// A single presigned PUT is all object storage accepts in one request, and it
/// stops well below `MAX_WORKSPACE_BYTES`. Refusing here is better than minting
/// a URL that the upload fails against after the renter has sent gigabytes.
const MAX_SNAPSHOT_UPLOAD_BYTES: u64 = 5 * 1_024 * 1_024 * 1_024;
/// Long enough for a node to read its GPU and post the report, short enough
/// that a nonce lifted off the wire is worthless by the time it is used.
const ATTESTATION_CHALLENGE_TTL_MINUTES: i64 = 5;
/// A verdict is device identity and firmware, neither of which changes hourly,
/// but re-proving daily is what makes a card that left the machine stop
/// carrying the class it earned.
const ATTESTATION_VERDICT_TTL_HOURS: i64 = 24;
/// A guest has to boot, generate its host key and take a report before it can
/// answer, which is minutes rather than the seconds a GPU read costs. Still
/// short enough that a nonce lifted off the wire is worthless by the time a
/// second guest could be launched against it.
const LEASE_ATTESTATION_CHALLENGE_TTL_MINUTES: i64 = 15;
/// A guest verdict is about one lease, so it is given the life of that lease
/// plus enough slack to cover provisioning. Nothing is served on it afterwards.
const LEASE_VERDICT_PROVISIONING_SLACK_HOURS: i64 = 2;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    store: MarketplaceStore,
    registry: RegistryVerifier,
    chain: ChainVerifier,
    identity: IdentityVerifier,
    credential_cipher: CredentialCipher,
    gateway_token: Option<Arc<String>>,
    public_gateway_host: Arc<String>,
    public_relay_port: u16,
    certificate_authority: Arc<CertificateAuthority>,
    require_node_certificates: bool,
    stake: StakeReader,
    workspaces: Option<Arc<workspaces::WorkspaceStorage>>,
    attestation_policy: Arc<prism_attestation::Policy>,
    /// Compose hashes a TDX node may prove it launched from, from
    /// PRISM_TDX_COMPOSE_HASHES. Empty refuses all TDX evidence.
    tdx_compose_allowlist: Arc<Vec<[u8; 32]>>,
    /// Absent only where the deployment has no route to AMD, in which case a
    /// guest that sends no chain is refused rather than quietly downgraded.
    amd_kds: Option<amd_kds::AmdKds>,
}

#[derive(Debug, Clone)]
struct VerifiedIdentity {
    subject: String,
    session_id: String,
    request_id: String,
}

#[derive(Clone)]
enum IdentityVerifier {
    Development,
    Hmac(Vec<u8>),
}

#[derive(Debug, Error)]
enum IdentityError {
    #[error("invalid internal identity signature")]
    InvalidSignature,
    #[error("internal identity has expired")]
    Expired,
}

#[derive(Clone)]
enum RegistryVerifier {
    Development,
    Rpc {
        client: reqwest::Client,
        rpc_url: String,
        registry_address: String,
    },
}

#[derive(Clone)]
enum ChainVerifier {
    Development {
        escrow_address: Option<String>,
    },
    Rpc {
        client: reqwest::Client,
        rpc_url: String,
        escrow_address: String,
        confirmations: u64,
    },
}

#[derive(Debug, Error)]
enum ChainError {
    #[error("funding transaction hash is invalid")]
    InvalidTransactionHash,
    #[error("chain RPC request failed")]
    Rpc(#[source] reqwest::Error),
    #[error("chain RPC returned an invalid response")]
    InvalidResponse,
    #[error("funding transaction is not final")]
    NotFinal,
    #[error("funding transaction reverted")]
    Reverted,
    #[error("funding event does not match the quote")]
    FundingMismatch,
}

#[derive(Debug, Error)]
enum RegistryError {
    #[error("node ID is not a bytes32 hex value")]
    InvalidNodeId,
    #[error("node registry RPC request failed")]
    Rpc(#[source] reqwest::Error),
    #[error("node registry RPC returned an invalid response")]
    InvalidResponse,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionReceipt {
    status: String,
    block_number: String,
    logs: Vec<ChainLog>,
}

#[derive(Deserialize)]
struct ChainLog {
    address: String,
    topics: Vec<String>,
    data: String,
}

struct AttestationSubmission<'a> {
    attestation: &'a NodeAttestation,
    /// The key this node enrolled with, not one carried on the submission.
    /// It is half of what the GPU signed over, so a report built against any
    /// other key hashes to a nonce that does not match.
    device_public_key: &'a str,
    policy: &'a prism_attestation::Policy,
    /// Compose hashes a TDX node may prove it launched from. Empty means no
    /// TDX evidence can verify, which is the shipped state until an operator
    /// deliberately lists the images this deployment accepts.
    tdx_compose_allowlist: &'a [[u8; 32]],
}

struct LeaseAttestationSubmission<'a> {
    attestation: &'a GuestAttestation,
    /// The lease this report claims to be about, resolved from the path. The
    /// image on it is what the guest's `HOST_DATA` has to name, and the node on
    /// it is who is allowed to present the report.
    lease: &'a LeaseRecord,
    policy: &'a prism_attestation::Policy,
}

/// The TDX counterpart of `LeaseAttestationSubmission`. It carries its own wire
/// type rather than sharing one: a TDX quote, its event log and Intel
/// collateral answer nothing the SEV-SNP fields describe, so folding them into
/// one shape would mean a submission full of columns the other kind never sets.
struct LeaseTdxAttestationSubmission<'a> {
    attestation: &'a TdxLeaseAttestation,
    /// The lease this quote claims to be about. The image on it fixes the
    /// compose the TD has to have launched from, and the node on it is who is
    /// allowed to present the quote.
    lease: &'a LeaseRecord,
    policy: &'a prism_attestation::Policy,
}

/// The GPU-CC counterpart. The card signs a report over the control plane's
/// nonce; the lease and node on the record are what the verdict is bound to.
struct LeaseGpuCcAttestationSubmission<'a> {
    attestation: &'a GpuCcAttestation,
    lease: &'a LeaseRecord,
    policy: &'a prism_attestation::Policy,
}

struct ConfirmedFunding {
    /// The id the escrow assigned. Unique only within the escrow that issued
    /// it, which is why the address travels with it.
    lease_id: u64,
    escrow_address: String,
    renter_wallet: String,
}

struct FundingConfirmation<'a> {
    subject: &'a str,
    quote: &'a LeaseQuote,
    transaction_hash: &'a str,
    funding: ConfirmedFunding,
    ssh_authorized_key: Option<&'a str>,
    jupyter_token: &'a str,
    encrypted_jupyter_token: EncryptedSecret,
}

#[derive(Clone)]
enum MarketplaceStore {
    Memory(Arc<RwLock<MemoryMarketplace>>),
    Postgres(PgPool),
}

#[derive(Default)]
struct MemoryMarketplace {
    offers: BTreeMap<String, NodeOffer>,
    telemetry: BTreeMap<String, NodeTelemetry>,
    open_quotes: BTreeMap<Uuid, LeaseQuote>,
    quote_subjects: BTreeMap<Uuid, String>,
    consumed_quotes: BTreeSet<Uuid>,
    repro_token_hashes: BTreeSet<String>,
    leases: BTreeMap<u64, (String, LeaseRecord)>,
    commands: BTreeMap<Uuid, MemoryCommand>,
    /// Request id to the node that sent it and when the record expires. The
    /// node id is what makes this table answer "is this node still polling".
    node_requests: BTreeMap<Uuid, (String, chrono::DateTime<Utc>)>,
    accounts: BTreeMap<String, bool>,
    suspended_accounts: BTreeSet<String>,
    sessions: BTreeMap<String, String>,
    revoked_sessions: BTreeSet<String>,
    identity_requests: BTreeMap<String, chrono::DateTime<Utc>>,
    tunnels: BTreeMap<String, chrono::DateTime<Utc>>,
    tunnel_connections: BTreeMap<String, String>,
    lease_secrets: BTreeMap<u64, EncryptedSecret>,
    lifecycle: BTreeMap<u64, MemoryLifecycle>,
    lifecycle_actions: BTreeSet<(u64, &'static str)>,
    certificates: BTreeMap<String, StoredNodeCertificate>,
    certificate_requests: BTreeSet<Uuid>,
    wallet_challenges: BTreeMap<Uuid, (String, WalletChallenge)>,
    linked_wallets: BTreeMap<String, BTreeSet<String>>,
    operators: BTreeSet<String>,
    suspended_nodes: BTreeSet<String>,
    operator_actions: BTreeSet<Uuid>,
    operator_audit: Vec<OperatorAuditEvent>,
    vault_items: BTreeMap<Uuid, (String, VaultItem)>,
    vault_releases: Vec<(String, VaultRelease)>,
    workspaces: BTreeMap<Uuid, (String, Workspace)>,
    attestation_challenges: BTreeMap<Uuid, StoredChallenge>,
    verdicts: BTreeMap<String, AttestationVerdict>,
    lease_challenges: BTreeMap<u64, StoredChallenge>,
    lease_verdicts: BTreeMap<u64, LeaseAttestationVerdict>,
    /// The TDX guest half of a lease, kept apart from the SEV-SNP half because a
    /// TD's evidence is an image measurement and a runtime-register binding, not
    /// the chip and VMSA columns an SNP verdict carries.
    lease_tdx_guest_verdicts: BTreeMap<u64, LeaseTdxGuestVerdict>,
    /// The GPU confidential-computing half of a lease. It rides its own axis
    /// because encrypted VRAM behind an unmeasured guest earns nothing on its
    /// own, so it never folds into a guest verdict.
    lease_gpu_cc_verdicts: BTreeMap<u64, LeaseGpuCcVerdict>,
    /// The GPU-CC submission answers a nonce of its own rather than the guest
    /// one, so a report captured for the guest challenge cannot stand in for it.
    lease_gpu_cc_challenges: BTreeMap<u64, StoredChallenge>,
    /// Which node a physical processor was last attested under, so the same
    /// chip cannot stand behind two identities.
    snp_chips: BTreeMap<String, String>,
}

struct StoredChallenge {
    challenge: AttestationChallenge,
    consumed_at: Option<chrono::DateTime<Utc>>,
}

/// The challenge is stored hex and the GPU signs over the bytes, so the two
/// sides only agree if this decodes. A stored nonce that is not hex is our own
/// corruption, never something a node can provoke.
fn expected_report_nonce(
    nonce: &str,
    node_id: &str,
    device_public_key: &str,
) -> Result<[u8; 32], StoreError> {
    let nonce = hex::decode(nonce)
        .map_err(|_| StoreError::InvalidStoredState("attestation nonce is not hex".to_owned()))?;
    Ok(attestation_report_nonce(&nonce, node_id, device_public_key))
}

/// The wire event log, hex fields decoded into what the verifier judges. A
/// field that does not decode refuses the submission; the verifier never sees
/// a partially decoded log.
fn decode_tdx_events(
    entries: &[TdxEventEntry],
) -> Result<Vec<prism_attestation::TdxEvent>, &'static str> {
    entries
        .iter()
        .map(|entry| {
            Ok(prism_attestation::TdxEvent {
                imr: entry.imr,
                event_type: entry.event_type,
                name: entry.event.clone(),
                digest: hex::decode(&entry.digest).map_err(|_| "an event digest is not hex")?,
                payload: hex::decode(&entry.event_payload)
                    .map_err(|_| "an event payload is not hex")?,
            })
        })
        .collect()
}

/// PRISM_TDX_COMPOSE_HASHES is a comma-separated list of sha256 hex digests
/// of the compose files this deployment accepts from TDX nodes. Absent or
/// empty means TDX evidence is refused, which is the safe default; an entry
/// that does not parse is a configuration mistake and refuses startup rather
/// than silently disabling the rung it was meant to open.
fn tdx_compose_allowlist_from_environment() -> anyhow::Result<Vec<[u8; 32]>> {
    let Ok(raw) = std::env::var("PRISM_TDX_COMPOSE_HASHES") else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            hex::decode(entry)
                .ok()
                .and_then(|digest| digest.try_into().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "PRISM_TDX_COMPOSE_HASHES entry {entry:?} is not a 32 byte hex digest"
                    )
                })
        })
        .collect()
}

/// Turns one submission's evidence into a verdict, whatever kind it carries.
/// Refusals are judged and logged here so both store backends refuse the same
/// way, and the challenge stays spent whichever way this goes.
fn verify_node_evidence(
    attestation: &NodeAttestation,
    nonce: &str,
    device_public_key: &str,
    policy: &prism_attestation::Policy,
    tdx_compose_allowlist: &[[u8; 32]],
    now: DateTime<Utc>,
) -> Result<AttestationVerdict, StoreError> {
    let node_id = attestation.node_id.as_str();
    match attestation.kind {
        AttestationKind::NvidiaGpu => {
            let expected = expected_report_nonce(nonce, node_id, device_public_key)?;
            prism_attestation::verify_nvidia_gpu_attestation(attestation, &expected, now, policy)
                .map_err(|error| {
                    tracing::warn!(node_id, %error, "attestation evidence rejected");
                    StoreError::AttestationUnverified
                })
        }
        AttestationKind::Tdx => {
            let Some(collateral) = attestation.tdx_collateral_json.as_deref() else {
                tracing::warn!(node_id, "TDX attestation carries no collateral");
                return Err(StoreError::AttestationUnverified);
            };
            if tdx_compose_allowlist.is_empty() {
                tracing::warn!(
                    node_id,
                    "no TDX compose hashes are configured, so no TDX evidence can verify"
                );
                return Err(StoreError::AttestationUnverified);
            }
            let events = decode_tdx_events(&attestation.tdx_event_log).map_err(|reason| {
                tracing::warn!(node_id, reason, "TDX event log rejected");
                StoreError::AttestationUnverified
            })?;
            let raw_nonce = hex::decode(nonce).map_err(|_| {
                StoreError::InvalidStoredState("attestation nonce is not hex".to_owned())
            })?;
            let report_data = tdx_report_data(&raw_nonce, node_id, device_public_key);
            // The allowlist is small and the quote is bound to one compose,
            // so trying each accepted compose against a full verification is
            // simpler than teaching the verifier about alternatives, and a
            // mismatch costs one DCAP walk.
            let mut refusal = None;
            for compose_hash in tdx_compose_allowlist {
                match prism_attestation::verify_tdx_attestation(
                    attestation,
                    collateral,
                    &events,
                    &prism_attestation::TdxExpectation {
                        report_data,
                        compose_hash: *compose_hash,
                    },
                    now,
                    policy,
                ) {
                    Ok(verdict) => return Ok(verdict),
                    Err(error) => refusal = Some(error),
                }
            }
            if let Some(error) = refusal {
                tracing::warn!(node_id, %error, "attestation evidence rejected");
            }
            Err(StoreError::AttestationUnverified)
        }
        kind => {
            tracing::warn!(
                node_id,
                ?kind,
                "attestation kind has no node-level verifier"
            );
            Err(StoreError::AttestationUnverified)
        }
    }
}

/// As above, for the 64 bytes a guest commits to in `REPORT_DATA`. The lease id
/// is in the digest because a report taken for one renter must not be
/// presentable for another's session, and the channel key is in it because a
/// correctly measured VM somewhere on the machine says nothing about the box
/// the renter's client terminates on.
fn expected_report_data(
    nonce: &str,
    lease_id: u64,
    guest_channel_key: &str,
) -> Result<[u8; 64], StoreError> {
    let nonce = hex::decode(nonce)
        .map_err(|_| StoreError::InvalidStoredState("attestation nonce is not hex".to_owned()))?;
    Ok(snp_report_data(&nonce, lease_id, guest_channel_key))
}

/// `HOST_DATA` is the one field the host fixes at launch and cannot change
/// afterwards, so it is where the image the renter paid for gets nailed down.
/// The expectation is the lease's own image digest, read off the record rather
/// than off anything the submission carries. It is worth something only because
/// the measured guest agent refuses to run any other image: nothing here checks
/// what was pulled.
fn lease_host_data(image: &str) -> Result<[u8; 32], StoreError> {
    image
        .rsplit_once("@sha256:")
        .and_then(|(_, digest)| hex::decode(digest).ok())
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .ok_or_else(|| {
            StoreError::InvalidStoredState(
                "lease image is not pinned to a sha256 digest".to_owned(),
            )
        })
}

/// The TDX counterpart of `lease_host_data`. A TD binds the compose it launched
/// from into its event log, and the digest pinned on the lease image is what
/// that has to match, read off the record rather than off the quote so a TD
/// that launched a different compose fails rather than verifies.
fn lease_compose_hash(image: &str) -> Result<[u8; 32], StoreError> {
    image
        .rsplit_once("@sha256:")
        .and_then(|(_, digest)| hex::decode(digest).ok())
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .ok_or_else(|| {
            StoreError::InvalidStoredState(
                "lease image is not pinned to a sha256 digest".to_owned(),
            )
        })
}

/// The GPU signs its report over the raw challenge nonce rather than over a
/// digest that folds the lease in, the way the SEV-SNP and TDX report data do,
/// so the stored nonce is decoded straight to the 32 bytes the card committed
/// to. A stored nonce that is not 32 hex bytes is our own corruption.
fn expected_gpu_cc_nonce(nonce: &str) -> Result<[u8; 32], StoreError> {
    hex::decode(nonce)
        .ok()
        .and_then(|nonce| <[u8; 32]>::try_from(nonce).ok())
        .ok_or_else(|| {
            StoreError::InvalidStoredState("gpu-cc challenge nonce is not 32 hex bytes".to_owned())
        })
}

/// Evidence a node carries base64 in either alphabet, as elsewhere in this
/// tree. A body that does not decode is refused as unverifiable rather than
/// surfaced as a storage fault, because it is the node's to get right.
fn decode_attestation_evidence(encoded: &str) -> Result<Vec<u8>, StoreError> {
    STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| StoreError::AttestationUnverified)
}

/// The processor this node was last attested on, if it has been. Passing it into
/// verification is what stops a node that earned a class on one chip presenting
/// a report from another: the first report binds the pair and every later one
/// has to match it.
fn bound_chip_digest(digest: Option<String>) -> Result<Option<[u8; 32]>, StoreError> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    hex::decode(&digest)
        .ok()
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .map(Some)
        .ok_or_else(|| {
            StoreError::InvalidStoredState("stored chip identity is not a sha256 digest".to_owned())
        })
}

/// A guest can bind a report to its lease while the machine is being prepared
/// for it and not afterwards. Once the lease is live the access grant has
/// already been decided, and a report arriving then would be asking for a class
/// the renter is mid-session at.
fn accepts_guest_attestation(state: &LeaseState) -> bool {
    matches!(state, LeaseState::Provisioning | LeaseState::Ready)
}

/// One code for every verification failure, as on the node path: which check
/// the evidence failed is a hint to whoever is trying to forge past it.
fn verify_lease_attestation(
    attestation: &GuestAttestation,
    expected: &prism_attestation::SnpExpectation,
    now: chrono::DateTime<Utc>,
    policy: &prism_attestation::Policy,
) -> Result<LeaseAttestationVerdict, StoreError> {
    prism_attestation::verify_sev_snp_attestation(attestation, expected, now, policy).map_err(
        |error| {
            tracing::warn!(
                lease_id = attestation.lease_id,
                node_id = %attestation.node_id,
                %error,
                "guest attestation evidence rejected"
            );
            StoreError::AttestationUnverified
        },
    )
}

/// The TDX guest half, judged the same way the SEV-SNP half is: one code for
/// every failure so the kind of miss stays a hint the forger has to guess at,
/// and the challenge is spent whatever comes back.
fn verify_lease_tdx_attestation(
    attestation: &TdxLeaseAttestation,
    nonce: &str,
    compose_hash: &[u8; 32],
    events: &[prism_attestation::TdxEvent],
    now: chrono::DateTime<Utc>,
    policy: &prism_attestation::Policy,
) -> Result<LeaseTdxGuestVerdict, StoreError> {
    let quote = decode_attestation_evidence(&attestation.quote_base64)?;
    let raw_nonce = hex::decode(nonce)
        .map_err(|_| StoreError::InvalidStoredState("attestation nonce is not hex".to_owned()))?;
    let report_data = tdx_lease_report_data(
        &raw_nonce,
        attestation.lease_id,
        &attestation.node_id,
        &attestation.guest_channel_key,
    );
    prism_attestation::verify_tdx_lease_attestation(
        attestation.lease_id,
        &attestation.node_id,
        &quote,
        &attestation.tdx_collateral_json,
        events,
        &report_data,
        compose_hash,
        &attestation.guest_channel_key,
        now,
        policy,
    )
    .map_err(|error| {
        tracing::warn!(
            lease_id = attestation.lease_id,
            node_id = %attestation.node_id,
            %error,
            "guest tdx attestation evidence rejected"
        );
        StoreError::AttestationUnverified
    })
}

/// The GPU-CC half. The card signs over the challenge this service issued for
/// it, so a report captured for another lease or another nonce fails here
/// rather than lifting a class it was never bound to.
fn verify_lease_gpu_cc_attestation(
    attestation: &GpuCcAttestation,
    nonce: &str,
    now: chrono::DateTime<Utc>,
    policy: &prism_attestation::Policy,
) -> Result<LeaseGpuCcVerdict, StoreError> {
    let report = decode_attestation_evidence(&attestation.report_base64)?;
    let mut chain = Vec::with_capacity(attestation.certificate_chain_base64.len());
    for encoded in &attestation.certificate_chain_base64 {
        chain.push(decode_attestation_evidence(encoded)?);
    }
    let expected_nonce = expected_gpu_cc_nonce(nonce)?;
    prism_attestation::verify_nvidia_cc_lease_attestation(
        attestation.lease_id,
        &attestation.node_id,
        &report,
        &chain,
        &expected_nonce,
        now,
        policy,
    )
    .map_err(|error| {
        tracing::warn!(
            lease_id = attestation.lease_id,
            node_id = %attestation.node_id,
            %error,
            "gpu-cc attestation evidence rejected"
        );
        StoreError::AttestationUnverified
    })
}

/// After any of the three lease verdicts is stored, the class is recomputed
/// from all of them together: a verdict on one axis lifts exactly what the
/// three substantiate and no single one over-grants. A missing or expired
/// verdict reads as absent, so nothing here lifts a class the evidence dropped.
fn rederive_lease_class(market: &mut MemoryMarketplace, lease_id: u64, now: DateTime<Utc>) {
    let snp = market.lease_verdicts.get(&lease_id).cloned();
    let tdx = market.lease_tdx_guest_verdicts.get(&lease_id).cloned();
    let gpu = market.lease_gpu_cc_verdicts.get(&lease_id).cloned();
    let Some(node_id) = market.leases.get(&lease_id).map(|(_, r)| r.node_id.clone()) else {
        return;
    };
    // The node's live class, not the lease's recorded one: a guest verdict
    // arriving after the node's tunnel lapsed must not ride the class the lease
    // held while the node was still healthy.
    let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
    let node_class = class_for_verdict(
        &node_id,
        market
            .tunnels
            .get(&node_id)
            .is_some_and(|observed_at| *observed_at >= cutoff),
        fresh_posture(market, &node_id, cutoff),
        market.verdicts.get(&node_id),
        now,
    );
    if let Some((_, record)) = market.leases.get_mut(&lease_id) {
        record.trust_class = class_for_lease(
            lease_id,
            &record.node_id,
            node_class,
            snp.as_ref(),
            tdx.as_ref(),
            gpu.as_ref(),
            now,
        );
        record.updated_at = now;
    }
}

/// The Postgres counterpart of `rederive_lease_class`. The three verdicts are
/// read back inside the caller's transaction, so the one it just inserted is
/// among them, and the lease row is rewritten at the class they earn together.
async fn rederive_lease_class_pg(
    transaction: &mut Transaction<'_, Postgres>,
    lease_id: u64,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let snp = query_scalar::<_, SqlJson<LeaseAttestationVerdict>>(
        "SELECT document FROM lease_attestation_verdicts WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    let tdx = query_scalar::<_, SqlJson<LeaseTdxGuestVerdict>>(
        "SELECT document FROM lease_tdx_guest_verdicts WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    let gpu = query_scalar::<_, SqlJson<LeaseGpuCcVerdict>>(
        "SELECT document FROM lease_gpu_cc_verdicts WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    let record = query_scalar::<_, SqlJson<LeaseRecord>>(
        "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
    )
    .bind(lease_id as i64)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    if let Some(SqlJson(mut record)) = record {
        // The node's live class, not the lease's recorded one, so a verdict
        // arriving after the node's tunnel lapsed cannot ride a stale standing.
        let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
        let tunneled = query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM node_tunnels WHERE node_id = $1 AND observed_at >= $2)",
        )
        .bind(&record.node_id)
        .bind(cutoff)
        .fetch_one(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
        let posture = query_scalar::<_, SqlJson<NodePosture>>(
            "SELECT document->'posture' FROM node_telemetry WHERE node_id = $1 AND observed_at >= $2",
        )
        .bind(&record.node_id)
        .bind(cutoff)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
        let node_verdict = query_scalar::<_, SqlJson<AttestationVerdict>>(
            "SELECT document FROM node_attestation_verdicts WHERE node_id = $1 AND expires_at > now()",
        )
        .bind(&record.node_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
        let node_class = class_for_verdict(
            &record.node_id,
            tunneled,
            posture.as_ref().map(|SqlJson(posture)| posture),
            node_verdict.as_ref().map(|SqlJson(verdict)| verdict),
            now,
        );
        record.trust_class = class_for_lease(
            lease_id,
            &record.node_id,
            node_class,
            snp.as_ref().map(|SqlJson(verdict)| verdict),
            tdx.as_ref().map(|SqlJson(verdict)| verdict),
            gpu.as_ref().map(|SqlJson(verdict)| verdict),
            now,
        );
        record.updated_at = now;
        query("UPDATE leases SET document = $2, updated_at = NOW() WHERE lease_id = $1")
            .bind(lease_id as i64)
            .bind(SqlJson(record))
            .execute(&mut **transaction)
            .await
            .map_err(StoreError::Storage)?;
    }
    Ok(())
}

/// Posture counts only while the heartbeat that carried it is still current.
/// The Postgres arm has always bounded it that way; the memory arm did not, so
/// tests were accepting a posture production would have thrown away.
fn fresh_posture<'a>(
    market: &'a MemoryMarketplace,
    node_id: &str,
    cutoff: chrono::DateTime<Utc>,
) -> Option<&'a NodePosture> {
    market
        .telemetry
        .get(node_id)
        .filter(|telemetry| telemetry.observed_at >= cutoff)
        .and_then(|telemetry| telemetry.posture.as_ref())
}

/// A node polls the command channel every few seconds and every poll is
/// signed by its device key, so a record inside the retention window is proof
/// the node is still there to take a command.
fn polls_command_channel(
    market: &MemoryMarketplace,
    node_id: &str,
    now: chrono::DateTime<Utc>,
) -> bool {
    market
        .node_requests
        .values()
        .any(|(polled_by, expires_at)| polled_by == node_id && *expires_at > now)
}

struct MemoryCommand {
    command: NodeCommand,
    status: &'static str,
    lease_until: Option<chrono::DateTime<Utc>>,
    authorization_request_id: Option<Uuid>,
    result: Option<CommandResult>,
    verified_report: Option<NodeCommandReport>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Default)]
struct MemoryLifecycle {
    grant_token: Option<EncryptedSecret>,
    grant_expires_at: Option<chrono::DateTime<Utc>>,
    channel_key_fingerprint: Option<String>,
}

enum StoredLeaseAccess {
    Gateway {
        token: EncryptedSecret,
        jupyter_token: EncryptedSecret,
        expires_at: chrono::DateTime<Utc>,
    },
    DirectSsh {
        host: String,
        port: u16,
        expires_at: chrono::DateTime<Utc>,
    },
}

struct LeaseAccessGrant {
    access: StoredLeaseAccess,
    channel_key: Option<ChannelKey>,
}

/// The SSH host key a renter's session should terminate on, and what stands
/// behind the claim.
///
/// The two are inseparable because they are worth different amounts. A
/// fingerprint out of a guest report is signed by the processor and cannot be
/// substituted by anyone, including us. A fingerprint a node reported is the
/// operator's word under their device key: it rules out substitution by the
/// relay and by the network path, and it leaves the operator, whose bond is
/// what a dispute would reach. Publishing the number without the provenance
/// would let the weaker claim read as the stronger one.
///
/// Either way it is worth something only if the renter's client pins it. A
/// client that auto-accepts host keys makes the binding decorative.
struct ChannelKey {
    fingerprint: String,
    source: ChannelKeySource,
}

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum ChannelKeySource {
    /// REPORT_DATA in a verified SEV-SNP report commits to this key.
    SnpReport,
    /// REPORTDATA in a verified TDX quote commits to this key.
    TdxQuote,
    /// The node said so on the signed report that opened access.
    NodeReport,
}

#[derive(Debug, Error)]
enum StoreError {
    #[error("node not found")]
    NodeNotFound,
    #[error("network lease limit reached")]
    NetworkCapacity,
    #[error("no compatible bonded node is online")]
    NoMatch,
    #[error("all compatible capacity is held by an open quote or an active lease")]
    CapacityReserved,
    #[error("matched offer exceeds the escrow limit")]
    EscrowLimit,
    #[error("the node this quote names has been suspended")]
    NodeSuspended,
    #[error("the execution path bound into this repro quote is no longer available")]
    ReproExecutorUnavailable,
    #[error("this repro capability token was already used")]
    ReproTokenAlreadyUsed,
    #[error("this repro capability token resolves to more than one quote")]
    AmbiguousReproToken,
    #[error("the capacity named by this funded quote is no longer available")]
    FundingCapacityUnavailable,
    #[error("telemetry sequence was already accepted")]
    TelemetryReplay,
    #[error("internal identity request was already accepted")]
    IdentityReplay,
    #[error("account session was revoked")]
    SessionRevoked,
    #[error("account is suspended")]
    AccountSuspended,
    #[error("quote not found")]
    QuoteNotFound,
    #[error("quote is expired or already consumed")]
    QuoteUnavailable,
    #[error("lease funding does not match its quote")]
    FundingMismatch,
    #[error("node command not found")]
    CommandNotFound,
    #[error("node command request was already accepted")]
    CommandReplay,
    #[error("node command execution was claimed by another poll")]
    CommandClaimed,
    #[error("interactive lease credentials are missing")]
    AccessCredentialsMissing,
    #[error("node certificate request was already accepted")]
    CertificateReplay,
    #[error("node certificate is not active")]
    CertificateInactive,
    #[error("wallet challenge was not found or is no longer active")]
    WalletChallengeUnavailable,
    #[error("wallet signature does not match the requested address")]
    WalletSignatureInvalid,
    #[error("operator authorization is required")]
    OperatorRequired,
    #[error("operator target does not exist")]
    OperatorTargetNotFound,
    #[error("operator action is invalid for its target")]
    InvalidOperatorAction,
    #[error("stored state is invalid: {0}")]
    InvalidStoredState(String),
    #[error("vault item not found")]
    VaultItemNotFound,
    #[error("vault item was modified by another writer")]
    VaultVersionConflict,
    #[error("vault item limit reached")]
    VaultFull,
    #[error("lease trust class {lease} is below the item's floor {floor}")]
    VaultTrustFloorUnmet {
        floor: &'static str,
        lease: &'static str,
    },
    #[error("lease is not active for this account")]
    VaultLeaseUnavailable,
    #[error("workspace not found")]
    WorkspaceNotFound,
    #[error("workspace name is already in use")]
    WorkspaceNameTaken,
    #[error("workspace snapshot was superseded by another writer")]
    WorkspaceVersionConflict,
    #[error("workspace limit reached")]
    WorkspaceFull,
    #[error("attestation challenge was not found, expired or already consumed")]
    AttestationChallengeUnavailable,
    #[error("attestation evidence did not verify")]
    AttestationUnverified,
    #[error("this device is already attested under another node")]
    AttestedDeviceConflict,
    #[error("this processor is already attested under another node")]
    AttestedChipConflict,
    #[error("this lease cannot carry a guest attestation")]
    LeaseNotAttestable,
    #[error("this lease was quoted above what its guest has proved")]
    LeaseUnattested,
    #[error("the node no longer holds the trust class this quote was issued at")]
    TrustClassExpired,
    #[error("storage failure")]
    Storage(#[source] SqlError),
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}

/// item_id, version, wrapped_key, nonce, ciphertext, min_trust_class, label,
/// created_at, updated_at.
type VaultRow = (
    Uuid,
    i32,
    String,
    String,
    String,
    String,
    String,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

fn vault_item_from_row(row: VaultRow) -> Result<VaultItem, StoreError> {
    let (item_id, version, wrapped_key, nonce, ciphertext, floor, label, created_at, updated_at) =
        row;
    Ok(VaultItem {
        item_id,
        version: u32::try_from(version)
            .map_err(|_| StoreError::InvalidStoredState("invalid vault version".into()))?,
        envelope: VaultEnvelope {
            wrapped_key,
            nonce,
            ciphertext,
        },
        min_trust_class: parse_trust_class(&floor)?,
        label,
        created_at,
        updated_at,
    })
}

/// workspace_id, name, version, wrapped_key, nonce, ciphertext_digest,
/// size_bytes, min_trust_class, created_at, updated_at.
type WorkspaceRow = (
    Uuid,
    String,
    i32,
    String,
    String,
    String,
    i64,
    String,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
);

fn workspace_from_row(row: WorkspaceRow) -> Result<Workspace, StoreError> {
    let (
        workspace_id,
        name,
        version,
        wrapped_key,
        nonce,
        ciphertext_digest,
        size_bytes,
        floor,
        created_at,
        updated_at,
    ) = row;
    let version = u32::try_from(version)
        .map_err(|_| StoreError::InvalidStoredState("invalid workspace version".into()))?;
    let size_bytes = u64::try_from(size_bytes)
        .map_err(|_| StoreError::InvalidStoredState("invalid workspace size".into()))?;
    Ok(Workspace {
        workspace_id,
        name,
        version,
        // Version zero is a workspace that exists and holds nothing, so the
        // envelope columns are still at their defaults and mean nothing.
        snapshot: (version > 0).then_some(WorkspaceSnapshot {
            wrapped_key,
            nonce,
            ciphertext_digest,
            size_bytes,
        }),
        min_trust_class: parse_trust_class(&floor)?,
        created_at,
        updated_at,
    })
}

fn parse_trust_class(value: &str) -> Result<TrustClass, StoreError> {
    match value {
        "open" => Ok(TrustClass::Open),
        "isolated" => Ok(TrustClass::Isolated),
        "attested" => Ok(TrustClass::Attested),
        "confidential" => Ok(TrustClass::Confidential),
        other => Err(StoreError::InvalidStoredState(format!(
            "unknown trust class {other}"
        ))),
    }
}

fn parse_lease_state(value: &str) -> Result<LeaseState, StoreError> {
    match value {
        "funded" => Ok(LeaseState::Funded),
        "provisioning" => Ok(LeaseState::Provisioning),
        "ready" => Ok(LeaseState::Ready),
        "active" => Ok(LeaseState::Active),
        "closing" => Ok(LeaseState::Closing),
        "settlement_pending" => Ok(LeaseState::SettlementPending),
        "disputed" => Ok(LeaseState::Disputed),
        "finalized" => Ok(LeaseState::Finalized),
        "refunded" => Ok(LeaseState::Refunded),
        "failed" => Ok(LeaseState::Failed),
        other => Err(StoreError::InvalidStoredState(format!(
            "unknown lease state {other}"
        ))),
    }
}

#[derive(Deserialize)]
struct MatchRequest {
    request: LeaseRequest,
}

#[derive(Debug, Clone, Serialize)]
struct PriceIndexEntry {
    gpu_model: String,
    sourced_low_micros_per_hour: Option<i64>,
    sourced_high_micros_per_hour: Option<i64>,
    sourced_median_micros_per_hour: Option<i64>,
    sourced_observations: i64,
    settled_mean_micros_per_hour: Option<i64>,
    settled_leases: i64,
    last_observed_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
struct PriceIndex {
    currency: &'static str,
    unit: &'static str,
    generated_at: chrono::DateTime<Utc>,
    gpus: Vec<PriceIndexEntry>,
}

/// The access grant, plus the fingerprint of the SSH host key the workspace
/// serving this lease listens on and where that fingerprint came from. Both ride
/// alongside rather than inside `LeaseAccess` because they are evidence about
/// the session, not a credential for it: clients that do not pin host keys
/// ignore the fields and lose only the binding.
///
/// Absent on capacity brokered from a public cloud. The instance's host key is
/// generated by the cloud and never shown to us, so there is nothing to publish
/// and a renter cannot be told to check one.
#[derive(Serialize)]
struct LeaseAccessResponse {
    #[serde(flatten)]
    access: LeaseAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_key_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_key_source: Option<ChannelKeySource>,
}

/// `state` is where the lease stands once the call returns: `closing` on a
/// release that took, and whatever it had already reached on one that arrived
/// late. `release` says what this call did rather than what the lease is doing:
/// `queued` on the first release, `already_closed` afterwards.
#[derive(Serialize)]
struct LeaseReleaseResponse {
    lease_id: u64,
    state: &'static str,
    release: &'static str,
}

/// What a release did to the lease it named.
enum LeaseRelease {
    /// Access is shut and the teardown is queued.
    Queued,
    /// Access had already ended before the call arrived.
    AlreadyClosed(LeaseState),
    /// Access never opened, so there is nothing to close.
    NotYetOpen,
    /// The lease carries a command and ends when that command reports.
    Batch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproStatusRequest {
    token: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReproStatus {
    Quoted,
    Funded,
    Preparing,
    Ready,
    Running,
    Completed,
    Failed,
    Settling,
    Settled,
    Refunded,
    Disputed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ReproStatusChecks {
    token_bound: bool,
    spec_hash_valid: bool,
    command_bound: Option<bool>,
    report_signature_valid: Option<bool>,
    executor_identity_valid: Option<bool>,
    report_bound: Option<bool>,
    receipt_hash_valid: Option<bool>,
    receipt_bound: Option<bool>,
    expected_exit_code: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ReproStatusEvidence {
    command: NodeCommand,
    report: ReproExecutionReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<PublicReceipt>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ReproStatusResponse {
    version: &'static str,
    status: ReproStatus,
    executor: ReproExecutor,
    spec: GpuReproSpec,
    spec_hash: String,
    quote_id: Uuid,
    maximum_escrow: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_state: Option<LeaseState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<CommandResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<ReproStatusEvidence>,
    checks: ReproStatusChecks,
}

struct StoredReproStatus {
    quote: LeaseQuote,
    lease: Option<StoredReproLease>,
}

struct StoredReproLease {
    lease_id: u64,
    chain_lease_id: u64,
    state: LeaseState,
    node_id: String,
    token_hash: Option<String>,
    spec_hash: Option<String>,
    execution: Option<StoredReproExecution>,
    receipt: Option<PublicReceipt>,
}

enum StoredReproExecution {
    Node {
        status: String,
        command: NodeCommand,
        report: Option<NodeCommandReport>,
        result: Option<CommandResult>,
        enrolled_device_public_key: Option<String>,
    },
    Managed {
        status: String,
        command: NodeCommand,
        report: Option<ManagedCommandReport>,
    },
}

#[derive(Deserialize)]
struct ConfirmLeaseRequest {
    quote_id: Uuid,
    transaction_hash: String,
    ssh_authorized_key: Option<String>,
}

#[derive(Deserialize)]
struct VaultReleaseRequest {
    lease_id: u64,
}

#[derive(Deserialize)]
struct WorkspaceRequest {
    name: String,
    #[serde(default = "default_workspace_floor")]
    min_trust_class: TrustClass,
}

fn default_workspace_floor() -> TrustClass {
    DEFAULT_WORKSPACE_TRUST_FLOOR
}

#[derive(Deserialize)]
struct SnapshotUploadRequest {
    size_bytes: u64,
}

#[derive(Deserialize)]
struct SnapshotCommitRequest {
    version: u32,
    #[serde(flatten)]
    snapshot: WorkspaceSnapshot,
}

/// The renter uploads straight to storage, so this is the whole of what the
/// control plane hands over: where to put the bytes, and which version they
/// have to be committed as.
#[derive(Serialize)]
struct SnapshotUpload {
    url: String,
    version: u32,
    key: String,
}

#[derive(Serialize)]
struct SnapshotDownload {
    url: String,
    version: u32,
    #[serde(flatten)]
    snapshot: WorkspaceSnapshot,
}

/// A restore names the lease it is landing on, so the trust floor can be
/// checked against real capacity rather than taken on the client's word.
#[derive(Deserialize)]
struct SnapshotDownloadRequest {
    lease_id: u64,
}

#[derive(Deserialize)]
struct TunnelObservation {
    connection_id: String,
    #[serde(default)]
    certificate_fingerprint: String,
    observed_at: chrono::DateTime<Utc>,
}

#[derive(Clone)]
struct CertificateAuthority {
    issuer: Arc<Issuer<'static, KeyPair>>,
    certificate_pem: Arc<String>,
}

#[derive(Clone)]
struct StoredNodeCertificate {
    certificate_id: Uuid,
    node_id: String,
    fingerprint_sha256: String,
    csr_sha256: String,
    not_before: chrono::DateTime<Utc>,
    not_after: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct WalletChallengeQuery {
    address: String,
}

#[derive(Debug, Clone, Serialize)]
struct WalletChallenge {
    challenge_id: Uuid,
    wallet_address: String,
    message: String,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct WalletLinkRequest {
    challenge_id: Uuid,
    wallet_address: String,
    signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OperatorAction {
    AccountRiskHold,
    AccountRiskRelease,
    AccountSuspend,
    AccountResume,
    NodeSuspend,
    NodeResume,
    NodeCertificateRevoke,
    SlashEvidenceRecord,
}

impl OperatorAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::AccountRiskHold => "account_risk_hold",
            Self::AccountRiskRelease => "account_risk_release",
            Self::AccountSuspend => "account_suspend",
            Self::AccountResume => "account_resume",
            Self::NodeSuspend => "node_suspend",
            Self::NodeResume => "node_resume",
            Self::NodeCertificateRevoke => "node_certificate_revoke",
            Self::SlashEvidenceRecord => "slash_evidence_record",
        }
    }

    fn target_type(self) -> &'static str {
        match self {
            Self::AccountRiskHold
            | Self::AccountRiskRelease
            | Self::AccountSuspend
            | Self::AccountResume => "account",
            Self::NodeSuspend
            | Self::NodeResume
            | Self::NodeCertificateRevoke
            | Self::SlashEvidenceRecord => "node",
        }
    }
}

impl TryFrom<&str> for OperatorAction {
    type Error = StoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "account_risk_hold" => Ok(Self::AccountRiskHold),
            "account_risk_release" => Ok(Self::AccountRiskRelease),
            "account_suspend" => Ok(Self::AccountSuspend),
            "account_resume" => Ok(Self::AccountResume),
            "node_suspend" => Ok(Self::NodeSuspend),
            "node_resume" => Ok(Self::NodeResume),
            "node_certificate_revoke" => Ok(Self::NodeCertificateRevoke),
            "slash_evidence_record" => Ok(Self::SlashEvidenceRecord),
            _ => Err(StoreError::InvalidOperatorAction),
        }
    }
}

#[derive(Deserialize)]
struct OperatorControlRequest {
    action_id: Uuid,
    action: OperatorAction,
    target_id: String,
    reason: String,
    evidence_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorAuditEvent {
    event_id: Uuid,
    action_id: Uuid,
    actor_subject: String,
    action: OperatorAction,
    target_type: String,
    target_id: String,
    reason: String,
    evidence_hash: Option<String>,
    before_state: serde_json::Value,
    after_state: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct SupplierNode {
    offer: NodeOffer,
    suspended: bool,
    certificate_status: String,
    certificate_expires_at: Option<chrono::DateTime<Utc>>,
    finalized_leases: u64,
    provider_paid_base_units: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SupplierSummary {
    linked_wallets: Vec<String>,
    nodes: Vec<SupplierNode>,
    total_provider_paid_base_units: u64,
    total_finalized_leases: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct StoredSettlementProposal {
    lease_id: u64,
    usage_seconds: u64,
    receipt_hash: String,
    evidence_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
struct StoredSettlementSubmission {
    proposal: StoredSettlementProposal,
    transaction_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct DisputeEvidenceSummary {
    gpu_model: String,
    image_digest: String,
    rate_per_second: u64,
    deposit_base_units: u64,
    duration_seconds: u32,
    access_started_at: u64,
    access_ended_at: u64,
    cuda_ready_at: u64,
    interactive_access_ready_at: u64,
    gateway_closed_at: u64,
    telemetry_records: usize,
    evidence_hash: String,
    proposal_integrity_valid: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct DisputeProposalSummary {
    usage_seconds: u64,
    receipt_hash: String,
    transaction_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct SafeTransaction {
    to: String,
    value: String,
    data: String,
    method: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorDispute {
    lease_id: u64,
    node_id: String,
    evidence: DisputeEvidenceSummary,
    proposal: Option<DisputeProposalSummary>,
    accept_proposal_transaction: Option<SafeTransaction>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let allow_development_auth = env::var("PRISM_ALLOW_DEVELOPMENT_AUTH").as_deref() == Ok("1");
    let store = MarketplaceStore::from_environment().await?;
    if env::var("PRISM_RUN_MIGRATIONS_ONLY").as_deref() == Ok("1") {
        if store.is_development() {
            anyhow::bail!("PRISM_RUN_MIGRATIONS_ONLY requires DATABASE_URL");
        }
        tracing::info!("control-plane migrations applied; exiting before admission startup");
        return Ok(());
    }
    let allow_development_registry =
        env::var("PRISM_ALLOW_DEVELOPMENT_REGISTRY").as_deref() == Ok("1");
    if allow_development_registry && !allow_development_auth {
        anyhow::bail!("PRISM_ALLOW_DEVELOPMENT_REGISTRY requires PRISM_ALLOW_DEVELOPMENT_AUTH");
    }
    let registry =
        RegistryVerifier::from_environment(store.is_development() || allow_development_registry)
            .await?;
    let identity = IdentityVerifier::from_environment(allow_development_auth)?;
    let allow_development_chain = env::var("PRISM_ALLOW_DEVELOPMENT_CHAIN").as_deref() == Ok("1");
    if allow_development_chain && !allow_development_auth {
        anyhow::bail!("PRISM_ALLOW_DEVELOPMENT_CHAIN requires PRISM_ALLOW_DEVELOPMENT_AUTH");
    }
    let chain = ChainVerifier::from_environment(store.is_development() || allow_development_chain)?;
    let credential_cipher = credential_cipher(allow_development_auth)?;
    let gateway_token = env::var("PRISM_GATEWAY_OBSERVER_TOKEN")
        .ok()
        .filter(|token| token.len() >= 32 && token.len() <= 512)
        .map(Arc::new);
    if gateway_token.is_none() && !store.is_development() {
        anyhow::bail!("PRISM_GATEWAY_OBSERVER_TOKEN is required outside local development");
    }
    let public_gateway_host = env::var("PRISM_PUBLIC_GATEWAY_HOST")
        .ok()
        .filter(|value| valid_gateway_host(value))
        .or_else(|| allow_development_auth.then(|| "127.0.0.1".to_owned()))
        .context("PRISM_PUBLIC_GATEWAY_HOST is required outside local development")?;
    let public_relay_port = env::var("PRISM_PUBLIC_RELAY_PORT")
        .ok()
        .map(|value| value.parse::<u16>())
        .transpose()?
        .unwrap_or(7_444);
    if public_relay_port == 0 {
        anyhow::bail!("PRISM_PUBLIC_RELAY_PORT must be non-zero");
    }
    let certificate_authority = Arc::new(CertificateAuthority::from_environment(
        allow_development_auth,
    )?);
    let require_node_certificates = !allow_development_auth
        || env::var("PRISM_REQUIRE_NODE_CERTIFICATES").as_deref() == Ok("1");
    let operator_subjects = env::var("PRISM_OPERATOR_SUBJECTS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|subject| !subject.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    store.seed_operators(&operator_subjects).await?;
    let state = AppState {
        store,
        registry,
        chain,
        identity,
        credential_cipher,
        gateway_token,
        public_gateway_host: Arc::new(public_gateway_host),
        public_relay_port,
        certificate_authority,
        require_node_certificates,
        stake: StakeReader::from_environment()?,
        workspaces: workspaces::WorkspaceStorage::from_environment()
            .await?
            .map(Arc::new),
        // No environment switch here on purpose. A relaxed verification mode is
        // one variable away from being set on the box that matters.
        attestation_policy: Arc::new(
            prism_attestation::Policy::default()
                .with_verdict_ttl(Duration::hours(ATTESTATION_VERDICT_TTL_HOURS)),
        ),
        tdx_compose_allowlist: {
            let allowlist = tdx_compose_allowlist_from_environment()?;
            if allowlist.is_empty() {
                tracing::info!(
                    "no TDX compose hashes configured; TDX attestations will be refused"
                );
            } else {
                tracing::info!(accepted = allowlist.len(), "TDX compose allowlist loaded");
            }
            Arc::new(allowlist)
        },
        // A guest whose firmware carries no certificates sends a report alone,
        // and this is what turns it into something that can be walked to the
        // AMD root.
        amd_kds: match amd_kds::AmdKds::from_environment() {
            Ok(client) => Some(client),
            Err(error) => {
                tracing::warn!(%error, "no AMD certificate service; reports must carry their own chain");
                None
            }
        },
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/offers", get(list_offers))
        .route("/v1/repros/status", post(get_repro_status))
        .route("/v1/price-index", get(price_index))
        .route("/v1/nodes/enroll", post(enroll_node))
        .route(
            "/v1/nodes/{node_id}/certificates",
            post(issue_node_certificate),
        )
        .route("/v1/nodes/{node_id}/heartbeat", post(record_telemetry))
        .route(
            "/v1/nodes/{node_id}/attestation/challenge",
            get(create_attestation_challenge),
        )
        .route("/v1/nodes/{node_id}/attestation", post(record_attestation))
        .route(
            "/v1/gateway/tunnels/{node_id}",
            post(record_tunnel_observation),
        )
        .route("/v1/nodes/{node_id}/commands/next", post(next_node_command))
        .route(
            "/v1/nodes/{node_id}/commands/{command_id}/report",
            post(report_node_command),
        )
        .route(
            "/v1/nodes/{node_id}/commands/{command_id}/authorize",
            post(authorize_node_command),
        )
        .route("/v1/leases/match", post(match_lease))
        .route("/v1/leases", get(list_account_leases))
        .route("/v1/leases/{lease_id}/access", get(get_lease_access))
        .route("/v1/leases/{lease_id}/release", post(release_lease))
        .route(
            "/v1/leases/{lease_id}/attestation/challenge",
            get(create_lease_attestation_challenge),
        )
        .route(
            "/v1/leases/{lease_id}/attestation",
            post(record_lease_attestation),
        )
        .route(
            "/v1/leases/{lease_id}/tdx-attestation",
            post(record_lease_tdx_attestation),
        )
        .route(
            "/v1/leases/{lease_id}/gpu-attestation/challenge",
            get(create_lease_gpu_cc_attestation_challenge),
        )
        .route(
            "/v1/leases/{lease_id}/gpu-attestation",
            post(record_lease_gpu_cc_attestation),
        )
        .route("/v1/leases/{lease_id}/result", get(get_lease_result))
        .route("/v1/leases/confirm", post(confirm_lease))
        .route("/v1/account/session/revoke", post(revoke_account_session))
        .route(
            "/v1/account/wallets/challenge",
            get(create_wallet_challenge),
        )
        .route("/v1/account/wallets/link", post(link_account_wallet))
        .route("/v1/vault/items", get(list_vault_items))
        .route(
            "/v1/vault/items/{item_id}",
            get(get_vault_item)
                .put(put_vault_item)
                .delete(delete_vault_item),
        )
        .route(
            "/v1/vault/items/{item_id}/release",
            post(release_vault_item),
        )
        .route("/v1/vault/releases", get(list_vault_releases))
        .route(
            "/v1/workspaces",
            get(list_workspaces).post(create_workspace),
        )
        .route("/v1/workspaces/{workspace_id}", delete(delete_workspace))
        .route(
            "/v1/workspaces/{workspace_id}/upload",
            post(upload_workspace),
        )
        .route(
            "/v1/workspaces/{workspace_id}/commit",
            post(commit_workspace),
        )
        .route(
            "/v1/workspaces/{workspace_id}/download",
            post(download_workspace),
        )
        .route("/v1/supplier/summary", get(get_supplier_summary))
        .route("/v1/operator/controls", post(apply_operator_control))
        .route("/v1/operator/audit", get(list_operator_audit))
        .route("/v1/operator/disputes", get(list_operator_disputes))
        .with_state(state)
        .layer(DefaultBodyLimit::max(256 * 1_024))
        .layer(CorsLayer::new())
        .layer(TraceLayer::new_for_http());

    let address: SocketAddr = env::var("PRISM_CONTROL_PLANE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "control plane listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

impl CertificateAuthority {
    fn from_environment(allow_development: bool) -> anyhow::Result<Self> {
        let certificate_path = env::var("PRISM_NODE_CA_CERTIFICATE").ok();
        let key_path = env::var("PRISM_NODE_CA_KEY").ok();
        let certificate_pem = env::var("PRISM_NODE_CA_CERTIFICATE_PEM").ok();
        let key_pem = env::var("PRISM_NODE_CA_KEY_PEM").ok();
        match (certificate_path, key_path, certificate_pem, key_pem) {
            (Some(certificate_path), Some(key_path), None, None) => {
                let certificate_pem =
                    read_bounded_file(FilePath::new(&certificate_path), 64 * 1_024)?;
                let key_pem = read_private_key(FilePath::new(&key_path))?;
                Self::from_pem(certificate_pem, key_pem)
            }
            (None, None, Some(certificate_pem), Some(key_pem))
                if certificate_pem.len() <= 64 * 1_024 && key_pem.len() <= 64 * 1_024 =>
            {
                Self::from_pem(certificate_pem, key_pem)
            }
            (None, None, None, None) if allow_development => {
                tracing::warn!("using an ephemeral node CA in local development");
                let key = KeyPair::generate().context("generate development node CA key")?;
                let mut params = CertificateParams::new(Vec::<String>::new())?;
                params.distinguished_name.remove(DnType::CommonName);
                params
                    .distinguished_name
                    .push(DnType::CommonName, "Prism development node CA");
                params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                params.key_usages = vec![
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::CrlSign,
                    KeyUsagePurpose::DigitalSignature,
                ];
                let now = OffsetDateTime::now_utc();
                params.not_before = now - time::Duration::minutes(5);
                params.not_after = now + time::Duration::days(30);
                let certificate = params.self_signed(&key)?;
                let certificate_pem = certificate.pem();
                Ok(Self {
                    issuer: Arc::new(Issuer::new(params, key)),
                    certificate_pem: Arc::new(certificate_pem),
                })
            }
            _ => {
                anyhow::bail!("configure exactly one complete node CA path or PEM credential pair")
            }
        }
    }

    fn from_pem(certificate_pem: String, key_pem: String) -> anyhow::Result<Self> {
        let key = KeyPair::from_pem(&key_pem).context("parse node CA private key")?;
        let issuer =
            Issuer::from_ca_cert_pem(&certificate_pem, key).context("parse node CA certificate")?;
        Ok(Self {
            issuer: Arc::new(issuer),
            certificate_pem: Arc::new(certificate_pem),
        })
    }

    fn issue(
        &self,
        node_id: &str,
        request: &NodeCertificateRequest,
    ) -> anyhow::Result<(NodeCertificateBundle, StoredNodeCertificate)> {
        if request.csr_pem.len() > 16 * 1_024 {
            anyhow::bail!("node certificate request exceeds the size limit");
        }
        let mut csr = CertificateSigningRequestParams::from_pem(&request.csr_pem)
            .context("parse and verify node certificate request")?;
        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::days(7);
        csr.params.distinguished_name.remove(DnType::CommonName);
        csr.params
            .distinguished_name
            .push(DnType::CommonName, node_id);
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.not_before = now - time::Duration::minutes(5);
        csr.params.not_after = expires;
        csr.params.use_authority_key_identifier_extension = true;
        let certificate = csr.signed_by(&self.issuer)?;
        let fingerprint_sha256 = hex::encode(Sha256::digest(certificate.der()));
        let csr_sha256 = hex::encode(Sha256::digest(request.csr_pem.as_bytes()));
        let certificate_id = Uuid::now_v7();
        let not_before = chrono::DateTime::<Utc>::from_timestamp(now.unix_timestamp() - 300, 0)
            .context("node certificate start time is out of range")?;
        let not_after = chrono::DateTime::<Utc>::from_timestamp(expires.unix_timestamp(), 0)
            .context("node certificate expiry is out of range")?;
        Ok((
            NodeCertificateBundle {
                certificate_id,
                certificate_pem: certificate.pem(),
                ca_certificate_pem: self.certificate_pem.as_ref().clone(),
                fingerprint_sha256: fingerprint_sha256.clone(),
                expires_at: not_after,
            },
            StoredNodeCertificate {
                certificate_id,
                node_id: node_id.to_owned(),
                fingerprint_sha256,
                csr_sha256,
                not_before,
                not_after,
            },
        ))
    }
}

fn read_bounded_file(path: &FilePath, maximum: u64) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect certificate file {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > maximum {
        anyhow::bail!("certificate file is invalid");
    }
    fs::read_to_string(path).with_context(|| format!("read certificate file {}", path.display()))
}

fn read_private_key(path: &FilePath) -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("node CA key must not grant group or other access");
        }
    }
    read_bounded_file(path, 64 * 1_024)
}

impl RegistryVerifier {
    async fn from_environment(allow_development: bool) -> anyhow::Result<Self> {
        let rpc_url = env::var("PRISM_RPC_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let registry_address = env::var("PRISM_NODE_REGISTRY_ADDRESS")
            .ok()
            .filter(|value| is_address(value));

        match (rpc_url, registry_address) {
            (Some(rpc_url), Some(registry_address)) => Ok(Self::Rpc {
                client: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .context("build node registry RPC client")?,
                rpc_url,
                registry_address: registry_address.to_ascii_lowercase(),
            }),
            (None, None) if allow_development => {
                tracing::warn!("skipping onchain node verification in local development");
                Ok(Self::Development)
            }
            _ => anyhow::bail!(
                "PRISM_RPC_URL and PRISM_NODE_REGISTRY_ADDRESS are required outside local development"
            ),
        }
    }

    async fn verify_offer(&self, offer: &NodeOffer) -> Result<bool, RegistryError> {
        match self {
            Self::Development => Ok(true),
            Self::Rpc {
                client,
                rpc_url,
                registry_address,
            } => {
                let node_id = bytes32(&offer.node_id)?;
                let call_data = format!("0x50c946fe{}", hex::encode(node_id));
                let response = client
                    .post(rpc_url)
                    .json(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_call",
                        "params": [{ "to": registry_address, "data": call_data }, "latest"],
                    }))
                    .send()
                    .await
                    .map_err(RegistryError::Rpc)?
                    .error_for_status()
                    .map_err(RegistryError::Rpc)?
                    .json::<RpcResponse<String>>()
                    .await
                    .map_err(RegistryError::Rpc)?;
                if response.error.is_some() {
                    return Err(RegistryError::InvalidResponse);
                }
                let node = decode_node(
                    response
                        .result
                        .as_deref()
                        .ok_or(RegistryError::InvalidResponse)?,
                )?;
                let required_bond: u128 = 1_000_000;
                Ok(node.status == 1
                    && node.active_lease_id == 0
                    && node.bond >= required_bond
                    && node.device_hash == offer.node_id.to_ascii_lowercase()
                    && node.operator == offer.operator_wallet.to_ascii_lowercase()
                    && node.payout == offer.payout_wallet.to_ascii_lowercase()
                    && node.rate_per_second == offer.rate_per_second as u128)
            }
        }
    }
}

impl ChainVerifier {
    fn escrow_address(&self) -> Option<&str> {
        match self {
            Self::Development { escrow_address } => escrow_address.as_deref(),
            Self::Rpc { escrow_address, .. } => Some(escrow_address),
        }
    }

    fn active_escrow_address(&self) -> &str {
        match self {
            Self::Development { escrow_address } => escrow_address
                .as_deref()
                .unwrap_or(DEVELOPMENT_ESCROW_ADDRESS),
            Self::Rpc { escrow_address, .. } => escrow_address,
        }
    }

    fn from_environment(allow_development: bool) -> anyhow::Result<Self> {
        let rpc_url = env::var("PRISM_RPC_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let escrow_address = env::var("PRISM_LEASE_ESCROW_ADDRESS").ok();
        if escrow_address
            .as_ref()
            .is_some_and(|value| !is_address(value))
        {
            anyhow::bail!("PRISM_LEASE_ESCROW_ADDRESS is not an EVM address");
        }
        match (rpc_url, escrow_address) {
            (Some(rpc_url), Some(escrow_address)) => {
                let rpc_url = url::Url::parse(&rpc_url).context("parse chain RPC URL")?;
                let local_http = rpc_url.scheme() == "http"
                    && rpc_url.host_str().is_some_and(|host| {
                        host == "localhost"
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|address| address.is_loopback())
                    });
                if rpc_url.scheme() != "https" && !local_http {
                    anyhow::bail!("PRISM_RPC_URL must use HTTPS outside localhost");
                }
                if rpc_url.username() != "" || rpc_url.password().is_some() {
                    anyhow::bail!("PRISM_RPC_URL must not contain credentials");
                }
                let confirmations = env::var("PRISM_FUNDING_CONFIRMATIONS")
                    .ok()
                    .map(|value| value.parse::<u64>())
                    .transpose()?
                    .unwrap_or(12);
                if confirmations == 0 || confirmations > 10_000 {
                    anyhow::bail!("PRISM_FUNDING_CONFIRMATIONS must be between 1 and 10000");
                }
                Ok(Self::Rpc {
                    client: reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(20))
                        .build()
                        .context("build chain RPC client")?,
                    rpc_url: rpc_url.into(),
                    escrow_address: escrow_address.to_ascii_lowercase(),
                    confirmations,
                })
            }
            (None, escrow_address) if allow_development => {
                tracing::warn!("accepting synthetic lease funding only in local development");
                Ok(Self::Development {
                    escrow_address: escrow_address.map(|address| address.to_ascii_lowercase()),
                })
            }
            _ => anyhow::bail!(
                "PRISM_RPC_URL and PRISM_LEASE_ESCROW_ADDRESS are required outside local development"
            ),
        }
    }

    async fn verify_funding(
        &self,
        transaction_hash: &str,
        quote: &LeaseQuote,
    ) -> Result<ConfirmedFunding, ChainError> {
        if !is_hash(transaction_hash) {
            return Err(ChainError::InvalidTransactionHash);
        }
        match self {
            Self::Development { escrow_address } => {
                let lease_id = u64::from_str_radix(&transaction_hash[2..18], 16)
                    .map_err(|_| ChainError::InvalidTransactionHash)?
                    .max(1);
                Ok(ConfirmedFunding {
                    lease_id,
                    escrow_address: escrow_address
                        .as_deref()
                        .unwrap_or(DEVELOPMENT_ESCROW_ADDRESS)
                        .to_owned(),
                    renter_wallet: format!(
                        "0x{}",
                        &transaction_hash[transaction_hash.len() - 40..]
                    )
                    .to_ascii_lowercase(),
                })
            }
            Self::Rpc {
                client,
                rpc_url,
                escrow_address,
                confirmations,
            } => {
                let chain_id: String =
                    rpc_call(client, rpc_url, "eth_chainId", serde_json::json!([])).await?;
                if parse_quantity(&chain_id)? != prism_protocol::ROBINHOOD_CHAIN_ID {
                    return Err(ChainError::InvalidResponse);
                }
                let receipt: Option<TransactionReceipt> = rpc_call(
                    client,
                    rpc_url,
                    "eth_getTransactionReceipt",
                    serde_json::json!([transaction_hash]),
                )
                .await?;
                let receipt = receipt.ok_or(ChainError::NotFinal)?;
                if parse_quantity(&receipt.status)? != 1 {
                    return Err(ChainError::Reverted);
                }
                let receipt_block = parse_quantity(&receipt.block_number)?;
                let current_block: String =
                    rpc_call(client, rpc_url, "eth_blockNumber", serde_json::json!([])).await?;
                if parse_quantity(&current_block)?
                    < receipt_block.saturating_add(confirmations.saturating_sub(1))
                {
                    return Err(ChainError::NotFinal);
                }
                decode_funding_event(&receipt.logs, escrow_address, quote)
            }
        }
    }
}

/// Reads how much PRISM a renter has had locked long enough to count. The
/// escrow charges a node's registered rate, so this cannot discount a quote;
/// it decides which rates the renter is allowed to be matched against.
/// keccak256("eligibleStakeOf(address)")[..4]. Pinned by a test, because a
/// wrong selector reads as "nobody has staked anything" rather than as an
/// error, and every staker would quietly lose their discount.
const ELIGIBLE_STAKE_SELECTOR: &str = "fc786d81";

/// Node ids set aside for renters who stake, read once at startup from
/// `PRISM_STAKER_NODE_IDS`. Marking capacity here rather than at enrolment
/// means the pool can be changed by restarting the service, and a node that
/// leaves the list goes straight back to serving everyone.
static STAKER_NODE_IDS: OnceLock<BTreeSet<String>> = OnceLock::new();

fn staker_node_ids() -> &'static BTreeSet<String> {
    STAKER_NODE_IDS.get_or_init(|| {
        let ids: BTreeSet<String> = env::var("PRISM_STAKER_NODE_IDS")
            .unwrap_or_default()
            .split(',')
            .map(|id| id.trim().to_ascii_lowercase())
            .filter(|id| !id.is_empty())
            .collect();
        if ids.is_empty() {
            tracing::info!(
                "no staker-only capacity configured; every renter prices at the published rate"
            );
        } else {
            tracing::info!(count = ids.len(), "staker-only capacity configured");
        }
        ids
    })
}

/// Applied when offers are read so the pool reflects current configuration
/// rather than whatever was true when a node enrolled.
fn mark_staker_capacity(mut offers: Vec<NodeOffer>) -> Vec<NodeOffer> {
    let staker = staker_node_ids();
    if staker.is_empty() {
        return offers;
    }
    for offer in &mut offers {
        offer.staker_only = staker.contains(&offer.node_id.to_ascii_lowercase());
    }
    offers
}

#[derive(Clone)]
enum StakeReader {
    /// No contract configured. Every renter prices at the published rate,
    /// which is the correct answer when staking is not deployed yet.
    Disabled,
    Rpc {
        client: reqwest::Client,
        rpc_url: Arc<String>,
        stake_address: Arc<String>,
        /// Divisor from the token's smallest unit to whole tokens.
        token_scale: u128,
    },
}

impl StakeReader {
    fn from_environment() -> anyhow::Result<Self> {
        let Some(stake_address) = env::var("PRISM_STAKE_ADDRESS")
            .ok()
            .filter(|value| !value.is_empty())
        else {
            tracing::warn!("PRISM_STAKE_ADDRESS unset, pricing every renter at the published rate");
            return Ok(Self::Disabled);
        };
        if !is_address(&stake_address) {
            anyhow::bail!("PRISM_STAKE_ADDRESS is not an address");
        }
        let rpc_url = env::var("PRISM_RPC_URL").context("PRISM_RPC_URL for stake reads")?;
        let decimals: u32 = env::var("PRISM_STAKE_TOKEN_DECIMALS")
            .ok()
            .map_or(Ok(18), |value| value.parse())
            .context("PRISM_STAKE_TOKEN_DECIMALS")?;
        if decimals > 36 {
            anyhow::bail!("PRISM_STAKE_TOKEN_DECIMALS is out of range");
        }
        Ok(Self::Rpc {
            client: reqwest::Client::new(),
            rpc_url: Arc::new(rpc_url),
            stake_address: Arc::new(stake_address),
            token_scale: 10_u128.pow(decimals),
        })
    }

    /// Whole tokens, floored. A read that fails prices the renter at the
    /// published rate rather than failing the quote: an RPC blip should cost a
    /// discount, never the ability to rent a GPU.
    async fn eligible_whole_tokens(&self, wallets: &[String]) -> u64 {
        let Self::Rpc {
            client,
            rpc_url,
            stake_address,
            token_scale,
        } = self
        else {
            return 0;
        };
        let mut best = 0;
        for wallet in wallets {
            let call_data = format!(
                "0x{ELIGIBLE_STAKE_SELECTOR}000000000000000000000000{}",
                &wallet[2..]
            );
            let response = client
                .post(rpc_url.as_str())
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "eth_call",
                    "params": [{ "to": stake_address.as_str(), "data": call_data }, "latest"],
                }))
                .send()
                .await;
            let Ok(response) = response else {
                tracing::warn!("stake read failed, pricing at the published rate");
                continue;
            };
            let Ok(body) = response.json::<RpcResponse<String>>().await else {
                continue;
            };
            let Some(result) = body.result else { continue };
            let Ok(raw) = u128::from_str_radix(result.trim_start_matches("0x"), 16) else {
                continue;
            };
            let whole = u64::try_from(raw / token_scale).unwrap_or(u64::MAX);
            best = best.max(whole);
        }
        best
    }
}

async fn rpc_call<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &'static str,
    params: serde_json::Value,
) -> Result<T, ChainError> {
    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .map_err(ChainError::Rpc)?
        .error_for_status()
        .map_err(ChainError::Rpc)?
        .json::<RpcResponse<T>>()
        .await
        .map_err(ChainError::Rpc)?;
    if response.error.is_some() {
        return Err(ChainError::InvalidResponse);
    }
    response.result.ok_or(ChainError::InvalidResponse)
}

fn decode_funding_event(
    logs: &[ChainLog],
    escrow_address: &str,
    quote: &LeaseQuote,
) -> Result<ConfirmedFunding, ChainError> {
    let signature = format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"LeaseFunded(uint256,bytes32,address,uint256,uint32,bytes32)"
        ))
    );
    let expected_node = quote.node_id.trim_start_matches("0x");
    let expected_reference = quote_reference(quote.quote_id);
    for log in logs {
        if !log.address.eq_ignore_ascii_case(escrow_address)
            || log.topics.len() != 4
            || !log.topics[0].eq_ignore_ascii_case(&signature)
            || !log.topics[2]
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(expected_node)
        {
            continue;
        }
        let lease_id = parse_topic_u64(&log.topics[1])?;
        let renter_word = decode_word(&log.topics[3])?;
        if renter_word[..12].iter().any(|byte| *byte != 0) {
            return Err(ChainError::InvalidResponse);
        }
        let data = hex::decode(
            log.data
                .strip_prefix("0x")
                .ok_or(ChainError::InvalidResponse)?,
        )
        .map_err(|_| ChainError::InvalidResponse)?;
        if data.len() != 96 {
            return Err(ChainError::InvalidResponse);
        }
        let deposit = word_u64(&data[0..32])?;
        let duration = word_u64(&data[32..64])?;
        if deposit != quote.maximum_escrow
            || duration != u64::from(quote.duration_seconds)
            || data[64..96] != expected_reference
        {
            return Err(ChainError::FundingMismatch);
        }
        return Ok(ConfirmedFunding {
            lease_id,
            escrow_address: escrow_address.to_ascii_lowercase(),
            renter_wallet: format!("0x{}", hex::encode(&renter_word[12..])),
        });
    }
    Err(ChainError::FundingMismatch)
}

fn quote_reference(quote_id: Uuid) -> [u8; 32] {
    Keccak256::digest(quote_id.to_string().as_bytes()).into()
}

fn decode_word(value: &str) -> Result<[u8; 32], ChainError> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .ok_or(ChainError::InvalidResponse)?,
    )
    .map_err(|_| ChainError::InvalidResponse)?;
    bytes.try_into().map_err(|_| ChainError::InvalidResponse)
}

fn parse_topic_u64(value: &str) -> Result<u64, ChainError> {
    word_u64(&decode_word(value)?)
}

fn word_u64(word: &[u8]) -> Result<u64, ChainError> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidResponse);
    }
    Ok(u64::from_be_bytes(
        word[24..]
            .try_into()
            .map_err(|_| ChainError::InvalidResponse)?,
    ))
}

fn parse_quantity(value: &str) -> Result<u64, ChainError> {
    u64::from_str_radix(
        value
            .strip_prefix("0x")
            .ok_or(ChainError::InvalidResponse)?,
        16,
    )
    .map_err(|_| ChainError::InvalidResponse)
}

impl IdentityVerifier {
    fn from_environment(allow_development: bool) -> anyhow::Result<Self> {
        let key = env::var("PRISM_CONTROL_PLANE_AUTH_KEY")
            .ok()
            .filter(|value| !value.is_empty());
        match key {
            Some(key) => {
                let key = hex::decode(key).context("decode control-plane auth key")?;
                if key.len() < 32 {
                    anyhow::bail!("PRISM_CONTROL_PLANE_AUTH_KEY must be at least 32 bytes");
                }
                Ok(Self::Hmac(key))
            }
            None if allow_development => {
                tracing::warn!("accepting development identity headers");
                Ok(Self::Development)
            }
            None => {
                anyhow::bail!("PRISM_CONTROL_PLANE_AUTH_KEY is required outside local development")
            }
        }
    }

    fn verify(
        &self,
        headers: &HeaderMap,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<VerifiedIdentity, IdentityError> {
        match self {
            Self::Development => {
                let subject = headers
                    .get("x-prism-development-subject")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.is_empty())
                    .ok_or(IdentityError::InvalidSignature)?;
                let request_id = request_id(headers)?;
                let session_id = headers
                    .get("x-prism-development-session")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| valid_internal_identifier(value))
                    .unwrap_or(subject);
                Ok(VerifiedIdentity {
                    subject: subject.to_owned(),
                    session_id: session_id.to_owned(),
                    request_id: request_id.to_owned(),
                })
            }
            Self::Hmac(key) => {
                let subject = headers
                    .get("x-prism-subject")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.is_empty() && value.len() <= 255)
                    .ok_or(IdentityError::InvalidSignature)?;
                let session_id = headers
                    .get("x-prism-session-id")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| valid_internal_identifier(value))
                    .ok_or(IdentityError::InvalidSignature)?;
                let timestamp = headers
                    .get("x-prism-timestamp")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or(IdentityError::InvalidSignature)?;
                if (Utc::now().timestamp() - timestamp).abs() > AUTH_MAX_AGE_SECONDS {
                    return Err(IdentityError::Expired);
                }
                let signature = headers
                    .get("x-prism-signature")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| hex::decode(value).ok())
                    .ok_or(IdentityError::InvalidSignature)?;
                let request_id = request_id(headers)?;
                let body_hash = hex::encode(sha2::Sha256::digest(body));
                let mut verifier =
                    HmacSha256::new_from_slice(key).map_err(|_| IdentityError::InvalidSignature)?;
                verifier.update(
                    [
                        "v2",
                        subject,
                        session_id,
                        &timestamp.to_string(),
                        request_id,
                        method,
                        path,
                        &body_hash,
                    ]
                    .join("\n")
                    .as_bytes(),
                );
                verifier
                    .verify_slice(&signature)
                    .map_err(|_| IdentityError::InvalidSignature)?;
                Ok(VerifiedIdentity {
                    subject: subject.to_owned(),
                    session_id: session_id.to_owned(),
                    request_id: request_id.to_owned(),
                })
            }
        }
    }
}

fn request_id(headers: &HeaderMap) -> Result<&str, IdentityError> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_internal_identifier(value))
        .ok_or(IdentityError::InvalidSignature)
}

fn valid_internal_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

struct OnchainNode {
    operator: String,
    payout: String,
    device_hash: String,
    rate_per_second: u128,
    bond: u128,
    active_lease_id: u64,
    status: u8,
}

fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn recover_evm_signer(message: &str, signature: &str) -> Option<String> {
    let signature = signature.strip_prefix("0x").unwrap_or(signature);
    let bytes = hex::decode(signature).ok()?;
    if bytes.len() != 65 {
        return None;
    }
    let signature = EcdsaSignature::from_slice(&bytes[..64]).ok()?;
    let recovery = match bytes[64] {
        0 | 1 => RecoveryId::try_from(bytes[64]).ok()?,
        27 | 28 => RecoveryId::try_from(bytes[64] - 27).ok()?,
        _ => return None,
    };
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut payload = Vec::with_capacity(prefix.len() + message.len());
    payload.extend_from_slice(prefix.as_bytes());
    payload.extend_from_slice(message.as_bytes());
    let digest = Keccak256::digest(payload);
    let key = EcdsaVerifyingKey::recover_from_prehash(&digest, &signature, recovery).ok()?;
    let encoded = key.to_encoded_point(false);
    let address = Keccak256::digest(&encoded.as_bytes()[1..]);
    Some(format!("0x{}", hex::encode(&address[12..])))
}

fn bytes32(value: &str) -> Result<[u8; 32], RegistryError> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err(RegistryError::InvalidNodeId);
    }
    let bytes = hex::decode(&value[2..]).map_err(|_| RegistryError::InvalidNodeId)?;
    bytes.try_into().map_err(|_| RegistryError::InvalidNodeId)
}

fn decode_node(value: &str) -> Result<OnchainNode, RegistryError> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .ok_or(RegistryError::InvalidResponse)?,
    )
    .map_err(|_| RegistryError::InvalidResponse)?;
    if bytes.len() != 256 {
        return Err(RegistryError::InvalidResponse);
    }
    let word = |index: usize| &bytes[index * 32..(index + 1) * 32];
    let address = |index: usize| format!("0x{}", hex::encode(&word(index)[12..]));
    let unsigned = |index: usize| {
        u128::from_be_bytes(
            word(index)[16..]
                .try_into()
                .expect("16-byte uint128 ABI word"),
        )
    };
    let active_lease_id =
        u64::from_be_bytes(word(6)[24..].try_into().expect("8-byte uint64 ABI word"));
    Ok(OnchainNode {
        operator: address(0),
        payout: address(1),
        device_hash: format!("0x{}", hex::encode(word(2))),
        rate_per_second: unsigned(4),
        bond: unsigned(5),
        active_lease_id,
        status: word(7)[31],
    })
}

impl MarketplaceStore {
    async fn from_environment() -> anyhow::Result<Self> {
        let database_url = env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let allow_memory_store = env::var("PRISM_ALLOW_DEVELOPMENT_STORE").as_deref() == Ok("1");

        let Some(database_url) = database_url else {
            if allow_memory_store {
                tracing::warn!("starting with the development-only memory store");
                return Ok(Self::Memory(Arc::new(RwLock::new(
                    MemoryMarketplace::default(),
                ))));
            }
            anyhow::bail!(
                "DATABASE_URL is required outside development; set PRISM_ALLOW_DEVELOPMENT_STORE=1 only for local work"
            );
        };

        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&database_url)
            .await
            .context("connect control-plane database")?;
        embedded_migrator()
            .run(&pool)
            .await
            .context("migrate control-plane database")?;
        record_service_version(&pool, "control-plane").await?;
        Ok(Self::Postgres(pool))
    }

    fn is_development(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    async fn check_health(&self) -> Result<(), StoreError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Postgres(pool) => query("SELECT 1")
                .execute(pool)
                .await
                .map(|_| ())
                .map_err(StoreError::Storage),
        }
    }

    async fn seed_operators(&self, subjects: &[String]) -> anyhow::Result<()> {
        for subject in subjects {
            if subject.len() > 255 || !valid_internal_identifier(subject) {
                anyhow::bail!("PRISM_OPERATOR_SUBJECTS contains an invalid subject");
            }
        }
        match self {
            Self::Memory(market) => {
                market
                    .write()
                    .await
                    .operators
                    .extend(subjects.iter().cloned());
            }
            Self::Postgres(pool) => {
                for subject in subjects {
                    query(
                        "INSERT INTO operator_accounts (subject, role) \
                         VALUES ($1, 'administrator') ON CONFLICT (subject) DO NOTHING",
                    )
                    .bind(subject)
                    .execute(pool)
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn store_certificate(
        &self,
        request_id: Uuid,
        certificate: StoredNodeCertificate,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.offers.contains_key(&certificate.node_id) {
                    return Err(StoreError::NodeNotFound);
                }
                if !market.certificate_requests.insert(request_id) {
                    return Err(StoreError::CertificateReplay);
                }
                market
                    .certificates
                    .insert(certificate.node_id.clone(), certificate);
                Ok(())
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let inserted = query(
                    "INSERT INTO node_certificate_requests (request_id, node_id) \
                     SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM node_offers WHERE node_id = $2) \
                     ON CONFLICT (request_id) DO NOTHING",
                )
                .bind(request_id)
                .bind(&certificate.node_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if inserted.rows_affected() != 1 {
                    let node_exists: bool = query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM node_offers WHERE node_id = $1)",
                    )
                    .bind(&certificate.node_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    return Err(if node_exists {
                        StoreError::CertificateReplay
                    } else {
                        StoreError::NodeNotFound
                    });
                }
                query(
                    "UPDATE node_certificates SET status = 'superseded', revoked_at = NOW() \
                     WHERE node_id = $1 AND status = 'active'",
                )
                .bind(&certificate.node_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                query(
                    "INSERT INTO node_certificates \
                         (certificate_id, node_id, fingerprint_sha256, csr_sha256, status, not_before, not_after) \
                     VALUES ($1, $2, $3, $4, 'active', $5, $6)",
                )
                .bind(certificate.certificate_id)
                .bind(&certificate.node_id)
                .bind(&certificate.fingerprint_sha256)
                .bind(&certificate.csr_sha256)
                .bind(certificate.not_before)
                .bind(certificate.not_after)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)
            }
        }
    }

    async fn create_wallet_challenge(
        &self,
        subject: &str,
        wallet_address: &str,
    ) -> Result<WalletChallenge, StoreError> {
        let challenge_id = Uuid::now_v7();
        let expires_at = Utc::now() + Duration::minutes(5);
        let message = format!(
            "Prism Network wallet ownership\nChallenge: {challenge_id}\nWallet: {wallet_address}\nExpires: {}",
            expires_at.to_rfc3339()
        );
        let challenge = WalletChallenge {
            challenge_id,
            wallet_address: wallet_address.to_owned(),
            message,
            expires_at,
        };
        match self {
            Self::Memory(market) => {
                market
                    .write()
                    .await
                    .wallet_challenges
                    .insert(challenge_id, (subject.to_owned(), challenge.clone()));
            }
            Self::Postgres(pool) => {
                query(
                    "DELETE FROM wallet_link_challenges \
                     WHERE expires_at <= NOW() OR consumed_at IS NOT NULL",
                )
                .execute(pool)
                .await
                .map_err(StoreError::Storage)?;
                query(
                    "INSERT INTO wallet_link_challenges \
                         (challenge_id, subject, wallet_address, message, expires_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(challenge_id)
                .bind(subject)
                .bind(wallet_address)
                .bind(&challenge.message)
                .bind(expires_at)
                .execute(pool)
                .await
                .map_err(StoreError::Storage)?;
            }
        }
        Ok(challenge)
    }

    async fn wallet_challenge(
        &self,
        subject: &str,
        challenge_id: Uuid,
        wallet_address: &str,
    ) -> Result<WalletChallenge, StoreError> {
        match self {
            Self::Memory(market) => market
                .read()
                .await
                .wallet_challenges
                .get(&challenge_id)
                .filter(|(owner, challenge)| {
                    owner == subject
                        && challenge.wallet_address == wallet_address
                        && challenge.expires_at > Utc::now()
                })
                .map(|(_, challenge)| challenge.clone())
                .ok_or(StoreError::WalletChallengeUnavailable),
            Self::Postgres(pool) => {
                let row: Option<(String, chrono::DateTime<Utc>)> = query_as(
                    "SELECT message, expires_at FROM wallet_link_challenges \
                     WHERE challenge_id = $1 AND subject = $2 AND wallet_address = $3 \
                       AND consumed_at IS NULL AND expires_at > NOW()",
                )
                .bind(challenge_id)
                .bind(subject)
                .bind(wallet_address)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                row.map(|(message, expires_at)| WalletChallenge {
                    challenge_id,
                    wallet_address: wallet_address.to_owned(),
                    message,
                    expires_at,
                })
                .ok_or(StoreError::WalletChallengeUnavailable)
            }
        }
    }

    async fn consume_wallet_challenge(
        &self,
        subject: &str,
        challenge_id: Uuid,
        wallet_address: &str,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let valid = market.wallet_challenges.remove(&challenge_id).is_some_and(
                    |(owner, challenge)| {
                        owner == subject
                            && challenge.wallet_address == wallet_address
                            && challenge.expires_at > Utc::now()
                    },
                );
                if !valid {
                    return Err(StoreError::WalletChallengeUnavailable);
                }
                market
                    .linked_wallets
                    .entry(subject.to_owned())
                    .or_default()
                    .insert(wallet_address.to_ascii_lowercase());
                Ok(())
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let consumed = query(
                    "UPDATE wallet_link_challenges SET consumed_at = NOW() \
                     WHERE challenge_id = $1 AND subject = $2 AND wallet_address = $3 \
                       AND consumed_at IS NULL AND expires_at > NOW()",
                )
                .bind(challenge_id)
                .bind(subject)
                .bind(wallet_address)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if consumed.rows_affected() != 1 {
                    return Err(StoreError::WalletChallengeUnavailable);
                }
                query(
                    "INSERT INTO account_wallets (subject, wallet_address, verified_at) \
                     VALUES ($1, $2, NOW()) \
                     ON CONFLICT (subject, wallet_address) DO UPDATE SET verified_at = NOW()",
                )
                .bind(subject)
                .bind(wallet_address)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)
            }
        }
    }

    async fn supplier_summary(&self, subject: &str) -> Result<SupplierSummary, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let linked_wallets: BTreeSet<String> = market
                    .linked_wallets
                    .get(subject)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|wallet| wallet.to_ascii_lowercase())
                    .collect();
                let nodes = market
                    .offers
                    .values()
                    .filter(|offer| {
                        linked_wallets.contains(&offer.operator_wallet.to_ascii_lowercase())
                            || linked_wallets.contains(&offer.payout_wallet.to_ascii_lowercase())
                    })
                    .map(|offer| {
                        let certificate = market.certificates.get(&offer.node_id);
                        SupplierNode {
                            offer: offer.clone(),
                            suspended: market.suspended_nodes.contains(&offer.node_id),
                            certificate_status: certificate
                                .map(|_| "active")
                                .unwrap_or("missing")
                                .to_owned(),
                            certificate_expires_at: certificate
                                .map(|certificate| certificate.not_after),
                            finalized_leases: 0,
                            provider_paid_base_units: 0,
                        }
                    })
                    .collect::<Vec<_>>();
                Ok(SupplierSummary {
                    linked_wallets: linked_wallets.into_iter().collect(),
                    nodes,
                    total_provider_paid_base_units: 0,
                    total_finalized_leases: 0,
                })
            }
            Self::Postgres(pool) => {
                // Offers are matched with LOWER() on the document side, so a
                // stored address that is not already lowercase would match
                // nothing and the operator would be told they have no nodes.
                let linked_wallets = query_scalar::<_, String>(
                    "SELECT LOWER(wallet_address) FROM account_wallets \
                     WHERE subject = $1 AND verified_at IS NOT NULL ORDER BY wallet_address",
                )
                .bind(subject)
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                if linked_wallets.is_empty() {
                    return Ok(SupplierSummary {
                        linked_wallets,
                        nodes: Vec::new(),
                        total_provider_paid_base_units: 0,
                        total_finalized_leases: 0,
                    });
                }
                let offers = query_scalar::<_, SqlJson<NodeOffer>>(
                    "SELECT document FROM node_offers \
                     WHERE LOWER(document->>'operator_wallet') = ANY($1) \
                        OR LOWER(document->>'payout_wallet') = ANY($1) \
                     ORDER BY created_at",
                )
                .bind(&linked_wallets)
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                let mut nodes = Vec::with_capacity(offers.len());
                for SqlJson(offer) in offers {
                    let suspended = query_scalar::<_, bool>(
                        "SELECT COALESCE((SELECT suspended FROM node_controls WHERE node_id = $1), FALSE)",
                    )
                    .bind(&offer.node_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                    let certificate = query_as::<_, (String, chrono::DateTime<Utc>)>(
                        "SELECT status, not_after FROM node_certificates \
                         WHERE node_id = $1 ORDER BY created_at DESC LIMIT 1",
                    )
                    .bind(&offer.node_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                    let settlement = query_as::<_, (i64, i64)>(
                        "SELECT COUNT(*)::bigint, \
                                COALESCE(SUM((p.document->>'provider_paid_base_units')::bigint), 0)::bigint \
                         FROM leases l JOIN proof_receipts p ON p.lease_id = l.lease_id \
                         WHERE l.document->>'node_id' = $1 AND l.state = 'finalized'",
                    )
                    .bind(&offer.node_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                    nodes.push(SupplierNode {
                        offer,
                        suspended,
                        certificate_status: certificate
                            .as_ref()
                            .map(|(status, _)| status.clone())
                            .unwrap_or_else(|| "missing".to_owned()),
                        certificate_expires_at: certificate.map(|(_, expires_at)| expires_at),
                        finalized_leases: settlement.0.max(0) as u64,
                        provider_paid_base_units: settlement.1.max(0) as u64,
                    });
                }
                Ok(SupplierSummary {
                    total_provider_paid_base_units: nodes
                        .iter()
                        .map(|node| node.provider_paid_base_units)
                        .sum(),
                    total_finalized_leases: nodes.iter().map(|node| node.finalized_leases).sum(),
                    linked_wallets,
                    nodes,
                })
            }
        }
    }

    async fn apply_operator_control(
        &self,
        actor_subject: &str,
        request: OperatorControlRequest,
    ) -> Result<OperatorAuditEvent, StoreError> {
        let target_type = request.action.target_type();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.operators.contains(actor_subject) {
                    return Err(StoreError::OperatorRequired);
                }
                if let Some(event) = market
                    .operator_audit
                    .iter()
                    .find(|event| event.action_id == request.action_id)
                {
                    return Ok(event.clone());
                }
                let before_state = match target_type {
                    "account" => {
                        let Some(risk_hold) = market.accounts.get(&request.target_id).copied()
                        else {
                            return Err(StoreError::OperatorTargetNotFound);
                        };
                        serde_json::json!({
                            "risk_hold": risk_hold,
                            "suspended": market.suspended_accounts.contains(&request.target_id)
                        })
                    }
                    "node" => {
                        if !market.offers.contains_key(&request.target_id) {
                            return Err(StoreError::OperatorTargetNotFound);
                        }
                        serde_json::json!({
                            "suspended": market.suspended_nodes.contains(&request.target_id),
                            "certificate_active": market.certificates.contains_key(&request.target_id)
                        })
                    }
                    _ => return Err(StoreError::InvalidOperatorAction),
                };
                match request.action {
                    OperatorAction::AccountRiskHold => {
                        market.accounts.insert(request.target_id.clone(), true);
                    }
                    OperatorAction::AccountRiskRelease => {
                        market.accounts.insert(request.target_id.clone(), false);
                    }
                    OperatorAction::AccountSuspend => {
                        market.suspended_accounts.insert(request.target_id.clone());
                        let sessions = market
                            .sessions
                            .iter()
                            .filter(|(_, subject)| *subject == &request.target_id)
                            .map(|(session, _)| session.clone())
                            .collect::<Vec<_>>();
                        market.revoked_sessions.extend(sessions);
                    }
                    OperatorAction::AccountResume => {
                        market.suspended_accounts.remove(&request.target_id);
                    }
                    OperatorAction::NodeSuspend => {
                        market.suspended_nodes.insert(request.target_id.clone());
                        market.tunnels.remove(&request.target_id);
                        market.tunnel_connections.remove(&request.target_id);
                    }
                    OperatorAction::NodeResume => {
                        market.suspended_nodes.remove(&request.target_id);
                    }
                    OperatorAction::NodeCertificateRevoke => {
                        if market.certificates.remove(&request.target_id).is_none() {
                            return Err(StoreError::InvalidOperatorAction);
                        }
                        market.tunnels.remove(&request.target_id);
                        market.tunnel_connections.remove(&request.target_id);
                    }
                    OperatorAction::SlashEvidenceRecord => {
                        if request.evidence_hash.is_none() {
                            return Err(StoreError::InvalidOperatorAction);
                        }
                    }
                }
                let after_state = match target_type {
                    "account" => serde_json::json!({
                        "risk_hold": market.accounts.get(&request.target_id).copied().unwrap_or(false),
                        "suspended": market.suspended_accounts.contains(&request.target_id)
                    }),
                    "node" => serde_json::json!({
                        "suspended": market.suspended_nodes.contains(&request.target_id),
                        "certificate_active": market.certificates.contains_key(&request.target_id)
                    }),
                    _ => unreachable!(),
                };
                let event = OperatorAuditEvent {
                    event_id: Uuid::now_v7(),
                    action_id: request.action_id,
                    actor_subject: actor_subject.to_owned(),
                    action: request.action,
                    target_type: target_type.to_owned(),
                    target_id: request.target_id,
                    reason: request.reason,
                    evidence_hash: request.evidence_hash,
                    before_state,
                    after_state,
                    created_at: Utc::now(),
                };
                market.operator_actions.insert(event.action_id);
                market.operator_audit.push(event.clone());
                Ok(event)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let operator: bool = query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM operator_accounts WHERE subject = $1)",
                )
                .bind(actor_subject)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if !operator {
                    return Err(StoreError::OperatorRequired);
                }
                if let Some(event) =
                    fetch_operator_audit(&mut transaction, request.action_id).await?
                {
                    return Ok(event);
                }
                let before_state =
                    operator_target_state(&mut transaction, target_type, &request.target_id)
                        .await?;
                match request.action {
                    OperatorAction::AccountRiskHold | OperatorAction::AccountRiskRelease => {
                        query("UPDATE accounts SET risk_hold = $2, updated_at = NOW() WHERE subject = $1")
                            .bind(&request.target_id)
                            .bind(request.action == OperatorAction::AccountRiskHold)
                            .execute(&mut *transaction)
                            .await
                            .map_err(StoreError::Storage)?;
                    }
                    OperatorAction::AccountSuspend | OperatorAction::AccountResume => {
                        let suspend = request.action == OperatorAction::AccountSuspend;
                        query("UPDATE accounts SET suspended = $2, updated_at = NOW() WHERE subject = $1")
                            .bind(&request.target_id)
                            .bind(suspend)
                            .execute(&mut *transaction)
                            .await
                            .map_err(StoreError::Storage)?;
                        if suspend {
                            query(
                                "UPDATE account_sessions SET revoked_at = NOW() \
                                 WHERE subject = $1 AND revoked_at IS NULL",
                            )
                            .bind(&request.target_id)
                            .execute(&mut *transaction)
                            .await
                            .map_err(StoreError::Storage)?;
                        }
                    }
                    OperatorAction::NodeSuspend | OperatorAction::NodeResume => {
                        let suspend = request.action == OperatorAction::NodeSuspend;
                        query(
                            "INSERT INTO node_controls (node_id, suspended, reason, updated_at) \
                             VALUES ($1, $2, $3, NOW()) \
                             ON CONFLICT (node_id) DO UPDATE \
                             SET suspended = EXCLUDED.suspended, reason = EXCLUDED.reason, updated_at = NOW()",
                        )
                        .bind(&request.target_id)
                        .bind(suspend)
                        .bind(&request.reason)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Storage)?;
                        if suspend {
                            query("DELETE FROM node_tunnels WHERE node_id = $1")
                                .bind(&request.target_id)
                                .execute(&mut *transaction)
                                .await
                                .map_err(StoreError::Storage)?;
                        }
                    }
                    OperatorAction::NodeCertificateRevoke => {
                        let revoked = query(
                            "UPDATE node_certificates \
                             SET status = 'revoked', revoked_at = NOW() \
                             WHERE node_id = $1 AND status = 'active'",
                        )
                        .bind(&request.target_id)
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Storage)?;
                        if revoked.rows_affected() != 1 {
                            return Err(StoreError::InvalidOperatorAction);
                        }
                        query("DELETE FROM node_tunnels WHERE node_id = $1")
                            .bind(&request.target_id)
                            .execute(&mut *transaction)
                            .await
                            .map_err(StoreError::Storage)?;
                    }
                    OperatorAction::SlashEvidenceRecord => {
                        if request.evidence_hash.is_none() {
                            return Err(StoreError::InvalidOperatorAction);
                        }
                    }
                }
                let after_state =
                    operator_target_state(&mut transaction, target_type, &request.target_id)
                        .await?;
                let event = OperatorAuditEvent {
                    event_id: Uuid::now_v7(),
                    action_id: request.action_id,
                    actor_subject: actor_subject.to_owned(),
                    action: request.action,
                    target_type: target_type.to_owned(),
                    target_id: request.target_id,
                    reason: request.reason,
                    evidence_hash: request.evidence_hash,
                    before_state,
                    after_state,
                    created_at: Utc::now(),
                };
                query(
                    "INSERT INTO operator_audit_events \
                         (event_id, action_id, actor_subject, action, target_type, target_id, reason, \
                          evidence_hash, before_state, after_state, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(event.event_id)
                .bind(event.action_id)
                .bind(&event.actor_subject)
                .bind(event.action.as_str())
                .bind(&event.target_type)
                .bind(&event.target_id)
                .bind(&event.reason)
                .bind(&event.evidence_hash)
                .bind(SqlJson(event.before_state.clone()))
                .bind(SqlJson(event.after_state.clone()))
                .bind(event.created_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(event)
            }
        }
    }

    async fn operator_audit(
        &self,
        actor_subject: &str,
    ) -> Result<Vec<OperatorAuditEvent>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                if !market.operators.contains(actor_subject) {
                    return Err(StoreError::OperatorRequired);
                }
                Ok(market
                    .operator_audit
                    .iter()
                    .rev()
                    .take(200)
                    .cloned()
                    .collect())
            }
            Self::Postgres(pool) => {
                let operator: bool = query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM operator_accounts WHERE subject = $1)",
                )
                .bind(actor_subject)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Storage)?;
                if !operator {
                    return Err(StoreError::OperatorRequired);
                }
                let rows = query_as::<
                    _,
                    (
                        Uuid,
                        Uuid,
                        String,
                        String,
                        String,
                        String,
                        String,
                        Option<String>,
                        SqlJson<serde_json::Value>,
                        SqlJson<serde_json::Value>,
                        chrono::DateTime<Utc>,
                    ),
                >(
                    "SELECT event_id, action_id, actor_subject, action, target_type, target_id, \
                            reason, evidence_hash, before_state, after_state, created_at \
                     FROM operator_audit_events ORDER BY created_at DESC LIMIT 200",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                rows.into_iter().map(operator_audit_from_row).collect()
            }
        }
    }

    async fn operator_disputes(
        &self,
        actor_subject: &str,
        escrow_address: Option<&str>,
    ) -> Result<Vec<OperatorDispute>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                if !market.operators.contains(actor_subject) {
                    return Err(StoreError::OperatorRequired);
                }
                Ok(Vec::new())
            }
            Self::Postgres(pool) => {
                let operator: bool = query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM operator_accounts WHERE subject = $1)",
                )
                .bind(actor_subject)
                .fetch_one(pool)
                .await
                .map_err(StoreError::Storage)?;
                if !operator {
                    return Err(StoreError::OperatorRequired);
                }
                let rows = query_as::<
                    _,
                    (
                        i64,
                        i64,
                        String,
                        SqlJson<SettlementEvidence>,
                        Option<SqlJson<StoredSettlementSubmission>>,
                        chrono::DateTime<Utc>,
                    ),
                >(
                    "SELECT j.lease_id, l.chain_lease_id, l.document->>'node_id', \
                            j.evidence, j.proposal, j.updated_at \
                     FROM settlement_jobs j JOIN leases l ON l.lease_id = j.lease_id \
                     WHERE j.status = 'disputed' AND l.state = 'disputed' \
                     ORDER BY j.updated_at, j.lease_id LIMIT 200",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                rows.into_iter()
                    .map(
                        |(
                            lease_id,
                            chain_lease_id,
                            node_id,
                            SqlJson(evidence),
                            proposal,
                            updated_at,
                        )| {
                            operator_dispute(
                                u64::try_from(lease_id)
                                    .map_err(|_| StoreError::InvalidOperatorAction)?,
                                u64::try_from(chain_lease_id)
                                    .map_err(|_| StoreError::InvalidOperatorAction)?,
                                node_id,
                                evidence,
                                proposal.map(|SqlJson(value)| value),
                                escrow_address,
                                updated_at,
                            )
                        },
                    )
                    .collect()
            }
        }
    }

    async fn authorize(&self, identity: VerifiedIdentity) -> Result<Account, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let now = Utc::now();
                market
                    .identity_requests
                    .retain(|_, expires_at| *expires_at > now);
                if market.identity_requests.contains_key(&identity.request_id) {
                    return Err(StoreError::IdentityReplay);
                }
                if market.revoked_sessions.contains(&identity.session_id)
                    || market.suspended_accounts.contains(&identity.subject)
                    || market
                        .sessions
                        .get(&identity.session_id)
                        .is_some_and(|subject| subject != &identity.subject)
                {
                    return Err(StoreError::SessionRevoked);
                }
                market.identity_requests.insert(
                    identity.request_id,
                    now + Duration::seconds(AUTH_MAX_AGE_SECONDS),
                );
                market
                    .sessions
                    .entry(identity.session_id)
                    .or_insert_with(|| identity.subject.clone());
                let risk_hold = *market
                    .accounts
                    .entry(identity.subject.clone())
                    .or_insert(false);
                Ok(Account {
                    subject: identity.subject,
                    linked_wallets: Vec::new(),
                    risk_hold,
                })
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                query("DELETE FROM identity_requests WHERE expires_at <= NOW()")
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                let inserted = query(
                    "INSERT INTO identity_requests (request_id, subject, expires_at) \
                     VALUES ($1, $2, NOW() + INTERVAL '60 seconds') \
                     ON CONFLICT (request_id) DO NOTHING",
                )
                .bind(&identity.request_id)
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if inserted.rows_affected() != 1 {
                    return Err(StoreError::IdentityReplay);
                }
                query(
                    "INSERT INTO accounts (subject) VALUES ($1) ON CONFLICT (subject) DO NOTHING",
                )
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let session = query(
                    "INSERT INTO account_sessions (session_id, subject) VALUES ($1, $2) \
                     ON CONFLICT (session_id) DO UPDATE SET last_seen_at = NOW() \
                     WHERE account_sessions.subject = EXCLUDED.subject \
                       AND account_sessions.revoked_at IS NULL",
                )
                .bind(&identity.session_id)
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if session.rows_affected() != 1 {
                    return Err(StoreError::SessionRevoked);
                }
                let controls = query_as::<_, (bool, bool)>(
                    "SELECT risk_hold, suspended FROM accounts WHERE subject = $1",
                )
                .bind(&identity.subject)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if controls.1 {
                    return Err(StoreError::AccountSuspended);
                }
                let linked_wallets = query_scalar(
                    "SELECT LOWER(wallet_address) FROM account_wallets \
                     WHERE subject = $1 AND verified_at IS NOT NULL ORDER BY wallet_address",
                )
                .bind(&identity.subject)
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(Account {
                    subject: identity.subject,
                    linked_wallets,
                    risk_hold: controls.0,
                })
            }
        }
    }

    async fn revoke_session(&self, identity: VerifiedIdentity) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if market
                    .sessions
                    .get(&identity.session_id)
                    .is_some_and(|subject| subject != &identity.subject)
                {
                    return Err(StoreError::SessionRevoked);
                }
                if market.identity_requests.contains_key(&identity.request_id) {
                    return Err(StoreError::IdentityReplay);
                }
                market.identity_requests.insert(
                    identity.request_id,
                    Utc::now() + Duration::seconds(AUTH_MAX_AGE_SECONDS),
                );
                market
                    .sessions
                    .insert(identity.session_id.clone(), identity.subject);
                market.revoked_sessions.insert(identity.session_id);
                Ok(())
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let inserted = query(
                    "INSERT INTO identity_requests (request_id, subject, expires_at) \
                     VALUES ($1, $2, NOW() + INTERVAL '60 seconds') \
                     ON CONFLICT (request_id) DO NOTHING",
                )
                .bind(&identity.request_id)
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if inserted.rows_affected() != 1 {
                    return Err(StoreError::IdentityReplay);
                }
                query(
                    "INSERT INTO accounts (subject) VALUES ($1) ON CONFLICT (subject) DO NOTHING",
                )
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let revoked = query(
                    "INSERT INTO account_sessions (session_id, subject, revoked_at) \
                     VALUES ($1, $2, NOW()) \
                     ON CONFLICT (session_id) DO UPDATE SET revoked_at = NOW() \
                     WHERE account_sessions.subject = EXCLUDED.subject",
                )
                .bind(&identity.session_id)
                .bind(&identity.subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if revoked.rows_affected() != 1 {
                    return Err(StoreError::SessionRevoked);
                }
                transaction.commit().await.map_err(StoreError::Storage)
            }
        }
    }

    /// What GPU time has actually cleared at, per class. Two series: what the
    /// supply side charged us, and what renters paid on leases that settled
    /// onchain. Public because a price nobody can check is a quote, not a price.
    async fn price_index(&self) -> Result<Vec<PriceIndexEntry>, StoreError> {
        match self {
            // The in-memory store exists for tests and carries no price history.
            Self::Memory(_) => Ok(Vec::new()),
            Self::Postgres(pool) => {
                let rows = query_as::<_, (String, Option<i64>, Option<i64>, Option<i64>, i64, Option<f64>, Option<i64>, Option<chrono::DateTime<Utc>>)>(
                    "WITH sourced AS ( \
                         SELECT gpu_model, \
                                min(hourly_cost_micros) AS low, \
                                max(hourly_cost_micros) AS high, \
                                (percentile_cont(0.5) WITHIN GROUP (ORDER BY hourly_cost_micros))::bigint AS median, \
                                count(*)::bigint AS observations, \
                                max(observed_at) AS latest \
                         FROM capacity_prices \
                         WHERE observed_at >= NOW() - INTERVAL '30 days' \
                         GROUP BY gpu_model \
                     ), settled AS ( \
                         SELECT document->>'gpu_model' AS gpu_model, \
                                avg((document->>'charged_base_units')::numeric \
                                    / NULLIF((document->>'runtime_seconds')::numeric, 0) * 3600)::float8 AS paid, \
                                count(*)::bigint AS leases \
                         FROM proof_receipts \
                         WHERE document->>'outcome' = 'finalized' \
                           AND (document->>'runtime_seconds')::numeric > 0 \
                         GROUP BY 1 \
                     ) \
                     SELECT COALESCE(s.gpu_model, t.gpu_model), s.low, s.high, s.median, \
                            COALESCE(s.observations, 0), t.paid, t.leases, s.latest \
                     FROM sourced s FULL OUTER JOIN settled t ON t.gpu_model = s.gpu_model \
                     ORDER BY 1",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                Ok(rows
                    .into_iter()
                    .map(
                        |(gpu_model, low, high, median, observations, paid, leases, latest)| {
                            PriceIndexEntry {
                                gpu_model,
                                sourced_low_micros_per_hour: low,
                                sourced_high_micros_per_hour: high,
                                sourced_median_micros_per_hour: median,
                                sourced_observations: observations,
                                settled_mean_micros_per_hour: paid
                                    .map(|value| value.round() as i64),
                                settled_leases: leases.unwrap_or(0),
                                last_observed_at: latest,
                            }
                        },
                    )
                    .collect())
            }
        }
    }

    /// Offers as served, with the staker pool marked from configuration.
    async fn list_offers(&self) -> Result<Vec<NodeOffer>, StoreError> {
        self.raw_offers().await.map(mark_staker_capacity)
    }

    async fn raw_offers(&self) -> Result<Vec<NodeOffer>, StoreError> {
        let cutoff = Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS);
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let busy = nodes_holding_commands(&market);
                Ok(market
                    .offers
                    .values()
                    .filter(|offer| {
                        offer.bonded
                            && offer.public_image_only
                            && offer.updated_at >= cutoff
                            && !market.suspended_nodes.contains(&offer.node_id)
                            && !busy.contains(&offer.node_id)
                            && market
                                .tunnels
                                .get(&offer.node_id)
                                .is_some_and(|observed_at| *observed_at >= cutoff)
                    })
                    .cloned()
                    .map(|mut offer| {
                        offer.online = true;
                        offer.trust_class = class_for_verdict(
                            &offer.node_id,
                            true,
                            fresh_posture(&market, &offer.node_id, cutoff),
                            market.verdicts.get(&offer.node_id),
                            Utc::now(),
                        );
                        offer.command_channel =
                            polls_command_channel(&market, &offer.node_id, Utc::now());
                        offer.managed_batch = false;
                        offer
                    })
                    .collect())
            }
            Self::Postgres(pool) => {
                let documents = query_as::<
                    _,
                    (
                        SqlJson<NodeOffer>,
                        bool,
                        Option<SqlJson<NodePosture>>,
                        Option<SqlJson<AttestationVerdict>>,
                        bool,
                        bool,
                    ),
                >(
                    "SELECT o.document, \
                            EXISTS ( \
                                SELECT 1 FROM node_tunnels t \
                                WHERE t.node_id = o.node_id AND t.observed_at >= $1 \
                            ), \
                            (SELECT nt.document->'posture' FROM node_telemetry nt \
                             WHERE nt.node_id = o.node_id AND nt.observed_at >= $1), \
                            (SELECT v.document FROM node_attestation_verdicts v \
                             WHERE v.node_id = o.node_id AND v.expires_at > now()), \
                            EXISTS ( \
                                SELECT 1 FROM node_command_requests r \
                                WHERE r.node_id = o.node_id AND r.expires_at > NOW() \
                            ), \
                            EXISTS ( \
                                SELECT 1 FROM cloud_capacity cc \
                                WHERE cc.node_id = o.node_id \
                                  AND cc.provider = 'vast' \
                                  AND cc.available \
                                  AND cc.observed_at >= $1 \
                                  AND EXISTS ( \
                                      SELECT 1 FROM cloud_provider_state ps \
                                      WHERE ps.provider = 'vast' AND ps.state = 'healthy' \
                                        AND ps.observed_at >= $1 \
                                  ) \
                            ) \
                     FROM node_offers o \
                     WHERE (o.document->>'bonded')::boolean = true \
                       AND (document->>'public_image_only')::boolean = true \
                       AND (o.updated_at >= $1 OR EXISTS ( \
                           SELECT 1 FROM cloud_capacity cc0 \
                           WHERE cc0.node_id = o.node_id \
                             AND cc0.provider = 'vast' \
                             AND cc0.available \
                             AND cc0.observed_at >= $1 \
                             AND EXISTS ( \
                                 SELECT 1 FROM cloud_provider_state ps \
                                 WHERE ps.provider = 'vast' AND ps.state = 'healthy' \
                                   AND ps.observed_at >= $1 \
                             ) \
                       )) \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM node_controls c \
                           WHERE c.node_id = o.node_id AND c.suspended \
                       ) \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM node_commands nc \
                           WHERE nc.node_id = o.node_id \
                             AND nc.status IN ('queued', 'leased', 'ready', 'running') \
                       ) \
                       AND (EXISTS ( \
                           SELECT 1 FROM node_tunnels t \
                           WHERE t.node_id = o.node_id AND t.observed_at >= $1 \
                       ) OR EXISTS ( \
                           SELECT 1 FROM cloud_capacity cc \
                           WHERE cc.node_id = o.node_id \
                             AND cc.provider = 'vast' \
                             AND cc.available \
                             AND cc.observed_at >= $1 \
                             AND EXISTS ( \
                                 SELECT 1 FROM cloud_provider_state ps \
                                 WHERE ps.provider = 'vast' AND ps.state = 'healthy' \
                                   AND ps.observed_at >= $1 \
                             ) \
                       ) \
                       ) \
                     ORDER BY (o.document->>'rate_per_second')::bigint ASC, o.updated_at DESC",
                )
                .bind(cutoff)
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                let now = Utc::now();
                Ok(documents
                    .into_iter()
                    .map(
                        |(
                            SqlJson(mut offer),
                            tunneled,
                            posture,
                            verdict,
                            polling,
                            managed_batch,
                        )| {
                            offer.online = true;
                            offer.trust_class = class_for_verdict(
                                &offer.node_id,
                                tunneled,
                                posture.as_ref().map(|SqlJson(posture)| posture),
                                verdict.as_ref().map(|SqlJson(verdict)| verdict),
                                now,
                            );
                            offer.command_channel = polling;
                            offer.managed_batch = managed_batch;
                            offer
                        },
                    )
                    .collect())
            }
        }
    }

    async fn observe_tunnel(
        &self,
        node_id: &str,
        observation: TunnelObservation,
        require_certificate: bool,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.offers.contains_key(node_id) {
                    return Err(StoreError::NodeNotFound);
                }
                if market.suspended_nodes.contains(node_id)
                    || (require_certificate
                        && !market.certificates.get(node_id).is_some_and(|certificate| {
                            certificate.fingerprint_sha256 == observation.certificate_fingerprint
                                && certificate.not_before <= Utc::now()
                                && certificate.not_after > Utc::now()
                        }))
                {
                    return Err(StoreError::CertificateInactive);
                }
                market
                    .tunnels
                    .insert(node_id.to_owned(), observation.observed_at);
                market
                    .tunnel_connections
                    .insert(node_id.to_owned(), observation.connection_id);
                Ok(())
            }
            Self::Postgres(pool) => {
                let updated = query(
                    "INSERT INTO node_tunnels (node_id, connection_id, observed_at) \
                     SELECT $1, $2, $3 WHERE EXISTS ( \
                         SELECT 1 FROM node_offers WHERE node_id = $1 \
                     ) AND NOT EXISTS ( \
                         SELECT 1 FROM node_controls \
                         WHERE node_id = $1 AND suspended \
                     ) AND (NOT $4 OR EXISTS ( \
                         SELECT 1 FROM node_certificates \
                         WHERE node_id = $1 AND fingerprint_sha256 = $5 \
                           AND status = 'active' AND not_before <= NOW() AND not_after > NOW() \
                     )) \
                     ON CONFLICT (node_id) DO UPDATE \
                     SET connection_id = EXCLUDED.connection_id, observed_at = EXCLUDED.observed_at",
                )
                .bind(node_id)
                .bind(observation.connection_id)
                .bind(observation.observed_at)
                .bind(require_certificate)
                .bind(observation.certificate_fingerprint)
                .execute(pool)
                .await
                .map_err(StoreError::Storage)?;
                if updated.rows_affected() != 1 {
                    let node_exists: bool = query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM node_offers WHERE node_id = $1)",
                    )
                    .bind(node_id)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                    return Err(if node_exists {
                        StoreError::CertificateInactive
                    } else {
                        StoreError::NodeNotFound
                    });
                }
                Ok(())
            }
        }
    }

    async fn enroll(&self, offer: NodeOffer) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                market
                    .write()
                    .await
                    .offers
                    .insert(offer.node_id.clone(), offer);
                Ok(())
            }
            Self::Postgres(pool) => {
                query(
                    "INSERT INTO node_offers (node_id, document, updated_at) VALUES ($1, $2, $3) \
                     ON CONFLICT (node_id) DO UPDATE \
                     SET document = EXCLUDED.document, updated_at = EXCLUDED.updated_at",
                )
                .bind(&offer.node_id)
                .bind(SqlJson(offer.clone()))
                .bind(offer.updated_at)
                .execute(pool)
                .await
                .map_err(StoreError::Storage)?;
                Ok(())
            }
        }
    }

    async fn offer(&self, node_id: &str) -> Result<Option<NodeOffer>, StoreError> {
        match self {
            Self::Memory(market) => Ok(market.read().await.offers.get(node_id).cloned()),
            Self::Postgres(pool) => query_scalar::<_, SqlJson<NodeOffer>>(
                "SELECT document FROM node_offers WHERE node_id = $1",
            )
            .bind(node_id)
            .fetch_optional(pool)
            .await
            .map(|offer| offer.map(|SqlJson(offer)| offer))
            .map_err(StoreError::Storage),
        }
    }

    async fn record_telemetry(
        &self,
        node_id: &str,
        offer: NodeOffer,
        telemetry: NodeTelemetry,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.offers.contains_key(node_id) {
                    return Err(StoreError::NodeNotFound);
                }
                if market
                    .telemetry
                    .get(node_id)
                    .is_some_and(|current| telemetry.sequence <= current.sequence)
                {
                    return Err(StoreError::TelemetryReplay);
                }
                market.offers.insert(node_id.to_owned(), offer);
                market.telemetry.insert(node_id.to_owned(), telemetry);
                Ok(())
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let telemetry_updated = query(
                    "INSERT INTO node_telemetry (node_id, document, observed_at) VALUES ($1, $2, $3) \
                     ON CONFLICT (node_id) DO UPDATE \
                     SET document = EXCLUDED.document, observed_at = EXCLUDED.observed_at, received_at = NOW() \
                     WHERE COALESCE((node_telemetry.document->>'sequence')::numeric, -1) < $4::numeric",
                )
                .bind(node_id)
                .bind(SqlJson(telemetry.clone()))
                .bind(telemetry.observed_at)
                .bind(telemetry.sequence.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if telemetry_updated.rows_affected() != 1 {
                    return Err(StoreError::TelemetryReplay);
                }
                let updated = query(
                    "UPDATE node_offers SET document = $2, updated_at = $3 WHERE node_id = $1",
                )
                .bind(node_id)
                .bind(SqlJson(offer.clone()))
                .bind(offer.updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if updated.rows_affected() != 1 {
                    return Err(StoreError::NodeNotFound);
                }
                if let Some(lease_id) = telemetry
                    .active_lease
                    .as_deref()
                    .and_then(|value| value.parse::<i64>().ok())
                {
                    query(
                        "INSERT INTO lease_telemetry \
                             (lease_id, sequence, document, observed_at) \
                         SELECT $1, $2, $3, $4 FROM leases \
                         WHERE lease_id = $1 AND document->>'node_id' = $5 \
                           AND state NOT IN ('finalized', 'refunded') \
                         ON CONFLICT (lease_id, sequence) DO NOTHING",
                    )
                    .bind(lease_id)
                    .bind(telemetry.sequence as i64)
                    .bind(SqlJson(telemetry.clone()))
                    .bind(telemetry.observed_at)
                    .bind(node_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                }
                transaction.commit().await.map_err(StoreError::Storage)
            }
        }
    }

    async fn create_attestation_challenge(
        &self,
        node_id: &str,
    ) -> Result<AttestationChallenge, StoreError> {
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let issued_at = Utc::now();
        let challenge = AttestationChallenge {
            challenge_id: Uuid::now_v7(),
            node_id: node_id.to_owned(),
            nonce: hex::encode(nonce),
            issued_at,
            expires_at: issued_at + Duration::minutes(ATTESTATION_CHALLENGE_TTL_MINUTES),
        };
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.offers.contains_key(node_id) {
                    return Err(StoreError::NodeNotFound);
                }
                // A live challenge is handed back, never replaced. One nonce at
                // a time stops a node shopping for the one a captured report
                // happens to match, and handing it back stops anyone who knows
                // a node id from invalidating the nonce that node is busy
                // answering. The nonce is worth nothing without the GPU that
                // has to sign over it.
                if let Some(live) = market.attestation_challenges.values().find(|stored| {
                    stored.consumed_at.is_none()
                        && stored.challenge.node_id == node_id
                        && stored.challenge.expires_at > issued_at
                }) {
                    return Ok(live.challenge.clone());
                }
                market.attestation_challenges.retain(|_, stored| {
                    stored.challenge.node_id != node_id
                        && stored.challenge.expires_at > issued_at - Duration::days(7)
                });
                market.attestation_challenges.insert(
                    challenge.challenge_id,
                    StoredChallenge {
                        challenge: challenge.clone(),
                        consumed_at: None,
                    },
                );
                Ok(challenge)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let enrolled = query_scalar::<_, bool>(
                    "SELECT EXISTS (SELECT 1 FROM node_offers WHERE node_id = $1)",
                )
                .bind(node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if !enrolled {
                    return Err(StoreError::NodeNotFound);
                }
                // A live challenge is handed back, never replaced. One nonce at
                // a time stops a node shopping for the one a captured report
                // happens to match, and handing it back stops anyone who knows
                // a node id from invalidating the nonce that node is busy
                // answering. The nonce is worth nothing without the GPU that
                // has to sign over it.
                if let Some(live) =
                    query_as::<_, (Uuid, String, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
                        "SELECT challenge_id, nonce, issued_at, expires_at \
                     FROM node_attestation_challenges \
                     WHERE node_id = $1 AND consumed_at IS NULL AND expires_at > NOW() \
                     ORDER BY issued_at DESC LIMIT 1",
                    )
                    .bind(node_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?
                {
                    let (challenge_id, nonce, issued_at, expires_at) = live;
                    return Ok(AttestationChallenge {
                        challenge_id,
                        node_id: node_id.to_owned(),
                        nonce,
                        issued_at,
                        expires_at,
                    });
                }
                // A spent nonce proves nothing once its verdict is on file, so
                // the table is not an archive.
                query(
                    "DELETE FROM node_attestation_challenges \
                     WHERE node_id = $1 OR expires_at < NOW() - INTERVAL '7 days'",
                )
                .bind(node_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                query(
                    "INSERT INTO node_attestation_challenges \
                         (challenge_id, node_id, nonce, issued_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(challenge.challenge_id)
                .bind(&challenge.node_id)
                .bind(&challenge.nonce)
                .bind(challenge.issued_at)
                .bind(challenge.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(challenge)
            }
        }
    }

    /// The challenge is spent whatever the evidence turns out to be. Handing it
    /// back on failure would let an operator grind reports against one nonce
    /// until something passed.
    async fn record_attestation(
        &self,
        submission: AttestationSubmission<'_>,
    ) -> Result<AttestationVerdict, StoreError> {
        let AttestationSubmission {
            attestation,
            device_public_key,
            policy,
            tdx_compose_allowlist,
        } = submission;
        let node_id = attestation.node_id.as_str();
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if !market.offers.contains_key(node_id) {
                    return Err(StoreError::NodeNotFound);
                }
                if market.suspended_nodes.contains(node_id) {
                    return Err(StoreError::NodeSuspended);
                }
                let nonce = {
                    let Some(stored) = market
                        .attestation_challenges
                        .get_mut(&attestation.challenge_id)
                        .filter(|stored| {
                            stored.consumed_at.is_none()
                                && stored.challenge.node_id == node_id
                                && stored.challenge.expires_at > now
                        })
                    else {
                        return Err(StoreError::AttestationChallengeUnavailable);
                    };
                    stored.consumed_at = Some(now);
                    stored.challenge.nonce.clone()
                };
                let verdict = verify_node_evidence(
                    attestation,
                    &nonce,
                    device_public_key,
                    policy,
                    tdx_compose_allowlist,
                    now,
                )?;
                if market.verdicts.values().any(|current| {
                    current.device_identity == verdict.device_identity
                        && current.node_id != verdict.node_id
                }) {
                    return Err(StoreError::AttestedDeviceConflict);
                }
                market.verdicts.insert(node_id.to_owned(), verdict.clone());
                Ok(verdict)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let enrolled = query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM node_offers o \
                         WHERE o.node_id = $1 AND NOT EXISTS ( \
                             SELECT 1 FROM node_controls c \
                             WHERE c.node_id = o.node_id AND c.suspended \
                         ) \
                     )",
                )
                .bind(node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if !enrolled {
                    let known = query_scalar::<_, bool>(
                        "SELECT EXISTS (SELECT 1 FROM node_offers WHERE node_id = $1)",
                    )
                    .bind(node_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    return Err(if known {
                        StoreError::NodeSuspended
                    } else {
                        StoreError::NodeNotFound
                    });
                }
                let Some(nonce) = query_scalar::<_, String>(
                    "UPDATE node_attestation_challenges SET consumed_at = now() \
                     WHERE challenge_id = $1 AND node_id = $2 \
                       AND consumed_at IS NULL AND expires_at > now() \
                     RETURNING nonce",
                )
                .bind(attestation.challenge_id)
                .bind(node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::AttestationChallengeUnavailable);
                };
                let verdict = match verify_node_evidence(
                    attestation,
                    &nonce,
                    device_public_key,
                    policy,
                    tdx_compose_allowlist,
                    now,
                ) {
                    Ok(verdict) => verdict,
                    Err(error) => {
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(error);
                    }
                };
                let taken = query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM node_attestation_verdicts \
                         WHERE device_identity = $1 AND node_id <> $2 \
                     )",
                )
                .bind(&verdict.device_identity)
                .bind(node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if taken {
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Err(StoreError::AttestedDeviceConflict);
                }
                query(
                    "INSERT INTO node_attestation_verdicts \
                         (node_id, document, device_identity, verified_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (node_id) DO UPDATE \
                     SET document = EXCLUDED.document, \
                         device_identity = EXCLUDED.device_identity, \
                         verified_at = EXCLUDED.verified_at, \
                         expires_at = EXCLUDED.expires_at",
                )
                .bind(node_id)
                .bind(SqlJson(verdict.clone()))
                .bind(&verdict.device_identity)
                .bind(verdict.verified_at)
                .bind(verdict.expires_at)
                .execute(&mut *transaction)
                .await
                // Two nodes racing the same card both pass the check above and
                // the index settles it, so that loss reads as a conflict too.
                .map_err(|error| match &error {
                    SqlError::Database(database) if database.is_unique_violation() => {
                        StoreError::AttestedDeviceConflict
                    }
                    _ => StoreError::Storage(error),
                })?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(verdict)
            }
        }
    }

    /// The nonce the guest serving one lease has to commit to in `REPORT_DATA`.
    /// It is issued against the lease rather than the node because an SNP report
    /// describes the guest that asked for it: a report bound to nothing but a
    /// machine is a badge the operator can farm, by booting the measured image
    /// once and serving the renter from a bare container beside it.
    async fn create_lease_attestation_challenge(
        &self,
        lease_id: u64,
    ) -> Result<AttestationChallenge, StoreError> {
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::minutes(LEASE_ATTESTATION_CHALLENGE_TTL_MINUTES);
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let Some((_, lease)) = market.leases.get(&lease_id) else {
                    return Err(StoreError::LeaseNotAttestable);
                };
                if !accepts_guest_attestation(&lease.state) {
                    return Err(StoreError::LeaseNotAttestable);
                }
                let node_id = lease.node_id.clone();
                // A live challenge is handed back rather than replaced, as on
                // the node path: one nonce at a time stops a host shopping for
                // the one a report it already holds happens to match.
                if let Some(live) = market.lease_challenges.get(&lease_id).filter(|stored| {
                    stored.consumed_at.is_none() && stored.challenge.expires_at > issued_at
                }) {
                    return Ok(live.challenge.clone());
                }
                let challenge = AttestationChallenge {
                    challenge_id: Uuid::now_v7(),
                    node_id,
                    nonce: hex::encode(nonce),
                    issued_at,
                    expires_at,
                };
                market.lease_challenges.insert(
                    lease_id,
                    StoredChallenge {
                        challenge: challenge.clone(),
                        consumed_at: None,
                    },
                );
                Ok(challenge)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let Some((node_id, state)) = query_as::<_, (String, String)>(
                    "SELECT document->>'node_id', state FROM leases \
                     WHERE lease_id = $1 FOR UPDATE",
                )
                .bind(lease_id as i64)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::LeaseNotAttestable);
                };
                if !matches!(state.as_str(), "provisioning" | "ready") {
                    return Err(StoreError::LeaseNotAttestable);
                }
                if let Some((challenge_id, nonce, issued_at, expires_at)) =
                    query_as::<_, (Uuid, String, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
                        "SELECT challenge_id, nonce, issued_at, expires_at \
                         FROM lease_attestation_challenges \
                         WHERE lease_id = $1 AND consumed_at IS NULL AND expires_at > now()",
                    )
                    .bind(lease_id as i64)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?
                {
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Ok(AttestationChallenge {
                        challenge_id,
                        node_id,
                        nonce,
                        issued_at,
                        expires_at,
                    });
                }
                let challenge = AttestationChallenge {
                    challenge_id: Uuid::now_v7(),
                    node_id,
                    nonce: hex::encode(nonce),
                    issued_at,
                    expires_at,
                };
                // A spent nonce proves nothing once its verdict is on file, so
                // the row is replaced rather than kept alongside a new one.
                query(
                    "INSERT INTO lease_attestation_challenges \
                         (lease_id, challenge_id, node_id, nonce, issued_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (lease_id) DO UPDATE \
                     SET challenge_id = EXCLUDED.challenge_id, \
                         node_id = EXCLUDED.node_id, \
                         nonce = EXCLUDED.nonce, \
                         issued_at = EXCLUDED.issued_at, \
                         expires_at = EXCLUDED.expires_at, \
                         consumed_at = NULL",
                )
                .bind(lease_id as i64)
                .bind(challenge.challenge_id)
                .bind(&challenge.node_id)
                .bind(&challenge.nonce)
                .bind(challenge.issued_at)
                .bind(challenge.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(challenge)
            }
        }
    }

    /// The expectation is computed here and never accepted from the submission:
    /// `REPORT_DATA` from the nonce this service issued, the lease it issued it
    /// for and the channel key presented with the report, and `HOST_DATA` from
    /// the image the renter paid for. A guest that answered a different question
    /// produces a report that fails rather than one that is stored.
    ///
    /// The challenge is spent whatever the evidence turns out to be, for the
    /// reason written above `record_attestation`: handing it back on failure
    /// would let a host grind reports against one nonce until something passed.
    async fn record_lease_attestation(
        &self,
        submission: LeaseAttestationSubmission<'_>,
    ) -> Result<LeaseAttestationVerdict, StoreError> {
        let LeaseAttestationSubmission {
            attestation,
            lease,
            policy,
        } = submission;
        let lease_id = lease.lease_id;
        let now = Utc::now();
        let host_data = lease_host_data(&lease.image)?;
        // A guest verdict is about one lease and is worth nothing past it, so it
        // is given that lease's life rather than the crate's default.
        let policy = policy.clone().with_lease_verdict_ttl(
            Duration::seconds(i64::from(lease.duration_seconds))
                + Duration::hours(LEASE_VERDICT_PROVISIONING_SLACK_HOURS),
        );
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let nonce = {
                    let Some(stored) =
                        market.lease_challenges.get_mut(&lease_id).filter(|stored| {
                            stored.consumed_at.is_none()
                                && stored.challenge.challenge_id == attestation.challenge_id
                                && stored.challenge.node_id == attestation.node_id
                                && stored.challenge.expires_at > now
                        })
                    else {
                        return Err(StoreError::AttestationChallengeUnavailable);
                    };
                    stored.consumed_at = Some(now);
                    stored.challenge.nonce.clone()
                };
                let expected = prism_attestation::SnpExpectation {
                    report_data: expected_report_data(
                        &nonce,
                        lease_id,
                        &attestation.guest_channel_key,
                    )?,
                    host_data,
                    chip_id_digest: bound_chip_digest(
                        market
                            .snp_chips
                            .iter()
                            .find(|(_, owner)| owner.as_str() == lease.node_id)
                            .map(|(digest, _)| digest.clone()),
                    )?,
                };
                let verdict = verify_lease_attestation(attestation, &expected, now, &policy)?;
                if verdict.lease_id != lease_id || verdict.node_id != lease.node_id {
                    return Err(StoreError::AttestationUnverified);
                }
                // One chip stands behind one node and one node behind one chip,
                // the bound 0017 already puts on the GPU. Either direction
                // failing is a conflict rather than a second earned class.
                let taken = market.snp_chips.iter().any(|(digest, owner)| {
                    if digest == &verdict.guest.chip_id_digest {
                        owner != &verdict.node_id
                    } else {
                        owner == &verdict.node_id
                    }
                });
                if taken {
                    return Err(StoreError::AttestedChipConflict);
                }
                market.snp_chips.insert(
                    verdict.guest.chip_id_digest.clone(),
                    verdict.node_id.clone(),
                );
                market.lease_verdicts.insert(lease_id, verdict.clone());
                rederive_lease_class(&mut market, lease_id, now);
                Ok(verdict)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let Some(nonce) = query_scalar::<_, String>(
                    "UPDATE lease_attestation_challenges SET consumed_at = now() \
                     WHERE lease_id = $1 AND challenge_id = $2 AND node_id = $3 \
                       AND consumed_at IS NULL AND expires_at > now() \
                     RETURNING nonce",
                )
                .bind(lease_id as i64)
                .bind(attestation.challenge_id)
                .bind(&attestation.node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::AttestationChallengeUnavailable);
                };
                let expected = prism_attestation::SnpExpectation {
                    report_data: expected_report_data(
                        &nonce,
                        lease_id,
                        &attestation.guest_channel_key,
                    )?,
                    host_data,
                    chip_id_digest: bound_chip_digest(
                        query_scalar::<_, String>(
                            "SELECT chip_id_digest FROM node_snp_chips WHERE node_id = $1",
                        )
                        .bind(&lease.node_id)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(StoreError::Storage)?,
                    )?,
                };
                let verdict = match verify_lease_attestation(attestation, &expected, now, &policy) {
                    Ok(verdict)
                        if verdict.lease_id == lease_id && verdict.node_id == lease.node_id =>
                    {
                        verdict
                    }
                    Ok(_) => {
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(StoreError::AttestationUnverified);
                    }
                    Err(error) => {
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(error);
                    }
                };
                // The insert settles a race between two nodes presenting the
                // same processor: the second one updates no row and reads as a
                // conflict rather than as a second earned class. A node that has
                // moved to another chip loses the unique node index instead.
                let bound = query(
                    "INSERT INTO node_snp_chips \
                         (chip_id_digest, node_id, first_attested_at, last_attested_at) \
                     VALUES ($1, $2, $3, $3) \
                     ON CONFLICT (chip_id_digest) DO UPDATE \
                     SET last_attested_at = EXCLUDED.last_attested_at \
                     WHERE node_snp_chips.node_id = EXCLUDED.node_id",
                )
                .bind(&verdict.guest.chip_id_digest)
                .bind(&verdict.node_id)
                .bind(verdict.verified_at)
                .execute(&mut *transaction)
                .await
                .map_err(|error| match &error {
                    SqlError::Database(database) if database.is_unique_violation() => {
                        StoreError::AttestedChipConflict
                    }
                    _ => StoreError::Storage(error),
                })?;
                if bound.rows_affected() != 1 {
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Err(StoreError::AttestedChipConflict);
                }
                query(
                    "INSERT INTO lease_attestation_verdicts \
                         (lease_id, node_id, document, measurement, chip_id_digest, \
                          channel_key_fingerprint, verified_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (lease_id) DO UPDATE \
                     SET node_id = EXCLUDED.node_id, \
                         document = EXCLUDED.document, \
                         measurement = EXCLUDED.measurement, \
                         chip_id_digest = EXCLUDED.chip_id_digest, \
                         channel_key_fingerprint = EXCLUDED.channel_key_fingerprint, \
                         verified_at = EXCLUDED.verified_at, \
                         expires_at = EXCLUDED.expires_at",
                )
                .bind(lease_id as i64)
                .bind(&verdict.node_id)
                .bind(SqlJson(verdict.clone()))
                .bind(&verdict.guest.measurement)
                .bind(&verdict.guest.chip_id_digest)
                .bind(&verdict.guest.channel_key_fingerprint)
                .bind(verdict.verified_at)
                .bind(verdict.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                rederive_lease_class_pg(&mut transaction, lease_id, now).await?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(verdict)
            }
        }
    }

    /// The TDX guest half of a lease, verified and stored the way the SEV-SNP
    /// half is. It answers the same lease challenge the SEV-SNP guest would:
    /// one guest report per lease, whichever silicon took it. The expectation
    /// is computed here and never accepted from the submission: `REPORT_DATA`
    /// from the nonce this service issued and the lease it issued it for, and
    /// the compose from the image the renter paid for. The challenge is spent
    /// whatever the evidence turns out to be, as on the SEV-SNP path.
    async fn record_lease_tdx_attestation(
        &self,
        submission: LeaseTdxAttestationSubmission<'_>,
    ) -> Result<LeaseTdxGuestVerdict, StoreError> {
        let LeaseTdxAttestationSubmission {
            attestation,
            lease,
            policy,
        } = submission;
        let lease_id = lease.lease_id;
        let now = Utc::now();
        let compose_hash = lease_compose_hash(&lease.image)?;
        let policy = policy.clone().with_lease_verdict_ttl(
            Duration::seconds(i64::from(lease.duration_seconds))
                + Duration::hours(LEASE_VERDICT_PROVISIONING_SLACK_HOURS),
        );
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let nonce = {
                    let Some(stored) =
                        market.lease_challenges.get_mut(&lease_id).filter(|stored| {
                            stored.consumed_at.is_none()
                                && stored.challenge.challenge_id == attestation.challenge_id
                                && stored.challenge.node_id == attestation.node_id
                                && stored.challenge.expires_at > now
                        })
                    else {
                        return Err(StoreError::AttestationChallengeUnavailable);
                    };
                    stored.consumed_at = Some(now);
                    stored.challenge.nonce.clone()
                };
                let events = decode_tdx_events(&attestation.tdx_event_log).map_err(|reason| {
                    tracing::warn!(
                        lease_id,
                        node_id = %attestation.node_id,
                        reason,
                        "guest tdx event log rejected"
                    );
                    StoreError::AttestationUnverified
                })?;
                let verdict = verify_lease_tdx_attestation(
                    attestation,
                    &nonce,
                    &compose_hash,
                    &events,
                    now,
                    &policy,
                )?;
                if verdict.lease_id != lease_id || verdict.node_id != lease.node_id {
                    return Err(StoreError::AttestationUnverified);
                }
                market
                    .lease_tdx_guest_verdicts
                    .insert(lease_id, verdict.clone());
                rederive_lease_class(&mut market, lease_id, now);
                Ok(verdict)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let Some(nonce) = query_scalar::<_, String>(
                    "UPDATE lease_attestation_challenges SET consumed_at = now() \
                     WHERE lease_id = $1 AND challenge_id = $2 AND node_id = $3 \
                       AND consumed_at IS NULL AND expires_at > now() \
                     RETURNING nonce",
                )
                .bind(lease_id as i64)
                .bind(attestation.challenge_id)
                .bind(&attestation.node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::AttestationChallengeUnavailable);
                };
                let events = match decode_tdx_events(&attestation.tdx_event_log) {
                    Ok(events) => events,
                    Err(reason) => {
                        tracing::warn!(
                            lease_id,
                            node_id = %attestation.node_id,
                            reason,
                            "guest tdx event log rejected"
                        );
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(StoreError::AttestationUnverified);
                    }
                };
                let verdict = match verify_lease_tdx_attestation(
                    attestation,
                    &nonce,
                    &compose_hash,
                    &events,
                    now,
                    &policy,
                ) {
                    Ok(verdict)
                        if verdict.lease_id == lease_id && verdict.node_id == lease.node_id =>
                    {
                        verdict
                    }
                    Ok(_) => {
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(StoreError::AttestationUnverified);
                    }
                    Err(error) => {
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Err(error);
                    }
                };
                query(
                    "INSERT INTO lease_tdx_guest_verdicts \
                         (lease_id, node_id, document, device_identity, compose_hash, \
                          measurement_digest, verified_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                     ON CONFLICT (lease_id) DO UPDATE \
                     SET node_id = EXCLUDED.node_id, \
                         document = EXCLUDED.document, \
                         device_identity = EXCLUDED.device_identity, \
                         compose_hash = EXCLUDED.compose_hash, \
                         measurement_digest = EXCLUDED.measurement_digest, \
                         verified_at = EXCLUDED.verified_at, \
                         expires_at = EXCLUDED.expires_at",
                )
                .bind(lease_id as i64)
                .bind(&verdict.node_id)
                .bind(SqlJson(verdict.clone()))
                .bind(&verdict.device_identity)
                .bind(&verdict.compose_hash)
                .bind(&verdict.measurement_digest)
                .bind(verdict.verified_at)
                .bind(verdict.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                rederive_lease_class_pg(&mut transaction, lease_id, now).await?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(verdict)
            }
        }
    }

    /// The nonce the GPU serving this lease has to answer. It is separate from
    /// the guest challenge because the card signs its own report: one live
    /// nonce at a time, keyed by the lease, so a report a host already holds
    /// cannot be matched to a challenge it was never issued for.
    async fn create_lease_gpu_cc_attestation_challenge(
        &self,
        lease_id: u64,
    ) -> Result<AttestationChallenge, StoreError> {
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::minutes(LEASE_ATTESTATION_CHALLENGE_TTL_MINUTES);
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let Some((_, lease)) = market.leases.get(&lease_id) else {
                    return Err(StoreError::LeaseNotAttestable);
                };
                if !accepts_guest_attestation(&lease.state) {
                    return Err(StoreError::LeaseNotAttestable);
                }
                let node_id = lease.node_id.clone();
                if let Some(live) = market
                    .lease_gpu_cc_challenges
                    .get(&lease_id)
                    .filter(|stored| {
                        stored.consumed_at.is_none() && stored.challenge.expires_at > issued_at
                    })
                {
                    return Ok(live.challenge.clone());
                }
                let challenge = AttestationChallenge {
                    challenge_id: Uuid::now_v7(),
                    node_id,
                    nonce: hex::encode(nonce),
                    issued_at,
                    expires_at,
                };
                market.lease_gpu_cc_challenges.insert(
                    lease_id,
                    StoredChallenge {
                        challenge: challenge.clone(),
                        consumed_at: None,
                    },
                );
                Ok(challenge)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let Some((node_id, state)) = query_as::<_, (String, String)>(
                    "SELECT document->>'node_id', state FROM leases \
                     WHERE lease_id = $1 FOR UPDATE",
                )
                .bind(lease_id as i64)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::LeaseNotAttestable);
                };
                if !matches!(state.as_str(), "provisioning" | "ready") {
                    return Err(StoreError::LeaseNotAttestable);
                }
                if let Some((challenge_id, nonce, issued_at, expires_at)) =
                    query_as::<_, (Uuid, String, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
                        "SELECT challenge_id, nonce, issued_at, expires_at \
                         FROM lease_gpu_cc_challenges \
                         WHERE lease_id = $1 AND consumed_at IS NULL AND expires_at > now()",
                    )
                    .bind(lease_id as i64)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?
                {
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Ok(AttestationChallenge {
                        challenge_id,
                        node_id,
                        nonce,
                        issued_at,
                        expires_at,
                    });
                }
                let challenge = AttestationChallenge {
                    challenge_id: Uuid::now_v7(),
                    node_id,
                    nonce: hex::encode(nonce),
                    issued_at,
                    expires_at,
                };
                query(
                    "INSERT INTO lease_gpu_cc_challenges \
                         (lease_id, challenge_id, node_id, nonce, issued_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (lease_id) DO UPDATE \
                     SET challenge_id = EXCLUDED.challenge_id, \
                         node_id = EXCLUDED.node_id, \
                         nonce = EXCLUDED.nonce, \
                         issued_at = EXCLUDED.issued_at, \
                         expires_at = EXCLUDED.expires_at, \
                         consumed_at = NULL",
                )
                .bind(lease_id as i64)
                .bind(challenge.challenge_id)
                .bind(&challenge.node_id)
                .bind(&challenge.nonce)
                .bind(challenge.issued_at)
                .bind(challenge.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(challenge)
            }
        }
    }

    /// The GPU-CC half of a lease. It answers its own challenge, so the nonce
    /// consumed here is the one issued by `create_lease_gpu_cc_attestation_
    /// challenge`, never the guest one. The expected nonce is the challenge
    /// this service issued and nothing the submission carries, and the
    /// challenge is spent whatever the evidence turns out to be.
    async fn record_lease_gpu_cc_attestation(
        &self,
        submission: LeaseGpuCcAttestationSubmission<'_>,
    ) -> Result<LeaseGpuCcVerdict, StoreError> {
        let LeaseGpuCcAttestationSubmission {
            attestation,
            lease,
            policy,
        } = submission;
        let lease_id = lease.lease_id;
        let now = Utc::now();
        let policy = policy.clone().with_lease_verdict_ttl(
            Duration::seconds(i64::from(lease.duration_seconds))
                + Duration::hours(LEASE_VERDICT_PROVISIONING_SLACK_HOURS),
        );
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let nonce = {
                    let Some(stored) =
                        market
                            .lease_gpu_cc_challenges
                            .get_mut(&lease_id)
                            .filter(|stored| {
                                stored.consumed_at.is_none()
                                    && stored.challenge.challenge_id == attestation.challenge_id
                                    && stored.challenge.node_id == attestation.node_id
                                    && stored.challenge.expires_at > now
                            })
                    else {
                        return Err(StoreError::AttestationChallengeUnavailable);
                    };
                    stored.consumed_at = Some(now);
                    stored.challenge.nonce.clone()
                };
                let verdict = verify_lease_gpu_cc_attestation(attestation, &nonce, now, &policy)?;
                if verdict.lease_id != lease_id || verdict.node_id != lease.node_id {
                    return Err(StoreError::AttestationUnverified);
                }
                market
                    .lease_gpu_cc_verdicts
                    .insert(lease_id, verdict.clone());
                rederive_lease_class(&mut market, lease_id, now);
                Ok(verdict)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let Some(nonce) = query_scalar::<_, String>(
                    "UPDATE lease_gpu_cc_challenges SET consumed_at = now() \
                     WHERE lease_id = $1 AND challenge_id = $2 AND node_id = $3 \
                       AND consumed_at IS NULL AND expires_at > now() \
                     RETURNING nonce",
                )
                .bind(lease_id as i64)
                .bind(attestation.challenge_id)
                .bind(&attestation.node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                else {
                    return Err(StoreError::AttestationChallengeUnavailable);
                };
                let verdict =
                    match verify_lease_gpu_cc_attestation(attestation, &nonce, now, &policy) {
                        Ok(verdict)
                            if verdict.lease_id == lease_id && verdict.node_id == lease.node_id =>
                        {
                            verdict
                        }
                        Ok(_) => {
                            transaction.commit().await.map_err(StoreError::Storage)?;
                            return Err(StoreError::AttestationUnverified);
                        }
                        Err(error) => {
                            transaction.commit().await.map_err(StoreError::Storage)?;
                            return Err(error);
                        }
                    };
                query(
                    "INSERT INTO lease_gpu_cc_verdicts \
                         (lease_id, node_id, document, device_identity, measurement_digest, \
                          verified_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) \
                     ON CONFLICT (lease_id) DO UPDATE \
                     SET node_id = EXCLUDED.node_id, \
                         document = EXCLUDED.document, \
                         device_identity = EXCLUDED.device_identity, \
                         measurement_digest = EXCLUDED.measurement_digest, \
                         verified_at = EXCLUDED.verified_at, \
                         expires_at = EXCLUDED.expires_at",
                )
                .bind(lease_id as i64)
                .bind(&verdict.node_id)
                .bind(SqlJson(verdict.clone()))
                .bind(&verdict.device_identity)
                .bind(&verdict.measurement_digest)
                .bind(verdict.verified_at)
                .bind(verdict.expires_at)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                rederive_lease_class_pg(&mut transaction, lease_id, now).await?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(verdict)
            }
        }
    }

    /// The lease a guest report claims to be about, read without an account:
    /// the caller here is the node carrying the report, not the renter.
    async fn lease_record(&self, lease_id: u64) -> Result<Option<LeaseRecord>, StoreError> {
        match self {
            Self::Memory(market) => Ok(market
                .read()
                .await
                .leases
                .get(&lease_id)
                .map(|(_, lease)| lease.clone())),
            Self::Postgres(pool) => Ok(query_scalar::<_, SqlJson<LeaseRecord>>(
                "SELECT document FROM leases WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            .map(|SqlJson(lease)| lease)),
        }
    }

    #[cfg(test)]
    async fn quote(
        &self,
        subject: &str,
        request: &LeaseRequest,
        staked_whole_tokens: u64,
    ) -> Result<LeaseQuote, StoreError> {
        self.quote_for_escrow(
            subject,
            request,
            staked_whole_tokens,
            DEVELOPMENT_ESCROW_ADDRESS,
        )
        .await
    }

    async fn quote_for_escrow(
        &self,
        subject: &str,
        request: &LeaseRequest,
        staked_whole_tokens: u64,
        escrow_address: &str,
    ) -> Result<LeaseQuote, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if let Some(capability) = request.repro.as_ref() {
                    let existing: Vec<&LeaseQuote> = market
                        .open_quotes
                        .values()
                        .filter(|quote| {
                            quote
                                .repro
                                .as_ref()
                                .is_some_and(|repro| repro.token_hash == capability.token_hash)
                        })
                        .collect();
                    if existing.len() == 1 {
                        let quote = existing[0];
                        if market
                            .quote_subjects
                            .get(&quote.quote_id)
                            .is_some_and(|owner| owner == subject)
                            && !market.consumed_quotes.contains(&quote.quote_id)
                            && quote.expires_at > Utc::now()
                            && quote_matches_request(quote, request)
                        {
                            return Ok(quote.clone());
                        }
                    }
                    let leased = market.leases.values().any(|(_, lease)| {
                        lease
                            .repro
                            .as_ref()
                            .is_some_and(|repro| repro.token_hash == capability.token_hash)
                    });
                    if market.repro_token_hashes.contains(&capability.token_hash)
                        || !existing.is_empty()
                        || leased
                    {
                        return Err(StoreError::ReproTokenAlreadyUsed);
                    }
                }
                market
                    .open_quotes
                    .retain(|_, quote| quote.expires_at > Utc::now() - Duration::hours(24));
                // A renter asking for a new quote is no longer holding the old
                // one. The quote stays honourable for anyone who already
                // funded it on chain; it just stops reserving the node.
                let superseded: Vec<Uuid> = market
                    .quote_subjects
                    .iter()
                    .filter(|(_, owner)| owner.as_str() == subject)
                    .map(|(quote_id, _)| *quote_id)
                    .collect();
                let released_at = Utc::now();
                for quote_id in superseded {
                    if let Some(quote) = market.open_quotes.get_mut(&quote_id) {
                        quote.expires_at = released_at;
                    }
                }
                let active_quote_count = market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        quote.expires_at > Utc::now()
                            && !market.consumed_quotes.contains(&quote.quote_id)
                    })
                    .count();
                let unsettled = market
                    .leases
                    .values()
                    .filter(|(_, lease)| occupies_node_for_escrow(lease, escrow_address))
                    .count();
                if active_quote_count + unsettled >= MAX_NETWORK_LEASES {
                    return Err(StoreError::NetworkCapacity);
                }
                let mut reserved: BTreeSet<_> = market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        holds_node(quote) && !market.consumed_quotes.contains(&quote.quote_id)
                    })
                    .map(|quote| quote.node_id.clone())
                    .collect();
                reserved.extend(
                    market
                        .leases
                        .values()
                        .filter(|(_, lease)| occupies_node_for_escrow(lease, escrow_address))
                        .map(|(_, lease)| lease.node_id.clone()),
                );
                reserved.extend(nodes_holding_commands(&market));
                let now = Utc::now();
                let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                let offers = market
                    .offers
                    .values()
                    .filter(|offer| !market.suspended_nodes.contains(&offer.node_id))
                    .cloned()
                    .map(|mut offer| {
                        let tunneled = market
                            .tunnels
                            .get(&offer.node_id)
                            .is_some_and(|observed_at| *observed_at >= cutoff);
                        offer.online = tunneled;
                        // The stored class is the floor enrolment wrote and
                        // nothing ever rewrites it. Deriving it here is what
                        // stops the matcher stamping every lease `Open`.
                        offer.trust_class = class_for_verdict(
                            &offer.node_id,
                            tunneled,
                            fresh_posture(&market, &offer.node_id, cutoff),
                            market.verdicts.get(&offer.node_id),
                            now,
                        );
                        offer.command_channel = polls_command_channel(&market, &offer.node_id, now);
                        offer.managed_batch = false;
                        offer
                    })
                    .collect::<Vec<_>>();
                // The matcher reads offers directly, so the staker pool has to
                // be marked here too: this is where the gate actually runs.
                let offers = mark_staker_capacity(offers);
                let quote =
                    quote_for_offers(request, offers.iter(), &reserved, staked_whole_tokens)?;
                if let Some(capability) = quote.repro.as_ref() {
                    market
                        .repro_token_hashes
                        .insert(capability.token_hash.clone());
                }
                market
                    .quote_subjects
                    .insert(quote.quote_id, subject.to_owned());
                market.open_quotes.insert(quote.quote_id, quote.clone());
                Ok(quote)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                query("SELECT pg_advisory_xact_lock($1)")
                    .bind(SCHEDULER_LOCK_KEY)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                if let Some(capability) = request.repro.as_ref() {
                    let existing = query_as::<_, (SqlJson<LeaseQuote>, String, bool, bool)>(
                        "SELECT document, subject, consumed_at IS NOT NULL, expires_at > NOW() \
                         FROM lease_quotes \
                         WHERE document #>> '{repro,token_hash}' = $1 \
                         ORDER BY created_at LIMIT 2",
                    )
                    .bind(&capability.token_hash)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    if let [(SqlJson(quote), owner, false, true)] = existing.as_slice()
                        && owner == subject
                        && quote_matches_request(quote, request)
                    {
                        let quote = quote.clone();
                        transaction.commit().await.map_err(StoreError::Storage)?;
                        return Ok(quote);
                    }
                    if !existing.is_empty() {
                        return Err(StoreError::ReproTokenAlreadyUsed);
                    }
                    let claimed = query(
                        "INSERT INTO repro_token_claims (token_hash) VALUES ($1) \
                         ON CONFLICT (token_hash) DO NOTHING",
                    )
                    .bind(&capability.token_hash)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    if claimed.rows_affected() != 1 {
                        return Err(StoreError::ReproTokenAlreadyUsed);
                    }
                }
                query(
                    "DELETE FROM lease_quotes \
                     WHERE consumed_at IS NULL AND expires_at <= NOW() - INTERVAL '24 hours'",
                )
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                query(
                    "UPDATE lease_quotes SET expires_at = NOW() \
                     WHERE subject = $1 AND consumed_at IS NULL AND expires_at > NOW()",
                )
                .bind(subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                // Only the escrow that can still settle a lease consumes this
                // chain cap. The reservation below keeps provider machines held
                // globally until their own cleanup says they were destroyed.
                let quote_count: i64 = query_scalar(
                    "SELECT \
                         (SELECT COUNT(*) FROM lease_quotes \
                          WHERE consumed_at IS NULL AND expires_at > NOW()) + \
                         (SELECT COUNT(*) FROM leases \
                          WHERE escrow_address = $1 \
                            AND state NOT IN ('finalized', 'refunded'))",
                )
                .bind(escrow_address)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if quote_count >= MAX_NETWORK_LEASES as i64 {
                    return Err(StoreError::NetworkCapacity);
                }
                let reserved: BTreeSet<String> = query_scalar(
                    "SELECT node_id FROM lease_quotes \
                     WHERE consumed_at IS NULL AND expires_at > NOW() \
                       AND created_at > NOW() - make_interval(secs => $1) \
                     UNION SELECT document->>'node_id' FROM leases \
                     WHERE escrow_address = $2 \
                       AND state NOT IN ('finalized', 'refunded') \
                     UNION SELECT l.document->>'node_id' FROM leases l \
                     JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
                     WHERE ci.status <> 'destroyed' \
                     UNION SELECT c.node_id FROM node_commands c \
                     WHERE c.status IN ('queued', 'leased', 'ready', 'running')",
                )
                .bind(QUOTE_HOLD_SECONDS as f64)
                .bind(escrow_address)
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .into_iter()
                .collect();
                let documents = query_scalar::<_, SqlJson<NodeOffer>>(
                    "SELECT o.document FROM node_offers o \
                     WHERE NOT EXISTS ( \
                         SELECT 1 FROM node_controls c \
                         WHERE c.node_id = o.node_id AND c.suspended \
                     ) \
                     FOR UPDATE",
                )
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let now = Utc::now();
                let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                // Broker capacity is reachable without a tunnel, so being
                // online and being tunneled are different questions and only
                // the second one can carry a class above `Open`.
                let tunneled: BTreeSet<String> =
                    query_scalar("SELECT node_id FROM node_tunnels WHERE observed_at >= $1")
                        .bind(cutoff)
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(StoreError::Storage)?
                        .into_iter()
                        .collect();
                let managed_batch: BTreeSet<String> = query_scalar(
                    "SELECT node_id FROM cloud_capacity \
                     WHERE provider = 'vast' AND available AND observed_at >= $1 \
                       AND EXISTS ( \
                           SELECT 1 FROM cloud_provider_state ps \
                           WHERE ps.provider = 'vast' AND ps.state = 'healthy' \
                             AND ps.observed_at >= $1 \
                       )",
                )
                .bind(cutoff)
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .into_iter()
                .collect();
                let online: BTreeSet<String> = managed_batch
                    .iter()
                    .cloned()
                    .chain(tunneled.iter().cloned())
                    .collect();
                // Every poll and every report a node makes is signed by its
                // device key and lands here, so a live record is the node
                // saying it is still ready to be handed a command.
                let polling: BTreeSet<String> = query_scalar(
                    "SELECT DISTINCT node_id FROM node_command_requests WHERE expires_at > NOW()",
                )
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .into_iter()
                .collect();
                let evidence: BTreeMap<String, (Option<NodePosture>, Option<AttestationVerdict>)> =
                    query_as::<
                        _,
                        (
                            String,
                            Option<SqlJson<NodePosture>>,
                            Option<SqlJson<AttestationVerdict>>,
                        ),
                    >(
                        "SELECT o.node_id, \
                            (SELECT nt.document->'posture' FROM node_telemetry nt \
                             WHERE nt.node_id = o.node_id AND nt.observed_at >= $1), \
                            (SELECT v.document FROM node_attestation_verdicts v \
                             WHERE v.node_id = o.node_id AND v.expires_at > now()) \
                         FROM node_offers o",
                    )
                    .bind(cutoff)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?
                    .into_iter()
                    .map(|(node_id, posture, verdict)| {
                        (
                            node_id,
                            (
                                posture.map(|SqlJson(posture)| posture),
                                verdict.map(|SqlJson(verdict)| verdict),
                            ),
                        )
                    })
                    .collect();
                let offers: Vec<_> = documents
                    .into_iter()
                    .map(|SqlJson(mut offer)| {
                        offer.online = online.contains(&offer.node_id);
                        // The stored class is the floor enrolment wrote and
                        // nothing ever rewrites it. Deriving it here is what
                        // stops the matcher stamping every lease `Open`.
                        let (posture, verdict) = evidence
                            .get(&offer.node_id)
                            .map_or((None, None), |(posture, verdict)| {
                                (posture.as_ref(), verdict.as_ref())
                            });
                        offer.trust_class = class_for_verdict(
                            &offer.node_id,
                            tunneled.contains(&offer.node_id),
                            posture,
                            verdict,
                            now,
                        );
                        offer.command_channel = polling.contains(&offer.node_id);
                        offer.managed_batch = managed_batch.contains(&offer.node_id);
                        offer
                    })
                    .collect();
                let offers = mark_staker_capacity(offers);
                let quote =
                    quote_for_offers(request, offers.iter(), &reserved, staked_whole_tokens)?;
                query(
                    "INSERT INTO lease_quotes \
                         (quote_id, node_id, document, expires_at, subject) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(quote.quote_id)
                .bind(&quote.node_id)
                .bind(SqlJson(quote.clone()))
                .bind(quote.expires_at)
                .bind(subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(quote)
            }
        }
    }

    async fn quote_for_subject(
        &self,
        subject: &str,
        quote_id: Uuid,
    ) -> Result<LeaseQuote, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let quote = market
                    .open_quotes
                    .get(&quote_id)
                    .filter(|quote| quote.expires_at > Utc::now() - Duration::hours(24))
                    .ok_or(StoreError::QuoteNotFound)?;
                if market.quote_subjects.get(&quote_id).map(String::as_str) != Some(subject) {
                    return Err(StoreError::QuoteNotFound);
                }
                Ok(quote.clone())
            }
            Self::Postgres(pool) => query_scalar::<_, SqlJson<LeaseQuote>>(
                "SELECT document FROM lease_quotes \
                 WHERE quote_id = $1 AND subject = $2 \
                   AND expires_at > NOW() - INTERVAL '24 hours'",
            )
            .bind(quote_id)
            .bind(subject)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            .map(|SqlJson(quote)| quote)
            .ok_or(StoreError::QuoteNotFound),
        }
    }

    async fn confirm_funding(
        &self,
        confirmation: FundingConfirmation<'_>,
    ) -> Result<LeaseRecord, StoreError> {
        let FundingConfirmation {
            subject,
            quote,
            transaction_hash,
            funding,
            ssh_authorized_key,
            jupyter_token,
            encrypted_jupyter_token,
        } = confirmation;
        let now = Utc::now();
        // `lease_id` is allocated below, per store, from a space that no
        // superseded escrow ever used. What the chain issued is kept separately.
        let mut lease = LeaseRecord {
            lease_id: 0,
            chain_lease_id: funding.lease_id,
            escrow_address: funding.escrow_address.to_ascii_lowercase(),
            quote_id: quote.quote_id,
            node_id: quote.node_id.clone(),
            renter_wallet: funding.renter_wallet.to_ascii_lowercase(),
            image: quote.image.clone(),
            duration_seconds: quote.duration_seconds,
            rate_per_second: quote.rate_per_second,
            maximum_escrow: quote.maximum_escrow,
            trust_class: quote.trust_class,
            funding_transaction_hash: transaction_hash.to_ascii_lowercase(),
            state: LeaseState::Funded,
            command: quote.command.clone(),
            repro: quote.repro.clone(),
            created_at: now,
            updated_at: now,
        };
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                if market
                    .quote_subjects
                    .get(&quote.quote_id)
                    .map(String::as_str)
                    != Some(subject)
                    || market
                        .open_quotes
                        .get(&quote.quote_id)
                        .is_none_or(|current| current.expires_at <= now - Duration::hours(24))
                {
                    return Err(StoreError::QuoteUnavailable);
                }
                // Identity is the escrow plus the id it issued. Matching on the
                // id alone treats a fresh escrow's lease 3 as a replay of a
                // superseded escrow's lease 3 and rejects a renter who has
                // already paid.
                // Suspension is the one control meant to stop a node at once,
                // so it is re-read at confirm rather than trusted from quote
                // time up to a day earlier.
                if market.suspended_nodes.contains(&quote.node_id) {
                    return Err(StoreError::NodeSuspended);
                }
                // A quote is confirmable for a day, a verdict lives a day and a
                // tunnel row ninety seconds, so a node can have lost everything
                // that earned its class since the quote was cut. The renter
                // funded against a stated class, so this refuses rather than
                // quietly handing back a weaker lease.
                let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                if class_for_verdict(
                    &quote.node_id,
                    market
                        .tunnels
                        .get(&quote.node_id)
                        .is_some_and(|observed_at| *observed_at >= cutoff),
                    fresh_posture(&market, &quote.node_id, cutoff),
                    market.verdicts.get(&quote.node_id),
                    now,
                ) < quote.trust_class
                {
                    return Err(StoreError::TrustClassExpired);
                }
                if let Some((owner, current)) = market.leases.values().find(|(_, current)| {
                    current.escrow_address == lease.escrow_address
                        && current.chain_lease_id == lease.chain_lease_id
                }) {
                    return if owner == subject
                        && current.funding_transaction_hash == lease.funding_transaction_hash
                    {
                        Ok(current.clone())
                    } else {
                        Err(StoreError::FundingMismatch)
                    };
                }
                if market.leases.values().any(|(_, current)| {
                    current.funding_transaction_hash == lease.funding_transaction_hash
                }) {
                    return Err(StoreError::FundingMismatch);
                }
                if let Some(capability) = quote.repro.as_ref()
                    && (capability.executor != ReproExecutor::Node
                        || !polls_command_channel(&market, &quote.node_id, now))
                {
                    return Err(StoreError::ReproExecutorUnavailable);
                }
                lease.lease_id = market
                    .leases
                    .keys()
                    .copied()
                    .max()
                    .unwrap_or(INTERNAL_LEASE_ID_FLOOR)
                    .saturating_add(1)
                    .max(INTERNAL_LEASE_ID_FLOOR);
                // Nothing has booted for this renter yet, so there is no guest
                // verdict to lift the class. Writing it through the same
                // function that will read one later is what keeps the record
                // inside what the network can substantiate without anybody
                // having to remember the ceiling.
                lease.trust_class = class_for_lease(
                    lease.lease_id,
                    &lease.node_id,
                    quote.trust_class,
                    None,
                    None,
                    None,
                    now,
                );
                if market.leases.values().any(|(_, current)| {
                    current.node_id == lease.node_id
                        && occupies_node_for_escrow(current, &lease.escrow_address)
                }) {
                    return Err(StoreError::FundingCapacityUnavailable);
                }
                market.consumed_quotes.insert(quote.quote_id);
                market
                    .leases
                    .insert(lease.lease_id, (subject.to_owned(), lease.clone()));
                market
                    .lease_secrets
                    .insert(lease.lease_id, encrypted_jupyter_token);
                market
                    .lifecycle
                    .insert(lease.lease_id, MemoryLifecycle::default());
                let command = launch_command(&lease, ssh_authorized_key, jupyter_token)?;
                market.commands.insert(
                    command.command_id,
                    MemoryCommand {
                        command,
                        status: "queued",
                        lease_until: None,
                        authorization_request_id: None,
                        result: None,
                        verified_report: None,
                        updated_at: now,
                    },
                );
                Ok(lease)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                query("SELECT pg_advisory_xact_lock($1)")
                    .bind(SCHEDULER_LOCK_KEY)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                // A quote stays confirmable for a day so a renter who already
                // funded is honoured, but every node-side check ran once at
                // quote time. Suspending a node for abuse therefore did not
                // stop it taking new work until the last quote naming it
                // expired. Suspension is the one control that exists to stop a
                // node immediately, so it is re-read here.
                let suspended = query_scalar::<_, bool>(
                    "SELECT COALESCE((SELECT suspended FROM node_controls \
                                      WHERE node_id = $1), FALSE)",
                )
                .bind(&quote.node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if suspended {
                    return Err(StoreError::NodeSuspended);
                }
                // Suspension is not the only thing that can lapse between quote
                // and funding. A verdict lives a day and a tunnel row ninety
                // seconds, so the class is recomputed here too. The renter
                // funded against a stated class, so this refuses rather than
                // quietly handing back a weaker lease.
                let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                let (tunneled, posture, verdict) = query_as::<
                    _,
                    (
                        bool,
                        Option<SqlJson<NodePosture>>,
                        Option<SqlJson<AttestationVerdict>>,
                    ),
                >(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM node_tunnels t \
                         WHERE t.node_id = $1 AND t.observed_at >= $2 \
                     ), \
                     (SELECT nt.document->'posture' FROM node_telemetry nt \
                      WHERE nt.node_id = $1 AND nt.observed_at >= $2), \
                     (SELECT v.document FROM node_attestation_verdicts v \
                      WHERE v.node_id = $1 AND v.expires_at > now())",
                )
                .bind(&quote.node_id)
                .bind(cutoff)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if class_for_verdict(
                    &quote.node_id,
                    tunneled,
                    posture.as_ref().map(|SqlJson(posture)| posture),
                    verdict.as_ref().map(|SqlJson(verdict)| verdict),
                    now,
                ) < quote.trust_class
                {
                    return Err(StoreError::TrustClassExpired);
                }
                // Identity is the escrow plus the id it issued. Matching on the
                // id alone treats a fresh escrow's lease 3 as a replay of a
                // superseded escrow's lease 3 and rejects a renter who has
                // already paid.
                if let Some(SqlJson(current)) = query_scalar::<_, SqlJson<LeaseRecord>>(
                    "SELECT document FROM leases \
                     WHERE (escrow_address = $1 AND chain_lease_id = $2) \
                        OR funding_transaction_hash = $3",
                )
                .bind(&lease.escrow_address)
                .bind(lease.chain_lease_id as i64)
                .bind(&lease.funding_transaction_hash)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                {
                    return if current.quote_id == quote.quote_id
                        && current.funding_transaction_hash == lease.funding_transaction_hash
                    {
                        Ok(current)
                    } else {
                        Err(StoreError::FundingMismatch)
                    };
                }
                lease.lease_id = query_scalar::<_, i64>("SELECT nextval('leases_internal_id_seq')")
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)? as u64;
                // Nothing has booted for this renter yet, so there is no guest
                // verdict to lift the class. Writing it through the same
                // function that will read one later is what keeps the record
                // inside what the network can substantiate without anybody
                // having to remember the ceiling.
                lease.trust_class = class_for_lease(
                    lease.lease_id,
                    &lease.node_id,
                    quote.trust_class,
                    None,
                    None,
                    None,
                    now,
                );
                // Keep the same logical/current and physical/global split used
                // when the quote was cut; either side can change before funding.
                let node_busy = query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM leases \
                         WHERE document->>'node_id' = $1 \
                           AND escrow_address = $2 \
                           AND state NOT IN ('finalized', 'refunded') \
                         UNION \
                         SELECT 1 FROM leases l \
                         JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
                         WHERE l.document->>'node_id' = $1 \
                           AND ci.status <> 'destroyed' \
                     )",
                )
                .bind(&lease.node_id)
                .bind(&lease.escrow_address)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if node_busy {
                    return Err(StoreError::FundingCapacityUnavailable);
                }
                let consumed = query(
                    "UPDATE lease_quotes SET consumed_at = NOW() \
                     WHERE quote_id = $1 AND subject = $2 \
                       AND consumed_at IS NULL \
                       AND expires_at > NOW() - INTERVAL '24 hours'",
                )
                .bind(quote.quote_id)
                .bind(subject)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if consumed.rows_affected() != 1 {
                    return Err(StoreError::QuoteUnavailable);
                }
                query(
                    "INSERT INTO account_wallets (subject, wallet_address, verified_at) \
                     VALUES ($1, $2, NOW()) \
                     ON CONFLICT (subject, wallet_address) DO UPDATE SET verified_at = NOW()",
                )
                .bind(subject)
                .bind(lease.renter_wallet.to_ascii_lowercase())
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let (managed_available, node_available) = query_as::<_, (bool, bool)>(
                    "SELECT \
                         EXISTS ( \
                             SELECT 1 FROM cloud_capacity \
                             WHERE node_id = $1 AND provider = 'vast' \
                               AND available AND observed_at >= $2 \
                               AND EXISTS ( \
                                   SELECT 1 FROM cloud_provider_state ps \
                                   WHERE ps.provider = 'vast' AND ps.state = 'healthy' \
                                     AND ps.observed_at >= $2 \
                               ) \
                         ), \
                         EXISTS ( \
                             SELECT 1 FROM node_command_requests \
                             WHERE node_id = $1 AND expires_at > NOW() \
                         )",
                )
                .bind(&lease.node_id)
                .bind(cutoff)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let cloud_backed =
                    confirmed_cloud_execution(quote, managed_available, node_available)?;
                if cloud_backed {
                    let reserved = query(
                        "UPDATE cloud_capacity SET available = FALSE \
                         WHERE node_id = $1 AND provider = 'vast' \
                           AND available AND observed_at >= $2",
                    )
                    .bind(&lease.node_id)
                    .bind(cutoff)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    if reserved.rows_affected() != 1 {
                        return Err(StoreError::FundingCapacityUnavailable);
                    }
                    lease.state = LeaseState::Provisioning;
                    lease.updated_at = Utc::now();
                }
                query(
                    "INSERT INTO leases \
                         (lease_id, escrow_address, chain_lease_id, quote_id, subject, \
                          renter_wallet, funding_transaction_hash, document, state) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind(lease.lease_id as i64)
                .bind(&lease.escrow_address)
                .bind(lease.chain_lease_id as i64)
                .bind(quote.quote_id)
                .bind(subject)
                .bind(&lease.renter_wallet)
                .bind(&lease.funding_transaction_hash)
                .bind(SqlJson(lease.clone()))
                .bind(lease_state_name(&lease.state))
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                query("INSERT INTO lease_secrets (lease_id, jupyter_token) VALUES ($1, $2)")
                    .bind(lease.lease_id as i64)
                    .bind(SqlJson(encrypted_jupyter_token))
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                query(
                    "INSERT INTO lease_lifecycle (lease_id, connection_id) \
                     VALUES ($1, (SELECT connection_id FROM node_tunnels WHERE node_id = $2)) \
                     ON CONFLICT (lease_id) DO NOTHING",
                )
                .bind(lease.lease_id as i64)
                .bind(&lease.node_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if cloud_backed {
                    let managed_repro = lease.repro.is_some();
                    if lease.command.is_some() != managed_repro {
                        return Err(StoreError::InvalidStoredState(
                            "cloud batch leases require a repro capability".to_owned(),
                        ));
                    }
                    let cloud_ssh_key = if managed_repro {
                        None
                    } else {
                        Some(ssh_authorized_key.ok_or(StoreError::AccessCredentialsMissing)?)
                    };
                    query(
                        "INSERT INTO cloud_instances (lease_id, ssh_authorized_key) \
                         VALUES ($1, $2)",
                    )
                    .bind(lease.lease_id as i64)
                    .bind(cloud_ssh_key)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    if managed_repro {
                        let command = launch_command(&lease, None, jupyter_token)?;
                        query(
                            "INSERT INTO managed_repro_jobs (command_id, lease_id, command) \
                             VALUES ($1, $2, $3)",
                        )
                        .bind(command.command_id)
                        .bind(lease.lease_id as i64)
                        .bind(SqlJson(command))
                        .execute(&mut *transaction)
                        .await
                        .map_err(StoreError::Storage)?;
                    }
                    query(
                        "INSERT INTO lifecycle_outbox \
                             (action_id, lease_id, kind, available_at) \
                         VALUES ($1, $2, 'start_access', NOW()) \
                         ON CONFLICT (lease_id, kind) DO NOTHING",
                    )
                    .bind(Uuid::now_v7())
                    .bind(lease.lease_id as i64)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                } else {
                    let command = launch_command(&lease, ssh_authorized_key, jupyter_token)?;
                    query(
                        "INSERT INTO node_commands \
                             (command_id, node_id, lease_id, document, status) \
                         VALUES ($1, $2, $3, $4, 'queued')",
                    )
                    .bind(command.command_id)
                    .bind(&command.node_id)
                    .bind(command.lease_id as i64)
                    .bind(SqlJson(command.clone()))
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                }
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(lease)
            }
        }
    }

    async fn list_leases(&self, subject: &str) -> Result<Vec<LeaseRecord>, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut leases = market
                    .read()
                    .await
                    .leases
                    .values()
                    .filter(|(owner, _)| owner == subject)
                    .map(|(_, lease)| lease.clone())
                    .collect::<Vec<_>>();
                leases.sort_by_key(|lease| Reverse(lease.created_at));
                Ok(leases)
            }
            Self::Postgres(pool) => query_scalar::<_, SqlJson<LeaseRecord>>(
                "SELECT document FROM leases WHERE subject = $1 ORDER BY created_at DESC LIMIT 200",
            )
            .bind(subject)
            .fetch_all(pool)
            .await
            .map(|leases| leases.into_iter().map(|SqlJson(lease)| lease).collect())
            .map_err(StoreError::Storage),
        }
    }

    async fn list_vault_items(&self, subject: &str) -> Result<Vec<VaultItem>, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut items = market
                    .read()
                    .await
                    .vault_items
                    .values()
                    .filter(|(owner, _)| owner == subject)
                    .map(|(_, item)| item.clone())
                    .collect::<Vec<_>>();
                items.sort_by_key(|item| Reverse(item.updated_at));
                Ok(items)
            }
            Self::Postgres(pool) => query_as::<_, VaultRow>(
                "SELECT item_id, version, wrapped_key, nonce, ciphertext, min_trust_class, \
                        label, created_at, updated_at \
                 FROM vault_items WHERE subject = $1 ORDER BY updated_at DESC",
            )
            .bind(subject)
            .fetch_all(pool)
            .await
            .map_err(StoreError::Storage)?
            .into_iter()
            .map(vault_item_from_row)
            .collect(),
        }
    }

    async fn vault_item(
        &self,
        subject: &str,
        item_id: Uuid,
    ) -> Result<Option<VaultItem>, StoreError> {
        match self {
            Self::Memory(market) => Ok(market
                .read()
                .await
                .vault_items
                .get(&item_id)
                .filter(|(owner, _)| owner == subject)
                .map(|(_, item)| item.clone())),
            Self::Postgres(pool) => query_as::<_, VaultRow>(
                "SELECT item_id, version, wrapped_key, nonce, ciphertext, min_trust_class, \
                        label, created_at, updated_at \
                 FROM vault_items WHERE subject = $1 AND item_id = $2",
            )
            .bind(subject)
            .bind(item_id)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            .map(vault_item_from_row)
            .transpose(),
        }
    }

    /// Creates when `previous_version` is absent, otherwise replaces exactly
    /// that version. The compare-and-set is what keeps two agents writing the
    /// same slot from silently dropping one of the writes.
    async fn write_vault_item(
        &self,
        subject: &str,
        item_id: Uuid,
        write: VaultWrite,
    ) -> Result<VaultItem, StoreError> {
        let now = Utc::now();
        let version = write.previous_version.map_or(1, |previous| previous + 1);
        let item = VaultItem {
            item_id,
            version,
            envelope: write.envelope,
            min_trust_class: write.min_trust_class,
            label: write.label,
            created_at: now,
            updated_at: now,
        };
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                match (market.vault_items.get(&item_id), write.previous_version) {
                    (Some((owner, _)), _) if owner != subject => {
                        return Err(StoreError::VaultItemNotFound);
                    }
                    (Some((_, existing)), Some(previous)) if existing.version != previous => {
                        return Err(StoreError::VaultVersionConflict);
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(StoreError::VaultVersionConflict);
                    }
                    (None, None)
                        if market
                            .vault_items
                            .values()
                            .filter(|(owner, _)| owner == subject)
                            .count()
                            >= MAX_VAULT_ITEMS_PER_ACCOUNT =>
                    {
                        return Err(StoreError::VaultFull);
                    }
                    _ => {}
                }
                let created_at = market
                    .vault_items
                    .get(&item_id)
                    .map_or(now, |(_, existing)| existing.created_at);
                let item = VaultItem { created_at, ..item };
                market
                    .vault_items
                    .insert(item_id, (subject.to_owned(), item.clone()));
                Ok(item)
            }
            Self::Postgres(pool) => {
                let Some(previous) = write.previous_version else {
                    let inserted = query_as::<_, VaultRow>(
                        "INSERT INTO vault_items \
                             (item_id, subject, version, wrapped_key, nonce, ciphertext, \
                              min_trust_class, label) \
                         SELECT $1, $2, 1, $3, $4, $5, $6, $7 \
                         WHERE (SELECT COUNT(*) FROM vault_items WHERE subject = $2) < $8 \
                         ON CONFLICT (item_id) DO NOTHING \
                         RETURNING item_id, version, wrapped_key, nonce, ciphertext, \
                                   min_trust_class, label, created_at, updated_at",
                    )
                    .bind(item_id)
                    .bind(subject)
                    .bind(&item.envelope.wrapped_key)
                    .bind(&item.envelope.nonce)
                    .bind(&item.envelope.ciphertext)
                    .bind(item.min_trust_class.label())
                    .bind(&item.label)
                    .bind(MAX_VAULT_ITEMS_PER_ACCOUNT as i64)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                    // No row means either the slot was taken or the account is
                    // at its limit. Distinguish them so the caller can tell a
                    // retryable conflict from a hard stop.
                    return match inserted {
                        Some(row) => vault_item_from_row(row),
                        None if self.vault_item(subject, item_id).await?.is_some()
                            || self.vault_item_exists(item_id).await? =>
                        {
                            Err(StoreError::VaultVersionConflict)
                        }
                        None => Err(StoreError::VaultFull),
                    };
                };
                query_as::<_, VaultRow>(
                    "UPDATE vault_items \
                     SET version = $3, wrapped_key = $4, nonce = $5, ciphertext = $6, \
                         min_trust_class = $7, label = $8, updated_at = NOW() \
                     WHERE item_id = $1 AND subject = $2 AND version = $9 \
                     RETURNING item_id, version, wrapped_key, nonce, ciphertext, \
                               min_trust_class, label, created_at, updated_at",
                )
                .bind(item_id)
                .bind(subject)
                .bind(version as i32)
                .bind(&item.envelope.wrapped_key)
                .bind(&item.envelope.nonce)
                .bind(&item.envelope.ciphertext)
                .bind(item.min_trust_class.label())
                .bind(&item.label)
                .bind(previous as i32)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?
                .ok_or(StoreError::VaultVersionConflict)
                .and_then(vault_item_from_row)
            }
        }
    }

    async fn vault_item_exists(&self, item_id: Uuid) -> Result<bool, StoreError> {
        match self {
            Self::Memory(market) => Ok(market.read().await.vault_items.contains_key(&item_id)),
            Self::Postgres(pool) => {
                query_scalar::<_, i64>("SELECT COUNT(*) FROM vault_items WHERE item_id = $1")
                    .bind(item_id)
                    .fetch_one(pool)
                    .await
                    .map(|count| count > 0)
                    .map_err(StoreError::Storage)
            }
        }
    }

    async fn delete_vault_item(&self, subject: &str, item_id: Uuid) -> Result<(), StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                match market.vault_items.get(&item_id) {
                    Some((owner, _)) if owner == subject => {
                        market.vault_items.remove(&item_id);
                        Ok(())
                    }
                    _ => Err(StoreError::VaultItemNotFound),
                }
            }
            Self::Postgres(pool) => {
                let deleted = query("DELETE FROM vault_items WHERE item_id = $1 AND subject = $2")
                    .bind(item_id)
                    .bind(subject)
                    .execute(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                if deleted.rows_affected() == 0 {
                    return Err(StoreError::VaultItemNotFound);
                }
                Ok(())
            }
        }
    }

    /// Authorizes an item to be carried into a running lease, and refuses when
    /// the lease's trust class sits below the floor the renter sealed into the
    /// item. The refusal is the point: it is what stops an autonomous agent
    /// from posting its owner's card to a host that can read it.
    async fn release_vault_item(
        &self,
        subject: &str,
        item_id: Uuid,
        lease_id: u64,
    ) -> Result<VaultRelease, StoreError> {
        let item = self
            .vault_item(subject, item_id)
            .await?
            .ok_or(StoreError::VaultItemNotFound)?;
        let lease_trust_class = self
            .active_lease_trust_class(subject, lease_id)
            .await?
            .ok_or(StoreError::VaultLeaseUnavailable)?;
        if !vault_release_permitted(item.min_trust_class, lease_trust_class) {
            return Err(StoreError::VaultTrustFloorUnmet {
                floor: item.min_trust_class.label(),
                lease: lease_trust_class.label(),
            });
        }
        let release = VaultRelease {
            item_id,
            lease_id,
            item_version: item.version,
            lease_trust_class,
            released_at: Utc::now(),
        };
        match self {
            Self::Memory(market) => market
                .write()
                .await
                .vault_releases
                .push((subject.to_owned(), release.clone())),
            Self::Postgres(pool) => {
                query(
                    "INSERT INTO vault_releases \
                         (subject, item_id, lease_id, item_version, lease_trust_class, released_at) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(subject)
                .bind(item_id)
                .bind(lease_id as i64)
                .bind(release.item_version as i32)
                .bind(lease_trust_class.label())
                .bind(release.released_at)
                .execute(pool)
                .await
                .map_err(StoreError::Storage)?;
            }
        }
        Ok(release)
    }

    /// The class a lease can be served at right now, recomputed from the node's
    /// live standing rather than read from the cached record. This gates vault
    /// release and workspace restore, so a node whose tunnel has lapsed since
    /// the class was recorded must drop below the floor here even though nothing
    /// rewrote the cached class: the same live-standing rule `get_lease_access`
    /// applies, on the gates that hand a renter their secrets.
    async fn active_lease_trust_class(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<TrustClass>, StoreError> {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let Some((owner, lease)) = market.leases.get(&lease_id) else {
                    return Ok(None);
                };
                if owner != subject || lease.state != LeaseState::Active {
                    return Ok(None);
                }
                let node_class = class_for_verdict(
                    &lease.node_id,
                    market
                        .tunnels
                        .get(&lease.node_id)
                        .is_some_and(|observed_at| *observed_at >= cutoff),
                    fresh_posture(&market, &lease.node_id, cutoff),
                    market.verdicts.get(&lease.node_id),
                    now,
                );
                Ok(Some(class_for_lease(
                    lease_id,
                    &lease.node_id,
                    node_class,
                    market.lease_verdicts.get(&lease_id),
                    market.lease_tdx_guest_verdicts.get(&lease_id),
                    market.lease_gpu_cc_verdicts.get(&lease_id),
                    now,
                )))
            }
            Self::Postgres(pool) => {
                let standing = query_as::<
                    _,
                    (
                        String,
                        Option<SqlJson<LeaseAttestationVerdict>>,
                        Option<SqlJson<LeaseTdxGuestVerdict>>,
                        Option<SqlJson<LeaseGpuCcVerdict>>,
                        bool,
                        Option<SqlJson<NodePosture>>,
                        Option<SqlJson<AttestationVerdict>>,
                    ),
                >(
                    "SELECT l.document->>'node_id', \
                            (SELECT v.document FROM lease_attestation_verdicts v \
                             WHERE v.lease_id = l.lease_id), \
                            (SELECT tv.document FROM lease_tdx_guest_verdicts tv \
                             WHERE tv.lease_id = l.lease_id), \
                            (SELECT gv.document FROM lease_gpu_cc_verdicts gv \
                             WHERE gv.lease_id = l.lease_id), \
                            EXISTS ( \
                                SELECT 1 FROM node_tunnels t \
                                WHERE t.node_id = l.document->>'node_id' \
                                  AND t.observed_at >= $3 \
                            ), \
                            (SELECT nt.document->'posture' FROM node_telemetry nt \
                             WHERE nt.node_id = l.document->>'node_id' \
                               AND nt.observed_at >= $3), \
                            (SELECT nv.document FROM node_attestation_verdicts nv \
                             WHERE nv.node_id = l.document->>'node_id' \
                               AND nv.expires_at > now()) \
                     FROM leases l \
                     WHERE l.lease_id = $1 AND l.subject = $2 AND l.state = 'active'",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .bind(cutoff)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                let Some((node_id, snp, tdx, gpu, tunneled, posture, node_verdict)) = standing
                else {
                    return Ok(None);
                };
                let node_class = class_for_verdict(
                    &node_id,
                    tunneled,
                    posture.as_ref().map(|SqlJson(posture)| posture),
                    node_verdict.as_ref().map(|SqlJson(verdict)| verdict),
                    now,
                );
                Ok(Some(class_for_lease(
                    lease_id,
                    &node_id,
                    node_class,
                    snp.as_ref().map(|SqlJson(verdict)| verdict),
                    tdx.as_ref().map(|SqlJson(verdict)| verdict),
                    gpu.as_ref().map(|SqlJson(verdict)| verdict),
                    now,
                )))
            }
        }
    }

    async fn list_vault_releases(&self, subject: &str) -> Result<Vec<VaultRelease>, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut releases = market
                    .read()
                    .await
                    .vault_releases
                    .iter()
                    .filter(|(owner, _)| owner == subject)
                    .map(|(_, release)| release.clone())
                    .collect::<Vec<_>>();
                releases.sort_by_key(|release| Reverse(release.released_at));
                Ok(releases)
            }
            Self::Postgres(pool) => query_as::<_, (Uuid, i64, i32, String, chrono::DateTime<Utc>)>(
                "SELECT item_id, lease_id, item_version, lease_trust_class, released_at \
                 FROM vault_releases WHERE subject = $1 ORDER BY released_at DESC LIMIT 200",
            )
            .bind(subject)
            .fetch_all(pool)
            .await
            .map_err(StoreError::Storage)?
            .into_iter()
            .map(
                |(item_id, lease_id, item_version, trust_class, released_at)| {
                    Ok(VaultRelease {
                        item_id,
                        lease_id: lease_id as u64,
                        item_version: item_version as u32,
                        lease_trust_class: parse_trust_class(&trust_class)?,
                        released_at,
                    })
                },
            )
            .collect(),
        }
    }

    async fn list_workspaces(&self, subject: &str) -> Result<Vec<Workspace>, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut workspaces = market
                    .read()
                    .await
                    .workspaces
                    .values()
                    .filter(|(owner, _)| owner == subject)
                    .map(|(_, workspace)| workspace.clone())
                    .collect::<Vec<_>>();
                // Matches the Postgres ORDER BY, tiebreak included. Two
                // workspaces created in one transaction share a timestamp
                // exactly, and a divergence here is a test that passes while
                // production returns a different order.
                workspaces.sort_by_key(|workspace| {
                    Reverse((workspace.updated_at, workspace.workspace_id))
                });
                Ok(workspaces)
            }
            Self::Postgres(pool) => query_as::<_, WorkspaceRow>(
                "SELECT workspace_id, name, version, wrapped_key, nonce, ciphertext_digest, \
                        size_bytes, min_trust_class, created_at, updated_at \
                 FROM workspaces WHERE subject = $1 \
                 ORDER BY updated_at DESC, workspace_id DESC",
            )
            .bind(subject)
            .fetch_all(pool)
            .await
            .map_err(StoreError::Storage)?
            .into_iter()
            .map(workspace_from_row)
            .collect(),
        }
    }

    async fn workspace(
        &self,
        subject: &str,
        workspace_id: Uuid,
    ) -> Result<Option<Workspace>, StoreError> {
        match self {
            Self::Memory(market) => Ok(market
                .read()
                .await
                .workspaces
                .get(&workspace_id)
                .filter(|(owner, _)| owner == subject)
                .map(|(_, workspace)| workspace.clone())),
            Self::Postgres(pool) => query_as::<_, WorkspaceRow>(
                "SELECT workspace_id, name, version, wrapped_key, nonce, ciphertext_digest, \
                        size_bytes, min_trust_class, created_at, updated_at \
                 FROM workspaces WHERE subject = $1 AND workspace_id = $2",
            )
            .bind(subject)
            .bind(workspace_id)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            .map(workspace_from_row)
            .transpose(),
        }
    }

    /// The id is minted here rather than accepted from the caller, so nobody
    /// can probe which ids exist by trying to create over one.
    async fn create_workspace(
        &self,
        subject: &str,
        name: &str,
        min_trust_class: TrustClass,
    ) -> Result<Workspace, StoreError> {
        let now = Utc::now();
        let workspace = Workspace {
            workspace_id: Uuid::now_v7(),
            name: name.to_owned(),
            version: 0,
            snapshot: None,
            min_trust_class,
            created_at: now,
            updated_at: now,
        };
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let mut held = 0;
                for (owner, existing) in market.workspaces.values() {
                    if owner != subject {
                        continue;
                    }
                    if existing.name == name {
                        return Err(StoreError::WorkspaceNameTaken);
                    }
                    held += 1;
                }
                if held >= MAX_WORKSPACES_PER_ACCOUNT {
                    return Err(StoreError::WorkspaceFull);
                }
                market.workspaces.insert(
                    workspace.workspace_id,
                    (subject.to_owned(), workspace.clone()),
                );
                Ok(workspace)
            }
            Self::Postgres(pool) => {
                let inserted = query_as::<_, WorkspaceRow>(
                    "INSERT INTO workspaces (workspace_id, subject, name, min_trust_class) \
                     SELECT $1, $2, $3, $4 \
                     WHERE (SELECT COUNT(*) FROM workspaces WHERE subject = $2) < $5 \
                     ON CONFLICT (subject, name) DO NOTHING \
                     RETURNING workspace_id, name, version, wrapped_key, nonce, \
                               ciphertext_digest, size_bytes, min_trust_class, \
                               created_at, updated_at",
                )
                .bind(workspace.workspace_id)
                .bind(subject)
                .bind(name)
                .bind(min_trust_class.label())
                .bind(MAX_WORKSPACES_PER_ACCOUNT as i64)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                // No row means the name is taken or the account is at its
                // limit, and the two want different things from the renter:
                // one is a rename, the other is a delete.
                match inserted {
                    Some(row) => workspace_from_row(row),
                    None if self.workspace_name_taken(subject, name).await? => {
                        Err(StoreError::WorkspaceNameTaken)
                    }
                    None => Err(StoreError::WorkspaceFull),
                }
            }
        }
    }

    /// Scoped to the subject because the uniqueness constraint is, so a name
    /// collision can only ever be with the caller's own workspace and never
    /// discloses that some other account holds it.
    async fn workspace_name_taken(&self, subject: &str, name: &str) -> Result<bool, StoreError> {
        match self {
            Self::Memory(market) => Ok(market
                .read()
                .await
                .workspaces
                .values()
                .any(|(owner, workspace)| owner == subject && workspace.name == name)),
            Self::Postgres(pool) => query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM workspaces WHERE subject = $1 AND name = $2",
            )
            .bind(subject)
            .bind(name)
            .fetch_one(pool)
            .await
            .map(|count| count > 0)
            .map_err(StoreError::Storage),
        }
    }

    /// Returns the removed workspace so the caller can sweep the objects it
    /// was pointing at. Nothing else records which those were.
    async fn delete_workspace(
        &self,
        subject: &str,
        workspace_id: Uuid,
    ) -> Result<Workspace, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                match market.workspaces.get(&workspace_id) {
                    Some((owner, _)) if owner == subject => {}
                    _ => return Err(StoreError::WorkspaceNotFound),
                }
                market
                    .workspaces
                    .remove(&workspace_id)
                    .map(|(_, workspace)| workspace)
                    .ok_or(StoreError::WorkspaceNotFound)
            }
            Self::Postgres(pool) => query_as::<_, WorkspaceRow>(
                "DELETE FROM workspaces WHERE workspace_id = $1 AND subject = $2 \
                 RETURNING workspace_id, name, version, wrapped_key, nonce, ciphertext_digest, \
                           size_bytes, min_trust_class, created_at, updated_at",
            )
            .bind(workspace_id)
            .bind(subject)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            .ok_or(StoreError::WorkspaceNotFound)
            .and_then(workspace_from_row),
        }
    }

    /// Records a snapshot against exactly the version that was presigned, and
    /// refuses anything else. Two machines saving the same workspace both
    /// presign the same next version and race on one object, so the writer
    /// that loses has to find out here rather than at restore time.
    async fn commit_workspace_snapshot(
        &self,
        subject: &str,
        workspace_id: Uuid,
        version: u32,
        snapshot: WorkspaceSnapshot,
    ) -> Result<Workspace, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let Some((owner, workspace)) = market.workspaces.get_mut(&workspace_id) else {
                    return Err(StoreError::WorkspaceNotFound);
                };
                if owner != subject {
                    return Err(StoreError::WorkspaceNotFound);
                }
                if version != workspace.version + 1 {
                    return Err(StoreError::WorkspaceVersionConflict);
                }
                workspace.version = version;
                workspace.snapshot = Some(snapshot);
                workspace.updated_at = Utc::now();
                Ok(workspace.clone())
            }
            Self::Postgres(pool) => {
                let updated = query_as::<_, WorkspaceRow>(
                    "UPDATE workspaces \
                     SET version = $3, wrapped_key = $4, nonce = $5, ciphertext_digest = $6, \
                         size_bytes = $7, updated_at = NOW() \
                     WHERE workspace_id = $1 AND subject = $2 AND version = $8 \
                     RETURNING workspace_id, name, version, wrapped_key, nonce, \
                               ciphertext_digest, size_bytes, min_trust_class, \
                               created_at, updated_at",
                )
                .bind(workspace_id)
                .bind(subject)
                .bind(version as i32)
                .bind(&snapshot.wrapped_key)
                .bind(&snapshot.nonce)
                .bind(&snapshot.ciphertext_digest)
                .bind(snapshot.size_bytes as i64)
                .bind(version as i32 - 1)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                match updated {
                    Some(row) => workspace_from_row(row),
                    None if self.workspace(subject, workspace_id).await?.is_some() => {
                        Err(StoreError::WorkspaceVersionConflict)
                    }
                    None => Err(StoreError::WorkspaceNotFound),
                }
            }
        }
    }

    /// Hands the node the next command it owes work on, after closing out the
    /// ones whose lease has ended. A poll is the node saying it is running
    /// nothing, so a command left open on a released lease is finished here
    /// rather than handed back.
    async fn claim_command(
        &self,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<Option<NodeCommand>, StoreError> {
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                remember_node_request(&mut market, node_id, request_id, now)?;
                close_ended_commands(&mut market, node_id, now);
                let command = market
                    .commands
                    .values_mut()
                    .filter(|entry| entry.command.node_id == node_id)
                    .filter(|entry| {
                        entry.status == "queued"
                            || (entry.status == "leased"
                                && entry.lease_until.is_none_or(|until| until <= now))
                            || (entry.status == "ready"
                                && entry
                                    .lease_until
                                    .unwrap_or(entry.updated_at + Duration::minutes(2))
                                    <= now)
                    })
                    .min_by_key(|entry| entry.command.issued_at);
                let Some(entry) = command else {
                    return Ok(None);
                };
                entry.status = "leased";
                entry.lease_until = Some(now + Duration::minutes(2));
                entry.authorization_request_id = None;
                entry.updated_at = now;
                let command = entry.command.clone();
                if let Some((_, lease)) = market.leases.get_mut(&command.lease_id)
                    && matches!(
                        lease.state,
                        LeaseState::Funded | LeaseState::Provisioning | LeaseState::Ready
                    )
                {
                    lease.state = LeaseState::Provisioning;
                    lease.updated_at = now;
                }
                Ok(Some(command))
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                record_node_request(&mut transaction, node_id, request_id).await?;
                query(
                    "UPDATE node_commands c \
                     SET status = 'failed', lease_until = NULL, \
                         last_error = COALESCE(c.last_error, $2), updated_at = NOW() \
                     FROM leases l \
                     WHERE l.lease_id = c.lease_id AND c.node_id = $1 \
                       AND c.status IN ('queued', 'leased', 'ready', 'running') \
                       AND l.state NOT IN ('funded', 'provisioning', 'ready', 'active')",
                )
                .bind(node_id)
                .bind(ENDED_LEASE_COMMAND_ERROR)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let command = query_scalar::<_, SqlJson<NodeCommand>>(
                    "SELECT c.document FROM node_commands c \
                     JOIN leases l ON l.lease_id = c.lease_id \
                     WHERE c.node_id = $1 AND c.attempts < 10 \
                       AND l.state IN ('funded', 'provisioning', 'ready', 'active') \
                       AND (c.status = 'queued' \
                            OR (c.status = 'leased' AND c.lease_until <= NOW()) \
                            OR (c.status = 'ready' AND COALESCE(c.lease_until, \
                                c.updated_at + INTERVAL '2 minutes') <= NOW())) \
                     ORDER BY c.created_at ASC LIMIT 1 FOR UPDATE OF c SKIP LOCKED",
                )
                .bind(node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .map(|SqlJson(command)| command);
                let Some(command) = command else {
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Ok(None);
                };
                query(
                    "UPDATE node_commands \
                     SET status = 'leased', attempts = attempts + 1, \
                         lease_until = NOW() + INTERVAL '2 minutes', \
                         authorization_request_id = NULL, updated_at = NOW() \
                     WHERE command_id = $1",
                )
                .bind(command.command_id)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                update_lease_state(&mut transaction, command.lease_id, LeaseState::Provisioning)
                    .await?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(Some(command))
            }
        }
    }

    /// `channel_key_fingerprint` is derived from the key line the node signed
    /// rather than taken from it, so what a renter is later told to pin is a
    /// value this side computed. Answers with where the lease stands afterwards,
    /// which is how a node learns its renter released the lease under it.
    async fn report_command(
        &self,
        report: &NodeCommandReport,
        channel_key_fingerprint: Option<&str>,
    ) -> Result<LeaseState, StoreError> {
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                remember_node_request(&mut market, &report.node_id, report.request_id, now)?;
                let entry = market
                    .commands
                    .get(&report.command_id)
                    .filter(|entry| entry.command.node_id == report.node_id)
                    .ok_or(StoreError::CommandNotFound)?;
                let lease_id = entry.command.lease_id;
                let lease = &market
                    .leases
                    .get(&lease_id)
                    .ok_or(StoreError::CommandNotFound)?
                    .1;
                let transition =
                    command_report_transition(&entry.command, entry.status, &lease.state, report)
                        .ok_or(StoreError::CommandNotFound)?;
                let reached = transition
                    .lease_state
                    .clone()
                    .unwrap_or_else(|| lease.state.clone());
                let entry = market
                    .commands
                    .get_mut(&report.command_id)
                    .ok_or(StoreError::CommandNotFound)?;
                entry.status = transition.status;
                entry.lease_until = transition.renew_claim.then_some(now + Duration::minutes(2));
                if report.result.is_some() {
                    entry.result = report.result.clone();
                }
                entry.verified_report = Some(report.clone());
                entry.updated_at = now;
                if let Some(lease_state) = transition.lease_state
                    && let Some((_, lease)) = market.leases.get_mut(&lease_id)
                {
                    lease.state = lease_state;
                    lease.updated_at = report.observed_at;
                }
                if let Some(fingerprint) = channel_key_fingerprint {
                    market
                        .lifecycle
                        .entry(lease_id)
                        .or_default()
                        .channel_key_fingerprint = Some(fingerprint.to_owned());
                }
                if let Some(action) = transition.action {
                    market.lifecycle_actions.insert((lease_id, action));
                }
                Ok(reached)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                record_node_request(&mut transaction, &report.node_id, report.request_id).await?;
                let current: Option<(i64, String, SqlJson<NodeCommand>, SqlJson<LeaseRecord>)> =
                    query_as(
                        "SELECT c.lease_id, c.status, c.document, l.document \
                     FROM node_commands c JOIN leases l ON l.lease_id = c.lease_id \
                     WHERE c.command_id = $1 AND c.node_id = $2 FOR UPDATE OF c, l",
                    )
                    .bind(report.command_id)
                    .bind(&report.node_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                let Some((lease_id, current, SqlJson(command), SqlJson(lease))) = current else {
                    return Err(StoreError::CommandNotFound);
                };
                let transition =
                    command_report_transition(&command, &current, &lease.state, report)
                        .ok_or(StoreError::CommandNotFound)?;
                let reached = transition
                    .lease_state
                    .clone()
                    .unwrap_or_else(|| lease.state.clone());
                query(
                    "UPDATE node_commands \
                     SET status = $2, last_error = $3, \
                         result = COALESCE($4, result), \
                         lease_until = CASE WHEN $5 THEN NOW() + INTERVAL '2 minutes' END, \
                         verified_report = $6, updated_at = NOW() \
                     WHERE command_id = $1",
                )
                .bind(report.command_id)
                .bind(transition.status)
                .bind(&report.error)
                .bind(report.result.as_ref().map(SqlJson))
                .bind(transition.renew_claim)
                .bind(SqlJson(report))
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if let Some(lease_state) = transition.lease_state {
                    update_lease_state(&mut transaction, lease_id as u64, lease_state).await?;
                }
                // A transition carries no action only when the node repeats a
                // status it already reported, and the first report already
                // stored the key, so recording it with the action loses nothing.
                if let Some(action) = transition.action {
                    query(
                        "INSERT INTO lease_lifecycle \
                             (lease_id, connection_id, node_ready_at, channel_key_fingerprint) \
                         SELECT $1, t.connection_id, \
                                CASE WHEN $2 = 'start_access' THEN $3 ELSE NULL END, $4 \
                         FROM leases l LEFT JOIN node_tunnels t \
                           ON t.node_id = l.document->>'node_id' \
                         WHERE l.lease_id = $1 \
                         ON CONFLICT (lease_id) DO UPDATE SET \
                           connection_id = COALESCE(EXCLUDED.connection_id, lease_lifecycle.connection_id), \
                           node_ready_at = COALESCE(EXCLUDED.node_ready_at, lease_lifecycle.node_ready_at), \
                           channel_key_fingerprint = COALESCE( \
                               EXCLUDED.channel_key_fingerprint, \
                               lease_lifecycle.channel_key_fingerprint), \
                           updated_at = NOW()",
                    )
                    .bind(lease_id)
                    .bind(action)
                    .bind(report.observed_at)
                    .bind(channel_key_fingerprint)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                    query(
                        "INSERT INTO lifecycle_outbox \
                             (action_id, lease_id, kind, available_at) \
                         SELECT $1, $2, $3, \
                             CASE WHEN $3 = 'expire_provision' \
                                  THEN GREATEST(NOW(), l.created_at + INTERVAL '10 minutes') \
                                  ELSE NOW() END \
                         FROM leases l WHERE l.lease_id = $2 \
                         ON CONFLICT (lease_id, kind) DO NOTHING",
                    )
                    .bind(Uuid::now_v7())
                    .bind(lease_id)
                    .bind(action)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
                }
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(reached)
            }
        }
    }

    async fn authorize_command(
        &self,
        node_id: &str,
        command_id: Uuid,
        request_id: Uuid,
    ) -> Result<bool, StoreError> {
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let entry = market
                    .commands
                    .get(&command_id)
                    .filter(|entry| entry.command.node_id == node_id)
                    .filter(|entry| matches!(entry.command.kind, NodeCommandKind::Batch { .. }))
                    .ok_or(StoreError::CommandNotFound)?;
                if entry.status == "running" {
                    return if entry.authorization_request_id == Some(request_id) {
                        Ok(true)
                    } else {
                        Err(StoreError::CommandClaimed)
                    };
                }
                if entry.status != "ready" {
                    return Err(StoreError::CommandClaimed);
                }
                let lease_id = entry.command.lease_id;
                let same_request = entry.authorization_request_id == Some(request_id);
                if !same_request {
                    remember_node_request(&mut market, node_id, request_id, now)?;
                }
                let active = market
                    .leases
                    .get(&lease_id)
                    .is_some_and(|(_, lease)| lease.state == LeaseState::Active);
                let entry = market
                    .commands
                    .get_mut(&command_id)
                    .ok_or(StoreError::CommandNotFound)?;
                entry.authorization_request_id = Some(request_id);
                entry.updated_at = now;
                if active {
                    entry.status = "running";
                    entry.lease_until = None;
                } else {
                    entry.lease_until = Some(now + Duration::minutes(2));
                }
                Ok(active)
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                let fresh_request =
                    insert_node_request(&mut transaction, node_id, request_id).await?;
                type CommandAuthorizationRow = (
                    String,
                    Option<Uuid>,
                    SqlJson<NodeCommand>,
                    SqlJson<LeaseRecord>,
                );
                let current: Option<CommandAuthorizationRow> = query_as(
                    "SELECT c.status, c.authorization_request_id, c.document, l.document \
                     FROM node_commands c JOIN leases l ON l.lease_id = c.lease_id \
                     WHERE c.command_id = $1 AND c.node_id = $2 FOR UPDATE OF c, l",
                )
                .bind(command_id)
                .bind(node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let Some((status, authorization_request_id, SqlJson(command), SqlJson(lease))) =
                    current
                else {
                    return Err(StoreError::CommandNotFound);
                };
                if !matches!(command.kind, NodeCommandKind::Batch { .. }) {
                    return Err(StoreError::CommandNotFound);
                }
                if !fresh_request && authorization_request_id != Some(request_id) {
                    return Err(StoreError::CommandReplay);
                }
                if status == "running" {
                    if authorization_request_id != Some(request_id) {
                        return Err(StoreError::CommandClaimed);
                    }
                    transaction.commit().await.map_err(StoreError::Storage)?;
                    return Ok(true);
                }
                if status != "ready" {
                    return Err(StoreError::CommandClaimed);
                }
                let active = lease.state == LeaseState::Active;
                query(
                    "UPDATE node_commands SET authorization_request_id = $2, \
                         status = CASE WHEN $3 THEN 'running' ELSE status END, \
                         lease_until = CASE WHEN $3 THEN NULL \
                              ELSE NOW() + INTERVAL '2 minutes' END, \
                         updated_at = NOW() WHERE command_id = $1",
                )
                .bind(command_id)
                .bind(request_id)
                .bind(active)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(active)
            }
        }
    }

    async fn repro_status(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredReproStatus>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let quote_ids: BTreeSet<Uuid> = market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        quote
                            .repro
                            .as_ref()
                            .is_some_and(|repro| repro.token_hash == token_hash)
                    })
                    .map(|quote| quote.quote_id)
                    .chain(
                        market
                            .leases
                            .values()
                            .map(|(_, lease)| lease)
                            .filter(|lease| {
                                lease
                                    .repro
                                    .as_ref()
                                    .is_some_and(|repro| repro.token_hash == token_hash)
                            })
                            .map(|lease| lease.quote_id),
                    )
                    .collect();
                if quote_ids.len() > 1 {
                    return Err(StoreError::AmbiguousReproToken);
                }
                let lease = market
                    .leases
                    .values()
                    .map(|(_, lease)| lease)
                    .filter(|lease| {
                        lease
                            .repro
                            .as_ref()
                            .is_some_and(|repro| repro.token_hash == token_hash)
                    })
                    .max_by_key(|lease| lease.created_at);
                if let Some(lease) = lease {
                    let quote = market
                        .open_quotes
                        .get(&lease.quote_id)
                        .cloned()
                        .ok_or_else(|| {
                            StoreError::InvalidStoredState(
                                "repro lease has no corresponding quote".to_owned(),
                            )
                        })?;
                    let execution = market
                        .commands
                        .values()
                        .find(|entry| entry.command.lease_id == lease.lease_id)
                        .map(|entry| StoredReproExecution::Node {
                            status: entry.status.to_owned(),
                            command: entry.command.clone(),
                            report: entry.verified_report.clone(),
                            result: entry.result.clone(),
                            enrolled_device_public_key: market
                                .offers
                                .get(&lease.node_id)
                                .map(|offer| offer.device_public_key.clone()),
                        });
                    return Ok(Some(StoredReproStatus {
                        quote,
                        lease: Some(StoredReproLease {
                            lease_id: lease.lease_id,
                            chain_lease_id: lease.chain_lease_id,
                            state: lease.state.clone(),
                            node_id: lease.node_id.clone(),
                            token_hash: lease.repro.as_ref().map(|repro| repro.token_hash.clone()),
                            spec_hash: lease.repro.as_ref().map(|repro| repro.spec_hash.clone()),
                            execution,
                            receipt: None,
                        }),
                    }));
                }
                Ok(market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        quote
                            .repro
                            .as_ref()
                            .is_some_and(|repro| repro.token_hash == token_hash)
                    })
                    .max_by_key(|quote| quote.expires_at)
                    .cloned()
                    .map(|quote| StoredReproStatus { quote, lease: None }))
            }
            Self::Postgres(pool) => {
                let claims = query_scalar::<_, i64>(REPRO_STATUS_CLAIM_COUNT_QUERY)
                    .bind(token_hash)
                    .fetch_one(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                if claims > 1 {
                    return Err(StoreError::AmbiguousReproToken);
                }
                type ReproLeaseRow = (
                    SqlJson<LeaseQuote>,
                    i64,
                    i64,
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<SqlJson<NodeCommand>>,
                    Option<SqlJson<NodeCommandReport>>,
                    Option<SqlJson<CommandResult>>,
                    Option<String>,
                    Option<SqlJson<NodeCommand>>,
                    Option<SqlJson<ManagedCommandReport>>,
                    Option<SqlJson<PublicReceipt>>,
                    Option<String>,
                );
                let row = query_as::<_, ReproLeaseRow>(REPRO_STATUS_LEASE_QUERY)
                    .bind(token_hash)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                if let Some((
                    SqlJson(quote),
                    lease_id,
                    chain_lease_id,
                    state,
                    node_id,
                    lease_token_hash,
                    lease_spec_hash,
                    node_status,
                    node_command,
                    node_report,
                    node_result,
                    managed_status,
                    managed_command,
                    managed_report,
                    receipt,
                    enrolled_device_public_key,
                )) = row
                {
                    let execution = match (node_command, managed_command) {
                        (Some(SqlJson(command)), None) => Some(StoredReproExecution::Node {
                            status: node_status.ok_or_else(|| {
                                StoreError::InvalidStoredState(
                                    "node repro command has no status".to_owned(),
                                )
                            })?,
                            command,
                            report: node_report.map(|SqlJson(report)| report),
                            result: node_result.map(|SqlJson(result)| result),
                            enrolled_device_public_key,
                        }),
                        (None, Some(SqlJson(command))) => Some(StoredReproExecution::Managed {
                            status: managed_status.ok_or_else(|| {
                                StoreError::InvalidStoredState(
                                    "managed repro command has no status".to_owned(),
                                )
                            })?,
                            command,
                            report: managed_report.map(|SqlJson(report)| report),
                        }),
                        (None, None) => None,
                        (Some(_), Some(_)) => {
                            return Err(StoreError::InvalidStoredState(
                                "repro lease has two executors".to_owned(),
                            ));
                        }
                    };
                    return Ok(Some(StoredReproStatus {
                        quote,
                        lease: Some(StoredReproLease {
                            lease_id: u64::try_from(lease_id).map_err(|_| {
                                StoreError::InvalidStoredState("invalid repro lease ID".to_owned())
                            })?,
                            chain_lease_id: u64::try_from(chain_lease_id).map_err(|_| {
                                StoreError::InvalidStoredState(
                                    "invalid repro chain lease ID".to_owned(),
                                )
                            })?,
                            state: parse_lease_state(&state)?,
                            node_id,
                            token_hash: lease_token_hash,
                            spec_hash: lease_spec_hash,
                            execution,
                            receipt: receipt.map(|SqlJson(receipt)| receipt),
                        }),
                    }));
                }
                Ok(
                    query_scalar::<_, SqlJson<LeaseQuote>>(REPRO_STATUS_QUOTE_QUERY)
                        .bind(token_hash)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Storage)?
                        .map(|SqlJson(quote)| StoredReproStatus { quote, lease: None }),
                )
            }
        }
    }

    /// The output of a batch lease. Scoped to the renter who paid for it: the
    /// command's result is theirs, not the operator's to hand out.
    async fn lease_result(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<CommandResult>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let Some((owner, _)) = market.leases.get(&lease_id) else {
                    return Ok(None);
                };
                if owner != subject {
                    return Ok(None);
                }
                Ok(market
                    .commands
                    .values()
                    .find(|entry| entry.command.lease_id == lease_id)
                    .and_then(|entry| entry.result.clone()))
            }
            Self::Postgres(pool) => {
                let stored = query_as::<
                    _,
                    (
                        Option<SqlJson<CommandResult>>,
                        Option<SqlJson<ManagedCommandReport>>,
                    ),
                >(
                    "SELECT c.result, m.report \
                     FROM leases l \
                     LEFT JOIN node_commands c ON c.lease_id = l.lease_id \
                     LEFT JOIN managed_repro_jobs m ON m.lease_id = l.lease_id \
                     WHERE l.lease_id = $1 AND l.subject = $2",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                let Some((native, managed)) = stored else {
                    return Ok(None);
                };
                if let Some(SqlJson(result)) = native {
                    return Ok(Some(result));
                }
                Ok(managed.and_then(|SqlJson(report)| {
                    (report.outcome == NodeCommandOutcome::Completed
                        && report.error.is_none()
                        && report.verify().is_ok())
                    .then_some(report.result)
                    .flatten()
                }))
            }
        }
    }

    /// Where the lease stands, for the account that owns it. Absent for anyone
    /// else, so asking about a stranger's lease cannot tell you whether it
    /// exists.
    async fn lease_state(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<LeaseState>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let Some((owner, lease)) = market.leases.get(&lease_id) else {
                    return Ok(None);
                };
                Ok((owner == subject).then_some(lease.state.clone()))
            }
            Self::Postgres(pool) => {
                let stored: Option<String> =
                    query_scalar("SELECT state FROM leases WHERE lease_id = $1 AND subject = $2")
                        .bind(lease_id as i64)
                        .bind(subject)
                        .fetch_optional(pool)
                        .await
                        .map_err(StoreError::Storage)?;
                stored.map(|state| parse_lease_state(&state)).transpose()
            }
        }
    }

    /// Shuts an active lease and queues the teardown the lifecycle worker
    /// performs, or answers `None` where the account owns no such lease. The
    /// lease moves to `closing` here rather than when that teardown confirms:
    /// the access path keys on `active`, so a lease left there would mint a
    /// fresh gateway grant after the worker had already revoked the last one
    /// and stopped the meter.
    async fn release_lease(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<LeaseRelease>, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                let Some((owner, lease)) = market.leases.get_mut(&lease_id) else {
                    return Ok(None);
                };
                if owner != subject {
                    return Ok(None);
                }
                if lease.command.is_some() {
                    return Ok(Some(LeaseRelease::Batch));
                }
                let observed = lease.state.clone();
                if observed != LeaseState::Active {
                    return Ok(Some(if observed.can_still_open_access() {
                        LeaseRelease::NotYetOpen
                    } else {
                        LeaseRelease::AlreadyClosed(observed)
                    }));
                }
                lease.state = LeaseState::Closing;
                lease.updated_at = Utc::now();
                market.lifecycle_actions.insert((lease_id, "close_access"));
                Ok(Some(LeaseRelease::Queued))
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                // The row lock is what makes two releases of the same lease, or
                // a release racing the periodic teardown scan, settle into one
                // queued close instead of two.
                let stored = query_as::<_, (String, bool)>(
                    "SELECT l.state, \
                            l.document->>'command' IS NOT NULL \
                            OR EXISTS (SELECT 1 FROM managed_repro_jobs m \
                                       WHERE m.lease_id = l.lease_id) \
                     FROM leases l \
                     WHERE l.lease_id = $1 AND l.subject = $2 FOR UPDATE OF l",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let Some((stored, batch)) = stored else {
                    return Ok(None);
                };
                if batch {
                    return Ok(Some(LeaseRelease::Batch));
                }
                let state = parse_lease_state(&stored)?;
                if state != LeaseState::Active {
                    return Ok(Some(if state.can_still_open_access() {
                        LeaseRelease::NotYetOpen
                    } else {
                        LeaseRelease::AlreadyClosed(state)
                    }));
                }
                query(
                    "INSERT INTO lifecycle_outbox \
                         (action_id, lease_id, kind, available_at) \
                     VALUES ($1, $2, 'close_access', NOW()) \
                     ON CONFLICT (lease_id, kind) DO NOTHING",
                )
                .bind(Uuid::now_v7())
                .bind(lease_id as i64)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                query(
                    "UPDATE leases \
                     SET state = 'closing', \
                         document = jsonb_set(document, '{state}', '\"closing\"'), \
                         updated_at = NOW() \
                     WHERE lease_id = $1 AND state = 'active'",
                )
                .bind(lease_id as i64)
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                transaction.commit().await.map_err(StoreError::Storage)?;
                Ok(Some(LeaseRelease::Queued))
            }
        }
    }

    /// Credentials are released only for a lease standing at the class it was
    /// quoted at. Above `Isolated` that means a verdict from the guest running
    /// this lease: a node-level report says which machine booted correctly at
    /// some point, never which VM the renter is about to be handed a shell in.
    /// A lease that never produces one gets no grant and can be refunded, which
    /// is the honest outcome; running it a rung lower than it was sold at is
    /// not.
    async fn lease_access(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<LeaseAccessGrant>, StoreError> {
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let Some((owner, lease)) = market.leases.get(&lease_id) else {
                    return Ok(None);
                };
                if owner != subject || lease.state != LeaseState::Active {
                    return Ok(None);
                }
                // What the renter bought is on the quote. The record carries
                // what the network could substantiate when the lease was
                // written, which is the same or weaker, so gating on the record
                // would let a lease sold above the ceiling pass unnoticed.
                let quoted_class = market
                    .open_quotes
                    .get(&lease.quote_id)
                    .map_or(lease.trust_class, |quote| quote.trust_class);
                let verdict = market.lease_verdicts.get(&lease_id);
                let tdx_verdict = market.lease_tdx_guest_verdicts.get(&lease_id);
                let gpu_cc_verdict = market.lease_gpu_cc_verdicts.get(&lease_id);
                let cutoff = now - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                let node_class = class_for_verdict(
                    &lease.node_id,
                    market
                        .tunnels
                        .get(&lease.node_id)
                        .is_some_and(|observed_at| *observed_at >= cutoff),
                    fresh_posture(&market, &lease.node_id, cutoff),
                    market.verdicts.get(&lease.node_id),
                    now,
                );
                if class_for_lease(
                    lease_id,
                    &lease.node_id,
                    node_class,
                    verdict,
                    tdx_verdict,
                    gpu_cc_verdict,
                    now,
                ) < quoted_class
                {
                    return Err(StoreError::LeaseUnattested);
                }
                let Some(lifecycle) = market.lifecycle.get(&lease_id) else {
                    return Ok(None);
                };
                let (Some(token), Some(expires_at), Some(jupyter_token)) = (
                    lifecycle.grant_token.clone(),
                    lifecycle.grant_expires_at,
                    market.lease_secrets.get(&lease_id).cloned(),
                ) else {
                    return Ok(None);
                };
                Ok(Some(LeaseAccessGrant {
                    access: StoredLeaseAccess::Gateway {
                        token,
                        jupyter_token,
                        expires_at,
                    },
                    channel_key: channel_key(
                        verdict.map(|verdict| verdict.guest.channel_key_fingerprint.clone()),
                        tdx_verdict.map(|verdict| verdict.channel_key_fingerprint.clone()),
                        lifecycle.channel_key_fingerprint.clone(),
                    ),
                }))
            }
            Self::Postgres(pool) => {
                let standing = query_as::<
                    _,
                    (
                        String,
                        Option<String>,
                        Option<String>,
                        Option<SqlJson<LeaseAttestationVerdict>>,
                        Option<SqlJson<LeaseTdxGuestVerdict>>,
                        Option<SqlJson<LeaseGpuCcVerdict>>,
                        bool,
                        Option<SqlJson<NodePosture>>,
                        Option<SqlJson<AttestationVerdict>>,
                    ),
                >(
                    "SELECT l.document->>'node_id', \
                            l.document->>'trust_class', \
                            q.document->>'trust_class', \
                            (SELECT v.document FROM lease_attestation_verdicts v \
                             WHERE v.lease_id = l.lease_id), \
                            (SELECT tv.document FROM lease_tdx_guest_verdicts tv \
                             WHERE tv.lease_id = l.lease_id), \
                            (SELECT gv.document FROM lease_gpu_cc_verdicts gv \
                             WHERE gv.lease_id = l.lease_id), \
                            EXISTS ( \
                                SELECT 1 FROM node_tunnels t \
                                WHERE t.node_id = l.document->>'node_id' \
                                  AND t.observed_at >= $3 \
                            ), \
                            (SELECT nt.document->'posture' FROM node_telemetry nt \
                             WHERE nt.node_id = l.document->>'node_id' \
                               AND nt.observed_at >= $3), \
                            (SELECT nv.document FROM node_attestation_verdicts nv \
                             WHERE nv.node_id = l.document->>'node_id' \
                               AND nv.expires_at > now()) \
                     FROM leases l \
                     LEFT JOIN lease_quotes q ON q.quote_id = l.quote_id \
                     WHERE l.lease_id = $1 AND l.subject = $2 AND l.state = 'active'",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .bind(now - Duration::seconds(OFFER_MAX_AGE_SECONDS))
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                let Some((
                    node_id,
                    recorded_class,
                    quoted_class,
                    verdict,
                    tdx_verdict,
                    gpu_cc_verdict,
                    tunneled,
                    posture,
                    node_verdict,
                )) = standing
                else {
                    return Ok(None);
                };
                // A lease predating trust classes is `open`, matching the serde
                // default, which is the weakest class and so fails closed.
                let recorded_class = recorded_class
                    .map_or(Ok(TrustClass::Open), |class| parse_trust_class(&class))?;
                let quoted_class =
                    quoted_class.map_or(Ok(recorded_class), |class| parse_trust_class(&class))?;
                let verdict = verdict.map(|SqlJson(verdict)| verdict);
                let tdx_verdict = tdx_verdict.map(|SqlJson(verdict)| verdict);
                let gpu_cc_verdict = gpu_cc_verdict.map(|SqlJson(verdict)| verdict);
                let node_class = class_for_verdict(
                    &node_id,
                    tunneled,
                    posture.as_ref().map(|SqlJson(posture)| posture),
                    node_verdict.as_ref().map(|SqlJson(verdict)| verdict),
                    now,
                );
                if class_for_lease(
                    lease_id,
                    &node_id,
                    node_class,
                    verdict.as_ref(),
                    tdx_verdict.as_ref(),
                    gpu_cc_verdict.as_ref(),
                    now,
                ) < quoted_class
                {
                    return Err(StoreError::LeaseUnattested);
                }
                let attested_channel_key =
                    verdict.map(|verdict| verdict.guest.channel_key_fingerprint);
                let tdx_channel_key = tdx_verdict.map(|verdict| verdict.channel_key_fingerprint);
                let direct = query_as::<_, (String, i32, chrono::DateTime<Utc>)>(
                    "SELECT ci.ssh_host, ci.ssh_port, \
                            lc.access_started_at + make_interval(secs => (l.document->>'duration_seconds')::integer) \
                     FROM leases l \
                     JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
                     JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
                     WHERE l.lease_id = $1 AND l.subject = $2 AND l.state = 'active' \
                       AND l.document->>'command' IS NULL \
                       AND ci.status = 'running' \
                       AND ci.ssh_host IS NOT NULL AND ci.ssh_port IS NOT NULL \
                       AND lc.access_started_at IS NOT NULL \
                       AND lc.access_started_at + make_interval(secs => (l.document->>'duration_seconds')::integer) > NOW()",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                if let Some((host, port, expires_at)) = direct {
                    return Ok(Some(LeaseAccessGrant {
                        access: StoredLeaseAccess::DirectSsh {
                            host,
                            port: u16::try_from(port).map_err(|_| {
                                StoreError::InvalidStoredState("invalid SSH port".into())
                            })?,
                            expires_at,
                        },
                        // Brokered capacity is a cloud instance whose host
                        // key the cloud generated and never showed us. There is
                        // no node here to report one either, so the renter is
                        // told nothing rather than told to trust a name we made
                        // up.
                        channel_key: channel_key(
                            attested_channel_key.clone(),
                            tdx_channel_key.clone(),
                            None,
                        ),
                    }));
                }
                let stored = query_as::<
                    _,
                    (
                        SqlJson<EncryptedSecret>,
                        SqlJson<EncryptedSecret>,
                        chrono::DateTime<Utc>,
                        Option<String>,
                    ),
                >(
                    "SELECT lc.grant_token, s.jupyter_token, lc.grant_expires_at, \
                            lc.channel_key_fingerprint \
                     FROM leases l \
                     JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
                     JOIN lease_secrets s ON s.lease_id = l.lease_id \
                     WHERE l.lease_id = $1 AND l.subject = $2 AND l.state = 'active' \
                       AND lc.grant_token IS NOT NULL \
                       AND lc.grant_expires_at > NOW()",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                Ok(stored.map(
                    |(SqlJson(token), SqlJson(jupyter_token), expires_at, reported)| {
                        LeaseAccessGrant {
                            access: StoredLeaseAccess::Gateway {
                                token,
                                jupyter_token,
                                expires_at,
                            },
                            channel_key: channel_key(
                                attested_channel_key,
                                tdx_channel_key,
                                reported,
                            ),
                        }
                    },
                ))
            }
        }
    }
}

type OperatorAuditRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    SqlJson<serde_json::Value>,
    SqlJson<serde_json::Value>,
    chrono::DateTime<Utc>,
);

fn operator_audit_from_row(row: OperatorAuditRow) -> Result<OperatorAuditEvent, StoreError> {
    Ok(OperatorAuditEvent {
        event_id: row.0,
        action_id: row.1,
        actor_subject: row.2,
        action: OperatorAction::try_from(row.3.as_str())?,
        target_type: row.4,
        target_id: row.5,
        reason: row.6,
        evidence_hash: row.7,
        before_state: row.8.0,
        after_state: row.9.0,
        created_at: row.10,
    })
}

async fn fetch_operator_audit(
    transaction: &mut Transaction<'_, Postgres>,
    action_id: Uuid,
) -> Result<Option<OperatorAuditEvent>, StoreError> {
    let row = query_as::<_, OperatorAuditRow>(
        "SELECT event_id, action_id, actor_subject, action, target_type, target_id, \
                reason, evidence_hash, before_state, after_state, created_at \
         FROM operator_audit_events WHERE action_id = $1",
    )
    .bind(action_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    row.map(operator_audit_from_row).transpose()
}

async fn operator_target_state(
    transaction: &mut Transaction<'_, Postgres>,
    target_type: &str,
    target_id: &str,
) -> Result<serde_json::Value, StoreError> {
    match target_type {
        "account" => {
            let controls = query_as::<_, (bool, bool)>(
                "SELECT risk_hold, suspended FROM accounts WHERE subject = $1 FOR UPDATE",
            )
            .bind(target_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(StoreError::Storage)?
            .ok_or(StoreError::OperatorTargetNotFound)?;
            Ok(serde_json::json!({
                "risk_hold": controls.0,
                "suspended": controls.1
            }))
        }
        "node" => {
            let exists: bool =
                query_scalar("SELECT EXISTS (SELECT 1 FROM node_offers WHERE node_id = $1)")
                    .bind(target_id)
                    .fetch_one(&mut **transaction)
                    .await
                    .map_err(StoreError::Storage)?;
            if !exists {
                return Err(StoreError::OperatorTargetNotFound);
            }
            let suspended = query_scalar::<_, bool>(
                "SELECT COALESCE((SELECT suspended FROM node_controls WHERE node_id = $1), FALSE)",
            )
            .bind(target_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(StoreError::Storage)?;
            let certificate_active: bool = query_scalar(
                "SELECT EXISTS (SELECT 1 FROM node_certificates \
                 WHERE node_id = $1 AND status = 'active' AND not_after > NOW())",
            )
            .bind(target_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(StoreError::Storage)?;
            Ok(serde_json::json!({
                "suspended": suspended,
                "certificate_active": certificate_active
            }))
        }
        _ => Err(StoreError::InvalidOperatorAction),
    }
}

fn remember_node_request(
    market: &mut MemoryMarketplace,
    node_id: &str,
    request_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(), StoreError> {
    market
        .node_requests
        .retain(|_, (_, expires_at)| *expires_at > now);
    if market.node_requests.contains_key(&request_id) {
        return Err(StoreError::CommandReplay);
    }
    market.node_requests.insert(
        request_id,
        (
            node_id.to_owned(),
            now + Duration::minutes(NODE_REQUEST_TTL_MINUTES),
        ),
    );
    Ok(())
}

async fn record_node_request(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    node_id: &str,
    request_id: Uuid,
) -> Result<(), StoreError> {
    if !insert_node_request(transaction, node_id, request_id).await? {
        return Err(StoreError::CommandReplay);
    }
    Ok(())
}

async fn insert_node_request(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    node_id: &str,
    request_id: Uuid,
) -> Result<bool, StoreError> {
    query("DELETE FROM node_command_requests WHERE expires_at <= NOW()")
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
    let inserted = query(
        "INSERT INTO node_command_requests (request_id, node_id, expires_at) \
         VALUES ($1, $2, NOW() + make_interval(mins => $3)) ON CONFLICT DO NOTHING",
    )
    .bind(request_id)
    .bind(node_id)
    .bind(NODE_REQUEST_TTL_MINUTES as i32)
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    Ok(inserted.rows_affected() == 1)
}

async fn update_lease_state(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    lease_id: u64,
    state: LeaseState,
) -> Result<(), StoreError> {
    let current = query_scalar::<_, SqlJson<LeaseRecord>>(
        "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
    )
    .bind(lease_id as i64)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    let Some(SqlJson(mut lease)) = current else {
        return Err(StoreError::CommandNotFound);
    };
    if state == LeaseState::Provisioning
        && !matches!(
            lease.state,
            LeaseState::Funded | LeaseState::Provisioning | LeaseState::Ready
        )
    {
        return Ok(());
    }
    lease.state = state;
    lease.updated_at = Utc::now();
    let state = lease_state_name(&lease.state);
    query("UPDATE leases SET document = $2, state = $3, updated_at = NOW() WHERE lease_id = $1")
        .bind(lease_id as i64)
        .bind(SqlJson(lease))
        .bind(state)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
    Ok(())
}

struct CommandReportTransition {
    status: &'static str,
    lease_state: Option<LeaseState>,
    action: Option<&'static str>,
    renew_claim: bool,
}

fn command_report_transition(
    command: &NodeCommand,
    current: &str,
    lease_state: &LeaseState,
    report: &NodeCommandReport,
) -> Option<CommandReportTransition> {
    let batch = matches!(&command.kind, NodeCommandKind::Batch { .. });
    if (batch && report.outcome == NodeCommandOutcome::Completed && report.result.is_none())
        || (!batch && report.result.is_some())
    {
        return None;
    }
    let status = match &report.outcome {
        NodeCommandOutcome::Ready => "ready",
        NodeCommandOutcome::Completed => "completed",
        NodeCommandOutcome::Failed => "failed",
    };
    if current == status {
        return Some(CommandReportTransition {
            status,
            lease_state: None,
            action: None,
            renew_claim: status == "ready",
        });
    }

    match &report.outcome {
        NodeCommandOutcome::Ready
            if matches!(current, "queued" | "leased")
                && matches!(
                    lease_state,
                    LeaseState::Funded
                        | LeaseState::Provisioning
                        | LeaseState::Ready
                        | LeaseState::Active
                ) =>
        {
            let already_active = *lease_state == LeaseState::Active;
            Some(CommandReportTransition {
                status,
                lease_state: (!already_active).then_some(LeaseState::Ready),
                action: (!already_active).then_some("start_access"),
                renew_claim: true,
            })
        }
        NodeCommandOutcome::Completed
            if *lease_state == LeaseState::Active
                && match &command.kind {
                    NodeCommandKind::Batch { .. } => current == "running",
                    _ => current == "ready",
                } =>
        {
            Some(CommandReportTransition {
                status,
                lease_state: Some(LeaseState::Closing),
                action: Some("close_access"),
                renew_claim: false,
            })
        }
        NodeCommandOutcome::Failed
            if *lease_state == LeaseState::Active
                && matches!(current, "queued" | "leased" | "ready" | "running") =>
        {
            Some(CommandReportTransition {
                status,
                lease_state: Some(LeaseState::Closing),
                action: Some("close_access"),
                renew_claim: false,
            })
        }
        NodeCommandOutcome::Failed
            if matches!(
                lease_state,
                LeaseState::Funded | LeaseState::Provisioning | LeaseState::Ready
            ) && matches!(current, "queued" | "leased" | "ready") =>
        {
            Some(CommandReportTransition {
                status,
                lease_state: Some(LeaseState::Closing),
                action: Some("expire_provision"),
                renew_claim: false,
            })
        }
        // A lease past active has already closed and queued its own teardown,
        // so whatever the node says about the command now is bookkeeping:
        // recording it frees the machine for the next lease without touching
        // the money. Refusing it would leave the daemon retrying a report it
        // can never place, and the command row holding a healthy node out of
        // every offer.
        _ if !lease_state.can_still_open_access() => {
            let status = match finished_status(current) {
                Some(finished) if report.outcome == NodeCommandOutcome::Ready => finished,
                _ => status,
            };
            Some(CommandReportTransition {
                status,
                lease_state: None,
                action: None,
                renew_claim: status == "ready",
            })
        }
        _ => None,
    }
}

/// Which host key a renter is handed when both a guest report and the node's own
/// account exist. The report wins: it is the same key, said by the party that
/// cannot lie about it.
fn channel_key(
    snp: Option<String>,
    tdx: Option<String>,
    reported: Option<String>,
) -> Option<ChannelKey> {
    snp.map(|fingerprint| ChannelKey {
        fingerprint,
        source: ChannelKeySource::SnpReport,
    })
    .or_else(|| {
        tdx.map(|fingerprint| ChannelKey {
            fingerprint,
            source: ChannelKeySource::TdxQuote,
        })
    })
    .or_else(|| {
        reported.map(|fingerprint| ChannelKey {
            fingerprint,
            source: ChannelKeySource::NodeReport,
        })
    })
}

/// Whether a lease still holds its machine. Settlement runs for a further 24
/// hours after access closes, and the node is schedulable again long before
/// that bookkeeping finishes.
/// The escrow holds a node's `activeLeaseId` until the lease finalizes or
/// refunds, so anything short of a terminal state still occupies it. Listing
/// the states that free a node rather than the ones that hold it means a new
/// non-terminal state reserves by default instead of silently letting the
/// scheduler quote a node the registry will reject with `LeaseNotReady`.
fn occupies_node(lease: &LeaseRecord) -> bool {
    // `Failed` is deliberately absent. Only this platform writes it, after a
    // lifecycle action ran out of attempts, and the escrow never agreed: the
    // deposit is still held and `activeLeaseId` is still set, so the registry
    // will refuse the next lease on that node with `LeaseNotReady` while the
    // scheduler keeps quoting it. Giving up on a lease does not free the
    // machine; only the chain does that.
    !matches!(lease.state, LeaseState::Finalized | LeaseState::Refunded)
}

fn occupies_node_for_escrow(lease: &LeaseRecord, escrow_address: &str) -> bool {
    lease.escrow_address.eq_ignore_ascii_case(escrow_address) && occupies_node(lease)
}

/// Nodes still holding a launch command. The daemon runs the container to the
/// deadline it was handed and reports only when it is done, so the machine
/// stays occupied after an early release has already freed the lease. Quoting
/// it inside that window strands the next renter in provisioning.
fn nodes_holding_commands(market: &MemoryMarketplace) -> BTreeSet<String> {
    market
        .commands
        .values()
        .filter(|entry| command_holds_node(entry.status))
        .map(|entry| entry.command.node_id.clone())
        .collect()
}

fn command_holds_node(status: &str) -> bool {
    matches!(status, "queued" | "leased" | "ready" | "running")
}

/// Where a report leaves a command that has already finished: exactly where it
/// was. A node repeating an old ready report cannot pull one back open.
fn finished_status(current: &str) -> Option<&'static str> {
    match current {
        "completed" => Some("completed"),
        "failed" => Some("failed"),
        _ => None,
    }
}

const ENDED_LEASE_COMMAND_ERROR: &str = "the lease ended before the command finished";

/// Closes out what a node still holds for leases that have ended. Handing a
/// released lease's launch back would start the renter's workspace again on
/// compute nobody is billed for, and leaving the row open would keep the node
/// out of every offer with no report left that could ever close it.
fn close_ended_commands(market: &mut MemoryMarketplace, node_id: &str, now: DateTime<Utc>) {
    let ended: Vec<Uuid> = market
        .commands
        .values()
        .filter(|entry| {
            entry.command.node_id == node_id
                && command_holds_node(entry.status)
                && market
                    .leases
                    .get(&entry.command.lease_id)
                    .is_none_or(|(_, lease)| !lease.state.can_still_open_access())
        })
        .map(|entry| entry.command.command_id)
        .collect();
    for command_id in ended {
        if let Some(entry) = market.commands.get_mut(&command_id) {
            entry.status = "failed";
            entry.lease_until = None;
            entry.updated_at = now;
        }
    }
}

fn lease_state_name(state: &LeaseState) -> &'static str {
    match state {
        LeaseState::Funded => "funded",
        LeaseState::Provisioning => "provisioning",
        LeaseState::Ready => "ready",
        LeaseState::Active => "active",
        LeaseState::Closing => "closing",
        LeaseState::SettlementPending => "settlement_pending",
        LeaseState::Disputed => "disputed",
        LeaseState::Finalized => "finalized",
        LeaseState::Refunded => "refunded",
        LeaseState::Failed => "failed",
    }
}

/// A lease carrying a command runs it and reports what it printed; a lease
/// without one hands back a session. The renter chose which at quote time, so
/// the credentials for an interactive workspace are simply never used for a
/// batch lease rather than being issued and left lying around.
fn launch_command(
    lease: &LeaseRecord,
    ssh_authorized_key: Option<&str>,
    jupyter_token: &str,
) -> Result<NodeCommand, StoreError> {
    let now = Utc::now();
    let kind = match lease.command.as_deref() {
        Some(command) => NodeCommandKind::Batch {
            image: lease.image.clone(),
            command: command.to_owned(),
            duration_seconds: lease.duration_seconds,
        },
        None => NodeCommandKind::Launch {
            image: lease.image.clone(),
            duration_seconds: lease.duration_seconds,
            ssh_authorized_key: ssh_authorized_key
                .ok_or(StoreError::AccessCredentialsMissing)?
                .to_owned(),
            jupyter_token: jupyter_token.to_owned(),
        },
    };
    Ok(NodeCommand {
        command_id: Uuid::now_v7(),
        node_id: lease.node_id.clone(),
        lease_id: lease.lease_id,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
        kind,
    })
}

async fn health(
    State(state): State<AppState>,
) -> Result<Json<Health>, (StatusCode, Json<ApiError>)> {
    state.store.check_health().await.map_err(internal_error)?;
    Ok(Json(Health {
        status: "ok",
        service: "control-plane",
    }))
}

#[derive(Deserialize)]
struct OfferFilter {
    #[serde(default)]
    min_trust: TrustClass,
}

/// A public price for compute. The sourced series is what providers charged
/// this network; the settled series is what renters paid on leases that
/// finished onchain. Both are in USDG micros per GPU hour.
async fn price_index(
    State(state): State<AppState>,
) -> Result<Json<PriceIndex>, (StatusCode, Json<ApiError>)> {
    let entries = state.store.price_index().await.map_err(internal_error)?;
    Ok(Json(PriceIndex {
        currency: "USDG",
        unit: "micros_per_gpu_hour",
        generated_at: Utc::now(),
        gpus: entries,
    }))
}

async fn list_offers(
    State(state): State<AppState>,
    Query(filter): Query<OfferFilter>,
) -> Result<Json<Vec<NodeOffer>>, (StatusCode, Json<ApiError>)> {
    let offers = state.store.list_offers().await.map_err(internal_error)?;
    Ok(Json(
        offers
            .into_iter()
            .filter(|offer| offer.trust_class >= filter.min_trust)
            .collect(),
    ))
}

async fn get_repro_status(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<ReproStatusResponse>, (StatusCode, Json<ApiError>)> {
    let request: ReproStatusRequest = serde_json::from_slice(&body).map_err(|_| {
        bad_request(
            "invalid_token",
            "body must contain one canonical 256-bit repro token",
        )
    })?;
    let token_hash = canonical_repro_token_hash(&request.token).ok_or_else(|| {
        bad_request(
            "invalid_token",
            "body must contain one canonical 256-bit repro token",
        )
    })?;
    let stored = state
        .store
        .repro_status(&token_hash)
        .await
        .map_err(store_error)?
        .ok_or_else(|| not_found("repro_not_found", "this repro capability has no quote"))?;
    let response = build_repro_status(&token_hash, stored).map_err(internal_error)?;
    let response_bytes = serde_json::to_vec(&response).map_err(|_| {
        internal_error(StoreError::InvalidStoredState(
            "repro status response is not serializable".to_owned(),
        ))
    })?;
    if response_bytes.len() > MAX_REPRO_STATUS_RESPONSE_BYTES {
        return Err(internal_error(StoreError::InvalidStoredState(
            "repro status response exceeds its size limit".to_owned(),
        )));
    }
    Ok(Json(response))
}

async fn enroll_node(
    State(state): State<AppState>,
    Json(enrollment): Json<NodeEnrollment>,
) -> Result<(StatusCode, Json<NodeOffer>), (StatusCode, Json<ApiError>)> {
    if enrollment.rate_per_second == 0
        || enrollment.gpu.vram_mib == 0
        || enrollment.gpu.cuda_major == 0
        || enrollment.gpu.model.trim().is_empty()
        || enrollment.gpu.model.len() > 128
    {
        return Err(bad_request(
            "invalid_node",
            "rate and GPU memory must be non-zero",
        ));
    }
    let device_key = verifying_key(&enrollment.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if node_id(&device_key) != enrollment.node_id {
        return Err(bad_request(
            "node_identity_mismatch",
            "node ID must be the device public key hash",
        ));
    }
    if !is_address(&enrollment.operator_wallet) || !is_address(&enrollment.payout_wallet) {
        return Err(bad_request(
            "invalid_wallet",
            "operator and payout wallets must be EVM addresses",
        ));
    }
    if enrollment
        .issued_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_enrollment",
            "node enrollment proof is older than five minutes",
        ));
    }
    if enrollment.verify(&device_key).is_err() {
        return Err(bad_request(
            "unsigned_enrollment",
            "node enrollment must be signed by the device identity",
        ));
    }
    let mut offer = NodeOffer {
        node_id: enrollment.node_id.clone(),
        operator_wallet: enrollment.operator_wallet,
        payout_wallet: enrollment.payout_wallet,
        device_public_key: enrollment.device_public_key,
        gpu: enrollment.gpu,
        rate_per_second: enrollment.rate_per_second,
        reliability_bps: 0,
        benchmark_score: enrollment.benchmark_score,
        bonded: false,
        online: false,
        public_image_only: true,
        trust_class: TrustClass::Open,
        staker_only: false,
        command_channel: false,
        managed_batch: false,
        updated_at: Utc::now(),
    };
    offer.bonded = state
        .registry
        .verify_offer(&offer)
        .await
        .map_err(registry_error)?;
    if !offer.bonded {
        return Err(conflict(
            "node_not_schedulable",
            "node is not active, bonded and idle in the registry",
        ));
    }
    state
        .store
        .enroll(offer.clone())
        .await
        .map_err(internal_error)?;
    Ok((StatusCode::CREATED, Json(offer)))
}

async fn issue_node_certificate(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(request): Json<NodeCertificateRequest>,
) -> Result<(StatusCode, Json<NodeCertificateBundle>), (StatusCode, Json<ApiError>)> {
    if request.node_id != node_id
        || !valid_node_id(&node_id)
        || request
            .issued_at
            .signed_duration_since(Utc::now())
            .num_seconds()
            .abs()
            > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "invalid_certificate_request",
            "node certificate request is invalid or stale",
        ));
    }
    let Some(offer) = state.store.offer(&node_id).await.map_err(internal_error)? else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before requesting a certificate",
        ));
    };
    let key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if request.device_public_key != offer.device_public_key
        || prism_protocol::node_id(&key) != node_id
        || request.verify(&key).is_err()
    {
        return Err(bad_request(
            "unsigned_certificate_request",
            "certificate request must be signed by the enrolled device identity",
        ));
    }
    let (bundle, stored) = state
        .certificate_authority
        .issue(&node_id, &request)
        .map_err(|error| {
            tracing::warn!(%error, %node_id, "rejected node certificate request");
            bad_request(
                "invalid_certificate_request",
                "node certificate request could not be verified",
            )
        })?;
    state
        .store
        .store_certificate(request.request_id, stored)
        .await
        .map_err(store_error)?;
    Ok((StatusCode::CREATED, Json(bundle)))
}

async fn create_wallet_challenge(
    State(state): State<AppState>,
    Query(query): Query<WalletChallengeQuery>,
    headers: HeaderMap,
) -> Result<Json<WalletChallenge>, (StatusCode, Json<ApiError>)> {
    let account = require_account(
        &state,
        &headers,
        "GET",
        "/v1/account/wallets/challenge",
        &[],
    )
    .await?;
    let address = query.address.to_ascii_lowercase();
    if !is_address(&address) {
        return Err(bad_request(
            "invalid_wallet_address",
            "wallet address must be a 20-byte EVM address",
        ));
    }
    state
        .store
        .create_wallet_challenge(&account.subject, &address)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn link_account_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let account =
        require_account(&state, &headers, "POST", "/v1/account/wallets/link", &body).await?;
    let request: WalletLinkRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    let address = request.wallet_address.to_ascii_lowercase();
    if !is_address(&address) {
        return Err(bad_request(
            "invalid_wallet_address",
            "wallet address must be a 20-byte EVM address",
        ));
    }
    let challenge = state
        .store
        .wallet_challenge(&account.subject, request.challenge_id, &address)
        .await
        .map_err(store_error)?;
    let recovered = recover_evm_signer(&challenge.message, &request.signature)
        .ok_or_else(|| store_error(StoreError::WalletSignatureInvalid))?;
    if recovered != address {
        return Err(store_error(StoreError::WalletSignatureInvalid));
    }
    state
        .store
        .consume_wallet_challenge(&account.subject, request.challenge_id, &address)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_vault_items(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<VaultItem>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/vault/items", &[]).await?;
    state
        .store
        .list_vault_items(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn get_vault_item(
    State(state): State<AppState>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<VaultItem>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/vault/items/{item_id}");
    let account = require_account(&state, &headers, "GET", &path, &[]).await?;
    state
        .store
        .vault_item(&account.subject, item_id)
        .await
        .map_err(store_error)?
        .map(Json)
        .ok_or_else(|| {
            not_found(
                "vault_item_not_found",
                "no such vault item for this account",
            )
        })
}

async fn put_vault_item(
    State(state): State<AppState>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<VaultItem>), (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/vault/items/{item_id}");
    let account = require_account(&state, &headers, "PUT", &path, &body).await?;
    let write: VaultWrite = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    validate_vault_write(&write)?;
    let created = write.previous_version.is_none();
    let item = state
        .store
        .write_vault_item(&account.subject, item_id, write)
        .await
        .map_err(store_error)?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(item)))
}

async fn delete_vault_item(
    State(state): State<AppState>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/vault/items/{item_id}");
    let account = require_account(&state, &headers, "DELETE", &path, &[]).await?;
    state
        .store
        .delete_vault_item(&account.subject, item_id)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn release_vault_item(
    State(state): State<AppState>,
    Path(item_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<VaultRelease>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/vault/items/{item_id}/release");
    let account = require_account(&state, &headers, "POST", &path, &body).await?;
    let request: VaultReleaseRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    state
        .store
        .release_vault_item(&account.subject, item_id, request.lease_id)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn list_vault_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<VaultRelease>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/vault/releases", &[]).await?;
    state
        .store
        .list_vault_releases(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

fn validate_vault_write(write: &VaultWrite) -> Result<(), (StatusCode, Json<ApiError>)> {
    let envelope = &write.envelope;
    let malformed = envelope.ciphertext.is_empty()
        || envelope.ciphertext.len() > MAX_VAULT_CIPHERTEXT_BYTES
        || envelope.wrapped_key.is_empty()
        || envelope.wrapped_key.len() > 1_024
        || envelope.nonce.is_empty()
        || envelope.nonce.len() > 64
        || write.label.len() > MAX_VAULT_LABEL_BYTES
        || !is_base64url(&envelope.ciphertext)
        || !is_base64url(&envelope.wrapped_key)
        || !is_base64url(&envelope.nonce);
    if malformed {
        return Err(bad_request(
            "invalid_vault_item",
            "vault envelope must be base64url and within the size limit",
        ));
    }
    if write.previous_version.is_some_and(|version| version == 0) {
        return Err(bad_request(
            "invalid_vault_item",
            "previous_version must be at least 1",
        ));
    }
    Ok(())
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Workspace>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/workspaces", &[]).await?;
    require_workspace_storage(&state)?;
    state
        .store
        .list_workspaces(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn create_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Workspace>), (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "POST", "/v1/workspaces", &body).await?;
    require_workspace_storage(&state)?;
    let request: WorkspaceRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    validate_workspace_name(&request.name)?;
    let workspace = state
        .store
        .create_workspace(&account.subject, &request.name, request.min_trust_class)
        .await
        .map_err(store_error)?;
    Ok((StatusCode::CREATED, Json(workspace)))
}

async fn delete_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/workspaces/{workspace_id}");
    let account = require_account(&state, &headers, "DELETE", &path, &[]).await?;
    let storage = require_workspace_storage(&state)?;
    let workspace = state
        .store
        .delete_workspace(&account.subject, workspace_id)
        .await
        .map_err(store_error)?;
    // Every version is a separate object and the row was the only record of
    // which ones exist, so they go now or they stay in the bucket forever. One
    // past the committed version catches bytes uploaded but never committed.
    for version in 1..=workspace.version + 1 {
        let key = workspaces::WorkspaceStorage::key(&account.subject, workspace_id, version as i32);
        if let Err(error) = storage.delete(&key).await {
            tracing::error!(%workspace_id, version, %error, "workspace object outlived its metadata");
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SnapshotUpload>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/workspaces/{workspace_id}/upload");
    let account = require_account(&state, &headers, "POST", &path, &body).await?;
    let storage = require_workspace_storage(&state)?;
    let request: SnapshotUploadRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    validate_snapshot_size(request.size_bytes)?;
    let workspace = require_workspace(&state, &account.subject, workspace_id).await?;
    // Only ever the next version, which by definition has nothing committed
    // against it. Presigning a version that does would hand out a URL that
    // overwrites bytes the renter still holds metadata for.
    let version = workspace.version + 1;
    let key = workspaces::WorkspaceStorage::key(&account.subject, workspace_id, version as i32);
    // Uploads are write-once, so an abandoned attempt would block every retry
    // at this version. Clearing it first is safe precisely because nothing is
    // committed here: no metadata the renter holds can refer to these bytes.
    if let Err(error) = storage.delete(&key).await {
        tracing::warn!(%workspace_id, version, %error, "could not clear an abandoned upload");
    }
    let url = storage
        .presign_put(&key, request.size_bytes as i64)
        .await
        .map_err(workspace_storage_error)?;
    // The URL carries its own authorization for as long as it lives, so the
    // record of handing one out never includes the URL itself.
    tracing::info!(%workspace_id, version, "presigned a workspace upload");
    Ok(Json(SnapshotUpload { url, version, key }))
}

async fn commit_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Workspace>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/workspaces/{workspace_id}/commit");
    let account = require_account(&state, &headers, "POST", &path, &body).await?;
    let storage = require_workspace_storage(&state)?;
    let request: SnapshotCommitRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    validate_snapshot_commit(&request)?;
    let workspace = require_workspace(&state, &account.subject, workspace_id).await?;
    if request.version != workspace.version + 1 {
        return Err(store_error(StoreError::WorkspaceVersionConflict));
    }
    let key =
        workspaces::WorkspaceStorage::key(&account.subject, workspace_id, request.version as i32);
    // Storage is the only party that knows what actually arrived. Without this
    // an account can record a snapshot it never uploaded and discover that at
    // restore, or declare a size it is not being billed for.
    match storage
        .object_size(&key)
        .await
        .map_err(workspace_storage_error)?
    {
        Some(size) if size == request.snapshot.size_bytes as i64 => {}
        Some(_) => {
            return Err(bad_request(
                "snapshot_size_mismatch",
                "the uploaded object is not the size this commit declares",
            ));
        }
        None => {
            return Err(bad_request(
                "snapshot_not_uploaded",
                "no object was uploaded for this version",
            ));
        }
    }
    let workspace = state
        .store
        .commit_workspace_snapshot(
            &account.subject,
            workspace_id,
            request.version,
            request.snapshot,
        )
        .await
        .map_err(store_error)?;
    // Only the current version is ever downloadable, so the one it replaced is
    // bytes nobody can read and everybody pays for. An agent checkpointing on a
    // timer would otherwise leave a day's worth behind. Best effort: the commit
    // has already succeeded and the renter should not be told it failed because
    // a cleanup did.
    if request.version > 1 {
        let stale = workspaces::WorkspaceStorage::key(
            &account.subject,
            workspace_id,
            request.version as i32 - 1,
        );
        if let Err(error) = storage.delete(&stale).await {
            tracing::warn!(%workspace_id, version = request.version - 1, %error, "could not remove a superseded snapshot");
        }
    }
    Ok(Json(workspace))
}

async fn download_workspace(
    State(state): State<AppState>,
    Path(workspace_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SnapshotDownload>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/workspaces/{workspace_id}/download");
    let account = require_account(&state, &headers, "POST", &path, &body).await?;
    let request: SnapshotDownloadRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    let storage = require_workspace_storage(&state)?;
    let workspace = require_workspace(&state, &account.subject, workspace_id).await?;
    let snapshot = committed_snapshot(&workspace)?.clone();

    // A restore is the moment a workspace lands on hardware someone else
    // administers, so it is gated exactly like a vault release. Enforcing this
    // in the client would be a courtesy; the renter's guarantee has to be that
    // the URL is never minted at all.
    let lease_trust_class = state
        .store
        .active_lease_trust_class(&account.subject, request.lease_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| {
            not_found(
                "workspace_lease_unavailable",
                "no active lease of yours with that id",
            )
        })?;
    if !vault_release_permitted(workspace.min_trust_class, lease_trust_class) {
        return Err(store_error(StoreError::VaultTrustFloorUnmet {
            floor: workspace.min_trust_class.label(),
            lease: lease_trust_class.label(),
        }));
    }

    let key =
        workspaces::WorkspaceStorage::key(&account.subject, workspace_id, workspace.version as i32);
    // A row can outlive its object: a lifecycle rule, a bucket-side deletion or
    // a lost upload all leave metadata pointing at nothing. Say so here rather
    // than handing over a URL that answers 404 and reads like a flaky network.
    if storage
        .object_size(&key)
        .await
        .map_err(workspace_storage_error)?
        .is_none()
    {
        return Err(not_found(
            "workspace_snapshot_missing",
            "the stored snapshot is no longer in storage",
        ));
    }
    let url = storage
        .presign_get(&key)
        .await
        .map_err(workspace_storage_error)?;
    tracing::info!(%workspace_id, version = workspace.version, "presigned a workspace download");
    Ok(Json(SnapshotDownload {
        url,
        version: workspace.version,
        snapshot,
    }))
}

/// Reads the workspace as the authenticated caller. That, plus deriving every
/// object key from the same subject rather than from the row, is what stops a
/// known workspace id from resolving to another account's snapshot.
async fn require_workspace(
    state: &AppState,
    subject: &str,
    workspace_id: Uuid,
) -> Result<Workspace, (StatusCode, Json<ApiError>)> {
    state
        .store
        .workspace(subject, workspace_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| store_error(StoreError::WorkspaceNotFound))
}

/// A workspace exists before it holds anything, so a restore has to be told
/// there is nothing to restore rather than handed a URL to a missing object.
fn committed_snapshot(
    workspace: &Workspace,
) -> Result<&WorkspaceSnapshot, (StatusCode, Json<ApiError>)> {
    workspace.snapshot.as_ref().ok_or_else(|| {
        not_found(
            "workspace_empty",
            "this workspace has no committed snapshot yet",
        )
    })
}

/// Names are the one part of a workspace this service can read, so they are
/// held to what belongs in a listing rather than to whatever the column takes.
fn validate_workspace_name(name: &str) -> Result<(), (StatusCode, Json<ApiError>)> {
    let malformed = name.trim().is_empty()
        || name.len() > MAX_WORKSPACE_NAME_BYTES
        || name.chars().any(char::is_control);
    if malformed {
        return Err(bad_request(
            "invalid_workspace_name",
            "a workspace name must be printable and at most 64 bytes",
        ));
    }
    Ok(())
}

fn validate_snapshot_size(size_bytes: u64) -> Result<(), (StatusCode, Json<ApiError>)> {
    if size_bytes == 0 || size_bytes > MAX_WORKSPACE_BYTES {
        return Err(bad_request(
            "invalid_snapshot_size",
            "a snapshot must be at least one byte and within the per-workspace cap",
        ));
    }
    if size_bytes > MAX_SNAPSHOT_UPLOAD_BYTES {
        return Err(bad_request(
            "snapshot_upload_too_large",
            "a snapshot larger than 5 GiB cannot be stored in a single upload",
        ));
    }
    Ok(())
}

fn validate_snapshot_commit(
    commit: &SnapshotCommitRequest,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let snapshot = &commit.snapshot;
    validate_snapshot_size(snapshot.size_bytes)?;
    let malformed = snapshot.wrapped_key.is_empty()
        || snapshot.wrapped_key.len() > 1_024
        || snapshot.nonce.is_empty()
        || snapshot.nonce.len() > 64
        || !is_base64url(&snapshot.wrapped_key)
        || !is_base64url(&snapshot.nonce)
        || !is_sha256_hex(&snapshot.ciphertext_digest);
    if malformed {
        return Err(bad_request(
            "invalid_snapshot",
            "a snapshot envelope must be base64url with a lowercase SHA-256 digest",
        ));
    }
    if commit.version == 0 || commit.version > i32::MAX as u32 {
        return Err(bad_request(
            "invalid_snapshot",
            "a snapshot version must be at least 1 and fit a 32-bit counter",
        ));
    }
    Ok(())
}

/// The digest column carries a hex constraint, so anything else would surface
/// as a storage failure instead of the bad request it is.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Refuses every workspace endpoint when no bucket is configured. Answering
/// the metadata calls alone would let a renter create workspaces and record
/// snapshots that no upload could ever have reached.
fn require_workspace_storage(
    state: &AppState,
) -> Result<&workspaces::WorkspaceStorage, (StatusCode, Json<ApiError>)> {
    state.workspaces.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError {
            code: "workspace_storage_unconfigured",
            message: "durable workspaces are not enabled on this deployment",
        }),
    ))
}

fn workspace_storage_error(error: anyhow::Error) -> (StatusCode, Json<ApiError>) {
    tracing::error!(%error, "workspace object storage failure");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError {
            code: "workspace_storage_unavailable",
            message: "workspace storage is temporarily unavailable",
        }),
    )
}

async fn get_supplier_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SupplierSummary>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/supplier/summary", &[]).await?;
    state
        .store
        .supplier_summary(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn apply_operator_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<OperatorAuditEvent>), (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "POST", "/v1/operator/controls", &body).await?;
    let request: OperatorControlRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    if request.reason.trim().len() < 8
        || request.reason.len() > 512
        || request.target_id.is_empty()
        || request.target_id.len() > 255
        || request
            .evidence_hash
            .as_ref()
            .is_some_and(|hash| !is_hash(hash))
        || (request.action.target_type() == "node" && !valid_node_id(&request.target_id))
    {
        return Err(bad_request(
            "invalid_operator_control",
            "operator control target, reason or evidence is invalid",
        ));
    }
    let event = state
        .store
        .apply_operator_control(&account.subject, request)
        .await
        .map_err(store_error)?;
    Ok((StatusCode::CREATED, Json(event)))
}

async fn list_operator_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorAuditEvent>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/operator/audit", &[]).await?;
    state
        .store
        .operator_audit(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn list_operator_disputes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorDispute>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/operator/disputes", &[]).await?;
    state
        .store
        .operator_disputes(&account.subject, state.chain.escrow_address())
        .await
        .map(Json)
        .map_err(store_error)
}

async fn record_telemetry(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(telemetry): Json<NodeTelemetry>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    if telemetry.node_id != node_id {
        return Err(bad_request(
            "node_mismatch",
            "path and payload node IDs differ",
        ));
    }
    let Some(mut offer) = state.store.offer(&node_id).await.map_err(internal_error)? else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before heartbeat",
        ));
    };
    let verifying_key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if telemetry.verify(&verifying_key).is_err() {
        return Err(bad_request(
            "unsigned_telemetry",
            "node telemetry must be signed",
        ));
    }
    if telemetry
        .observed_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_telemetry",
            "node telemetry is older than five minutes",
        ));
    }
    if telemetry.sequence == 0
        || telemetry.gpu_utilization_bps > 10_000
        || telemetry.gpu_memory_used_mib > offer.gpu.vram_mib
        || telemetry
            .active_lease
            .as_ref()
            .is_some_and(|lease| lease.parse::<u64>().is_err() || lease == "0" || lease.len() > 20)
        || (telemetry.active_lease.is_some() && telemetry.image_digest.is_none())
        || telemetry
            .image_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_digest(digest))
    {
        return Err(bad_request(
            "invalid_telemetry",
            "node telemetry contains values outside the advertised hardware limits",
        ));
    }
    offer.bonded = state
        .registry
        .verify_offer(&offer)
        .await
        .map_err(registry_error)?;
    offer.online = false;
    offer.updated_at = telemetry.observed_at;
    state
        .store
        .record_telemetry(&node_id, offer, telemetry)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// The nonce a node's GPU has to sign over. It is ours, single use, and bound
/// to this node id, which is what stops a report captured once, or taken from
/// another machine, standing in for this one.
async fn create_attestation_challenge(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<AttestationChallenge>, (StatusCode, Json<ApiError>)> {
    if !valid_node_id(&node_id) {
        return Err(bad_request(
            "invalid_node_id",
            "node ID must be a bytes32 hex value",
        ));
    }
    state
        .store
        .create_attestation_challenge(&node_id)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn record_attestation(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(attestation): Json<NodeAttestation>,
) -> Result<Json<AttestationVerdict>, (StatusCode, Json<ApiError>)> {
    if attestation.node_id != node_id {
        return Err(bad_request(
            "node_mismatch",
            "path and payload node IDs differ",
        ));
    }
    let Some(offer) = state.store.offer(&node_id).await.map_err(internal_error)? else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before it can attest",
        ));
    };
    check_attestation_envelope(&offer, &attestation)?;
    let verdict = state
        .store
        .record_attestation(AttestationSubmission {
            attestation: &attestation,
            device_public_key: &offer.device_public_key,
            policy: &state.attestation_policy,
            tdx_compose_allowlist: &state.tdx_compose_allowlist,
        })
        .await
        .map_err(store_error)?;
    Ok(Json(verdict))
}

/// Everything that can be judged from the envelope alone, before a challenge is
/// spent or a certificate chain is walked. The key is the one the node enrolled
/// with, so an attestation signed by anything else is somebody else's.
fn check_attestation_envelope(
    offer: &NodeOffer,
    attestation: &NodeAttestation,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if attestation.validate().is_err() {
        return Err(bad_request(
            "invalid_attestation",
            "attestation evidence is malformed or larger than this service accepts",
        ));
    }
    // Only kinds this service can actually check are let past the envelope:
    // a GPU device report, or a TDX quote carrying the event log and Intel
    // collateral its verification consumes. Anything else would be stored
    // unverified.
    match attestation.kind {
        AttestationKind::NvidiaGpu => {}
        AttestationKind::Tdx => {
            if attestation.tdx_collateral_json.is_none() || attestation.tdx_event_log.is_empty() {
                return Err(bad_request(
                    "incomplete_tdx_evidence",
                    "TDX attestations carry a quote, an event log and collateral",
                ));
            }
        }
        _ => {
            return Err(bad_request(
                "unsupported_attestation_kind",
                "this endpoint verifies NVIDIA GPU device reports and TDX quotes",
            ));
        }
    }
    let device_key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if attestation.verify(&device_key).is_err() {
        return Err(bad_request(
            "unsigned_attestation",
            "node attestation must be signed by the enrolled device identity",
        ));
    }
    if attestation
        .collected_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_attestation",
            "node attestation is older than five minutes",
        ));
    }
    Ok(())
}

async fn record_tunnel_observation(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(observation): Json<TunnelObservation>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let authorized = state.gateway_token.as_ref().is_some_and(|expected| {
        provided.is_some_and(|provided| constant_time_eq(provided, expected))
    });
    if !authorized {
        return Err(unauthorized(
            "gateway_identity_required",
            "a trusted access gateway must report tunnel state",
        ));
    }
    if !valid_node_id(&node_id)
        || !valid_internal_identifier(&observation.connection_id)
        || (state.require_node_certificates
            && !is_sha256_fingerprint(&observation.certificate_fingerprint))
        || (!observation.certificate_fingerprint.is_empty()
            && !is_sha256_fingerprint(&observation.certificate_fingerprint))
        || observation
            .observed_at
            .signed_duration_since(Utc::now())
            .num_seconds()
            .abs()
            > AUTH_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "invalid_tunnel_observation",
            "gateway tunnel observation is invalid or stale",
        ));
    }
    state
        .store
        .observe_tunnel(&node_id, observation, state.require_node_certificates)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn next_node_command(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(poll): Json<NodeCommandPoll>,
) -> Result<Json<Option<NodeCommand>>, (StatusCode, Json<ApiError>)> {
    verify_command_poll(&state, &node_id, &poll).await?;
    state
        .store
        .claim_command(&node_id, poll.request_id)
        .await
        .map(Json)
        .map_err(store_error)
}

async fn authorize_node_command(
    State(state): State<AppState>,
    Path((node_id, command_id)): Path<(String, Uuid)>,
    Json(poll): Json<NodeCommandPoll>,
) -> Result<Json<bool>, (StatusCode, Json<ApiError>)> {
    verify_command_poll(&state, &node_id, &poll).await?;
    state
        .store
        .authorize_command(&node_id, command_id, poll.request_id)
        .await
        .map(Json)
        .map_err(store_error)
}

/// The answer carries where the lease stands so the node can stop a container
/// whose lease ended early. A daemon that predates the field ignores it.
async fn report_node_command(
    State(state): State<AppState>,
    Path((node_id, command_id)): Path<(String, Uuid)>,
    Json(report): Json<NodeCommandReport>,
) -> Result<Json<NodeCommandReportAck>, (StatusCode, Json<ApiError>)> {
    if report.node_id != node_id
        || report.command_id != command_id
        || report
            .observed_at
            .signed_duration_since(Utc::now())
            .num_seconds()
            .abs()
            > NODE_MESSAGE_MAX_AGE_SECONDS
        || report
            .error
            .as_ref()
            .is_some_and(|error| error.is_empty() || error.len() > 512)
        || (report.outcome == NodeCommandOutcome::Failed && report.error.is_none())
        || (report.outcome != NodeCommandOutcome::Failed && report.error.is_some())
        || (report.outcome != NodeCommandOutcome::Completed && report.result.is_some())
        || report
            .result
            .as_ref()
            .is_some_and(|result| !result.within_limits())
        // A host key belongs to a session, and the ready report is the only one
        // that opens one.
        || (report.outcome != NodeCommandOutcome::Ready && report.channel_key.is_some())
    {
        return Err(bad_request(
            "invalid_command_report",
            "node command report is invalid or stale",
        ));
    }
    let Some(offer) = state.store.offer(&node_id).await.map_err(internal_error)? else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before reporting commands",
        ));
    };
    let key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if report.device_public_key != offer.device_public_key
        || report.verify(&key).is_err()
        || node_id != prism_protocol::node_id(&key)
    {
        return Err(unauthorized(
            "invalid_node_signature",
            "node command report must be signed by the enrolled device",
        ));
    }
    let channel_key_fingerprint = report
        .channel_key
        .as_deref()
        .map(prism_protocol::channel_key_fingerprint)
        .transpose()
        .map_err(|_| {
            bad_request(
                "invalid_channel_key",
                "workspace host key must be an OpenSSH public key line",
            )
        })?;
    let lease_state = state
        .store
        .report_command(&report, channel_key_fingerprint.as_deref())
        .await
        .map_err(store_error)?;
    Ok(Json(NodeCommandReportAck {
        lease_state: Some(lease_state),
    }))
}

async fn verify_command_poll(
    state: &AppState,
    path_node_id: &str,
    poll: &NodeCommandPoll,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if poll.node_id != path_node_id
        || poll
            .issued_at
            .signed_duration_since(Utc::now())
            .num_seconds()
            .abs()
            > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "invalid_command_poll",
            "node command poll is invalid or stale",
        ));
    }
    let Some(offer) = state
        .store
        .offer(path_node_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before polling commands",
        ));
    };
    let key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if poll.device_public_key != offer.device_public_key
        || poll.verify(&key).is_err()
        || path_node_id != node_id(&key)
    {
        return Err(unauthorized(
            "invalid_node_signature",
            "node command poll must be signed by the enrolled device",
        ));
    }
    Ok(())
}

/// Wallets whose stake counts for this account: the one it authenticated as,
/// plus any it has verified. An account cannot borrow a stranger's stake
/// because it never proved control of that wallet.
fn renter_wallets(account: &Account) -> Vec<String> {
    let mut wallets: Vec<String> = account
        .linked_wallets
        .iter()
        .map(|wallet| wallet.to_ascii_lowercase())
        .collect();
    if let Some(wallet) = account.subject.strip_prefix("wallet:") {
        let wallet = wallet.to_ascii_lowercase();
        if is_address(&wallet) && !wallets.contains(&wallet) {
            wallets.push(wallet);
        }
    }
    wallets.retain(|wallet| is_address(wallet));
    wallets
}

async fn match_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<LeaseQuote>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "POST", "/v1/leases/match", &body).await?;
    let payload: MatchRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    if account.risk_hold {
        return Err(forbidden("risk_hold", "this account cannot create a lease"));
    }
    if payload.request.duration_seconds == 0 || payload.request.duration_seconds > MAX_LEASE_SECONDS
    {
        return Err(bad_request(
            "invalid_duration",
            "duration exceeds the lease limit",
        ));
    }
    if !is_pinned_image(&payload.request.image) {
        return Err(bad_request(
            "image_not_pinned",
            "public OCI images must use an immutable digest",
        ));
    }
    if payload.request.min_vram_mib == 0 {
        return Err(bad_request(
            "invalid_gpu_request",
            "minimum GPU memory must be non-zero",
        ));
    }
    // Catch a doomed batch command here rather than after the renter has funded
    // an escrow for a job the node will refuse.
    if let Some(command) = payload.request.command.as_deref() {
        if command.trim().is_empty() {
            return Err(bad_request(
                "invalid_command",
                "a batch command cannot be empty",
            ));
        }
        if command.len() > MAX_BATCH_COMMAND_BYTES {
            return Err(bad_request(
                "invalid_command",
                "a batch command cannot exceed 8 KiB",
            ));
        }
    }
    if let Err(message) = validate_repro_request(&payload.request) {
        return Err(bad_request("invalid_repro", message));
    }
    if payload
        .request
        .preferred_node_id
        .as_deref()
        .is_some_and(|node_id| !is_hash(node_id))
    {
        return Err(bad_request(
            "invalid_node_id",
            "preferred node must be a 32-byte hex node id",
        ));
    }
    let staked = state
        .stake
        .eligible_whole_tokens(&renter_wallets(&account))
        .await;
    state
        .store
        .quote_for_escrow(
            &account.subject,
            &payload.request,
            staked,
            state.chain.active_escrow_address(),
        )
        .await
        .map(Json)
        .map_err(store_error)
}

async fn list_account_leases(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<LeaseRecord>>, (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "GET", "/v1/leases", &[]).await?;
    state
        .store
        .list_leases(&account.subject)
        .await
        .map(Json)
        .map_err(store_error)
}

/// A batch lease reports what its command printed. Until the node reports, and
/// for anyone who is not the renter, there is nothing here.
async fn get_lease_result(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<CommandResult>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/leases/{lease_id}/result");
    let account = require_account(&state, &headers, "GET", &path, &[]).await?;
    state
        .store
        .lease_result(&account.subject, lease_id)
        .await
        .map_err(internal_error)?
        .map(Json)
        .ok_or_else(|| not_found("result_not_ready", "this lease has no batch result yet"))
}

async fn get_lease_access(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<LeaseAccessResponse>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/leases/{lease_id}/access");
    let account = require_account(&state, &headers, "GET", &path, &[]).await?;
    let grant = match state
        .store
        .lease_access(&account.subject, lease_id)
        .await
        .map_err(store_error)?
    {
        Some(grant) => grant,
        None => {
            // "Not yet" and "never" look identical from here, and a caller that
            // cannot tell them apart waits out the whole provisioning window on
            // a lease that already failed. The escrow times the refund and
            // nothing here can pay it sooner, but the renter can at least stop
            // waiting and say why.
            let state = state
                .store
                .lease_state(&account.subject, lease_id)
                .await
                .map_err(store_error)?;
            return Err(match state {
                Some(ref state) if !state.can_still_open_access() => conflict(
                    "lease_not_servable",
                    "this lease will not open access: it is closing or already settled, and its escrow refunds on the contract's own schedule",
                ),
                _ => not_found(
                    "access_not_ready",
                    "lease access is unavailable until provider readiness and onchain start are final",
                ),
            });
        }
    };
    let access = match grant.access {
        StoredLeaseAccess::Gateway {
            token,
            jupyter_token,
            expires_at,
        } => LeaseAccess::Gateway {
            lease_id,
            token: state
                .credential_cipher
                .decrypt(&token)
                .map_err(|_| credential_error())?,
            gateway_host: state.public_gateway_host.as_ref().clone(),
            relay_port: state.public_relay_port,
            ssh_user: "workspace".to_owned(),
            jupyter_path: "/lab".to_owned(),
            gateway_ca: state.certificate_authority.certificate_pem.as_ref().clone(),
            jupyter_token: state
                .credential_cipher
                .decrypt(&jupyter_token)
                .map_err(|_| credential_error())?,
            expires_at,
        },
        StoredLeaseAccess::DirectSsh {
            host,
            port,
            expires_at,
        } => LeaseAccess::DirectSsh {
            lease_id,
            ssh_host: host,
            ssh_port: port,
            ssh_user: "root".to_owned(),
            expires_at,
        },
    };
    Ok(Json(LeaseAccessResponse {
        access,
        channel_key_fingerprint: grant
            .channel_key
            .as_ref()
            .map(|key| key.fingerprint.clone()),
        channel_key_source: grant.channel_key.map(|key| key.source),
    }))
}

/// Releasing a lease ends access and stops the meter. Settlement charges only
/// the seconds between access opening and this close, and the rest of the
/// deposit goes back to the renter once the escrow's dispute window, currently
/// 300 seconds, has run. The lease reads `closing` from here on and serves no
/// further credentials.
async fn release_lease(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<LeaseReleaseResponse>), (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/leases/{lease_id}/release");
    let account = require_account(&state, &headers, "POST", &path, &body).await?;
    let Some(release) = state
        .store
        .release_lease(&account.subject, lease_id)
        .await
        .map_err(store_error)?
    else {
        return Err(not_found("lease_not_found", "no such lease"));
    };
    lease_release_response(lease_id, &release)
}

fn lease_release_response(
    lease_id: u64,
    release: &LeaseRelease,
) -> Result<(StatusCode, Json<LeaseReleaseResponse>), (StatusCode, Json<ApiError>)> {
    let (status, state, release) = match release {
        LeaseRelease::Queued => (StatusCode::ACCEPTED, &LeaseState::Closing, "queued"),
        LeaseRelease::AlreadyClosed(state) => (StatusCode::OK, state, "already_closed"),
        LeaseRelease::NotYetOpen => {
            return Err(conflict(
                "lease_not_active",
                "this lease has not opened access yet; the escrow refunds a lease \
                 that never provisions on its own schedule",
            ));
        }
        LeaseRelease::Batch => {
            return Err(conflict(
                "lease_not_releasable",
                "a batch lease ends when its command reports; there is nothing to \
                 release early",
            ));
        }
    };
    Ok((
        status,
        Json(LeaseReleaseResponse {
            lease_id,
            state: lease_state_name(state),
            release,
        }),
    ))
}

/// The nonce the guest serving this lease has to answer. Handed out without an
/// account or a node signature, as on the node path: a nonce is worth nothing to
/// anyone who cannot produce a report the processor signed over it.
async fn create_lease_attestation_challenge(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
) -> Result<Json<AttestationChallenge>, (StatusCode, Json<ApiError>)> {
    state
        .store
        .create_lease_attestation_challenge(lease_id)
        .await
        .map(Json)
        .map_err(store_error)
}

/// A guest whose firmware was never loaded with certificates has none to send,
/// so the report arrives alone and there is nothing to walk to the AMD root.
/// The chip and TCB it names are enough to ask AMD for the certificate that
/// would settle it.
///
/// Steering this with a claimed chip id gains an attacker nothing. The
/// certificate they point us at carries a public key that cannot verify the
/// signature they sent, so the report is refused a moment later by the check
/// that was always going to decide it.
async fn fill_missing_certificate_chain(
    state: &AppState,
    attestation: &mut GuestAttestation,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if !attestation.certificate_chain_base64.is_empty() {
        return Ok(());
    }
    let Some(kds) = state.amd_kds.as_ref() else {
        return Err(bad_request(
            "certificate_chain_required",
            "this report carries no certificate chain and no certificate service is configured",
        ));
    };
    let report = STANDARD
        .decode(&attestation.report_base64)
        .map_err(|_| bad_request("malformed_report", "the report is not base64"))?;
    let origin = prism_attestation::claimed_origin(&report).map_err(|_| {
        bad_request(
            "malformed_report",
            "the report does not name a chip to fetch a certificate for",
        )
    })?;
    let chain = kds
        .chain_for(&origin.chip_id, &origin.reported_tcb)
        .await
        .map_err(|error| {
            tracing::warn!(%error, lease_id = attestation.lease_id, "could not fetch the AMD certificate chain");
            (
                StatusCode::BAD_GATEWAY,
                Json(ApiError {
                    code: "certificate_chain_unavailable",
                    message: "the certificate that would settle this report could not be fetched",
                }),
            )
        })?;
    attestation.certificate_chain_base64 = chain
        .into_iter()
        .map(|certificate| STANDARD.encode(certificate))
        .collect();
    Ok(())
}

async fn record_lease_attestation(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    Json(mut attestation): Json<GuestAttestation>,
) -> Result<Json<LeaseAttestationVerdict>, (StatusCode, Json<ApiError>)> {
    if attestation.lease_id != lease_id {
        return Err(bad_request(
            "lease_mismatch",
            "path and payload lease IDs differ",
        ));
    }
    let Some(lease) = state
        .store
        .lease_record(lease_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found("lease_not_found", "no such lease"));
    };
    // A report is about one lease on one machine. A node presenting somebody
    // else's lease is refused here rather than at the class check, so nothing
    // downstream has to reason about a verdict that was never plausible.
    if lease.node_id != attestation.node_id {
        return Err(forbidden(
            "node_mismatch",
            "this lease is not running on the node presenting the report",
        ));
    }
    if !accepts_guest_attestation(&lease.state) {
        return Err(store_error(StoreError::LeaseNotAttestable));
    }
    let Some(offer) = state
        .store
        .offer(&lease.node_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before it can attest",
        ));
    };
    check_guest_attestation_envelope(&offer, &attestation)?;
    fill_missing_certificate_chain(&state, &mut attestation).await?;
    let verdict = state
        .store
        .record_lease_attestation(LeaseAttestationSubmission {
            attestation: &attestation,
            lease: &lease,
            policy: &state.attestation_policy,
        })
        .await
        .map_err(store_error)?;
    Ok(Json(verdict))
}

/// Everything that can be judged from the envelope alone, before a challenge is
/// spent or a certificate chain is walked. The node's key signs the envelope
/// because the host carries the report; it does not vouch for what is inside,
/// and cannot, since the report is signed by a processor it does not hold a key
/// for.
fn check_guest_attestation_envelope(
    offer: &NodeOffer,
    attestation: &GuestAttestation,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if attestation.validate().is_err() {
        return Err(bad_request(
            "invalid_attestation",
            "attestation evidence is malformed or larger than this service accepts",
        ));
    }
    if attestation.kind != AttestationKind::SevSnp {
        return Err(bad_request(
            "unsupported_attestation_kind",
            "this endpoint verifies SEV-SNP guest reports",
        ));
    }
    let device_key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if attestation.verify(&device_key).is_err() {
        return Err(bad_request(
            "unsigned_attestation",
            "guest attestation must be signed by the enrolled device identity",
        ));
    }
    if attestation
        .collected_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_attestation",
            "guest attestation is older than five minutes",
        ));
    }
    Ok(())
}

/// The TDX guest report for a lease. A TD answers the same lease challenge the
/// SEV-SNP guest would, so the guest challenge endpoint serves both; only the
/// quote it returns lands here.
async fn record_lease_tdx_attestation(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    Json(attestation): Json<TdxLeaseAttestation>,
) -> Result<Json<LeaseTdxGuestVerdict>, (StatusCode, Json<ApiError>)> {
    if attestation.lease_id != lease_id {
        return Err(bad_request(
            "lease_mismatch",
            "path and payload lease IDs differ",
        ));
    }
    let Some(lease) = state
        .store
        .lease_record(lease_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found("lease_not_found", "no such lease"));
    };
    if lease.node_id != attestation.node_id {
        return Err(forbidden(
            "node_mismatch",
            "this lease is not running on the node presenting the report",
        ));
    }
    if !accepts_guest_attestation(&lease.state) {
        return Err(store_error(StoreError::LeaseNotAttestable));
    }
    let Some(offer) = state
        .store
        .offer(&lease.node_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before it can attest",
        ));
    };
    check_tdx_lease_attestation_envelope(&offer, &attestation)?;
    let verdict = state
        .store
        .record_lease_tdx_attestation(LeaseTdxAttestationSubmission {
            attestation: &attestation,
            lease: &lease,
            policy: &state.attestation_policy,
        })
        .await
        .map_err(store_error)?;
    Ok(Json(verdict))
}

/// The nonce the GPU serving this lease answers. Handed out without an account
/// or a node signature, as on the guest path: a nonce is worth nothing to
/// anyone who cannot produce a report the device signed over it.
async fn create_lease_gpu_cc_attestation_challenge(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
) -> Result<Json<AttestationChallenge>, (StatusCode, Json<ApiError>)> {
    state
        .store
        .create_lease_gpu_cc_attestation_challenge(lease_id)
        .await
        .map(Json)
        .map_err(store_error)
}

/// The GPU confidential-computing report for a lease. It answers its own
/// challenge, so the device signs over the nonce this endpoint's challenge
/// counterpart issued, never the guest one.
async fn record_lease_gpu_cc_attestation(
    State(state): State<AppState>,
    Path(lease_id): Path<u64>,
    Json(attestation): Json<GpuCcAttestation>,
) -> Result<Json<LeaseGpuCcVerdict>, (StatusCode, Json<ApiError>)> {
    if attestation.lease_id != lease_id {
        return Err(bad_request(
            "lease_mismatch",
            "path and payload lease IDs differ",
        ));
    }
    let Some(lease) = state
        .store
        .lease_record(lease_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found("lease_not_found", "no such lease"));
    };
    if lease.node_id != attestation.node_id {
        return Err(forbidden(
            "node_mismatch",
            "this lease is not running on the node presenting the report",
        ));
    }
    if !accepts_guest_attestation(&lease.state) {
        return Err(store_error(StoreError::LeaseNotAttestable));
    }
    let Some(offer) = state
        .store
        .offer(&lease.node_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(not_found(
            "node_not_found",
            "node must be enrolled before it can attest",
        ));
    };
    check_gpu_cc_attestation_envelope(&offer, &attestation)?;
    let verdict = state
        .store
        .record_lease_gpu_cc_attestation(LeaseGpuCcAttestationSubmission {
            attestation: &attestation,
            lease: &lease,
            policy: &state.attestation_policy,
        })
        .await
        .map_err(store_error)?;
    Ok(Json(verdict))
}

/// The TDX counterpart of `check_guest_attestation_envelope`. The node's key
/// signs the courier envelope; it does not vouch for the quote inside, which
/// the TD sealed with a key the host does not hold.
fn check_tdx_lease_attestation_envelope(
    offer: &NodeOffer,
    attestation: &TdxLeaseAttestation,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if attestation.validate().is_err() {
        return Err(bad_request(
            "invalid_attestation",
            "attestation evidence is malformed or larger than this service accepts",
        ));
    }
    let device_key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if attestation.verify(&device_key).is_err() {
        return Err(bad_request(
            "unsigned_attestation",
            "guest attestation must be signed by the enrolled device identity",
        ));
    }
    if attestation
        .collected_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_attestation",
            "guest attestation is older than five minutes",
        ));
    }
    Ok(())
}

/// The GPU-CC counterpart. Same courier model: the node signs which node is
/// presenting the report, the device signs the report itself.
fn check_gpu_cc_attestation_envelope(
    offer: &NodeOffer,
    attestation: &GpuCcAttestation,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if attestation.validate().is_err() {
        return Err(bad_request(
            "invalid_attestation",
            "attestation evidence is malformed or larger than this service accepts",
        ));
    }
    let device_key = verifying_key(&offer.device_public_key)
        .map_err(|_| bad_request("invalid_device_key", "node device key is invalid"))?;
    if attestation.verify(&device_key).is_err() {
        return Err(bad_request(
            "unsigned_attestation",
            "gpu attestation must be signed by the enrolled device identity",
        ));
    }
    if attestation
        .collected_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .abs()
        > NODE_MESSAGE_MAX_AGE_SECONDS
    {
        return Err(bad_request(
            "stale_attestation",
            "gpu attestation is older than five minutes",
        ));
    }
    Ok(())
}

async fn confirm_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<LeaseRecord>), (StatusCode, Json<ApiError>)> {
    let account = require_account(&state, &headers, "POST", "/v1/leases/confirm", &body).await?;
    if account.risk_hold {
        return Err(forbidden(
            "risk_hold",
            "this account cannot confirm a lease",
        ));
    }
    let request: ConfirmLeaseRequest = serde_json::from_slice(&body)
        .map_err(|_| bad_request("invalid_json", "request body is not valid JSON"))?;
    if !is_hash(&request.transaction_hash) {
        return Err(bad_request(
            "invalid_transaction_hash",
            "funding transaction hash must be 32-byte hex",
        ));
    }
    let quote = state
        .store
        .quote_for_subject(&account.subject, request.quote_id)
        .await
        .map_err(store_error)?;
    let ssh_authorized_key = request.ssh_authorized_key.as_deref();
    if quote.command.is_none() && !ssh_authorized_key.is_some_and(is_ssh_authorized_key) {
        return Err(bad_request(
            "invalid_ssh_key",
            "interactive access requires one Ed25519 public key",
        ));
    }
    let funding = state
        .chain
        .verify_funding(&request.transaction_hash, &quote)
        .await
        .map_err(chain_error)?;
    let jupyter_token = generate_jupyter_token();
    let encrypted_jupyter_token = state
        .credential_cipher
        .encrypt(&jupyter_token)
        .map_err(|_| credential_error())?;
    let lease = state
        .store
        .confirm_funding(FundingConfirmation {
            subject: &account.subject,
            quote: &quote,
            transaction_hash: &request.transaction_hash,
            funding,
            ssh_authorized_key,
            jupyter_token: &jupyter_token,
            encrypted_jupyter_token,
        })
        .await
        .map_err(store_error)?;
    Ok((StatusCode::CREATED, Json(lease)))
}

async fn revoke_account_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let identity = state
        .identity
        .verify(&headers, "POST", "/v1/account/session/revoke", &body)
        .map_err(identity_error)?;
    state
        .store
        .revoke_session(identity)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn embedded_migrator() -> Migrator {
    Migrator {
        migrations: Cow::Owned(vec![
            Migration::new(
                1,
                Cow::Borrowed("marketplace"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0001_marketplace.sql")),
                false,
            ),
            Migration::new(
                2,
                Cow::Borrowed("account controls"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0002_account_controls.sql")),
                false,
            ),
            Migration::new(
                3,
                Cow::Borrowed("lease indexing"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0003_leases.sql")),
                false,
            ),
            Migration::new(
                4,
                Cow::Borrowed("node commands"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0004_node_commands.sql")),
                false,
            ),
            Migration::new(
                5,
                Cow::Borrowed("lease lifecycle"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0005_lifecycle.sql")),
                false,
            ),
            Migration::new(
                6,
                Cow::Borrowed("operational controls"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0006_operations.sql")),
                false,
            ),
            Migration::new(
                7,
                Cow::Borrowed("cloud broker"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0007_cloud_broker.sql")),
                false,
            ),
            Migration::new(
                8,
                Cow::Borrowed("cloud instance rejections"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0008_cloud_instance_rejections.sql"
                )),
                false,
            ),
            Migration::new(
                9,
                Cow::Borrowed("machine rejections"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0009_machine_rejections.sql")),
                false,
            ),
            Migration::new(
                10,
                Cow::Borrowed("service versions"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0010_service_versions.sql")),
                false,
            ),
            Migration::new(
                11,
                Cow::Borrowed("renter vault"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0011_vault.sql")),
                false,
            ),
            Migration::new(
                12,
                Cow::Borrowed("batch results"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0012_batch_results.sql")),
                false,
            ),
            Migration::new(
                13,
                Cow::Borrowed("capacity prices"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0013_capacity_prices.sql")),
                false,
            ),
            Migration::new(
                14,
                Cow::Borrowed("escrow generation"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0014_escrow_generation.sql")),
                false,
            ),
            Migration::new(
                15,
                Cow::Borrowed("cloud liveness"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0015_cloud_liveness.sql")),
                false,
            ),
            Migration::new(
                16,
                Cow::Borrowed("workspaces"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0016_workspaces.sql")),
                false,
            ),
            Migration::new(
                17,
                Cow::Borrowed("node attestation"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0017_node_attestation.sql")),
                false,
            ),
            Migration::new(
                18,
                Cow::Borrowed("lease attestation"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0018_lease_attestation.sql")),
                false,
            ),
            Migration::new(
                19,
                Cow::Borrowed("node command polling"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0019_node_command_polling.sql")),
                false,
            ),
            Migration::new(
                20,
                Cow::Borrowed("lease confidential attestation"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0020_lease_confidential_attestation.sql"
                )),
                false,
            ),
            Migration::new(
                21,
                Cow::Borrowed("batch authorization"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0021_batch_authorization.sql")),
                false,
            ),
            Migration::new(
                22,
                Cow::Borrowed("managed repros"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0022_managed_repros.sql")),
                false,
            ),
            Migration::new(
                23,
                Cow::Borrowed("repro token claims"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0023_repro_token_claims.sql")),
                false,
            ),
            Migration::new(
                24,
                Cow::Borrowed("provider admission"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0024_provider_admission.sql")),
                false,
            ),
            Migration::new(
                25,
                Cow::Borrowed("lifecycle transaction attempts"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0025_lifecycle_transaction_attempts.sql"
                )),
                false,
            ),
            Migration::new(
                26,
                Cow::Borrowed("settlement transaction attempts"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0026_settlement_attempts.sql")),
                false,
            ),
            Migration::new(
                27,
                Cow::Borrowed("proof receipt identity"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!(
                    "../migrations/0027_proof_receipt_identity.sql"
                )),
                false,
            ),
            Migration::new(
                28,
                Cow::Borrowed("provider maintenance"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0028_provider_maintenance.sql")),
                false,
            ),
            Migration::new(
                29,
                Cow::Borrowed("lease channel key"),
                MigrationType::Simple,
                Cow::Borrowed(include_str!("../migrations/0029_lease_channel_key.sql")),
                false,
            ),
        ]),
        ..Migrator::DEFAULT
    }
}

/// A quote holds its node only for the funding round trip, not for the whole
/// five minutes it stays valid.
fn holds_node(quote: &LeaseQuote) -> bool {
    let issued_at = quote.expires_at - Duration::minutes(QUOTE_TTL_MINUTES);
    Utc::now() < issued_at + Duration::seconds(QUOTE_HOLD_SECONDS)
}

fn quote_matches_request(quote: &LeaseQuote, request: &LeaseRequest) -> bool {
    quote.image == request.image
        && quote.duration_seconds == request.duration_seconds
        && quote.min_vram_mib == request.min_vram_mib
        && quote.trust_class >= request.min_trust_class
        && quote.command == request.command
        && quote.repro == request.repro
        && request
            .preferred_node_id
            .as_ref()
            .is_none_or(|node_id| node_id == &quote.node_id)
}

/// The cheapest staker-only rate this renter may reach. The escrow charges a
/// node's registered rate, not anything this service quotes, so a discount
/// cannot be written into the quote: it has to decide which capacity a renter
/// is allowed to match against. Locking PRISM unlocks the cheaper pool.
fn rate_floor_for_stake(staked_whole_tokens: u64) -> u64 {
    discounted_rate(
        STANDARD_RATE_PER_SECOND,
        stake_discount_bps(staked_whole_tokens),
    )
}

fn quote_for_offers<'a>(
    request: &LeaseRequest,
    offers: impl IntoIterator<Item = &'a NodeOffer>,
    reserved: &BTreeSet<String>,
    staked_whole_tokens: u64,
) -> Result<LeaseQuote, StoreError> {
    let rate_floor = rate_floor_for_stake(staked_whole_tokens);
    let cutoff = Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS);
    let mut compatible = offers
        .into_iter()
        .filter(|offer| offer.online && offer.bonded && offer.public_image_only)
        .filter(|offer| offer.updated_at >= cutoff)
        .filter(|offer| offer.gpu.vram_mib >= request.min_vram_mib)
        .filter(|offer| offer.trust_class >= request.min_trust_class)
        // Capacity set aside for stakers, unlocked by having enough locked long
        // enough. Gating on the offer's own flag rather than on its price keeps
        // a cheap independent node visible to everybody.
        .filter(|offer| !offer.staker_only || offer.rate_per_second >= rate_floor)
        // A repro approval fixes its executor as well as its workload. Capacity
        // changing between preparation and matching must fail or re-quote, not
        // silently move the command across a different trust boundary.
        .filter(|offer| {
            request.repro.as_ref().map_or_else(
                || request.command.is_none() || offer.command_channel,
                |capability| match capability.executor {
                    ReproExecutor::Node => offer.command_channel,
                    ReproExecutor::Managed => offer.managed_batch,
                },
            )
        })
        .filter(|offer| {
            request
                .preferred_node_id
                .as_ref()
                .is_none_or(|node_id| node_id == &offer.node_id)
        })
        .peekable();
    if compatible.peek().is_none() {
        return Err(StoreError::NoMatch);
    }
    // Capacity that exists but is spoken for is a different answer than no
    // capacity at all: one clears on its own, the other needs supply.
    let selected = compatible
        .filter(|offer| !reserved.contains(&offer.node_id))
        .min_by_key(|offer| {
            (
                offer.rate_per_second,
                Reverse(offer.reliability_bps),
                Reverse(offer.benchmark_score),
            )
        })
        .ok_or(StoreError::CapacityReserved)?;
    let maximum_escrow = selected
        .rate_per_second
        .saturating_mul(request.duration_seconds as u64);
    if maximum_escrow > MAX_ESCROW_BASE_UNITS {
        return Err(StoreError::EscrowLimit);
    }
    Ok(LeaseQuote {
        quote_id: Uuid::now_v7(),
        node_id: selected.node_id.clone(),
        image: request.image.clone(),
        duration_seconds: request.duration_seconds,
        min_vram_mib: request.min_vram_mib,
        rate_per_second: selected.rate_per_second,
        maximum_escrow,
        trust_class: selected.trust_class,
        command: request.command.clone(),
        repro: request.repro.clone(),
        expires_at: Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES),
    })
}

fn confirmed_cloud_execution(
    quote: &LeaseQuote,
    managed_available: bool,
    node_available: bool,
) -> Result<bool, StoreError> {
    match quote.repro.as_ref().map(|repro| repro.executor) {
        Some(ReproExecutor::Managed) if managed_available => Ok(true),
        Some(ReproExecutor::Node) if node_available => Ok(false),
        Some(_) => Err(StoreError::ReproExecutorUnavailable),
        None => Ok(quote.command.is_none() && managed_available),
    }
}

fn is_pinned_image(image: &str) -> bool {
    if image.is_empty() || image.len() > 512 || image.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    if repository.is_empty()
        || repository.starts_with('/')
        || repository.ends_with('/')
        || repository.contains("//")
        || repository.split('/').any(|part| matches!(part, "." | ".."))
        || !repository.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'[' | b']' | b'/')
        })
        || !is_lower_sha256(digest)
    {
        return false;
    }

    let first = repository.split('/').next().unwrap_or_default();
    let explicit_registry = first.contains('.')
        || first.contains(':')
        || first.starts_with('[')
        || first.eq_ignore_ascii_case("localhost");
    if !explicit_registry {
        return true;
    }
    if first.contains(':') {
        return false;
    }
    let Ok(reference) = url::Url::parse(&format!("https://{repository}")) else {
        return false;
    };
    reference.username().is_empty()
        && reference.password().is_none()
        && reference.query().is_none()
        && reference.fragment().is_none()
        && reference.port().is_none()
        && reference.host_str().is_some_and(is_trusted_registry_host)
}

fn is_trusted_registry_host(host: &str) -> bool {
    let normalized = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "docker.io"
            | "index.docker.io"
            | "registry-1.docker.io"
            | "quay.io"
            | "nvcr.io"
            | "public.ecr.aws"
            | "mcr.microsoft.com"
            | "registry.k8s.io"
            | "gcr.io"
            | "ghcr.io"
            | "registry.prismnetwork.tech"
    ) || normalized.ends_with(".pkg.dev")
}

fn canonical_repro_token_hash(token: &str) -> Option<String> {
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return None;
    }
    repro_token_hash(token).ok()
}

fn build_repro_status(
    token_hash: &str,
    stored: StoredReproStatus,
) -> Result<ReproStatusResponse, StoreError> {
    let capability = stored.quote.repro.clone().ok_or_else(|| {
        StoreError::InvalidStoredState("repro quote has no capability".to_owned())
    })?;
    let command_text =
        stored.quote.command.clone().ok_or_else(|| {
            StoreError::InvalidStoredState("repro quote has no command".to_owned())
        })?;
    let spec = GpuReproSpec {
        image: stored.quote.image.clone(),
        command: command_text,
        duration_seconds: stored.quote.duration_seconds,
        min_vram_mib: stored.quote.min_vram_mib,
        expected_exit_code: capability.expected_exit_code,
    };
    let mut checks = ReproStatusChecks {
        token_bound: capability.token_hash == token_hash,
        spec_hash_valid: spec.hash().ok().as_deref() == Some(capability.spec_hash.as_str()),
        command_bound: None,
        report_signature_valid: None,
        executor_identity_valid: None,
        report_bound: None,
        receipt_hash_valid: None,
        receipt_bound: None,
        expected_exit_code: None,
    };
    let mut response = ReproStatusResponse {
        version: REPRO_STATUS_VERSION,
        status: ReproStatus::Quoted,
        executor: capability.executor,
        spec,
        spec_hash: capability.spec_hash.clone(),
        quote_id: stored.quote.quote_id,
        maximum_escrow: stored.quote.maximum_escrow,
        lease_id: None,
        lease_state: None,
        command_status: None,
        result: None,
        evidence: None,
        checks: checks.clone(),
    };
    let Some(lease) = stored.lease else {
        return Ok(response);
    };

    checks.token_bound &= lease.token_hash.as_deref() == Some(token_hash);
    checks.spec_hash_valid &= lease.spec_hash.as_deref() == Some(capability.spec_hash.as_str());
    response.lease_id = Some(lease.lease_id);
    response.lease_state = Some(lease.state.clone());

    let mut execution_status = None;
    let mut execution_outcome = None;
    if let Some(execution) = lease.execution.as_ref() {
        if !matches!(
            (capability.executor, execution),
            (ReproExecutor::Node, StoredReproExecution::Node { .. })
                | (ReproExecutor::Managed, StoredReproExecution::Managed { .. })
        ) {
            return Err(StoreError::InvalidStoredState(
                "repro execution does not match its approved executor".to_owned(),
            ));
        }
        match execution {
            StoredReproExecution::Node {
                status,
                command,
                report,
                result,
                enrolled_device_public_key,
            } => {
                execution_status = Some(status.as_str());
                checks.command_bound = Some(repro_command_bound(command, &lease, &response.spec));
                ensure_public_repro_command(command)?;
                response.result = report
                    .as_ref()
                    .and_then(|report| report.result.clone())
                    .or_else(|| result.clone());
                if let Some(report) = report {
                    execution_outcome = Some(&report.outcome);
                    if final_command_outcome(&report.outcome) {
                        checks.report_signature_valid = Some(native_report_signature_valid(report));
                        checks.executor_identity_valid = Some(native_executor_identity_valid(
                            report,
                            enrolled_device_public_key.as_deref(),
                            &lease.node_id,
                        ));
                        checks.report_bound = Some(native_report_bound(
                            report,
                            command,
                            &lease,
                            enrolled_device_public_key.as_deref(),
                        ));
                        let signed_report = ReproExecutionReport::Node {
                            report: report.clone(),
                        };
                        attach_repro_evidence(
                            &mut response,
                            &mut checks,
                            &lease,
                            &capability,
                            command,
                            signed_report,
                        );
                    }
                }
            }
            StoredReproExecution::Managed {
                status,
                command,
                report,
            } => {
                execution_status = Some(status.as_str());
                checks.command_bound = Some(repro_command_bound(command, &lease, &response.spec));
                ensure_public_repro_command(command)?;
                if let Some(report) = report {
                    execution_outcome = Some(&report.outcome);
                    response.result = report.result.clone();
                    if final_command_outcome(&report.outcome) {
                        checks.report_signature_valid = Some(report.verify().is_ok());
                        checks.report_bound = Some(managed_report_bound(
                            report,
                            command,
                            &lease,
                            &response.spec,
                        ));
                        let signed_report = ReproExecutionReport::Managed {
                            report: report.clone(),
                        };
                        attach_repro_evidence(
                            &mut response,
                            &mut checks,
                            &lease,
                            &capability,
                            command,
                            signed_report,
                        );
                    }
                }
            }
        }
    }
    checks.expected_exit_code = response
        .result
        .as_ref()
        .map(|result| result.exit_code == response.spec.expected_exit_code);
    response.status = derive_repro_status(&lease.state, execution_status, execution_outcome);
    response.command_status = execution_status.map(str::to_owned);
    response.checks = checks;
    Ok(response)
}

fn final_command_outcome(outcome: &NodeCommandOutcome) -> bool {
    matches!(
        outcome,
        NodeCommandOutcome::Completed | NodeCommandOutcome::Failed
    )
}

fn derive_repro_status(
    state: &LeaseState,
    command_status: Option<&str>,
    outcome: Option<&NodeCommandOutcome>,
) -> ReproStatus {
    match state {
        LeaseState::Finalized => return ReproStatus::Settled,
        LeaseState::Refunded => return ReproStatus::Refunded,
        LeaseState::Disputed => return ReproStatus::Disputed,
        _ => {}
    }
    if *state == LeaseState::Failed
        || command_status == Some("failed")
        || outcome == Some(&NodeCommandOutcome::Failed)
    {
        return ReproStatus::Failed;
    }
    if matches!(state, LeaseState::Closing | LeaseState::SettlementPending) {
        return ReproStatus::Settling;
    }
    if outcome == Some(&NodeCommandOutcome::Completed) {
        return ReproStatus::Completed;
    }
    if matches!(command_status, Some("launching" | "running")) {
        return ReproStatus::Running;
    }
    if command_status == Some("ready") || *state == LeaseState::Ready {
        return ReproStatus::Ready;
    }
    if command_status == Some("preparing") || *state == LeaseState::Provisioning {
        return ReproStatus::Preparing;
    }
    if *state == LeaseState::Active {
        return ReproStatus::Running;
    }
    ReproStatus::Funded
}

fn repro_command_bound(
    command: &NodeCommand,
    lease: &StoredReproLease,
    spec: &GpuReproSpec,
) -> bool {
    command.command_id != Uuid::nil()
        && command.node_id == lease.node_id
        && command.lease_id == lease.lease_id
        && command.expires_at > command.issued_at
        && matches!(
            &command.kind,
            NodeCommandKind::Batch {
                image,
                command: text,
                duration_seconds,
            } if image == &spec.image
                && text == &spec.command
                && *duration_seconds == spec.duration_seconds
        )
}

fn ensure_public_repro_command(command: &NodeCommand) -> Result<(), StoreError> {
    if matches!(command.kind, NodeCommandKind::Batch { .. }) {
        return Ok(());
    }
    Err(StoreError::InvalidStoredState(
        "repro execution contains a credential-bearing command".to_owned(),
    ))
}

fn native_report_signature_valid(report: &NodeCommandReport) -> bool {
    verifying_key(&report.device_public_key)
        .ok()
        .is_some_and(|key| report.verify(&key).is_ok())
}

fn native_executor_identity_valid(
    report: &NodeCommandReport,
    enrolled_key: Option<&str>,
    expected_node_id: &str,
) -> bool {
    enrolled_key == Some(report.device_public_key.as_str())
        && enrolled_key
            .and_then(|encoded| verifying_key(encoded).ok())
            .is_some_and(|key| {
                node_id(&key) == expected_node_id && report.node_id == expected_node_id
            })
}

fn native_report_bound(
    report: &NodeCommandReport,
    command: &NodeCommand,
    lease: &StoredReproLease,
    enrolled_key: Option<&str>,
) -> bool {
    let outcome_bound = match report.outcome {
        NodeCommandOutcome::Completed => report.error.is_none() && report.result.is_some(),
        NodeCommandOutcome::Failed => {
            report
                .error
                .as_ref()
                .is_some_and(|error| !error.is_empty() && error.len() <= 512)
                && report.result.is_none()
        }
        NodeCommandOutcome::Ready => false,
    };
    report.node_id == lease.node_id
        && enrolled_key == Some(report.device_public_key.as_str())
        && report.command_id == command.command_id
        && !report.request_id.is_nil()
        && report.observed_at >= command.issued_at
        && outcome_bound
        && report
            .result
            .as_ref()
            .is_none_or(|result| result.within_limits() && (-255..=255).contains(&result.exit_code))
}

fn managed_report_bound(
    report: &ManagedCommandReport,
    command: &NodeCommand,
    lease: &StoredReproLease,
    spec: &GpuReproSpec,
) -> bool {
    let duration = report
        .finished_at
        .signed_duration_since(report.started_at)
        .num_seconds();
    let outcome_bound = match report.outcome {
        NodeCommandOutcome::Completed => report.error.is_none() && report.result.is_some(),
        NodeCommandOutcome::Failed => {
            report
                .error
                .as_ref()
                .is_some_and(|error| !error.is_empty() && error.len() <= 512)
                && report.result.is_none()
        }
        NodeCommandOutcome::Ready => false,
    };
    !report.report_id.is_nil()
        && report.command_id == command.command_id
        && report.lease_id == lease.lease_id
        && report.provider == ManagedProvider::Vast
        && report.provider_instance_id > 0
        && !report.gpu_model.trim().is_empty()
        && report.gpu_model.len() <= 128
        && report.gpu_vram_mib >= spec.min_vram_mib
        && report.gpu_vram_mib <= 196_608
        && is_lower_sha256(&report.transport_host_key_sha256)
        && report.started_at >= command.issued_at
        && duration >= 0
        && duration <= i64::from(spec.duration_seconds)
        && outcome_bound
        && report
            .result
            .as_ref()
            .is_none_or(|result| result.within_limits() && (-255..=255).contains(&result.exit_code))
}

fn attach_repro_evidence(
    response: &mut ReproStatusResponse,
    checks: &mut ReproStatusChecks,
    lease: &StoredReproLease,
    capability: &prism_protocol::ReproCapability,
    command: &NodeCommand,
    report: ReproExecutionReport,
) {
    let result = match &report {
        ReproExecutionReport::Node { report } => report.result.as_ref(),
        ReproExecutionReport::Managed { report } => report.result.as_ref(),
    };
    if let Some(receipt) = lease.receipt.as_ref() {
        checks.receipt_hash_valid = Some(receipt_hash_matches(receipt).unwrap_or(false));
        checks.receipt_bound = Some(result.is_some_and(|result| {
            repro_receipt_bound(
                receipt,
                lease,
                capability,
                &response.spec,
                command,
                &report,
                result,
            )
        }));
    }
    response.evidence = Some(ReproStatusEvidence {
        command: command.clone(),
        report,
        receipt: lease.receipt.clone(),
    });
}

fn repro_receipt_bound(
    receipt: &PublicReceipt,
    lease: &StoredReproLease,
    capability: &prism_protocol::ReproCapability,
    spec: &GpuReproSpec,
    command: &NodeCommand,
    report: &ReproExecutionReport,
    result: &CommandResult,
) -> bool {
    let Some(repro) = receipt.repro.as_ref() else {
        return false;
    };
    let image_digest = spec.image.rsplit_once('@').map(|(_, digest)| digest);
    let (executor, report_hash) = match report {
        ReproExecutionReport::Node { report } => {
            (ReproExecutor::Node, repro_report_hash(report).ok())
        }
        ReproExecutionReport::Managed { report } => (
            ReproExecutor::Managed,
            managed_repro_report_hash(report).ok(),
        ),
    };
    receipt.receipt_id != Uuid::nil()
        && receipt.outcome == ReceiptOutcome::Finalized
        && receipt.lease_id == lease.chain_lease_id.to_string()
        && receipt.node_id_hash
            == format!(
                "0x{}",
                hex::encode(Sha256::digest(lease.node_id.as_bytes()))
            )
        && is_hash(&receipt.transaction_hash)
        && repro.executor == executor
        && capability.executor == executor
        && repro.token_hash == capability.token_hash
        && repro.spec_hash == capability.spec_hash
        && image_digest == Some(repro.image_digest.as_str())
        && repro_command_hash(command).ok().as_deref() == Some(repro.command_hash.as_str())
        && repro_result_hash(result).ok().as_deref() == Some(repro.result_hash.as_str())
        && repro.stdout_hash == repro_stream_hash(&result.stdout)
        && repro.stderr_hash == repro_stream_hash(&result.stderr)
        && report_hash.as_deref() == Some(repro.report_hash.as_str())
        && repro.exit_code == result.exit_code
        && repro.expected_exit_code == spec.expected_exit_code
        && repro.succeeded == (result.exit_code == spec.expected_exit_code)
        && repro.truncated == result.truncated
}

fn validate_repro_request(request: &LeaseRequest) -> Result<(), &'static str> {
    let Some(capability) = request.repro.as_ref() else {
        return Ok(());
    };
    let Some(command) = request.command.as_ref() else {
        return Err("a repro capability requires a batch command");
    };
    if !is_lower_sha256(&capability.token_hash) || !is_lower_sha256(&capability.spec_hash) {
        return Err("repro token and spec commitments must be lowercase SHA-256 hex");
    }
    if !(0..=255).contains(&capability.expected_exit_code) {
        return Err("repro expected exit code must be between 0 and 255");
    }
    let spec = GpuReproSpec {
        image: request.image.clone(),
        command: command.clone(),
        duration_seconds: request.duration_seconds,
        min_vram_mib: request.min_vram_mib,
        expected_exit_code: capability.expected_exit_code,
    };
    if spec.hash().ok().as_deref() != Some(capability.spec_hash.as_str()) {
        return Err("repro capability does not commit to this exact workload");
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(is_lower_sha256)
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `chain_lease_id` is the escrow's id and the only one that may reach
/// calldata; the internal id addresses a different lease, or none at all.
fn operator_dispute(
    lease_id: u64,
    chain_lease_id: u64,
    node_id: String,
    evidence: SettlementEvidence,
    proposal: Option<StoredSettlementSubmission>,
    escrow_address: Option<&str>,
    updated_at: chrono::DateTime<Utc>,
) -> Result<OperatorDispute, StoreError> {
    let evidence_hash = format!(
        "0x{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&evidence).map_err(|_| StoreError::InvalidOperatorAction)?
        ))
    );
    let proposal_integrity_valid = proposal.as_ref().map(|submission| {
        submission.proposal.lease_id == lease_id
            && submission
                .proposal
                .evidence_hash
                .eq_ignore_ascii_case(&evidence_hash)
            && is_hash(&submission.proposal.receipt_hash)
            && is_hash(&submission.transaction_hash)
            && submission.proposal.usage_seconds <= u64::from(evidence.duration_seconds)
            && submission
                .proposal
                .usage_seconds
                .checked_mul(evidence.rate_per_second)
                .is_some_and(|charge| charge <= evidence.deposit_base_units)
    });
    let proposal_summary = proposal.as_ref().map(|submission| DisputeProposalSummary {
        usage_seconds: submission.proposal.usage_seconds,
        receipt_hash: submission.proposal.receipt_hash.clone(),
        transaction_hash: submission.transaction_hash.clone(),
    });
    let accept_proposal_transaction = match (escrow_address, proposal.as_ref()) {
        (Some(escrow_address), Some(submission))
            if proposal_integrity_valid == Some(true)
                && is_address(escrow_address)
                && is_hash(&submission.proposal.receipt_hash) =>
        {
            Some(SafeTransaction {
                to: escrow_address.to_ascii_lowercase(),
                value: "0".to_owned(),
                data: resolve_dispute_calldata(
                    chain_lease_id,
                    submission.proposal.usage_seconds,
                    &submission.proposal.receipt_hash,
                )?,
                method: "resolveDispute(uint256,uint64,bytes32)",
            })
        }
        _ => None,
    };
    Ok(OperatorDispute {
        lease_id,
        node_id,
        evidence: DisputeEvidenceSummary {
            gpu_model: evidence.gpu_model,
            image_digest: evidence.image_digest,
            rate_per_second: evidence.rate_per_second,
            deposit_base_units: evidence.deposit_base_units,
            duration_seconds: evidence.duration_seconds,
            access_started_at: evidence.access_started_at,
            access_ended_at: evidence.access_ended_at,
            cuda_ready_at: evidence.cuda_ready_at,
            interactive_access_ready_at: evidence.interactive_access_ready_at,
            gateway_closed_at: evidence.gateway_closed_at,
            telemetry_records: evidence.node_telemetry.len(),
            evidence_hash,
            proposal_integrity_valid,
        },
        proposal: proposal_summary,
        accept_proposal_transaction,
        updated_at,
    })
}

fn resolve_dispute_calldata(
    lease_id: u64,
    usage_seconds: u64,
    receipt_hash: &str,
) -> Result<String, StoreError> {
    let receipt_hash = hex::decode(
        receipt_hash
            .strip_prefix("0x")
            .filter(|value| value.len() == 64)
            .ok_or(StoreError::InvalidOperatorAction)?,
    )
    .map_err(|_| StoreError::InvalidOperatorAction)?;
    let mut calldata = Vec::with_capacity(100);
    calldata.extend(&Keccak256::digest(b"resolveDispute(uint256,uint64,bytes32)")[..4]);
    calldata.extend(abi_word(lease_id));
    calldata.extend(abi_word(usage_seconds));
    calldata.extend(receipt_hash);
    Ok(format!("0x{}", hex::encode(calldata)))
}

fn abi_word(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn is_ssh_authorized_key(value: &str) -> bool {
    let value = value.trim();
    value.len() <= 16_384
        && value.lines().count() == 1
        && value.starts_with("ssh-ed25519 ")
        && value
            .split_whitespace()
            .nth(1)
            .is_some_and(|key| !key.is_empty() && key.len() <= 12_000)
}

fn generate_jupyter_token() -> String {
    let mut token = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    hex::encode(token)
}

fn credential_cipher(allow_development: bool) -> anyhow::Result<CredentialCipher> {
    let key = env::var("PRISM_ACCESS_CREDENTIAL_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| allow_development.then(|| "11".repeat(32)))
        .context("PRISM_ACCESS_CREDENTIAL_KEY is required outside local development")?;
    CredentialCipher::from_hex(&key).context("PRISM_ACCESS_CREDENTIAL_KEY must be 32 bytes of hex")
}

fn valid_gateway_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains("://")
        && !value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}

fn valid_node_id(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn require_account(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Account, (StatusCode, Json<ApiError>)> {
    let identity = state
        .identity
        .verify(headers, method, path, body)
        .map_err(identity_error)?;
    state.store.authorize(identity).await.map_err(store_error)
}

fn identity_error(error: IdentityError) -> (StatusCode, Json<ApiError>) {
    let code = match error {
        IdentityError::InvalidSignature => "identity_required",
        IdentityError::Expired => "identity_expired",
    };
    unauthorized(
        code,
        "a Privy-verified identity must be supplied by the auth boundary",
    )
}

fn store_error(error: StoreError) -> (StatusCode, Json<ApiError>) {
    match error {
        StoreError::NodeNotFound => {
            not_found("node_not_found", "node must be enrolled before heartbeat")
        }
        StoreError::NetworkCapacity => conflict("network_capacity", "network lease limit reached"),
        StoreError::NoMatch => not_found("no_match", "no compatible bonded node is online"),
        StoreError::CapacityReserved => conflict(
            "capacity_reserved",
            "all compatible capacity is held by an open quote or an active lease",
        ),
        StoreError::EscrowLimit => {
            bad_request("escrow_limit", "matched offer exceeds the escrow limit")
        }
        StoreError::NodeSuspended => conflict(
            "node_suspended",
            "the node this quote names has been suspended; the funding was not \
             claimed and can be recovered with cancelUnprovisioned",
        ),
        StoreError::ReproExecutorUnavailable => conflict(
            "repro_executor_unavailable",
            "the approved GPU repro execution path is no longer available; the funding was not \
             claimed and can be recovered with cancelUnprovisioned",
        ),
        StoreError::ReproTokenAlreadyUsed => conflict(
            "repro_token_already_used",
            "this GPU repro capability token already names another quote; prepare a new repro",
        ),
        StoreError::AmbiguousReproToken => conflict(
            "ambiguous_repro_token",
            "this legacy GPU repro capability resolves to more than one quote and cannot be read safely",
        ),
        StoreError::FundingCapacityUnavailable => conflict(
            "funding_capacity_unavailable",
            "the quoted GPU capacity is already occupied; the funding was not claimed and can be recovered with cancelUnprovisioned",
        ),
        StoreError::TelemetryReplay => conflict(
            "telemetry_replay",
            "node telemetry sequence has already been accepted",
        ),
        StoreError::IdentityReplay => conflict(
            "identity_replay",
            "the signed request has already been accepted",
        ),
        StoreError::SessionRevoked => unauthorized(
            "session_revoked",
            "this account session is no longer active",
        ),
        StoreError::AccountSuspended => {
            forbidden("account_suspended", "this account has been suspended")
        }
        StoreError::QuoteNotFound => not_found(
            "quote_not_found",
            "the lease quote does not exist or does not belong to this account",
        ),
        StoreError::QuoteUnavailable => conflict(
            "quote_unavailable",
            "the lease quote expired or was already consumed",
        ),
        StoreError::FundingMismatch => conflict(
            "funding_mismatch",
            "the funding transaction is already claimed or does not match this quote",
        ),
        StoreError::CommandNotFound => not_found(
            "command_not_found",
            "the node command does not exist or cannot make this transition",
        ),
        StoreError::CommandReplay => conflict(
            "command_replay",
            "the signed node command request was already accepted",
        ),
        StoreError::CommandClaimed => conflict(
            "command_claimed",
            "the node command execution was claimed by another signed poll",
        ),
        StoreError::AccessCredentialsMissing => bad_request(
            "missing_access_credentials",
            "interactive access requires an SSH public key",
        ),
        StoreError::CertificateReplay => conflict(
            "certificate_replay",
            "the signed node certificate request was already accepted",
        ),
        StoreError::CertificateInactive => forbidden(
            "certificate_inactive",
            "node certificate is missing, expired, revoked or suspended",
        ),
        StoreError::WalletChallengeUnavailable => conflict(
            "wallet_challenge_unavailable",
            "wallet challenge was not found, expired or already consumed",
        ),
        StoreError::WalletSignatureInvalid => forbidden(
            "wallet_signature_invalid",
            "wallet signature does not match the requested address",
        ),
        StoreError::OperatorRequired => forbidden(
            "operator_required",
            "this account is not authorized for operator controls",
        ),
        StoreError::OperatorTargetNotFound => not_found(
            "operator_target_not_found",
            "operator target does not exist",
        ),
        StoreError::InvalidOperatorAction => conflict(
            "invalid_operator_action",
            "operator action is invalid for the requested target state",
        ),
        StoreError::VaultItemNotFound => not_found(
            "vault_item_not_found",
            "no such vault item for this account",
        ),
        StoreError::VaultVersionConflict => conflict(
            "vault_version_conflict",
            "the vault item was created or modified by another writer; re-read it and retry",
        ),
        StoreError::VaultFull => conflict(
            "vault_full",
            "this account is holding the maximum number of vault items",
        ),
        StoreError::VaultTrustFloorUnmet { .. } => forbidden(
            "vault_trust_floor_unmet",
            "the lease's trust class is below the floor sealed into this item; \
             lower the floor deliberately or wait for capacity that qualifies",
        ),
        StoreError::VaultLeaseUnavailable => not_found(
            "vault_lease_unavailable",
            "the lease does not exist, is not active, or does not belong to this account",
        ),
        StoreError::WorkspaceNotFound => {
            not_found("workspace_not_found", "no such workspace for this account")
        }
        StoreError::WorkspaceNameTaken => conflict(
            "workspace_name_taken",
            "this account already has a workspace with that name",
        ),
        StoreError::WorkspaceVersionConflict => conflict(
            "workspace_version_conflict",
            "another writer committed a snapshot first; re-read the workspace and upload again",
        ),
        StoreError::WorkspaceFull => conflict(
            "workspace_full",
            "this account is holding the maximum number of workspaces",
        ),
        StoreError::AttestationChallengeUnavailable => conflict(
            "attestation_challenge_unavailable",
            "the attestation challenge does not exist, has expired, or was already used",
        ),
        // One code for every verification failure. Which check the evidence
        // failed is a hint to whoever is trying to forge past it.
        StoreError::AttestationUnverified => bad_request(
            "attestation_unverified",
            "the attestation evidence did not verify against the pinned vendor root",
        ),
        StoreError::AttestedDeviceConflict => conflict(
            "attested_device_conflict",
            "this device is already attested under a different node identity",
        ),
        StoreError::AttestedChipConflict => conflict(
            "attested_chip_conflict",
            "this processor is already attested under a different node identity",
        ),
        StoreError::LeaseNotAttestable => conflict(
            "lease_not_attestable",
            "the lease does not exist, or has moved past the point where a guest \
             report can bind to it",
        ),
        StoreError::LeaseUnattested => conflict(
            "lease_unattested",
            "this machine has not proved itself for the class this lease was quoted \
             at; no credentials are issued and the funding can be recovered with \
             cancelUnprovisioned",
        ),
        StoreError::TrustClassExpired => conflict(
            "trust_class_expired",
            "the node no longer holds the trust class this quote was issued at; \
             the funding was not claimed and can be recovered with cancelUnprovisioned",
        ),
        StoreError::InvalidStoredState(message) => {
            tracing::error!(%message, "invalid stored marketplace state");
            internal_error(StoreError::InvalidStoredState(message))
        }
        StoreError::Storage(error) => internal_error(StoreError::Storage(error)),
    }
}

fn chain_error(error: ChainError) -> (StatusCode, Json<ApiError>) {
    match error {
        ChainError::InvalidTransactionHash => bad_request(
            "invalid_transaction_hash",
            "funding transaction hash must be 32-byte hex",
        ),
        ChainError::FundingMismatch => conflict(
            "funding_mismatch",
            "the escrow funding event does not match this quote",
        ),
        ChainError::NotFinal => conflict(
            "funding_not_final",
            "the escrow funding transaction has not reached the confirmation threshold",
        ),
        ChainError::Reverted => conflict(
            "funding_reverted",
            "the escrow funding transaction reverted",
        ),
        ChainError::Rpc(error) => {
            tracing::error!(error = %error, "chain RPC failure during funding confirmation");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "chain_unavailable",
                    message: "funding confirmation is temporarily unavailable",
                }),
            )
        }
        ChainError::InvalidResponse => {
            tracing::error!("invalid chain RPC response during funding confirmation");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "chain_unavailable",
                    message: "funding confirmation is temporarily unavailable",
                }),
            )
        }
    }
}

fn registry_error(error: RegistryError) -> (StatusCode, Json<ApiError>) {
    match error {
        RegistryError::InvalidNodeId => {
            bad_request("invalid_node_id", "node ID must be a bytes32 hex value")
        }
        RegistryError::Rpc(error) => {
            tracing::error!(error = %error, "node registry RPC failure");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "registry_unavailable",
                    message: "the node registry is temporarily unavailable",
                }),
            )
        }
        RegistryError::InvalidResponse => {
            tracing::error!("invalid node registry RPC response");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    code: "registry_unavailable",
                    message: "the node registry is temporarily unavailable",
                }),
            )
        }
    }
}

fn internal_error(error: StoreError) -> (StatusCode, Json<ApiError>) {
    tracing::error!(error = ?error, "control-plane storage failure");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            code: "storage_unavailable",
            message: "the control plane is temporarily unavailable",
        }),
    )
}

fn credential_error() -> (StatusCode, Json<ApiError>) {
    tracing::error!("lease credential encryption failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            code: "credential_unavailable",
            message: "lease credentials are temporarily unavailable",
        }),
    )
}

fn bad_request(code: &'static str, message: &'static str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { code, message }))
}

fn unauthorized(code: &'static str, message: &'static str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::UNAUTHORIZED, Json(ApiError { code, message }))
}

fn forbidden(code: &'static str, message: &'static str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::FORBIDDEN, Json(ApiError { code, message }))
}

fn not_found(code: &'static str, message: &'static str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::NOT_FOUND, Json(ApiError { code, message }))
}

fn conflict(code: &'static str, message: &'static str) -> (StatusCode, Json<ApiError>) {
    (StatusCode::CONFLICT, Json(ApiError { code, message }))
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal");
    }
}

/// Recorded on startup so a service running behind the repository shows up in
/// one query instead of an image-digest comparison done by hand.
async fn record_service_version(pool: &PgPool, service: &str) -> anyhow::Result<()> {
    let version = prism_protocol::build_version();
    tracing::info!(service, %version, "recording build version");
    query(prism_protocol::RECORD_SERVICE_VERSION_SQL)
        .bind(service)
        .bind(&version)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use prism_protocol::{
        DEFAULT_VAULT_TRUST_FLOOR, GpuSpec, IsolationMode, MAX_STAKE_DISCOUNT_BPS,
        NodeCommandReportPayload, NodePosture, ReproCapability, ReproReceiptEvidence,
    };

    /// Most scheduler tests are about matching, not pricing, so they ask as a
    /// renter with no stake.
    fn quote_for_offers_unstaked<'a>(
        request: &LeaseRequest,
        offers: impl IntoIterator<Item = &'a NodeOffer>,
        reserved: &BTreeSet<String>,
    ) -> Result<LeaseQuote, StoreError> {
        quote_for_offers(request, offers, reserved, 0)
    }

    fn offer(node_id: &str, rate_per_second: u64, benchmark_score: u32) -> NodeOffer {
        NodeOffer {
            node_id: node_id.to_owned(),
            operator_wallet: "0x1".to_owned(),
            payout_wallet: "0x2".to_owned(),
            device_public_key: "test".to_owned(),
            gpu: GpuSpec {
                model: "NVIDIA L4".to_owned(),
                vram_mib: 24_576,
                cuda_major: 12,
            },
            rate_per_second,
            reliability_bps: 9_000,
            benchmark_score,
            bonded: true,
            online: true,
            public_image_only: true,
            trust_class: TrustClass::Open,
            staker_only: false,
            command_channel: false,
            managed_batch: false,
            updated_at: Utc::now(),
        }
    }

    fn attestation_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn attested_node_id() -> String {
        node_id(&attestation_signing_key().verifying_key())
    }

    fn attestation_device_key() -> String {
        URL_SAFE_NO_PAD.encode(attestation_signing_key().verifying_key().as_bytes())
    }

    /// The one thing the test policy relaxes is the certificate validity
    /// window, so checked-in vectors keep working as they age. No build of the
    /// service can reach it.
    fn attestation_policy() -> prism_attestation::Policy {
        prism_attestation::Policy::for_tests()
    }

    /// The verifier's own vectors. Borrowing them is what makes these tests
    /// walk a real chain to the pinned root instead of standing in for one.
    fn attestation_fixture(name: &str) -> Vec<u8> {
        let path = FilePath::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/attestation/tests/fixtures")
            .join(name);
        fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "missing fixture {}: {error}. Run: cargo test -p prism-attestation -- \
                 --ignored regenerate_fixtures",
                path.display()
            )
        })
    }

    fn reference_measurements() -> Vec<(u32, [u8; 48])> {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../../crates/attestation/reference/h100-measurements.json"
        ))
        .expect("reference measurements are valid JSON");
        file["measurements"]
            .as_array()
            .expect("reference measurements")
            .iter()
            .map(|entry| {
                // A slot may list alternatives; a report carries one, so the
                // fixture reports the first.
                let first = entry["sha384"][0].as_str().expect("digest");
                let digest: [u8; 48] = hex::decode(first)
                    .expect("hex digest")
                    .try_into()
                    .expect("48 byte digest");
                (entry["index"].as_u64().expect("index") as u32, digest)
            })
            .collect()
    }

    fn h100_evidence(report_nonce: [u8; 32], board_serial: &str) -> (String, Vec<String>) {
        use p384::pkcs8::DecodePrivateKey;

        let mut builder = prism_attestation::ReportBuilder::h100(report_nonce, board_serial);
        for (index, digest) in reference_measurements() {
            builder = builder.measurement(index, digest);
        }
        let device_key =
            p384::ecdsa::SigningKey::from_pkcs8_der(&attestation_fixture("leaf-key.pkcs8.der"))
                .expect("fixture leaf key");
        let chain = ["leaf.der", "intermediate.der", "test-root.der"]
            .iter()
            .map(|name| URL_SAFE_NO_PAD.encode(attestation_fixture(name)))
            .collect();
        (
            URL_SAFE_NO_PAD.encode(builder.signed_with(&device_key)),
            chain,
        )
    }

    /// A report answering this challenge, from this node, under this key. The
    /// three are hashed together, so changing any one of them is what the
    /// verifier sees as a relayed report.
    fn attested_submission(
        challenge: &AttestationChallenge,
        key: &SigningKey,
        report_key: &SigningKey,
        board_serial: &str,
    ) -> NodeAttestation {
        let report_nonce = attestation_report_nonce(
            &hex::decode(&challenge.nonce).expect("the nonce we issued is hex"),
            &challenge.node_id,
            &URL_SAFE_NO_PAD.encode(report_key.verifying_key().as_bytes()),
        );
        let (evidence_base64, certificate_chain_base64) = h100_evidence(report_nonce, board_serial);
        NodeAttestation::sign(
            prism_protocol::UnsignedNodeAttestation {
                tdx_event_log: Vec::new(),
                tdx_collateral_json: None,
                node_id: challenge.node_id.clone(),
                challenge_id: challenge.challenge_id,
                kind: AttestationKind::NvidiaGpu,
                evidence_base64,
                certificate_chain_base64,
                capability: prism_protocol::HostTeeCapability {
                    sev: true,
                    sev_es: true,
                    kata_runtime: true,
                    ..Default::default()
                },
                pci_address: "0000:01:00.0".to_owned(),
                collected_at: Utc::now(),
            },
            key,
        )
        .unwrap()
    }

    /// A well-formed envelope carrying evidence that cannot possibly verify.
    /// These tests are about the challenge and the signature; the certificate
    /// walk is the verifier crate's own subject.
    fn signed_attestation(challenge_id: Uuid, key: &SigningKey) -> NodeAttestation {
        NodeAttestation::sign(
            prism_protocol::UnsignedNodeAttestation {
                tdx_event_log: Vec::new(),
                tdx_collateral_json: None,
                node_id: attested_node_id(),
                challenge_id,
                kind: AttestationKind::NvidiaGpu,
                evidence_base64: URL_SAFE_NO_PAD.encode([0_u8; 64]),
                certificate_chain_base64: vec![URL_SAFE_NO_PAD.encode([0_u8; 96])],
                capability: prism_protocol::HostTeeCapability {
                    sev: true,
                    sev_es: true,
                    kata_runtime: true,
                    ..Default::default()
                },
                pci_address: "0000:01:00.0".to_owned(),
                collected_at: Utc::now(),
            },
            key,
        )
        .unwrap()
    }

    fn attestation_verdict(node_id: &str, expires_at: chrono::DateTime<Utc>) -> AttestationVerdict {
        AttestationVerdict {
            node_id: node_id.to_owned(),
            kind: prism_protocol::AttestationKind::NvidiaGpu,
            device_identity: format!("{node_id}/h100"),
            measurement_digest: "0".repeat(64),
            claimed_capability: prism_protocol::HostTeeCapability {
                sev: true,
                sev_es: true,
                kata_runtime: true,
                ..Default::default()
            },
            granted_class: TrustClass::Isolated,
            verifier_version: "test".to_owned(),
            verified_at: expires_at - Duration::hours(24),
            expires_at,
        }
    }

    fn posture_telemetry(
        node_id: &str,
        isolation: IsolationMode,
        observed_at: chrono::DateTime<Utc>,
    ) -> NodeTelemetry {
        NodeTelemetry {
            node_id: node_id.to_owned(),
            sequence: 1,
            observed_at,
            gpu_utilization_bps: 0,
            gpu_memory_used_mib: 0,
            active_lease: None,
            tunnel_connected: true,
            image_digest: None,
            posture: Some(NodePosture {
                isolation,
                attestation: None,
            }),
            signature: String::new(),
        }
    }

    /// Everything an `Isolated` grant rests on, in one place: a live tunnel,
    /// a confirmed kata posture, and a verdict this service issued itself.
    fn attested_market(
        isolation: IsolationMode,
        tunneled: bool,
        posture_observed_at: chrono::DateTime<Utc>,
        verdict: Option<AttestationVerdict>,
    ) -> MarketplaceStore {
        let node_id = attested_node_id();
        let mut market = MemoryMarketplace::default();
        let mut listing = offer(&node_id, 100, 10_000);
        listing.device_public_key = attestation_device_key();
        market.offers.insert(node_id.clone(), listing);
        if tunneled {
            market.tunnels.insert(node_id.clone(), Utc::now());
        }
        market.telemetry.insert(
            node_id.clone(),
            posture_telemetry(&node_id, isolation, posture_observed_at),
        );
        if let Some(verdict) = verdict {
            market.verdicts.insert(node_id, verdict);
        }
        MarketplaceStore::Memory(Arc::new(RwLock::new(market)))
    }

    fn lease_request(min_trust_class: TrustClass, command: Option<&str>) -> LeaseRequest {
        LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class,
            command: command.map(str::to_owned),
            repro: None,
        }
    }

    fn funding_confirmation<'a>(
        subject: &'a str,
        quote: &'a LeaseQuote,
        transaction_hash: &'a str,
        chain_lease_id: u64,
    ) -> FundingConfirmation<'a> {
        FundingConfirmation {
            subject,
            quote,
            transaction_hash,
            funding: ConfirmedFunding {
                lease_id: chain_lease_id,
                escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                renter_wallet: format!("0x{}", "33".repeat(20)),
            },
            ssh_authorized_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA"),
            jupyter_token: "token",
            encrypted_jupyter_token: EncryptedSecret {
                nonce: "bm9uY2U".to_owned(),
                ciphertext: "Y2lwaGVy".to_owned(),
            },
        }
    }

    /// The load-bearing case. The matcher reads the class off the offer, and
    /// what enrolment stored there is `Open` for every node that ever existed,
    /// so until the class was derived at quote time every lease was stamped
    /// `Open` no matter what the node had proved.
    #[tokio::test]
    async fn a_verified_node_is_quoted_isolated() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );

        let offers = store.list_offers().await.unwrap();
        assert_eq!(offers[0].trust_class, TrustClass::Isolated);

        let quote = store
            .quote("renter", &lease_request(TrustClass::Isolated, None), 0)
            .await
            .unwrap();
        assert_eq!(quote.node_id, node_id);
        assert_eq!(quote.trust_class, TrustClass::Isolated);
    }

    /// Same node, same posture, same tunnel. Only the verdict has run out.
    #[tokio::test]
    async fn the_same_node_falls_back_to_open_once_its_verdict_expires() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() - Duration::minutes(1),
            )),
        );

        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open
        );
        assert!(matches!(
            store
                .quote("renter", &lease_request(TrustClass::Isolated, None), 0)
                .await,
            Err(StoreError::NoMatch)
        ));
        let quote = store
            .quote("renter", &lease_request(TrustClass::Open, None), 0)
            .await
            .unwrap();
        assert_eq!(quote.trust_class, TrustClass::Open);
    }

    /// Broker capacity reaches the renter over direct SSH with nothing of ours
    /// in the path, so a verdict about its GPU changes nothing about what the
    /// renter can rely on.
    #[tokio::test]
    async fn an_untunneled_node_stays_open_with_a_verdict_on_file() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::KataVfio,
            false,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );

        assert!(
            store.list_offers().await.unwrap().is_empty(),
            "an offer with no tunnel is not served at all"
        );
        assert!(matches!(
            store
                .quote("renter", &lease_request(TrustClass::Isolated, None), 0)
                .await,
            Err(StoreError::NoMatch)
        ));
    }

    #[tokio::test]
    async fn a_shared_node_is_open_however_good_its_verdict() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::Shared,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );

        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open,
            "a verified GPU in a shared host is still a shared host"
        );
    }

    /// Posture rides on the heartbeat, and a node that stopped heart-beating
    /// has stopped saying anything. Postgres has always bounded it at ninety
    /// seconds; the memory store used to accept a posture of any age, so tests
    /// passed on evidence production would have discarded.
    #[tokio::test]
    async fn a_stale_posture_no_longer_carries_a_class() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS + 1),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );

        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open
        );
    }

    /// A batch command reaches the node over the signed command channel, so the
    /// property the matcher filters on is whether the node polls it. The trust
    /// class says nothing about that either way.
    #[tokio::test]
    async fn a_batch_lease_matches_only_a_node_that_polls() {
        let node_id = attested_node_id();
        let polling = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );
        polling
            .claim_command(&node_id, Uuid::now_v7())
            .await
            .expect("an empty queue is not an error");
        let quote = polling
            .quote(
                "renter",
                &lease_request(TrustClass::Open, Some("nvidia-smi")),
                0,
            )
            .await
            .unwrap();
        assert_eq!(quote.node_id, node_id);
        assert_eq!(quote.command.as_deref(), Some("nvidia-smi"));

        // The same node, the same class, and nobody has heard it poll.
        let quiet = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );
        assert!(matches!(
            quiet
                .quote(
                    "renter",
                    &lease_request(TrustClass::Open, Some("nvidia-smi")),
                    0
                )
                .await,
            Err(StoreError::NoMatch)
        ));
    }

    /// A quote is confirmable for a day. A verdict lives a day and a tunnel row
    /// ninety seconds, so a node can lose everything that earned its class in
    /// between. The renter funded against a stated class, so the answer is a
    /// refusal, not a quieter lease.
    #[tokio::test]
    async fn confirm_refuses_a_quote_whose_class_no_longer_holds() {
        let node_id = attested_node_id();
        let store = attested_market(
            IsolationMode::KataVfio,
            true,
            Utc::now(),
            Some(attestation_verdict(
                &node_id,
                Utc::now() + Duration::hours(1),
            )),
        );
        let quote = store
            .quote("renter", &lease_request(TrustClass::Isolated, None), 0)
            .await
            .unwrap();
        assert_eq!(quote.trust_class, TrustClass::Isolated);

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market.write().await.verdicts.clear();

        let confirmed = store
            .confirm_funding(FundingConfirmation {
                subject: "renter",
                quote: &quote,
                transaction_hash: &format!("0x{}", "ee".repeat(32)),
                funding: ConfirmedFunding {
                    lease_id: 91,
                    escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                    renter_wallet: format!("0x{}", "33".repeat(20)),
                },
                ssh_authorized_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA"),
                jupyter_token: "token",
                encrypted_jupyter_token: EncryptedSecret {
                    nonce: "bm9uY2U".to_owned(),
                    ciphertext: "Y2lwaGVy".to_owned(),
                },
            })
            .await;
        assert!(
            matches!(confirmed, Err(StoreError::TrustClassExpired)),
            "expected a refusal, got {confirmed:?}"
        );
    }

    /// The whole path, with a real chain walk in the middle: a nonce this
    /// service chose, a report signed under a leaf that anchors at the pinned
    /// root, and a class the node never got to name.
    #[tokio::test]
    async fn a_verified_report_turns_a_claim_into_a_class() {
        let node_id = attested_node_id();
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);
        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open,
            "a kata posture on its own earns nothing"
        );

        let challenge = store.create_attestation_challenge(&node_id).await.unwrap();
        let key = attestation_signing_key();
        let attestation = attested_submission(&challenge, &key, &key, "1650223000001");
        let verdict = store
            .record_attestation(AttestationSubmission {
                attestation: &attestation,
                device_public_key: &attestation_device_key(),
                policy: &attestation_policy(),
                tdx_compose_allowlist: &[],
            })
            .await
            .unwrap();

        assert_eq!(verdict.node_id, node_id);
        assert_eq!(verdict.granted_class, TrustClass::Isolated);
        assert!(verdict.device_identity.ends_with("1650223000001"));
        assert!(verdict.claimed_capability.sev_es && !verdict.claimed_capability.sev_snp);
        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Isolated
        );
        let quote = store
            .quote("renter", &lease_request(TrustClass::Isolated, None), 0)
            .await
            .unwrap();
        assert_eq!(quote.trust_class, TrustClass::Isolated);
    }

    /// The report is bound to the key the node enrolled with. A report built
    /// against any other key hashes to a different nonce, which is what makes
    /// one taken from another machine worthless here.
    #[tokio::test]
    async fn a_report_bound_to_another_device_key_does_not_verify() {
        let node_id = attested_node_id();
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);
        let challenge = store.create_attestation_challenge(&node_id).await.unwrap();
        let attestation = attested_submission(
            &challenge,
            &attestation_signing_key(),
            &SigningKey::from_bytes(&[11_u8; 32]),
            "1650223000001",
        );

        assert!(matches!(
            store
                .record_attestation(AttestationSubmission {
                    attestation: &attestation,
                    device_public_key: &attestation_device_key(),
                    policy: &attestation_policy(),
                    tdx_compose_allowlist: &[],
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open,
            "a failed verification stores nothing"
        );
    }

    /// The TDX path is routed and fails closed on real evidence. The quote,
    /// log and collateral are the live capture the attestation crate's
    /// vectors run, and it is genuinely Intel-signed, but its REPORT_DATA
    /// answers the CVM's own TLS binding rather than a challenge this store
    /// issued, so the submission refuses at the nonce binding, and the spent
    /// challenge stays spent. With no accepted compose hashes it refuses
    /// before any of that.
    #[tokio::test]
    async fn a_tdx_submission_is_bound_to_the_challenge_it_answers() {
        let quote: &[u8] =
            include_bytes!("../../../crates/attestation/tests/fixtures/tdx/live-quote.bin");
        let collateral =
            include_str!("../../../crates/attestation/tests/fixtures/tdx/live-collateral.json");
        let events: Vec<TdxEventEntry> = serde_json::from_str(include_str!(
            "../../../crates/attestation/tests/fixtures/tdx/live-events.json"
        ))
        .expect("live event log fixture");
        let compose_hash: [u8; 32] =
            hex::decode("c0fbe230ec1ce7ad7a092b8b698181a980df8555ab47e671f5464623c567b54f")
                .unwrap()
                .try_into()
                .unwrap();

        let node_id = attested_node_id();
        let store = attested_market(IsolationMode::Shared, true, Utc::now(), None);
        let submit = |challenge: &AttestationChallenge, allowlist: Vec<[u8; 32]>| {
            let attestation = NodeAttestation {
                node_id: challenge.node_id.clone(),
                challenge_id: challenge.challenge_id,
                kind: AttestationKind::Tdx,
                evidence_base64: URL_SAFE_NO_PAD.encode(quote),
                certificate_chain_base64: Vec::new(),
                tdx_event_log: events.clone(),
                tdx_collateral_json: Some(collateral.to_owned()),
                capability: prism_protocol::HostTeeCapability::default(),
                pci_address: String::new(),
                collected_at: Utc::now(),
                signature: String::new(),
            };
            let store = store.clone();
            async move {
                store
                    .record_attestation(AttestationSubmission {
                        attestation: &attestation,
                        device_public_key: &attestation_device_key(),
                        policy: &attestation_policy(),
                        tdx_compose_allowlist: &allowlist,
                    })
                    .await
            }
        };

        let challenge = store.create_attestation_challenge(&node_id).await.unwrap();
        assert!(matches!(
            submit(&challenge, vec![compose_hash]).await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(
            matches!(
                submit(&challenge, vec![compose_hash]).await,
                Err(StoreError::AttestationChallengeUnavailable)
            ),
            "a refusal spends the challenge"
        );

        let challenge = store.create_attestation_challenge(&node_id).await.unwrap();
        assert!(matches!(
            submit(&challenge, Vec::new()).await,
            Err(StoreError::AttestationUnverified)
        ));
        assert_eq!(
            store.list_offers().await.unwrap()[0].trust_class,
            TrustClass::Open,
            "nothing was stored"
        );
    }

    /// One physical GPU cannot stand behind two node identities. An operator
    /// who moves a card gets a conflict, not a second earned class.
    #[tokio::test]
    async fn the_same_device_cannot_back_two_nodes() {
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);
        let first = attestation_signing_key();
        let second = SigningKey::from_bytes(&[13_u8; 32]);
        let neighbour = node_id(&second.verifying_key());
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        let mut listing = offer(&neighbour, 100, 10_000);
        listing.device_public_key = URL_SAFE_NO_PAD.encode(second.verifying_key().as_bytes());
        market
            .write()
            .await
            .offers
            .insert(neighbour.clone(), listing);

        let mine = store
            .create_attestation_challenge(&attested_node_id())
            .await
            .unwrap();
        store
            .record_attestation(AttestationSubmission {
                attestation: &attested_submission(&mine, &first, &first, "1650223000001"),
                device_public_key: &attestation_device_key(),
                policy: &attestation_policy(),
                tdx_compose_allowlist: &[],
            })
            .await
            .unwrap();

        let theirs = store
            .create_attestation_challenge(&neighbour)
            .await
            .unwrap();
        let relayed = attested_submission(&theirs, &second, &second, "1650223000001");
        assert!(matches!(
            store
                .record_attestation(AttestationSubmission {
                    attestation: &relayed,
                    device_public_key: &URL_SAFE_NO_PAD.encode(second.verifying_key().as_bytes()),
                    policy: &attestation_policy(),
                    tdx_compose_allowlist: &[],
                })
                .await,
            Err(StoreError::AttestedDeviceConflict)
        ));
        assert_eq!(
            store_error(StoreError::AttestedDeviceConflict).0,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn a_challenge_needs_an_enrolled_node_and_only_one_lives_at_a_time() {
        let node_id = attested_node_id();
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);

        assert!(matches!(
            store.create_attestation_challenge("0xnot-enrolled").await,
            Err(StoreError::NodeNotFound)
        ));

        let first = store.create_attestation_challenge(&node_id).await.unwrap();
        assert_eq!(first.nonce.len(), 64, "32 random bytes, hex");

        // Asking again returns the same one. Minting a second would let anyone
        // who knows a node id keep cancelling the nonce that node is answering.
        let second = store.create_attestation_challenge(&node_id).await.unwrap();
        assert_eq!(second.challenge_id, first.challenge_id);
        assert_eq!(second.nonce, first.nonce);

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        let live = market.read().await.attestation_challenges.len();
        assert_eq!(live, 1, "one live nonce per node, never more");
    }

    #[test]
    fn an_attestation_signed_by_another_key_is_refused() {
        let mut listing = offer(&attested_node_id(), 100, 10_000);
        listing.device_public_key = attestation_device_key();
        let challenge_id = Uuid::now_v7();

        assert!(
            check_attestation_envelope(
                &listing,
                &signed_attestation(challenge_id, &attestation_signing_key())
            )
            .is_ok()
        );

        // The same envelope, signed by a key this node never enrolled.
        let stranger = SigningKey::from_bytes(&[9_u8; 32]);
        let refused =
            check_attestation_envelope(&listing, &signed_attestation(challenge_id, &stranger))
                .expect_err("a foreign signature is not this node");
        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert_eq!(refused.1.0.code, "unsigned_attestation");
    }

    #[tokio::test]
    async fn a_challenge_is_good_once_for_the_node_it_was_issued_to() {
        let node_id = attested_node_id();
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);
        let policy = attestation_policy();
        let submit = async |challenge_id: Uuid| {
            let attestation = signed_attestation(challenge_id, &attestation_signing_key());
            store
                .record_attestation(AttestationSubmission {
                    attestation: &attestation,
                    device_public_key: &attestation_device_key(),
                    policy: &policy,
                    tdx_compose_allowlist: &[],
                })
                .await
        };

        assert!(
            matches!(
                submit(Uuid::now_v7()).await,
                Err(StoreError::AttestationChallengeUnavailable)
            ),
            "a challenge nobody issued is not a challenge"
        );

        let challenge = store.create_attestation_challenge(&node_id).await.unwrap();
        // The evidence is nonsense, so this can only fail verification. What
        // matters is that it got that far: the challenge was accepted and spent.
        assert!(matches!(
            submit(challenge.challenge_id).await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(
            matches!(
                submit(challenge.challenge_id).await,
                Err(StoreError::AttestationChallengeUnavailable)
            ),
            "a spent challenge must not be usable a second time"
        );

        let expired = store.create_attestation_challenge(&node_id).await.unwrap();
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .attestation_challenges
            .get_mut(&expired.challenge_id)
            .unwrap()
            .challenge
            .expires_at = Utc::now() - Duration::seconds(1);
        assert!(matches!(
            submit(expired.challenge_id).await,
            Err(StoreError::AttestationChallengeUnavailable)
        ));
    }

    /// A challenge is bound to the node it was issued to, so one operator
    /// cannot answer on behalf of another node it also runs.
    #[tokio::test]
    async fn a_challenge_issued_to_another_node_is_refused() {
        let node_id = attested_node_id();
        let neighbour = format!("0x{}", "b".repeat(64));
        let store = attested_market(IsolationMode::KataVfio, true, Utc::now(), None);
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .offers
            .insert(neighbour.clone(), offer(&neighbour, 100, 10_000));

        let theirs = store
            .create_attestation_challenge(&neighbour)
            .await
            .unwrap();
        let attestation = signed_attestation(theirs.challenge_id, &attestation_signing_key());
        assert_eq!(attestation.node_id, node_id);

        assert!(matches!(
            store
                .record_attestation(AttestationSubmission {
                    attestation: &attestation,
                    device_public_key: &attestation_device_key(),
                    policy: &attestation_policy(),
                    tdx_compose_allowlist: &[],
                })
                .await,
            Err(StoreError::AttestationChallengeUnavailable)
        ));
    }

    const GUEST_LEASE_ID: u64 = 4_663;
    const GUEST_RENTER: &str = "renter";
    /// What a node's ready report leaves behind for a lease no report covers.
    const REPORTED_FINGERPRINT: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
    /// The chip the checked-in VCEK is issued against. A second node presenting
    /// this one is a node claiming somebody else's processor.
    const GUEST_CHIP_ID: [u8; 64] = [0x5a; 64];

    /// The OpenSSH line a guest would publish for its lease. Only the blob
    /// matters: the fingerprint the renter pins is taken from it, so it has to
    /// be a key line rather than a placeholder string.
    fn guest_channel_key(lease_id: u64) -> String {
        let mut blob = Vec::with_capacity(51);
        blob.extend_from_slice(&11_u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&[0x9e; 32]);
        format!(
            "ssh-ed25519 {} prism-lease-{lease_id}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    fn guest_lease_image() -> String {
        format!("registry.example/runtime@sha256:{}", "ab".repeat(32))
    }

    fn stored_secret(label: &str) -> EncryptedSecret {
        EncryptedSecret {
            nonce: URL_SAFE_NO_PAD.encode([1_u8; 12]),
            ciphertext: URL_SAFE_NO_PAD.encode(label.as_bytes()),
        }
    }

    /// A lease on the attested node carrying everything the access grant needs
    /// except a guest verdict: the quote it was funded against, the lifecycle
    /// row holding the relay token, and the renter's Jupyter secret.
    fn guest_lease_market(quoted_class: TrustClass, state: LeaseState) -> MemoryMarketplace {
        let node_id = attested_node_id();
        let mut market = MemoryMarketplace::default();
        let mut listing = offer(&node_id, 100, 10_000);
        listing.device_public_key = attestation_device_key();
        market.offers.insert(node_id.clone(), listing);
        // The guest rung sits on top of the node rung, so the node has to have
        // earned `Isolated` before any report from the VM on it can lift a
        // lease to `Attested`.
        market.tunnels.insert(node_id.clone(), Utc::now());
        market.telemetry.insert(
            node_id.clone(),
            posture_telemetry(&node_id, IsolationMode::KataVfio, Utc::now()),
        );
        market.verdicts.insert(
            node_id.clone(),
            attestation_verdict(&node_id, Utc::now() + Duration::hours(24)),
        );
        let quote_id = Uuid::now_v7();
        market.open_quotes.insert(
            quote_id,
            LeaseQuote {
                quote_id,
                node_id: node_id.clone(),
                image: guest_lease_image(),
                duration_seconds: 60,
                min_vram_mib: 1,
                rate_per_second: 100,
                maximum_escrow: 6_000,
                trust_class: quoted_class,
                command: None,
                repro: None,
                expires_at: Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES),
            },
        );
        market.leases.insert(
            GUEST_LEASE_ID,
            (
                GUEST_RENTER.to_owned(),
                LeaseRecord {
                    lease_id: GUEST_LEASE_ID,
                    chain_lease_id: 1,
                    escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                    quote_id,
                    node_id,
                    renter_wallet: "0x1".to_owned(),
                    image: guest_lease_image(),
                    duration_seconds: 60,
                    rate_per_second: 100,
                    maximum_escrow: 6_000,
                    trust_class: class_for_lease(
                        GUEST_LEASE_ID,
                        &attested_node_id(),
                        quoted_class,
                        None,
                        None,
                        None,
                        Utc::now(),
                    ),
                    funding_transaction_hash: format!("0x{}", "cd".repeat(32)),
                    state,
                    command: None,
                    repro: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ),
        );
        market
            .lease_secrets
            .insert(GUEST_LEASE_ID, stored_secret("jupyter"));
        market.lifecycle.insert(
            GUEST_LEASE_ID,
            MemoryLifecycle {
                grant_token: Some(stored_secret("relay")),
                grant_expires_at: Some(Utc::now() + Duration::hours(1)),
                channel_key_fingerprint: None,
            },
        );
        market
    }

    fn guest_verdict(
        lease_id: u64,
        node_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> LeaseAttestationVerdict {
        LeaseAttestationVerdict {
            lease_id,
            node_id: node_id.to_owned(),
            kind: AttestationKind::SevSnp,
            guest: prism_protocol::AttestedGuest {
                measurement: "a".repeat(96),
                host_data: "b".repeat(64),
                chip_id_digest: "c".repeat(64),
                reported_tcb: prism_protocol::SnpTcb {
                    bootloader: 4,
                    tee: 0,
                    snp: 22,
                    microcode: 72,
                },
                policy_debug: false,
                vmpl: 0,
                channel_key_fingerprint: "SHA256:1IVsxwrSD9jbfOTfSHzBn7dFxHfKmzZBUS7EQ0zVCXY"
                    .to_owned(),
                image_digest: format!("sha256:{}", "ab".repeat(32)),
            },
            granted_class: TrustClass::Attested,
            verifier_version: "test".to_owned(),
            verified_at: expires_at - Duration::hours(24),
            expires_at,
        }
    }

    async fn lease_access_for(
        market: MemoryMarketplace,
    ) -> Result<Option<LeaseAccessGrant>, StoreError> {
        MarketplaceStore::Memory(Arc::new(RwLock::new(market)))
            .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
            .await
    }

    /// The point of the rung. A renter who paid for a machine that proves what
    /// booted gets no credentials until the guest running their lease has
    /// proved it, and an unproved lease is refundable rather than quietly
    /// served a rung lower.
    #[tokio::test]
    async fn a_lease_quoted_above_isolated_opens_nothing_without_a_guest_verdict() {
        assert!(matches!(
            lease_access_for(guest_lease_market(TrustClass::Attested, LeaseState::Active)).await,
            Err(StoreError::LeaseUnattested)
        ));
    }

    #[tokio::test]
    async fn a_verdict_for_another_lease_opens_nothing() {
        let mut market = guest_lease_market(TrustClass::Attested, LeaseState::Active);
        market.lease_verdicts.insert(
            GUEST_LEASE_ID,
            guest_verdict(
                GUEST_LEASE_ID + 1,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );

        assert!(matches!(
            lease_access_for(market).await,
            Err(StoreError::LeaseUnattested)
        ));
    }

    #[tokio::test]
    async fn a_verdict_from_another_node_opens_nothing() {
        let mut market = guest_lease_market(TrustClass::Attested, LeaseState::Active);
        market.lease_verdicts.insert(
            GUEST_LEASE_ID,
            guest_verdict(
                GUEST_LEASE_ID,
                &format!("0x{}", "b".repeat(64)),
                Utc::now() + Duration::hours(1),
            ),
        );

        assert!(matches!(
            lease_access_for(market).await,
            Err(StoreError::LeaseUnattested)
        ));
    }

    /// The class is checked when credentials are asked for, not once at funding,
    /// so a verdict that lapses mid-lease closes the session it was opening.
    #[tokio::test]
    async fn a_verdict_that_expired_mid_lease_opens_nothing() {
        let mut market = guest_lease_market(TrustClass::Attested, LeaseState::Active);
        market.lease_verdicts.insert(
            GUEST_LEASE_ID,
            guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() - Duration::minutes(1),
            ),
        );

        assert!(matches!(
            lease_access_for(market).await,
            Err(StoreError::LeaseUnattested)
        ));
    }

    /// A lease that has stopped being servable has to be distinguishable from
    /// one that is merely slow, or the renter waits out the whole provisioning
    /// window on a session that is never opening.
    #[tokio::test]
    async fn a_closing_lease_reports_where_it_stands_to_its_owner() {
        let market = guest_lease_market(TrustClass::Open, LeaseState::Closing);
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        assert!(
            store
                .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_none(),
            "a closing lease opens nothing"
        );
        let state = store
            .lease_state(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner can see where their lease stands");
        assert!(!state.can_still_open_access());
    }

    /// Asking about someone else's lease answers the same way whether or not it
    /// exists.
    #[tokio::test]
    async fn a_stranger_learns_nothing_about_a_lease() {
        let market = guest_lease_market(TrustClass::Open, LeaseState::Closing);
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        assert!(
            store
                .lease_state("somebody-else", GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .lease_state("somebody-else", GUEST_LEASE_ID + 999)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Releasing is the only renter-side way to stop the meter, so it answers a
    /// stranger the way every other lease read does: absent, whether or not the
    /// lease exists, and with nothing queued against it.
    #[tokio::test]
    async fn a_stranger_cannot_release_a_lease() {
        let market = Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Open,
            LeaseState::Active,
        )));
        let store = MarketplaceStore::Memory(market.clone());

        assert!(
            store
                .release_lease("somebody-else", GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .release_lease(GUEST_RENTER, GUEST_LEASE_ID + 999)
                .await
                .unwrap()
                .is_none()
        );

        let market = market.read().await;
        assert_eq!(
            market.leases.get(&GUEST_LEASE_ID).unwrap().1.state,
            LeaseState::Active
        );
        assert!(market.lifecycle_actions.is_empty());
    }

    /// Before access opens there is nothing to close, and the escrow already
    /// refunds a lease that never provisions. Queueing a teardown here would
    /// meter a window that never started.
    #[tokio::test]
    async fn releasing_a_lease_before_access_opens_is_refused() {
        let market = Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Open,
            LeaseState::Funded,
        )));
        let store = MarketplaceStore::Memory(market.clone());

        let release = store
            .release_lease(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner sees where their lease stands");
        match lease_release_response(GUEST_LEASE_ID, &release) {
            Err((status, Json(error))) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(error.code, "lease_not_active");
            }
            Ok(_) => panic!("a lease that never opened access cannot be released"),
        }

        let market = market.read().await;
        assert_eq!(
            market.leases.get(&GUEST_LEASE_ID).unwrap().1.state,
            LeaseState::Funded
        );
        assert!(market.lifecycle_actions.is_empty());
    }

    /// The release itself only queues the teardown the lifecycle worker
    /// performs: revoking the grant, closing the escrow's access window and
    /// handing settlement the seconds actually used.
    #[tokio::test]
    async fn releasing_an_active_lease_queues_the_close() {
        let market = Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Open,
            LeaseState::Active,
        )));
        let store = MarketplaceStore::Memory(market.clone());

        let state = store
            .release_lease(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner can release their own lease");
        let Ok((status, Json(response))) = lease_release_response(GUEST_LEASE_ID, &state) else {
            panic!("an active lease can be released")
        };
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response.lease_id, GUEST_LEASE_ID);
        assert_eq!(response.state, "closing");
        assert_eq!(response.release, "queued");

        let held = market.read().await;
        assert_eq!(
            held.leases.get(&GUEST_LEASE_ID).unwrap().1.state,
            LeaseState::Closing
        );
        assert!(
            held.lifecycle_actions
                .contains(&(GUEST_LEASE_ID, "close_access"))
        );
        drop(held);

        let state = store
            .release_lease(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("a released lease is still the renter's to ask about");
        let Ok((status, Json(response))) = lease_release_response(GUEST_LEASE_ID, &state) else {
            panic!("releasing twice is not an error")
        };
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.state, "closing");
        assert_eq!(response.release, "already_closed");
        assert_eq!(market.read().await.lifecycle_actions.len(), 1);
    }

    /// A batch lease has no session to end: its command is what closes it, and
    /// closing access under a command still running would leave the escrow
    /// waiting on a report that settlement can no longer accept.
    #[tokio::test]
    async fn a_batch_lease_cannot_be_released_early() {
        let mut market = guest_lease_market(TrustClass::Open, LeaseState::Active);
        market.leases.get_mut(&GUEST_LEASE_ID).unwrap().1.command = Some("nvidia-smi".to_owned());
        let market = Arc::new(RwLock::new(market));
        let store = MarketplaceStore::Memory(market.clone());

        let state = store
            .release_lease(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner can ask");
        let Err((status, Json(error))) = lease_release_response(GUEST_LEASE_ID, &state) else {
            panic!("a batch lease is refused")
        };
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error.code, "lease_not_releasable");
        let held = market.read().await;
        assert_eq!(
            held.leases.get(&GUEST_LEASE_ID).unwrap().1.state,
            LeaseState::Active
        );
        assert!(held.lifecycle_actions.is_empty());
    }

    /// The daemon runs a container to the deadline it was handed. After an
    /// early release the lease settles and frees the node on chain while the
    /// machine is still busy, so the command, not the lease, is what says the
    /// node can take the next renter.
    #[tokio::test]
    async fn a_node_still_running_a_released_command_is_not_offered() {
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), now);
        let lease = LeaseRecord {
            lease_id: 27,
            chain_lease_id: 27,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "only".to_owned(),
            renter_wallet: format!("0x{}", "11".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{:064x}", 27),
            state: LeaseState::Finalized,
            command: None,
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(&lease, Some("ssh-ed25519 AAAA"), &"a".repeat(64)).unwrap();
        let command_id = command.command_id;
        market
            .leases
            .insert(lease.lease_id, ("previous-renter".to_owned(), lease));
        market.commands.insert(
            command_id,
            MemoryCommand {
                command,
                result: None,
                status: "ready",
                lease_until: None,
                authorization_request_id: None,
                verified_report: None,
                updated_at: now,
            },
        );
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        assert!(matches!(
            store.quote("renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .commands
            .get_mut(&command_id)
            .unwrap()
            .status = "completed";

        assert_eq!(
            store.quote("renter", &request, 0).await.unwrap().node_id,
            "only"
        );
    }

    /// A released lease stops serving the session it was serving, and says so
    /// rather than leaving the renter polling for credentials that are gone.
    #[tokio::test]
    async fn a_released_lease_serves_no_more_access() {
        let market = Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Open,
            LeaseState::Active,
        )));
        let store = MarketplaceStore::Memory(market);

        assert!(
            store
                .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_some(),
            "an active lease serves its renter"
        );
        store
            .release_lease(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner can release their own lease");

        assert!(
            store
                .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_none()
        );
        let state = store
            .lease_state(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .expect("the owner can see where their lease stands");
        assert!(!state.can_still_open_access());
    }

    /// The renter can only pin the host key if it reaches them, and it is the
    /// key inside the report rather than whatever the relay presents.
    #[tokio::test]
    async fn a_bound_verdict_hands_back_the_host_key_to_pin() {
        let mut market = guest_lease_market(TrustClass::Isolated, LeaseState::Active);
        market.lease_verdicts.insert(
            GUEST_LEASE_ID,
            guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );

        let grant = lease_access_for(market).await.unwrap().unwrap();
        let key = grant.channel_key.expect("a bound verdict names a host key");
        assert_eq!(
            key.fingerprint,
            guest_verdict(GUEST_LEASE_ID, &attested_node_id(), Utc::now())
                .guest
                .channel_key_fingerprint
        );
        assert_eq!(key.source, ChannelKeySource::SnpReport);
    }

    /// The classes the network serves in volume produce no report, so without
    /// this the renter is told to trust whatever answers on the port. The node
    /// names the key it started under its device key, and the grant says the
    /// claim is the node's rather than the processor's, because the two are
    /// worth different amounts and a renter deciding what to pin needs to know
    /// which one they have.
    #[tokio::test]
    async fn a_node_reported_host_key_reaches_the_renter_marked_as_the_node_s_word() {
        let mut market = guest_lease_market(TrustClass::Isolated, LeaseState::Active);
        market
            .lifecycle
            .get_mut(&GUEST_LEASE_ID)
            .unwrap()
            .channel_key_fingerprint = Some(REPORTED_FINGERPRINT.to_owned());

        let key = lease_access_for(market)
            .await
            .unwrap()
            .unwrap()
            .channel_key
            .expect("the node named the key it started");
        assert_eq!(key.fingerprint, REPORTED_FINGERPRINT);
        assert_eq!(key.source, ChannelKeySource::NodeReport);
    }

    /// Both claims cover the same key, and only one of them is signed by
    /// something the operator cannot forge.
    #[tokio::test]
    async fn a_guest_report_supersedes_what_the_node_said() {
        let mut market = guest_lease_market(TrustClass::Isolated, LeaseState::Active);
        market
            .lifecycle
            .get_mut(&GUEST_LEASE_ID)
            .unwrap()
            .channel_key_fingerprint = Some(REPORTED_FINGERPRINT.to_owned());
        market.lease_verdicts.insert(
            GUEST_LEASE_ID,
            guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );

        let key = lease_access_for(market)
            .await
            .unwrap()
            .unwrap()
            .channel_key
            .expect("a bound verdict names a host key");
        assert_ne!(key.fingerprint, REPORTED_FINGERPRINT);
        assert_eq!(key.source, ChannelKeySource::SnpReport);
    }

    /// A lease with no guest evidence at all still runs at `Isolated`, because
    /// that rung rests on the node's own verdict and nothing here withdraws it.
    #[tokio::test]
    async fn an_isolated_lease_needs_no_guest_verdict() {
        let grant = lease_access_for(guest_lease_market(TrustClass::Isolated, LeaseState::Active))
            .await
            .unwrap()
            .unwrap();
        assert!(grant.channel_key.is_none());
    }

    /// A guest binds its report while the machine is being prepared for it.
    /// Afterwards the grant has already been decided, and a report arriving then
    /// would be asking for a class the renter is mid-session at.
    #[tokio::test]
    async fn a_lease_challenge_is_issued_while_the_machine_is_being_prepared() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Isolated,
            LeaseState::Provisioning,
        ))));
        let challenge = store
            .create_lease_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        assert_eq!(challenge.node_id, attested_node_id());
        // One live nonce at a time, so a host cannot shop for the one a report
        // it already holds happens to answer.
        assert_eq!(
            store
                .create_lease_attestation_challenge(GUEST_LEASE_ID)
                .await
                .unwrap()
                .challenge_id,
            challenge.challenge_id
        );

        let running = MarketplaceStore::Memory(Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Isolated,
            LeaseState::Active,
        ))));
        assert!(matches!(
            running
                .create_lease_attestation_challenge(GUEST_LEASE_ID)
                .await,
            Err(StoreError::LeaseNotAttestable)
        ));
        assert!(matches!(
            running
                .create_lease_attestation_challenge(GUEST_LEASE_ID + 7)
                .await,
            Err(StoreError::LeaseNotAttestable)
        ));
    }

    /// A well-formed envelope carrying evidence that cannot verify. These tests
    /// are about the challenge and the binding; the chain walk is the verifier
    /// crate's own subject.
    fn signed_guest_attestation(lease_id: u64, challenge_id: Uuid) -> GuestAttestation {
        guest_attestation(
            attested_node_id(),
            lease_id,
            challenge_id,
            URL_SAFE_NO_PAD.encode([0_u8; 1_184]),
            vec![URL_SAFE_NO_PAD.encode([0_u8; 96])],
        )
    }

    fn guest_attestation(
        node_id: String,
        lease_id: u64,
        challenge_id: Uuid,
        report_base64: String,
        certificate_chain_base64: Vec<String>,
    ) -> GuestAttestation {
        GuestAttestation::sign(
            prism_protocol::UnsignedGuestAttestation {
                node_id,
                lease_id,
                challenge_id,
                kind: AttestationKind::SevSnp,
                report_base64,
                certificate_chain_base64,
                guest_channel_key: guest_channel_key(lease_id),
                collected_at: Utc::now(),
            },
            &attestation_signing_key(),
        )
        .unwrap()
    }

    fn snp_platform() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../crates/attestation/reference/snp-platform.json"
        ))
        .expect("the pinned platform is valid JSON")
    }

    /// The floor the platform file pins. Read rather than repeated, because the
    /// checked-in VCEK carries these four numbers in its SVN extensions and a
    /// report that disagrees with it is refused before anything here runs.
    fn snp_tcb_floor() -> (u8, u8, u8, u8) {
        let platform = snp_platform();
        let floor = &platform["tcb_floor"];
        let field = |name: &str| floor[name].as_u64().expect("tcb component") as u8;
        (
            field("bootloader"),
            field("tee"),
            field("snp"),
            field("microcode"),
        )
    }

    fn snp_launch_measurement() -> [u8; 48] {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../../crates/attestation/reference/snp-launch-measurements.json"
        ))
        .expect("the reference measurements are valid JSON");
        hex::decode(file["measurements"][0]["sha384"].as_str().expect("digest"))
            .expect("hex digest")
            .try_into()
            .expect("48 byte digest")
    }

    /// A report the guest of this lease would have taken: the control plane's
    /// own nonce, its lease, its channel key and the image it was quoted for,
    /// signed by the VCEK the verifier's vectors are built around.
    fn guest_evidence(lease_id: u64, nonce: &str) -> (String, Vec<String>) {
        use p384::pkcs8::DecodePrivateKey;

        let (bootloader, tee, snp, microcode) = snp_tcb_floor();
        let report = prism_attestation::SnpReportBuilder::genoa(
            snp_report_data(
                &hex::decode(nonce).expect("the nonce we issued is hex"),
                lease_id,
                &guest_channel_key(lease_id),
            ),
            snp_launch_measurement(),
            GUEST_CHIP_ID,
        )
        .host_data(lease_host_data(&guest_lease_image()).unwrap())
        .tcb(bootloader, tee, snp, microcode);
        let vcek =
            p384::ecdsa::SigningKey::from_pkcs8_der(&attestation_fixture("snp/vcek-key.pkcs8.der"))
                .expect("fixture VCEK key");
        (
            URL_SAFE_NO_PAD.encode(report.signed_with(&vcek)),
            ["snp/vcek.der", "snp/ask.der", "snp/test-ark.der"]
                .iter()
                .map(|name| URL_SAFE_NO_PAD.encode(attestation_fixture(name)))
                .collect(),
        )
    }

    async fn attest_guest(
        store: &MarketplaceStore,
        lease: &LeaseRecord,
    ) -> Result<LeaseAttestationVerdict, StoreError> {
        let challenge = store
            .create_lease_attestation_challenge(lease.lease_id)
            .await
            .unwrap();
        let (report_base64, chain) = guest_evidence(lease.lease_id, &challenge.nonce);
        let attestation = guest_attestation(
            lease.node_id.clone(),
            lease.lease_id,
            challenge.challenge_id,
            report_base64,
            chain,
        );
        store
            .record_lease_attestation(LeaseAttestationSubmission {
                attestation: &attestation,
                lease,
                policy: &attestation_policy(),
            })
            .await
    }

    /// A report that passes every check earns `Attested`, and a guest-only
    /// lease settles there: the confidential rung needs a GPU CC verdict
    /// beside the guest one, which this lease does not carry, so it stops at
    /// the guest half however good the report is.
    #[tokio::test]
    async fn a_fully_verified_guest_settles_at_attested() {
        let market = guest_lease_market(TrustClass::Isolated, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        let verdict = attest_guest(&store, &lease).await.unwrap();
        assert_eq!(verdict.granted_class, TrustClass::Attested);
        assert_eq!(verdict.lease_id, GUEST_LEASE_ID);

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        let mut market = market.write().await;
        assert_eq!(
            market.leases[&GUEST_LEASE_ID].1.trust_class,
            TrustClass::Attested
        );

        // The renter is handed the host key the report names, not whatever the
        // relay happens to present.
        market.leases.get_mut(&GUEST_LEASE_ID).unwrap().1.state = LeaseState::Active;
        drop(market);
        let grant = store
            .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
            .await
            .unwrap()
            .unwrap();
        let key = grant.channel_key.expect("a bound verdict names a host key");
        assert_eq!(key.fingerprint, verdict.guest.channel_key_fingerprint);
        assert_eq!(key.source, ChannelKeySource::SnpReport);
    }

    /// One processor stands behind one node. A second node presenting a report
    /// from the same chip is refused rather than granted a class off hardware
    /// that is already spoken for.
    #[tokio::test]
    async fn the_same_processor_cannot_back_two_nodes() {
        let neighbour_lease_id = GUEST_LEASE_ID + 1;
        let neighbour = format!("0x{}", "b".repeat(64));
        let mut market = guest_lease_market(TrustClass::Isolated, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let mut theirs = lease.clone();
        theirs.lease_id = neighbour_lease_id;
        theirs.node_id = neighbour.clone();
        market
            .offers
            .insert(neighbour.clone(), offer(&neighbour, 100, 10_000));
        market
            .leases
            .insert(neighbour_lease_id, ("neighbour".to_owned(), theirs.clone()));
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        attest_guest(&store, &lease).await.unwrap();

        assert!(matches!(
            attest_guest(&store, &theirs).await,
            Err(StoreError::AttestedChipConflict)
        ));
    }

    /// The nonce is spent whether or not the evidence stands up. Handing it back
    /// on failure would let a host grind reports against one challenge until
    /// something passed.
    #[tokio::test]
    async fn a_spent_lease_challenge_cannot_be_answered_twice() {
        let market = guest_lease_market(TrustClass::Isolated, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let challenge = store
            .create_lease_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        let attestation = signed_guest_attestation(GUEST_LEASE_ID, challenge.challenge_id);

        assert!(matches!(
            store
                .record_lease_attestation(LeaseAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(matches!(
            store
                .record_lease_attestation(LeaseAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationChallengeUnavailable)
        ));
    }

    fn tdx_guest_verdict(
        lease_id: u64,
        node_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> LeaseTdxGuestVerdict {
        LeaseTdxGuestVerdict {
            lease_id,
            node_id: node_id.to_owned(),
            kind: AttestationKind::Tdx,
            device_identity: format!("tdx/{}", "e".repeat(64)),
            compose_hash: "f".repeat(64),
            channel_key_fingerprint: "SHA256:testtesttesttesttesttesttesttesttesttestte".to_owned(),
            measurement_digest: "0".repeat(64),
            granted_class: TrustClass::Attested,
            verifier_version: "test".to_owned(),
            verified_at: expires_at - Duration::hours(24),
            expires_at,
        }
    }

    fn gpu_cc_verdict(
        lease_id: u64,
        node_id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> LeaseGpuCcVerdict {
        LeaseGpuCcVerdict {
            lease_id,
            node_id: node_id.to_owned(),
            kind: AttestationKind::NvidiaCc,
            device_identity: "nvidia/H100".to_owned(),
            measurement_digest: "1".repeat(64),
            granted_class: TrustClass::Confidential,
            verifier_version: "test".to_owned(),
            verified_at: expires_at - Duration::hours(24),
            expires_at,
        }
    }

    fn signed_tdx_lease_attestation(lease_id: u64, challenge_id: Uuid) -> TdxLeaseAttestation {
        TdxLeaseAttestation::sign(
            prism_protocol::UnsignedTdxLeaseAttestation {
                node_id: attested_node_id(),
                lease_id,
                challenge_id,
                quote_base64: URL_SAFE_NO_PAD.encode([0_u8; 128]),
                tdx_event_log: Vec::new(),
                tdx_collateral_json: "{}".to_owned(),
                guest_channel_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-lease".to_owned(),
                collected_at: Utc::now(),
            },
            &attestation_signing_key(),
        )
        .unwrap()
    }

    fn signed_gpu_cc_attestation(lease_id: u64, challenge_id: Uuid) -> GpuCcAttestation {
        GpuCcAttestation::sign(
            prism_protocol::UnsignedGpuCcAttestation {
                node_id: attested_node_id(),
                lease_id,
                challenge_id,
                report_base64: URL_SAFE_NO_PAD.encode([0_u8; 256]),
                certificate_chain_base64: vec![URL_SAFE_NO_PAD.encode([0_u8; 96])],
                collected_at: Utc::now(),
            },
            &attestation_signing_key(),
        )
        .unwrap()
    }

    /// The GPU answers a challenge of its own, so the nonce is issued while the
    /// machine is prepared and handed back rather than replaced while it lives,
    /// the same lifecycle the guest challenge has.
    #[tokio::test]
    async fn a_gpu_cc_challenge_is_issued_while_the_machine_is_being_prepared() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Isolated,
            LeaseState::Provisioning,
        ))));
        let challenge = store
            .create_lease_gpu_cc_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        assert_eq!(challenge.node_id, attested_node_id());
        assert_eq!(
            store
                .create_lease_gpu_cc_attestation_challenge(GUEST_LEASE_ID)
                .await
                .unwrap()
                .challenge_id,
            challenge.challenge_id
        );

        let running = MarketplaceStore::Memory(Arc::new(RwLock::new(guest_lease_market(
            TrustClass::Isolated,
            LeaseState::Active,
        ))));
        assert!(matches!(
            running
                .create_lease_gpu_cc_attestation_challenge(GUEST_LEASE_ID)
                .await,
            Err(StoreError::LeaseNotAttestable)
        ));
    }

    /// A well-formed TDX envelope carrying a quote that cannot verify is
    /// refused, and the guest challenge it answered is spent whichever way it
    /// went, so a host cannot grind quotes against one nonce.
    #[tokio::test]
    async fn a_tdx_quote_that_cannot_verify_spends_the_guest_challenge() {
        let market = guest_lease_market(TrustClass::Isolated, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let challenge = store
            .create_lease_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        let attestation = signed_tdx_lease_attestation(GUEST_LEASE_ID, challenge.challenge_id);

        assert!(matches!(
            store
                .record_lease_tdx_attestation(LeaseTdxAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(matches!(
            store
                .record_lease_tdx_attestation(LeaseTdxAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationChallengeUnavailable)
        ));
    }

    /// The GPU-CC path is fail-closed the same way, against its own challenge.
    #[tokio::test]
    async fn a_gpu_cc_report_that_cannot_verify_spends_its_challenge() {
        let market = guest_lease_market(TrustClass::Isolated, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let challenge = store
            .create_lease_gpu_cc_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        let attestation = signed_gpu_cc_attestation(GUEST_LEASE_ID, challenge.challenge_id);

        assert!(matches!(
            store
                .record_lease_gpu_cc_attestation(LeaseGpuCcAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(matches!(
            store
                .record_lease_gpu_cc_attestation(LeaseGpuCcAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationChallengeUnavailable)
        ));
    }

    /// A TDX quote is the guest half on Intel silicon, so a lease quoted at
    /// `Attested` opens once its TDX guest verdict stands, the same as it would
    /// on a SEV-SNP guest report.
    #[tokio::test]
    async fn a_tdx_guest_verdict_opens_an_attested_lease() {
        let mut market = guest_lease_market(TrustClass::Attested, LeaseState::Active);
        market.lease_tdx_guest_verdicts.insert(
            GUEST_LEASE_ID,
            tdx_guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );

        assert!(lease_access_for(market).await.unwrap().is_some());
    }

    /// `Confidential` is guest memory and VRAM together. A TDX guest verdict
    /// alone stops at the guest rung, so a lease quoted at `Confidential` opens
    /// nothing until a GPU-CC verdict stands beside it.
    #[tokio::test]
    async fn confidential_needs_the_gpu_verdict_beside_the_guest_one() {
        let mut market = guest_lease_market(TrustClass::Confidential, LeaseState::Active);
        market.lease_tdx_guest_verdicts.insert(
            GUEST_LEASE_ID,
            tdx_guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );
        assert!(matches!(
            lease_access_for(market).await,
            Err(StoreError::LeaseUnattested)
        ));

        let mut market = guest_lease_market(TrustClass::Confidential, LeaseState::Active);
        market.lease_tdx_guest_verdicts.insert(
            GUEST_LEASE_ID,
            tdx_guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );
        market.lease_gpu_cc_verdicts.insert(
            GUEST_LEASE_ID,
            gpu_cc_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );
        assert!(lease_access_for(market).await.unwrap().is_some());
    }

    /// A GPU-CC verdict for another lease lifts nothing: it is bound to the
    /// lease it names, so a confidential-quoted lease with a verdict for its
    /// neighbour opens nothing.
    #[tokio::test]
    async fn a_gpu_verdict_for_another_lease_lifts_nothing() {
        let mut market = guest_lease_market(TrustClass::Confidential, LeaseState::Active);
        market.lease_tdx_guest_verdicts.insert(
            GUEST_LEASE_ID,
            tdx_guest_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );
        market.lease_gpu_cc_verdicts.insert(
            GUEST_LEASE_ID,
            gpu_cc_verdict(
                GUEST_LEASE_ID + 1,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );
        assert!(matches!(
            lease_access_for(market).await,
            Err(StoreError::LeaseUnattested)
        ));
    }

    /// The genuine H100 CC report captured from confidential silicon, wrapped
    /// in the courier envelope a node presents it under. Its nonce is the
    /// provider's, taken when the card was captured, so it stands in for a real
    /// report answering a challenge this store never issued.
    fn genuine_gpu_cc_attestation(lease_id: u64, challenge_id: Uuid) -> GpuCcAttestation {
        let report = attestation_fixture("nvidia-cc/genuine/report.bin");
        let chain: Vec<String> =
            serde_json::from_slice(&attestation_fixture("nvidia-cc/genuine/chain.json"))
                .expect("genuine cc chain fixture");
        GpuCcAttestation::sign(
            prism_protocol::UnsignedGpuCcAttestation {
                node_id: attested_node_id(),
                lease_id,
                challenge_id,
                report_base64: STANDARD.encode(report),
                certificate_chain_base64: chain,
                collected_at: Utc::now(),
            },
            &attestation_signing_key(),
        )
        .unwrap()
    }

    /// The live TDX quote captured from a CVM we deployed and tore down, with
    /// its collateral and event log, in the same courier envelope. Intel signed
    /// it, but its REPORT_DATA answers the CVM's own binding rather than a
    /// challenge this store issued.
    fn live_tdx_lease_attestation(lease_id: u64, challenge_id: Uuid) -> TdxLeaseAttestation {
        let quote = attestation_fixture("tdx/live-quote.bin");
        let collateral =
            String::from_utf8(attestation_fixture("tdx/live-collateral.json")).unwrap();
        let events: Vec<TdxEventEntry> =
            serde_json::from_slice(&attestation_fixture("tdx/live-events.json"))
                .expect("live tdx event log fixture");
        TdxLeaseAttestation::sign(
            prism_protocol::UnsignedTdxLeaseAttestation {
                node_id: attested_node_id(),
                lease_id,
                challenge_id,
                quote_base64: STANDARD.encode(quote),
                tdx_event_log: events,
                tdx_collateral_json: collateral,
                guest_channel_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-lease".to_owned(),
                collected_at: Utc::now(),
            },
            &attestation_signing_key(),
        )
        .unwrap()
    }

    /// A lease reaches `Confidential` through the store's own methods. The guest
    /// half is a real SEV-SNP report, built around the checked-in VCEK and
    /// walked to the test root, submitted through the same record path a node
    /// uses; it earns `Attested` on its own. The GPU half is a verified CC
    /// verdict standing beside it, and the access gate fuses the two the last
    /// rung to `Confidential`. The GPU verdict is placed rather than submitted
    /// because the only real CC report we hold answers its capture nonce, not a
    /// challenge this store issues; that report's verify path is exercised in
    /// `the_gpu_cc_submission_refuses_a_report_bound_to_its_capture_nonce`, so
    /// the full silicon-to-`Confidential` grant is what a live node closes and
    /// everything short of the two lease-bound nonces is proved here.
    #[tokio::test]
    async fn a_lease_reaches_confidential_through_the_store() {
        let market = guest_lease_market(TrustClass::Confidential, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        let guest = attest_guest(&store, &lease).await.unwrap();
        assert_eq!(guest.kind, AttestationKind::SevSnp);
        assert_eq!(
            guest.granted_class,
            TrustClass::Attested,
            "the guest report earns the guest rung on its own"
        );

        let MarketplaceStore::Memory(handle) = &store else {
            unreachable!()
        };
        handle
            .write()
            .await
            .leases
            .get_mut(&GUEST_LEASE_ID)
            .unwrap()
            .1
            .state = LeaseState::Active;

        // The guest half alone does not open a confidential lease: encrypted
        // memory behind an unmeasured GPU is not what the renter paid for.
        assert!(matches!(
            store.lease_access(GUEST_RENTER, GUEST_LEASE_ID).await,
            Err(StoreError::LeaseUnattested)
        ));

        handle.write().await.lease_gpu_cc_verdicts.insert(
            GUEST_LEASE_ID,
            gpu_cc_verdict(
                GUEST_LEASE_ID,
                &attested_node_id(),
                Utc::now() + Duration::hours(1),
            ),
        );

        // The fusion the gate runs, off the node's own earned floor rather than
        // the record's optimistic class: the real guest verdict on file stops
        // at `Attested`, and only the GPU verdict beside it reaches
        // `Confidential`.
        {
            let market = handle.read().await;
            let snp = market.lease_verdicts[&GUEST_LEASE_ID].clone();
            let gpu = market.lease_gpu_cc_verdicts[&GUEST_LEASE_ID].clone();
            let now = Utc::now();
            assert_eq!(
                class_for_lease(
                    GUEST_LEASE_ID,
                    &attested_node_id(),
                    TrustClass::Isolated,
                    Some(&snp),
                    None,
                    None,
                    now,
                ),
                TrustClass::Attested
            );
            assert_eq!(
                class_for_lease(
                    GUEST_LEASE_ID,
                    &attested_node_id(),
                    TrustClass::Isolated,
                    Some(&snp),
                    None,
                    Some(&gpu),
                    now,
                ),
                TrustClass::Confidential
            );
        }

        assert!(
            store
                .lease_access(GUEST_RENTER, GUEST_LEASE_ID)
                .await
                .unwrap()
                .is_some(),
            "with both halves proved the confidential lease opens"
        );
    }

    /// The GPU-CC submission the `/v1/leases/{id}/gpu-attestation` handler
    /// delegates to runs the real NVIDIA verifier and fails closed. The report
    /// is the genuine H100 CC capture: its signature chains to NVIDIA's device
    /// root and its confidential-mode flag is set, but it answers its capture
    /// nonce, not the challenge this store just issued, so the submission
    /// refuses at the nonce binding. The challenge is spent whichever way it
    /// went, so a host cannot grind the one report it holds against a live
    /// nonce.
    #[tokio::test]
    async fn the_gpu_cc_submission_refuses_a_report_bound_to_its_capture_nonce() {
        let market = guest_lease_market(TrustClass::Confidential, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let challenge = store
            .create_lease_gpu_cc_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        let attestation = genuine_gpu_cc_attestation(GUEST_LEASE_ID, challenge.challenge_id);

        assert!(matches!(
            store
                .record_lease_gpu_cc_attestation(LeaseGpuCcAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(
            matches!(
                store
                    .record_lease_gpu_cc_attestation(LeaseGpuCcAttestationSubmission {
                        attestation: &attestation,
                        lease: &lease,
                        policy: &attestation_policy(),
                    })
                    .await,
                Err(StoreError::AttestationChallengeUnavailable)
            ),
            "a refusal spends the challenge"
        );

        let MarketplaceStore::Memory(handle) = &store else {
            unreachable!()
        };
        assert!(
            handle.read().await.lease_gpu_cc_verdicts.is_empty(),
            "a report that cannot verify stores no verdict"
        );
    }

    /// The TDX submission the `/v1/leases/{id}/tdx-attestation` handler
    /// delegates to is verify-gated the same way, against the guest challenge it
    /// answers. The quote is the live capture the attestation crate's vectors
    /// run, genuinely Intel-signed, but its REPORT_DATA is the CVM's own binding
    /// rather than this lease's challenge, so it refuses at the nonce binding
    /// and stores nothing.
    #[tokio::test]
    async fn the_tdx_submission_refuses_a_quote_bound_to_its_capture_nonce() {
        let market = guest_lease_market(TrustClass::Confidential, LeaseState::Provisioning);
        let lease = market.leases[&GUEST_LEASE_ID].1.clone();
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let challenge = store
            .create_lease_attestation_challenge(GUEST_LEASE_ID)
            .await
            .unwrap();
        let attestation = live_tdx_lease_attestation(GUEST_LEASE_ID, challenge.challenge_id);

        assert!(matches!(
            store
                .record_lease_tdx_attestation(LeaseTdxAttestationSubmission {
                    attestation: &attestation,
                    lease: &lease,
                    policy: &attestation_policy(),
                })
                .await,
            Err(StoreError::AttestationUnverified)
        ));
        assert!(
            matches!(
                store
                    .record_lease_tdx_attestation(LeaseTdxAttestationSubmission {
                        attestation: &attestation,
                        lease: &lease,
                        policy: &attestation_policy(),
                    })
                    .await,
                Err(StoreError::AttestationChallengeUnavailable)
            ),
            "a refusal spends the challenge"
        );

        let MarketplaceStore::Memory(handle) = &store else {
            unreachable!()
        };
        assert!(
            handle.read().await.lease_tdx_guest_verdicts.is_empty(),
            "a quote that cannot verify stores no verdict"
        );
    }

    #[tokio::test]
    async fn a_checksummed_linked_wallet_still_finds_its_nodes() {
        let checksummed = "0xAbC0000000000000000000000000000000000001";
        let mut market = MemoryMarketplace::default();
        let mut listing = offer("node-1", 100, 10_000);
        listing.operator_wallet = checksummed.to_ascii_lowercase();
        listing.payout_wallet = listing.operator_wallet.clone();
        market.offers.insert("node-1".to_owned(), listing);
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .linked_wallets
            .entry("subject-1".to_owned())
            .or_default()
            .insert(checksummed.to_owned());

        let summary = store.supplier_summary("subject-1").await.unwrap();
        assert_eq!(
            summary.nodes.len(),
            1,
            "a wallet is the same wallet in any casing"
        );
    }

    /// A self-hosted node at `Open` runs the same daemon and polls the same
    /// command channel as any other node, so it can take batch work. Until it
    /// has polled, nothing knows that, and the quote has to fail rather than
    /// bill a renter for a command that would never be collected.
    #[tokio::test]
    async fn an_open_node_that_polls_can_be_handed_a_batch_command() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("node-1".to_owned(), offer("node-1", 100, 10_000));
        market.tunnels.insert("node-1".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: "registry.example/runtime@sha256:abc".to_owned(),
            duration_seconds: 60,
            min_vram_mib: 16_000,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: Some("nvidia-smi".to_owned()),
            repro: None,
        };

        assert!(matches!(
            store.quote("subject-1", &request, 0).await,
            Err(StoreError::NoMatch)
        ));

        store
            .claim_command("node-1", Uuid::now_v7())
            .await
            .expect("an empty queue is not an error");

        let quote = store.quote("subject-1", &request, 0).await.unwrap();
        assert_eq!(quote.node_id, "node-1");
        assert_eq!(quote.trust_class, TrustClass::Open);

        let listed = store.list_offers().await.unwrap();
        assert!(listed[0].command_channel);
    }

    /// The window a poll is remembered for is the replay guard's retention
    /// window, and batch matching now reads the same records. Shortening it to
    /// tighten replay would quietly take nodes out of the batch fleet.
    #[test]
    fn a_node_that_stopped_polling_falls_out_of_batch_matching() {
        let mut market = MemoryMarketplace::default();
        let now = Utc::now();
        remember_node_request(
            &mut market,
            "node-1",
            Uuid::now_v7(),
            now - Duration::minutes(NODE_REQUEST_TTL_MINUTES) - Duration::seconds(1),
        )
        .unwrap();

        assert!(!polls_command_channel(&market, "node-1", now));

        remember_node_request(
            &mut market,
            "node-1",
            Uuid::now_v7(),
            now - Duration::seconds(30),
        )
        .unwrap();

        assert!(polls_command_channel(&market, "node-1", now));
        assert!(
            !polls_command_channel(&market, "node-2", now),
            "one node's poll says nothing about another node"
        );
    }

    /// The renter chose at quote time whether they wanted a session or a
    /// command. Issuing the wrong one either hands out a shell nobody asked for
    /// or leaves a batch renter waiting on a workspace that never reports.
    #[test]
    fn a_lease_with_a_command_is_dispatched_as_batch() {
        let base = LeaseRecord {
            lease_id: 9,
            chain_lease_id: 9,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "0xabc".to_owned(),
            renter_wallet: "0xrenter".to_owned(),
            image: "docker.io/library/debian@sha256:1".to_owned(),
            duration_seconds: 600,
            rate_per_second: 222,
            maximum_escrow: 133_200,
            trust_class: TrustClass::Isolated,
            funding_transaction_hash: "0x2".to_owned(),
            state: LeaseState::Funded,
            command: None,
            repro: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let interactive = launch_command(&base, Some("ssh-ed25519 AAAA"), "token").unwrap();
        assert!(matches!(interactive.kind, NodeCommandKind::Launch { .. }));
        assert!(matches!(
            launch_command(&base, None, "token"),
            Err(StoreError::AccessCredentialsMissing)
        ));

        let batch = launch_command(
            &LeaseRecord {
                command: Some("nvidia-smi -L".to_owned()),
                ..base
            },
            None,
            "token",
        )
        .unwrap();
        match batch.kind {
            NodeCommandKind::Batch {
                command,
                duration_seconds,
                ..
            } => {
                assert_eq!(command, "nvidia-smi -L");
                assert_eq!(duration_seconds, 600);
            }
            other => panic!("expected a batch command, got {other:?}"),
        }
    }

    #[test]
    fn a_lease_awaiting_settlement_still_occupies_its_node() {
        let lease = |state| LeaseRecord {
            lease_id: 1,
            chain_lease_id: 1,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "node".to_owned(),
            renter_wallet: "0x1".to_owned(),
            image: "registry.example/runtime@sha256:abc".to_owned(),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: "0x2".to_owned(),
            state,
            command: None,
            repro: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // The escrow keeps activeLeaseId set until finalize or refund, so
        // quoting a node in these states reverts with LeaseNotReady.
        assert!(occupies_node(&lease(LeaseState::Active)));
        assert!(occupies_node(&lease(LeaseState::Closing)));
        assert!(occupies_node(&lease(LeaseState::SettlementPending)));
        assert!(occupies_node(&lease(LeaseState::Disputed)));

        // Only the chain frees a node. `Failed` is written by this platform
        // when a lifecycle action ran out of attempts, which is precisely when
        // the escrow still holds the deposit and `activeLeaseId` is still set.
        // Treating it as free let the scheduler quote a node the registry then
        // refused with `LeaseNotReady`.
        assert!(occupies_node(&lease(LeaseState::Failed)));

        assert!(!occupies_node(&lease(LeaseState::Finalized)));
        assert!(!occupies_node(&lease(LeaseState::Refunded)));
    }

    #[test]
    fn matching_prefers_price_then_reliability_then_benchmark() {
        let slower = offer("slower", 100, 5_000);
        let faster = offer("faster", 100, 8_000);
        let expensive = offer("expensive", 101, 10_000);
        let quote = quote_for_offers_unstaked(
            &LeaseRequest {
                image: "registry.example/runtime@sha256:abc".to_owned(),
                duration_seconds: 60,
                min_vram_mib: 16_000,
                preferred_node_id: None,
                min_trust_class: TrustClass::Open,
                command: None,
                repro: None,
            },
            [&slower, &faster, &expensive],
            &BTreeSet::new(),
        )
        .unwrap();

        assert_eq!(quote.node_id, "faster");
        assert_eq!(quote.maximum_escrow, 6_000);
        assert_eq!(quote.trust_class, TrustClass::Open);
    }

    #[test]
    fn matching_refuses_offers_below_the_requested_trust_class() {
        let broker = offer("broker", 100, 10_000);
        let mut isolated = offer("isolated", 900, 1_000);
        isolated.trust_class = TrustClass::Isolated;
        let request = |min_trust_class| LeaseRequest {
            command: None,
            repro: None,
            image: "registry.example/runtime@sha256:abc".to_owned(),
            duration_seconds: 60,
            min_vram_mib: 16_000,
            preferred_node_id: None,
            min_trust_class,
        };

        let cheapest = quote_for_offers_unstaked(
            &request(TrustClass::Open),
            [&broker, &isolated],
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(cheapest.node_id, "broker");

        let guarded = quote_for_offers_unstaked(
            &request(TrustClass::Isolated),
            [&broker, &isolated],
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(guarded.node_id, "isolated");
        assert_eq!(guarded.trust_class, TrustClass::Isolated);

        assert!(matches!(
            quote_for_offers_unstaked(
                &request(TrustClass::Confidential),
                [&broker, &isolated],
                &BTreeSet::new()
            ),
            Err(StoreError::NoMatch)
        ));
    }

    #[test]
    fn broker_capacity_cannot_rise_above_open() {
        let kata = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: None,
        };
        let verdict = attestation_verdict("node-1", Utc::now() + Duration::hours(24));
        let now = Utc::now();

        assert_eq!(
            class_for_verdict("node-1", false, Some(&kata), Some(&verdict), now),
            TrustClass::Open,
            "capacity with no tunnel is broker capacity whatever it attests"
        );
        assert_eq!(
            class_for_verdict("node-1", true, Some(&kata), Some(&verdict), now),
            TrustClass::Isolated
        );
        assert_eq!(
            class_for_verdict("node-1", true, None, Some(&verdict), now),
            TrustClass::Open
        );
        assert_eq!(
            class_for_verdict("node-1", true, Some(&kata), None, now),
            TrustClass::Open,
            "a kata posture on its own is still the node talking about itself"
        );
    }

    #[test]
    fn a_verdict_that_has_expired_carries_nothing() {
        let kata = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: None,
        };
        let expired = attestation_verdict("node-1", Utc::now() - Duration::minutes(1));

        assert_eq!(
            class_for_verdict("node-1", true, Some(&kata), Some(&expired), Utc::now()),
            TrustClass::Open
        );
    }

    /// The posture names a confidential kind, the verdict backing it is an
    /// ordinary GPU report granting `Isolated`, and the node is served at
    /// `Isolated`. What the node says about its own hardware adds nothing to
    /// what the verifier was able to check.
    #[test]
    fn a_claimed_kind_buys_nothing_the_verdict_did_not() {
        let claimed = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: Some(prism_protocol::AttestationRef {
                kind: prism_protocol::AttestationKind::NvidiaCc,
                quote_sha256: "0".repeat(64),
            }),
        };
        let verdict = attestation_verdict("node-1", Utc::now() + Duration::hours(24));

        assert_eq!(
            class_for_verdict("node-1", true, Some(&claimed), Some(&verdict), Utc::now()),
            TrustClass::Isolated,
            "naming a confidential kind is a claim, and a claim buys nothing"
        );
    }

    #[test]
    fn matching_rejects_escrow_above_the_contract_limit() {
        let offer = offer("node", 3_000, 10_000);
        let result = quote_for_offers_unstaked(
            &LeaseRequest {
                image: "registry.example/runtime@sha256:abc".to_owned(),
                duration_seconds: MAX_LEASE_SECONDS,
                min_vram_mib: 1,
                preferred_node_id: None,
                min_trust_class: TrustClass::Open,
                command: None,
                repro: None,
            },
            [&offer],
            &BTreeSet::new(),
        );

        assert!(matches!(result, Err(StoreError::EscrowLimit)));
    }

    #[test]
    fn matching_skips_reserved_and_stale_nodes() {
        let reserved = offer("reserved", 100, 10_000);
        let mut stale = offer("stale", 90, 10_000);
        stale.updated_at = Utc::now() - Duration::minutes(5);
        let available = offer("available", 110, 10_000);
        let quote = quote_for_offers_unstaked(
            &LeaseRequest {
                image: format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
                duration_seconds: 60,
                min_vram_mib: 1,
                preferred_node_id: None,
                min_trust_class: TrustClass::Open,
                command: None,
                repro: None,
            },
            [&reserved, &stale, &available],
            &BTreeSet::from(["reserved".to_owned()]),
        )
        .unwrap();

        assert_eq!(quote.node_id, "available");
    }

    /// A network with one node reads as empty the moment anyone holds a quote
    /// on it, which sent an operator hunting for missing supply that was in
    /// `/v1/offers` the whole time.
    #[test]
    fn fully_reserved_capacity_is_not_reported_as_missing_capacity() {
        let only = offer("only", 100, 10_000);
        let mut undersized = offer("undersized", 100, 10_000);
        undersized.gpu.vram_mib = 8_192;
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
            duration_seconds: 60,
            min_vram_mib: 16_000,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        assert!(matches!(
            quote_for_offers_unstaked(&request, [&only], &BTreeSet::from(["only".to_owned()])),
            Err(StoreError::CapacityReserved)
        ));
        assert!(matches!(
            quote_for_offers_unstaked(&request, [&undersized], &BTreeSet::new()),
            Err(StoreError::NoMatch)
        ));
    }

    #[test]
    fn image_reference_requires_a_complete_digest() {
        assert!(is_pinned_image(&format!(
            "docker.io/library/runtime@sha256:{}",
            "a".repeat(64)
        )));
        assert!(is_pinned_image(&format!(
            "pytorch/pytorch@sha256:{}",
            "a".repeat(64)
        )));
        assert!(is_pinned_image(&format!(
            "registry.prismnetwork.tech/prism-cuda-vectoradd:vast-base-20260826@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_pinned_image(&format!(
            "docker.io/library/runtime@sha256:{}",
            "A".repeat(64)
        )));
        assert!(!is_pinned_image("registry.example/runtime@sha256:abc"));
        assert!(!is_pinned_image(&format!(
            "registry.example/../runtime@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_pinned_image(&format!(
            "registry.example/runtime@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_pinned_image(&format!(
            "docker.io:443/library/runtime@sha256:{}",
            "a".repeat(64)
        )));
        for registry in [
            "localhost:5000",
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "[::1]:5000",
            "registry.internal",
        ] {
            assert!(!is_pinned_image(&format!(
                "{registry}/runtime@sha256:{}",
                "a".repeat(64)
            )));
        }
        assert!(!is_pinned_image(&format!(
            "https://registry.example/runtime@sha256:{}",
            "a".repeat(64)
        )));
    }

    #[test]
    fn a_repro_capability_must_commit_to_the_exact_request() {
        let mut request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
            duration_seconds: 120,
            min_vram_mib: 24_576,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: Some("python verify.py".to_owned()),
            repro: None,
        };
        let spec = GpuReproSpec {
            image: request.image.clone(),
            command: request.command.clone().unwrap(),
            duration_seconds: request.duration_seconds,
            min_vram_mib: request.min_vram_mib,
            expected_exit_code: 0,
        };
        request.repro = Some(prism_protocol::ReproCapability {
            token_hash: "b".repeat(64),
            spec_hash: spec.hash().unwrap(),
            expected_exit_code: 0,
            executor: ReproExecutor::Managed,
        });
        assert_eq!(validate_repro_request(&request), Ok(()));

        let mut missing_command = request.clone();
        missing_command.command = None;
        assert!(validate_repro_request(&missing_command).is_err());

        let mut uppercase = request.clone();
        uppercase.repro.as_mut().unwrap().token_hash = "B".repeat(64);
        assert!(validate_repro_request(&uppercase).is_err());

        let mut invalid_exit = request.clone();
        invalid_exit.repro.as_mut().unwrap().expected_exit_code = 256;
        assert!(validate_repro_request(&invalid_exit).is_err());

        let mut different_duration = request;
        different_duration.duration_seconds += 1;
        assert!(validate_repro_request(&different_duration).is_err());
    }

    #[test]
    fn internal_identity_signature_is_bound_to_the_request() {
        let key = vec![7_u8; 32];
        let verifier = IdentityVerifier::Hmac(key.clone());
        let subject = "did:privy:test";
        let session_id = "session-test";
        let timestamp = Utc::now().timestamp().to_string();
        let request_id = "request-1";
        let method = "POST";
        let path = "/v1/leases/match";
        let body = br#"{"request":{"duration_seconds":60}}"#;
        let body_hash = hex::encode(Sha256::digest(body));
        let mut signer = HmacSha256::new_from_slice(&key).unwrap();
        signer.update(
            [
                "v2", subject, session_id, &timestamp, request_id, method, path, &body_hash,
            ]
            .join("\n")
            .as_bytes(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-prism-subject", subject.parse().unwrap());
        headers.insert("x-prism-session-id", session_id.parse().unwrap());
        headers.insert("x-prism-timestamp", timestamp.parse().unwrap());
        headers.insert("x-request-id", request_id.parse().unwrap());
        headers.insert(
            "x-prism-signature",
            hex::encode(signer.finalize().into_bytes()).parse().unwrap(),
        );

        assert!(verifier.verify(&headers, method, path, body).is_ok());
        assert!(
            verifier
                .verify(&headers, method, path, br#"{"request":{}}"#)
                .is_err()
        );
        assert!(
            verifier
                .verify(&headers, method, "/v1/other", body)
                .is_err()
        );
    }

    #[tokio::test]
    async fn account_authorization_rejects_request_replay_and_session_rebinding() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())));
        let identity = VerifiedIdentity {
            subject: "did:privy:one".to_owned(),
            session_id: "session-one".to_owned(),
            request_id: "request-one".to_owned(),
        };
        assert!(store.authorize(identity.clone()).await.is_ok());
        assert!(matches!(
            store.authorize(identity).await,
            Err(StoreError::IdentityReplay)
        ));
        assert!(matches!(
            store
                .authorize(VerifiedIdentity {
                    subject: "did:privy:two".to_owned(),
                    session_id: "session-one".to_owned(),
                    request_id: "request-two".to_owned(),
                })
                .await,
            Err(StoreError::SessionRevoked)
        ));
        store
            .revoke_session(VerifiedIdentity {
                subject: "did:privy:one".to_owned(),
                session_id: "session-two".to_owned(),
                request_id: "request-three".to_owned(),
            })
            .await
            .unwrap();
        assert!(matches!(
            store
                .authorize(VerifiedIdentity {
                    subject: "did:privy:one".to_owned(),
                    session_id: "session-two".to_owned(),
                    request_id: "request-four".to_owned(),
                })
                .await,
            Err(StoreError::SessionRevoked)
        ));
    }

    #[tokio::test]
    async fn scheduler_requires_a_fresh_gateway_tunnel_observation() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())));
        let advertised = offer(&format!("0x{}", "a".repeat(64)), 100, 10_000);
        store.enroll(advertised.clone()).await.unwrap();

        assert!(store.list_offers().await.unwrap().is_empty());
        store
            .observe_tunnel(
                &advertised.node_id,
                TunnelObservation {
                    connection_id: "connection-1".to_owned(),
                    certificate_fingerprint: String::new(),
                    observed_at: Utc::now(),
                },
                false,
            )
            .await
            .unwrap();
        assert_eq!(store.list_offers().await.unwrap().len(), 1);

        store
            .observe_tunnel(
                &advertised.node_id,
                TunnelObservation {
                    connection_id: "connection-1".to_owned(),
                    certificate_fingerprint: String::new(),
                    observed_at: Utc::now() - Duration::minutes(2),
                },
                false,
            )
            .await
            .unwrap();
        assert!(store.list_offers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn development_funding_uses_the_scheduler_escrow() {
        let configured = "0x2222222222222222222222222222222222222222";
        let chain = ChainVerifier::Development {
            escrow_address: Some(configured.to_owned()),
        };
        let listing = offer("only", 100, 10_000);
        let quote = quote_for_offers_unstaked(
            &lease_request(TrustClass::Open, None),
            [&listing],
            &BTreeSet::new(),
        )
        .unwrap();
        let funding = chain
            .verify_funding(&format!("0x{}", "01".repeat(32)), &quote)
            .await
            .unwrap();

        assert_eq!(chain.active_escrow_address(), configured);
        assert_eq!(funding.escrow_address, configured);
        assert_eq!(
            ChainVerifier::Development {
                escrow_address: None,
            }
            .active_escrow_address(),
            DEVELOPMENT_ESCROW_ADDRESS
        );
    }

    #[tokio::test]
    async fn scheduler_serializes_concurrent_quotes_at_the_network_cap() {
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        for index in 0..MAX_NETWORK_LEASES {
            let node_id = format!("node-{index}");
            market
                .offers
                .insert(node_id.clone(), offer(&node_id, 100, 10_000));
            market.tunnels.insert(node_id, now);
        }
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };
        let mut tasks = Vec::new();
        for index in 0..MAX_NETWORK_LEASES {
            let store = store.clone();
            let request = request.clone();
            tasks.push(tokio::spawn(async move {
                store.quote(&format!("subject-{index}"), &request, 0).await
            }));
        }
        let mut nodes = BTreeSet::new();
        for task in tasks {
            nodes.insert(task.await.unwrap().unwrap().node_id);
        }
        assert_eq!(nodes.len(), MAX_NETWORK_LEASES);
        assert!(matches!(
            store.quote("subject-over-cap", &request, 0).await,
            Err(StoreError::NetworkCapacity)
        ));
    }

    #[tokio::test]
    async fn network_cap_counts_failed_leases_only_for_the_active_escrow() {
        let current = "0x2222222222222222222222222222222222222222";
        let superseded = "0x1111111111111111111111111111111111111111";
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), now);
        for index in 0..MAX_NETWORK_LEASES {
            let lease_id = index as u64 + 1;
            let lease = LeaseRecord {
                lease_id,
                chain_lease_id: lease_id,
                escrow_address: superseded.to_owned(),
                quote_id: Uuid::now_v7(),
                node_id: "only".to_owned(),
                renter_wallet: format!("0x{}", "11".repeat(20)),
                image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
                duration_seconds: 60,
                rate_per_second: 100,
                maximum_escrow: 6_000,
                trust_class: TrustClass::Open,
                funding_transaction_hash: format!("0x{lease_id:064x}"),
                state: LeaseState::Failed,
                command: None,
                repro: None,
                created_at: now,
                updated_at: now,
            };
            market
                .leases
                .insert(lease_id, (format!("historical-{index}"), lease));
        }
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = lease_request(TrustClass::Open, None);

        store
            .quote_for_escrow("renter", &request, 0, current)
            .await
            .expect("superseded failed leases must not consume the current network cap");

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        for (_, lease) in market.write().await.leases.values_mut() {
            lease.escrow_address = current.to_owned();
        }
        assert!(matches!(
            store
                .quote_for_escrow("next-renter", &request, 0, current)
                .await,
            Err(StoreError::NetworkCapacity)
        ));
    }

    /// The renter who abandons a quote is the one most likely to ask for
    /// another, and on a one-node network its own five-minute hold used to
    /// lock it out until the quote expired.
    #[tokio::test]
    async fn a_renter_is_not_blocked_by_its_own_open_quote() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        let first = store.quote("renter", &request, 0).await.unwrap();
        let second = store.quote("renter", &request, 0).await.unwrap();
        assert_eq!(second.node_id, "only");
        assert_ne!(second.quote_id, first.quote_id);

        assert!(matches!(
            store.quote("other-renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));
    }

    /// One renter quoting and walking away used to take a one-node network out
    /// of service for the full five minutes the quote stayed valid.
    #[tokio::test]
    async fn an_abandoned_quote_stops_holding_its_node_before_it_expires() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        let abandoned = store.quote("renter", &request, 0).await.unwrap();
        assert!(matches!(
            store.quote("other-renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));

        // Age it past the hold while leaving it valid, and fundable, for the
        // rest of its five minutes.
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .open_quotes
            .get_mut(&abandoned.quote_id)
            .unwrap()
            .expires_at = Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES)
            - Duration::seconds(QUOTE_HOLD_SECONDS + 1);

        assert_eq!(
            store
                .quote("other-renter", &request, 0)
                .await
                .unwrap()
                .node_id,
            "only"
        );
        assert!(
            store
                .quote_for_subject("renter", abandoned.quote_id)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn funding_confirmation_refuses_a_node_claimed_by_another_quote() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = lease_request(TrustClass::Open, None);
        let first = store.quote("first", &request, 0).await.unwrap();
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .open_quotes
            .get_mut(&first.quote_id)
            .unwrap()
            .expires_at = Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES)
            - Duration::seconds(QUOTE_HOLD_SECONDS + 1);
        let second = store.quote("second", &request, 0).await.unwrap();
        let first_hash = format!("0x{}", "aa".repeat(32));
        let second_hash = format!("0x{}", "bb".repeat(32));

        store
            .confirm_funding(funding_confirmation("first", &first, &first_hash, 1))
            .await
            .unwrap();
        assert!(matches!(
            store
                .confirm_funding(funding_confirmation("second", &second, &second_hash, 2))
                .await,
            Err(StoreError::FundingCapacityUnavailable)
        ));
    }

    #[tokio::test]
    async fn replayed_repro_confirmation_does_not_require_a_new_node_poll() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        store.claim_command("only", Uuid::now_v7()).await.unwrap();
        let (template, _) = repro_quote("c".repeat(64), "only");
        let request = LeaseRequest {
            image: template.image,
            duration_seconds: template.duration_seconds,
            min_vram_mib: template.min_vram_mib,
            preferred_node_id: None,
            min_trust_class: template.trust_class,
            command: template.command,
            repro: template.repro,
        };
        let quote = store.quote("renter", &request, 0).await.unwrap();
        let transaction_hash = format!("0x{}", "cc".repeat(32));
        let first = store
            .confirm_funding(funding_confirmation("renter", &quote, &transaction_hash, 3))
            .await
            .unwrap();
        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market.write().await.node_requests.clear();

        let replay = store
            .confirm_funding(funding_confirmation("renter", &quote, &transaction_hash, 3))
            .await
            .unwrap();
        assert_eq!(replay.lease_id, first.lease_id);
    }

    #[tokio::test]
    async fn a_node_is_released_once_its_lease_settles_not_before() {
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), now);
        let lease = LeaseRecord {
            lease_id: 27,
            chain_lease_id: 27,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "only".to_owned(),
            renter_wallet: format!("0x{}", "11".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{:064x}", 27),
            state: LeaseState::Active,
            command: None,
            repro: None,
            created_at: now,
            updated_at: now,
        };
        market
            .leases
            .insert(lease.lease_id, ("previous-renter".to_owned(), lease));
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        assert!(matches!(
            store.quote("renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        // The escrow holds activeLeaseId until finalize or refund, so capacity
        // remains reserved after the machine is gone.
        market.write().await.leases.get_mut(&27).unwrap().1.state = LeaseState::SettlementPending;

        assert!(matches!(
            store.quote("renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));

        market.write().await.leases.get_mut(&27).unwrap().1.state = LeaseState::Finalized;

        assert_eq!(
            store.quote("renter", &request, 0).await.unwrap().node_id,
            "only"
        );
    }

    #[tokio::test]
    async fn command_polling_handles_network_cap_concurrency() {
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        for index in 0..MAX_NETWORK_LEASES {
            let node_id = format!("node-{index}");
            let lease = LeaseRecord {
                lease_id: index as u64 + 1,
                chain_lease_id: index as u64 + 1,
                escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                quote_id: Uuid::now_v7(),
                node_id: node_id.clone(),
                renter_wallet: format!("0x{}", "11".repeat(20)),
                image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
                duration_seconds: 60,
                rate_per_second: 100,
                maximum_escrow: 6_000,
                trust_class: TrustClass::Open,
                funding_transaction_hash: format!("0x{index:064x}"),
                state: LeaseState::Funded,
                command: None,
                repro: None,
                created_at: now,
                updated_at: now,
            };
            let command = launch_command(
                &lease,
                Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"),
                &"a".repeat(64),
            )
            .unwrap();
            market
                .leases
                .insert(lease.lease_id, (format!("subject-{index}"), lease));
            market.commands.insert(
                command.command_id,
                MemoryCommand {
                    command,
                    result: None,
                    status: "queued",
                    lease_until: None,
                    authorization_request_id: None,
                    verified_report: None,
                    updated_at: now,
                },
            );
        }
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let mut tasks = Vec::new();
        for index in 0..MAX_NETWORK_LEASES {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .claim_command(&format!("node-{index}"), Uuid::now_v7())
                    .await
            }));
        }
        let mut commands = BTreeSet::new();
        for task in tasks {
            commands.insert(task.await.unwrap().unwrap().unwrap().command_id);
        }
        assert_eq!(commands.len(), MAX_NETWORK_LEASES);
    }

    #[test]
    fn funding_event_is_bound_to_the_exact_quote() {
        let quote_id = Uuid::now_v7();
        let quote = LeaseQuote {
            command: None,
            repro: None,
            quote_id,
            node_id: format!("0x{}", "ab".repeat(32)),
            image: format!("registry.example/runtime@sha256:{}", "cd".repeat(32)),
            duration_seconds: 600,
            min_vram_mib: 16_000,
            rate_per_second: 100,
            maximum_escrow: 60_000,
            trust_class: TrustClass::Open,
            expires_at: Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES),
        };
        let lease_id = 42_u64;
        let renter = "11".repeat(20);
        let mut data = Vec::new();
        data.extend(abi_word(quote.maximum_escrow));
        data.extend(abi_word(u64::from(quote.duration_seconds)));
        data.extend(quote_reference(quote_id));
        let event = ChainLog {
            address: "0x2222222222222222222222222222222222222222".to_owned(),
            topics: vec![
                format!(
                    "0x{}",
                    hex::encode(Keccak256::digest(
                        b"LeaseFunded(uint256,bytes32,address,uint256,uint32,bytes32)"
                    ))
                ),
                format!("0x{}", hex::encode(abi_word(lease_id))),
                quote.node_id.clone(),
                format!("0x{}{}", "00".repeat(12), renter),
            ],
            data: format!("0x{}", hex::encode(&data)),
        };

        let funding = decode_funding_event(
            &[event],
            "0x2222222222222222222222222222222222222222",
            &quote,
        )
        .unwrap();
        assert_eq!(funding.lease_id, lease_id);
        assert_eq!(funding.renter_wallet, format!("0x{renter}"));

        let mut wrong_quote = quote;
        wrong_quote.quote_id = Uuid::now_v7();
        assert!(matches!(
            decode_funding_event(
                &[ChainLog {
                    address: "0x2222222222222222222222222222222222222222".to_owned(),
                    topics: vec![
                        format!(
                            "0x{}",
                            hex::encode(Keccak256::digest(
                                b"LeaseFunded(uint256,bytes32,address,uint256,uint32,bytes32)"
                            ))
                        ),
                        format!("0x{}", hex::encode(abi_word(lease_id))),
                        wrong_quote.node_id.clone(),
                        format!("0x{}{}", "00".repeat(12), renter),
                    ],
                    data: format!("0x{}", hex::encode(data)),
                }],
                "0x2222222222222222222222222222222222222222",
                &wrong_quote,
            ),
            Err(ChainError::FundingMismatch)
        ));
    }

    /// Suspension is the one control that exists to stop a node immediately.
    /// Every other node check runs at quote time, and a quote stays confirmable
    /// for a day, so a node suspended for abuse kept taking new work until the
    /// last quote naming it expired.
    #[tokio::test]
    async fn a_suspended_node_cannot_take_a_lease_on_an_older_quote() {
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 222, 100_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };
        let quote = store.quote("renter", &request, 0).await.unwrap();

        // Quoted while healthy, suspended before the renter confirms.
        match &store {
            MarketplaceStore::Memory(market) => {
                market
                    .write()
                    .await
                    .suspended_nodes
                    .insert("only".to_owned());
            }
            _ => unreachable!(),
        }

        let confirmed = store
            .confirm_funding(FundingConfirmation {
                subject: "renter",
                quote: &quote,
                transaction_hash: &format!("0x{}", "ee".repeat(32)),
                funding: ConfirmedFunding {
                    lease_id: 77,
                    escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                    renter_wallet: format!("0x{}", "33".repeat(20)),
                },
                ssh_authorized_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA"),
                jupyter_token: "token",
                encrypted_jupyter_token: EncryptedSecret {
                    nonce: "bm9uY2U".to_owned(),
                    ciphertext: "Y2lwaGVy".to_owned(),
                },
            })
            .await;
        assert!(
            matches!(confirmed, Err(StoreError::NodeSuspended)),
            "a suspended node must refuse the lease, got {confirmed:?}"
        );
    }

    /// Production regression. Replacing the escrow restarted its lease counter
    /// at 1, so a fresh lease 3 arrived while a superseded escrow's failed lease
    /// 3 was still on file. The historical row must neither reserve the node nor
    /// make confirmation look like a replay.
    #[tokio::test]
    async fn a_failed_lease_from_a_superseded_escrow_does_not_reserve_or_replay() {
        let superseded = "0x71df0ef3bc81022cb3bec0b1a05f52f12bafcded";
        let current = "0x62c042265991bea17b07229322a01850974626da";
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 222, 100_000));
        market.tunnels.insert("only".to_owned(), Utc::now());
        let history = LeaseRecord {
            lease_id: 3,
            chain_lease_id: 3,
            escrow_address: superseded.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "only".to_owned(),
            renter_wallet: format!("0x{}", "11".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            rate_per_second: 222,
            maximum_escrow: 13_320,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{}", "cc".repeat(32)),
            state: LeaseState::Failed,
            command: None,
            repro: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        market
            .leases
            .insert(3, ("someone-else".to_owned(), history));
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };
        let quote = store
            .quote_for_escrow("renter", &request, 0, current)
            .await
            .expect("a superseded escrow must not reserve current capacity");
        let confirmed = store
            .confirm_funding(FundingConfirmation {
                subject: "renter",
                quote: &quote,
                transaction_hash: &format!("0x{}", "dd".repeat(32)),
                funding: ConfirmedFunding {
                    lease_id: 3,
                    escrow_address: current.to_owned(),
                    renter_wallet: format!("0x{}", "22".repeat(20)),
                },
                ssh_authorized_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA"),
                jupyter_token: "token",
                encrypted_jupyter_token: EncryptedSecret {
                    nonce: "bm9uY2U".to_owned(),
                    ciphertext: "Y2lwaGVy".to_owned(),
                },
            })
            .await
            .expect("a new escrow's lease 3 is a different lease, not a replay");

        assert_eq!(confirmed.chain_lease_id, 3);
        assert_eq!(confirmed.escrow_address, current);
        assert_ne!(
            confirmed.lease_id, 3,
            "the internal id must not collide with the superseded record"
        );
        assert!(confirmed.lease_id >= INTERNAL_LEASE_ID_FLOOR);

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        market
            .write()
            .await
            .leases
            .get_mut(&confirmed.lease_id)
            .unwrap()
            .1
            .state = LeaseState::Failed;
        assert!(matches!(
            store
                .quote_for_escrow("next-renter", &request, 0, current)
                .await,
            Err(StoreError::CapacityReserved)
        ));
    }

    #[test]
    fn dispute_resolution_calldata_is_safe_ready() {
        let calldata =
            resolve_dispute_calldata(42, 3_600, &format!("0x{}", "ab".repeat(32))).unwrap();
        assert_eq!(&calldata[..10], "0x001bb9c1");
        assert_eq!(calldata.len(), 202);
        assert_eq!(&calldata[10..74], &format!("{:064x}", 42));
        assert_eq!(&calldata[74..138], &format!("{:064x}", 3_600));
        assert_eq!(&calldata[138..], &"ab".repeat(32));
        assert!(resolve_dispute_calldata(1, 1, "0x01").is_err());
    }

    #[tokio::test]
    async fn command_queue_is_exclusive_replay_safe_and_updates_the_lease() {
        let node = format!("0x{}", "aa".repeat(32));
        let now = Utc::now();
        let lease = LeaseRecord {
            lease_id: 7,
            chain_lease_id: 7,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: node.clone(),
            renter_wallet: format!("0x{}", "11".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "bb".repeat(32)),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{}", "cc".repeat(32)),
            state: LeaseState::Funded,
            command: None,
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(
            &lease,
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"),
            &"a".repeat(64),
        )
        .unwrap();
        let command_id = command.command_id;
        let market = MemoryMarketplace {
            leases: BTreeMap::from([(lease.lease_id, ("subject".to_owned(), lease))]),
            commands: BTreeMap::from([(
                command_id,
                MemoryCommand {
                    command,
                    result: None,
                    status: "queued",
                    lease_until: None,
                    authorization_request_id: None,
                    verified_report: None,
                    updated_at: now,
                },
            )]),
            ..MemoryMarketplace::default()
        };
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        let request_id = Uuid::now_v7();
        assert_eq!(
            store
                .claim_command(&node, request_id)
                .await
                .unwrap()
                .unwrap()
                .command_id,
            command_id
        );
        assert!(matches!(
            store.claim_command(&node, request_id).await,
            Err(StoreError::CommandReplay)
        ));

        let report = NodeCommandReport {
            node_id: node,
            device_public_key: "test".to_owned(),
            request_id: Uuid::now_v7(),
            command_id,
            outcome: NodeCommandOutcome::Ready,
            observed_at: Utc::now(),
            error: None,
            result: None,
            channel_key: None,
            signature: "test".to_owned(),
        };
        store.report_command(&report, None).await.unwrap();
        let market = match store {
            MarketplaceStore::Memory(market) => market,
            MarketplaceStore::Postgres(_) => unreachable!(),
        };
        let market = market.read().await;
        assert_eq!(market.leases.get(&7).unwrap().1.state, LeaseState::Ready);
        assert_eq!(market.commands.get(&command_id).unwrap().status, "ready");
    }

    #[tokio::test]
    async fn a_batch_runs_only_after_active_and_persists_its_signed_result() {
        let node = format!("0x{}", "ab".repeat(32));
        let now = Utc::now();
        let lease = LeaseRecord {
            lease_id: 17,
            chain_lease_id: 17,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: node.clone(),
            renter_wallet: format!("0x{}", "12".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "cd".repeat(32)),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{}", "ef".repeat(32)),
            state: LeaseState::Funded,
            command: Some("nvidia-smi -L".to_owned()),
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(&lease, None, "unused").unwrap();
        let command_id = command.command_id;
        let market = Arc::new(RwLock::new(MemoryMarketplace {
            leases: BTreeMap::from([(lease.lease_id, ("subject".to_owned(), lease))]),
            commands: BTreeMap::from([(
                command_id,
                MemoryCommand {
                    command,
                    status: "queued",
                    lease_until: None,
                    authorization_request_id: None,
                    result: None,
                    verified_report: None,
                    updated_at: now,
                },
            )]),
            ..MemoryMarketplace::default()
        }));
        let store = MarketplaceStore::Memory(market.clone());
        store
            .claim_command(&node, Uuid::now_v7())
            .await
            .unwrap()
            .unwrap();
        let ready = NodeCommandReport {
            node_id: node.clone(),
            device_public_key: "device-key".to_owned(),
            request_id: Uuid::now_v7(),
            command_id,
            outcome: NodeCommandOutcome::Ready,
            observed_at: Utc::now(),
            error: None,
            result: None,
            channel_key: None,
            signature: "signature".to_owned(),
        };
        store.report_command(&ready, None).await.unwrap();
        assert!(
            !store
                .authorize_command(&node, command_id, Uuid::now_v7())
                .await
                .unwrap(),
            "a Funded lease cannot authorize execution"
        );

        market.write().await.leases.get_mut(&17).unwrap().1.state = LeaseState::Active;
        let execution_claim = Uuid::now_v7();
        assert!(
            store
                .authorize_command(&node, command_id, execution_claim)
                .await
                .unwrap()
        );
        assert!(
            store
                .authorize_command(&node, command_id, execution_claim)
                .await
                .unwrap(),
            "a lost response is retryable by the same signed claim"
        );
        assert!(matches!(
            store
                .authorize_command(&node, command_id, Uuid::now_v7())
                .await,
            Err(StoreError::CommandClaimed)
        ));

        let result = CommandResult::capture(0, "GPU ready\n", "");
        let completed = NodeCommandReport {
            node_id: node,
            device_public_key: "device-key".to_owned(),
            request_id: Uuid::now_v7(),
            command_id,
            outcome: NodeCommandOutcome::Completed,
            observed_at: Utc::now(),
            error: None,
            result: Some(result.clone()),
            channel_key: None,
            signature: "signature".to_owned(),
        };
        store.report_command(&completed, None).await.unwrap();

        let market = market.read().await;
        let command = market.commands.get(&command_id).unwrap();
        assert_eq!(command.status, "completed");
        assert_eq!(command.result.as_ref(), Some(&result));
        assert_eq!(command.verified_report.as_ref(), Some(&completed));
        assert_eq!(market.leases.get(&17).unwrap().1.state, LeaseState::Closing);
        assert!(market.lifecycle_actions.contains(&(17, "start_access")));
        assert!(market.lifecycle_actions.contains(&(17, "close_access")));
    }

    /// Once a renter has released, the node reporting that it stopped the
    /// container is bookkeeping: the command completes, and neither the lease
    /// nor the money moves again.
    #[test]
    fn a_node_letting_go_of_a_released_lease_completes_its_command_quietly() {
        let now = Utc::now();
        let lease = LeaseRecord {
            lease_id: 23,
            chain_lease_id: 23,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "node".to_owned(),
            renter_wallet: "renter".to_owned(),
            image: "registry.example/runtime@sha256:abc".to_owned(),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: "0xabc".to_owned(),
            state: LeaseState::Closing,
            command: None,
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(&lease, Some("ssh-ed25519 AAAA"), "unused").unwrap();
        let report = NodeCommandReport {
            node_id: "node".to_owned(),
            device_public_key: "device-key".to_owned(),
            request_id: Uuid::now_v7(),
            command_id: command.command_id,
            outcome: NodeCommandOutcome::Completed,
            observed_at: now,
            error: None,
            result: None,
            channel_key: None,
            signature: "signature".to_owned(),
        };
        for state in [
            LeaseState::Closing,
            LeaseState::SettlementPending,
            LeaseState::Finalized,
        ] {
            let transition = command_report_transition(&command, "ready", &state, &report)
                .expect("a stopped container is always worth recording");
            assert_eq!(transition.status, "completed");
            assert_eq!(transition.lease_state, None);
            assert_eq!(transition.action, None);
            assert!(!transition.renew_claim);
        }
        // Before access opened there is no container to have stopped, so the
        // report is rejected as it always was.
        assert!(
            command_report_transition(&command, "ready", &LeaseState::Ready, &report).is_none()
        );

        // Letting go can fail: the container may have exited on its own, or the
        // runtime may refuse to stop it. Refusing that report leaves the daemon
        // retrying it forever against a lease that will never take it back, and
        // the command row holding the node out of every offer.
        for outcome in [NodeCommandOutcome::Failed, NodeCommandOutcome::Completed] {
            for current in ["queued", "leased", "ready", "running"] {
                for state in [
                    LeaseState::Closing,
                    LeaseState::SettlementPending,
                    LeaseState::Disputed,
                    LeaseState::Finalized,
                    LeaseState::Refunded,
                    LeaseState::Failed,
                ] {
                    let report = NodeCommandReport {
                        outcome: outcome.clone(),
                        ..report.clone()
                    };
                    let transition = command_report_transition(&command, current, &state, &report)
                        .expect("a node that cannot place its report stops polling");
                    assert_eq!(transition.lease_state, None, "{current} {state:?}");
                    assert_eq!(transition.action, None, "{current} {state:?}");
                    assert!(!transition.renew_claim, "{current} {state:?}");
                }
            }
        }

        // A ready report during the wind-down keeps the claim: the node is told
        // where the lease stands and stops the container itself.
        let ready = NodeCommandReport {
            outcome: NodeCommandOutcome::Ready,
            ..report.clone()
        };
        let transition =
            command_report_transition(&command, "leased", &LeaseState::Closing, &ready).unwrap();
        assert_eq!(transition.status, "ready");
        assert_eq!(transition.lease_state, None);
        assert_eq!(transition.action, None);
        assert!(transition.renew_claim);

        // A ready report the node kept retrying arrives after the command was
        // closed out. It is accepted and changes nothing: reopening the row
        // would hold the machine out of the market all over again.
        for current in ["completed", "failed"] {
            let transition =
                command_report_transition(&command, current, &LeaseState::Finalized, &ready)
                    .unwrap();
            assert_eq!(transition.status, current);
            assert!(!transition.renew_claim);
        }
    }

    /// A node that polls while holding a command for a lease that has ended is
    /// not handed that lease back: the workspace would run on compute nobody
    /// pays for. The row is closed instead, which is what frees the node for
    /// the next renter.
    #[tokio::test]
    async fn a_poll_closes_out_a_released_lease_instead_of_relaunching_it() {
        let node = format!("0x{}", "ad".repeat(32));
        let now = Utc::now();
        let lease = LeaseRecord {
            lease_id: 29,
            chain_lease_id: 29,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: node.clone(),
            renter_wallet: format!("0x{}", "13".repeat(20)),
            image: format!("registry.example/runtime@sha256:{}", "de".repeat(32)),
            duration_seconds: 3_600,
            rate_per_second: 100,
            maximum_escrow: 360_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: format!("0x{}", "fa".repeat(32)),
            state: LeaseState::Closing,
            command: None,
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(&lease, Some("ssh-ed25519 AAAA"), "unused").unwrap();
        let command_id = command.command_id;
        let market = Arc::new(RwLock::new(MemoryMarketplace {
            leases: BTreeMap::from([(lease.lease_id, ("subject".to_owned(), lease))]),
            commands: BTreeMap::from([(
                command_id,
                MemoryCommand {
                    command,
                    status: "ready",
                    lease_until: Some(now - Duration::minutes(5)),
                    authorization_request_id: None,
                    result: None,
                    verified_report: None,
                    updated_at: now - Duration::minutes(5),
                },
            )]),
            ..MemoryMarketplace::default()
        }));
        let store = MarketplaceStore::Memory(market.clone());
        assert!(
            store
                .claim_command(&node, Uuid::now_v7())
                .await
                .unwrap()
                .is_none()
        );
        let market = market.read().await;
        assert_eq!(market.commands.get(&command_id).unwrap().status, "failed");
        assert!(!nodes_holding_commands(&market).contains(&node));
    }

    #[test]
    fn a_prestart_batch_failure_expires_instead_of_closing_access() {
        let now = Utc::now();
        let lease = LeaseRecord {
            lease_id: 19,
            chain_lease_id: 19,
            escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
            quote_id: Uuid::now_v7(),
            node_id: "node".to_owned(),
            renter_wallet: "renter".to_owned(),
            image: "registry.example/runtime@sha256:abc".to_owned(),
            duration_seconds: 60,
            rate_per_second: 100,
            maximum_escrow: 6_000,
            trust_class: TrustClass::Open,
            funding_transaction_hash: "0xabc".to_owned(),
            state: LeaseState::Provisioning,
            command: Some("false".to_owned()),
            repro: None,
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(&lease, None, "unused").unwrap();
        let report = NodeCommandReport {
            node_id: "node".to_owned(),
            device_public_key: "device-key".to_owned(),
            request_id: Uuid::now_v7(),
            command_id: command.command_id,
            outcome: NodeCommandOutcome::Failed,
            observed_at: now,
            error: Some("preflight failed".to_owned()),
            result: None,
            channel_key: None,
            signature: "signature".to_owned(),
        };
        let transition =
            command_report_transition(&command, "leased", &lease.state, &report).unwrap();

        assert_eq!(transition.status, "failed");
        assert_eq!(transition.lease_state, Some(LeaseState::Closing));
        assert_eq!(transition.action, Some("expire_provision"));
    }

    fn envelope(ciphertext: &str) -> VaultEnvelope {
        VaultEnvelope {
            wrapped_key: "d3JhcHBlZA".to_owned(),
            nonce: "bm9uY2UtMTIzNA".to_owned(),
            ciphertext: ciphertext.to_owned(),
        }
    }

    fn vault_write(ciphertext: &str, floor: TrustClass) -> VaultWrite {
        VaultWrite {
            envelope: envelope(ciphertext),
            min_trust_class: floor,
            label: "card".to_owned(),
            previous_version: None,
        }
    }

    async fn store_with_active_lease(subject: &str, trust_class: TrustClass) -> MarketplaceStore {
        let mut market = MemoryMarketplace::default();
        market.leases.insert(
            9,
            (
                subject.to_owned(),
                LeaseRecord {
                    lease_id: 9,
                    chain_lease_id: 9,
                    escrow_address: DEVELOPMENT_ESCROW_ADDRESS.to_owned(),
                    quote_id: Uuid::now_v7(),
                    node_id: "node".to_owned(),
                    renter_wallet: "0x1".to_owned(),
                    image: "registry.example/runtime@sha256:abc".to_owned(),
                    duration_seconds: 60,
                    rate_per_second: 100,
                    maximum_escrow: 6_000,
                    trust_class,
                    funding_transaction_hash: "0xabc".to_owned(),
                    state: LeaseState::Active,
                    command: None,
                    repro: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ),
        );
        // The vault and workspace gates recompute the lease class from the
        // node's live standing, so a lease that is meant to be servable at
        // `trust_class` needs the standing that earns it: a fresh tunnel and a
        // node verdict for Isolated, a lease guest verdict for Attested, and a
        // GPU-CC verdict for Confidential.
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);
        if trust_class >= TrustClass::Isolated {
            market.tunnels.insert("node".to_owned(), now);
            market.verdicts.insert(
                "node".to_owned(),
                AttestationVerdict {
                    node_id: "node".to_owned(),
                    kind: AttestationKind::Tdx,
                    device_identity: "tdx/node".to_owned(),
                    measurement_digest: "0".repeat(64),
                    claimed_capability: prism_protocol::HostTeeCapability::default(),
                    granted_class: TrustClass::Isolated,
                    verifier_version: "test".to_owned(),
                    verified_at: now,
                    expires_at,
                },
            );
        }
        if trust_class >= TrustClass::Attested {
            market
                .lease_tdx_guest_verdicts
                .insert(9, tdx_guest_verdict(9, "node", expires_at));
        }
        if trust_class >= TrustClass::Confidential {
            market
                .lease_gpu_cc_verdicts
                .insert(9, gpu_cc_verdict(9, "node", expires_at));
        }
        MarketplaceStore::Memory(Arc::new(RwLock::new(market)))
    }

    #[tokio::test]
    async fn a_vault_item_is_invisible_to_every_other_account() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())));
        let item_id = Uuid::now_v7();
        store
            .write_vault_item(
                "owner",
                item_id,
                vault_write("c2VjcmV0", TrustClass::Confidential),
            )
            .await
            .unwrap();

        assert!(
            store
                .vault_item("intruder", item_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.list_vault_items("intruder").await.unwrap().is_empty());
        assert!(matches!(
            store.delete_vault_item("intruder", item_id).await,
            Err(StoreError::VaultItemNotFound)
        ));
        // The intruder must not be able to overwrite the slot either, which
        // would destroy the owner's item without ever reading it.
        assert!(matches!(
            store
                .write_vault_item(
                    "intruder",
                    item_id,
                    vault_write("b3RoZXI", TrustClass::Open)
                )
                .await,
            Err(StoreError::VaultItemNotFound)
        ));
        assert_eq!(
            store
                .vault_item("owner", item_id)
                .await
                .unwrap()
                .unwrap()
                .envelope
                .ciphertext,
            "c2VjcmV0"
        );
    }

    #[tokio::test]
    async fn a_vault_write_that_lost_the_race_is_rejected_rather_than_merged() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())));
        let item_id = Uuid::now_v7();
        let created = store
            .write_vault_item(
                "owner",
                item_id,
                vault_write("dg", TrustClass::Confidential),
            )
            .await
            .unwrap();
        assert_eq!(created.version, 1);

        let second = store
            .write_vault_item(
                "owner",
                item_id,
                VaultWrite {
                    previous_version: Some(1),
                    ..vault_write("djI", TrustClass::Confidential)
                },
            )
            .await
            .unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second.created_at, created.created_at);

        // A writer still holding version 1 must not clobber version 2.
        assert!(matches!(
            store
                .write_vault_item(
                    "owner",
                    item_id,
                    VaultWrite {
                        previous_version: Some(1),
                        ..vault_write("c3RhbGU", TrustClass::Confidential)
                    },
                )
                .await,
            Err(StoreError::VaultVersionConflict)
        ));
        // And a create against an occupied slot is a conflict, not a silent replace.
        assert!(matches!(
            store
                .write_vault_item(
                    "owner",
                    item_id,
                    vault_write("bmV3", TrustClass::Confidential)
                )
                .await,
            Err(StoreError::VaultVersionConflict)
        ));
        assert_eq!(
            store
                .vault_item("owner", item_id)
                .await
                .unwrap()
                .unwrap()
                .envelope
                .ciphertext,
            "djI"
        );
    }

    #[tokio::test]
    async fn releasing_into_a_weaker_lease_is_refused() {
        let store = store_with_active_lease("owner", TrustClass::Open).await;
        let item_id = Uuid::now_v7();
        store
            .write_vault_item(
                "owner",
                item_id,
                vault_write("Y2FyZA", DEFAULT_VAULT_TRUST_FLOOR),
            )
            .await
            .unwrap();

        assert!(matches!(
            store.release_vault_item("owner", item_id, 9).await,
            Err(StoreError::VaultTrustFloorUnmet { .. })
        ));
        // A refused release leaves no audit row; only real exposure is recorded.
        assert!(store.list_vault_releases("owner").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn releasing_into_a_qualifying_lease_is_recorded() {
        let store = store_with_active_lease("owner", TrustClass::Isolated).await;
        let item_id = Uuid::now_v7();
        store
            .write_vault_item(
                "owner",
                item_id,
                vault_write("dG9rZW4", TrustClass::Isolated),
            )
            .await
            .unwrap();

        let release = store.release_vault_item("owner", item_id, 9).await.unwrap();
        assert_eq!(release.lease_id, 9);
        assert_eq!(release.item_version, 1);
        assert_eq!(release.lease_trust_class, TrustClass::Isolated);

        let audit = store.list_vault_releases("owner").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].item_id, item_id);
        assert!(
            store
                .list_vault_releases("intruder")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_lapsed_node_cannot_release_a_confidential_secret() {
        let store = store_with_active_lease("owner", TrustClass::Confidential).await;
        let item_id = Uuid::now_v7();
        store
            .write_vault_item(
                "owner",
                item_id,
                vault_write("dG9rZW4", TrustClass::Confidential),
            )
            .await
            .unwrap();
        // With the node's tunnel fresh, the lease clears the confidential floor.
        store.release_vault_item("owner", item_id, 9).await.unwrap();

        // The node's tunnel lapses and nothing rewrites the cached class, but
        // the gate recomputes the class live, so the node is now Open and the
        // confidential secret is withheld.
        if let MarketplaceStore::Memory(market) = &store {
            market.write().await.tunnels.remove("node");
        }
        assert!(matches!(
            store.release_vault_item("owner", item_id, 9).await,
            Err(StoreError::VaultTrustFloorUnmet { .. })
        ));
    }

    #[tokio::test]
    async fn a_release_needs_an_active_lease_owned_by_the_caller() {
        let store = store_with_active_lease("owner", TrustClass::Confidential).await;
        let item_id = Uuid::now_v7();
        store
            .write_vault_item("owner", item_id, vault_write("dG9rZW4", TrustClass::Open))
            .await
            .unwrap();

        assert!(matches!(
            store.release_vault_item("owner", item_id, 404).await,
            Err(StoreError::VaultLeaseUnavailable)
        ));
        // Someone else's lease is not a venue for this account's items, even
        // when that lease would clear the floor.
        store
            .write_vault_item(
                "intruder",
                Uuid::now_v7(),
                vault_write("eA", TrustClass::Open),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.release_vault_item("intruder", item_id, 9).await,
            Err(StoreError::VaultItemNotFound)
        ));
    }

    #[tokio::test]
    async fn the_vault_stops_accepting_new_items_at_the_cap() {
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())));
        for _ in 0..MAX_VAULT_ITEMS_PER_ACCOUNT {
            store
                .write_vault_item("owner", Uuid::now_v7(), vault_write("eA", TrustClass::Open))
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .write_vault_item("owner", Uuid::now_v7(), vault_write("eA", TrustClass::Open))
                .await,
            Err(StoreError::VaultFull)
        ));
        // The cap is per account, so one full vault cannot starve anyone else.
        assert!(
            store
                .write_vault_item("other", Uuid::now_v7(), vault_write("eA", TrustClass::Open))
                .await
                .is_ok()
        );
    }

    #[test]
    fn a_vault_write_must_be_base64url_and_within_the_size_cap() {
        assert!(validate_vault_write(&vault_write("Y2FyZA", TrustClass::Open)).is_ok());

        let padded = vault_write("Y2FyZA==", TrustClass::Open);
        assert!(validate_vault_write(&padded).is_err());

        let oversized = vault_write(
            &"a".repeat(MAX_VAULT_CIPHERTEXT_BYTES + 1),
            TrustClass::Open,
        );
        assert!(validate_vault_write(&oversized).is_err());

        let empty = vault_write("", TrustClass::Open);
        assert!(validate_vault_write(&empty).is_err());

        let long_label = VaultWrite {
            label: "l".repeat(MAX_VAULT_LABEL_BYTES + 1),
            ..vault_write("Y2FyZA", TrustClass::Open)
        };
        assert!(validate_vault_write(&long_label).is_err());
    }

    // Absent trust class means the strongest floor, never the weakest. A client
    // that forgets the field must not end up storing a card at "open".
    #[test]
    fn a_vault_write_without_a_trust_class_defaults_to_the_strongest_floor() {
        let write: VaultWrite = serde_json::from_value(serde_json::json!({
            "envelope": {"wrapped_key": "dw", "nonce": "bg", "ciphertext": "Yw"}
        }))
        .unwrap();

        assert_eq!(write.min_trust_class, DEFAULT_VAULT_TRUST_FLOOR);
        assert!(write.previous_version.is_none());
    }

    fn memory_store() -> MarketplaceStore {
        MarketplaceStore::Memory(Arc::new(RwLock::new(MemoryMarketplace::default())))
    }

    fn snapshot(size_bytes: u64) -> WorkspaceSnapshot {
        WorkspaceSnapshot {
            wrapped_key: "d3JhcHBlZA".to_owned(),
            nonce: "bm9uY2UtMTIzNA".to_owned(),
            ciphertext_digest: "a".repeat(64),
            size_bytes,
        }
    }

    #[tokio::test]
    async fn a_workspace_is_invisible_to_every_other_account() {
        let store = memory_store();
        let workspace = store
            .create_workspace("owner", "checkpoints", TrustClass::Open)
            .await
            .unwrap();
        let workspace_id = workspace.workspace_id;

        assert!(
            store
                .workspace("intruder", workspace_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.list_workspaces("intruder").await.unwrap().is_empty());
        assert!(matches!(
            store.delete_workspace("intruder", workspace_id).await,
            Err(StoreError::WorkspaceNotFound)
        ));
        // Committing over a stranger's workspace would destroy their snapshot
        // without ever reading it, and point the row at bytes they cannot open.
        assert!(matches!(
            store
                .commit_workspace_snapshot("intruder", workspace_id, 1, snapshot(64))
                .await,
            Err(StoreError::WorkspaceNotFound)
        ));
        assert_eq!(
            store
                .workspace("owner", workspace_id)
                .await
                .unwrap()
                .unwrap()
                .version,
            0
        );
        // And the objects the two would presign never collide, so knowing a
        // workspace id is not enough to name someone else's snapshot.
        assert_ne!(
            workspaces::WorkspaceStorage::key("owner", workspace_id, 1),
            workspaces::WorkspaceStorage::key("intruder", workspace_id, 1),
        );
    }

    #[tokio::test]
    async fn the_workspace_cap_is_counted_per_account() {
        let store = memory_store();
        for index in 0..MAX_WORKSPACES_PER_ACCOUNT {
            store
                .create_workspace("owner", &format!("run-{index}"), TrustClass::Open)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .create_workspace("owner", "one-more", TrustClass::Open)
                .await,
            Err(StoreError::WorkspaceFull)
        ));
        // A full account cannot starve anyone else, and a name is only taken
        // for the account that took it.
        assert!(
            store
                .create_workspace("other", "run-0", TrustClass::Open)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn one_account_cannot_hold_the_same_workspace_name_twice() {
        let store = memory_store();
        store
            .create_workspace("owner", "checkpoints", TrustClass::Open)
            .await
            .unwrap();
        assert!(matches!(
            store
                .create_workspace("owner", "checkpoints", TrustClass::Open)
                .await,
            Err(StoreError::WorkspaceNameTaken)
        ));
    }

    #[tokio::test]
    async fn a_commit_only_lands_on_the_version_that_was_presigned() {
        let store = memory_store();
        let workspace = store
            .create_workspace("owner", "checkpoints", TrustClass::Open)
            .await
            .unwrap();
        let workspace_id = workspace.workspace_id;

        // Nothing is committed yet, so version 2 was never on offer.
        assert!(matches!(
            store
                .commit_workspace_snapshot("owner", workspace_id, 2, snapshot(64))
                .await,
            Err(StoreError::WorkspaceVersionConflict)
        ));

        let first = store
            .commit_workspace_snapshot("owner", workspace_id, 1, snapshot(64))
            .await
            .unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.snapshot.unwrap().size_bytes, 64);

        // A second machine that presigned version 1 before the first committed
        // must not replace it, because both sealed different bytes as v1.
        assert!(matches!(
            store
                .commit_workspace_snapshot("owner", workspace_id, 1, snapshot(9))
                .await,
            Err(StoreError::WorkspaceVersionConflict)
        ));

        let second = store
            .commit_workspace_snapshot("owner", workspace_id, 2, snapshot(128))
            .await
            .unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second.created_at, workspace.created_at);
        assert_eq!(second.snapshot.unwrap().size_bytes, 128);
    }

    #[tokio::test]
    async fn a_workspace_with_no_snapshot_has_nothing_to_download() {
        let store = memory_store();
        let workspace = store
            .create_workspace("owner", "checkpoints", TrustClass::Open)
            .await
            .unwrap();
        assert!(workspace.snapshot.is_none());
        assert!(committed_snapshot(&workspace).is_err());

        let committed = store
            .commit_workspace_snapshot("owner", workspace.workspace_id, 1, snapshot(64))
            .await
            .unwrap();
        assert!(committed_snapshot(&committed).is_ok());
    }

    #[test]
    fn a_workspace_name_must_be_printable_and_short() {
        assert!(validate_workspace_name("checkpoints").is_ok());
        assert!(validate_workspace_name("").is_err());
        assert!(validate_workspace_name("   ").is_err());
        assert!(validate_workspace_name(&"n".repeat(MAX_WORKSPACE_NAME_BYTES + 1)).is_err());
        assert!(validate_workspace_name("two\nlines").is_err());
    }

    #[test]
    fn a_snapshot_too_large_to_store_is_refused_before_it_is_presigned() {
        assert!(validate_snapshot_size(1).is_ok());
        assert!(validate_snapshot_size(0).is_err());
        assert!(validate_snapshot_size(MAX_WORKSPACE_BYTES + 1).is_err());
        // The per-workspace cap is larger than one upload can carry, so this
        // has to be refused here rather than at the end of a long PUT.
        const { assert!(MAX_SNAPSHOT_UPLOAD_BYTES < MAX_WORKSPACE_BYTES) };
        assert!(validate_snapshot_size(MAX_SNAPSHOT_UPLOAD_BYTES + 1).is_err());
    }

    #[test]
    fn a_commit_must_carry_a_lowercase_sha256_digest() {
        let commit = |digest: &str| SnapshotCommitRequest {
            version: 1,
            snapshot: WorkspaceSnapshot {
                ciphertext_digest: digest.to_owned(),
                ..snapshot(64)
            },
        };
        assert!(validate_snapshot_commit(&commit(&"a".repeat(64))).is_ok());
        assert!(validate_snapshot_commit(&commit(&"A".repeat(64))).is_err());
        assert!(validate_snapshot_commit(&commit(&"a".repeat(63))).is_err());
        assert!(validate_snapshot_commit(&commit("")).is_err());

        let unversioned = SnapshotCommitRequest {
            version: 0,
            snapshot: snapshot(64),
        };
        assert!(validate_snapshot_commit(&unversioned).is_err());
    }

    // Unlike a vault item, a workspace defaults to the weakest floor. Its
    // contents are the files the renter is already handing to a rented machine,
    // and a default no live capacity meets would make the feature unusable.
    #[test]
    fn a_workspace_request_without_a_trust_class_defaults_to_open() {
        let request: WorkspaceRequest =
            serde_json::from_value(serde_json::json!({"name": "checkpoints"})).unwrap();

        assert_eq!(request.min_trust_class, DEFAULT_WORKSPACE_TRUST_FLOOR);
        assert_eq!(request.name, "checkpoints");
    }

    // Marking has to happen wherever offers are read for matching. An earlier
    // cut applied it only in list_offers, which the matcher does not use, so
    // the pool would have been advertised and then ignored at the gate.
    #[test]
    fn configured_capacity_is_marked_and_the_rest_is_left_alone() {
        let pool = offer("0xPOOL", 177, 10_000);
        let ordinary = offer("0xother", 222, 10_000);
        assert!(
            !pool.staker_only && !ordinary.staker_only,
            "flag is off by default"
        );

        // Set from configuration, matched case-insensitively.
        let marked = {
            let ids: BTreeSet<String> = ["0xpool".to_owned()].into_iter().collect();
            let mut offers = vec![pool.clone(), ordinary.clone()];
            for entry in &mut offers {
                entry.staker_only = ids.contains(&entry.node_id.to_ascii_lowercase());
            }
            offers
        };
        assert!(marked[0].staker_only, "configured node was not marked");
        assert!(!marked[1].staker_only, "an unconfigured node was marked");

        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ef".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1_024,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        // Unstaked renters get the ordinary node and never the pool.
        let quote = quote_for_offers(&request, marked.iter(), &BTreeSet::new(), 0).unwrap();
        assert_eq!(quote.node_id, "0xother");

        // The top tier reaches the pool and pays the lower rate.
        let quote = quote_for_offers(&request, marked.iter(), &BTreeSet::new(), 250_000).unwrap();
        assert_eq!(quote.node_id, "0xPOOL");
        assert_eq!(quote.rate_per_second, 177);
    }

    #[test]
    fn staker_capacity_needs_enough_stake_to_reach() {
        let mut discounted = offer("cheap", 190, 10_000);
        discounted.staker_only = true;
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "ab".repeat(32)),
            duration_seconds: 60,
            min_vram_mib: 1_024,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        // 190 sits below the floor for an unstaked renter, so it is invisible.
        assert!(matches!(
            quote_for_offers(&request, [&discounted], &BTreeSet::new(), 0),
            Err(StoreError::NoMatch)
        ));

        // 10k PRISM buys 10%, a floor of 199, which still does not reach it.
        assert!(matches!(
            quote_for_offers(&request, [&discounted], &BTreeSet::new(), 10_000),
            Err(StoreError::NoMatch)
        ));

        // 250k buys the full 20%, a floor of 177, and the node becomes matchable.
        let quote = quote_for_offers(&request, [&discounted], &BTreeSet::new(), 250_000)
            .expect("top tier should reach discounted capacity");
        assert_eq!(quote.rate_per_second, 190);
        assert_eq!(quote.maximum_escrow, 190 * 60);
    }

    // Ordinary capacity has to stay reachable by everyone, or staking would
    // gate access to the network rather than to a cheaper pool. That includes
    // an independent operator who simply prices below the published rate.
    #[test]
    fn ordinary_capacity_is_reachable_without_any_stake() {
        let listed = offer("listed", STANDARD_RATE_PER_SECOND, 10_000);
        let cheap_independent = offer("independent", 150, 10_000);
        let request = LeaseRequest {
            image: format!("registry.example/runtime@sha256:{}", "cd".repeat(32)),
            duration_seconds: 30,
            min_vram_mib: 1_024,
            preferred_node_id: None,
            min_trust_class: TrustClass::Open,
            command: None,
            repro: None,
        };

        for staked in [0, 1_000, 250_000, u64::MAX] {
            let quote = quote_for_offers(&request, [&listed], &BTreeSet::new(), staked)
                .expect("the published rate must always be matchable");
            assert_eq!(quote.rate_per_second, STANDARD_RATE_PER_SECOND);

            let quote = quote_for_offers(&request, [&cheap_independent], &BTreeSet::new(), staked)
                .expect("an unmarked cheap node must never be hidden");
            assert_eq!(quote.rate_per_second, 150);
        }
    }

    #[test]
    fn the_rate_floor_falls_as_stake_rises_and_never_passes_the_ceiling() {
        assert_eq!(rate_floor_for_stake(0), STANDARD_RATE_PER_SECOND);
        assert!(rate_floor_for_stake(1_000) < rate_floor_for_stake(0));
        assert!(rate_floor_for_stake(250_000) < rate_floor_for_stake(50_000));
        assert_eq!(
            rate_floor_for_stake(u64::MAX),
            discounted_rate(STANDARD_RATE_PER_SECOND, MAX_STAKE_DISCOUNT_BPS),
            "no stake may price below the ceiling",
        );
    }

    // Stake counts only for wallets the account actually proved it controls.
    #[test]
    fn renter_wallets_cover_the_authenticated_and_verified_wallets() {
        let agent = Account {
            subject: "wallet:0xAbC0000000000000000000000000000000000001".to_owned(),
            linked_wallets: Vec::new(),
            risk_hold: false,
        };
        assert_eq!(
            renter_wallets(&agent),
            vec!["0xabc0000000000000000000000000000000000001".to_owned()]
        );

        let browser = Account {
            subject: "did:privy:abc".to_owned(),
            linked_wallets: vec!["0xDEF0000000000000000000000000000000000002".to_owned()],
            risk_hold: false,
        };
        assert_eq!(
            renter_wallets(&browser),
            vec!["0xdef0000000000000000000000000000000000002".to_owned()]
        );

        // A subject that is not a wallet contributes nothing to price against.
        let neither = Account {
            subject: "wallet:not-an-address".to_owned(),
            linked_wallets: Vec::new(),
            risk_hold: false,
        };
        assert!(renter_wallets(&neither).is_empty());
    }

    // A wrong selector reads as "no stake" instead of erroring, so every
    // staker would silently lose their discount. Pin it.
    #[test]
    fn the_stake_selector_matches_the_contract() {
        let digest = Keccak256::digest(b"eligibleStakeOf(address)");
        assert_eq!(hex::encode(&digest[..4]), ELIGIBLE_STAKE_SELECTOR);
    }

    fn repro_quote(token_hash: String, node_id: &str) -> (LeaseQuote, GpuReproSpec) {
        let spec = GpuReproSpec {
            image: format!("registry.example/repro@sha256:{}", "a".repeat(64)),
            command: "python -c 'print(42)'".to_owned(),
            duration_seconds: 300,
            min_vram_mib: 16_000,
            expected_exit_code: 0,
        };
        let quote = LeaseQuote {
            quote_id: Uuid::now_v7(),
            node_id: node_id.to_owned(),
            image: spec.image.clone(),
            duration_seconds: spec.duration_seconds,
            min_vram_mib: spec.min_vram_mib,
            rate_per_second: 222,
            maximum_escrow: 66_600,
            trust_class: TrustClass::Open,
            command: Some(spec.command.clone()),
            repro: Some(ReproCapability {
                token_hash,
                spec_hash: spec.hash().unwrap(),
                expected_exit_code: spec.expected_exit_code,
                executor: ReproExecutor::Node,
            }),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        (quote, spec)
    }

    #[tokio::test]
    async fn a_repro_token_can_create_only_one_quote() {
        let token_hash = "a".repeat(64);
        let (template, _) = repro_quote(token_hash, "node-1");
        let request = LeaseRequest {
            image: template.image,
            duration_seconds: template.duration_seconds,
            min_vram_mib: template.min_vram_mib,
            preferred_node_id: None,
            min_trust_class: template.trust_class,
            command: template.command,
            repro: template.repro,
        };
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("node-1".to_owned(), offer("node-1", 222, 10_000));
        market.tunnels.insert("node-1".to_owned(), Utc::now());
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));
        store.claim_command("node-1", Uuid::now_v7()).await.unwrap();

        let first = store.quote("first", &request, 0).await.unwrap();
        let replay = store.quote("first", &request, 0).await.unwrap();
        assert_eq!(replay.quote_id, first.quote_id);
        assert!(matches!(
            store.quote("second", &request, 0).await,
            Err(StoreError::ReproTokenAlreadyUsed)
        ));
    }

    #[test]
    fn repro_status_accepts_only_canonical_capability_tokens() {
        let token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        assert_eq!(token.len(), 43);
        assert_eq!(
            canonical_repro_token_hash(&token),
            Some(repro_token_hash(&token).unwrap())
        );
        for malformed in [
            "not-a-capability".to_owned(),
            "a".repeat(64),
            format!("{token}="),
            format!(" {}", token),
        ] {
            assert_eq!(canonical_repro_token_hash(&malformed), None);
        }
        assert!(
            serde_json::from_value::<ReproStatusRequest>(serde_json::json!({
                "token": token,
                "token_hash": "a".repeat(64),
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn repro_status_tokens_are_isolated_in_memory() {
        let first_token = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let second_token = URL_SAFE_NO_PAD.encode([2_u8; 32]);
        let first_hash = repro_token_hash(&first_token).unwrap();
        let second_hash = repro_token_hash(&second_token).unwrap();
        let (first, _) = repro_quote(first_hash.clone(), "node-1");
        let (second, _) = repro_quote(second_hash.clone(), "node-2");
        let first_id = first.quote_id;
        let second_id = second.quote_id;
        let mut market = MemoryMarketplace::default();
        market.open_quotes.insert(first_id, first);
        market.open_quotes.insert(second_id, second);
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        assert_eq!(
            store
                .repro_status(&first_hash)
                .await
                .unwrap()
                .unwrap()
                .quote
                .quote_id,
            first_id
        );
        assert_eq!(
            store
                .repro_status(&second_hash)
                .await
                .unwrap()
                .unwrap()
                .quote
                .quote_id,
            second_id
        );
        assert!(store.repro_status(&"f".repeat(64)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn repro_status_rejects_a_token_reused_by_multiple_quotes() {
        let token_hash = "a".repeat(64);
        let (first, _) = repro_quote(token_hash.clone(), "node-1");
        let (second, _) = repro_quote(token_hash.clone(), "node-2");
        let mut market = MemoryMarketplace::default();
        market.open_quotes.insert(first.quote_id, first);
        market.open_quotes.insert(second.quote_id, second);
        let store = MarketplaceStore::Memory(Arc::new(RwLock::new(market)));

        assert!(matches!(
            store.repro_status(&token_hash).await,
            Err(StoreError::AmbiguousReproToken)
        ));
    }

    #[test]
    fn repro_status_queries_use_only_indexed_public_fields() {
        for query in [REPRO_STATUS_LEASE_QUERY, REPRO_STATUS_QUOTE_QUERY] {
            assert!(query.contains("document #>> '{repro,token_hash}' = $1"));
            assert!(query.contains("ORDER BY"));
            assert!(query.contains("LIMIT 1"));
            let lower = query.to_ascii_lowercase();
            for forbidden in [
                "subject",
                "renter_wallet",
                "funding_transaction_hash",
                "ssh_authorized_key",
                "jupyter_token",
                "runner_private_key",
                "ssh_host",
                "ssh_port",
            ] {
                assert!(!lower.contains(forbidden), "query exposes {forbidden}");
            }
        }
        assert_eq!(
            REPRO_STATUS_CLAIM_COUNT_QUERY
                .matches("document #>> '{repro,token_hash}' = $1")
                .count(),
            2
        );
        assert!(REPRO_STATUS_CLAIM_COUNT_QUERY.contains("UNION"));
        let migration = include_str!("../migrations/0022_managed_repros.sql");
        assert!(
            migration
                .matches("((document #>> '{repro,token_hash}'))")
                .count()
                >= 2
        );
        let claims = include_str!("../migrations/0023_repro_token_claims.sql");
        assert!(claims.contains("token_hash TEXT PRIMARY KEY"));
        assert!(claims.contains("SELECT DISTINCT token_hash"));
        assert!(claims.contains("UNION ALL"));
        assert!(claims.contains("ON CONFLICT (token_hash) DO NOTHING"));
    }

    #[test]
    fn repro_status_returns_bound_signed_evidence_without_authority_secrets() {
        let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let token_hash = repro_token_hash(&token).unwrap();
        let key = SigningKey::from_bytes(&[42_u8; 32]);
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        let node_id = node_id(&key.verifying_key());
        let (quote, spec) = repro_quote(token_hash.clone(), &node_id);
        let capability = quote.repro.clone().unwrap();
        let now = Utc::now();
        let command = NodeCommand {
            command_id: Uuid::now_v7(),
            node_id: node_id.clone(),
            lease_id: 1_001,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            kind: NodeCommandKind::Batch {
                image: spec.image.clone(),
                command: spec.command.clone(),
                duration_seconds: spec.duration_seconds,
            },
        };
        let result = CommandResult {
            exit_code: 0,
            stdout: "42\n".to_owned(),
            stderr: String::new(),
            truncated: false,
        };
        let report = NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: node_id.clone(),
                device_public_key: public_key.clone(),
                request_id: Uuid::now_v7(),
                command_id: command.command_id,
                outcome: NodeCommandOutcome::Completed,
                observed_at: now + Duration::seconds(2),
                error: None,
                result: Some(result.clone()),
                channel_key: None,
            },
            &key,
        )
        .unwrap();
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: "77".to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: format!("0x{}", hex::encode(Sha256::digest(node_id.as_bytes()))),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 2,
            charged_base_units: 444,
            refunded_base_units: 66_156,
            provider_paid_base_units: 400,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: Some(TrustClass::Open),
            attestation: None,
            credited_seconds: None,
            repro: Some(ReproReceiptEvidence {
                executor: ReproExecutor::Node,
                token_hash: token_hash.clone(),
                spec_hash: spec.hash().unwrap(),
                image_digest: format!("sha256:{}", "a".repeat(64)),
                command_hash: repro_command_hash(&command).unwrap(),
                result_hash: repro_result_hash(&result).unwrap(),
                stdout_hash: repro_stream_hash(&result.stdout),
                stderr_hash: repro_stream_hash(&result.stderr),
                report_hash: repro_report_hash(&report).unwrap(),
                exit_code: result.exit_code,
                expected_exit_code: spec.expected_exit_code,
                succeeded: true,
                truncated: false,
            }),
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", "b".repeat(64)),
        };
        receipt.receipt_hash = prism_protocol::receipt_hash(&receipt).unwrap();
        let response = build_repro_status(
            &token_hash,
            StoredReproStatus {
                quote,
                lease: Some(StoredReproLease {
                    lease_id: command.lease_id,
                    chain_lease_id: 77,
                    state: LeaseState::Finalized,
                    node_id,
                    token_hash: Some(token_hash.clone()),
                    spec_hash: Some(capability.spec_hash),
                    execution: Some(StoredReproExecution::Node {
                        status: "completed".to_owned(),
                        command,
                        report: Some(report),
                        result: Some(result),
                        enrolled_device_public_key: Some(public_key),
                    }),
                    receipt: Some(receipt),
                }),
            },
        )
        .unwrap();

        assert_eq!(response.status, ReproStatus::Settled);
        assert_eq!(response.executor, ReproExecutor::Node);
        assert!(response.evidence.is_some());
        assert!(response.checks.token_bound);
        assert!(response.checks.spec_hash_valid);
        assert_eq!(response.checks.command_bound, Some(true));
        assert_eq!(response.checks.report_signature_valid, Some(true));
        assert_eq!(response.checks.executor_identity_valid, Some(true));
        assert_eq!(response.checks.report_bound, Some(true));
        assert_eq!(response.checks.receipt_hash_valid, Some(true));
        assert_eq!(response.checks.receipt_bound, Some(true));
        assert_eq!(response.checks.expected_exit_code, Some(true));

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.len() <= MAX_REPRO_STATUS_RESPONSE_BYTES);
        assert!(!encoded.contains(&token));
        for forbidden in [
            "\"subject\"",
            "\"renter_wallet\"",
            "\"funding_transaction_hash\"",
            "\"ssh_authorized_key\"",
            "\"jupyter_token\"",
            "\"runner_private_key\"",
            "\"ssh_host\"",
            "\"ssh_port\"",
        ] {
            assert!(!encoded.contains(forbidden), "response exposes {forbidden}");
        }
    }

    #[test]
    fn managed_status_does_not_claim_an_unresolved_executor_identity() {
        let token_hash = "d".repeat(64);
        let (mut quote, spec) = repro_quote(token_hash.clone(), "broker");
        quote.repro.as_mut().unwrap().executor = ReproExecutor::Managed;
        let now = Utc::now();
        let command = NodeCommand {
            command_id: Uuid::now_v7(),
            node_id: "broker".to_owned(),
            lease_id: 1_002,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            kind: NodeCommandKind::Batch {
                image: spec.image.clone(),
                command: spec.command.clone(),
                duration_seconds: spec.duration_seconds,
            },
        };
        let report = ManagedCommandReport {
            report_id: Uuid::now_v7(),
            signer: format!("0x{}", "11".repeat(20)),
            command_id: command.command_id,
            lease_id: command.lease_id,
            provider: ManagedProvider::Vast,
            provider_instance_id: 42,
            gpu_model: "NVIDIA L4".to_owned(),
            gpu_vram_mib: 24_576,
            transport_host_key_sha256: "e".repeat(64),
            started_at: now + Duration::seconds(1),
            finished_at: now + Duration::seconds(2),
            outcome: NodeCommandOutcome::Failed,
            error: Some("runner failed".to_owned()),
            result: None,
            signature: "0x00".to_owned(),
        };
        let response = build_repro_status(
            &token_hash,
            StoredReproStatus {
                quote,
                lease: Some(StoredReproLease {
                    lease_id: command.lease_id,
                    chain_lease_id: 78,
                    state: LeaseState::Closing,
                    node_id: command.node_id.clone(),
                    token_hash: Some(token_hash.clone()),
                    spec_hash: Some(spec.hash().unwrap()),
                    execution: Some(StoredReproExecution::Managed {
                        status: "failed".to_owned(),
                        command,
                        report: Some(report),
                    }),
                    receipt: None,
                }),
            },
        )
        .unwrap();

        assert_eq!(response.checks.report_signature_valid, Some(false));
        assert_eq!(response.checks.executor_identity_valid, None);
    }

    #[test]
    fn repro_status_mapping_preserves_terminal_and_execution_states() {
        assert_eq!(
            derive_repro_status(&LeaseState::Funded, None, None),
            ReproStatus::Funded
        );
        assert_eq!(
            derive_repro_status(&LeaseState::Provisioning, Some("ready"), None),
            ReproStatus::Ready
        );
        assert_eq!(
            derive_repro_status(&LeaseState::Active, Some("launching"), None),
            ReproStatus::Running
        );
        assert_eq!(
            derive_repro_status(
                &LeaseState::Active,
                Some("completed"),
                Some(&NodeCommandOutcome::Completed),
            ),
            ReproStatus::Completed
        );
        assert_eq!(
            derive_repro_status(
                &LeaseState::Closing,
                Some("completed"),
                Some(&NodeCommandOutcome::Completed),
            ),
            ReproStatus::Settling
        );
        assert_eq!(
            derive_repro_status(&LeaseState::Finalized, Some("failed"), None),
            ReproStatus::Settled
        );
    }

    // With no contract deployed, everyone prices at the published rate rather
    // than the quote failing.
    #[tokio::test]
    async fn a_disabled_stake_reader_reports_no_stake() {
        let reader = StakeReader::Disabled;
        let wallets = vec!["0xabc0000000000000000000000000000000000001".to_owned()];
        assert_eq!(reader.eligible_whole_tokens(&wallets).await, 0);
    }
}
/// Migrations are a hand-written list, not a directory scan, so a new .sql file
/// that nobody registered is silently never applied. Migration 0012 reached
/// production that way and the column it adds simply was not there.
#[test]
fn every_migration_file_is_registered() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut on_disk = std::fs::read_dir(&directory)
        .expect("migrations directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let (version, _) = name.split_once('_')?;
            version.parse::<i64>().ok()
        })
        .collect::<Vec<_>>();
    on_disk.sort_unstable();

    let mut registered = embedded_migrator()
        .migrations
        .iter()
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    registered.sort_unstable();

    assert_eq!(
        on_disk, registered,
        "a migration file exists that embedded_migrator does not include"
    );
}

/// Native commands require a fresh device poll. A managed host accepts only a
/// capability-bound repro, never an arbitrary command.
#[test]
fn managed_capacity_matches_only_capability_bound_repros() {
    use prism_protocol::GpuSpec;

    let offer = |node_id: &str, trust_class, command_channel, managed_batch| NodeOffer {
        node_id: node_id.to_owned(),
        operator_wallet: "0xop".to_owned(),
        payout_wallet: "0xpay".to_owned(),
        device_public_key: "key".to_owned(),
        gpu: GpuSpec {
            model: "L40S".to_owned(),
            vram_mib: 46_068,
            cuda_major: 12,
        },
        rate_per_second: 222,
        reliability_bps: 0,
        benchmark_score: 10_000,
        bonded: true,
        online: true,
        public_image_only: true,
        trust_class,
        staker_only: false,
        command_channel,
        managed_batch,
        updated_at: Utc::now(),
    };
    let broker = offer("0xbroker", TrustClass::Open, false, true);
    let isolated = offer("0xisolated", TrustClass::Isolated, true, false);
    let self_hosted = offer("0xopen", TrustClass::Open, true, false);
    let request = |command: Option<&str>| LeaseRequest {
        image: "docker.io/library/debian@sha256:1".to_owned(),
        duration_seconds: 600,
        min_vram_mib: 16_000,
        preferred_node_id: None,
        min_trust_class: TrustClass::Open,
        command: command.map(str::to_owned),
        repro: None,
    };
    let reserved = BTreeSet::new();

    // An interactive lease is happy with the broker.
    let interactive = quote_for_offers(&request(None), [&broker], &reserved, 0).unwrap();
    assert_eq!(interactive.node_id, "0xbroker");

    // An unrestricted batch lease is not, even though the broker is available.
    assert!(matches!(
        quote_for_offers(&request(Some("nvidia-smi")), [&broker], &reserved, 0),
        Err(StoreError::NoMatch)
    ));

    let mut repro = request(Some("nvidia-smi"));
    let spec = GpuReproSpec {
        image: repro.image.clone(),
        command: repro.command.clone().unwrap(),
        duration_seconds: repro.duration_seconds,
        min_vram_mib: repro.min_vram_mib,
        expected_exit_code: 0,
    };
    repro.repro = Some(prism_protocol::ReproCapability {
        token_hash: "a".repeat(64),
        spec_hash: spec.hash().unwrap(),
        expected_exit_code: 0,
        executor: ReproExecutor::Managed,
    });
    let managed = quote_for_offers(&repro, [&broker], &reserved, 0).unwrap();
    assert_eq!(managed.node_id, "0xbroker");
    assert!(matches!(
        confirmed_cloud_execution(&managed, false, true),
        Err(StoreError::ReproExecutorUnavailable)
    ));
    assert!(matches!(
        confirmed_cloud_execution(&managed, true, false),
        Ok(true)
    ));

    let mut node_repro = repro.clone();
    node_repro.repro.as_mut().unwrap().executor = ReproExecutor::Node;
    assert!(matches!(
        quote_for_offers(&node_repro, [&broker], &reserved, 0),
        Err(StoreError::NoMatch)
    ));
    let native = quote_for_offers(&node_repro, [&self_hosted], &reserved, 0).unwrap();
    assert!(matches!(
        confirmed_cloud_execution(&native, false, true),
        Ok(false)
    ));
    assert!(matches!(
        confirmed_cloud_execution(&native, true, false),
        Err(StoreError::ReproExecutorUnavailable)
    ));

    let batch = quote_for_offers(
        &request(Some("nvidia-smi")),
        [&broker, &isolated],
        &reserved,
        0,
    )
    .unwrap();
    assert_eq!(batch.node_id, "0xisolated");
    assert_eq!(batch.command.as_deref(), Some("nvidia-smi"));

    // Same price, same class as the broker, and it matches, because it is the
    // one of the two that polls.
    let open = quote_for_offers(
        &request(Some("nvidia-smi")),
        [&broker, &self_hosted],
        &reserved,
        0,
    )
    .unwrap();
    assert_eq!(open.node_id, "0xopen");
    assert_eq!(open.trust_class, TrustClass::Open);

    // A node inside a long interactive lease stops polling, and while it does
    // it is out of batch matching whatever class it holds.
    let quiet = offer("0xquiet", TrustClass::Isolated, false, false);
    assert!(matches!(
        quote_for_offers(&request(Some("nvidia-smi")), [&quiet], &reserved, 0),
        Err(StoreError::NoMatch)
    ));
}
