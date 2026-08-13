use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::Path as FilePath,
    sync::{Arc, OnceLock},
};

use anyhow::Context;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use prism_protocol::{
    Account, CommandResult, CredentialCipher, EncryptedSecret, LeaseAccess, LeaseQuote,
    LeaseRecord, LeaseRequest, LeaseState, MAX_ESCROW_BASE_UNITS, MAX_LEASE_SECONDS,
    MAX_NETWORK_LEASES, MAX_VAULT_CIPHERTEXT_BYTES, MAX_VAULT_ITEMS_PER_ACCOUNT,
    MAX_VAULT_LABEL_BYTES, NodeCertificateBundle, NodeCertificateRequest, NodeCommand,
    NodeCommandKind, NodeCommandOutcome, NodeCommandPoll, NodeCommandReport, NodeEnrollment,
    NodeOffer, NodePosture, NodeTelemetry, STANDARD_RATE_PER_SECOND, SettlementEvidence,
    TrustClass, VaultEnvelope, VaultItem, VaultRelease, VaultWrite, discounted_rate, node_id,
    stake_discount_bps, vault_release_permitted, verifying_key,
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
const QUOTE_TTL_MINUTES: i64 = 5;
type HmacSha256 = Hmac<Sha256>;

/// Broker-backed capacity reaches renters over direct SSH with no tunnel and
/// no daemon, so it can never rise above `Open`. Everything stronger has to
/// come from a device-signed posture on a node we hold a bond for.
fn trust_class_for(tunneled: bool, posture: Option<&NodePosture>) -> TrustClass {
    if !tunneled {
        return TrustClass::Open;
    }
    posture.map_or(TrustClass::Open, NodePosture::effective_class)
}

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

struct ConfirmedFunding {
    lease_id: u64,
    renter_wallet: String,
}

struct FundingConfirmation<'a> {
    subject: &'a str,
    quote: &'a LeaseQuote,
    transaction_hash: &'a str,
    funding: ConfirmedFunding,
    ssh_authorized_key: &'a str,
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
    leases: BTreeMap<u64, (String, LeaseRecord)>,
    commands: BTreeMap<Uuid, MemoryCommand>,
    node_requests: BTreeMap<Uuid, chrono::DateTime<Utc>>,
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
}

struct MemoryCommand {
    command: NodeCommand,
    status: &'static str,
    lease_until: Option<chrono::DateTime<Utc>>,
    result: Option<CommandResult>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Default)]
struct MemoryLifecycle {
    grant_token: Option<EncryptedSecret>,
    grant_expires_at: Option<chrono::DateTime<Utc>>,
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

#[derive(Deserialize)]
struct ConfirmLeaseRequest {
    quote_id: Uuid,
    transaction_hash: String,
    ssh_authorized_key: String,
}

#[derive(Deserialize)]
struct VaultReleaseRequest {
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
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/offers", get(list_offers))
        .route("/v1/price-index", get(price_index))
        .route("/v1/nodes/enroll", post(enroll_node))
        .route(
            "/v1/nodes/{node_id}/certificates",
            post(issue_node_certificate),
        )
        .route("/v1/nodes/{node_id}/heartbeat", post(record_telemetry))
        .route(
            "/v1/gateway/tunnels/{node_id}",
            post(record_tunnel_observation),
        )
        .route("/v1/nodes/{node_id}/commands/next", post(next_node_command))
        .route(
            "/v1/nodes/{node_id}/commands/{command_id}/report",
            post(report_node_command),
        )
        .route("/v1/leases/match", post(match_lease))
        .route("/v1/leases", get(list_account_leases))
        .route("/v1/leases/{lease_id}/access", get(get_lease_access))
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
                Ok(Self::Development { escrow_address })
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
            Self::Development { .. } => {
                let lease_id = u64::from_str_radix(&transaction_hash[2..18], 16)
                    .map_err(|_| ChainError::InvalidTransactionHash)?
                    .max(1);
                Ok(ConfirmedFunding {
                    lease_id,
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
                        String,
                        SqlJson<SettlementEvidence>,
                        Option<SqlJson<StoredSettlementSubmission>>,
                        chrono::DateTime<Utc>,
                    ),
                >(
                    "SELECT j.lease_id, l.document->>'node_id', j.evidence, j.proposal, j.updated_at \
                     FROM settlement_jobs j JOIN leases l ON l.lease_id = j.lease_id \
                     WHERE j.status = 'disputed' AND l.state = 'disputed' \
                     ORDER BY j.updated_at, j.lease_id LIMIT 200",
                )
                .fetch_all(pool)
                .await
                .map_err(StoreError::Storage)?;
                rows.into_iter()
                    .map(
                        |(lease_id, node_id, SqlJson(evidence), proposal, updated_at)| {
                            operator_dispute(
                                u64::try_from(lease_id)
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
                Ok(market
                    .offers
                    .values()
                    .filter(|offer| {
                        offer.bonded
                            && offer.public_image_only
                            && offer.updated_at >= cutoff
                            && !market.suspended_nodes.contains(&offer.node_id)
                            && market
                                .tunnels
                                .get(&offer.node_id)
                                .is_some_and(|observed_at| *observed_at >= cutoff)
                    })
                    .cloned()
                    .map(|mut offer| {
                        offer.online = true;
                        offer.trust_class = trust_class_for(
                            true,
                            market
                                .telemetry
                                .get(&offer.node_id)
                                .and_then(|telemetry| telemetry.posture.as_ref()),
                        );
                        offer
                    })
                    .collect())
            }
            Self::Postgres(pool) => {
                let documents =
                    query_as::<_, (SqlJson<NodeOffer>, bool, Option<SqlJson<NodePosture>>)>(
                        "SELECT o.document, \
                            EXISTS ( \
                                SELECT 1 FROM node_tunnels t \
                                WHERE t.node_id = o.node_id AND t.observed_at >= $1 \
                            ), \
                            (SELECT nt.document->'posture' FROM node_telemetry nt \
                             WHERE nt.node_id = o.node_id AND nt.observed_at >= $1) \
                     FROM node_offers o \
                     WHERE (o.document->>'bonded')::boolean = true \
                       AND (document->>'public_image_only')::boolean = true \
                       AND (o.updated_at >= $1 OR EXISTS ( \
                           SELECT 1 FROM cloud_capacity cc0 \
                           WHERE cc0.node_id = o.node_id \
                             AND cc0.provider = 'vast' \
                             AND cc0.available \
                             AND cc0.observed_at >= $1 \
                       )) \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM node_controls c \
                           WHERE c.node_id = o.node_id AND c.suspended \
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
                       ) \
                       ) \
                     ORDER BY (o.document->>'rate_per_second')::bigint ASC, o.updated_at DESC",
                    )
                    .bind(cutoff)
                    .fetch_all(pool)
                    .await
                    .map_err(StoreError::Storage)?;
                Ok(documents
                    .into_iter()
                    .map(|(SqlJson(mut offer), tunneled, posture)| {
                        offer.online = true;
                        offer.trust_class =
                            trust_class_for(tunneled, posture.as_ref().map(|SqlJson(p)| p));
                        offer
                    })
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
                           AND state NOT IN ('finalized', 'refunded', 'failed') \
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

    async fn quote(
        &self,
        subject: &str,
        request: &LeaseRequest,
        staked_whole_tokens: u64,
    ) -> Result<LeaseQuote, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
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
                    .filter(|(_, lease)| {
                        !matches!(
                            lease.state,
                            LeaseState::Finalized | LeaseState::Refunded | LeaseState::Failed
                        )
                    })
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
                        .filter(|(_, lease)| occupies_node(lease))
                        .map(|(_, lease)| lease.node_id.clone()),
                );
                let cutoff = Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                let offers = market
                    .offers
                    .values()
                    .filter(|offer| !market.suspended_nodes.contains(&offer.node_id))
                    .cloned()
                    .map(|mut offer| {
                        offer.online = market
                            .tunnels
                            .get(&offer.node_id)
                            .is_some_and(|observed_at| *observed_at >= cutoff);
                        offer
                    })
                    .collect::<Vec<_>>();
                // The matcher reads offers directly, so the staker pool has to
                // be marked here too: this is where the gate actually runs.
                let offers = mark_staker_capacity(offers);
                let quote =
                    quote_for_offers(request, offers.iter(), &reserved, staked_whole_tokens)?;
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
                let quote_count: i64 = query_scalar(
                    "SELECT \
                         (SELECT COUNT(*) FROM lease_quotes \
                          WHERE consumed_at IS NULL AND expires_at > NOW()) + \
                         (SELECT COUNT(*) FROM leases WHERE state NOT IN ('finalized', 'refunded', 'failed'))",
                )
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
                     WHERE state NOT IN ('finalized', 'refunded', 'failed')",
                )
                .bind(QUOTE_HOLD_SECONDS as f64)
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
                let online: BTreeSet<String> = query_scalar(
                    "SELECT node_id FROM node_tunnels WHERE observed_at >= $1 \
                     UNION \
                     SELECT node_id FROM cloud_capacity \
                     WHERE provider = 'vast' AND available AND observed_at >= $1",
                )
                .bind(Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS))
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .into_iter()
                .collect();
                let offers: Vec<_> = documents
                    .into_iter()
                    .map(|SqlJson(mut offer)| {
                        offer.online = online.contains(&offer.node_id);
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
        let mut lease = LeaseRecord {
            lease_id: funding.lease_id,
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
                if let Some((owner, current)) = market.leases.get(&lease.lease_id) {
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
                if market
                    .leases
                    .values()
                    .any(|(_, current)| current.node_id == lease.node_id && occupies_node(current))
                {
                    tracing::warn!(
                        lease_id = lease.lease_id,
                        node_id = %lease.node_id,
                        "funding confirmed for a node this store still thinks is busy"
                    );
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
                let command = launch_command(&lease, ssh_authorized_key, jupyter_token);
                market.commands.insert(
                    command.command_id,
                    MemoryCommand {
                        command,
                        status: "queued",
                        lease_until: None,
                        result: None,
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
                if let Some(SqlJson(current)) = query_scalar::<_, SqlJson<LeaseRecord>>(
                    "SELECT document FROM leases WHERE lease_id = $1 OR funding_transaction_hash = $2",
                )
                .bind(lease.lease_id as i64)
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
                let node_busy = query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM leases \
                         WHERE document->>'node_id' = $1 \
                           AND state IN ('funded', 'provisioning', 'ready', 'active', 'closing') \
                     )",
                )
                .bind(&lease.node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if node_busy {
                    tracing::warn!(
                        lease_id = lease.lease_id,
                        node_id = %lease.node_id,
                        "funding confirmed for a node this store still thinks is busy"
                    );
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
                let cloud_backed = query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM cloud_capacity \
                         WHERE node_id = $1 AND provider = 'vast' \
                     )",
                )
                .bind(&lease.node_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                if cloud_backed {
                    lease.state = LeaseState::Provisioning;
                    lease.updated_at = Utc::now();
                }
                query(
                    "INSERT INTO leases \
                         (lease_id, quote_id, subject, renter_wallet, funding_transaction_hash, document, state) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(lease.lease_id as i64)
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
                    query(
                        "INSERT INTO cloud_instances (lease_id, ssh_authorized_key) \
                         VALUES ($1, $2)",
                    )
                    .bind(lease.lease_id as i64)
                    .bind(ssh_authorized_key)
                    .execute(&mut *transaction)
                    .await
                    .map_err(StoreError::Storage)?;
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
                    let command = launch_command(&lease, ssh_authorized_key, jupyter_token);
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

    async fn active_lease_trust_class(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<TrustClass>, StoreError> {
        match self {
            Self::Memory(market) => Ok(market
                .read()
                .await
                .leases
                .get(&lease_id)
                .filter(|(owner, lease)| owner == subject && lease.state == LeaseState::Active)
                .map(|(_, lease)| lease.trust_class)),
            // Read the one field rather than the whole record: this gate must
            // not start returning 500s because some unrelated part of a lease
            // document changed shape.
            Self::Postgres(pool) => query_scalar::<_, Option<String>>(
                "SELECT document->>'trust_class' FROM leases \
                 WHERE lease_id = $1 AND subject = $2 AND state = 'active'",
            )
            .bind(lease_id as i64)
            .bind(subject)
            .fetch_optional(pool)
            .await
            .map_err(StoreError::Storage)?
            // A lease predating trust classes is `open`, matching the serde
            // default, which is the weakest class and so fails closed.
            .map(|class| class.map_or(Ok(TrustClass::Open), |class| parse_trust_class(&class)))
            .transpose(),
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

    async fn claim_command(
        &self,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<Option<NodeCommand>, StoreError> {
        let now = Utc::now();
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                remember_node_request(&mut market, request_id, now)?;
                let command = market
                    .commands
                    .values_mut()
                    .filter(|entry| entry.command.node_id == node_id)
                    .filter(|entry| {
                        entry.status == "queued"
                            || (entry.status == "leased"
                                && entry.lease_until.is_none_or(|until| until <= now))
                            || (entry.status == "ready"
                                && entry.updated_at <= now - Duration::minutes(2))
                    })
                    .min_by_key(|entry| entry.command.issued_at);
                let Some(entry) = command else {
                    return Ok(None);
                };
                entry.status = "leased";
                entry.lease_until = Some(now + Duration::minutes(2));
                entry.updated_at = now;
                let command = entry.command.clone();
                if let Some((_, lease)) = market.leases.get_mut(&command.lease_id) {
                    lease.state = LeaseState::Provisioning;
                    lease.updated_at = now;
                }
                Ok(Some(command))
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                record_node_request(&mut transaction, node_id, request_id).await?;
                let command = query_scalar::<_, SqlJson<NodeCommand>>(
                    "SELECT document FROM node_commands \
                     WHERE node_id = $1 AND attempts < 10 \
                       AND (status = 'queued' \
                            OR (status = 'leased' AND lease_until <= NOW()) \
                            OR (status = 'ready' AND updated_at <= NOW() - INTERVAL '2 minutes')) \
                     ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
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
                         lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
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

    async fn report_command(&self, report: &NodeCommandReport) -> Result<(), StoreError> {
        let now = Utc::now();
        let (status, lease_state, action) = match report.outcome {
            NodeCommandOutcome::Ready => ("ready", LeaseState::Ready, "start_access"),
            NodeCommandOutcome::Completed => ("completed", LeaseState::Closing, "close_access"),
            NodeCommandOutcome::Failed => ("failed", LeaseState::Closing, "expire_provision"),
        };
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                remember_node_request(&mut market, report.request_id, now)?;
                let entry = market
                    .commands
                    .get_mut(&report.command_id)
                    .filter(|entry| entry.command.node_id == report.node_id)
                    .ok_or(StoreError::CommandNotFound)?;
                if !valid_command_transition(entry.status, status) {
                    return Err(StoreError::CommandNotFound);
                }
                entry.status = status;
                entry.lease_until = None;
                if report.result.is_some() {
                    entry.result = report.result.clone();
                }
                entry.updated_at = now;
                let lease_id = entry.command.lease_id;
                if let Some((_, lease)) = market.leases.get_mut(&lease_id) {
                    lease.state = lease_state;
                    lease.updated_at = report.observed_at;
                }
                market.lifecycle_actions.insert((lease_id, action));
                Ok(())
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await.map_err(StoreError::Storage)?;
                record_node_request(&mut transaction, &report.node_id, report.request_id).await?;
                let current: Option<(i64, String)> = query_as(
                    "SELECT lease_id, status FROM node_commands \
                     WHERE command_id = $1 AND node_id = $2 FOR UPDATE",
                )
                .bind(report.command_id)
                .bind(&report.node_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let Some((lease_id, current)) = current else {
                    return Err(StoreError::CommandNotFound);
                };
                if !valid_command_transition(&current, status) {
                    return Err(StoreError::CommandNotFound);
                }
                query(
                    "UPDATE node_commands \
                     SET status = $2, lease_until = NULL, last_error = $3, \
                         result = COALESCE($4, result), updated_at = NOW() \
                     WHERE command_id = $1",
                )
                .bind(report.command_id)
                .bind(status)
                .bind(&report.error)
                .bind(report.result.as_ref().map(SqlJson))
                .execute(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                update_lease_state(&mut transaction, lease_id as u64, lease_state).await?;
                query(
                    "INSERT INTO lease_lifecycle (lease_id, connection_id, node_ready_at) \
                     SELECT $1, t.connection_id, CASE WHEN $2 = 'start_access' THEN $3 ELSE NULL END \
                     FROM leases l LEFT JOIN node_tunnels t \
                       ON t.node_id = l.document->>'node_id' \
                     WHERE l.lease_id = $1 \
                     ON CONFLICT (lease_id) DO UPDATE SET \
                       connection_id = COALESCE(EXCLUDED.connection_id, lease_lifecycle.connection_id), \
                       node_ready_at = COALESCE(EXCLUDED.node_ready_at, lease_lifecycle.node_ready_at), \
                       updated_at = NOW()",
                )
                .bind(lease_id)
                .bind(action)
                .bind(report.observed_at)
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
                transaction.commit().await.map_err(StoreError::Storage)
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
                let stored: Option<Option<SqlJson<CommandResult>>> = query_scalar(
                    "SELECT c.result FROM node_commands c \
                     JOIN leases l ON l.lease_id = c.lease_id \
                     WHERE c.lease_id = $1 AND l.subject = $2",
                )
                .bind(lease_id as i64)
                .bind(subject)
                .fetch_optional(pool)
                .await
                .map_err(StoreError::Storage)?;
                Ok(stored.flatten().map(|SqlJson(result)| result))
            }
        }
    }

    async fn lease_access(
        &self,
        subject: &str,
        lease_id: u64,
    ) -> Result<Option<StoredLeaseAccess>, StoreError> {
        match self {
            Self::Memory(market) => {
                let market = market.read().await;
                let Some((owner, lease)) = market.leases.get(&lease_id) else {
                    return Ok(None);
                };
                if owner != subject || lease.state != LeaseState::Active {
                    return Ok(None);
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
                Ok(Some(StoredLeaseAccess::Gateway {
                    token,
                    jupyter_token,
                    expires_at,
                }))
            }
            Self::Postgres(pool) => {
                let direct = query_as::<_, (String, i32, chrono::DateTime<Utc>)>(
                    "SELECT ci.ssh_host, ci.ssh_port, \
                            lc.access_started_at + make_interval(secs => (l.document->>'duration_seconds')::integer) \
                     FROM leases l \
                     JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
                     JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
                     WHERE l.lease_id = $1 AND l.subject = $2 AND l.state = 'active' \
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
                    return Ok(Some(StoredLeaseAccess::DirectSsh {
                        host,
                        port: u16::try_from(port).map_err(|_| {
                            StoreError::InvalidStoredState("invalid SSH port".into())
                        })?,
                        expires_at,
                    }));
                }
                let stored = query_as::<
                    _,
                    (
                        SqlJson<EncryptedSecret>,
                        SqlJson<EncryptedSecret>,
                        chrono::DateTime<Utc>,
                    ),
                >(
                    "SELECT lc.grant_token, s.jupyter_token, lc.grant_expires_at \
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
                Ok(
                    stored.map(|(SqlJson(token), SqlJson(jupyter_token), expires_at)| {
                        StoredLeaseAccess::Gateway {
                            token,
                            jupyter_token,
                            expires_at,
                        }
                    }),
                )
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
    request_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(), StoreError> {
    market
        .node_requests
        .retain(|_, expires_at| *expires_at > now);
    if market.node_requests.contains_key(&request_id) {
        return Err(StoreError::CommandReplay);
    }
    market
        .node_requests
        .insert(request_id, now + Duration::minutes(5));
    Ok(())
}

async fn record_node_request(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    node_id: &str,
    request_id: Uuid,
) -> Result<(), StoreError> {
    query("DELETE FROM node_command_requests WHERE expires_at <= NOW()")
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::Storage)?;
    let inserted = query(
        "INSERT INTO node_command_requests (request_id, node_id, expires_at) \
         VALUES ($1, $2, NOW() + INTERVAL '5 minutes') ON CONFLICT DO NOTHING",
    )
    .bind(request_id)
    .bind(node_id)
    .execute(&mut **transaction)
    .await
    .map_err(StoreError::Storage)?;
    if inserted.rows_affected() != 1 {
        return Err(StoreError::CommandReplay);
    }
    Ok(())
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

fn valid_command_transition(current: &str, next: &str) -> bool {
    current == next
        || matches!(
            (current, next),
            ("queued" | "leased", "ready" | "completed" | "failed")
                | ("ready", "completed" | "failed")
        )
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
    !matches!(
        lease.state,
        LeaseState::Finalized | LeaseState::Refunded | LeaseState::Failed
    )
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
    ssh_authorized_key: &str,
    jupyter_token: &str,
) -> NodeCommand {
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
            ssh_authorized_key: ssh_authorized_key.to_owned(),
            jupyter_token: jupyter_token.to_owned(),
        },
    };
    NodeCommand {
        command_id: Uuid::now_v7(),
        node_id: lease.node_id.clone(),
        lease_id: lease.lease_id,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
        kind,
    }
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

async fn report_node_command(
    State(state): State<AppState>,
    Path((node_id, command_id)): Path<(String, Uuid)>,
    Json(report): Json<NodeCommandReport>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
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
    state
        .store
        .report_command(&report)
        .await
        .map_err(store_error)?;
    Ok(StatusCode::NO_CONTENT)
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
        .quote(&account.subject, &payload.request, staked)
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
) -> Result<Json<LeaseAccess>, (StatusCode, Json<ApiError>)> {
    let path = format!("/v1/leases/{lease_id}/access");
    let account = require_account(&state, &headers, "GET", &path, &[]).await?;
    let stored = state
        .store
        .lease_access(&account.subject, lease_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            not_found(
                "access_not_ready",
                "lease access is unavailable until provider readiness and onchain start are final",
            )
        })?;
    match stored {
        StoredLeaseAccess::Gateway {
            token,
            jupyter_token,
            expires_at,
        } => Ok(Json(LeaseAccess::Gateway {
            lease_id,
            token: state
                .credential_cipher
                .decrypt(&token)
                .map_err(|_| credential_error())?,
            gateway_host: state.public_gateway_host.as_ref().clone(),
            relay_port: state.public_relay_port,
            ssh_user: "workspace".to_owned(),
            jupyter_path: "/lab".to_owned(),
            jupyter_token: state
                .credential_cipher
                .decrypt(&jupyter_token)
                .map_err(|_| credential_error())?,
            expires_at,
        })),
        StoredLeaseAccess::DirectSsh {
            host,
            port,
            expires_at,
        } => Ok(Json(LeaseAccess::DirectSsh {
            lease_id,
            ssh_host: host,
            ssh_port: port,
            ssh_user: "root".to_owned(),
            expires_at,
        })),
    }
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
    if !is_ssh_authorized_key(&request.ssh_authorized_key) {
        return Err(bad_request(
            "invalid_ssh_key",
            "SSH access requires one Ed25519 public key",
        ));
    }
    let quote = state
        .store
        .quote_for_subject(&account.subject, request.quote_id)
        .await
        .map_err(store_error)?;
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
            ssh_authorized_key: &request.ssh_authorized_key,
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
        // Only a node that takes work through the signed command channel can
        // run a batch command, and the broker path does not: it is provisioned
        // by the lifecycle worker and nothing there polls for commands. Matching
        // a batch request to one would take the renter's money and hand back an
        // interactive box their command never ran on.
        .filter(|offer| request.command.is_none() || offer.trust_class >= TrustClass::Isolated)
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
        expires_at: Utc::now() + Duration::minutes(QUOTE_TTL_MINUTES),
    })
}

fn is_pinned_image(image: &str) -> bool {
    if image.is_empty() || image.len() > 512 || image.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !repository.contains("..")
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256_digest(digest: &str) -> bool {
    digest.len() == 71
        && digest.starts_with("sha256:")
        && digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn operator_dispute(
    lease_id: u64,
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
                    lease_id,
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
    use prism_protocol::{
        DEFAULT_VAULT_TRUST_FLOOR, GpuSpec, IsolationMode, MAX_STAKE_DISCOUNT_BPS, NodePosture,
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
            updated_at: Utc::now(),
        }
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

    /// The renter chose at quote time whether they wanted a session or a
    /// command. Issuing the wrong one either hands out a shell nobody asked for
    /// or leaves a batch renter waiting on a workspace that never reports.
    #[test]
    fn a_lease_with_a_command_is_dispatched_as_batch() {
        let base = LeaseRecord {
            lease_id: 9,
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let interactive = launch_command(&base, "ssh-ed25519 AAAA", "token");
        assert!(matches!(interactive.kind, NodeCommandKind::Launch { .. }));

        let batch = launch_command(
            &LeaseRecord {
                command: Some("nvidia-smi -L".to_owned()),
                ..base
            },
            "ssh-ed25519 AAAA",
            "token",
        );
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // The escrow keeps activeLeaseId set until finalize or refund, so
        // quoting a node in these states reverts with LeaseNotReady.
        assert!(occupies_node(&lease(LeaseState::Active)));
        assert!(occupies_node(&lease(LeaseState::Closing)));
        assert!(occupies_node(&lease(LeaseState::SettlementPending)));
        assert!(occupies_node(&lease(LeaseState::Disputed)));

        assert!(!occupies_node(&lease(LeaseState::Finalized)));
        assert!(!occupies_node(&lease(LeaseState::Refunded)));
        assert!(!occupies_node(&lease(LeaseState::Failed)));
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

        assert_eq!(trust_class_for(false, Some(&kata)), TrustClass::Open);
        assert_eq!(trust_class_for(true, Some(&kata)), TrustClass::Isolated);
        assert_eq!(trust_class_for(true, None), TrustClass::Open);
    }

    #[test]
    fn attested_hardware_claims_are_capped_until_a_verifier_exists() {
        let confidential = NodePosture {
            isolation: IsolationMode::KataVfio,
            attestation: Some(prism_protocol::AttestationRef {
                kind: prism_protocol::AttestationKind::NvidiaCc,
                quote_sha256: "0".repeat(64),
            }),
        };

        assert_eq!(
            trust_class_for(true, Some(&confidential)),
            prism_protocol::MAX_VERIFIABLE_TRUST_CLASS
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
            "registry.example/runtime@sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_pinned_image("registry.example/runtime@sha256:abc"));
        assert!(!is_pinned_image(
            "registry.example/../runtime@sha256:aaaaaaaa"
        ));
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

    /// Settlement runs for a further 24 hours after the machine is torn down.
    /// Holding the node for that whole window took the one-node network out of
    /// service for a day after every lease.
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
    async fn a_node_is_released_once_its_lease_settles_not_before() {
        let now = Utc::now();
        let mut market = MemoryMarketplace::default();
        market
            .offers
            .insert("only".to_owned(), offer("only", 100, 10_000));
        market.tunnels.insert("only".to_owned(), now);
        let lease = LeaseRecord {
            lease_id: 27,
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
        };

        assert!(matches!(
            store.quote("renter", &request, 0).await,
            Err(StoreError::CapacityReserved)
        ));

        let MarketplaceStore::Memory(market) = &store else {
            unreachable!()
        };
        // #83 released the node here, on the reasoning that its machine was
        // already gone. The escrow disagrees: it holds activeLeaseId until
        // finalize or refund, so quoting now reverts with LeaseNotReady. That
        // optimisation existed because finalize was hardcoded 24h out; #96 made
        // it read DISPUTE_WINDOW, so settling costs about five minutes and
        // waiting for it is cheap.
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
                created_at: now,
                updated_at: now,
            };
            let command = launch_command(
                &lease,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
                &"a".repeat(64),
            );
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
            created_at: now,
            updated_at: now,
        };
        let command = launch_command(
            &lease,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
            &"a".repeat(64),
        );
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
            signature: "test".to_owned(),
        };
        store.report_command(&report).await.unwrap();
        let market = match store {
            MarketplaceStore::Memory(market) => market,
            MarketplaceStore::Postgres(_) => unreachable!(),
        };
        let market = market.read().await;
        assert_eq!(market.leases.get(&7).unwrap().1.state, LeaseState::Ready);
        assert_eq!(market.commands.get(&command_id).unwrap().status, "ready");
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
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ),
        );
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

/// The broker path is provisioned by the lifecycle worker and never polls
/// for commands, so a batch request that matched one would bill the renter
/// for a box their command never ran on.
#[test]
fn a_batch_request_never_matches_a_broker_node() {
    use prism_protocol::GpuSpec;

    let offer = |node_id: &str, trust_class| NodeOffer {
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
        updated_at: Utc::now(),
    };
    let broker = offer("0xbroker", TrustClass::Open);
    let isolated = offer("0xisolated", TrustClass::Isolated);
    let request = |command: Option<&str>| LeaseRequest {
        image: "docker.io/library/debian@sha256:1".to_owned(),
        duration_seconds: 600,
        min_vram_mib: 16_000,
        preferred_node_id: None,
        min_trust_class: TrustClass::Open,
        command: command.map(str::to_owned),
    };
    let reserved = BTreeSet::new();

    // An interactive lease is happy with the broker.
    let interactive = quote_for_offers(&request(None), [&broker], &reserved, 0).unwrap();
    assert_eq!(interactive.node_id, "0xbroker");

    // A batch lease is not, even though the broker is cheaper and online.
    assert!(matches!(
        quote_for_offers(&request(Some("nvidia-smi")), [&broker], &reserved, 0),
        Err(StoreError::NoMatch)
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
}
