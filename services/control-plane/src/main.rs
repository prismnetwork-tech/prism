use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::Path as FilePath,
    sync::Arc,
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
    Account, CredentialCipher, EncryptedSecret, LeaseAccess, LeaseQuote, LeaseRecord, LeaseRequest,
    LeaseState, MAX_ESCROW_BASE_UNITS, MAX_LEASE_SECONDS, MAX_NETWORK_LEASES,
    NodeCertificateBundle, NodeCertificateRequest, NodeCommand, NodeCommandKind,
    NodeCommandOutcome, NodeCommandPoll, NodeCommandReport, NodeEnrollment, NodeOffer,
    NodeTelemetry, SettlementEvidence, node_id, verifying_key,
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
}

struct MemoryCommand {
    command: NodeCommand,
    status: &'static str,
    lease_until: Option<chrono::DateTime<Utc>>,
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
    #[error("storage failure")]
    Storage(#[source] SqlError),
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}

#[derive(Deserialize)]
struct MatchRequest {
    request: LeaseRequest,
}

#[derive(Deserialize)]
struct ConfirmLeaseRequest {
    quote_id: Uuid,
    transaction_hash: String,
    ssh_authorized_key: String,
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
        .with_env_filter(EnvFilter::from_default_env())
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
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/offers", get(list_offers))
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
        .route("/v1/leases/confirm", post(confirm_lease))
        .route("/v1/account/session/revoke", post(revoke_account_session))
        .route(
            "/v1/account/wallets/challenge",
            get(create_wallet_challenge),
        )
        .route("/v1/account/wallets/link", post(link_account_wallet))
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
                    .insert(wallet_address.to_owned());
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
                let linked_wallets = market
                    .linked_wallets
                    .get(subject)
                    .cloned()
                    .unwrap_or_default();
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
                let linked_wallets = query_scalar::<_, String>(
                    "SELECT wallet_address FROM account_wallets \
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
                    "SELECT wallet_address FROM account_wallets \
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

    async fn list_offers(&self) -> Result<Vec<NodeOffer>, StoreError> {
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
                        offer
                    })
                    .collect())
            }
            Self::Postgres(pool) => {
                let documents = query_scalar::<_, SqlJson<NodeOffer>>(
                    "SELECT o.document FROM node_offers o \
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
                    .map(|SqlJson(mut offer)| {
                        offer.online = true;
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

    async fn quote(&self, subject: &str, request: &LeaseRequest) -> Result<LeaseQuote, StoreError> {
        match self {
            Self::Memory(market) => {
                let mut market = market.write().await;
                market
                    .open_quotes
                    .retain(|_, quote| quote.expires_at > Utc::now() - Duration::hours(24));
                let active_quote_count = market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        quote.expires_at > Utc::now()
                            && !market.consumed_quotes.contains(&quote.quote_id)
                    })
                    .count();
                if active_quote_count + market.leases.len() >= MAX_NETWORK_LEASES {
                    return Err(StoreError::NetworkCapacity);
                }
                let mut reserved: BTreeSet<_> = market
                    .open_quotes
                    .values()
                    .filter(|quote| {
                        quote.expires_at > Utc::now()
                            && !market.consumed_quotes.contains(&quote.quote_id)
                    })
                    .map(|quote| quote.node_id.clone())
                    .collect();
                reserved.extend(
                    market
                        .leases
                        .values()
                        .map(|(_, lease)| lease.node_id.clone()),
                );
                let cutoff = Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS);
                let offers = market
                    .offers
                    .values()
                    .cloned()
                    .map(|mut offer| {
                        offer.online = market
                            .tunnels
                            .get(&offer.node_id)
                            .is_some_and(|observed_at| *observed_at >= cutoff);
                        offer
                    })
                    .collect::<Vec<_>>();
                let quote = quote_for_offers(request, offers.iter(), &reserved)?;
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
                     UNION SELECT document->>'node_id' FROM leases \
                     WHERE state NOT IN ('finalized', 'refunded', 'failed')",
                )
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?
                .into_iter()
                .collect();
                let documents = query_scalar::<_, SqlJson<NodeOffer>>(
                    "SELECT document FROM node_offers FOR UPDATE",
                )
                .fetch_all(&mut *transaction)
                .await
                .map_err(StoreError::Storage)?;
                let online: BTreeSet<String> = query_scalar(
                    "SELECT node_id FROM node_tunnels \
                     WHERE observed_at >= NOW() - INTERVAL '90 seconds' \
                     UNION \
                     SELECT node_id FROM cloud_capacity \
                     WHERE provider = 'vast' AND available \
                       AND observed_at >= NOW() - INTERVAL '90 seconds'",
                )
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
                let quote = quote_for_offers(request, offers.iter(), &reserved)?;
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
            funding_transaction_hash: transaction_hash.to_ascii_lowercase(),
            state: LeaseState::Funded,
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
                .bind(&lease.renter_wallet)
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
                     SET status = $2, lease_until = NULL, last_error = $3, updated_at = NOW() \
                     WHERE command_id = $1",
                )
                .bind(report.command_id)
                .bind(status)
                .bind(&report.error)
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

fn launch_command(
    lease: &LeaseRecord,
    ssh_authorized_key: &str,
    jupyter_token: &str,
) -> NodeCommand {
    let now = Utc::now();
    NodeCommand {
        command_id: Uuid::now_v7(),
        node_id: lease.node_id.clone(),
        lease_id: lease.lease_id,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
        kind: NodeCommandKind::Launch {
            image: lease.image.clone(),
            duration_seconds: lease.duration_seconds,
            ssh_authorized_key: ssh_authorized_key.to_owned(),
            jupyter_token: jupyter_token.to_owned(),
        },
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

async fn list_offers(
    State(state): State<AppState>,
) -> Result<Json<Vec<NodeOffer>>, (StatusCode, Json<ApiError>)> {
    state
        .store
        .list_offers()
        .await
        .map(Json)
        .map_err(internal_error)
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
    state
        .store
        .quote(&account.subject, &payload.request)
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
        ]),
        ..Migrator::DEFAULT
    }
}

fn quote_for_offers<'a>(
    request: &LeaseRequest,
    offers: impl IntoIterator<Item = &'a NodeOffer>,
    reserved: &BTreeSet<String>,
) -> Result<LeaseQuote, StoreError> {
    let cutoff = Utc::now() - Duration::seconds(OFFER_MAX_AGE_SECONDS);
    let selected = offers
        .into_iter()
        .filter(|offer| offer.online && offer.bonded && offer.public_image_only)
        .filter(|offer| offer.updated_at >= cutoff && !reserved.contains(&offer.node_id))
        .filter(|offer| offer.gpu.vram_mib >= request.min_vram_mib)
        .filter(|offer| {
            request
                .preferred_node_id
                .as_ref()
                .is_none_or(|node_id| node_id == &offer.node_id)
        })
        .min_by_key(|offer| {
            (
                offer.rate_per_second,
                Reverse(offer.reliability_bps),
                Reverse(offer.benchmark_score),
            )
        })
        .ok_or(StoreError::NoMatch)?;
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
        expires_at: Utc::now() + Duration::minutes(5),
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
    tracing::error!(error = %error, "control-plane storage failure");
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

#[cfg(test)]
mod tests {
    use super::*;
    use prism_protocol::GpuSpec;

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
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn matching_prefers_price_then_reliability_then_benchmark() {
        let slower = offer("slower", 100, 5_000);
        let faster = offer("faster", 100, 8_000);
        let expensive = offer("expensive", 101, 10_000);
        let quote = quote_for_offers(
            &LeaseRequest {
                image: "registry.example/runtime@sha256:abc".to_owned(),
                duration_seconds: 60,
                min_vram_mib: 16_000,
                preferred_node_id: None,
            },
            [&slower, &faster, &expensive],
            &BTreeSet::new(),
        )
        .unwrap();

        assert_eq!(quote.node_id, "faster");
        assert_eq!(quote.maximum_escrow, 6_000);
    }

    #[test]
    fn matching_rejects_escrow_above_the_contract_limit() {
        let offer = offer("node", 3_000, 10_000);
        let result = quote_for_offers(
            &LeaseRequest {
                image: "registry.example/runtime@sha256:abc".to_owned(),
                duration_seconds: MAX_LEASE_SECONDS,
                min_vram_mib: 1,
                preferred_node_id: None,
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
        let quote = quote_for_offers(
            &LeaseRequest {
                image: format!("registry.example/runtime@sha256:{}", "a".repeat(64)),
                duration_seconds: 60,
                min_vram_mib: 1,
                preferred_node_id: None,
            },
            [&reserved, &stale, &available],
            &BTreeSet::from(["reserved".to_owned()]),
        )
        .unwrap();

        assert_eq!(quote.node_id, "available");
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
        };
        let mut tasks = Vec::new();
        for index in 0..MAX_NETWORK_LEASES {
            let store = store.clone();
            let request = request.clone();
            tasks.push(tokio::spawn(async move {
                store.quote(&format!("subject-{index}"), &request).await
            }));
        }
        let mut nodes = BTreeSet::new();
        for task in tasks {
            nodes.insert(task.await.unwrap().unwrap().node_id);
        }
        assert_eq!(nodes.len(), MAX_NETWORK_LEASES);
        assert!(matches!(
            store.quote("subject-over-cap", &request).await,
            Err(StoreError::NetworkCapacity)
        ));
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
                funding_transaction_hash: format!("0x{index:064x}"),
                state: LeaseState::Funded,
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
            quote_id,
            node_id: format!("0x{}", "ab".repeat(32)),
            image: format!("registry.example/runtime@sha256:{}", "cd".repeat(32)),
            duration_seconds: 600,
            min_vram_mib: 16_000,
            rate_per_second: 100,
            maximum_escrow: 60_000,
            expires_at: Utc::now() + Duration::minutes(5),
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
            funding_transaction_hash: format!("0x{}", "cc".repeat(32)),
            state: LeaseState::Funded,
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
}
