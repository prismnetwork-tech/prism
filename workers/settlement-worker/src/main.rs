use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use k256::ecdsa::{
    RecoveryId, Signature as EthereumSignature, VerifyingKey as EthereumVerifyingKey,
};
use prism_chain::EthereumSigner;
use prism_protocol::{
    CommandResult, ExecutionEvidence, MAX_VERIFIABLE_TRUST_CLASS, ManagedCommandReport,
    ManagedProvider, NodeCommandKind, NodeCommandOutcome, PublicReceipt, ROBINHOOD_CHAIN_ID,
    ReceiptOutcome, ReproExecutionReport, ReproExecutor, ReproReceiptEvidence, SettlementEvidence,
    TrustClass, gpu_repro_spec_hash, managed_repro_report_hash, node_id, receipt_hash,
    receipt_hash_matches, repro_command_hash, repro_report_hash, repro_result_hash,
    repro_stream_hash, validate_receipt_identity, verifying_key,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

/// Rebuild a settlement proposal rather than resubmit it after this many
/// failed attempts, so a transaction priced below the base fee cannot strand
/// the lease and hold its node until the retry limit runs out.
/// How much life a signature needs left for it to be worth sending. Under this
/// it is rebuilt, because a proposal that expires in flight reverts and costs an
/// attempt for nothing.
const DEADLINE_MARGIN_SECONDS: u64 = 600;
const RESIGN_AFTER_ATTEMPTS: i16 = 5;
const SIGNER_LOCK: i64 = 4_663_002;
const MAX_EVIDENCE_BYTES: u64 = 20_000_000;
const MAX_EVIDENCE_RECORDS: usize = 1_000;
const MAX_LEASE_SECONDS: u64 = 21_600;
const MAX_ESCROW_BASE_UNITS: u64 = 50_000_000;
const TELEMETRY_EDGE_TOLERANCE_SECONDS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettlementProposal {
    /// Internal id, for storage and joins.
    lease_id: u64,
    /// The escrow's id. The signature and the calldata are bound to this, so
    /// signing the internal id would produce a settlement the escrow rejects.
    #[serde(default)]
    chain_lease_id: u64,
    usage_seconds: u64,
    receipt_hash: String,
    nonce: u128,
    deadline: u64,
    evidence_hash: String,
    receipt: PublicReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Submission {
    proposal: SettlementProposal,
    attestation_signature: String,
    raw_transaction: String,
    transaction_hash: String,
    submitted: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Outbox {
    submissions: BTreeMap<u64, Submission>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedReproBinding {
    provider_instance_id: u64,
    hourly_cost_micros: u64,
    gpu_model: String,
    gpu_vram_mib: u32,
    transport_host_key_sha256: String,
    report: Option<ManagedCommandReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EscrowGeneration {
    chain_address: [u8; 20],
    database_address: String,
}

impl EscrowGeneration {
    fn parse(value: &str) -> anyhow::Result<Self> {
        let chain_address = address(value)?;
        Ok(Self {
            chain_address,
            database_address: format!("0x{}", hex::encode(chain_address)),
        })
    }
}

#[derive(Debug)]
struct ClaimedSettlement {
    lease_id: u64,
    chain_lease_id: u64,
    claim_generation: i64,
    evidence: SettlementEvidence,
}

#[derive(Debug)]
struct HistoricalNonceAttempt {
    transaction_hash: String,
    lease_id: i64,
    status: String,
}

struct HistoricalBindingAudit {
    transaction_hash: String,
    signer_address: String,
    stored_proposal: serde_json::Value,
    current_job_proposal: Option<serde_json::Value>,
    result: GenerationBindingAudit,
}

struct SelectedSubmission {
    submission: Submission,
    chain_confirmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoricalNonceResolution {
    ReservedBy(i64),
    Conflict(&'static str),
}

enum GenerationBindingAudit {
    Verified(Submission),
    Normalized(Submission),
    Quarantined(&'static str),
}

#[derive(Clone)]
struct ShutdownGate {
    receiver: watch::Receiver<bool>,
}

impl ShutdownGate {
    fn channel() -> (Self, watch::Sender<bool>) {
        let (sender, receiver) = watch::channel(false);
        (Self { receiver }, sender)
    }

    fn requested(&self) -> bool {
        *self.receiver.borrow()
    }

    async fn wait(&self) {
        let mut receiver = self.receiver.clone();
        if *receiver.borrow() {
            return;
        }
        let _ = receiver.changed().await;
    }
}

#[derive(Debug)]
struct ShutdownRequested;

impl fmt::Display for ShutdownRequested {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("settlement worker shutdown requested")
    }
}

impl std::error::Error for ShutdownRequested {}

impl GenerationBindingAudit {
    fn state(&self) -> &'static str {
        match self {
            Self::Verified(_) => "verified",
            Self::Normalized(_) => "normalized",
            Self::Quarantined(_) => "quarantined",
        }
    }

    fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Verified(_) => None,
            Self::Normalized(_) => Some("legacy_receipt_identity_normalized"),
            Self::Quarantined(reason) => Some(reason),
        }
    }

    fn proposal(&self) -> Option<&Submission> {
        match self {
            Self::Verified(proposal) | Self::Normalized(proposal) => Some(proposal),
            Self::Quarantined(_) => None,
        }
    }
}

const CONFIRMED_HISTORICAL_NONCE_OWNER: &str = "confirmed_historical_nonce_owner";
const NO_CONFIRMED_HISTORICAL_NONCE_OWNER: &str =
    "historical_nonce_collision_without_confirmed_owner";
const MULTIPLE_CONFIRMED_HISTORICAL_NONCE_OWNERS: &str =
    "historical_nonce_collision_with_multiple_confirmed_owners";

enum ClaimHeartbeat<'a> {
    Detached,
    Durable {
        pool: &'a PgPool,
        escrow: &'a EscrowGeneration,
        settlement: &'a ClaimedSettlement,
        shutdown: &'a ShutdownGate,
    },
}

impl ClaimHeartbeat<'_> {
    async fn renew(&self) -> anyhow::Result<()> {
        match self {
            Self::Detached => Ok(()),
            Self::Durable {
                pool,
                escrow,
                settlement,
                ..
            } => extend_settlement_claim(pool, escrow, settlement).await,
        }
    }

    async fn run<T>(&self, future: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
        self.renew().await?;
        tokio::pin!(future);
        loop {
            match self {
                Self::Detached => {
                    let value = future.await?;
                    return Ok(value);
                }
                Self::Durable { shutdown, .. } => {
                    tokio::select! {
                        biased;
                        () = shutdown.wait() => {
                            return Err(ShutdownRequested.into());
                        }
                        result = &mut future => {
                            let value = result?;
                            self.renew().await?;
                            return Ok(value);
                        }
                        () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                            self.renew().await?;
                        }
                    }
                }
            }
        }
    }
}

struct ChainClient {
    client: reqwest::Client,
    rpc_url: url::Url,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: serde_json::Value,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionReceipt {
    status: String,
    block_number: String,
    block_hash: String,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
    timestamp: String,
}

enum SettlementFinality {
    Pending,
    Confirmed {
        block_number: u64,
        block_hash: String,
        block_time: u64,
    },
    Reverted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptObservation {
    Adopt,
    Ignore,
    MarkReverted,
    CheckTransaction,
}

fn observe_attempt(status: &str, finality: &SettlementFinality) -> AttemptObservation {
    match status {
        "confirmed" => AttemptObservation::Adopt,
        "reverted" => AttemptObservation::Ignore,
        _ => match finality {
            SettlementFinality::Confirmed { .. } => AttemptObservation::Adopt,
            SettlementFinality::Reverted => AttemptObservation::MarkReverted,
            SettlementFinality::Pending => AttemptObservation::CheckTransaction,
        },
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let shutdown = install_shutdown_gate()?;
    if let Ok(database_url) = env::var("DATABASE_URL") {
        return run_database(&database_url, &shutdown).await;
    }
    if env::var("PRISM_ALLOW_DEVELOPMENT_FILE_HANDOFF").as_deref() != Ok("1") {
        anyhow::bail!("DATABASE_URL is required for durable settlement processing");
    }
    run_file(&shutdown).await
}

fn install_shutdown_gate() -> anyhow::Result<ShutdownGate> {
    let (shutdown, sender) = ShutdownGate::channel();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        tokio::spawn(async move {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if let Err(error) = result {
                        tracing::error!(%error, "settlement interrupt handler failed");
                    }
                }
                _ = terminate.recv() => {}
            }
            let _ = sender.send(true);
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "settlement interrupt handler failed");
        }
        let _ = sender.send(true);
    });
    Ok(shutdown)
}

async fn run_file(shutdown: &ShutdownGate) -> anyhow::Result<()> {
    let evidence_path = PathBuf::from(required_env("PRISM_SETTLEMENT_EVIDENCE_FILE")?);
    let outbox_path = PathBuf::from(required_env("PRISM_SETTLEMENT_OUTBOX_FILE")?);
    let escrow = EscrowGeneration::parse(&required_env("PRISM_LEASE_ESCROW_ADDRESS")?)?;
    let evidence: Vec<SettlementEvidence> =
        serde_json::from_slice(&read_bounded(&evidence_path, MAX_EVIDENCE_BYTES)?)?;
    if evidence.len() > MAX_EVIDENCE_RECORDS {
        anyhow::bail!("settlement input contains too many evidence records");
    }
    let rpc_url = secure_url(&required_env("PRISM_RPC_URL")?)?;
    let chain = ChainClient::new(rpc_url)?;
    let chain_id = chain.quantity("eth_chainId", serde_json::json!([])).await?;
    if chain_id != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("RPC chain ID does not match Robinhood Chain mainnet");
    }
    let gateway = chain.gateway(escrow.chain_address).await?;
    let mut proposals = evidence
        .iter()
        .map(|evidence| reconcile_with_gateway(evidence, Some(gateway)))
        .collect::<Result<Vec<_>, _>>()?;
    for proposal in &mut proposals {
        enrich_receipt_identity(proposal, &escrow)?;
    }
    proposals.sort_by_key(|proposal| proposal.lease_id);

    let signer = EthereumSigner::from_environment("PRISM_ATTESTOR_KMS_KEY_ID").await?;
    let mut outbox = if outbox_path.exists() {
        serde_json::from_slice(&read_bounded(&outbox_path, MAX_EVIDENCE_BYTES)?)?
    } else {
        Outbox::default()
    };
    let heartbeat = ClaimHeartbeat::Detached;

    for proposal in proposals {
        if shutdown.requested() {
            tracing::info!("settlement worker stopped before claiming more file submissions");
            return Ok(());
        }
        let lease_id = proposal.lease_id;
        if !outbox.submissions.contains_key(&lease_id) {
            let signer_address = format!("0x{}", hex::encode(signer.address()));
            let nonce = chain
                .quantity(
                    "eth_getTransactionCount",
                    serde_json::json!([signer_address, "pending"]),
                )
                .await?;
            let submission = prepare_submission(
                &chain,
                &signer,
                escrow.chain_address,
                proposal,
                nonce,
                &heartbeat,
            )
            .await?;
            outbox
                .submissions
                .insert(submission.proposal.lease_id, submission);
            atomic_write(&outbox_path, &serde_json::to_vec_pretty(&outbox)?)?;
        }
        let submission = outbox
            .submissions
            .get_mut(&lease_id)
            .expect("submission was inserted");
        if submission.submitted {
            continue;
        }
        let known: Option<serde_json::Value> = chain
            .call(
                "eth_getTransactionByHash",
                serde_json::json!([submission.transaction_hash]),
            )
            .await?;
        if known.is_none() {
            let transaction_hash: String = chain
                .call(
                    "eth_sendRawTransaction",
                    serde_json::json!([submission.raw_transaction]),
                )
                .await?;
            if !transaction_hash.eq_ignore_ascii_case(&submission.transaction_hash) {
                anyhow::bail!("RPC returned an unexpected transaction hash");
            }
        }
        submission.submitted = true;
        let lease_id = submission.proposal.lease_id;
        let transaction_hash = submission.transaction_hash.clone();
        atomic_write(&outbox_path, &serde_json::to_vec_pretty(&outbox)?)?;
        tracing::info!(
            lease_id,
            transaction_hash = %transaction_hash,
            "settlement proposal submitted"
        );
    }
    Ok(())
}

async fn run_database(database_url: &str, shutdown: &ShutdownGate) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(database_url)
        .await
        .context("connect settlement database")?;
    let present = query_as::<_, (Option<String>, Option<String>)>(
        "SELECT to_regclass('public.settlement_transaction_attempts')::text, \
                to_regclass('public.settlement_signer_nonce_reservations')::text",
    )
    .fetch_one(&pool)
    .await?;
    if present.0.is_none() || present.1.is_none() {
        anyhow::bail!("control-plane settlement migrations have not been applied");
    }
    record_service_version(&pool, "settlement-worker").await?;
    let escrow = EscrowGeneration::parse(&required_env("PRISM_LEASE_ESCROW_ADDRESS")?)?;
    tracing::info!(
        escrow_generation = %escrow.database_address,
        "settlement worker bound to escrow generation"
    );
    let chain = ChainClient::new(secure_url(&required_env("PRISM_RPC_URL")?)?)?;
    if chain.quantity("eth_chainId", serde_json::json!([])).await? != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("settlement RPC is not Robinhood Chain");
    }
    let signer = EthereumSigner::from_environment("PRISM_ATTESTOR_KMS_KEY_ID").await?;
    backfill_attempt_signers(&pool).await?;
    let confirmations = env::var("PRISM_SETTLEMENT_CONFIRMATIONS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(12);
    if confirmations == 0 || confirmations > 10_000 {
        anyhow::bail!("settlement confirmation threshold is invalid");
    }
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    loop {
        let settlement = tokio::select! {
            biased;
            () = shutdown.wait() => {
                tracing::info!("settlement worker stopped before claiming another job");
                return Ok(());
            }
            settlement = claim_settlement(&pool, &escrow) => settlement?,
        };
        let Some(settlement) = settlement else {
            if run_once {
                return Ok(());
            }
            tokio::select! {
                biased;
                () = shutdown.wait() => {
                    tracing::info!("settlement worker stopped while idle");
                    return Ok(());
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
            continue;
        };
        let lease_id = settlement.lease_id;
        let result = process_settlement(
            &pool,
            &chain,
            &signer,
            &escrow,
            confirmations,
            &settlement,
            shutdown,
        )
        .await;
        if shutdown.requested() {
            if let Err(error) = &result {
                tracing::info!(lease_id, %error, "settlement job stopped at a durable boundary");
            }
            release_settlement_claim(&pool, &escrow, &settlement).await?;
            tracing::info!("settlement worker shut down cleanly");
            return Ok(());
        }
        if let Err(error) = result {
            tracing::error!(lease_id, %error, "settlement job failed");
            retry_settlement(&pool, &escrow, &settlement, &error).await?;
        }
        if run_once {
            return Ok(());
        }
    }
}

/// Claims a job. The stored proposal is deliberately not returned: whether it
/// can still be reused is decided in `prepare_durable_submission`, which is the
/// only place that knows the rules for rebuilding one.
async fn claim_settlement(
    pool: &PgPool,
    escrow: &EscrowGeneration,
) -> anyhow::Result<Option<ClaimedSettlement>> {
    let mut transaction = pool.begin().await?;
    let row = query_as::<_, (i64, i64, SqlJson<SettlementEvidence>)>(
        "SELECT job.lease_id, lease.chain_lease_id, job.evidence \
         FROM settlement_jobs AS job \
         JOIN leases AS lease ON lease.lease_id = job.lease_id \
         WHERE lease.escrow_address = $1 \
           AND job.attempts < 100 AND job.available_at <= NOW() \
           AND (job.status IN ('queued', 'submitted') \
                OR (job.status = 'processing' AND job.lease_until <= NOW())) \
         ORDER BY job.available_at, job.created_at LIMIT 1 \
         FOR UPDATE OF job, lease SKIP LOCKED",
    )
    .bind(&escrow.database_address)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((lease_id, chain_lease_id, SqlJson(evidence))) = row else {
        transaction.commit().await?;
        return Ok(None);
    };
    let settlement = ClaimedSettlement {
        lease_id: u64::try_from(lease_id)?,
        chain_lease_id: u64::try_from(chain_lease_id)?,
        claim_generation: 0,
        evidence,
    };
    validate_claimed_identity(&settlement)?;
    let claim_generation: i64 = query_scalar(
        "UPDATE settlement_jobs AS job \
         SET status = 'processing', attempts = attempts + 1, \
             claim_generation = claim_generation + 1, \
             lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
         RETURNING job.claim_generation",
    )
    .bind(lease_id)
    .bind(&escrow.database_address)
    .bind(chain_lease_id)
    .fetch_one(&mut *transaction)
    .await?;
    if claim_generation <= 0 {
        anyhow::bail!("settlement claim generation is invalid");
    }
    transaction.commit().await?;
    Ok(Some(ClaimedSettlement {
        claim_generation,
        ..settlement
    }))
}

fn validate_claimed_identity(settlement: &ClaimedSettlement) -> anyhow::Result<()> {
    if settlement.evidence.lease_id != settlement.lease_id
        || settlement.evidence.chain_lease_id != settlement.chain_lease_id
        || settlement.chain_lease_id == 0
    {
        anyhow::bail!("settlement evidence does not match its lease identity");
    }
    Ok(())
}

fn validate_stored_binding(
    settlement: &ClaimedSettlement,
    binding: Option<(i64, SqlJson<SettlementEvidence>)>,
) -> anyhow::Result<()> {
    let Some((chain_lease_id, SqlJson(evidence))) = binding else {
        anyhow::bail!("settlement lease does not belong to this escrow generation");
    };
    if u64::try_from(chain_lease_id)? != settlement.chain_lease_id
        || evidence != settlement.evidence
    {
        anyhow::bail!("settlement binding changed after it was claimed");
    }
    validate_claimed_identity(settlement)
}

fn current_job_proposal_matches_attempt(
    attempt: &serde_json::Value,
    current: &serde_json::Value,
    escrow_address: &str,
    chain_lease_id: i64,
) -> bool {
    if current == attempt {
        return true;
    }
    let Ok(mut legacy) = serde_json::from_value::<Submission>(current.clone()) else {
        return false;
    };
    if legacy.proposal.receipt.escrow_address.is_some()
        || legacy.proposal.receipt.chain_lease_id.is_some()
    {
        return false;
    }
    legacy.proposal.receipt.escrow_address = Some(escrow_address.to_owned());
    legacy.proposal.receipt.chain_lease_id = Some(chain_lease_id.to_string());
    serde_json::to_value(legacy).is_ok_and(|normalized| normalized == *attempt)
}

#[allow(clippy::too_many_arguments)]
fn audit_generation_binding(
    transaction_hash: &str,
    raw_transaction: &str,
    stored_nonce: i64,
    lease_id: i64,
    escrow_address: &str,
    chain_lease_id: i64,
    proposal_value: &serde_json::Value,
    current_job_proposal: Option<&serde_json::Value>,
    decoded: &DecodedLegacyTransaction,
) -> GenerationBindingAudit {
    let raw_bytes = match hex::decode(
        raw_transaction
            .strip_prefix("0x")
            .unwrap_or(raw_transaction),
    ) {
        Ok(bytes) => bytes,
        Err(_) => return GenerationBindingAudit::Quarantined("submission_transaction_mismatch"),
    };
    let computed_hash = format!("0x{}", hex::encode(Keccak256::digest(raw_bytes)));
    if computed_hash != transaction_hash {
        return GenerationBindingAudit::Quarantined("transaction_hash_mismatch");
    }
    if current_job_proposal.is_some_and(|proposal| {
        !current_job_proposal_matches_attempt(
            proposal_value,
            proposal,
            escrow_address,
            chain_lease_id,
        )
    }) {
        return GenerationBindingAudit::Quarantined("job_attempt_proposal_mismatch");
    }
    let Ok(mut submission) = serde_json::from_value::<Submission>(proposal_value.clone()) else {
        return GenerationBindingAudit::Quarantined("invalid_stored_submission");
    };
    if submission.raw_transaction != raw_transaction
        || submission.transaction_hash != transaction_hash
    {
        return GenerationBindingAudit::Quarantined("submission_transaction_mismatch");
    }
    if decoded.chain_id != ROBINHOOD_CHAIN_ID {
        return GenerationBindingAudit::Quarantined("signed_chain_mismatch");
    }
    let Ok(expected_escrow) = address(escrow_address) else {
        return GenerationBindingAudit::Quarantined("signed_escrow_mismatch");
    };
    if decoded.destination != expected_escrow {
        return GenerationBindingAudit::Quarantined("signed_escrow_mismatch");
    }
    if i64::try_from(decoded.nonce).ok() != Some(stored_nonce) {
        return GenerationBindingAudit::Quarantined("signed_nonce_mismatch");
    }
    if i64::try_from(submission.proposal.lease_id).ok() != Some(lease_id)
        || i64::try_from(submission.proposal.chain_lease_id).ok() != Some(chain_lease_id)
        || submission.proposal.receipt.lease_id != chain_lease_id.to_string()
    {
        return GenerationBindingAudit::Quarantined("proposal_lease_mismatch");
    }
    if submission.proposal.receipt.receipt_hash != submission.proposal.receipt_hash
        || !receipt_hash_matches(&submission.proposal.receipt).unwrap_or(false)
    {
        return GenerationBindingAudit::Quarantined("receipt_hash_mismatch");
    }
    let normalized = match (
        submission.proposal.receipt.escrow_address.as_deref(),
        submission.proposal.receipt.chain_lease_id.as_deref(),
    ) {
        (None, None) => true,
        (Some(receipt_escrow), Some(receipt_chain_lease_id))
            if receipt_escrow == escrow_address
                && receipt_chain_lease_id == chain_lease_id.to_string()
                && validate_receipt_identity(&submission.proposal.receipt).is_ok() =>
        {
            false
        }
        _ => return GenerationBindingAudit::Quarantined("receipt_identity_mismatch"),
    };
    let Ok(attestation_signature) = hex::decode(
        submission
            .attestation_signature
            .strip_prefix("0x")
            .unwrap_or(&submission.attestation_signature),
    ) else {
        return GenerationBindingAudit::Quarantined("attestation_signature_mismatch");
    };
    let Ok(attestation_signature) = <[u8; 65]>::try_from(attestation_signature) else {
        return GenerationBindingAudit::Quarantined("attestation_signature_mismatch");
    };
    if proposal_calldata(&submission.proposal, &attestation_signature)
        .map_or(true, |calldata| calldata != decoded.data)
    {
        return GenerationBindingAudit::Quarantined("calldata_mismatch");
    }
    let Ok(digest) = settlement_digest(ROBINHOOD_CHAIN_ID, expected_escrow, &submission.proposal)
    else {
        return GenerationBindingAudit::Quarantined("attestation_signature_mismatch");
    };
    if recover_digest_signer(&digest, &attestation_signature)
        .map_or(true, |signer| signer != decoded.signer_address)
    {
        return GenerationBindingAudit::Quarantined("attestation_signature_mismatch");
    }
    if !normalized {
        return GenerationBindingAudit::Verified(submission);
    }
    let committed_receipt_hash = submission.proposal.receipt_hash.clone();
    submission.proposal.receipt.escrow_address = Some(escrow_address.to_owned());
    submission.proposal.receipt.chain_lease_id = Some(chain_lease_id.to_string());
    if validate_receipt_identity(&submission.proposal.receipt).is_err()
        || receipt_hash(&submission.proposal.receipt).ok().as_deref()
            != Some(committed_receipt_hash.as_str())
    {
        return GenerationBindingAudit::Quarantined("receipt_identity_mismatch");
    }
    GenerationBindingAudit::Normalized(submission)
}

fn recover_digest_signer(digest: &[u8; 32], signature: &[u8; 65]) -> anyhow::Result<String> {
    let recovery_id = signature[64]
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
        .context("signature recovery id is invalid")?;
    let signature = EthereumSignature::from_slice(&signature[..64])?;
    if signature.normalize_s().is_some() {
        anyhow::bail!("signature scalar is not canonical");
    }
    let signer = EthereumVerifyingKey::recover_from_prehash(digest, &signature, recovery_id)?;
    let point = signer.to_encoded_point(false);
    Ok(format!(
        "0x{}",
        hex::encode(&Keccak256::digest(&point.as_bytes()[1..])[12..])
    ))
}

async fn backfill_attempt_signers(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    query("SELECT pg_advisory_xact_lock($1)")
        .bind(SIGNER_LOCK)
        .execute(&mut *transaction)
        .await?;
    let attempts = query_as::<
        _,
        (
            String,
            String,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            String,
            Option<String>,
            SqlJson<serde_json::Value>,
            Option<String>,
            Option<SqlJson<serde_json::Value>>,
            String,
            i64,
        ),
    >(
        "SELECT attempt.transaction_hash, attempt.raw_transaction, attempt.lease_id, \
                attempt.transaction_nonce, attempt.status, attempt.signer_address, \
                attempt.nonce_reservation_state, attempt.nonce_reservation_reason, \
                attempt.generation_binding_state, attempt.generation_binding_reason, \
                attempt.proposal, job.transaction_hash, job.proposal, \
                lease.escrow_address, lease.chain_lease_id \
         FROM settlement_transaction_attempts AS attempt \
         JOIN settlement_jobs AS job ON job.lease_id = attempt.lease_id \
         JOIN leases AS lease ON lease.lease_id = attempt.lease_id \
         ORDER BY attempt.prepared_at, attempt.transaction_hash \
         FOR UPDATE OF attempt, job, lease",
    )
    .fetch_all(&mut *transaction)
    .await?;
    let mut groups = BTreeMap::<(String, i64), Vec<HistoricalNonceAttempt>>::new();
    let mut binding_audits = Vec::<HistoricalBindingAudit>::new();
    for (
        transaction_hash,
        raw_transaction,
        lease_id,
        stored_nonce,
        status,
        stored_signer,
        reservation_state,
        reservation_reason,
        binding_state,
        _binding_reason,
        SqlJson(attempt_proposal),
        job_transaction_hash,
        job_proposal,
        escrow_address,
        chain_lease_id,
    ) in attempts
    {
        let decoded = match decode_legacy_transaction(&raw_transaction) {
            Ok(decoded) => decoded,
            Err(error) => {
                quarantine_undecodable_attempt(&mut transaction, &transaction_hash).await?;
                tracing::error!(
                    transaction_hash,
                    %error,
                    "quarantined undecodable historical settlement transaction"
                );
                continue;
            }
        };
        let signer_address = decoded.signer_address.clone();
        let signed_nonce = i64::try_from(decoded.nonce)?;
        if stored_signer
            .as_ref()
            .is_some_and(|stored| stored != &signer_address)
        {
            anyhow::bail!("settlement transaction signer backfill conflicted");
        }
        if reservation_state == "pending" && reservation_reason.is_some() {
            anyhow::bail!("pending settlement nonce reservation has a resolution reason");
        }
        let is_current_job = job_transaction_hash.as_deref() == Some(&transaction_hash);
        let current_job_proposal = if is_current_job {
            job_proposal.map(|SqlJson(proposal)| proposal)
        } else {
            None
        };
        let mut audit = if is_current_job && current_job_proposal.is_none() {
            GenerationBindingAudit::Quarantined("job_attempt_proposal_mismatch")
        } else {
            audit_generation_binding(
                &transaction_hash,
                &raw_transaction,
                stored_nonce,
                lease_id,
                &escrow_address,
                chain_lease_id,
                &attempt_proposal,
                current_job_proposal.as_ref(),
                &decoded,
            )
        };
        if binding_state == "normalized"
            && let GenerationBindingAudit::Verified(proposal) = audit
        {
            audit = GenerationBindingAudit::Normalized(proposal);
        }
        binding_audits.push(HistoricalBindingAudit {
            transaction_hash: transaction_hash.clone(),
            signer_address: signer_address.clone(),
            stored_proposal: attempt_proposal,
            current_job_proposal,
            result: audit,
        });
        groups
            .entry((signer_address, signed_nonce))
            .or_default()
            .push(HistoricalNonceAttempt {
                transaction_hash,
                lease_id,
                status,
            });
    }

    let resolutions = groups
        .iter()
        .map(|(key, attempts)| (key.clone(), resolve_historical_nonce(attempts)))
        .collect::<Vec<_>>();
    let conflicts = resolutions
        .iter()
        .filter_map(|((signer, nonce), resolution)| match resolution {
            HistoricalNonceResolution::ReservedBy(_) => None,
            HistoricalNonceResolution::Conflict(reason) => Some((signer.clone(), *nonce, *reason)),
        })
        .collect::<Vec<_>>();
    if !conflicts.is_empty() {
        for ((signer, nonce), resolution) in &resolutions {
            let HistoricalNonceResolution::Conflict(reason) = resolution else {
                continue;
            };
            for attempt in groups.get(&(signer.clone(), *nonce)).into_iter().flatten() {
                annotate_historical_nonce_attempt(
                    &mut transaction,
                    attempt,
                    signer,
                    "conflict",
                    Some(reason),
                )
                .await?;
            }
        }
        for audit in &binding_audits {
            if matches!(audit.result, GenerationBindingAudit::Quarantined(_)) {
                annotate_historical_generation_binding(
                    &mut transaction,
                    &audit.transaction_hash,
                    &audit.signer_address,
                    &audit.stored_proposal,
                    &audit.result,
                )
                .await?;
            }
        }
        detach_unsafe_historical_job_cursors(&mut transaction).await?;
        transaction.commit().await?;
        let details = conflicts
            .into_iter()
            .map(|(signer, nonce, reason)| format!("{signer}:{nonce} ({reason})"))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "historical settlement signer nonce conflicts require operator resolution: {details}"
        );
    }

    for ((signer, nonce), resolution) in resolutions {
        let HistoricalNonceResolution::ReservedBy(owner) = resolution else {
            unreachable!("historical nonce conflicts returned before reservation")
        };
        let attempts = groups
            .get(&(signer.clone(), nonce))
            .context("historical settlement nonce group disappeared")?;
        for attempt in attempts {
            let (state, reason) = if attempt.lease_id == owner {
                ("reserved", None)
            } else {
                ("noncanonical", Some(CONFIRMED_HISTORICAL_NONCE_OWNER))
            };
            annotate_historical_nonce_attempt(&mut transaction, attempt, &signer, state, reason)
                .await?;
        }
        reserve_historical_nonce(&mut transaction, &signer, nonce, owner, attempts).await?;
    }
    for audit in binding_audits {
        annotate_historical_generation_binding(
            &mut transaction,
            &audit.transaction_hash,
            &audit.signer_address,
            &audit.stored_proposal,
            &audit.result,
        )
        .await?;
        let (Some(original), GenerationBindingAudit::Normalized(normalized)) =
            (audit.current_job_proposal, &audit.result)
        else {
            continue;
        };
        normalize_historical_job_proposal(
            &mut transaction,
            &audit.transaction_hash,
            &original,
            &serde_json::to_value(normalized)?,
        )
        .await?;
    }
    detach_unsafe_historical_job_cursors(&mut transaction).await?;
    let incomplete: i64 = query_scalar(
        "SELECT COUNT(*) FROM settlement_transaction_attempts \
         WHERE generation_binding_state = 'pending' \
            OR ((signer_address IS NULL OR nonce_reservation_state = 'pending') \
                AND NOT (generation_binding_state = 'quarantined' \
                         AND generation_binding_reason = 'invalid_signed_transaction'))",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if incomplete != 0 {
        anyhow::bail!("settlement transaction signer backfill is incomplete");
    }
    transaction.commit().await?;
    Ok(())
}

async fn annotate_historical_generation_binding(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
    transaction_hash: &str,
    signer: &str,
    original_proposal: &serde_json::Value,
    audit: &GenerationBindingAudit,
) -> anyhow::Result<()> {
    let proposal = audit
        .proposal()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| original_proposal.clone());
    let state = audit.state();
    let reason = audit.reason();
    let updated = query(
        "UPDATE settlement_transaction_attempts \
         SET signer_address = $2, proposal = $3, generation_binding_state = $4, \
             generation_binding_reason = $5 \
         WHERE transaction_hash = $1 \
           AND (signer_address IS NULL OR signer_address = $2) \
           AND (generation_binding_state = 'pending' \
                OR (generation_binding_state = $4 \
                    AND generation_binding_reason IS NOT DISTINCT FROM $5 \
                    AND proposal = $3))",
    )
    .bind(transaction_hash)
    .bind(signer)
    .bind(SqlJson(proposal.clone()))
    .bind(state)
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!(
            "settlement attempt {transaction_hash} has an incompatible generation binding: {state}/{}",
            reason.unwrap_or("none")
        );
    }

    Ok(())
}

async fn quarantine_undecodable_attempt(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
    transaction_hash: &str,
) -> anyhow::Result<()> {
    let quarantined = query(
        "UPDATE settlement_transaction_attempts \
         SET generation_binding_state = 'quarantined', \
             generation_binding_reason = 'invalid_signed_transaction' \
         WHERE transaction_hash = $1 \
           AND (generation_binding_state = 'pending' \
                OR (generation_binding_state = 'quarantined' \
                    AND generation_binding_reason = 'invalid_signed_transaction'))",
    )
    .bind(transaction_hash)
    .execute(&mut **transaction)
    .await?;
    if quarantined.rows_affected() != 1 {
        anyhow::bail!(
            "settlement attempt {transaction_hash} has an incompatible undecodable transaction binding"
        );
    }
    Ok(())
}

async fn normalize_historical_job_proposal(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
    transaction_hash: &str,
    original: &serde_json::Value,
    normalized: &serde_json::Value,
) -> anyhow::Result<()> {
    let eligible: bool = query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM settlement_transaction_attempts AS attempt \
             WHERE attempt.transaction_hash = $1 \
               AND attempt.generation_binding_state = 'normalized' \
               AND attempt.nonce_reservation_state = 'reserved' \
               AND attempt.signer_address IS NOT NULL \
               AND EXISTS ( \
                   SELECT 1 FROM settlement_signer_nonce_reservations AS reservation \
                   WHERE reservation.signer_address = attempt.signer_address \
                     AND reservation.transaction_nonce = attempt.transaction_nonce \
                     AND reservation.lease_id = attempt.lease_id \
               ) \
         )",
    )
    .bind(transaction_hash)
    .fetch_one(&mut **transaction)
    .await?;
    if !eligible {
        return Ok(());
    }
    let updated = query(
        "UPDATE settlement_jobs AS job \
         SET proposal = $2, updated_at = NOW() \
         FROM settlement_transaction_attempts AS attempt \
         WHERE attempt.transaction_hash = $1 \
           AND attempt.lease_id = job.lease_id \
           AND attempt.generation_binding_state = 'normalized' \
           AND attempt.nonce_reservation_state = 'reserved' \
           AND attempt.signer_address IS NOT NULL \
           AND attempt.proposal = $2 \
           AND job.transaction_hash = attempt.transaction_hash \
           AND job.raw_transaction = attempt.raw_transaction \
           AND job.transaction_nonce = attempt.transaction_nonce \
           AND job.proposal = $3 \
           AND EXISTS ( \
               SELECT 1 FROM settlement_signer_nonce_reservations AS reservation \
               WHERE reservation.signer_address = attempt.signer_address \
                 AND reservation.transaction_nonce = attempt.transaction_nonce \
                 AND reservation.lease_id = attempt.lease_id \
           )",
    )
    .bind(transaction_hash)
    .bind(SqlJson(normalized.clone()))
    .bind(SqlJson(original.clone()))
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!(
            "settlement job for attempt {transaction_hash} could not normalize its legacy receipt identity"
        );
    }
    Ok(())
}

async fn detach_unsafe_historical_job_cursors(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
) -> anyhow::Result<()> {
    let detached = query(
        "UPDATE settlement_jobs AS job \
         SET proposal = NULL, raw_transaction = NULL, transaction_hash = NULL, \
             transaction_nonce = NULL, \
             status = CASE \
                 WHEN job.status IN ('queued', 'processing', 'submitted') THEN 'queued' \
                 WHEN job.status IN ('proposed', 'disputed', 'finalized') THEN 'failed' \
                 ELSE job.status \
             END, \
             attempts = CASE WHEN job.status IN ('queued', 'processing', 'submitted') \
                             THEN 0 ELSE job.attempts END, \
             available_at = CASE WHEN job.status IN ('queued', 'processing', 'submitted') \
                                 THEN NOW() ELSE job.available_at END, \
             lease_until = CASE WHEN job.status IN ('queued', 'processing', 'submitted') \
                                THEN NULL ELSE job.lease_until END, \
             confirmed_block = NULL, confirmed_block_hash = NULL, \
             last_error = 'historical settlement cursor quarantined; immutable attempt evidence retained', \
             updated_at = NOW() \
         FROM settlement_transaction_attempts AS attempt \
         WHERE attempt.transaction_hash = job.transaction_hash \
           AND attempt.lease_id = job.lease_id \
           AND NOT ( \
               attempt.raw_transaction = job.raw_transaction \
               AND attempt.transaction_nonce = job.transaction_nonce \
               AND attempt.proposal = job.proposal \
               AND attempt.signer_address IS NOT NULL \
               AND attempt.nonce_reservation_state = 'reserved' \
               AND attempt.generation_binding_state IN ('verified', 'normalized') \
               AND EXISTS ( \
                   SELECT 1 FROM settlement_signer_nonce_reservations AS reservation \
                   WHERE reservation.signer_address = attempt.signer_address \
                     AND reservation.transaction_nonce = attempt.transaction_nonce \
                     AND reservation.lease_id = attempt.lease_id \
               ) \
           )",
    )
    .execute(&mut **transaction)
    .await?;
    if detached.rows_affected() > 0 {
        tracing::warn!(
            jobs = detached.rows_affected(),
            "detached unsafe historical settlement job cursors"
        );
    }
    Ok(())
}

fn resolve_historical_nonce(attempts: &[HistoricalNonceAttempt]) -> HistoricalNonceResolution {
    let leases = attempts
        .iter()
        .map(|attempt| attempt.lease_id)
        .collect::<BTreeSet<_>>();
    if let [lease_id] = leases.iter().copied().collect::<Vec<_>>().as_slice() {
        return HistoricalNonceResolution::ReservedBy(*lease_id);
    }
    let confirmed = attempts
        .iter()
        .filter(|attempt| attempt.status == "confirmed")
        .map(|attempt| attempt.lease_id)
        .collect::<BTreeSet<_>>();
    match confirmed.iter().copied().collect::<Vec<_>>().as_slice() {
        [lease_id] => HistoricalNonceResolution::ReservedBy(*lease_id),
        [] => HistoricalNonceResolution::Conflict(NO_CONFIRMED_HISTORICAL_NONCE_OWNER),
        _ => HistoricalNonceResolution::Conflict(MULTIPLE_CONFIRMED_HISTORICAL_NONCE_OWNERS),
    }
}

async fn annotate_historical_nonce_attempt(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
    attempt: &HistoricalNonceAttempt,
    signer: &str,
    state: &str,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let updated = query(
        "UPDATE settlement_transaction_attempts \
         SET signer_address = $2, nonce_reservation_state = $3, \
             nonce_reservation_reason = $4 \
         WHERE transaction_hash = $1 \
           AND (signer_address IS NULL OR signer_address = $2) \
           AND (nonce_reservation_state = 'pending' \
                OR (nonce_reservation_state = 'conflict' \
                    AND $3 IN ('reserved', 'noncanonical')) \
                OR (nonce_reservation_state = $3 \
                    AND nonce_reservation_reason IS NOT DISTINCT FROM $4))",
    )
    .bind(&attempt.transaction_hash)
    .bind(signer)
    .bind(state)
    .bind(reason)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!(
            "settlement attempt {} has an incompatible nonce reservation state",
            attempt.transaction_hash
        );
    }
    Ok(())
}

async fn reserve_historical_nonce(
    transaction: &mut sqlx_postgres::PgTransaction<'_>,
    signer: &str,
    nonce: i64,
    owner: i64,
    attempts: &[HistoricalNonceAttempt],
) -> anyhow::Result<()> {
    let existing = query_as::<_, (i64, Option<i64>)>(
        "SELECT lease_id, corrected_from_lease_id \
         FROM settlement_signer_nonce_reservations \
         WHERE signer_address = $1 AND transaction_nonce = $2 \
         FOR UPDATE",
    )
    .bind(signer)
    .bind(nonce)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((reserved_owner, corrected_from)) = existing else {
        query(
            "INSERT INTO settlement_signer_nonce_reservations ( \
                 signer_address, transaction_nonce, lease_id \
             ) VALUES ($1, $2, $3)",
        )
        .bind(signer)
        .bind(nonce)
        .bind(owner)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    };
    if reserved_owner == owner {
        return Ok(());
    }
    let group_leases = attempts
        .iter()
        .map(|attempt| attempt.lease_id)
        .collect::<BTreeSet<_>>();
    if corrected_from.is_some() || !group_leases.contains(&reserved_owner) {
        anyhow::bail!(
            "settlement signer {signer} nonce {nonce} is reserved by unrelated lease {reserved_owner}"
        );
    }
    let corrected = query(
        "UPDATE settlement_signer_nonce_reservations \
         SET corrected_from_lease_id = lease_id, lease_id = $3, \
             corrected_at = NOW(), correction_reason = $4 \
         WHERE signer_address = $1 AND transaction_nonce = $2 \
           AND lease_id = $5 AND corrected_from_lease_id IS NULL",
    )
    .bind(signer)
    .bind(nonce)
    .bind(owner)
    .bind(CONFIRMED_HISTORICAL_NONCE_OWNER)
    .bind(reserved_owner)
    .execute(&mut **transaction)
    .await?;
    if corrected.rows_affected() != 1 {
        anyhow::bail!("historical settlement nonce reservation correction conflicted");
    }
    Ok(())
}

async fn extend_settlement_claim(
    pool: &PgPool,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
) -> anyhow::Result<()> {
    let extended = query(
        "UPDATE settlement_jobs AS job \
         SET lease_until = NOW() + INTERVAL '2 minutes' \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
           AND job.claim_generation = $4 AND job.evidence = $5 \
           AND job.status = 'processing'",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .execute(pool)
    .await?;
    if extended.rows_affected() != 1 {
        anyhow::bail!("settlement claim ownership changed during preparation");
    }
    Ok(())
}

async fn load_managed_repro_binding(
    connection: &mut PgConnection,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
) -> anyhow::Result<Option<ManagedReproBinding>> {
    let Some((
        provider_instance_id,
        hourly_cost_micros,
        gpu_model,
        gpu_vram_mib,
        transport_host_key_sha256,
        report,
    )) = query_as::<
        _,
        (
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<i32>,
            Option<String>,
            Option<SqlJson<ManagedCommandReport>>,
        ),
    >(
        "SELECT repro.prepared_provider_instance_id, repro.prepared_hourly_cost_micros, \
                repro.gpu_model, repro.gpu_vram_mib, \
                repro.transport_host_key_sha256, repro.report \
         FROM managed_repro_jobs AS repro \
         JOIN leases AS lease ON lease.lease_id = repro.lease_id \
         WHERE repro.lease_id = $1 AND lease.escrow_address = $2 \
           AND lease.chain_lease_id = $3",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .fetch_optional(connection)
    .await?
    else {
        return Ok(None);
    };
    let provider_instance_id = provider_instance_id
        .and_then(|value| u64::try_from(value).ok())
        .context("managed settlement has no prepared provider instance")?;
    let hourly_cost_micros = hourly_cost_micros
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .context("managed settlement has no captured provider cost")?;
    let gpu_model = gpu_model
        .filter(|value| !value.trim().is_empty() && value.len() <= 128)
        .context("managed settlement has no valid captured GPU model")?;
    let gpu_vram_mib = gpu_vram_mib
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= 196_608)
        .context("managed settlement has no valid captured GPU memory")?;
    let transport_host_key_sha256 = transport_host_key_sha256
        .filter(|value| is_lower_sha256(value))
        .context("managed settlement has no valid captured host-key commitment")?;
    Ok(Some(ManagedReproBinding {
        provider_instance_id,
        hourly_cost_micros,
        gpu_model,
        gpu_vram_mib,
        transport_host_key_sha256,
        report: report.map(|SqlJson(report)| report),
    }))
}

fn submission_matches_settlement(submission: &Submission, proposal: &SettlementProposal) -> bool {
    submission.proposal.lease_id == proposal.lease_id
        && submission.proposal.chain_lease_id == proposal.chain_lease_id
        && submission.proposal.usage_seconds == proposal.usage_seconds
        && submission.proposal.receipt_hash == proposal.receipt_hash
        && submission.proposal.nonce == proposal.nonce
        && submission.proposal.evidence_hash == proposal.evidence_hash
        && submission.proposal.receipt == proposal.receipt
}

fn deadline_has_margin(deadline: u64, now: u64) -> bool {
    deadline > now.saturating_add(DEADLINE_MARGIN_SECONDS)
}

fn pending_attempt_is_reusable(transaction_known: bool, deadline: u64, now: u64) -> bool {
    transaction_known && deadline_has_margin(deadline, now)
}

fn current_timestamp() -> anyhow::Result<u64> {
    u64::try_from(Utc::now().timestamp()).context("system clock is before the Unix epoch")
}

async fn reconcile_transaction_attempts(
    connection: &mut PgConnection,
    chain: &ChainClient,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    proposal: &SettlementProposal,
    confirmations: u64,
    heartbeat: &ClaimHeartbeat<'_>,
) -> anyhow::Result<Option<SelectedSubmission>> {
    let attempts = query_as::<_, (SqlJson<Submission>, String, String, i64, String, String)>(
        "SELECT proposal, status, raw_transaction, transaction_nonce, transaction_hash, \
                signer_address \
         FROM settlement_transaction_attempts \
         WHERE lease_id = $1 AND escrow_address = $2 AND chain_lease_id = $3 \
           AND nonce_reservation_state = 'reserved' \
           AND generation_binding_state IN ('verified', 'normalized') \
         ORDER BY prepared_at DESC",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .fetch_all(&mut *connection)
    .await?;
    let mut known = None;
    for (SqlJson(submission), status, raw_transaction, nonce, transaction_hash, signer_address) in
        attempts
    {
        if !submission_matches_settlement(&submission, proposal)
            || submission.raw_transaction != raw_transaction
            || submission.transaction_hash != transaction_hash
            || i64::try_from(transaction_nonce(&submission.raw_transaction)?)? != nonce
            || transaction_signer(&submission.raw_transaction)? != signer_address
        {
            anyhow::bail!("settlement attempt no longer matches verified evidence");
        }
        if status == "confirmed" {
            return Ok(Some(SelectedSubmission {
                submission,
                chain_confirmed: true,
            }));
        }
        if status == "reverted" {
            continue;
        }
        let finality = heartbeat
            .run(chain.finality(&submission.transaction_hash, confirmations))
            .await?;
        match observe_attempt(&status, &finality) {
            AttemptObservation::Adopt => {
                return Ok(Some(SelectedSubmission {
                    submission,
                    chain_confirmed: true,
                }));
            }
            AttemptObservation::Ignore => continue,
            AttemptObservation::MarkReverted => {
                let reverted = query(
                    "UPDATE settlement_transaction_attempts AS attempt \
                     SET status = 'reverted', reverted_at = COALESCE(reverted_at, NOW()) \
                     FROM settlement_jobs AS job, leases AS lease \
                     WHERE attempt.transaction_hash = $1 AND attempt.lease_id = job.lease_id \
                       AND job.lease_id = $2 AND job.claim_generation = $3 \
                       AND job.evidence = $4 AND lease.lease_id = job.lease_id \
                       AND lease.escrow_address = $5 AND lease.chain_lease_id = $6 \
                       AND attempt.nonce_reservation_state = 'reserved' \
                       AND attempt.generation_binding_state IN ('verified', 'normalized') \
                       AND attempt.status IN ('prepared', 'submitted', 'superseded')",
                )
                .bind(&submission.transaction_hash)
                .bind(i64::try_from(settlement.lease_id)?)
                .bind(settlement.claim_generation)
                .bind(SqlJson(settlement.evidence.clone()))
                .bind(&escrow.database_address)
                .bind(i64::try_from(settlement.chain_lease_id)?)
                .execute(&mut *connection)
                .await?;
                if reverted.rows_affected() != 1 {
                    anyhow::bail!("reverted settlement attempt lost its active claim");
                }
                anyhow::bail!(
                    "settlement proposal transaction reverted after the confirmation threshold"
                );
            }
            AttemptObservation::CheckTransaction => {
                let transaction: Option<serde_json::Value> = heartbeat
                    .run(chain.call(
                        "eth_getTransactionByHash",
                        serde_json::json!([submission.transaction_hash]),
                    ))
                    .await?;
                if known.is_none() {
                    if pending_attempt_is_reusable(
                        transaction.is_some(),
                        submission.proposal.deadline,
                        current_timestamp()?,
                    ) {
                        known = Some(SelectedSubmission {
                            submission,
                            chain_confirmed: false,
                        });
                    } else if transaction.is_some() {
                        tracing::warn!(
                            lease_id = settlement.lease_id,
                            transaction_hash = %submission.transaction_hash,
                            deadline = submission.proposal.deadline,
                            "settlement attempt is too close to expiry; preparing replacement"
                        );
                    }
                }
            }
        }
    }
    Ok(known)
}

async fn persist_existing_submission(
    connection: &mut PgConnection,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
) -> anyhow::Result<()> {
    let stored = query(
        "UPDATE settlement_jobs AS job \
         SET proposal = $2, raw_transaction = $3, transaction_hash = $4, \
             transaction_nonce = $5, updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $6 AND lease.chain_lease_id = $7 \
           AND job.claim_generation = $8 AND job.evidence = $9 \
           AND EXISTS ( \
               SELECT 1 FROM settlement_transaction_attempts AS attempt \
               WHERE attempt.transaction_hash = $4 AND attempt.lease_id = job.lease_id \
                 AND attempt.escrow_address = $6 AND attempt.chain_lease_id = $7 \
                 AND attempt.raw_transaction = $3 AND attempt.transaction_nonce = $5 \
                 AND attempt.proposal = $2 \
                 AND attempt.nonce_reservation_state = 'reserved' \
                 AND attempt.generation_binding_state IN ('verified', 'normalized') \
           )",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(SqlJson(submission.clone()))
    .bind(&submission.raw_transaction)
    .bind(&submission.transaction_hash)
    .bind(i64::try_from(transaction_nonce(
        &submission.raw_transaction,
    )?)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .execute(connection)
    .await?;
    if stored.rows_affected() != 1 {
        anyhow::bail!("settlement attempt lost its active claim");
    }
    Ok(())
}

async fn persist_new_submission(
    connection: &mut PgConnection,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
    signer_address: &str,
) -> anyhow::Result<()> {
    let nonce = i64::try_from(transaction_nonce(&submission.raw_transaction)?)?;
    let stored: Option<i64> = query_scalar(
        "WITH eligible AS ( \
             SELECT job.lease_id FROM settlement_jobs AS job \
             JOIN leases AS lease ON lease.lease_id = job.lease_id \
             WHERE job.lease_id = $1 AND lease.escrow_address = $2 \
               AND lease.chain_lease_id = $3 AND job.claim_generation = $4 \
               AND job.evidence = $9 \
             FOR UPDATE OF job, lease \
         ), reservation AS ( \
             INSERT INTO settlement_signer_nonce_reservations ( \
                 signer_address, transaction_nonce, lease_id \
             ) \
             SELECT $10, $6, eligible.lease_id FROM eligible \
             ON CONFLICT (signer_address, transaction_nonce) DO UPDATE \
             SET lease_id = settlement_signer_nonce_reservations.lease_id \
             WHERE settlement_signer_nonce_reservations.lease_id = EXCLUDED.lease_id \
             RETURNING lease_id \
         ), attempt AS ( \
             INSERT INTO settlement_transaction_attempts ( \
                 transaction_hash, lease_id, claim_generation, escrow_address, \
                 chain_lease_id, transaction_nonce, signer_address, raw_transaction, \
                 proposal, status, nonce_reservation_state, generation_binding_state \
             ) \
             SELECT $5, eligible.lease_id, $4, $2, $3, $6, $10, $7, $8, \
                    'prepared', 'reserved', 'verified' \
             FROM eligible, reservation \
             WHERE reservation.lease_id = eligible.lease_id \
             RETURNING transaction_hash \
         ), superseded AS ( \
             UPDATE settlement_transaction_attempts AS prior \
             SET status = 'superseded', superseded_at = COALESCE(superseded_at, NOW()) \
             WHERE prior.lease_id = $1 AND prior.escrow_address = $2 \
               AND prior.chain_lease_id = $3 AND prior.transaction_hash <> $5 \
               AND prior.status IN ('prepared', 'submitted') \
               AND prior.generation_binding_state IN ('verified', 'normalized') \
               AND EXISTS (SELECT 1 FROM attempt) \
         ) \
         UPDATE settlement_jobs AS job \
         SET proposal = $8, raw_transaction = $7, transaction_hash = $5, \
             transaction_nonce = $6, updated_at = NOW() \
         FROM leases AS lease, attempt \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
           AND job.claim_generation = $4 AND job.evidence = $9 \
         RETURNING job.lease_id",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(&submission.transaction_hash)
    .bind(nonce)
    .bind(&submission.raw_transaction)
    .bind(SqlJson(submission.clone()))
    .bind(SqlJson(settlement.evidence.clone()))
    .bind(signer_address)
    .fetch_optional(connection)
    .await?;
    if stored.is_none() {
        anyhow::bail!("settlement preparation lost its active claim");
    }
    Ok(())
}

async fn record_submission_attempt(
    connection: &mut PgConnection,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
    broadcasting: bool,
) -> anyhow::Result<()> {
    let attempt = query(
        "UPDATE settlement_transaction_attempts AS attempt \
         SET status = CASE WHEN attempt.status IN ('confirmed', 'reverted', 'superseded') \
                           THEN attempt.status ELSE 'submitted' END, \
             submission_count = CASE \
                 WHEN attempt.status IN ('confirmed', 'reverted', 'superseded') \
                 THEN attempt.submission_count \
                 ELSE LEAST(100, CASE WHEN $9 \
                     THEN attempt.submission_count + 1 \
                     ELSE GREATEST(attempt.submission_count, 1) END) END, \
             submitted_at = CASE \
                 WHEN attempt.status IN ('confirmed', 'reverted', 'superseded') \
                 THEN attempt.submitted_at ELSE COALESCE(attempt.submitted_at, NOW()) END \
         FROM settlement_jobs AS job, leases AS lease \
         WHERE attempt.transaction_hash = $1 AND attempt.lease_id = $2 \
           AND attempt.escrow_address = $3 AND attempt.chain_lease_id = $4 \
           AND job.lease_id = attempt.lease_id AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $3 AND lease.chain_lease_id = $4 \
           AND job.claim_generation = $5 AND job.evidence = $6 \
           AND attempt.raw_transaction = $7 AND attempt.proposal = $8 \
           AND attempt.nonce_reservation_state = 'reserved' \
           AND attempt.generation_binding_state IN ('verified', 'normalized')",
    )
    .bind(&submission.transaction_hash)
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .bind(&submission.raw_transaction)
    .bind(SqlJson(submission.clone()))
    .bind(broadcasting)
    .execute(connection)
    .await?;
    if attempt.rows_affected() != 1 {
        anyhow::bail!("settlement attempt lost its active claim before submission");
    }
    Ok(())
}

async fn mark_settlement_submitted(
    connection: &mut PgConnection,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
) -> anyhow::Result<()> {
    let submitted = query(
        "UPDATE settlement_jobs AS job \
         SET status = 'submitted', lease_until = NULL, \
             available_at = NOW() + INTERVAL '5 seconds', updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
           AND job.claim_generation = $4 AND job.evidence = $5 \
           AND job.transaction_hash = $6 AND job.raw_transaction = $7 \
           AND job.proposal = $8",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .bind(&submission.transaction_hash)
    .bind(&submission.raw_transaction)
    .bind(SqlJson(submission.clone()))
    .execute(connection)
    .await?;
    if submitted.rows_affected() != 1 {
        anyhow::bail!("settlement submission lost its escrow-generation binding");
    }
    Ok(())
}

async fn submit_durable_submission(
    connection: &mut PgConnection,
    chain: &ChainClient,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
    chain_confirmed: bool,
    heartbeat: &ClaimHeartbeat<'_>,
) -> anyhow::Result<()> {
    if !chain_confirmed && !deadline_has_margin(submission.proposal.deadline, current_timestamp()?)
    {
        anyhow::bail!("settlement proposal deadline is too close for safe submission");
    }
    let broadcasting = if chain_confirmed {
        false
    } else {
        let known: Option<serde_json::Value> = heartbeat
            .run(chain.call(
                "eth_getTransactionByHash",
                serde_json::json!([submission.transaction_hash]),
            ))
            .await?;
        known.is_none()
    };

    // Preserve the exact bytes and the fact that a broadcast was attempted
    // before touching the RPC. A lost response can then only cause an exact
    // resubmission, never a second transaction signed for the same job.
    record_submission_attempt(connection, escrow, settlement, submission, broadcasting).await?;
    if broadcasting {
        let transaction_hash: String = heartbeat
            .run(chain.call(
                "eth_sendRawTransaction",
                serde_json::json!([submission.raw_transaction]),
            ))
            .await?;
        if !transaction_hash.eq_ignore_ascii_case(&submission.transaction_hash) {
            anyhow::bail!("RPC returned an unexpected transaction hash");
        }
    }
    mark_settlement_submitted(connection, escrow, settlement, submission).await
}

#[allow(clippy::too_many_arguments)]
async fn process_settlement(
    pool: &PgPool,
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: &EscrowGeneration,
    confirmations: u64,
    settlement: &ClaimedSettlement,
    shutdown: &ShutdownGate,
) -> anyhow::Result<()> {
    // Always ask. Taking the claimed submission directly used to bypass the
    // rebuild rules entirely, so a proposal that could no longer land was
    // resubmitted verbatim until the job ran out of attempts.
    let submission = prepare_durable_submission(
        pool,
        chain,
        signer,
        escrow,
        confirmations,
        settlement,
        shutdown,
    )
    .await?;
    if shutdown.requested() {
        return Err(ShutdownRequested.into());
    }
    let (block_number, block_hash, block_time) = match chain
        .finality(&submission.transaction_hash, confirmations)
        .await?
    {
        SettlementFinality::Pending => {
            refund_pending_settlement_attempt(pool, escrow, settlement, &submission).await?;
            return Ok(());
        }
        SettlementFinality::Reverted => {
            let reverted = query(
                "UPDATE settlement_transaction_attempts AS attempt \
                 SET status = 'reverted', reverted_at = COALESCE(reverted_at, NOW()) \
                 FROM settlement_jobs AS job, leases AS lease \
                 WHERE attempt.transaction_hash = $1 AND attempt.lease_id = job.lease_id \
                   AND job.lease_id = $2 AND job.claim_generation = $3 \
                   AND lease.lease_id = job.lease_id AND lease.escrow_address = $4 \
                   AND lease.chain_lease_id = $5 \
                   AND attempt.nonce_reservation_state = 'reserved' \
                   AND attempt.generation_binding_state IN ('verified', 'normalized')",
            )
            .bind(&submission.transaction_hash)
            .bind(i64::try_from(settlement.lease_id)?)
            .bind(settlement.claim_generation)
            .bind(&escrow.database_address)
            .bind(i64::try_from(settlement.chain_lease_id)?)
            .execute(pool)
            .await?;
            if reverted.rows_affected() != 1 {
                anyhow::bail!("reverted settlement attempt lost its active claim");
            }
            anyhow::bail!("settlement proposal transaction reverted");
        }
        SettlementFinality::Confirmed {
            block_number,
            block_hash,
            block_time,
        } => (block_number, block_hash, block_time),
    };
    if shutdown.requested() {
        return Err(ShutdownRequested.into());
    }
    let dispute_window = chain.dispute_window(escrow.chain_address).await?;
    let finalize_timestamp = i64::try_from(block_time)?
        .checked_add(i64::try_from(dispute_window)?)
        .context("settlement finalization time is invalid")?;
    let finalize_at = DateTime::from_timestamp(finalize_timestamp, 0)
        .context("settlement finalization time is invalid")?;
    let mut transaction = pool.begin().await?;
    let proposed = query(
        "UPDATE settlement_jobs AS job \
         SET status = 'proposed', lease_until = NULL, \
             confirmed_block = $2, confirmed_block_hash = $3, last_error = NULL, \
             updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $4 AND lease.chain_lease_id = $5 \
           AND job.claim_generation = $6 AND job.evidence = $7",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(i64::try_from(block_number)?)
    .bind(block_hash.to_ascii_lowercase())
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .execute(&mut *transaction)
    .await?;
    if proposed.rows_affected() != 1 {
        anyhow::bail!("settlement confirmation lost its escrow-generation binding");
    }
    let confirmed = query(
        "UPDATE settlement_transaction_attempts AS attempt \
         SET status = 'confirmed', confirmed_at = COALESCE(confirmed_at, NOW()), \
             confirmed_block = $2, confirmed_block_hash = $3 \
         FROM settlement_jobs AS job \
         WHERE attempt.transaction_hash = $1 AND attempt.lease_id = job.lease_id \
           AND job.lease_id = $4 AND job.claim_generation = $5 \
           AND attempt.nonce_reservation_state = 'reserved' \
           AND attempt.generation_binding_state IN ('verified', 'normalized')",
    )
    .bind(&submission.transaction_hash)
    .bind(i64::try_from(block_number)?)
    .bind(block_hash.to_ascii_lowercase())
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(settlement.claim_generation)
    .execute(&mut *transaction)
    .await?;
    if confirmed.rows_affected() != 1 {
        anyhow::bail!("confirmed settlement attempt lost its active claim");
    }
    query(
        "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
         SELECT $1, lease.lease_id, 'finalize', $3 \
         FROM leases AS lease \
         WHERE lease.lease_id = $2 AND lease.escrow_address = $4 \
           AND lease.chain_lease_id = $5 \
         ON CONFLICT (lease_id, kind) DO NOTHING",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(finalize_at)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    tracing::info!(
        lease_id = settlement.lease_id,
        transaction_hash = %submission.transaction_hash,
        "settlement proposal reached finality"
    );
    Ok(())
}

async fn prepare_durable_submission(
    pool: &PgPool,
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: &EscrowGeneration,
    confirmations: u64,
    settlement: &ClaimedSettlement,
    shutdown: &ShutdownGate,
) -> anyhow::Result<Submission> {
    let mut connection = pool.acquire().await?;
    let heartbeat = ClaimHeartbeat::Durable {
        pool,
        escrow,
        settlement,
        shutdown,
    };
    loop {
        heartbeat.renew().await?;
        let acquired: bool = query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(SIGNER_LOCK)
            .fetch_one(&mut *connection)
            .await?;
        if acquired {
            break;
        }
        tokio::select! {
            biased;
            () = shutdown.wait() => return Err(ShutdownRequested.into()),
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
        }
    }
    let result = async {
        heartbeat.renew().await?;
        let binding = query_as::<_, (i64, SqlJson<SettlementEvidence>)>(
            "SELECT lease.chain_lease_id, job.evidence \
             FROM settlement_jobs AS job \
             JOIN leases AS lease ON lease.lease_id = job.lease_id \
             WHERE job.lease_id = $1 AND lease.escrow_address = $2 \
               AND lease.chain_lease_id = $3 AND job.claim_generation = $4",
        )
        .bind(i64::try_from(settlement.lease_id)?)
        .bind(&escrow.database_address)
        .bind(i64::try_from(settlement.chain_lease_id)?)
        .bind(settlement.claim_generation)
        .fetch_optional(&mut *connection)
        .await?;
        validate_stored_binding(settlement, binding)?;
        let gateway = heartbeat.run(chain.gateway(escrow.chain_address)).await?;
        let managed_binding =
            load_managed_repro_binding(&mut connection, escrow, settlement).await?;
        let mut proposal = reconcile_with_managed_binding(
            &settlement.evidence,
            Some(gateway),
            managed_binding.as_ref(),
        )?;
        enrich_receipt_identity(&mut proposal, escrow)?;
        if let Some(selected) = reconcile_transaction_attempts(
            &mut connection,
            chain,
            escrow,
            settlement,
            &proposal,
            confirmations,
            &heartbeat,
        )
        .await?
        {
            persist_existing_submission(&mut connection, escrow, settlement, &selected.submission)
                .await?;
            return Ok(selected);
        }
        // Reusing the stored submission is what makes settlement idempotent, but
        // those bytes carry the gas price they were signed at. If the chain has
        // rejected them repeatedly they can never land, and resubmitting until
        // the attempt limit strands the lease and holds its node the whole time.
        // Past a few failures the proposal is rebuilt at the current price.
        // The signature also carries a deadline. Once that passes the escrow
        // rejects the proposal with Expired() no matter how often it is sent,
        // so a stale one is rebuilt rather than retried.
        if let Some(SqlJson(existing)) = query_scalar::<_, SqlJson<Submission>>(
            "SELECT job.proposal FROM settlement_jobs AS job \
             JOIN leases AS lease ON lease.lease_id = job.lease_id \
             WHERE job.lease_id = $1 AND job.proposal IS NOT NULL \
               AND job.attempts < $2 AND lease.escrow_address = $3 \
               AND lease.chain_lease_id = $4 AND job.claim_generation = $5 \
               AND EXISTS ( \
                   SELECT 1 FROM settlement_transaction_attempts AS attempt \
                   WHERE attempt.transaction_hash = job.transaction_hash \
                     AND attempt.status NOT IN ('reverted', 'superseded') \
                     AND attempt.nonce_reservation_state = 'reserved' \
                     AND attempt.generation_binding_state IN ('verified', 'normalized') \
               )",
        )
        .bind(i64::try_from(settlement.lease_id)?)
        .bind(RESIGN_AFTER_ATTEMPTS)
        .bind(&escrow.database_address)
        .bind(i64::try_from(settlement.chain_lease_id)?)
        .bind(settlement.claim_generation)
        .fetch_optional(&mut *connection)
        .await?
            && deadline_has_margin(existing.proposal.deadline, current_timestamp()?)
        {
            if existing.proposal.lease_id != settlement.lease_id
                || existing.proposal.chain_lease_id != settlement.chain_lease_id
                || existing.proposal.receipt_hash != proposal.receipt_hash
            {
                anyhow::bail!("stored settlement proposal no longer matches verified evidence");
            }
            persist_existing_submission(&mut connection, escrow, settlement, &existing).await?;
            return Ok(SelectedSubmission {
                submission: existing,
                chain_confirmed: false,
            });
        }
        let signer_address = format!("0x{}", hex::encode(signer.address()));
        let nonce = next_signer_nonce(
            &mut connection,
            chain,
            &signer_address,
            settlement,
            &heartbeat,
        )
        .await?;
        let submission = prepare_submission(
            chain,
            signer,
            escrow.chain_address,
            proposal,
            nonce,
            &heartbeat,
        )
        .await?;
        persist_new_submission(
            &mut connection,
            escrow,
            settlement,
            &submission,
            &signer_address,
        )
        .await?;
        Ok::<_, anyhow::Error>(SelectedSubmission {
            submission,
            chain_confirmed: false,
        })
    }
    .await;
    let result = match result {
        Ok(selected) => submit_durable_submission(
            &mut connection,
            chain,
            escrow,
            settlement,
            &selected.submission,
            selected.chain_confirmed,
            &heartbeat,
        )
        .await
        .map(|()| selected.submission),
        Err(error) => Err(error),
    };
    query("SELECT pg_advisory_unlock($1)")
        .bind(SIGNER_LOCK)
        .execute(&mut *connection)
        .await?;
    result
}

async fn refund_pending_settlement_attempt(
    pool: &PgPool,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    submission: &Submission,
) -> anyhow::Result<()> {
    let refunded = query(
        "UPDATE settlement_jobs AS job \
         SET attempts = GREATEST(0, attempts - 1), updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
           AND job.claim_generation = $4 AND job.evidence = $5 \
           AND job.status = 'submitted' AND job.transaction_hash = $6 \
           AND EXISTS ( \
               SELECT 1 FROM settlement_transaction_attempts AS attempt \
               WHERE attempt.transaction_hash = $6 AND attempt.lease_id = job.lease_id \
                 AND attempt.escrow_address = $2 AND attempt.chain_lease_id = $3 \
                 AND attempt.raw_transaction = $7 AND attempt.proposal = $8 \
                 AND attempt.status = 'submitted' \
                 AND attempt.nonce_reservation_state = 'reserved' \
                 AND attempt.generation_binding_state IN ('verified', 'normalized') \
           )",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .bind(&submission.transaction_hash)
    .bind(&submission.raw_transaction)
    .bind(SqlJson(submission.clone()))
    .execute(pool)
    .await?;
    if refunded.rows_affected() != 1 {
        tracing::warn!(
            lease_id = settlement.lease_id,
            claim_generation = settlement.claim_generation,
            "pending settlement poll was not refunded after claim ownership changed"
        );
    }
    Ok(())
}

async fn retry_settlement(
    pool: &PgPool,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    let message: String = format!("{error:#}").chars().take(1_024).collect();
    let retried = query(
        "UPDATE settlement_jobs AS job SET \
             status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END, \
             lease_until = NULL, \
             available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)), \
             last_error = $2, updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $3 AND lease.chain_lease_id = $4 \
           AND job.claim_generation = $5 AND job.evidence = $6",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(message)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .execute(pool)
    .await?;
    if retried.rows_affected() != 1 {
        tracing::warn!(
            lease_id = settlement.lease_id,
            claim_generation = settlement.claim_generation,
            "settlement retry ignored after claim ownership changed"
        );
    }
    Ok(())
}

async fn release_settlement_claim(
    pool: &PgPool,
    escrow: &EscrowGeneration,
    settlement: &ClaimedSettlement,
) -> anyhow::Result<()> {
    let released = query(
        "UPDATE settlement_jobs AS job \
         SET status = CASE WHEN transaction_hash IS NULL THEN 'queued' ELSE 'submitted' END, \
             attempts = GREATEST(0, attempts - 1), lease_until = NULL, \
             available_at = NOW(), updated_at = NOW() \
         FROM leases AS lease \
         WHERE job.lease_id = $1 AND lease.lease_id = job.lease_id \
           AND lease.escrow_address = $2 AND lease.chain_lease_id = $3 \
           AND job.claim_generation = $4 AND job.evidence = $5 \
           AND job.status = 'processing'",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(&escrow.database_address)
    .bind(i64::try_from(settlement.chain_lease_id)?)
    .bind(settlement.claim_generation)
    .bind(SqlJson(settlement.evidence.clone()))
    .execute(pool)
    .await?;
    if released.rows_affected() == 1 {
        tracing::info!(
            lease_id = settlement.lease_id,
            claim_generation = settlement.claim_generation,
            "settlement claim returned for another worker"
        );
    }
    Ok(())
}

fn transaction_nonce(raw: &str) -> anyhow::Result<u64> {
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?;
    rlp::Rlp::new(&bytes)
        .at(0)?
        .as_val()
        .context("settlement transaction nonce is invalid")
}

struct DecodedLegacyTransaction {
    nonce: u64,
    chain_id: u64,
    destination: [u8; 20],
    data: Vec<u8>,
    signer_address: String,
}

fn decode_legacy_transaction(raw: &str) -> anyhow::Result<DecodedLegacyTransaction> {
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?;
    let transaction = rlp::Rlp::new(&bytes);
    if !transaction.is_list() || transaction.item_count()? != 9 {
        anyhow::bail!("settlement transaction is not a legacy signed transaction");
    }
    let nonce: u64 = transaction.at(0)?.as_val()?;
    let gas_price: u64 = transaction.at(1)?.as_val()?;
    let gas_limit: u64 = transaction.at(2)?.as_val()?;
    let to = transaction.at(3)?.data()?;
    if to.len() != 20 {
        anyhow::bail!("settlement transaction destination is invalid");
    }
    let mut destination = [0_u8; 20];
    destination.copy_from_slice(to);
    let value: u64 = transaction.at(4)?.as_val()?;
    if value != 0 {
        anyhow::bail!("settlement transaction unexpectedly transfers value");
    }
    let data = transaction.at(5)?.data()?;
    let v: u64 = transaction.at(6)?.as_val()?;
    let eip155 = v
        .checked_sub(35)
        .context("settlement transaction has no EIP-155 replay protection")?;
    let chain_id = eip155 / 2;
    let recovery_id = RecoveryId::from_byte((eip155 % 2) as u8)
        .context("settlement transaction recovery id is invalid")?;
    let signature = EthereumSignature::from_scalars(
        padded_scalar(transaction.at(7)?.data()?)?,
        padded_scalar(transaction.at(8)?.data()?)?,
    )?;
    let unsigned =
        legacy_unsigned_transaction(nonce, gas_price, gas_limit, destination, data, chain_id);
    let digest: [u8; 32] = Keccak256::digest(unsigned).into();
    let signer = EthereumVerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)?;
    let point = signer.to_encoded_point(false);
    Ok(DecodedLegacyTransaction {
        nonce,
        chain_id,
        destination,
        data: data.to_vec(),
        signer_address: format!(
            "0x{}",
            hex::encode(&Keccak256::digest(&point.as_bytes()[1..])[12..])
        ),
    })
}

fn transaction_signer(raw: &str) -> anyhow::Result<String> {
    let transaction = decode_legacy_transaction(raw)?;
    if transaction.chain_id != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("settlement transaction is signed for another chain");
    }
    Ok(transaction.signer_address)
}

fn padded_scalar(value: &[u8]) -> anyhow::Result<[u8; 32]> {
    if value.is_empty() || value.len() > 32 {
        anyhow::bail!("settlement transaction signature scalar is invalid");
    }
    let mut padded = [0_u8; 32];
    padded[32 - value.len()..].copy_from_slice(value);
    Ok(padded)
}

/// How far short of its paid window a lease has to end before the ending is
/// treated as something going wrong rather than a lease closing on time.
const EARLY_CLOSE_GRACE_SECONDS: u64 = 5;

/// How stale the last sighting of a machine has to be, at the moment its lease
/// closed, before the machine counts as having gone away. Below the window that
/// triggers the close in the first place, and well above a normal poll gap, so
/// a lease that finished between two polls is not mistaken for a fault.
const STALE_OBSERVATION_SECONDS: u64 = 60;

#[cfg(test)]
fn reconcile(evidence: &SettlementEvidence) -> anyhow::Result<SettlementProposal> {
    reconcile_with_gateway(evidence, None)
}

fn reconcile_with_gateway(
    evidence: &SettlementEvidence,
    managed_gateway: Option<[u8; 20]>,
) -> anyhow::Result<SettlementProposal> {
    reconcile_with_managed_binding(evidence, managed_gateway, None)
}

fn reconcile_with_managed_binding(
    evidence: &SettlementEvidence,
    managed_gateway: Option<[u8; 20]>,
    managed_binding: Option<&ManagedReproBinding>,
) -> anyhow::Result<SettlementProposal> {
    if evidence.lease_id == 0
        || evidence.chain_lease_id == 0
        || evidence.lease_nonce == 0
        || evidence.rate_per_second == 0
        || evidence.deposit_base_units == 0
        || evidence.deposit_base_units > MAX_ESCROW_BASE_UNITS
        || evidence.duration_seconds == 0
        || u64::from(evidence.duration_seconds) > MAX_LEASE_SECONDS
        || evidence.gpu_model.trim().is_empty()
        || evidence.gpu_model.len() > 128
        || !is_sha256_digest(&evidence.image_digest)
    {
        anyhow::bail!("lease {} has invalid settlement terms", evidence.lease_id);
    }
    let expected_deposit = evidence
        .rate_per_second
        .checked_mul(u64::from(evidence.duration_seconds))
        .context("lease deposit overflow")?;
    if expected_deposit != evidence.deposit_base_units {
        anyhow::bail!(
            "lease {} deposit does not match its rate",
            evidence.lease_id
        );
    }
    let start = evidence
        .access_started_at
        .max(evidence.cuda_ready_at)
        .max(evidence.interactive_access_ready_at);
    // The paid window runs from the moment the chain started the lease, which
    // is what the renter is charged against, not from the later moment the
    // machine finished coming up.
    let scheduled_end = evidence
        .access_started_at
        .saturating_add(u64::from(evidence.duration_seconds));
    let closed_at = evidence
        .access_ended_at
        .min(evidence.gateway_closed_at)
        .min(scheduled_end);
    if start < evidence.access_started_at
        || closed_at > evidence.access_ended_at
        || closed_at < start
        || evidence.access_ended_at <= evidence.access_started_at
    {
        anyhow::bail!("lease {} has an invalid metering window", evidence.lease_id);
    }
    // Two things have to be true before a lease counts as cut short, and
    // neither alone is enough. It has to have ended before the time it was paid
    // for, and the machine has to have already stopped answering when it ended.
    // Timing alone would blame the provider when a renter closed their own
    // access early. A stale reading alone would blame a lease that simply
    // finished between polls. Only the pair means the machine went away.
    let ended_early = closed_at.saturating_add(EARLY_CLOSE_GRACE_SECONDS) < scheduled_end;
    let interrupted = ended_early
        && evidence.last_observed_at.is_some_and(|observed| {
            closed_at.saturating_sub(observed) >= STALE_OBSERVATION_SECONDS
        });
    // Closing a lease means noticing it should be closed, and noticing takes a
    // staleness window. Meter to the last moment the machine was known to be
    // there so the renter never pays for the interval in which it was already
    // gone and we had not caught up.
    let end = match evidence.last_observed_at {
        Some(observed) if interrupted => closed_at.min(observed.max(start)),
        _ => closed_at,
    };
    let credited_seconds = interrupted.then(|| closed_at.saturating_sub(end));
    validate_execution_evidence(evidence, start, end)?;
    validate_managed_execution_binding(evidence, managed_binding)?;
    let repro = validate_repro_evidence(evidence, managed_gateway, managed_binding)?;
    let trust_class = settled_trust_class(evidence)?;
    let maximum_by_deposit = evidence.deposit_base_units / evidence.rate_per_second;
    let usage_seconds = end
        .saturating_sub(start)
        .min(u64::from(evidence.duration_seconds))
        .min(maximum_by_deposit);
    let evidence_bytes = serde_json::to_vec(evidence)?;
    let evidence_digest = Sha256::digest(&evidence_bytes);
    let evidence_hash = format!("0x{}", hex::encode(evidence_digest));
    let mut receipt_id = [0_u8; 16];
    receipt_id.copy_from_slice(&evidence_digest[..16]);
    receipt_id[6] = (receipt_id[6] & 0x0f) | 0x80;
    receipt_id[8] = (receipt_id[8] & 0x3f) | 0x80;
    let charged_base_units = usage_seconds
        .checked_mul(evidence.rate_per_second)
        .context("settlement charge overflow")?;
    let mut receipt = PublicReceipt {
        receipt_id: uuid::Uuid::from_bytes(receipt_id),
        lease_id: evidence.chain_lease_id.to_string(),
        escrow_address: None,
        chain_lease_id: None,
        node_id_hash: format!(
            "0x{}",
            hex::encode(Sha256::digest(evidence.node_id.as_bytes()))
        ),
        gpu_model: evidence.gpu_model.clone(),
        runtime_seconds: usage_seconds,
        charged_base_units,
        refunded_base_units: evidence.deposit_base_units - charged_base_units,
        provider_paid_base_units: charged_base_units - charged_base_units * 1_000 / 10_000,
        // Named so a cut-short lease is legible as one on the public feed
        // instead of reading like a clean run that happened to be short.
        failure_class: interrupted.then(|| "interrupted".to_owned()),
        outcome: ReceiptOutcome::Finalized,
        trust_class,
        attestation: None,
        credited_seconds,
        repro,
        receipt_hash: String::new(),
        transaction_hash: String::new(),
    };
    receipt.receipt_hash = receipt_hash(&receipt)?;
    Ok(SettlementProposal {
        lease_id: evidence.lease_id,
        chain_lease_id: evidence.chain_lease_id,
        usage_seconds,
        receipt_hash: receipt.receipt_hash.clone(),
        nonce: evidence.lease_nonce,
        deadline: Utc::now().timestamp() as u64 + 3_600,
        evidence_hash,
        receipt,
    })
}

fn enrich_receipt_identity(
    proposal: &mut SettlementProposal,
    escrow: &EscrowGeneration,
) -> anyhow::Result<()> {
    let chain_lease_id = proposal.chain_lease_id.to_string();
    if proposal.receipt.lease_id != chain_lease_id {
        anyhow::bail!("settlement receipt chain lease does not match the proposal");
    }
    proposal.receipt.escrow_address = Some(escrow.database_address.clone());
    proposal.receipt.chain_lease_id = Some(chain_lease_id);
    validate_receipt_identity(&proposal.receipt)?;
    Ok(())
}

fn validate_managed_execution_binding(
    evidence: &SettlementEvidence,
    binding: Option<&ManagedReproBinding>,
) -> anyhow::Result<()> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let ExecutionEvidence::Vast {
        instance_id,
        hourly_cost_micros,
    } = &evidence.execution
    else {
        anyhow::bail!("managed repro is not backed by managed execution");
    };
    if *instance_id != binding.provider_instance_id
        || *hourly_cost_micros != binding.hourly_cost_micros
        || evidence.gpu_model != binding.gpu_model
    {
        anyhow::bail!("managed repro execution does not match its preflight binding");
    }
    match (
        binding.report.as_ref(),
        evidence.repro.as_ref().map(|repro| &repro.report),
    ) {
        (Some(stored), Some(ReproExecutionReport::Managed { report })) if stored == report => {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => anyhow::bail!("managed repro report does not match its stored execution binding"),
    }
}

/// Settlement is where a trust class stops being a row in a database and
/// becomes a signed artifact the chain commits to through `receiptHash`, so the
/// ceiling is enforced here instead of being taken on trust from whatever built
/// the evidence. A claim above it is refused rather than quietly downgraded: a
/// receipt settling a lease under a weaker class than the renter agreed to is a
/// worse artifact than no receipt at all, and the difference has to be visible.
fn settled_trust_class(evidence: &SettlementEvidence) -> anyhow::Result<Option<TrustClass>> {
    match evidence.trust_class {
        Some(class) if class > MAX_VERIFIABLE_TRUST_CLASS => anyhow::bail!(
            "lease {} claims trust class {} with no verified attestation",
            evidence.lease_id,
            class.label()
        ),
        class => Ok(class),
    }
}

fn validate_execution_evidence(
    evidence: &SettlementEvidence,
    start: u64,
    end: u64,
) -> anyhow::Result<()> {
    let key = verifying_key(&evidence.device_public_key)?;
    if node_id(&key) != evidence.node_id {
        anyhow::bail!("lease {} node identity does not match", evidence.lease_id);
    }
    if let ExecutionEvidence::Vast {
        instance_id,
        hourly_cost_micros,
    } = &evidence.execution
    {
        let retail_hourly = evidence
            .rate_per_second
            .checked_mul(3_600)
            .context("cloud retail rate overflow")?;
        if *instance_id == 0
            || *hourly_cost_micros == 0
            || *hourly_cost_micros >= retail_hourly
            || !evidence.node_telemetry.is_empty()
        {
            anyhow::bail!(
                "lease {} has invalid Vast execution evidence",
                evidence.lease_id
            );
        }
        return Ok(());
    }
    if evidence.node_telemetry.is_empty() || evidence.node_telemetry.len() > 10_000 {
        anyhow::bail!(
            "lease {} has no bounded telemetry evidence",
            evidence.lease_id
        );
    }
    let lease_id = evidence.lease_id.to_string();
    let mut previous_sequence = None;
    let mut first_active = None;
    let mut last_active = None;
    for telemetry in &evidence.node_telemetry {
        if telemetry.node_id != evidence.node_id
            || telemetry.verify(&key).is_err()
            || previous_sequence.is_some_and(|sequence| telemetry.sequence <= sequence)
        {
            anyhow::bail!(
                "lease {} contains invalid node telemetry",
                evidence.lease_id
            );
        }
        previous_sequence = Some(telemetry.sequence);
        if telemetry.active_lease.as_deref() == Some(&lease_id)
            && telemetry.image_digest.as_deref() == Some(&evidence.image_digest)
        {
            let observed_at = telemetry.observed_at.timestamp();
            first_active.get_or_insert(observed_at);
            last_active = Some(observed_at);
        }
    }
    let first_active = first_active.context("node never confirmed the active lease")?;
    let last_active = last_active.context("node never confirmed the active lease")?;
    let start = i64::try_from(start)?;
    let end = i64::try_from(end)?;
    if first_active > start + TELEMETRY_EDGE_TOLERANCE_SECONDS
        || last_active < end - TELEMETRY_EDGE_TOLERANCE_SECONDS
    {
        anyhow::bail!(
            "lease {} telemetry does not cover the billed window",
            evidence.lease_id
        );
    }
    Ok(())
}

fn validate_repro_evidence(
    evidence: &SettlementEvidence,
    managed_gateway: Option<[u8; 20]>,
    managed_binding: Option<&ManagedReproBinding>,
) -> anyhow::Result<Option<ReproReceiptEvidence>> {
    let Some(repro) = &evidence.repro else {
        return Ok(None);
    };
    if !is_lower_sha256(&repro.capability.token_hash)
        || !is_lower_sha256(&repro.capability.spec_hash)
        || repro.spec.command.trim().is_empty()
        || repro.spec.command.len() > 8 * 1024
        || repro.spec.min_vram_mib == 0
        || repro.spec.duration_seconds != evidence.duration_seconds
        || repro.spec.expected_exit_code != repro.capability.expected_exit_code
        || !(0..=255).contains(&repro.spec.expected_exit_code)
        || gpu_repro_spec_hash(&repro.spec)? != repro.capability.spec_hash
    {
        anyhow::bail!(
            "lease {} has an invalid repro capability or spec",
            evidence.lease_id
        );
    }

    let image_digest = repro
        .spec
        .image
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .filter(|digest| is_sha256_digest(digest) && is_lower_sha256(&digest[7..]))
        .context("repro image is not pinned to a sha256 digest")?;
    if image_digest != evidence.image_digest
        || repro.command.node_id != evidence.node_id
        || repro.command.lease_id != evidence.lease_id
        || repro.command.command_id.is_nil()
        || repro.command.expires_at <= repro.command.issued_at
    {
        anyhow::bail!(
            "lease {} repro command does not match its lease",
            evidence.lease_id
        );
    }
    let NodeCommandKind::Batch {
        image,
        command,
        duration_seconds,
    } = &repro.command.kind
    else {
        anyhow::bail!(
            "lease {} repro command is not a batch run",
            evidence.lease_id
        );
    };
    if image != &repro.spec.image
        || command != &repro.spec.command
        || *duration_seconds != repro.spec.duration_seconds
    {
        anyhow::bail!(
            "lease {} repro command does not match its spec",
            evidence.lease_id
        );
    }

    let (executor, result, report_hash) = match &repro.report {
        ReproExecutionReport::Node { report } => {
            let key = verifying_key(&evidence.device_public_key)?;
            if node_id(&key) != evidence.node_id
                || report.node_id != evidence.node_id
                || report.device_public_key != evidence.device_public_key
                || report.command_id != repro.command.command_id
                || report.request_id.is_nil()
                || report.observed_at < repro.command.issued_at
                || !terminal_report_shape(
                    &report.outcome,
                    report.error.as_deref(),
                    report.result.as_ref(),
                )
                || report.verify(&key).is_err()
            {
                anyhow::bail!(
                    "lease {} has an invalid final node repro report",
                    evidence.lease_id
                );
            }
            (
                ReproExecutor::Node,
                report.result.as_ref(),
                repro_report_hash(report)?,
            )
        }
        ReproExecutionReport::Managed { report } => {
            let gateway = managed_gateway.context("managed repro gateway was not resolved")?;
            let binding =
                managed_binding.context("managed repro database binding was not resolved")?;
            let ExecutionEvidence::Vast {
                instance_id,
                hourly_cost_micros,
            } = &evidence.execution
            else {
                anyhow::bail!(
                    "lease {} managed repro report is not backed by managed execution",
                    evidence.lease_id
                );
            };
            let started_at = u64::try_from(report.started_at.timestamp())
                .context("managed repro start precedes the Unix epoch")?;
            let finished_at = u64::try_from(report.finished_at.timestamp())
                .context("managed repro finish precedes the Unix epoch")?;
            if report.report_id.is_nil()
                || report.command_id != repro.command.command_id
                || report.lease_id != evidence.lease_id
                || report.provider != ManagedProvider::Vast
                || binding.report.as_ref() != Some(report)
                || binding.provider_instance_id != *instance_id
                || binding.hourly_cost_micros != *hourly_cost_micros
                || report.provider_instance_id != binding.provider_instance_id
                || binding.gpu_model != evidence.gpu_model
                || report.gpu_model != binding.gpu_model
                || report.gpu_vram_mib != binding.gpu_vram_mib
                || binding.gpu_vram_mib < repro.spec.min_vram_mib
                || report.gpu_vram_mib > 196_608
                || report.transport_host_key_sha256 != binding.transport_host_key_sha256
                || !is_lower_sha256(&report.transport_host_key_sha256)
                || report.started_at < repro.command.issued_at
                || started_at < evidence.access_started_at
                || finished_at < started_at
                || finished_at > evidence.access_ended_at
                || finished_at.saturating_sub(started_at) > u64::from(repro.spec.duration_seconds)
                || !terminal_report_shape(
                    &report.outcome,
                    report.error.as_deref(),
                    report.result.as_ref(),
                )
                || report.verify().is_err()
                || address(&report.signer)? != gateway
            {
                anyhow::bail!(
                    "lease {} has an invalid final managed repro report",
                    evidence.lease_id
                );
            }
            (
                ReproExecutor::Managed,
                report.result.as_ref(),
                managed_repro_report_hash(report)?,
            )
        }
    };
    if repro.capability.executor != executor {
        anyhow::bail!(
            "lease {} repro report does not match its approved executor",
            evidence.lease_id
        );
    }
    let Some(result) = result else {
        return Ok(None);
    };
    if !result.within_limits() || !(-255..=255).contains(&result.exit_code) {
        anyhow::bail!("lease {} repro output exceeds its limit", evidence.lease_id);
    }

    Ok(Some(ReproReceiptEvidence {
        executor,
        token_hash: repro.capability.token_hash.clone(),
        spec_hash: repro.capability.spec_hash.clone(),
        image_digest: evidence.image_digest.clone(),
        command_hash: repro_command_hash(&repro.command)?,
        result_hash: repro_result_hash(result)?,
        stdout_hash: repro_stream_hash(&result.stdout),
        stderr_hash: repro_stream_hash(&result.stderr),
        report_hash,
        exit_code: result.exit_code,
        expected_exit_code: repro.capability.expected_exit_code,
        succeeded: result.exit_code == repro.capability.expected_exit_code,
        truncated: result.truncated,
    }))
}

fn terminal_report_shape(
    outcome: &NodeCommandOutcome,
    error: Option<&str>,
    result: Option<&CommandResult>,
) -> bool {
    match outcome {
        NodeCommandOutcome::Completed => error.is_none() && result.is_some(),
        NodeCommandOutcome::Failed => {
            error.is_some_and(|message| !message.is_empty() && message.len() <= 512)
                && result.is_none()
        }
        NodeCommandOutcome::Ready => false,
    }
}

async fn next_signer_nonce(
    connection: &mut PgConnection,
    chain: &ChainClient,
    signer_address: &str,
    settlement: &ClaimedSettlement,
    heartbeat: &ClaimHeartbeat<'_>,
) -> anyhow::Result<u64> {
    let own_nonce: Option<i64> = query_scalar(
        "SELECT job.transaction_nonce \
         FROM settlement_jobs AS job \
         JOIN settlement_transaction_attempts AS attempt \
           ON attempt.transaction_hash = job.transaction_hash \
         WHERE job.lease_id = $1 AND job.transaction_nonce IS NOT NULL \
           AND attempt.signer_address = $2 \
           AND attempt.status IN ('prepared', 'submitted', 'superseded') \
           AND attempt.nonce_reservation_state = 'reserved' \
           AND attempt.generation_binding_state IN ('verified', 'normalized') \
           AND EXISTS ( \
               SELECT 1 FROM settlement_signer_nonce_reservations AS reservation \
               WHERE reservation.signer_address = attempt.signer_address \
                 AND reservation.transaction_nonce = attempt.transaction_nonce \
                 AND reservation.lease_id = attempt.lease_id \
           )",
    )
    .bind(i64::try_from(settlement.lease_id)?)
    .bind(signer_address)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(nonce) = own_nonce {
        return u64::try_from(nonce).context("reserved settlement nonce is invalid");
    }

    let chain_nonce = heartbeat
        .run(chain.quantity(
            "eth_getTransactionCount",
            serde_json::json!([signer_address, "pending"]),
        ))
        .await?;
    let highest_reserved: Option<i64> = query_scalar(
        "SELECT MAX(transaction_nonce) \
         FROM settlement_signer_nonce_reservations \
         WHERE signer_address = $1",
    )
    .bind(signer_address)
    .fetch_one(connection)
    .await?;
    let after_reservations = highest_reserved
        .map(u64::try_from)
        .transpose()?
        .map(|nonce| {
            nonce
                .checked_add(1)
                .context("settlement nonce space is exhausted")
        })
        .transpose()?
        .unwrap_or(0);
    Ok(chain_nonce.max(after_reservations))
}

async fn prepare_submission(
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: [u8; 20],
    proposal: SettlementProposal,
    nonce: u64,
    heartbeat: &ClaimHeartbeat<'_>,
) -> anyhow::Result<Submission> {
    let digest = settlement_digest(ROBINHOOD_CHAIN_ID, escrow, &proposal)?;
    let signature = heartbeat.run(signer.sign_digest(&digest)).await?;
    let calldata = proposal_calldata(&proposal, &signature)?;
    let from = format!("0x{}", hex::encode(signer.address()));
    let to = format!("0x{}", hex::encode(escrow));
    let gas_price = heartbeat.run(chain.suggested_gas_price()).await?;
    let gas_limit = heartbeat
        .run(chain.quantity(
            "eth_estimateGas",
            serde_json::json!([{
                "from": from,
                "to": to,
                "data": format!("0x{}", hex::encode(&calldata)),
                "value": "0x0"
            }, "latest"]),
        ))
        .await?;
    let unsigned = legacy_unsigned_transaction(
        nonce,
        gas_price,
        gas_limit,
        escrow,
        &calldata,
        ROBINHOOD_CHAIN_ID,
    );
    let transaction_digest: [u8; 32] = Keccak256::digest(&unsigned).into();
    let transaction_signature = heartbeat
        .run(signer.sign_digest(&transaction_digest))
        .await?;
    let raw = legacy_signed_transaction(
        nonce,
        gas_price,
        gas_limit,
        escrow,
        &calldata,
        ROBINHOOD_CHAIN_ID,
        &transaction_signature,
    );
    let transaction_hash = format!("0x{}", hex::encode(Keccak256::digest(&raw)));
    Ok(Submission {
        proposal,
        attestation_signature: format!("0x{}", hex::encode(signature)),
        raw_transaction: format!("0x{}", hex::encode(raw)),
        transaction_hash,
        submitted: false,
    })
}

fn settlement_digest(
    chain_id: u64,
    escrow: [u8; 20],
    proposal: &SettlementProposal,
) -> anyhow::Result<[u8; 32]> {
    let domain_typehash = Keccak256::digest(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let settlement_typehash =
        Keccak256::digest(b"Settlement(uint256 leaseId,uint64 usageSeconds,bytes32 receiptHash,uint256 nonce,uint256 deadline)");
    let mut domain = Vec::with_capacity(32 * 5);
    domain.extend_from_slice(&domain_typehash);
    domain.extend_from_slice(&Keccak256::digest(b"Prism Network"));
    domain.extend_from_slice(&Keccak256::digest(b"1"));
    domain.extend_from_slice(&word_u128(u128::from(chain_id)));
    domain.extend_from_slice(&word_address(escrow));
    let domain_separator = Keccak256::digest(domain);

    let receipt_hash = bytes32(&proposal.receipt_hash)?;
    let mut settlement = Vec::with_capacity(32 * 6);
    settlement.extend_from_slice(&settlement_typehash);
    settlement.extend_from_slice(&word_u128(u128::from(proposal.chain_lease_id)));
    settlement.extend_from_slice(&word_u128(u128::from(proposal.usage_seconds)));
    settlement.extend_from_slice(&receipt_hash);
    settlement.extend_from_slice(&word_u128(proposal.nonce));
    settlement.extend_from_slice(&word_u128(u128::from(proposal.deadline)));
    let struct_hash = Keccak256::digest(settlement);
    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(b"\x19\x01");
    payload.extend_from_slice(&domain_separator);
    payload.extend_from_slice(&struct_hash);
    Ok(Keccak256::digest(payload).into())
}

fn proposal_calldata(
    proposal: &SettlementProposal,
    signature: &[u8; 65],
) -> anyhow::Result<Vec<u8>> {
    let selector = Keccak256::digest(b"proposeSettlement(uint256,uint64,bytes32,uint256,bytes)");
    let mut calldata = Vec::with_capacity(4 + 32 * 9);
    calldata.extend_from_slice(&selector[..4]);
    calldata.extend_from_slice(&word_u128(u128::from(proposal.chain_lease_id)));
    calldata.extend_from_slice(&word_u128(u128::from(proposal.usage_seconds)));
    calldata.extend_from_slice(&bytes32(&proposal.receipt_hash)?);
    calldata.extend_from_slice(&word_u128(u128::from(proposal.deadline)));
    calldata.extend_from_slice(&word_u128(160));
    calldata.extend_from_slice(&word_u128(signature.len() as u128));
    calldata.extend_from_slice(signature);
    calldata.resize(4 + 32 * 9, 0);
    Ok(calldata)
}

fn legacy_unsigned_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&chain_id);
    stream.append(&0_u8);
    stream.append(&0_u8);
    stream.out().to_vec()
}

fn legacy_signed_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
    signature: &[u8; 65],
) -> Vec<u8> {
    let v = chain_id * 2 + 35 + u64::from(signature[64] - 27);
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&v);
    stream.append(&trim_integer(&signature[..32]));
    stream.append(&trim_integer(&signature[32..64]));
    stream.out().to_vec()
}

fn trim_integer(value: &[u8]) -> &[u8] {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first..]
}

impl ChainClient {
    fn new(rpc_url: url::Url) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            rpc_url,
        })
    }

    async fn quantity(
        &self,
        method: &'static str,
        parameters: serde_json::Value,
    ) -> anyhow::Result<u64> {
        let value: String = self.call(method, parameters).await?;
        u64::from_str_radix(
            value
                .strip_prefix("0x")
                .context("RPC quantity is not hex")?,
            16,
        )
        .context("RPC quantity exceeds uint64")
    }

    /// `eth_gasPrice` here answers with the current base fee rather than the
    /// next block's, so a transaction priced at exactly what it suggests is
    /// rejected the moment the base fee ticks up. Double it, as the shared
    /// chain client does. Lease 39 sat unsettled for nineteen hours because
    /// this path did not.
    async fn suggested_gas_price(&self) -> anyhow::Result<u64> {
        Ok(self
            .quantity("eth_gasPrice", serde_json::json!([]))
            .await?
            .saturating_mul(2))
    }

    async fn gateway(&self, escrow: [u8; 20]) -> anyhow::Result<[u8; 20]> {
        let selector = Keccak256::digest(b"gateway()");
        let value: String = self
            .call(
                "eth_call",
                serde_json::json!([
                    {
                        "to": format!("0x{}", hex::encode(escrow)),
                        "data": format!("0x{}", hex::encode(&selector[..4])),
                    },
                    "latest"
                ]),
            )
            .await?;
        decode_abi_address(&value).context("escrow gateway response is invalid")
    }

    /// The escrow decides how long a proposal can be disputed. Reading it beats
    /// assuming: the value is a constant in a non-upgradeable contract, so a
    /// hardcoded guess is wrong for every deployment that does not share it.
    async fn dispute_window(&self, escrow: [u8; 20]) -> anyhow::Result<u64> {
        let selector = Keccak256::digest(b"DISPUTE_WINDOW()");
        let value: String = self
            .call(
                "eth_call",
                serde_json::json!([
                    {
                        "to": format!("0x{}", hex::encode(escrow)),
                        "data": format!("0x{}", hex::encode(&selector[..4])),
                    },
                    "latest"
                ]),
            )
            .await?;
        let raw = value
            .strip_prefix("0x")
            .context("dispute window is not hex")?;
        let window = u64::from_str_radix(raw.trim_start_matches('0'), 16)
            .context("dispute window exceeds uint64")?;
        if window == 0 || window > 30 * 86_400 {
            anyhow::bail!("escrow reported an implausible dispute window of {window}s");
        }
        Ok(window)
    }

    async fn finality(
        &self,
        transaction_hash: &str,
        confirmations: u64,
    ) -> anyhow::Result<SettlementFinality> {
        let receipt: Option<TransactionReceipt> = self
            .call(
                "eth_getTransactionReceipt",
                serde_json::json!([transaction_hash]),
            )
            .await?;
        let Some(receipt) = receipt else {
            return Ok(SettlementFinality::Pending);
        };
        let block_number = parse_quantity(&receipt.block_number)?;
        let current = self
            .quantity("eth_blockNumber", serde_json::json!([]))
            .await?;
        if current < block_number.saturating_add(confirmations) {
            return Ok(SettlementFinality::Pending);
        }
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([receipt.block_number, false]),
            )
            .await?;
        let Some(block) = block else {
            return Ok(SettlementFinality::Pending);
        };
        if !block.hash.eq_ignore_ascii_case(&receipt.block_hash) {
            return Ok(SettlementFinality::Pending);
        }
        if parse_quantity(&receipt.status)? != 1 {
            return Ok(SettlementFinality::Reverted);
        }
        Ok(SettlementFinality::Confirmed {
            block_number,
            block_hash: receipt.block_hash,
            block_time: parse_quantity(&block.timestamp)?,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        parameters: serde_json::Value,
    ) -> anyhow::Result<T> {
        let response = self
            .client
            .post(self.rpc_url.clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": parameters,
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<RpcResponse>()
            .await?;
        if let Some(error) = response.error {
            anyhow::bail!("RPC {method} failed with {}: {}", error.code, error.message);
        }
        serde_json::from_value(response.result).context("RPC response contains an invalid result")
    }
}

fn parse_quantity(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(
        value
            .strip_prefix("0x")
            .context("RPC quantity is not hex")?,
        16,
    )
    .context("RPC quantity exceeds uint64")
}

fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_address(value: [u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&value);
    word
}

fn address(value: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .context("address must start with 0x")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("address must contain 20 bytes"))
}

fn decode_abi_address(value: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .context("ABI address must start with 0x")?,
    )?;
    if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
        anyhow::bail!("ABI address must be one zero-padded word");
    }
    let address: [u8; 20] = bytes[12..]
        .try_into()
        .expect("validated ABI address is 20 bytes");
    if address == [0_u8; 20] {
        anyhow::bail!("ABI address must not be zero");
    }
    Ok(address)
}

fn bytes32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash must contain 32 bytes"))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn secure_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if url.scheme() != "https" && !local_http {
        anyhow::bail!("RPC URL must use HTTPS outside localhost");
    }
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("RPC URL must not contain credentials");
    }
    Ok(url)
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("{key} is required"))
}

fn read_bounded(path: &Path, maximum: u64) -> anyhow::Result<Vec<u8>> {
    if fs::metadata(path)?.len() > maximum {
        anyhow::bail!("settlement input exceeds the size limit");
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > maximum {
        anyhow::bail!("settlement input exceeds the size limit");
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .context("write settlement outbox")
        .and_then(|()| fs::rename(&temporary, path).context("persist settlement outbox"));
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey as DeviceSigningKey;
    use k256::ecdsa::{
        RecoveryId, Signature, SigningKey as ManagedSigningKey, VerifyingKey,
        signature::hazmat::PrehashSigner,
    };
    use prism_protocol::{
        CommandResult, GpuReproSpec, ManagedCommandReport, ManagedCommandReportPayload,
        ManagedProvider, NodeCommand, NodeCommandReport, NodeCommandReportPayload, NodeTelemetry,
        ReproCapability, ReproExecutionEvidence, ReproExecutionReport, UnsignedTelemetry,
        gpu_repro_spec_hash, managed_command_report_digest, node_id,
    };
    use rand::rngs::OsRng;

    use super::*;

    fn evidence_with_key(key: &DeviceSigningKey) -> SettlementEvidence {
        let node = node_id(&key.verifying_key());
        let image_digest = format!("sha256:{}", "a".repeat(64));
        let telemetry = [1_i64, 70, 120]
            .into_iter()
            .enumerate()
            .map(|(index, timestamp)| {
                NodeTelemetry::sign(
                    UnsignedTelemetry {
                        node_id: node.clone(),
                        sequence: index as u64 + 1,
                        observed_at: Utc.timestamp_opt(timestamp, 0).unwrap(),
                        gpu_utilization_bps: 5_000,
                        gpu_memory_used_mib: 1_024,
                        active_lease: Some("1".to_owned()),
                        tunnel_connected: true,
                        image_digest: Some(image_digest.clone()),
                        posture: None,
                    },
                    key,
                )
                .unwrap()
            })
            .collect();
        SettlementEvidence {
            lease_id: 1,
            chain_lease_id: 1,
            lease_nonce: 1,
            node_id: node,
            device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
            gpu_model: "NVIDIA L4".to_owned(),
            image_digest,
            rate_per_second: 1_000,
            deposit_base_units: 120_000,
            duration_seconds: 120,
            access_started_at: 0,
            access_ended_at: 120,
            cuda_ready_at: 10,
            interactive_access_ready_at: 20,
            gateway_closed_at: 100,
            last_observed_at: None,
            trust_class: None,
            execution: ExecutionEvidence::Physical,
            node_telemetry: telemetry,
            repro: None,
        }
    }

    fn evidence() -> SettlementEvidence {
        evidence_with_key(&DeviceSigningKey::generate(&mut OsRng))
    }

    #[test]
    fn escrow_generation_uses_the_canonical_database_identity() {
        let generation =
            EscrowGeneration::parse("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

        assert_eq!(
            generation.database_address,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(generation.chain_address, [0xaa; 20]);
    }

    #[tokio::test]
    async fn shutdown_gate_wakes_waiters_and_stays_closed() {
        let (shutdown, sender) = ShutdownGate::channel();
        assert!(!shutdown.requested());

        sender.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(50), shutdown.wait())
            .await
            .unwrap();
        assert!(shutdown.requested());
    }

    #[test]
    fn a_reused_chain_id_does_not_make_another_internal_lease_the_same_job() {
        let mut current_evidence = evidence();
        current_evidence.lease_id = 1_001;
        current_evidence.chain_lease_id = 42;
        let current = ClaimedSettlement {
            lease_id: 1_001,
            chain_lease_id: 42,
            claim_generation: 1,
            evidence: current_evidence.clone(),
        };
        let mut historical_evidence = current_evidence;
        historical_evidence.lease_id = 7;

        assert!(validate_claimed_identity(&current).is_ok());
        assert!(
            validate_stored_binding(&current, Some((42, SqlJson(historical_evidence)))).is_err()
        );
    }

    #[test]
    fn a_shallow_revert_stays_recheckable_until_finality() {
        assert_eq!(
            observe_attempt("submitted", &SettlementFinality::Pending),
            AttemptObservation::CheckTransaction
        );
    }

    #[test]
    fn a_finalized_revert_is_retired_instead_of_reused() {
        assert_eq!(
            observe_attempt("submitted", &SettlementFinality::Reverted),
            AttemptObservation::MarkReverted
        );
        assert_eq!(
            observe_attempt("reverted", &SettlementFinality::Pending),
            AttemptObservation::Ignore
        );
    }

    fn repro_evidence(exit_code: i32, expected_exit_code: i32) -> SettlementEvidence {
        let key = DeviceSigningKey::generate(&mut OsRng);
        let mut evidence = evidence_with_key(&key);
        let spec = GpuReproSpec {
            image: format!("registry.example/runtime@{}", evidence.image_digest),
            command: "python -c 'print(6 * 7)'".to_owned(),
            duration_seconds: evidence.duration_seconds,
            min_vram_mib: 1_024,
            expected_exit_code,
        };
        let capability = ReproCapability {
            token_hash: "1".repeat(64),
            spec_hash: gpu_repro_spec_hash(&spec).unwrap(),
            expected_exit_code,
            executor: ReproExecutor::Node,
        };
        let command = NodeCommand {
            command_id: uuid::Uuid::now_v7(),
            node_id: evidence.node_id.clone(),
            lease_id: evidence.lease_id,
            issued_at: Utc.timestamp_opt(1, 0).unwrap(),
            expires_at: Utc.timestamp_opt(601, 0).unwrap(),
            kind: NodeCommandKind::Batch {
                image: spec.image.clone(),
                command: spec.command.clone(),
                duration_seconds: spec.duration_seconds,
            },
        };
        let report = NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: evidence.node_id.clone(),
                device_public_key: evidence.device_public_key.clone(),
                request_id: uuid::Uuid::now_v7(),
                command_id: command.command_id,
                outcome: NodeCommandOutcome::Completed,
                observed_at: Utc.timestamp_opt(100, 0).unwrap(),
                error: None,
                channel_key: None,
                result: Some(CommandResult {
                    exit_code,
                    stdout: "42\n".to_owned(),
                    stderr: String::new(),
                    truncated: false,
                }),
            },
            &key,
        )
        .unwrap();
        evidence.repro = Some(ReproExecutionEvidence {
            capability,
            spec,
            command,
            report: ReproExecutionReport::Node { report },
        });
        evidence
    }

    fn managed_repro_evidence() -> (SettlementEvidence, [u8; 20]) {
        let mut evidence = repro_evidence(0, 0);
        evidence.execution = ExecutionEvidence::Vast {
            instance_id: 42,
            hourly_cost_micros: 600_000,
        };
        evidence.node_telemetry.clear();
        let repro = evidence.repro.as_mut().unwrap();
        repro.capability.executor = ReproExecutor::Managed;
        let payload = ManagedCommandReportPayload {
            report_id: uuid::Uuid::now_v7(),
            signer: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".to_owned(),
            command_id: repro.command.command_id,
            lease_id: evidence.lease_id,
            provider: ManagedProvider::Vast,
            provider_instance_id: 42,
            gpu_model: evidence.gpu_model.clone(),
            gpu_vram_mib: 24_576,
            transport_host_key_sha256: "b".repeat(64),
            started_at: Utc.timestamp_opt(20, 0).unwrap(),
            finished_at: Utc.timestamp_opt(100, 0).unwrap(),
            outcome: NodeCommandOutcome::Completed,
            error: None,
            result: Some(CommandResult {
                exit_code: 0,
                stdout: "42\n".to_owned(),
                stderr: String::new(),
                truncated: false,
            }),
        };
        let gateway = address(&payload.signer).unwrap();
        let mut report = ManagedCommandReport {
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
            signature: String::new(),
        };
        sign_managed_report(&mut report);
        repro.report = ReproExecutionReport::Managed { report };
        (evidence, gateway)
    }

    fn binding_for(evidence: &SettlementEvidence) -> ManagedReproBinding {
        let ReproExecutionReport::Managed { report } =
            &evidence.repro.as_ref().expect("repro").report
        else {
            panic!("managed report")
        };
        ManagedReproBinding {
            provider_instance_id: report.provider_instance_id,
            hourly_cost_micros: match &evidence.execution {
                ExecutionEvidence::Vast {
                    hourly_cost_micros, ..
                } => *hourly_cost_micros,
                ExecutionEvidence::Physical => panic!("managed execution"),
            },
            gpu_model: report.gpu_model.clone(),
            gpu_vram_mib: report.gpu_vram_mib,
            transport_host_key_sha256: report.transport_host_key_sha256.clone(),
            report: Some(report.clone()),
        }
    }

    fn reconcile_managed(
        evidence: &SettlementEvidence,
        gateway: [u8; 20],
    ) -> anyhow::Result<SettlementProposal> {
        let binding = binding_for(evidence);
        reconcile_with_managed_binding(evidence, Some(gateway), Some(&binding))
    }

    fn sign_managed_report(report: &mut ManagedCommandReport) {
        let digest = managed_command_report_digest(&report.payload()).unwrap();
        report.signature = format!("0x{}", hex::encode(sign_test_digest(&digest)));
    }

    fn sign_test_digest(digest: &[u8; 32]) -> [u8; 65] {
        let mut key_bytes = [0_u8; 32];
        key_bytes[31] = 1;
        let key = ManagedSigningKey::from_slice(&key_bytes).unwrap();
        let signature: Signature = key.sign_prehash(digest).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        let recovery_id = [0_u8, 1]
            .into_iter()
            .filter_map(RecoveryId::from_byte)
            .find(|recovery_id| {
                VerifyingKey::recover_from_prehash(digest, &signature, *recovery_id)
                    .is_ok_and(|recovered| recovered == *key.verifying_key())
            })
            .unwrap();
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = 27 + recovery_id.to_byte();
        encoded
    }

    fn legacy_submission(escrow: [u8; 20], nonce: u64) -> (Submission, DecodedLegacyTransaction) {
        let proposal = reconcile(&evidence()).unwrap();
        let digest = settlement_digest(ROBINHOOD_CHAIN_ID, escrow, &proposal).unwrap();
        let attestation_signature = sign_test_digest(&digest);
        let calldata = proposal_calldata(&proposal, &attestation_signature).unwrap();
        let unsigned =
            legacy_unsigned_transaction(nonce, 2, 500_000, escrow, &calldata, ROBINHOOD_CHAIN_ID);
        let transaction_digest: [u8; 32] = Keccak256::digest(unsigned).into();
        let transaction_signature = sign_test_digest(&transaction_digest);
        let raw = legacy_signed_transaction(
            nonce,
            2,
            500_000,
            escrow,
            &calldata,
            ROBINHOOD_CHAIN_ID,
            &transaction_signature,
        );
        let raw_transaction = format!("0x{}", hex::encode(raw));
        let transaction_hash = format!(
            "0x{}",
            hex::encode(Keccak256::digest(
                hex::decode(raw_transaction.trim_start_matches("0x")).unwrap()
            ))
        );
        let submission = Submission {
            proposal,
            attestation_signature: format!("0x{}", hex::encode(attestation_signature)),
            raw_transaction,
            transaction_hash,
            submitted: true,
        };
        let decoded = decode_legacy_transaction(&submission.raw_transaction).unwrap();
        (submission, decoded)
    }

    /// A lease whose machine went away 200s into a 900s window, noticed 150s
    /// later, which is how long the cloud staleness window takes to fire.
    fn interrupted_evidence() -> SettlementEvidence {
        let mut evidence = evidence();
        evidence.duration_seconds = 900;
        evidence.deposit_base_units = 900_000;
        evidence.access_started_at = 0;
        evidence.cuda_ready_at = 0;
        evidence.interactive_access_ready_at = 0;
        evidence.access_ended_at = 350;
        evidence.gateway_closed_at = 350;
        evidence.last_observed_at = Some(200);
        // The broker path, which is what every machine on the network runs on
        // today, and which meters from the provider's own view of the instance
        // rather than from telemetry a daemon signs.
        evidence.execution = ExecutionEvidence::Vast {
            instance_id: 42,
            hourly_cost_micros: 600_000,
        };
        evidence.node_telemetry.clear();
        evidence
    }

    #[test]
    fn a_machine_that_goes_away_is_billed_to_its_last_sighting() {
        let proposal = reconcile(&interrupted_evidence()).unwrap();
        assert_eq!(
            proposal.usage_seconds, 200,
            "the 150s of noticing is not billable"
        );
        assert_eq!(proposal.receipt.credited_seconds, Some(150));
        assert_eq!(
            proposal.receipt.failure_class.as_deref(),
            Some("interrupted")
        );
        assert_eq!(proposal.receipt.charged_base_units, 200_000);
        assert_eq!(proposal.receipt.refunded_base_units, 700_000);
    }

    #[test]
    fn a_lease_that_runs_its_full_window_is_never_called_interrupted() {
        let mut evidence = interrupted_evidence();
        evidence.access_ended_at = 900;
        evidence.gateway_closed_at = 900;
        evidence.last_observed_at = Some(840);
        let proposal = reconcile(&evidence).unwrap();
        assert_eq!(proposal.usage_seconds, 900);
        assert_eq!(proposal.receipt.failure_class, None);
        assert_eq!(proposal.receipt.credited_seconds, None);
    }

    #[test]
    fn a_renter_closing_early_is_not_a_provider_fault() {
        let mut evidence = interrupted_evidence();
        // Closed well before the window ended, but the machine was answering
        // right up to the moment it closed.
        evidence.last_observed_at = Some(348);
        let proposal = reconcile(&evidence).unwrap();
        assert_eq!(
            proposal.usage_seconds, 350,
            "voluntary early close bills in full"
        );
        assert_eq!(proposal.receipt.failure_class, None);
        assert_eq!(proposal.receipt.credited_seconds, None);
    }

    #[test]
    fn a_lease_with_no_sighting_to_go_on_is_billed_as_it_always_was() {
        let mut evidence = interrupted_evidence();
        evidence.last_observed_at = None;
        let proposal = reconcile(&evidence).unwrap();
        assert_eq!(proposal.usage_seconds, 350);
        assert_eq!(proposal.receipt.failure_class, None);
    }

    #[test]
    fn a_sighting_from_before_the_lease_cannot_bill_negative_time() {
        let mut evidence = interrupted_evidence();
        evidence.cuda_ready_at = 120;
        evidence.interactive_access_ready_at = 120;
        evidence.last_observed_at = Some(5);
        let proposal = reconcile(&evidence).unwrap();
        assert_eq!(proposal.usage_seconds, 0);
        assert_eq!(proposal.receipt.charged_base_units, 0);
        assert_eq!(proposal.receipt.credited_seconds, Some(230));
    }

    #[test]
    fn crediting_a_lease_changes_the_hash_it_settles_under() {
        let plain = reconcile(&evidence()).unwrap();
        let credited = reconcile(&interrupted_evidence()).unwrap();
        assert_ne!(plain.receipt.receipt_hash, credited.receipt.receipt_hash);
        assert!(prism_protocol::receipt_hash_matches(&credited.receipt).unwrap());
    }

    #[test]
    fn reconciliation_bills_only_the_confirmed_intersection() {
        let proposal = reconcile(&evidence()).unwrap();
        assert_eq!(proposal.usage_seconds, 80);
        assert_eq!(proposal.lease_id, 1);
        assert!(bytes32(&proposal.receipt_hash).is_ok());
    }

    #[test]
    fn reconciliation_commits_verified_repro_evidence() {
        let evidence = repro_evidence(0, 0);
        let source = evidence.repro.as_ref().unwrap();
        let ReproExecutionReport::Node { report } = &source.report else {
            panic!("node report")
        };
        let result = report.result.as_ref().unwrap();
        let proposal = reconcile(&evidence).unwrap();
        let receipt = proposal.receipt.repro.as_ref().unwrap();

        assert_eq!(receipt.executor, ReproExecutor::Node);
        assert_eq!(receipt.token_hash, source.capability.token_hash);
        assert_eq!(receipt.spec_hash, source.capability.spec_hash);
        assert_eq!(receipt.image_digest, evidence.image_digest);
        assert_eq!(
            receipt.command_hash,
            repro_command_hash(&source.command).unwrap()
        );
        assert_eq!(receipt.result_hash, repro_result_hash(result).unwrap());
        assert_eq!(receipt.report_hash, repro_report_hash(report).unwrap());
        assert_eq!(receipt.stdout_hash, repro_stream_hash("42\n"));
        assert_eq!(receipt.stderr_hash, repro_stream_hash(""));
        assert_eq!(receipt.exit_code, 0);
        assert_eq!(receipt.expected_exit_code, 0);
        assert!(receipt.succeeded);
        assert!(!receipt.truncated);
        assert!(prism_protocol::receipt_hash_matches(&proposal.receipt).unwrap());
    }

    #[test]
    fn a_completed_repro_can_prove_an_expected_failure() {
        let proposal = reconcile(&repro_evidence(2, 2)).unwrap();
        assert!(proposal.receipt.repro.unwrap().succeeded);

        let proposal = reconcile(&repro_evidence(2, 0)).unwrap();
        assert!(!proposal.receipt.repro.unwrap().succeeded);
    }

    #[test]
    fn reconciliation_rejects_a_tampered_repro_report() {
        let mut evidence = repro_evidence(0, 0);
        let ReproExecutionReport::Node { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("node report")
        };
        report.result.as_mut().unwrap().stdout = "43\n".to_owned();

        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn reconciliation_accepts_a_gateway_signed_managed_report() {
        let (evidence, gateway) = managed_repro_evidence();
        let proposal = reconcile_managed(&evidence, gateway).unwrap();
        let receipt = proposal.receipt.repro.unwrap();

        assert_eq!(receipt.executor, ReproExecutor::Managed);
        assert!(receipt.succeeded);
        assert_eq!(receipt.stdout_hash, repro_stream_hash("42\n"));
    }

    #[test]
    fn reconciliation_rejects_mutable_cloud_terms_after_preflight() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let binding = binding_for(&evidence);
        evidence.execution = ExecutionEvidence::Vast {
            instance_id: binding.provider_instance_id + 1,
            hourly_cost_micros: binding.hourly_cost_micros + 1,
        };

        assert!(reconcile_with_managed_binding(&evidence, Some(gateway), Some(&binding)).is_err());
    }

    #[test]
    fn reportless_post_launch_failure_still_uses_preflight_terms() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let mut binding = binding_for(&evidence);
        binding.report = None;
        evidence.repro = None;

        assert!(reconcile_with_managed_binding(&evidence, Some(gateway), Some(&binding)).is_ok());
    }

    #[test]
    fn reconciliation_rejects_an_executor_changed_after_approval() {
        let (mut evidence, gateway) = managed_repro_evidence();
        evidence.repro.as_mut().unwrap().capability.executor = ReproExecutor::Node;

        assert!(reconcile_managed(&evidence, gateway).is_err());
    }

    #[test]
    fn a_gateway_signed_infrastructure_failure_can_close_without_a_fake_result() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let ReproExecutionReport::Managed { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("managed report")
        };
        report.outcome = NodeCommandOutcome::Failed;
        report.error = Some("managed result became unavailable".to_owned());
        report.result = None;
        sign_managed_report(report);

        let proposal = reconcile_managed(&evidence, gateway).unwrap();
        assert!(proposal.receipt.repro.is_none());
        assert!(prism_protocol::receipt_hash_matches(&proposal.receipt).unwrap());
    }

    #[test]
    fn reconciliation_rejects_a_managed_report_from_the_wrong_gateway() {
        let (evidence, _) = managed_repro_evidence();

        assert!(reconcile_managed(&evidence, [9_u8; 20]).is_err());
        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn reconciliation_rejects_tampered_managed_results() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let ReproExecutionReport::Managed { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("managed report")
        };
        report.result.as_mut().unwrap().stdout = "43\n".to_owned();

        assert!(reconcile_managed(&evidence, gateway).is_err());
    }

    #[test]
    fn reconciliation_rejects_managed_execution_outside_the_active_window() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let ReproExecutionReport::Managed { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("managed report")
        };
        report.finished_at = Utc.timestamp_opt(121, 0).unwrap();
        sign_managed_report(report);

        assert!(reconcile_managed(&evidence, gateway).is_err());
    }

    #[test]
    fn reconciliation_rejects_a_managed_report_for_another_instance() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let ReproExecutionReport::Managed { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("managed report")
        };
        report.provider_instance_id += 1;
        sign_managed_report(report);

        assert!(reconcile_managed(&evidence, gateway).is_err());
    }

    #[test]
    fn reconciliation_rejects_a_managed_report_for_another_gpu() {
        let (mut evidence, gateway) = managed_repro_evidence();
        let ReproExecutionReport::Managed { report } = &mut evidence.repro.as_mut().unwrap().report
        else {
            panic!("managed report")
        };
        report.gpu_model = "NVIDIA H100".to_owned();
        sign_managed_report(report);

        assert!(reconcile_managed(&evidence, gateway).is_err());
    }

    #[test]
    fn reconciliation_rejects_a_repro_spec_not_bound_to_the_capability() {
        let mut evidence = repro_evidence(0, 0);
        evidence.repro.as_mut().unwrap().spec.min_vram_mib += 1;

        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn reconciliation_rejects_exit_codes_outside_the_capsule_contract() {
        assert!(reconcile(&repro_evidence(0, 256)).is_err());
        assert!(reconcile(&repro_evidence(256, 0)).is_err());
    }

    #[test]
    fn reconciliation_rejects_a_command_for_another_lease() {
        let mut evidence = repro_evidence(0, 0);
        evidence.repro.as_mut().unwrap().command.lease_id += 1;

        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn cloud_reconciliation_uses_explicit_profitable_provider_evidence() {
        let mut evidence = evidence();
        evidence.execution = ExecutionEvidence::Vast {
            instance_id: 42,
            hourly_cost_micros: 600_000,
        };
        evidence.node_telemetry.clear();
        assert_eq!(reconcile(&evidence).unwrap().usage_seconds, 80);

        evidence.execution = ExecutionEvidence::Vast {
            instance_id: 42,
            hourly_cost_micros: 3_600_000,
        };
        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn every_servable_class_settles_and_the_guard_holds_the_ceiling() {
        // Confidential is now the ceiling, so every class up to it settles.
        for class in [
            TrustClass::Open,
            TrustClass::Isolated,
            TrustClass::Attested,
            TrustClass::Confidential,
        ] {
            let mut evidence = evidence();
            evidence.trust_class = Some(class);
            assert!(reconcile(&evidence).is_ok(), "{class:?} should settle");
        }
        // The guard still refuses anything past the ceiling; with Confidential
        // the top class there is nothing above it to construct, so this pins
        // the boundary at exactly the ceiling.
        assert!(
            settled_trust_class(&{
                let mut evidence = evidence();
                evidence.trust_class = Some(MAX_VERIFIABLE_TRUST_CLASS);
                evidence
            })
            .is_ok()
        );
    }

    #[test]
    fn a_servable_class_reaches_the_receipt_unchanged() {
        let mut evidence = evidence();
        evidence.trust_class = Some(MAX_VERIFIABLE_TRUST_CLASS);
        let proposal = reconcile(&evidence).unwrap();
        assert_eq!(
            proposal.receipt.trust_class,
            Some(MAX_VERIFIABLE_TRUST_CLASS)
        );
        assert_eq!(
            proposal.receipt.receipt_hash,
            receipt_hash(&proposal.receipt).unwrap()
        );
    }

    #[test]
    fn reconciliation_rejects_tampered_node_telemetry() {
        let mut evidence = evidence();
        evidence.node_telemetry[1].gpu_utilization_bps = 9_999;
        assert!(reconcile(&evidence).is_err());
    }

    #[test]
    fn dispute_window_selector_matches_the_escrow() {
        let selector = Keccak256::digest(b"DISPUTE_WINDOW()");
        assert_eq!(hex::encode(&selector[..4]), "f585dc57");
    }

    #[test]
    fn gateway_selector_and_abi_address_match_the_escrow() {
        let selector = Keccak256::digest(b"gateway()");
        assert_eq!(hex::encode(&selector[..4]), "116191b6");

        let gateway = [7_u8; 20];
        let mut word = [0_u8; 32];
        word[12..].copy_from_slice(&gateway);
        assert_eq!(
            decode_abi_address(&format!("0x{}", hex::encode(word))).unwrap(),
            gateway
        );
        assert!(decode_abi_address(&format!("0x{}", "00".repeat(32))).is_err());
        assert!(decode_abi_address("0x01").is_err());
    }

    #[test]
    fn proposal_calldata_uses_the_contract_selector_and_dynamic_signature_offset() {
        let proposal = reconcile(&evidence()).unwrap();
        let signature = [7_u8; 65];
        let calldata = proposal_calldata(&proposal, &signature).unwrap();
        assert_eq!(
            &calldata[..4],
            &Keccak256::digest(b"proposeSettlement(uint256,uint64,bytes32,uint256,bytes)")[..4]
        );
        assert_eq!(&calldata[4 + 32 * 4..4 + 32 * 5], &word_u128(160));
        assert_eq!(calldata.len(), 4 + 32 * 9);
        let signature_start = 4 + 32 * 6;
        assert_eq!(calldata[signature_start + 64], 7);
        assert!(
            calldata[signature_start + 65..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    /// A signature carries a deadline, and past it the escrow rejects the
    /// proposal with Expired() however many times it is sent. Reuse has to stop
    /// before that, with enough margin that a proposal does not expire while it
    /// is in flight.
    #[test]
    fn a_known_pending_signature_is_not_reused_once_it_is_close_to_expiring() {
        let now = 1_700_000_000u64;

        assert!(
            pending_attempt_is_reusable(true, now + 3_600, now),
            "a fresh hour-long signature is fine"
        );
        assert!(
            !pending_attempt_is_reusable(true, now + DEADLINE_MARGIN_SECONDS, now),
            "exactly at the margin is already too late to start"
        );
        assert!(
            !pending_attempt_is_reusable(true, now, now),
            "expiring now must be rebuilt"
        );
        assert!(
            !pending_attempt_is_reusable(true, now - 1, now),
            "expired must be rebuilt"
        );
        assert!(
            !pending_attempt_is_reusable(true, u64::MAX, u64::MAX),
            "timestamp overflow must fail closed"
        );
        assert!(
            !pending_attempt_is_reusable(false, now + 3_600, now),
            "unknown bytes must not be adopted even with a fresh deadline"
        );
        const {
            assert!(
                DEADLINE_MARGIN_SECONDS < 3_600,
                "the margin has to leave a freshly signed proposal usable"
            );
        }
    }

    #[test]
    fn replacement_deadlines_do_not_change_settlement_identity() {
        let (submission, _) = legacy_submission([0x11; 20], 7);
        let mut replacement = submission.proposal.clone();
        replacement.deadline = replacement.deadline.saturating_add(1);

        assert!(submission_matches_settlement(&submission, &replacement));
        assert_ne!(submission.proposal.deadline, replacement.deadline);
    }

    #[test]
    fn settlement_digest_matches_the_eip712_reference_vector() {
        let mut proposal = reconcile(&evidence()).unwrap();
        proposal.lease_id = 1;
        proposal.usage_seconds = 80;
        proposal.receipt_hash = "aa".repeat(32);
        proposal.nonce = 1;
        proposal.deadline = 2_000;
        let digest = settlement_digest(ROBINHOOD_CHAIN_ID, [0x11; 20], &proposal).unwrap();
        let encoded = hex::decode(
            "993bd2ee3ac380b5e2c67715aa14010a0c4ddbab32d10d51c172a7fda24dd395\
             7b4dc73eed142a6dd46bf5f63c6e1c5fa38f3ff91e7d3072a9d284a16894a25f1b",
        )
        .unwrap();
        let signature = Signature::from_slice(&encoded[..64]).unwrap();
        let recovery_id = RecoveryId::from_byte(encoded[64] - 27).unwrap();
        let recovered =
            VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
        let point = recovered.to_encoded_point(false);
        let recovered_address = &Keccak256::digest(&point.as_bytes()[1..])[12..];
        assert_eq!(
            hex::encode(recovered_address),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn legacy_transaction_is_replay_bound_to_robinhood_chain() {
        let data = vec![1, 2, 3];
        let to = [9_u8; 20];
        let signature = {
            let mut signature = [1_u8; 65];
            signature[64] = 27;
            signature
        };
        let raw =
            legacy_signed_transaction(1, 2, 100_000, to, &data, ROBINHOOD_CHAIN_ID, &signature);
        let decoded = rlp::Rlp::new(&raw);
        assert_eq!(
            decoded.at(6).unwrap().as_val::<u64>().unwrap(),
            ROBINHOOD_CHAIN_ID * 2 + 35
        );
    }

    #[test]
    fn legacy_transaction_recovers_its_nonce_owner() {
        let mut key_bytes = [0_u8; 32];
        key_bytes[31] = 1;
        let key = ManagedSigningKey::from_slice(&key_bytes).unwrap();
        let unsigned =
            legacy_unsigned_transaction(7, 2, 100_000, [9_u8; 20], &[1, 2, 3], ROBINHOOD_CHAIN_ID);
        let digest: [u8; 32] = Keccak256::digest(unsigned).into();
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        let recovery_id = [0_u8, 1]
            .into_iter()
            .filter_map(RecoveryId::from_byte)
            .find(|recovery_id| {
                VerifyingKey::recover_from_prehash(&digest, &signature, *recovery_id)
                    .is_ok_and(|recovered| recovered == *key.verifying_key())
            })
            .unwrap();
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = 27 + recovery_id.to_byte();
        let raw = legacy_signed_transaction(
            7,
            2,
            100_000,
            [9_u8; 20],
            &[1, 2, 3],
            ROBINHOOD_CHAIN_ID,
            &encoded,
        );

        assert_eq!(
            transaction_signer(&format!("0x{}", hex::encode(raw))).unwrap(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn a_fully_bound_legacy_submission_normalizes_only_receipt_identity() {
        let escrow = [0x11; 20];
        let escrow_address = format!("0x{}", hex::encode(escrow));
        let (submission, decoded) = legacy_submission(escrow, 7);
        let original_receipt_hash = submission.proposal.receipt.receipt_hash.clone();
        let value = serde_json::to_value(&submission).unwrap();

        let audit = audit_generation_binding(
            &submission.transaction_hash,
            &submission.raw_transaction,
            7,
            i64::try_from(submission.proposal.lease_id).unwrap(),
            &escrow_address,
            i64::try_from(submission.proposal.chain_lease_id).unwrap(),
            &value,
            Some(&value),
            &decoded,
        );

        let GenerationBindingAudit::Normalized(normalized) = audit else {
            panic!("valid legacy submission was not normalized")
        };
        assert_eq!(
            normalized.proposal.receipt.escrow_address.as_deref(),
            Some(escrow_address.as_str())
        );
        assert_eq!(
            normalized.proposal.receipt.chain_lease_id.as_deref(),
            Some("1")
        );
        assert_eq!(
            normalized.proposal.receipt.receipt_hash,
            original_receipt_hash
        );
        assert!(receipt_hash_matches(&normalized.proposal.receipt).unwrap());
        let normalized_value = serde_json::to_value(&normalized).unwrap();
        assert!(current_job_proposal_matches_attempt(
            &normalized_value,
            &value,
            &escrow_address,
            1,
        ));
        let mut mismatched = value;
        mismatched["submitted"] = serde_json::Value::Bool(false);
        assert!(!current_job_proposal_matches_attempt(
            &normalized_value,
            &mismatched,
            &escrow_address,
            1,
        ));
    }

    #[test]
    fn historical_bytes_for_another_escrow_generation_are_quarantined() {
        let current_escrow = [0x22; 20];
        let historical_escrow = [0x11; 20];
        let (submission, decoded) = legacy_submission(current_escrow, 9);
        let value = serde_json::to_value(&submission).unwrap();

        let audit = audit_generation_binding(
            &submission.transaction_hash,
            &submission.raw_transaction,
            9,
            i64::try_from(submission.proposal.lease_id).unwrap(),
            &format!("0x{}", hex::encode(historical_escrow)),
            i64::try_from(submission.proposal.chain_lease_id).unwrap(),
            &value,
            Some(&value),
            &decoded,
        );

        assert!(matches!(
            audit,
            GenerationBindingAudit::Quarantined("signed_escrow_mismatch")
        ));
    }

    #[test]
    fn historical_bytes_with_a_false_transaction_hash_are_quarantined() {
        let escrow = [0x11; 20];
        let (submission, decoded) = legacy_submission(escrow, 11);
        let value = serde_json::to_value(&submission).unwrap();

        let audit = audit_generation_binding(
            &format!("0x{}", "00".repeat(32)),
            &submission.raw_transaction,
            11,
            i64::try_from(submission.proposal.lease_id).unwrap(),
            &format!("0x{}", hex::encode(escrow)),
            i64::try_from(submission.proposal.chain_lease_id).unwrap(),
            &value,
            Some(&value),
            &decoded,
        );

        assert!(matches!(
            audit,
            GenerationBindingAudit::Quarantined("transaction_hash_mismatch")
        ));
    }

    #[test]
    fn a_unique_confirmed_lease_owns_a_historical_nonce_collision() {
        let attempts = [
            historical_attempt(13, "prepared", 'a'),
            historical_attempt(14, "confirmed", 'b'),
        ];

        assert_eq!(
            resolve_historical_nonce(&attempts),
            HistoricalNonceResolution::ReservedBy(14)
        );
    }

    #[test]
    fn same_lease_replacements_share_one_historical_nonce_reservation() {
        let attempts = [
            historical_attempt(14, "superseded", 'a'),
            historical_attempt(14, "submitted", 'b'),
            historical_attempt(14, "confirmed", 'c'),
        ];

        assert_eq!(
            resolve_historical_nonce(&attempts),
            HistoricalNonceResolution::ReservedBy(14)
        );
    }

    #[test]
    fn ambiguous_cross_lease_historical_nonces_fail_closed() {
        let unconfirmed = [
            historical_attempt(13, "prepared", 'a'),
            historical_attempt(14, "submitted", 'b'),
        ];
        assert_eq!(
            resolve_historical_nonce(&unconfirmed),
            HistoricalNonceResolution::Conflict(NO_CONFIRMED_HISTORICAL_NONCE_OWNER)
        );

        let multiply_confirmed = [
            historical_attempt(13, "confirmed", 'a'),
            historical_attempt(14, "confirmed", 'b'),
        ];
        assert_eq!(
            resolve_historical_nonce(&multiply_confirmed),
            HistoricalNonceResolution::Conflict(MULTIPLE_CONFIRMED_HISTORICAL_NONCE_OWNERS)
        );
    }

    fn historical_attempt(lease_id: i64, status: &str, marker: char) -> HistoricalNonceAttempt {
        HistoricalNonceAttempt {
            transaction_hash: format!("0x{}", marker.to_string().repeat(64)),
            lease_id,
            status: status.to_owned(),
        }
    }
}
