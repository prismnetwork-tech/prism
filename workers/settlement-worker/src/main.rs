use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use prism_chain::EthereumSigner;
use prism_protocol::{
    CommandResult, ExecutionEvidence, MAX_VERIFIABLE_TRUST_CLASS, ManagedCommandReport,
    ManagedProvider, NodeCommandKind, NodeCommandOutcome, PublicReceipt, ROBINHOOD_CHAIN_ID,
    ReceiptOutcome, ReproExecutionReport, ReproExecutor, ReproReceiptEvidence, SettlementEvidence,
    TrustClass, gpu_repro_spec_hash, managed_repro_report_hash, node_id, receipt_hash,
    repro_command_hash, repro_report_hash, repro_result_hash, repro_stream_hash, verifying_key,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgConnection, PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;

/// Rebuild a settlement proposal rather than resubmit it after this many
/// failed attempts, so a transaction priced below the base fee cannot strand
/// the lease and hold its node until the retry limit runs out.
/// How much life a signature needs left for it to be worth sending. Under this
/// it is rebuilt, because a proposal that expires in flight reverts and costs an
/// attempt for nothing.
const DEADLINE_MARGIN_SECONDS: u64 = 600;
const RESIGN_AFTER_ATTEMPTS: i16 = 5;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    if let Ok(database_url) = env::var("DATABASE_URL") {
        return run_database(&database_url).await;
    }
    if env::var("PRISM_ALLOW_DEVELOPMENT_FILE_HANDOFF").as_deref() != Ok("1") {
        anyhow::bail!("DATABASE_URL is required for durable settlement processing");
    }
    run_file().await
}

async fn run_file() -> anyhow::Result<()> {
    let evidence_path = PathBuf::from(required_env("PRISM_SETTLEMENT_EVIDENCE_FILE")?);
    let outbox_path = PathBuf::from(required_env("PRISM_SETTLEMENT_OUTBOX_FILE")?);
    let escrow = address(&required_env("PRISM_LEASE_ESCROW_ADDRESS")?)?;
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
    let gateway = chain.gateway(escrow).await?;
    let mut proposals = evidence
        .iter()
        .map(|evidence| reconcile_with_gateway(evidence, Some(gateway)))
        .collect::<Result<Vec<_>, _>>()?;
    proposals.sort_by_key(|proposal| proposal.lease_id);

    let signer = EthereumSigner::from_environment("PRISM_ATTESTOR_KMS_KEY_ID").await?;
    let mut outbox = if outbox_path.exists() {
        serde_json::from_slice(&read_bounded(&outbox_path, MAX_EVIDENCE_BYTES)?)?
    } else {
        Outbox::default()
    };

    for proposal in proposals {
        let lease_id = proposal.lease_id;
        if !outbox.submissions.contains_key(&lease_id) {
            let submission = prepare_submission(&chain, &signer, escrow, proposal).await?;
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

async fn run_database(database_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(database_url)
        .await
        .context("connect settlement database")?;
    let present: Option<String> =
        query_scalar("SELECT to_regclass('public.settlement_jobs')::text")
            .fetch_one(&pool)
            .await?;
    if present.is_none() {
        anyhow::bail!("control-plane settlement migrations have not been applied");
    }
    record_service_version(&pool, "settlement-worker").await?;
    let escrow = address(&required_env("PRISM_LEASE_ESCROW_ADDRESS")?)?;
    let chain = ChainClient::new(secure_url(&required_env("PRISM_RPC_URL")?)?)?;
    if chain.quantity("eth_chainId", serde_json::json!([])).await? != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("settlement RPC is not Robinhood Chain");
    }
    let signer = EthereumSigner::from_environment("PRISM_ATTESTOR_KMS_KEY_ID").await?;
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
        let Some((lease_id, evidence)) = claim_settlement(&pool).await? else {
            if run_once {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        };
        let result = process_settlement(
            &pool,
            &chain,
            &signer,
            escrow,
            confirmations,
            lease_id,
            &evidence,
        )
        .await;
        if let Err(error) = result {
            tracing::error!(lease_id, %error, "settlement job failed");
            retry_settlement(&pool, lease_id, &error).await?;
        }
        if run_once {
            return Ok(());
        }
    }
}

/// Claims a job. The stored proposal is deliberately not returned: whether it
/// can still be reused is decided in `prepare_durable_submission`, which is the
/// only place that knows the rules for rebuilding one.
async fn claim_settlement(pool: &PgPool) -> anyhow::Result<Option<(u64, SettlementEvidence)>> {
    let mut transaction = pool.begin().await?;
    let row = query_as::<_, (i64, SqlJson<SettlementEvidence>)>(
        "SELECT lease_id, evidence FROM settlement_jobs \
         WHERE attempts < 100 AND available_at <= NOW() \
           AND (status IN ('queued', 'submitted') \
                OR (status = 'processing' AND lease_until <= NOW())) \
         ORDER BY available_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((lease_id, SqlJson(evidence))) = row else {
        transaction.commit().await?;
        return Ok(None);
    };
    query(
        "UPDATE settlement_jobs SET status = 'processing', attempts = attempts + 1, \
             lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
         WHERE lease_id = $1",
    )
    .bind(lease_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some((u64::try_from(lease_id)?, evidence)))
}

async fn load_managed_repro_binding(
    connection: &mut PgConnection,
    lease_id: u64,
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
        "SELECT prepared_provider_instance_id, prepared_hourly_cost_micros, \
                gpu_model, gpu_vram_mib, \
                transport_host_key_sha256, report \
         FROM managed_repro_jobs WHERE lease_id = $1",
    )
    .bind(i64::try_from(lease_id)?)
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

#[allow(clippy::too_many_arguments)]
async fn process_settlement(
    pool: &PgPool,
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: [u8; 20],
    confirmations: u64,
    lease_id: u64,
    evidence: &SettlementEvidence,
) -> anyhow::Result<()> {
    // Always ask. Taking the claimed submission directly used to bypass the
    // rebuild rules entirely, so a proposal that could no longer land was
    // resubmitted verbatim until the job ran out of attempts.
    let submission = prepare_durable_submission(pool, chain, signer, escrow, evidence).await?;
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
    // Waiting for confirmations is not an attempt. Charging one for every poll
    // burned the whole allowance in about eight minutes of a slow inclusion,
    // after which the job could never be claimed again. Its status stayed
    // 'submitted' rather than 'failed', so the critical alert never fired and
    // the finalize step, which is only scheduled on the confirmed path, was
    // never queued at all.
    query(
        "UPDATE settlement_jobs SET status = 'submitted', lease_until = NULL, \
             attempts = GREATEST(0, attempts - 1), \
             available_at = NOW() + INTERVAL '5 seconds', updated_at = NOW() \
         WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .execute(pool)
    .await?;
    let Some((block_number, block_hash, block_time)) = chain
        .confirmed(&submission.transaction_hash, confirmations)
        .await?
    else {
        return Ok(());
    };
    let dispute_window = chain.dispute_window(escrow).await?;
    let finalize_at = DateTime::from_timestamp(block_time as i64 + dispute_window as i64, 0)
        .context("settlement finalization time is invalid")?;
    let mut transaction = pool.begin().await?;
    query(
        "UPDATE settlement_jobs SET status = 'proposed', lease_until = NULL, \
             confirmed_block = $2, confirmed_block_hash = $3, last_error = NULL, \
             updated_at = NOW() WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .bind(block_number as i64)
    .bind(block_hash.to_ascii_lowercase())
    .execute(&mut *transaction)
    .await?;
    query(
        "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
         VALUES ($1, $2, 'finalize', $3) \
         ON CONFLICT (lease_id, kind) DO NOTHING",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(lease_id as i64)
    .bind(finalize_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    tracing::info!(
        lease_id,
        transaction_hash = %submission.transaction_hash,
        "settlement proposal reached finality"
    );
    Ok(())
}

async fn prepare_durable_submission(
    pool: &PgPool,
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: [u8; 20],
    evidence: &SettlementEvidence,
) -> anyhow::Result<Submission> {
    let mut connection = pool.acquire().await?;
    query("SELECT pg_advisory_lock(4663002)")
        .execute(&mut *connection)
        .await?;
    let result = async {
        let gateway = chain.gateway(escrow).await?;
        let managed_binding =
            load_managed_repro_binding(&mut connection, evidence.lease_id).await?;
        let proposal =
            reconcile_with_managed_binding(evidence, Some(gateway), managed_binding.as_ref())?;
        // Reusing the stored submission is what makes settlement idempotent, but
        // those bytes carry the gas price they were signed at. If the chain has
        // rejected them repeatedly they can never land, and resubmitting until
        // the attempt limit strands the lease and holds its node the whole time.
        // Past a few failures the proposal is rebuilt at the current price.
        // The signature also carries a deadline. Once that passes the escrow
        // rejects the proposal with Expired() no matter how often it is sent,
        // so a stale one is rebuilt rather than retried.
        if let Some(SqlJson(existing)) = query_scalar::<_, SqlJson<Submission>>(
            "SELECT proposal FROM settlement_jobs \
                 WHERE lease_id = $1 AND proposal IS NOT NULL AND attempts < $2",
        )
        .bind(evidence.lease_id as i64)
        .bind(RESIGN_AFTER_ATTEMPTS)
        .fetch_optional(&mut *connection)
        .await?
            && existing.proposal.deadline
                > (Utc::now().timestamp() as u64) + DEADLINE_MARGIN_SECONDS
        {
            if existing.proposal.receipt_hash != proposal.receipt_hash {
                anyhow::bail!("stored settlement proposal no longer matches verified evidence");
            }
            return Ok(existing);
        }
        let submission = prepare_submission(chain, signer, escrow, proposal).await?;
        query(
            "UPDATE settlement_jobs SET proposal = $2, raw_transaction = $3, \
                 transaction_hash = $4, transaction_nonce = $5, status = 'submitted', \
                 lease_until = NULL, updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(evidence.lease_id as i64)
        .bind(SqlJson(submission.clone()))
        .bind(&submission.raw_transaction)
        .bind(&submission.transaction_hash)
        .bind(transaction_nonce(&submission.raw_transaction)? as i64)
        .execute(&mut *connection)
        .await?;
        Ok::<_, anyhow::Error>(submission)
    }
    .await;
    query("SELECT pg_advisory_unlock(4663002)")
        .execute(&mut *connection)
        .await?;
    result
}

async fn retry_settlement(
    pool: &PgPool,
    lease_id: u64,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    let message: String = format!("{error:#}").chars().take(1_024).collect();
    query(
        "UPDATE settlement_jobs SET \
             status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END, \
             lease_until = NULL, \
             available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)), \
             last_error = $2, updated_at = NOW() WHERE lease_id = $1",
    )
    .bind(lease_id as i64)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

fn transaction_nonce(raw: &str) -> anyhow::Result<u64> {
    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?;
    rlp::Rlp::new(&bytes)
        .at(0)?
        .as_val()
        .context("settlement transaction nonce is invalid")
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

async fn prepare_submission(
    chain: &ChainClient,
    signer: &EthereumSigner,
    escrow: [u8; 20],
    proposal: SettlementProposal,
) -> anyhow::Result<Submission> {
    let digest = settlement_digest(ROBINHOOD_CHAIN_ID, escrow, &proposal)?;
    let signature = signer.sign_digest(&digest).await?;
    let calldata = proposal_calldata(&proposal, &signature)?;
    let from = format!("0x{}", hex::encode(signer.address()));
    let to = format!("0x{}", hex::encode(escrow));
    let nonce = chain
        .quantity(
            "eth_getTransactionCount",
            serde_json::json!([from, "pending"]),
        )
        .await?;
    let gas_price = chain.suggested_gas_price().await?;
    let gas_limit = chain
        .quantity(
            "eth_estimateGas",
            serde_json::json!([{
                "from": from,
                "to": to,
                "data": format!("0x{}", hex::encode(&calldata)),
                "value": "0x0"
            }]),
        )
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
    let transaction_signature = signer.sign_digest(&transaction_digest).await?;
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

    async fn confirmed(
        &self,
        transaction_hash: &str,
        confirmations: u64,
    ) -> anyhow::Result<Option<(u64, String, u64)>> {
        let receipt: Option<TransactionReceipt> = self
            .call(
                "eth_getTransactionReceipt",
                serde_json::json!([transaction_hash]),
            )
            .await?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        if parse_quantity(&receipt.status)? != 1 {
            anyhow::bail!("settlement proposal transaction reverted");
        }
        let block_number = parse_quantity(&receipt.block_number)?;
        let current = self
            .quantity("eth_blockNumber", serde_json::json!([]))
            .await?;
        if current < block_number.saturating_add(confirmations) {
            return Ok(None);
        }
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([receipt.block_number, false]),
            )
            .await?;
        let Some(block) = block else {
            return Ok(None);
        };
        if !block.hash.eq_ignore_ascii_case(&receipt.block_hash) {
            return Ok(None);
        }
        Ok(Some((
            block_number,
            receipt.block_hash,
            parse_quantity(&block.timestamp)?,
        )))
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
        let mut key_bytes = [0_u8; 32];
        key_bytes[31] = 1;
        let key = ManagedSigningKey::from_slice(&key_bytes).unwrap();
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
        report.signature = format!("0x{}", hex::encode(encoded));
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
    fn a_signature_is_not_reused_once_it_is_close_to_expiring() {
        let now = 1_700_000_000u64;
        let reusable = |deadline: u64| deadline > now + DEADLINE_MARGIN_SECONDS;

        assert!(reusable(now + 3_600), "a fresh hour-long signature is fine");
        assert!(
            !reusable(now + DEADLINE_MARGIN_SECONDS),
            "exactly at the margin is already too late to start"
        );
        assert!(!reusable(now), "expiring now must be rebuilt");
        assert!(!reusable(now - 1), "expired must be rebuilt");
        assert!(
            DEADLINE_MARGIN_SECONDS < 3_600,
            "the margin has to leave a freshly signed proposal usable"
        );
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
}
