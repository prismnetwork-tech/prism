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
    ExecutionEvidence, PublicReceipt, ROBINHOOD_CHAIN_ID, ReceiptOutcome, SettlementEvidence,
    node_id, receipt_hash, verifying_key,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;

const MAX_EVIDENCE_BYTES: u64 = 20_000_000;
const MAX_EVIDENCE_RECORDS: usize = 1_000;
const MAX_LEASE_SECONDS: u64 = 21_600;
const MAX_ESCROW_BASE_UNITS: u64 = 50_000_000;
const TELEMETRY_EDGE_TOLERANCE_SECONDS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettlementProposal {
    lease_id: u64,
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
        .with_env_filter(EnvFilter::from_default_env())
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
    let mut proposals = evidence
        .iter()
        .map(reconcile)
        .collect::<Result<Vec<_>, _>>()?;
    proposals.sort_by_key(|proposal| proposal.lease_id);

    let rpc_url = secure_url(&required_env("PRISM_RPC_URL")?)?;
    let chain = ChainClient::new(rpc_url)?;
    let chain_id = chain.quantity("eth_chainId", serde_json::json!([])).await?;
    if chain_id != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("RPC chain ID does not match Robinhood Chain mainnet");
    }
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
        let Some((lease_id, evidence, stored)) = claim_settlement(&pool).await? else {
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
            stored,
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

async fn claim_settlement(
    pool: &PgPool,
) -> anyhow::Result<Option<(u64, SettlementEvidence, Option<Submission>)>> {
    let mut transaction = pool.begin().await?;
    let row = query_as::<
        _,
        (
            i64,
            SqlJson<SettlementEvidence>,
            Option<SqlJson<Submission>>,
        ),
    >(
        "SELECT lease_id, evidence, proposal FROM settlement_jobs \
         WHERE attempts < 100 AND available_at <= NOW() \
           AND (status IN ('queued', 'submitted') \
                OR (status = 'processing' AND lease_until <= NOW())) \
         ORDER BY available_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((lease_id, SqlJson(evidence), submission)) = row else {
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
    Ok(Some((
        u64::try_from(lease_id)?,
        evidence,
        submission.map(|SqlJson(value)| value),
    )))
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
    stored: Option<Submission>,
) -> anyhow::Result<()> {
    let submission = match stored {
        Some(submission) => submission,
        None => prepare_durable_submission(pool, chain, signer, escrow, evidence).await?,
    };
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
    query(
        "UPDATE settlement_jobs SET status = 'submitted', lease_until = NULL, \
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
    let finalize_at = DateTime::from_timestamp(block_time as i64 + 86_400, 0)
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
        if let Some(SqlJson(existing)) = query_scalar::<_, SqlJson<Submission>>(
            "SELECT proposal FROM settlement_jobs \
                 WHERE lease_id = $1 AND proposal IS NOT NULL",
        )
        .bind(evidence.lease_id as i64)
        .fetch_optional(&mut *connection)
        .await?
        {
            return Ok(existing);
        }
        let proposal = reconcile(evidence)?;
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

fn reconcile(evidence: &SettlementEvidence) -> anyhow::Result<SettlementProposal> {
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
    let end = evidence
        .access_ended_at
        .min(evidence.gateway_closed_at)
        .min(start.saturating_add(u64::from(evidence.duration_seconds)));
    if start < evidence.access_started_at
        || end > evidence.access_ended_at
        || end < start
        || evidence.access_ended_at <= evidence.access_started_at
    {
        anyhow::bail!("lease {} has an invalid metering window", evidence.lease_id);
    }
    validate_execution_evidence(evidence, start, end)?;
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
        lease_id: evidence.lease_id.to_string(),
        node_id_hash: format!(
            "0x{}",
            hex::encode(Sha256::digest(evidence.node_id.as_bytes()))
        ),
        gpu_model: evidence.gpu_model.clone(),
        runtime_seconds: usage_seconds,
        charged_base_units,
        refunded_base_units: evidence.deposit_base_units - charged_base_units,
        provider_paid_base_units: charged_base_units - charged_base_units * 1_000 / 10_000,
        failure_class: None,
        outcome: ReceiptOutcome::Finalized,
        receipt_hash: String::new(),
        transaction_hash: String::new(),
    };
    receipt.receipt_hash = receipt_hash(&receipt)?;
    Ok(SettlementProposal {
        lease_id: evidence.lease_id,
        usage_seconds,
        receipt_hash: receipt.receipt_hash.clone(),
        nonce: evidence.lease_nonce,
        deadline: Utc::now().timestamp() as u64 + 3_600,
        evidence_hash,
        receipt,
    })
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
    let gas_price = chain
        .quantity("eth_gasPrice", serde_json::json!([]))
        .await?;
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
    settlement.extend_from_slice(&word_u128(u128::from(proposal.lease_id)));
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
    calldata.extend_from_slice(&word_u128(u128::from(proposal.lease_id)));
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

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey as DeviceSigningKey;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use prism_protocol::{NodeTelemetry, UnsignedTelemetry, node_id};
    use rand::rngs::OsRng;

    use super::*;

    fn evidence() -> SettlementEvidence {
        let key = DeviceSigningKey::generate(&mut OsRng);
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
                    },
                    &key,
                )
                .unwrap()
            })
            .collect();
        SettlementEvidence {
            lease_id: 1,
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
            execution: ExecutionEvidence::Physical,
            node_telemetry: telemetry,
        }
    }

    #[test]
    fn reconciliation_bills_only_the_confirmed_intersection() {
        let proposal = reconcile(&evidence()).unwrap();
        assert_eq!(proposal.usage_seconds, 80);
        assert_eq!(proposal.lease_id, 1);
        assert!(bytes32(&proposal.receipt_hash).is_ok());
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
    fn reconciliation_rejects_tampered_node_telemetry() {
        let mut evidence = evidence();
        evidence.node_telemetry[1].gpu_utilization_bps = 9_999;
        assert!(reconcile(&evidence).is_err());
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
