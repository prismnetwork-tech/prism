use std::{
    collections::{BTreeSet, HashSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use aws_sdk_s3::{Client as S3Client, primitives::ByteStream};
use chrono::{Datelike, Days, NaiveDate, Utc};
use prism_protocol::{PublicReceipt, ROBINHOOD_CHAIN_ID, ReceiptOutcome, receipt_hash_matches};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DailyDigest {
    digest_id: String,
    window: String,
    finalized_leases: usize,
    gpu_hours: String,
    settled_usdg: String,
    refunded_usdg: String,
    failures: usize,
    representative_transactions: Vec<String>,
}

enum ArtifactStore {
    S3 { client: S3Client, bucket: String },
    Local(PathBuf),
}

#[derive(Serialize)]
struct ProofIndex<'a> {
    generated_at: chrono::DateTime<Utc>,
    receipts: &'a [PublicReceipt],
}

#[derive(Default, Serialize, Deserialize)]
struct Outbox {
    sent_windows: BTreeSet<String>,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: serde_json::Value,
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
        anyhow::bail!("DATABASE_URL is required for durable proof publication");
    }
    run_file().await
}

async fn run_file() -> anyhow::Result<()> {
    let source = PathBuf::from(required_env("PRISM_PROOF_RECEIPTS_FILE")?);
    let outbox = PathBuf::from(required_env("PRISM_PROOF_OUTBOX_FILE")?);
    let artifacts = PathBuf::from(required_env("PRISM_PROOF_ARTIFACT_DIR")?);
    let receipts: Vec<PublicReceipt> = serde_json::from_slice(&read_bounded(&source, 10_000_000)?)?;
    validate_receipts(&receipts)?;
    verify_chain_receipts(&receipts).await?;
    publish_artifacts(&artifacts, &receipts)?;
    if receipts.is_empty() {
        tracing::info!("no finalized settlement receipts in this proof window");
        return Ok(());
    }
    let digest = build_digest(&receipts)?;
    let key = receipt_set_id(&receipts)?;
    let mut outbox_state: Outbox = if outbox.exists() {
        serde_json::from_slice(&read_bounded(&outbox, 1_000_000)?)?
    } else {
        Outbox::default()
    };
    if outbox_state.sent_windows.contains(&key) {
        tracing::info!(window = %key, "daily proof digest already sent");
        return Ok(());
    }
    let proof_url = public_url("PRISM_PUBLIC_PROOF_URL")?;
    let explorer_url = env::var("PRISM_EXPLORER_URL")
        .unwrap_or_else(|_| "https://robinhoodchain.blockscout.com".to_owned());
    let explorer_url = parse_https_url(&explorer_url)?;
    let post = format_post(&digest, &proof_url, &explorer_url);
    let _ = post_to_x(&post).await?;
    outbox_state.sent_windows.insert(key);
    atomic_write(&outbox, &serde_json::to_vec_pretty(&outbox_state)?)?;
    println!("{}", serde_json::to_string_pretty(&digest)?);
    Ok(())
}

async fn run_database(database_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(database_url)
        .await
        .context("connect proof database")?;
    let present: Option<String> = query_scalar("SELECT to_regclass('public.proof_receipts')::text")
        .fetch_one(&pool)
        .await?;
    if present.is_none() {
        anyhow::bail!("control-plane proof migrations have not been applied");
    }
    let artifacts = ArtifactStore::from_environment().await?;
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    loop {
        publish_pending_receipts(&pool, &artifacts).await?;
        queue_daily_digest(&pool).await?;
        if let Err(error) = deliver_daily_digest(&pool).await {
            tracing::error!(%error, "daily proof digest delivery failed");
        }
        if run_once {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}

async fn publish_pending_receipts(pool: &PgPool, store: &ArtifactStore) -> anyhow::Result<()> {
    let pending = query_scalar::<_, SqlJson<PublicReceipt>>(
        "SELECT document FROM proof_receipts \
         WHERE published_at IS NULL ORDER BY block_number, receipt_id LIMIT 1000",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|SqlJson(receipt)| receipt)
    .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(());
    }
    validate_receipts(&pending)?;
    verify_chain_receipts(&pending).await?;
    for receipt in &pending {
        store
            .put(
                &format!("receipts/{}.json", receipt.receipt_id),
                serde_json::to_vec_pretty(receipt)?,
                "application/json",
            )
            .await?;
    }
    let all = query_scalar::<_, SqlJson<PublicReceipt>>(
        "SELECT document FROM proof_receipts \
         ORDER BY block_number DESC, receipt_id DESC LIMIT 10000",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|SqlJson(receipt)| receipt)
    .collect::<Vec<_>>();
    validate_receipts(&all)?;
    store
        .put(
            "index.json",
            serde_json::to_vec_pretty(&ProofIndex {
                generated_at: Utc::now(),
                receipts: &all,
            })?,
            "application/json",
        )
        .await?;
    let ids = pending
        .iter()
        .map(|receipt| receipt.receipt_id)
        .collect::<Vec<_>>();
    query(
        "UPDATE proof_receipts SET published_at = NOW() \
         WHERE receipt_id = ANY($1) AND published_at IS NULL",
    )
    .bind(&ids)
    .execute(pool)
    .await?;
    Ok(())
}

async fn queue_daily_digest(pool: &PgPool) -> anyhow::Result<()> {
    let window = Utc::now()
        .date_naive()
        .checked_sub_days(Days::new(1))
        .context("daily proof window underflowed")?;
    let receipts = query_scalar::<_, SqlJson<PublicReceipt>>(
        "SELECT document FROM proof_receipts \
         WHERE created_at >= $1::date AND created_at < ($1::date + INTERVAL '1 day') \
         ORDER BY created_at",
    )
    .bind(window)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|SqlJson(receipt)| receipt)
    .collect::<Vec<_>>();
    if receipts.is_empty() {
        return Ok(());
    }
    let digest = build_digest_for(window, &receipts)?;
    query(
        "INSERT INTO proof_digest_outbox (window_date, document) VALUES ($1, $2) \
         ON CONFLICT (window_date) DO NOTHING",
    )
    .bind(window)
    .bind(SqlJson(digest))
    .execute(pool)
    .await?;
    Ok(())
}

async fn deliver_daily_digest(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let row = query_as::<_, (NaiveDate, SqlJson<DailyDigest>)>(
        "SELECT window_date, document FROM proof_digest_outbox \
         WHERE attempts < 100 AND available_at <= NOW() \
           AND (status = 'queued' OR (status = 'processing' AND lease_until <= NOW())) \
         ORDER BY window_date LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((window, SqlJson(digest))) = row else {
        transaction.commit().await?;
        return Ok(());
    };
    query(
        "UPDATE proof_digest_outbox SET status = 'processing', attempts = attempts + 1, \
             lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
         WHERE window_date = $1",
    )
    .bind(window)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let result = async {
        let proof_url = public_url("PRISM_PUBLIC_PROOF_URL")?;
        let explorer_url = env::var("PRISM_EXPLORER_URL")
            .unwrap_or_else(|_| "https://robinhoodchain.blockscout.com".to_owned());
        let explorer_url = parse_https_url(&explorer_url)?;
        post_to_x(&format_post(&digest, &proof_url, &explorer_url)).await
    }
    .await;
    match result {
        Ok(post_id) => {
            query(
                "UPDATE proof_digest_outbox SET status = 'sent', lease_until = NULL, \
                     provider_post_id = $2, last_error = NULL, updated_at = NOW() \
                 WHERE window_date = $1",
            )
            .bind(window)
            .bind(post_id)
            .execute(pool)
            .await?;
        }
        Err(error) => {
            let message: String = format!("{error:#}").chars().take(1_024).collect();
            query(
                "UPDATE proof_digest_outbox SET \
                     status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END, \
                     lease_until = NULL, \
                     available_at = NOW() + make_interval(secs => LEAST(3600, attempts * attempts * 10)), \
                     last_error = $2, updated_at = NOW() WHERE window_date = $1",
            )
            .bind(window)
            .bind(message)
            .execute(pool)
            .await?;
            return Err(error);
        }
    }
    Ok(())
}

fn build_digest(receipts: &[PublicReceipt]) -> anyhow::Result<DailyDigest> {
    build_digest_for(Utc::now().date_naive(), receipts)
}

fn build_digest_for(window: NaiveDate, receipts: &[PublicReceipt]) -> anyhow::Result<DailyDigest> {
    let window = format!(
        "{:04}-{:02}-{:02}",
        window.year(),
        window.month(),
        window.day()
    );
    let finalized: Vec<&PublicReceipt> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == ReceiptOutcome::Finalized)
        .collect();
    let charged = checked_sum(finalized.iter().map(|receipt| receipt.charged_base_units))?;
    let refunded = checked_sum(receipts.iter().map(|receipt| receipt.refunded_base_units))?;
    let gpu_seconds = checked_sum(finalized.iter().map(|receipt| receipt.runtime_seconds))?;
    let mut digest = DailyDigest {
        digest_id: String::new(),
        window,
        finalized_leases: finalized.len(),
        gpu_hours: format_decimal(gpu_seconds, 3_600),
        settled_usdg: format_decimal(charged, 1_000_000),
        refunded_usdg: format_decimal(refunded, 1_000_000),
        failures: receipts
            .iter()
            .filter(|receipt| receipt.outcome != ReceiptOutcome::Finalized)
            .count(),
        representative_transactions: finalized
            .iter()
            .take(1)
            .map(|receipt| receipt.transaction_hash.clone())
            .collect(),
    };
    digest.digest_id = hex::encode(Sha256::digest(
        serde_json::to_vec(&digest).expect("digest serializes"),
    ));
    Ok(digest)
}

fn validate_receipts(receipts: &[PublicReceipt]) -> anyhow::Result<()> {
    if receipts.len() > 10_000 {
        anyhow::bail!("proof window contains too many receipts");
    }
    let mut receipt_ids = BTreeSet::new();
    for receipt in receipts {
        if !receipt_ids.insert(receipt.receipt_id) {
            anyhow::bail!("duplicate public receipt ID");
        }
        if !receipt_hash_matches(receipt)? {
            anyhow::bail!("public receipt hash does not match its canonical payload");
        }
        if !is_hash(&receipt.transaction_hash) || !is_hash(&receipt.node_id_hash) {
            anyhow::bail!("public receipt contains an invalid chain or node hash");
        }
        if receipt.lease_id.is_empty()
            || receipt.lease_id.len() > 128
            || receipt.gpu_model.trim().is_empty()
            || receipt.gpu_model.len() > 128
            || receipt.runtime_seconds > 21_600
            || receipt.charged_base_units > 50_000_000
            || receipt.refunded_base_units > 50_000_000
            || receipt
                .charged_base_units
                .checked_add(receipt.refunded_base_units)
                .is_none_or(|total| total > 50_000_000)
        {
            anyhow::bail!("public receipt exceeds settlement limits");
        }
        let expected_provider_payment =
            receipt.charged_base_units - receipt.charged_base_units * 1_000 / 10_000;
        if receipt.provider_paid_base_units != expected_provider_payment {
            anyhow::bail!("public receipt provider payment does not match the fee split");
        }
        if receipt.outcome != ReceiptOutcome::Finalized
            && (receipt.charged_base_units != 0 || receipt.provider_paid_base_units != 0)
        {
            anyhow::bail!("non-final receipt contains a provider payment");
        }
        if receipt.failure_class.as_ref().is_some_and(|class| {
            class.is_empty()
                || class.len() > 64
                || !class
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }) {
            anyhow::bail!("public receipt contains an invalid failure class");
        }
    }
    Ok(())
}

async fn verify_chain_receipts(receipts: &[PublicReceipt]) -> anyhow::Result<()> {
    let rpc_url = env::var("PRISM_RPC_URL")
        .ok()
        .filter(|value| !value.is_empty());
    let escrow = env::var("PRISM_LEASE_ESCROW_ADDRESS")
        .ok()
        .filter(|value| is_address(value));
    let (Some(rpc_url), Some(escrow)) = (rpc_url, escrow) else {
        if env::var("PRISM_ALLOW_UNVERIFIED_PROOF").as_deref() == Ok("1") {
            tracing::warn!("skipping chain receipt verification in local development");
            return Ok(());
        }
        anyhow::bail!(
            "PRISM_RPC_URL and PRISM_LEASE_ESCROW_ADDRESS are required for proof publication"
        );
    };
    let rpc_url = secure_rpc_url(&rpc_url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let chain_id = rpc_quantity(&client, &rpc_url, "eth_chainId", serde_json::json!([])).await?;
    if chain_id != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("proof RPC is not Robinhood Chain mainnet");
    }
    let current_block =
        rpc_quantity(&client, &rpc_url, "eth_blockNumber", serde_json::json!([])).await?;
    let confirmations = env::var("PRISM_PROOF_CONFIRMATIONS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(12);
    if confirmations == 0 || confirmations > 10_000 {
        anyhow::bail!("proof confirmation threshold is invalid");
    }

    for receipt in receipts {
        let chain_receipt: Option<TransactionReceipt> = rpc_call(
            &client,
            &rpc_url,
            "eth_getTransactionReceipt",
            serde_json::json!([receipt.transaction_hash]),
        )
        .await?;
        let chain_receipt = chain_receipt.context("proof transaction is not mined")?;
        if parse_quantity(&chain_receipt.status)? != 1 {
            anyhow::bail!("proof transaction reverted");
        }
        let block = parse_quantity(&chain_receipt.block_number)?;
        if current_block < block.saturating_add(confirmations) {
            anyhow::bail!("proof transaction has not reached the confirmation threshold");
        }
        verify_settlement_event(receipt, &escrow, &chain_receipt.logs)?;
    }
    Ok(())
}

fn verify_settlement_event(
    receipt: &PublicReceipt,
    escrow: &str,
    logs: &[ChainLog],
) -> anyhow::Result<()> {
    let lease_id = receipt
        .lease_id
        .parse::<u64>()
        .context("receipt lease ID is not a contract uint")?;
    let expected_topic = format!("0x{:064x}", lease_id);
    let finalized_topic =
        event_topic("LeaseFinalized(uint256,uint256,uint256,uint256,uint256,bytes32)");
    let refunded_topic = event_topic("LeaseRefunded(uint256,uint256,bytes32)");
    let expected_event = match receipt.outcome {
        ReceiptOutcome::Finalized => &finalized_topic,
        ReceiptOutcome::Refunded => &refunded_topic,
        ReceiptOutcome::Disputed => {
            anyhow::bail!("disputed receipts are not final proof artifacts")
        }
    };
    let log = logs
        .iter()
        .find(|log| {
            log.address.eq_ignore_ascii_case(escrow)
                && log
                    .topics
                    .first()
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(expected_event))
                && log
                    .topics
                    .get(1)
                    .is_some_and(|topic| topic.eq_ignore_ascii_case(&expected_topic))
        })
        .context("transaction contains no matching escrow settlement event")?;
    let data = hex::decode(
        log.data
            .strip_prefix("0x")
            .context("event data is not hex")?,
    )?;
    match receipt.outcome {
        ReceiptOutcome::Finalized => {
            if data.len() != 32 * 5 {
                anyhow::bail!("finalization event has invalid ABI data");
            }
            let charged = event_u64(&data, 0)?;
            let provider_paid = event_u64(&data, 2)?;
            let refunded = event_u64(&data, 3)?;
            if charged != receipt.charged_base_units
                || provider_paid != receipt.provider_paid_base_units
                || refunded != receipt.refunded_base_units
                || !hex::encode(&data[32 * 4..32 * 5])
                    .eq_ignore_ascii_case(receipt.receipt_hash.trim_start_matches("0x"))
            {
                anyhow::bail!("public receipt does not match the finalization event");
            }
        }
        ReceiptOutcome::Refunded => {
            if data.len() != 32 * 2
                || event_u64(&data, 0)? != receipt.refunded_base_units
                || receipt.charged_base_units != 0
            {
                anyhow::bail!("public receipt does not match the refund event");
            }
        }
        ReceiptOutcome::Disputed => unreachable!(),
    }
    Ok(())
}

fn event_u64(data: &[u8], index: usize) -> anyhow::Result<u64> {
    let word = data
        .get(index * 32..(index + 1) * 32)
        .context("event word is missing")?;
    if word[..24].iter().any(|byte| *byte != 0) {
        anyhow::bail!("event value exceeds uint64");
    }
    Ok(u64::from_be_bytes(word[24..].try_into()?))
}

fn event_topic(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}

fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn secure_rpc_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if url.scheme() != "https" && !local_http {
        anyhow::bail!("proof RPC URL must use HTTPS outside localhost");
    }
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("proof RPC URL must not contain credentials");
    }
    Ok(url)
}

async fn rpc_quantity(
    client: &reqwest::Client,
    rpc_url: &url::Url,
    method: &'static str,
    parameters: serde_json::Value,
) -> anyhow::Result<u64> {
    let value: String = rpc_call(client, rpc_url, method, parameters).await?;
    parse_quantity(&value)
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

async fn rpc_call<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    rpc_url: &url::Url,
    method: &'static str,
    parameters: serde_json::Value,
) -> anyhow::Result<T> {
    let response = client
        .post(rpc_url.clone())
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
        anyhow::bail!("proof RPC {method} returned an error: {error}");
    }
    serde_json::from_value(response.result).context("proof RPC response contains an invalid result")
}

fn publish_artifacts(directory: &Path, receipts: &[PublicReceipt]) -> anyhow::Result<()> {
    let receipt_directory = directory.join("receipts");
    fs::create_dir_all(&receipt_directory)?;
    let expected: HashSet<String> = receipts
        .iter()
        .map(|receipt| format!("{}.json", receipt.receipt_id))
        .collect();
    for entry in fs::read_dir(&receipt_directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
            && !expected.contains(&entry.file_name().to_string_lossy().into_owned())
        {
            fs::remove_file(entry.path())?;
        }
    }
    for receipt in receipts {
        let path = receipt_directory.join(format!("{}.json", receipt.receipt_id));
        atomic_write(&path, &serde_json::to_vec_pretty(receipt)?)?;
    }
    let index = ProofIndex {
        generated_at: Utc::now(),
        receipts,
    };
    atomic_write(
        &directory.join("index.json"),
        &serde_json::to_vec_pretty(&index)?,
    )?;
    Ok(())
}

impl ArtifactStore {
    async fn from_environment() -> anyhow::Result<Self> {
        if let Ok(bucket) = env::var("PRISM_PROOF_S3_BUCKET") {
            if bucket.is_empty() || bucket.len() > 63 {
                anyhow::bail!("PRISM_PROOF_S3_BUCKET is invalid");
            }
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .load()
                .await;
            return Ok(Self::S3 {
                client: S3Client::new(&config),
                bucket,
            });
        }
        if env::var("PRISM_ALLOW_LOCAL_PROOF_ARTIFACTS").as_deref() != Ok("1") {
            anyhow::bail!(
                "PRISM_PROOF_S3_BUCKET is required outside local proof artifact development"
            );
        }
        Ok(Self::Local(PathBuf::from(required_env(
            "PRISM_PROOF_ARTIFACT_DIR",
        )?)))
    }

    async fn put(&self, key: &str, body: Vec<u8>, content_type: &str) -> anyhow::Result<()> {
        if key.is_empty() || key.starts_with('/') || key.contains("..") {
            anyhow::bail!("proof artifact key is invalid");
        }
        match self {
            Self::S3 { client, bucket } => {
                client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .body(ByteStream::from(body))
                    .content_type(content_type)
                    .cache_control(if key == "index.json" {
                        "public, max-age=30"
                    } else {
                        "public, max-age=31536000, immutable"
                    })
                    .send()
                    .await?;
            }
            Self::Local(root) => {
                let path = root.join(key);
                atomic_write(&path, &body)?;
            }
        }
        Ok(())
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn post_to_x(text: &str) -> anyhow::Result<String> {
    validate_x_post(text)?;
    let token = required_env("PRISM_X_USER_ACCESS_TOKEN")?;
    let endpoint = env::var("PRISM_X_POST_ENDPOINT")
        .unwrap_or_else(|_| "https://api.x.com/2/tweets".to_owned());
    let endpoint = url::Url::parse(&endpoint)?;
    let production_endpoint =
        endpoint.scheme() == "https" && endpoint.host_str() == Some("api.x.com");
    if !production_endpoint && env::var("PRISM_ALLOW_DEVELOPMENT_X_ENDPOINT").as_deref() != Ok("1")
    {
        anyhow::bail!("PRISM_X_POST_ENDPOINT must use the official HTTPS API host");
    }
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .post(endpoint)
        .bearer_auth(token)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await?;
    let value: serde_json::Value = response.error_for_status()?.json().await?;
    value
        .pointer("/data/id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(ToOwned::to_owned)
        .context("X create-post response contains no post ID")
}

fn validate_x_post(text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        anyhow::bail!("X post cannot be empty");
    }
    let weighted_length = text
        .split_inclusive(char::is_whitespace)
        .map(|part| {
            let token = part.trim_end_matches(char::is_whitespace);
            let whitespace = part[token.len()..].chars().count();
            let token_weight = if token.starts_with("https://") {
                23
            } else {
                token
                    .chars()
                    .map(|character| if character.is_ascii() { 1 } else { 2 })
                    .sum()
            };
            token_weight + whitespace
        })
        .sum::<usize>();
    if weighted_length > 280 {
        anyhow::bail!("X post exceeds the 280-character weighted limit");
    }
    Ok(())
}

fn format_post(digest: &DailyDigest, proof_url: &url::Url, explorer_url: &url::Url) -> String {
    let transaction = digest
        .representative_transactions
        .first()
        .map(|hash| format!("{}/tx/{hash}", explorer_url.as_str().trim_end_matches('/')))
        .unwrap_or_default();
    format!(
        "Prism Network settlement summary · {} UTC\n{} finalized leases · {} GPU-hours\n{} USDG settled · {} USDG refunded\n{} non-final outcomes · proof:{}\n{}\n{}",
        digest.window,
        digest.finalized_leases,
        digest.gpu_hours,
        digest.settled_usdg,
        digest.refunded_usdg,
        digest.failures,
        &digest.digest_id[..12],
        proof_url,
        transaction,
    )
    .trim_end()
    .to_owned()
}

fn format_decimal(value: u64, divisor: u64) -> String {
    format!("{}.{:02}", value / divisor, value % divisor * 100 / divisor)
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("{key} is required"))
}

fn read_bounded(path: &Path, maximum: u64) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > maximum {
        anyhow::bail!("proof receipt source exceeds the size limit");
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > maximum {
        anyhow::bail!("proof receipt source exceeds the size limit");
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(anyhow::Error::from)
        .and_then(|()| fs::rename(&temporary, path).map_err(anyhow::Error::from));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> anyhow::Result<u64> {
    values.into_iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| anyhow::anyhow!("proof digest total overflowed"))
    })
}

fn receipt_set_id(receipts: &[PublicReceipt]) -> anyhow::Result<String> {
    let hashes: BTreeSet<&str> = receipts
        .iter()
        .map(|receipt| receipt.receipt_hash.as_str())
        .collect();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&hashes)?)))
}

fn public_url(key: &str) -> anyhow::Result<url::Url> {
    parse_https_url(&required_env(key)?)
}

fn parse_https_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    if url.scheme() != "https" || url.host_str().is_none() || url.username() != "" {
        anyhow::bail!("public proof links must use HTTPS URLs without credentials");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_protocol::{PublicReceipt, ReceiptOutcome, receipt_hash};
    use uuid::Uuid;

    #[test]
    fn digest_uses_only_finalized_charges() {
        let receipts = vec![
            PublicReceipt {
                receipt_id: Uuid::now_v7(),
                lease_id: "1".to_owned(),
                node_id_hash: "n".to_owned(),
                gpu_model: "GPU".to_owned(),
                runtime_seconds: 3_600,
                charged_base_units: 1_250_000,
                refunded_base_units: 250_000,
                provider_paid_base_units: 1_125_000,
                failure_class: None,
                outcome: ReceiptOutcome::Finalized,
                receipt_hash: String::new(),
                transaction_hash: format!("0x{}", "a".repeat(64)),
            },
            PublicReceipt {
                receipt_id: Uuid::now_v7(),
                lease_id: "2".to_owned(),
                node_id_hash: "n".to_owned(),
                gpu_model: "GPU".to_owned(),
                runtime_seconds: 0,
                charged_base_units: 0,
                refunded_base_units: 500_000,
                provider_paid_base_units: 0,
                failure_class: Some("provisioning_timeout".to_owned()),
                outcome: ReceiptOutcome::Refunded,
                receipt_hash: String::new(),
                transaction_hash: format!("0x{}", "b".repeat(64)),
            },
        ];
        let mut receipts = receipts;
        for receipt in &mut receipts {
            receipt.node_id_hash = format!("0x{}", "c".repeat(64));
            receipt.receipt_hash = receipt_hash(receipt).unwrap();
        }
        validate_receipts(&receipts).unwrap();
        let digest = build_digest(&receipts).unwrap();
        assert_eq!(digest.finalized_leases, 1);
        assert_eq!(digest.settled_usdg, "1.25");
        assert_eq!(digest.refunded_usdg, "0.75");
    }

    #[test]
    fn receipt_validation_enforces_provider_split() {
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: "1".to_owned(),
            node_id_hash: format!("0x{}", "a".repeat(64)),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000_000,
            refunded_base_units: 0,
            provider_paid_base_units: 1,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", "b".repeat(64)),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(validate_receipts(&[receipt]).is_err());
    }

    #[test]
    fn receipt_set_id_is_order_independent() {
        let mut first = valid_receipt("1", 'a');
        let mut second = valid_receipt("2", 'b');
        first.receipt_hash = receipt_hash(&first).unwrap();
        second.receipt_hash = receipt_hash(&second).unwrap();

        assert_eq!(
            receipt_set_id(&[first.clone(), second.clone()]).unwrap(),
            receipt_set_id(&[second, first]).unwrap()
        );
    }

    #[test]
    fn finalization_event_must_match_every_published_amount() {
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        let mut data = Vec::new();
        for value in [
            receipt.charged_base_units,
            100_000,
            receipt.provider_paid_base_units,
            receipt.refunded_base_units,
        ] {
            let mut word = [0_u8; 32];
            word[24..].copy_from_slice(&value.to_be_bytes());
            data.extend_from_slice(&word);
        }
        data.extend_from_slice(&hex::decode(&receipt.receipt_hash).unwrap());
        let escrow = format!("0x{}", "1".repeat(40));
        let log = ChainLog {
            address: escrow.clone(),
            topics: vec![
                event_topic("LeaseFinalized(uint256,uint256,uint256,uint256,uint256,bytes32)"),
                format!("0x{:064x}", 1),
            ],
            data: format!("0x{}", hex::encode(&data)),
        };
        assert!(verify_settlement_event(&receipt, &escrow, &[log]).is_ok());

        receipt.provider_paid_base_units -= 1;
        assert!(
            verify_settlement_event(
                &receipt,
                &escrow,
                &[ChainLog {
                    address: escrow.clone(),
                    topics: vec![
                        event_topic(
                            "LeaseFinalized(uint256,uint256,uint256,uint256,uint256,bytes32)",
                        ),
                        format!("0x{:064x}", 1),
                    ],
                    data: format!("0x{}", hex::encode(data)),
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_publication_removes_stale_receipts() {
        let directory = env::temp_dir().join(format!("prism-proof-test-{}", Uuid::now_v7()));
        let receipts = directory.join("receipts");
        fs::create_dir_all(&receipts).unwrap();
        fs::write(receipts.join("stale.json"), b"{}").unwrap();
        fs::write(receipts.join("keep.txt"), b"not a receipt").unwrap();
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        publish_artifacts(&directory, &[receipt.clone()]).unwrap();

        assert!(!receipts.join("stale.json").exists());
        assert!(receipts.join("keep.txt").exists());
        assert!(
            receipts
                .join(format!("{}.json", receipt.receipt_id))
                .exists()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn proof_publication_handles_the_network_cap_volume() {
        let directory = env::temp_dir().join(format!("prism-proof-load-{}", Uuid::now_v7()));
        let receipts = (1..=25)
            .map(|lease_id| {
                let mut receipt = valid_receipt(&lease_id.to_string(), 'b');
                receipt.receipt_hash = receipt_hash(&receipt).unwrap();
                receipt
            })
            .collect::<Vec<_>>();

        validate_receipts(&receipts).unwrap();
        publish_artifacts(&directory, &receipts).unwrap();

        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["receipts"].as_array().unwrap().len(), 25);
        assert_eq!(
            fs::read_dir(directory.join("receipts"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json"))
                .count(),
            25
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn x_post_validation_counts_urls_at_the_shortened_length() {
        let long_url = format!("https://proof.example/{}", "a".repeat(400));
        assert!(validate_x_post(&format!("Daily proof\n{long_url}")).is_ok());
        assert!(validate_x_post(&"a".repeat(281)).is_err());
        assert!(validate_x_post("  \n").is_err());
    }

    fn valid_receipt(lease_id: &str, transaction: char) -> PublicReceipt {
        PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: lease_id.to_owned(),
            node_id_hash: format!("0x{}", "a".repeat(64)),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000_000,
            refunded_base_units: 0,
            provider_paid_base_units: 900_000,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", transaction.to_string().repeat(64)),
        }
    }
}
