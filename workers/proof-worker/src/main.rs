use std::{
    collections::{BTreeSet, HashSet},
    env, fs,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use aws_sdk_s3::{Client as S3Client, primitives::ByteStream};
use chrono::{Datelike, Days, NaiveDate, Utc};
use prism_protocol::{
    MAX_VERIFIABLE_TRUST_CLASS, PublicReceipt, ROBINHOOD_CHAIN_ID, ReceiptOutcome, TrustClass,
    receipt_hash_matches, validate_receipt_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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

struct StagedProof {
    set_id: String,
    pages: usize,
    complete: bool,
    index_digest: Option<String>,
    receipt_checks: usize,
    receipt_writes: usize,
}

#[derive(Clone)]
struct PublicationSnapshot {
    set_id: String,
    index_digest: String,
    published_count: i64,
    max_published_at: Option<chrono::DateTime<Utc>>,
}

enum PublicationCompletion {
    Incomplete,
    Complete(String),
}

#[derive(Deserialize)]
struct PublicationMarker {
    version: u8,
    set_id: String,
    receipt_count: usize,
    index_sha256: String,
    state: String,
}

#[derive(Serialize)]
struct ProofIndex<'a> {
    generated_at: chrono::DateTime<Utc>,
    /// Every receipt the index carries, newest first. Kept whole so existing
    /// readers do not have to change.
    receipts: &'a [PublicReceipt],
    /// How many receipts exist, which is not always how many are listed above.
    /// A reader that finds `total` larger than `receipts` is looking at a
    /// truncated window and should walk `pages` instead of assuming the feed
    /// stopped.
    total: usize,
    page_size: usize,
    pages: usize,
    /// First page of the complete set, newest first. `null` when there is
    /// nothing published yet.
    first_page: Option<String>,
}

/// One page of the complete set. `next` is the path to the following page, or
/// `null` on the last one, so a verifier can walk to the end without guessing
/// how many pages exist.
#[derive(Serialize)]
struct ProofPage<'a> {
    page: usize,
    page_size: usize,
    pages: usize,
    total: usize,
    next: Option<String>,
    receipts: &'a [PublicReceipt],
}

/// Small enough that a page is cheap to fetch, large enough that the common
/// case is one request.
const PROOF_PAGE_SIZE: usize = 500;
const PROOF_INDEX_RECEIPT_LIMIT: usize = 1_000;
const MAX_PUBLISHED_RECEIPTS: i64 = 100_000;
const PROOF_WORKER_LOCK: i64 = 4_663_003;
const PROVISIONING_TIMEOUT_REASON: &[u8] = b"prism.provisioning-timeout.v1";
const RECEIPT_ARTIFACT_VERSION: u8 = 2;
const ARTIFACT_DIGEST_METADATA: &str = "prism-sha256";
const INDEX_DIGEST_METADATA: &str = "prism-index-sha256";
const ARTIFACT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

fn proof_pages(receipts: &[PublicReceipt], set_id: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let total = receipts.len();
    let pages = total.div_ceil(PROOF_PAGE_SIZE).max(1);
    let mut out = Vec::new();
    for (i, chunk) in receipts.chunks(PROOF_PAGE_SIZE).enumerate() {
        let page = i + 1;
        let body = ProofPage {
            page,
            page_size: PROOF_PAGE_SIZE,
            pages,
            total,
            next: (page < pages).then(|| format!("sets/{set_id}/pages/{}.json", page + 1)),
            receipts: chunk,
        };
        let bytes = serde_json::to_vec_pretty(&body)?;
        out.push((format!("sets/{set_id}/pages/{page}.json"), bytes));
    }
    Ok(out)
}

fn receipt_reconciliation_key(set_id: &str) -> String {
    format!("sets/{set_id}/receipts-v{RECEIPT_ARTIFACT_VERSION}.json")
}

fn publication_complete_key(set_id: &str) -> String {
    format!("state/sets/{set_id}/publication-v{RECEIPT_ARTIFACT_VERSION}.json")
}

fn artifact_marker(set_id: &str, receipt_count: usize, state: &str) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&serde_json::json!({
        "version": RECEIPT_ARTIFACT_VERSION,
        "set_id": set_id,
        "receipt_count": receipt_count,
        "state": state,
    }))?)
}

fn publication_marker(
    set_id: &str,
    receipt_count: usize,
    index_digest: &str,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&serde_json::json!({
        "version": RECEIPT_ARTIFACT_VERSION,
        "set_id": set_id,
        "receipt_count": receipt_count,
        "index_sha256": index_digest,
        "state": "published",
    }))?)
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
    block_hash: String,
    logs: Vec<ChainLog>,
}

#[derive(Deserialize)]
struct ChainBlock {
    hash: String,
}

#[derive(Deserialize)]
struct ChainLog {
    address: String,
    topics: Vec<String>,
    data: String,
}

struct ChainVerifier {
    client: reqwest::Client,
    rpc_url: url::Url,
    current_block: u64,
    confirmations: u64,
    skip: bool,
}

enum ChainVerification {
    Verified,
    Pending(&'static str),
    Quarantined(&'static str),
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
        anyhow::bail!("DATABASE_URL is required for durable proof publication");
    }
    run_file().await
}

async fn run_file() -> anyhow::Result<()> {
    let source = PathBuf::from(required_env("PRISM_PROOF_RECEIPTS_FILE")?);
    let artifacts = PathBuf::from(required_env("PRISM_PROOF_ARTIFACT_DIR")?);
    let receipts: Vec<PublicReceipt> = serde_json::from_slice(&read_bounded(&source, 10_000_000)?)?;
    validate_receipts(&receipts)?;
    verify_chain_receipts(&receipts).await?;
    publish_authoritative_index(&ArtifactStore::Local(artifacts), &receipts, 0).await?;
    if receipts.is_empty() {
        tracing::info!("no finalized settlement receipts in this proof window");
        return Ok(());
    }
    let digest = build_digest(&receipts)?;
    println!("{}", serde_json::to_string_pretty(&digest)?);
    if !x_digest_posting_enabled() {
        return Ok(());
    }
    let outbox = PathBuf::from(required_env("PRISM_PROOF_OUTBOX_FILE")?);
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
    let identity_columns: i64 = query_scalar(
        "SELECT COUNT(*)::bigint FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'proof_receipts' \
           AND column_name IN ('escrow_address', 'chain_lease_id', 'publication_state')",
    )
    .fetch_one(&pool)
    .await?;
    if identity_columns != 3 {
        anyhow::bail!("proof receipt identity migration has not been applied");
    }
    let mut singleton = pool.acquire().await?;
    let acquired: bool = query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(PROOF_WORKER_LOCK)
        .fetch_one(&mut *singleton)
        .await?;
    if !acquired {
        anyhow::bail!("another database proof worker is already running");
    }
    let artifacts = ArtifactStore::from_environment().await?;
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    let post_x_digests = x_digest_posting_enabled();
    let mut shutdown = spawn_shutdown_listener()?;
    let mut publication_snapshot = None;
    loop {
        if shutdown.is_finished() {
            (&mut shutdown)
                .await
                .context("proof shutdown listener failed")?;
            tracing::info!("proof worker stopped before starting another batch");
            return Ok(());
        }
        let index_ready =
            publish_pending_receipts(&pool, &artifacts, &shutdown, &mut publication_snapshot)
                .await?;
        if shutdown.is_finished() {
            (&mut shutdown)
                .await
                .context("proof shutdown listener failed")?;
            tracing::info!("proof worker stopped after completing its active batch");
            return Ok(());
        }
        if index_ready && post_x_digests {
            tokio::select! {
                result = &mut shutdown => {
                    result.context("proof shutdown listener failed")?;
                    tracing::info!("proof worker stopped before optional X delivery");
                    return Ok(());
                }
                result = async {
                    queue_daily_digest(&pool).await?;
                    if let Err(error) = deliver_daily_digest(&pool).await {
                        tracing::error!(%error, "daily proof digest delivery failed");
                    }
                    Ok::<(), anyhow::Error>(())
                } => result?,
            }
        }
        if run_once {
            return Ok(());
        }
        tokio::select! {
            result = &mut shutdown => {
                result.context("proof shutdown listener failed")?;
                tracing::info!("proof worker received a shutdown signal");
                return Ok(());
            }
            () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
        }
    }
}

#[cfg(unix)]
fn spawn_shutdown_listener() -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }))
}

#[cfg(not(unix))]
fn spawn_shutdown_listener() -> anyhow::Result<tokio::task::JoinHandle<()>> {
    Ok(tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

async fn publish_pending_receipts(
    pool: &PgPool,
    store: &ArtifactStore,
    shutdown: &tokio::task::JoinHandle<()>,
    publication_snapshot: &mut Option<PublicationSnapshot>,
) -> anyhow::Result<bool> {
    let pending = query_as::<_, (Uuid, String, i64, SqlJson<PublicReceipt>)>(
        "SELECT receipt_id, escrow_address, chain_lease_id, document \
         FROM proof_receipts WHERE publication_state = 'pending' \
         ORDER BY block_number, receipt_id LIMIT 1000",
    )
    .fetch_all(pool)
    .await?;
    if shutdown.is_finished() {
        tracing::info!("proof receipt batch stopped before chain verification");
        return Ok(false);
    }
    if pending.is_empty() {
        if let Some(snapshot) = publication_snapshot.as_ref() {
            let (published_count, max_published_at) =
                query_as::<_, (i64, Option<chrono::DateTime<Utc>>)>(
                    "SELECT COUNT(*)::bigint, MAX(published_at) FROM proof_receipts \
                     WHERE publication_state = 'published'",
                )
                .fetch_one(pool)
                .await?;
            if !publication_snapshot_matches(snapshot, published_count, max_published_at) {
                *publication_snapshot = None;
            }
        }
        if let Some(snapshot) = publication_snapshot.as_ref() {
            let Some(completion) = store
                .publication_complete(&snapshot.set_id, Some(shutdown))
                .await?
            else {
                return Ok(false);
            };
            if matches!(
                completion,
                PublicationCompletion::Complete(ref index_digest)
                    if index_digest == &snapshot.index_digest
            ) {
                return Ok(true);
            }
        }
    }
    *publication_snapshot = None;
    let verifier = if pending.is_empty() {
        None
    } else {
        Some(ChainVerifier::from_environment(false).await?)
    };
    for (receipt_id, escrow_address, chain_lease_id, SqlJson(receipt)) in pending {
        if shutdown.is_finished() {
            tracing::info!("proof receipt batch stopped between receipts");
            return Ok(false);
        }
        let chain_lease_id = match u64::try_from(chain_lease_id) {
            Ok(chain_lease_id) if chain_lease_id > 0 => chain_lease_id,
            _ => {
                quarantine_receipt(pool, receipt_id, "invalid_chain_identity").await?;
                continue;
            }
        };
        if receipt.receipt_id != receipt_id
            || validate_database_identity(&receipt, &escrow_address, chain_lease_id).is_err()
        {
            quarantine_receipt(pool, receipt_id, "receipt_identity_mismatch").await?;
            continue;
        }
        if validate_receipts(std::slice::from_ref(&receipt)).is_err() {
            quarantine_receipt(pool, receipt_id, "malformed_receipt").await?;
            continue;
        }
        let verification = verifier
            .as_ref()
            .expect("pending receipts initialize the verifier")
            .verify(&receipt, &escrow_address, chain_lease_id)
            .await;
        let verification = match verification {
            Ok(verification) => verification,
            Err(error) => {
                tracing::error!(%receipt_id, %error, "proof chain verification deferred");
                continue;
            }
        };
        match verification {
            ChainVerification::Verified => {}
            ChainVerification::Pending(reason) => {
                tracing::info!(%receipt_id, reason, "proof receipt is waiting for chain finality");
                continue;
            }
            ChainVerification::Quarantined(reason) => {
                quarantine_receipt(pool, receipt_id, reason).await?;
                continue;
            }
        }
        if !store
            .put(
                &format!("receipts/{}.json", receipt.receipt_id),
                serde_json::to_vec_pretty(&receipt)?,
                "application/json",
                Some(shutdown),
            )
            .await?
        {
            tracing::info!(%receipt_id, "proof receipt batch stopped during artifact publication");
            return Ok(false);
        }
        let published = query(
            "UPDATE proof_receipts SET publication_state = 'published', \
                 published_at = NOW(), quarantine_reason = NULL \
             WHERE receipt_id = $1 AND escrow_address = $2 AND chain_lease_id = $3 \
               AND publication_state = 'pending'",
        )
        .bind(receipt_id)
        .bind(&escrow_address)
        .bind(i64::try_from(chain_lease_id)?)
        .execute(pool)
        .await?;
        if published.rows_affected() != 1 {
            anyhow::bail!("proof receipt changed while it was being published");
        }
    }
    let remaining: i64 = query_scalar(
        "SELECT COUNT(*)::bigint FROM proof_receipts WHERE publication_state = 'pending'",
    )
    .fetch_one(pool)
    .await?;
    if shutdown.is_finished() {
        tracing::info!(
            remaining,
            "proof receipt batch stopped before index publication"
        );
        return Ok(false);
    }
    if remaining != 0 {
        if !revoke_unpublished_receipt_artifacts(pool, store, Some(shutdown)).await? {
            tracing::info!(
                remaining,
                "proof receipt revocation stopped during artifact cleanup"
            );
            return Ok(false);
        }
        tracing::info!(
            remaining,
            "preserving the authoritative proof index until verification finishes"
        );
        return Ok(false);
    }
    let Some(snapshot) = rebuild_index(pool, store, shutdown).await? else {
        return Ok(false);
    };
    *publication_snapshot = Some(snapshot);
    Ok(true)
}

async fn revoke_unpublished_receipt_artifacts(
    pool: &PgPool,
    store: &ArtifactStore,
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<bool> {
    let published = query_scalar::<_, Uuid>(
        "SELECT receipt_id FROM proof_receipts WHERE publication_state = 'published'",
    )
    .fetch_all(pool)
    .await?;
    if published.len() > usize::try_from(MAX_PUBLISHED_RECEIPTS)? {
        anyhow::bail!("published proof receipt count exceeds the safe rebuild limit");
    }
    let expected = published
        .into_iter()
        .map(|receipt_id| format!("receipts/{receipt_id}.json"))
        .collect::<HashSet<_>>();
    remove_stale_receipt_artifacts(store, &expected, shutdown).await
}

async fn quarantine_receipt(pool: &PgPool, receipt_id: Uuid, reason: &str) -> anyhow::Result<()> {
    if reason.is_empty() || reason.len() > 128 {
        anyhow::bail!("proof quarantine reason is invalid");
    }
    query(
        "UPDATE proof_receipts SET publication_state = 'quarantined', \
             quarantine_reason = $2, published_at = NULL \
         WHERE receipt_id = $1 AND publication_state <> 'quarantined'",
    )
    .bind(receipt_id)
    .bind(reason)
    .execute(pool)
    .await?;
    tracing::warn!(%receipt_id, reason, "proof receipt quarantined");
    Ok(())
}

fn validate_database_identity(
    receipt: &PublicReceipt,
    escrow_address: &str,
    chain_lease_id: u64,
) -> anyhow::Result<()> {
    validate_receipt_identity(receipt)?;
    let expected_chain_id = chain_lease_id.to_string();
    if receipt.escrow_address.as_deref() != Some(escrow_address)
        || receipt.chain_lease_id.as_deref() != Some(expected_chain_id.as_str())
        || receipt.lease_id != expected_chain_id
    {
        anyhow::bail!("receipt document and row chain identities differ");
    }
    Ok(())
}

fn publication_snapshot_matches(
    snapshot: &PublicationSnapshot,
    published_count: i64,
    max_published_at: Option<chrono::DateTime<Utc>>,
) -> bool {
    snapshot.published_count == published_count && snapshot.max_published_at == max_published_at
}

async fn rebuild_index(
    pool: &PgPool,
    store: &ArtifactStore,
    shutdown: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<Option<PublicationSnapshot>> {
    let expected: i64 = query_scalar(
        "SELECT COUNT(*)::bigint FROM proof_receipts WHERE publication_state = 'published'",
    )
    .fetch_one(pool)
    .await?;
    if !(0..=MAX_PUBLISHED_RECEIPTS).contains(&expected) {
        anyhow::bail!("published proof receipt count exceeds the safe rebuild limit");
    }
    let rows = query_as::<_, (Uuid, String, i64, SqlJson<PublicReceipt>)>(
        "SELECT receipt_id, escrow_address, chain_lease_id, document FROM proof_receipts \
         WHERE publication_state = 'published' \
         ORDER BY block_number DESC, receipt_id DESC",
    )
    .fetch_all(pool)
    .await?;
    if rows.len() != usize::try_from(expected)? {
        tracing::info!(
            "preserving the authoritative proof index after a concurrent receipt change"
        );
        return Ok(None);
    }
    let mut all = Vec::with_capacity(rows.len());
    for (receipt_id, escrow_address, chain_lease_id, SqlJson(receipt)) in rows {
        let valid = u64::try_from(chain_lease_id)
            .ok()
            .is_some_and(|chain_lease_id| {
                chain_lease_id > 0
                    && receipt.receipt_id == receipt_id
                    && validate_database_identity(&receipt, &escrow_address, chain_lease_id).is_ok()
                    && validate_receipts(std::slice::from_ref(&receipt)).is_ok()
            });
        if !valid {
            quarantine_receipt(pool, receipt_id, "published_receipt_invalid").await?;
            continue;
        }
        all.push(receipt);
    }
    if shutdown.is_finished() {
        tracing::info!("proof index rebuild stopped before artifact staging");
        return Ok(None);
    }

    let Some(staged) = stage_proof_artifacts(store, &all, Some(shutdown)).await? else {
        tracing::info!("proof index rebuild stopped during artifact staging");
        return Ok(None);
    };
    if shutdown.is_finished() {
        tracing::info!("proof index rebuild stopped after artifact staging");
        return Ok(None);
    }
    let mut transaction = pool.begin().await?;
    query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *transaction)
        .await?;
    query("LOCK TABLE proof_receipts IN SHARE MODE")
        .execute(&mut *transaction)
        .await?;
    let pending: i64 = query_scalar(
        "SELECT COUNT(*)::bigint FROM proof_receipts WHERE publication_state = 'pending'",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if pending != 0 {
        transaction.commit().await?;
        tracing::info!(
            pending,
            "preserving the authoritative proof index after a concurrent pending receipt"
        );
        return Ok(None);
    }
    let (current_count, max_published_at) = query_as::<_, (i64, Option<chrono::DateTime<Utc>>)>(
        "SELECT COUNT(*)::bigint, MAX(published_at) FROM proof_receipts \
             WHERE publication_state = 'published'",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if !(0..=MAX_PUBLISHED_RECEIPTS).contains(&current_count) {
        anyhow::bail!("published proof receipt count exceeds the safe rebuild limit");
    }
    let current = query_scalar::<_, SqlJson<PublicReceipt>>(
        "SELECT document FROM proof_receipts WHERE publication_state = 'published' \
         ORDER BY block_number DESC, receipt_id DESC",
    )
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|SqlJson(receipt)| receipt)
    .collect::<Vec<_>>();
    if current.len() != usize::try_from(current_count)?
        || proof_artifact_set_id(&current)? != staged.set_id
    {
        transaction.commit().await?;
        tracing::info!("preserving the authoritative proof index after the staged set changed");
        return Ok(None);
    }
    if shutdown.is_finished() {
        transaction.commit().await?;
        tracing::info!("proof index rebuild stopped before authoritative publication");
        return Ok(None);
    }

    if staged.complete {
        transaction.commit().await?;
        return Ok(Some(PublicationSnapshot {
            set_id: staged.set_id,
            index_digest: staged
                .index_digest
                .context("completed proof staging has no index digest")?,
            published_count: current_count,
            max_published_at,
        }));
    }
    tracing::info!(
        receipt_checks = staged.receipt_checks,
        receipt_writes = staged.receipt_writes,
        proof_set = %staged.set_id,
        "proof artifacts staged"
    );
    let Some(index_digest) = publish_staged_index(store, &all, &staged, Some(shutdown)).await?
    else {
        transaction.commit().await?;
        tracing::info!("proof index rebuild stopped during authoritative publication");
        return Ok(None);
    };
    transaction.commit().await?;
    if !remove_obsolete_artifacts(store, &all, Some(shutdown)).await? {
        tracing::info!("proof index rebuild stopped during obsolete artifact cleanup");
        return Ok(None);
    }
    if !mark_publication_complete(store, &staged, all.len(), &index_digest, Some(shutdown)).await? {
        tracing::info!("proof index rebuild stopped before recording publication completion");
        return Ok(None);
    }
    Ok(Some(PublicationSnapshot {
        set_id: staged.set_id,
        index_digest,
        published_count: current_count,
        max_published_at,
    }))
}

async fn queue_daily_digest(pool: &PgPool) -> anyhow::Result<()> {
    let window = Utc::now()
        .date_naive()
        .checked_sub_days(Days::new(1))
        .context("daily proof window underflowed")?;
    let receipts = query_scalar::<_, SqlJson<PublicReceipt>>(
        "SELECT document FROM proof_receipts \
         WHERE publication_state = 'published' \
           AND created_at >= $1::date AND created_at < ($1::date + INTERVAL '1 day') \
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
        validate_receipt_identity(receipt)?;
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
        if receipt
            .trust_class
            .is_some_and(|class| class > MAX_VERIFIABLE_TRUST_CLASS)
        {
            anyhow::bail!("public receipt claims a trust class the network cannot verify");
        }
        // A class at or above `Attested` is a statement about verified evidence,
        // so a receipt making one has to carry the digest that backs it. Kept
        // separate from the ceiling check above so raising the ceiling does not
        // silently let unbacked claims through.
        if receipt
            .trust_class
            .is_some_and(|class| class >= TrustClass::Attested)
            && receipt.attestation.is_none()
        {
            anyhow::bail!("public receipt claims an attested class with no attestation");
        }
        if receipt.attestation.as_ref().is_some_and(|attestation| {
            !is_digest(&attestation.verdict_digest)
                || attestation.verifier_version.is_empty()
                || attestation.verifier_version.len() > 64
        }) {
            anyhow::bail!("public receipt contains a malformed attestation");
        }
        if receipt.repro.as_ref().is_some_and(|repro| {
            receipt.outcome != ReceiptOutcome::Finalized
                || !is_lower_digest(&repro.token_hash)
                || !is_lower_digest(&repro.spec_hash)
                || !is_lower_image_digest(&repro.image_digest)
                || !is_lower_digest(&repro.command_hash)
                || !is_lower_digest(&repro.result_hash)
                || !is_lower_digest(&repro.stdout_hash)
                || !is_lower_digest(&repro.stderr_hash)
                || !is_lower_digest(&repro.report_hash)
                || !(-255..=255).contains(&repro.exit_code)
                || !(0..=255).contains(&repro.expected_exit_code)
                || repro.succeeded != (repro.exit_code == repro.expected_exit_code)
        }) {
            anyhow::bail!("public receipt contains malformed repro evidence");
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
    let verifier = ChainVerifier::from_environment(true).await?;
    if verifier.skip {
        return Ok(());
    }
    let fallback_escrow = env::var("PRISM_LEASE_ESCROW_ADDRESS")
        .ok()
        .filter(|value| is_address(value))
        .map(|value| value.to_ascii_lowercase());
    for receipt in receipts {
        let (escrow_address, chain_lease_id) = match (
            receipt.escrow_address.as_deref(),
            receipt.chain_lease_id.as_deref(),
        ) {
            (Some(escrow_address), Some(chain_lease_id)) => {
                validate_receipt_identity(receipt)?;
                (escrow_address.to_owned(), chain_lease_id.parse::<u64>()?)
            }
            (None, None) => (
                fallback_escrow
                    .clone()
                    .context("PRISM_LEASE_ESCROW_ADDRESS is required for legacy file receipts")?,
                receipt
                    .lease_id
                    .parse::<u64>()
                    .context("receipt lease ID is not a contract uint")?,
            ),
            _ => anyhow::bail!("public receipt chain identity is incomplete"),
        };
        match verifier
            .verify(receipt, &escrow_address, chain_lease_id)
            .await?
        {
            ChainVerification::Verified => {}
            ChainVerification::Pending(reason) | ChainVerification::Quarantined(reason) => {
                anyhow::bail!("proof receipt failed chain verification: {reason}")
            }
        }
    }
    Ok(())
}

impl ChainVerifier {
    async fn from_environment(allow_unverified: bool) -> anyhow::Result<Self> {
        let rpc_url = env::var("PRISM_RPC_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let Some(rpc_url) = rpc_url else {
            if allow_unverified && env::var("PRISM_ALLOW_UNVERIFIED_PROOF").as_deref() == Ok("1") {
                tracing::warn!("skipping chain receipt verification in local development");
                return Ok(Self {
                    client: reqwest::Client::new(),
                    rpc_url: url::Url::parse("http://localhost")?,
                    current_block: 0,
                    confirmations: 1,
                    skip: true,
                });
            }
            anyhow::bail!("PRISM_RPC_URL is required for proof publication");
        };
        let rpc_url = secure_rpc_url(&rpc_url)?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let chain_id =
            rpc_quantity(&client, &rpc_url, "eth_chainId", serde_json::json!([])).await?;
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
        Ok(Self {
            client,
            rpc_url,
            current_block,
            confirmations,
            skip: false,
        })
    }

    async fn verify(
        &self,
        receipt: &PublicReceipt,
        escrow_address: &str,
        chain_lease_id: u64,
    ) -> anyhow::Result<ChainVerification> {
        if self.skip {
            return Ok(ChainVerification::Verified);
        }
        let chain_receipt: Option<TransactionReceipt> = rpc_call(
            &self.client,
            &self.rpc_url,
            "eth_getTransactionReceipt",
            serde_json::json!([receipt.transaction_hash]),
        )
        .await?;
        let Some(chain_receipt) = chain_receipt else {
            return Ok(ChainVerification::Pending("transaction_not_mined"));
        };
        let block = parse_quantity(&chain_receipt.block_number)?;
        if self.current_block < block.saturating_add(self.confirmations) {
            return Ok(ChainVerification::Pending("confirmation_threshold"));
        }
        let canonical_block: Option<ChainBlock> = rpc_call(
            &self.client,
            &self.rpc_url,
            "eth_getBlockByNumber",
            serde_json::json!([chain_receipt.block_number, false]),
        )
        .await?;
        let Some(canonical_block) = canonical_block else {
            return Ok(ChainVerification::Pending("canonical_block_unavailable"));
        };
        if !has_canonical_finality(
            self.current_block,
            block,
            self.confirmations,
            &chain_receipt.block_hash,
            &canonical_block.hash,
        ) {
            return Ok(ChainVerification::Pending(
                "noncanonical_transaction_receipt",
            ));
        }
        if parse_quantity(&chain_receipt.status)? != 1 {
            return Ok(ChainVerification::Quarantined(
                "finalized_transaction_reverted",
            ));
        }
        if verify_settlement_event(receipt, escrow_address, chain_lease_id, &chain_receipt.logs)
            .is_err()
        {
            return Ok(ChainVerification::Quarantined("settlement_event_mismatch"));
        }
        Ok(ChainVerification::Verified)
    }
}

fn verify_settlement_event(
    receipt: &PublicReceipt,
    escrow: &str,
    chain_lease_id: u64,
    logs: &[ChainLog],
) -> anyhow::Result<()> {
    let expected_topic = format!("0x{:064x}", chain_lease_id);
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
            match receipt.failure_class.as_deref() {
                Some("provisioning_timeout")
                    if data[32..64] == Keccak256::digest(PROVISIONING_TIMEOUT_REASON)[..] => {}
                None => {}
                Some("provisioning_timeout") => {
                    anyhow::bail!("refund reason does not match the provisioning timeout")
                }
                Some(_) => anyhow::bail!("refund receipt contains an unsupported failure class"),
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

async fn publish_authoritative_index(
    store: &ArtifactStore,
    receipts: &[PublicReceipt],
    pending_receipts: i64,
) -> anyhow::Result<bool> {
    if pending_receipts != 0 {
        return Ok(false);
    }
    let staged = stage_proof_artifacts(store, receipts, None)
        .await?
        .context("uninterruptible proof staging stopped unexpectedly")?;
    if staged.complete {
        return Ok(true);
    }
    let Some(index_digest) = publish_staged_index(store, receipts, &staged, None).await? else {
        anyhow::bail!("uninterruptible proof index publication stopped unexpectedly");
    };
    if !remove_obsolete_artifacts(store, receipts, None).await? {
        anyhow::bail!("uninterruptible proof cleanup stopped unexpectedly");
    }
    if !mark_publication_complete(store, &staged, receipts.len(), &index_digest, None).await? {
        anyhow::bail!("uninterruptible proof completion marker stopped unexpectedly");
    }
    Ok(true)
}

async fn stage_proof_artifacts(
    store: &ArtifactStore,
    receipts: &[PublicReceipt],
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<Option<StagedProof>> {
    if receipts.len() > usize::try_from(MAX_PUBLISHED_RECEIPTS)? {
        anyhow::bail!("published proof receipt count exceeds the safe rebuild limit");
    }
    let set_id = proof_artifact_set_id(receipts)?;
    let Some(completion) = store.publication_complete(&set_id, shutdown).await? else {
        return Ok(None);
    };
    if let PublicationCompletion::Complete(index_digest) = completion {
        return Ok(Some(StagedProof {
            set_id,
            pages: receipts.len().div_ceil(PROOF_PAGE_SIZE),
            complete: true,
            index_digest: Some(index_digest),
            receipt_checks: 0,
            receipt_writes: 0,
        }));
    }

    let pages = proof_pages(receipts, &set_id)?;
    let reconciliation_key = receipt_reconciliation_key(&set_id);
    let reconciliation_body = artifact_marker(&set_id, receipts.len(), "receipts_reconciled")?;
    let Some(reconciled) = store
        .artifact_is_current(
            &reconciliation_key,
            &reconciliation_body,
            "application/json",
            shutdown,
        )
        .await?
    else {
        return Ok(None);
    };
    let mut receipt_checks = 0;
    let mut receipt_writes = 0;
    if !reconciled {
        for receipt in receipts {
            if publication_cancelled(shutdown).await {
                return Ok(None);
            }
            let key = format!("receipts/{}.json", receipt.receipt_id);
            let body = serde_json::to_vec_pretty(receipt)?;
            let Some(current) = store.receipt_is_current(&key, &body, shutdown).await? else {
                return Ok(None);
            };
            receipt_checks += 1;
            if !current {
                if !store.put(&key, body, "application/json", shutdown).await? {
                    return Ok(None);
                }
                receipt_writes += 1;
            }
        }
        if !store
            .put(
                &reconciliation_key,
                reconciliation_body,
                "application/json",
                shutdown,
            )
            .await?
        {
            return Ok(None);
        }
    }
    let page_prefix = format!("sets/{set_id}/pages/");
    let Some(existing_pages) = store.list(&page_prefix, shutdown).await? else {
        return Ok(None);
    };
    let existing_pages = existing_pages.into_iter().collect::<HashSet<_>>();
    for (key, body) in &pages {
        if publication_cancelled(shutdown).await {
            return Ok(None);
        }
        if !existing_pages.contains(key)
            && !store
                .put(key, body.clone(), "application/json", shutdown)
                .await?
        {
            return Ok(None);
        }
    }
    Ok(Some(StagedProof {
        set_id,
        pages: pages.len(),
        complete: false,
        index_digest: None,
        receipt_checks,
        receipt_writes,
    }))
}

async fn publish_staged_index(
    store: &ArtifactStore,
    receipts: &[PublicReceipt],
    staged: &StagedProof,
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<Option<String>> {
    let visible = &receipts[..receipts.len().min(PROOF_INDEX_RECEIPT_LIMIT)];
    let body = serde_json::to_vec_pretty(&ProofIndex {
        generated_at: Utc::now(),
        receipts: visible,
        total: receipts.len(),
        page_size: PROOF_PAGE_SIZE,
        pages: staged.pages,
        first_page: (!receipts.is_empty()).then(|| format!("sets/{}/pages/1.json", staged.set_id)),
    })?;
    let digest = hex::encode(Sha256::digest(&body));
    if !store
        .put("index.json", body, "application/json", shutdown)
        .await?
    {
        return Ok(None);
    }
    Ok(Some(digest))
}

async fn mark_publication_complete(
    store: &ArtifactStore,
    staged: &StagedProof,
    receipt_count: usize,
    index_digest: &str,
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<bool> {
    store
        .put_with_metadata(
            &publication_complete_key(&staged.set_id),
            publication_marker(&staged.set_id, receipt_count, index_digest)?,
            "application/json",
            Some((INDEX_DIGEST_METADATA, index_digest)),
            shutdown,
        )
        .await
}

async fn remove_obsolete_artifacts(
    store: &ArtifactStore,
    receipts: &[PublicReceipt],
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<bool> {
    let expected_receipts: HashSet<String> = receipts
        .iter()
        .map(|receipt| format!("receipts/{}.json", receipt.receipt_id))
        .collect();
    if !remove_stale_receipt_artifacts(store, &expected_receipts, shutdown).await? {
        return Ok(false);
    }
    let Some(legacy_pages) = store.list("pages/", shutdown).await? else {
        return Ok(false);
    };
    for key in legacy_pages {
        if publication_cancelled(shutdown).await {
            return Ok(false);
        }
        if key.ends_with(".json") && !store.delete(&key, shutdown).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn remove_stale_receipt_artifacts(
    store: &ArtifactStore,
    expected_receipts: &HashSet<String>,
    shutdown: Option<&tokio::task::JoinHandle<()>>,
) -> anyhow::Result<bool> {
    let Some(receipts) = store.list("receipts/", shutdown).await? else {
        return Ok(false);
    };
    for key in receipts {
        if publication_cancelled(shutdown).await {
            return Ok(false);
        }
        if key.ends_with(".json")
            && !expected_receipts.contains(&key)
            && !store.delete(&key, shutdown).await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn publication_cancelled(shutdown: Option<&tokio::task::JoinHandle<()>>) -> bool {
    let Some(shutdown) = shutdown else {
        return false;
    };
    tokio::task::yield_now().await;
    shutdown.is_finished()
}

async fn artifact_operation<T>(
    shutdown: Option<&tokio::task::JoinHandle<()>>,
    operation: impl Future<Output = T>,
    description: &'static str,
) -> anyhow::Result<Option<T>> {
    let operation = tokio::time::timeout(ARTIFACT_OPERATION_TIMEOUT, operation);
    if let Some(shutdown) = shutdown {
        tokio::select! {
            result = operation => Ok(Some(result.with_context(|| format!("{description} timed out"))?)),
            () = wait_for_publication_shutdown(shutdown) => Ok(None),
        }
    } else {
        Ok(Some(
            operation
                .await
                .with_context(|| format!("{description} timed out"))?,
        ))
    }
}

async fn wait_for_publication_shutdown(shutdown: &tokio::task::JoinHandle<()>) {
    while !shutdown.is_finished() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

    async fn put(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<bool> {
        self.put_with_metadata(key, body, content_type, None, shutdown)
            .await
    }

    async fn put_with_metadata(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
        metadata: Option<(&str, &str)>,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<bool> {
        validate_artifact_key(key)?;
        if publication_cancelled(shutdown).await {
            return Ok(false);
        }
        match self {
            Self::S3 { client, bucket } => {
                let artifact_digest = hex::encode(Sha256::digest(&body));
                let mut request = client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .body(ByteStream::from(body))
                    .content_type(content_type)
                    .cache_control(artifact_cache_control(key))
                    .metadata(ARTIFACT_DIGEST_METADATA, artifact_digest);
                if let Some((name, value)) = metadata {
                    request = request.metadata(name, value);
                }
                let Some(result) =
                    artifact_operation(shutdown, request.send(), "S3 proof artifact put").await?
                else {
                    return Ok(false);
                };
                result?;
            }
            Self::Local(root) => {
                let path = root.join(key);
                atomic_write(&path, &body)?;
            }
        }
        Ok(true)
    }

    async fn delete(
        &self,
        key: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<bool> {
        validate_artifact_key(key)?;
        if publication_cancelled(shutdown).await {
            return Ok(false);
        }
        match self {
            Self::S3 { client, bucket } => {
                let request = client.delete_object().bucket(bucket).key(key).send();
                let Some(result) =
                    artifact_operation(shutdown, request, "S3 proof artifact deletion").await?
                else {
                    return Ok(false);
                };
                result?;
            }
            Self::Local(root) => {
                let path = root.join(key);
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(true)
    }

    async fn publication_complete(
        &self,
        set_id: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<Option<PublicationCompletion>> {
        let marker_key = publication_complete_key(set_id);
        match self {
            Self::Local(root) => {
                if publication_cancelled(shutdown).await {
                    return Ok(None);
                }
                let marker: PublicationMarker = match fs::read(root.join(&marker_key)) {
                    Ok(body) => match serde_json::from_slice(&body) {
                        Ok(marker) => marker,
                        Err(_) => return Ok(Some(PublicationCompletion::Incomplete)),
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(Some(PublicationCompletion::Incomplete));
                    }
                    Err(error) => return Err(error.into()),
                };
                let marker_valid = marker.version == RECEIPT_ARTIFACT_VERSION
                    && marker.set_id == set_id
                    && marker.receipt_count <= usize::try_from(MAX_PUBLISHED_RECEIPTS)?
                    && marker.state == "published"
                    && is_lower_digest(&marker.index_sha256);
                if !marker_valid {
                    return Ok(Some(PublicationCompletion::Incomplete));
                }
                let Some(index_current) = self
                    .index_is_current(&marker.index_sha256, shutdown)
                    .await?
                else {
                    return Ok(None);
                };
                if !index_current {
                    return Ok(Some(PublicationCompletion::Incomplete));
                }
                Ok(Some(PublicationCompletion::Complete(marker.index_sha256)))
            }
            Self::S3 { client, bucket } => {
                let request = client.head_object().bucket(bucket).key(&marker_key).send();
                let Some(result) =
                    artifact_operation(shutdown, request, "S3 proof publication marker lookup")
                        .await?
                else {
                    return Ok(None);
                };
                let marker = match result {
                    Ok(marker) => marker,
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|error| error.is_not_found()) =>
                    {
                        return Ok(Some(PublicationCompletion::Incomplete));
                    }
                    Err(error) => return Err(error.into()),
                };
                let index_digest = marker
                    .metadata()
                    .and_then(|metadata| metadata.get(INDEX_DIGEST_METADATA))
                    .filter(|digest| is_lower_digest(digest))
                    .cloned();
                let Some(index_digest) = index_digest else {
                    return Ok(Some(PublicationCompletion::Incomplete));
                };
                if marker.cache_control() != Some(artifact_cache_control(&marker_key))
                    || marker.content_type() != Some("application/json")
                {
                    return Ok(Some(PublicationCompletion::Incomplete));
                }
                let Some(index_current) = self.index_is_current(&index_digest, shutdown).await?
                else {
                    return Ok(None);
                };
                if !index_current {
                    return Ok(Some(PublicationCompletion::Incomplete));
                }
                Ok(Some(PublicationCompletion::Complete(index_digest)))
            }
        }
    }

    async fn index_is_current(
        &self,
        expected_digest: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<Option<bool>> {
        if !is_lower_digest(expected_digest) {
            return Ok(Some(false));
        }
        if publication_cancelled(shutdown).await {
            return Ok(None);
        }
        match self {
            Self::Local(root) => match fs::read(root.join("index.json")) {
                Ok(body) => Ok(Some(hex::encode(Sha256::digest(body)) == expected_digest)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(false)),
                Err(error) => Err(error.into()),
            },
            Self::S3 { client, bucket } => {
                let request = client.head_object().bucket(bucket).key("index.json").send();
                let Some(result) =
                    artifact_operation(shutdown, request, "S3 proof index lookup").await?
                else {
                    return Ok(None);
                };
                match result {
                    Ok(index) => {
                        let current = index.cache_control()
                            == Some(artifact_cache_control("index.json"))
                            && index.content_type() == Some("application/json")
                            && index.metadata().and_then(|metadata| {
                                metadata.get(ARTIFACT_DIGEST_METADATA).map(String::as_str)
                            }) == Some(expected_digest);
                        Ok(Some(current))
                    }
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|error| error.is_not_found()) =>
                    {
                        Ok(Some(false))
                    }
                    Err(error) => Err(error.into()),
                }
            }
        }
    }

    async fn artifact_is_current(
        &self,
        key: &str,
        body: &[u8],
        content_type: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<Option<bool>> {
        validate_artifact_key(key)?;
        if publication_cancelled(shutdown).await {
            return Ok(None);
        }
        match self {
            Self::Local(root) => match fs::read(root.join(key)) {
                Ok(existing) => Ok(Some(existing == body)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(false)),
                Err(error) => Err(error.into()),
            },
            Self::S3 { client, bucket } => {
                let request = client.head_object().bucket(bucket).key(key).send();
                let Some(result) =
                    artifact_operation(shutdown, request, "S3 proof artifact metadata lookup")
                        .await?
                else {
                    return Ok(None);
                };
                match result {
                    Ok(head) => {
                        let digest = hex::encode(Sha256::digest(body));
                        let current = head.cache_control() == Some(artifact_cache_control(key))
                            && head.content_type() == Some(content_type)
                            && head.metadata().and_then(|metadata| {
                                metadata.get(ARTIFACT_DIGEST_METADATA).map(String::as_str)
                            }) == Some(digest.as_str());
                        Ok(Some(current))
                    }
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|error| error.is_not_found()) =>
                    {
                        Ok(Some(false))
                    }
                    Err(error) => Err(error.into()),
                }
            }
        }
    }

    async fn receipt_is_current(
        &self,
        key: &str,
        body: &[u8],
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<Option<bool>> {
        if !key.starts_with("receipts/") || !key.ends_with(".json") {
            anyhow::bail!("receipt artifact key is invalid");
        }
        self.artifact_is_current(key, body, "application/json", shutdown)
            .await
    }

    async fn list(
        &self,
        prefix: &str,
        shutdown: Option<&tokio::task::JoinHandle<()>>,
    ) -> anyhow::Result<Option<Vec<String>>> {
        validate_artifact_prefix(prefix)?;
        if publication_cancelled(shutdown).await {
            return Ok(None);
        }
        match self {
            Self::Local(root) => {
                let directory = root.join(prefix.trim_end_matches('/'));
                let entries = match fs::read_dir(directory) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(Some(Vec::new()));
                    }
                    Err(error) => return Err(error.into()),
                };
                let mut keys = Vec::new();
                for entry in entries {
                    if publication_cancelled(shutdown).await {
                        return Ok(None);
                    }
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        keys.push(format!("{prefix}{}", entry.file_name().to_string_lossy()));
                    }
                }
                Ok(Some(keys))
            }
            Self::S3 { client, bucket } => {
                let mut keys = Vec::new();
                let mut continuation_token = None;
                loop {
                    if publication_cancelled(shutdown).await {
                        return Ok(None);
                    }
                    let mut request = client.list_objects_v2().bucket(bucket).prefix(prefix);
                    if let Some(token) = continuation_token.as_deref() {
                        request = request.continuation_token(token);
                    }
                    let Some(response) =
                        artifact_operation(shutdown, request.send(), "S3 proof artifact listing")
                            .await?
                    else {
                        return Ok(None);
                    };
                    let response = response?;
                    keys.extend(
                        response
                            .contents()
                            .iter()
                            .filter_map(|object| object.key().map(ToOwned::to_owned)),
                    );
                    if response.is_truncated() != Some(true) {
                        break;
                    }
                    continuation_token = response.next_continuation_token().map(ToOwned::to_owned);
                    if continuation_token.is_none() {
                        anyhow::bail!("S3 proof listing ended without a continuation token");
                    }
                }
                Ok(Some(keys))
            }
        }
    }
}

fn validate_artifact_key(key: &str) -> anyhow::Result<()> {
    if key.is_empty() || key.starts_with('/') || key.ends_with('/') || key.contains("..") {
        anyhow::bail!("proof artifact key is invalid");
    }
    Ok(())
}

fn validate_artifact_prefix(prefix: &str) -> anyhow::Result<()> {
    if prefix.is_empty()
        || prefix.starts_with('/')
        || !prefix.ends_with('/')
        || prefix.contains("..")
    {
        anyhow::bail!("proof artifact prefix is invalid");
    }
    Ok(())
}

fn artifact_cache_control(key: &str) -> &'static str {
    if key == "index.json" || key.starts_with("state/") {
        "no-cache"
    } else if key.starts_with("sets/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=30"
    }
}

fn is_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn has_canonical_finality(
    current_block: u64,
    receipt_block: u64,
    confirmations: u64,
    receipt_block_hash: &str,
    canonical_block_hash: &str,
) -> bool {
    current_block >= receipt_block.saturating_add(confirmations)
        && is_hash(receipt_block_hash)
        && is_hash(canonical_block_hash)
        && receipt_block_hash.eq_ignore_ascii_case(canonical_block_hash)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_lower_digest)
}

fn x_digest_posting_enabled() -> bool {
    env::var("PRISM_ENABLE_X_DIGEST_POSTING").as_deref() == Ok("1")
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

fn proof_artifact_set_id(receipts: &[PublicReceipt]) -> anyhow::Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(receipts)?)))
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
    use prism_protocol::{
        AttestationKind, PublicReceipt, ReceiptAttestation, ReceiptOutcome, ReproExecutor,
        ReproReceiptEvidence, receipt_hash,
    };

    #[test]
    fn digest_uses_only_finalized_charges() {
        let receipts = vec![
            PublicReceipt {
                receipt_id: Uuid::now_v7(),
                lease_id: "1".to_owned(),
                escrow_address: None,
                chain_lease_id: None,
                node_id_hash: "n".to_owned(),
                gpu_model: "GPU".to_owned(),
                runtime_seconds: 3_600,
                charged_base_units: 1_250_000,
                refunded_base_units: 250_000,
                provider_paid_base_units: 1_125_000,
                failure_class: None,
                credited_seconds: None,
                outcome: ReceiptOutcome::Finalized,
                trust_class: None,
                attestation: None,
                repro: None,
                receipt_hash: String::new(),
                transaction_hash: format!("0x{}", "a".repeat(64)),
            },
            PublicReceipt {
                receipt_id: Uuid::now_v7(),
                lease_id: "2".to_owned(),
                escrow_address: None,
                chain_lease_id: None,
                node_id_hash: "n".to_owned(),
                gpu_model: "GPU".to_owned(),
                runtime_seconds: 0,
                charged_base_units: 0,
                refunded_base_units: 500_000,
                provider_paid_base_units: 0,
                failure_class: Some("provisioning_timeout".to_owned()),
                credited_seconds: None,
                outcome: ReceiptOutcome::Refunded,
                trust_class: None,
                attestation: None,
                repro: None,
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
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: format!("0x{}", "a".repeat(64)),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000_000,
            refunded_base_units: 0,
            provider_paid_base_units: 1,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", "b".repeat(64)),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(validate_receipts(&[receipt]).is_err());
    }

    /// `Confidential` is the one class left above the ceiling, and a receipt
    /// carrying perfectly well-formed evidence for it is still refused. The
    /// evidence is what makes this worth asserting: the receipt fails on the
    /// class alone.
    #[test]
    fn a_confidential_receipt_is_valid_with_its_backing_and_rejected_without() {
        // The ceiling now reaches Confidential, so a receipt claiming it is
        // accepted when it carries the attestation digest that backs the claim.
        let mut backed = valid_receipt("1", 'a');
        backed.trust_class = Some(TrustClass::Confidential);
        backed.attestation = Some(attestation());
        backed.receipt_hash = receipt_hash(&backed).unwrap();
        assert!(validate_receipts(&[backed]).is_ok());

        // The same claim without the digest is an unbacked claim and is refused.
        let mut unbacked = valid_receipt("2", 'b');
        unbacked.trust_class = Some(TrustClass::Confidential);
        unbacked.attestation = None;
        unbacked.receipt_hash = receipt_hash(&unbacked).unwrap();
        assert!(
            validate_receipts(&[unbacked]).is_err(),
            "confidential claimed without a backing digest"
        );
    }

    #[test]
    fn receipt_validation_rejects_an_attested_class_with_no_attestation() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.trust_class = Some(TrustClass::Attested);
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        assert!(validate_receipts(&[receipt]).is_err());
    }

    /// Every receipt published so far predates attestation and carries none.
    /// The new rules have to leave those alone, or turning them on retracts
    /// artifacts that are already committed on chain.
    #[test]
    fn receipt_validation_still_accepts_the_classes_served_today() {
        for class in [
            None,
            Some(TrustClass::Open),
            Some(MAX_VERIFIABLE_TRUST_CLASS),
        ] {
            let mut receipt = valid_receipt("1", 'a');
            receipt.trust_class = class;
            if class.is_some_and(|class| class >= TrustClass::Attested) {
                receipt.attestation = Some(attestation());
            }
            receipt.receipt_hash = receipt_hash(&receipt).unwrap();
            validate_receipts(&[receipt]).unwrap();
        }
    }

    #[test]
    fn receipt_validation_rejects_a_malformed_attestation() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.trust_class = Some(TrustClass::Isolated);
        receipt.attestation = Some(ReceiptAttestation {
            verdict_digest: "not-a-digest".to_owned(),
            ..attestation()
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        assert!(validate_receipts(&[receipt]).is_err());
    }

    #[test]
    fn receipt_validation_accepts_anchored_node_repro_commitments() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.repro = Some(repro());
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        validate_receipts(&[receipt]).unwrap();
    }

    #[test]
    fn receipt_validation_rejects_inconsistent_repro_outcomes() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.repro = Some(ReproReceiptEvidence {
            succeeded: false,
            ..repro()
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(validate_receipts(&[receipt]).is_err());
    }

    #[test]
    fn receipt_validation_rejects_noncanonical_repro_hashes() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.repro = Some(ReproReceiptEvidence {
            report_hash: "A".repeat(64),
            ..repro()
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(validate_receipts(&[receipt]).is_err());
    }

    #[test]
    fn receipt_validation_accepts_gateway_verified_managed_repro() {
        let mut receipt = valid_receipt("1", 'a');
        receipt.repro = Some(ReproReceiptEvidence {
            executor: ReproExecutor::Managed,
            ..repro()
        });
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        validate_receipts(&[receipt]).unwrap();
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
        assert!(verify_settlement_event(&receipt, &escrow, 1, &[log]).is_ok());

        receipt.provider_paid_base_units -= 1;
        assert!(
            verify_settlement_event(
                &receipt,
                &escrow,
                1,
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
    fn refund_event_binds_the_worker_failure_reason_not_the_receipt_hash() {
        assert_eq!(
            hex::encode(Keccak256::digest(PROVISIONING_TIMEOUT_REASON)),
            "9f1f4b0aec6dde9a1e7725bf64aa4c6bf61cb16c5854f71dd6014bf44ab42eea"
        );
        let mut receipt = valid_receipt("3", 'c');
        receipt.runtime_seconds = 0;
        receipt.charged_base_units = 0;
        receipt.refunded_base_units = 1_000_000;
        receipt.provider_paid_base_units = 0;
        receipt.failure_class = Some("provisioning_timeout".to_owned());
        receipt.outcome = ReceiptOutcome::Refunded;
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        let mut amount = [0_u8; 32];
        amount[24..].copy_from_slice(&receipt.refunded_base_units.to_be_bytes());
        let mut data = amount.to_vec();
        data.extend_from_slice(&Keccak256::digest(PROVISIONING_TIMEOUT_REASON));
        let escrow = format!("0x{}", "1".repeat(40));
        let log = |data: &[u8]| ChainLog {
            address: escrow.clone(),
            topics: vec![
                event_topic("LeaseRefunded(uint256,uint256,bytes32)"),
                format!("0x{:064x}", 3),
            ],
            data: format!("0x{}", hex::encode(data)),
        };

        assert!(verify_settlement_event(&receipt, &escrow, 3, &[log(&data)]).is_ok());
        receipt.gpu_model = "legacy corrected model".to_owned();
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        assert!(verify_settlement_event(&receipt, &escrow, 3, &[log(&data)]).is_ok());
        data[63] ^= 1;
        assert!(verify_settlement_event(&receipt, &escrow, 3, &[log(&data)]).is_err());

        receipt.failure_class = None;
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        assert!(verify_settlement_event(&receipt, &escrow, 3, &[log(&data)]).is_ok());
    }

    #[test]
    fn same_chain_id_is_verified_against_each_rows_escrow() {
        let mut receipt = valid_receipt("7", 'b');
        let first_escrow = format!("0x{}", "1".repeat(40));
        let second_escrow = format!("0x{}", "2".repeat(40));
        receipt.escrow_address = Some(first_escrow.clone());
        receipt.chain_lease_id = Some("7".to_owned());
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
        let event = |address: String| ChainLog {
            address,
            topics: vec![
                event_topic("LeaseFinalized(uint256,uint256,uint256,uint256,uint256,bytes32)"),
                format!("0x{:064x}", 7),
            ],
            data: format!("0x{}", hex::encode(&data)),
        };
        let logs = [event(second_escrow.clone()), event(first_escrow.clone())];

        validate_database_identity(&receipt, &first_escrow, 7).unwrap();
        assert!(verify_settlement_event(&receipt, &first_escrow, 7, &logs).is_ok());
        assert!(
            verify_settlement_event(&receipt, &format!("0x{}", "3".repeat(40)), 7, &logs).is_err()
        );
        assert!(validate_database_identity(&receipt, &second_escrow, 7).is_err());
    }

    #[test]
    fn a_shallow_reorg_never_finalizes_a_reverted_receipt() {
        let receipt_hash = format!("0x{}", "a".repeat(64));
        let replacement_hash = format!("0x{}", "b".repeat(64));

        assert!(!has_canonical_finality(
            110,
            100,
            12,
            &receipt_hash,
            &receipt_hash,
        ));
        assert!(!has_canonical_finality(
            112,
            100,
            12,
            &receipt_hash,
            &replacement_hash,
        ));
        assert!(has_canonical_finality(
            112,
            100,
            12,
            &receipt_hash,
            &receipt_hash,
        ));
    }

    #[tokio::test]
    async fn authoritative_publication_revokes_stale_mutable_artifacts() {
        let directory = env::temp_dir().join(format!("prism-proof-test-{}", Uuid::now_v7()));
        let receipts = directory.join("receipts");
        let legacy_pages = directory.join("pages");
        fs::create_dir_all(&receipts).unwrap();
        fs::create_dir_all(&legacy_pages).unwrap();
        fs::write(receipts.join("stale.json"), b"{}").unwrap();
        fs::write(receipts.join("keep.txt"), b"not a receipt").unwrap();
        fs::write(legacy_pages.join("1.json"), b"{}").unwrap();
        fs::write(legacy_pages.join("keep.txt"), b"not a page").unwrap();
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(
            publish_authoritative_index(
                &ArtifactStore::Local(directory.clone()),
                &[receipt.clone()],
                0,
            )
            .await
            .unwrap()
        );

        assert!(!receipts.join("stale.json").exists());
        assert!(receipts.join("keep.txt").exists());
        assert!(!legacy_pages.join("1.json").exists());
        assert!(legacy_pages.join("keep.txt").exists());
        assert!(
            receipts
                .join(format!("{}.json", receipt.receipt_id))
                .exists()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn authoritative_publication_rewrites_pre_identity_receipt_artifacts() {
        let directory = env::temp_dir().join(format!("prism-proof-upgrade-{}", Uuid::now_v7()));
        let receipts = directory.join("receipts");
        fs::create_dir_all(&receipts).unwrap();

        let mut receipt = valid_receipt("7", 'b');
        receipt.escrow_address = Some(format!("0x{}", "1".repeat(40)));
        receipt.chain_lease_id = Some("7".to_owned());
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();
        let path = receipts.join(format!("{}.json", receipt.receipt_id));
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "receipt_id": receipt.receipt_id,
                "lease_id": receipt.lease_id,
                "receipt_hash": receipt.receipt_hash,
            }))
            .unwrap(),
        )
        .unwrap();

        let store = ArtifactStore::Local(directory.clone());
        let first = stage_proof_artifacts(&store, &[receipt.clone()], None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.receipt_checks, 1);
        assert_eq!(first.receipt_writes, 1);
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec_pretty(&receipt).unwrap()
        );

        let second = stage_proof_artifacts(&store, &[receipt.clone()], None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.receipt_checks, 0);
        assert_eq!(second.receipt_writes, 0);
        assert!(
            publish_authoritative_index(&store, &[receipt], 0)
                .await
                .unwrap()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn completion_marker_recovers_a_missing_or_corrupt_index() {
        let directory =
            env::temp_dir().join(format!("prism-proof-index-recovery-{}", Uuid::now_v7()));
        let store = ArtifactStore::Local(directory.clone());
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(
            publish_authoritative_index(&store, &[receipt.clone()], 0)
                .await
                .unwrap()
        );
        fs::remove_file(directory.join("index.json")).unwrap();
        let missing = stage_proof_artifacts(&store, &[receipt.clone()], None)
            .await
            .unwrap()
            .unwrap();
        assert!(!missing.complete);
        assert_eq!(missing.receipt_checks, 0);
        assert_eq!(missing.receipt_writes, 0);
        assert!(
            publish_authoritative_index(&store, &[receipt.clone()], 0)
                .await
                .unwrap()
        );

        fs::write(directory.join("index.json"), b"corrupt index").unwrap();
        let corrupt = stage_proof_artifacts(&store, &[receipt.clone()], None)
            .await
            .unwrap()
            .unwrap();
        assert!(!corrupt.complete);
        assert!(
            publish_authoritative_index(&store, &[receipt], 0)
                .await
                .unwrap()
        );
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["total"], 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn index_recovery_revalidates_a_corrupt_reconciliation_marker() {
        let directory =
            env::temp_dir().join(format!("prism-proof-marker-recovery-{}", Uuid::now_v7()));
        let store = ArtifactStore::Local(directory.clone());
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(
            publish_authoritative_index(&store, &[receipt.clone()], 0)
                .await
                .unwrap()
        );
        let set_id = proof_artifact_set_id(std::slice::from_ref(&receipt)).unwrap();
        fs::remove_file(directory.join("index.json")).unwrap();
        fs::write(
            directory.join(receipt_reconciliation_key(&set_id)),
            b"corrupt",
        )
        .unwrap();
        let receipt_path = directory.join(format!("receipts/{}.json", receipt.receipt_id));
        fs::write(&receipt_path, b"corrupt").unwrap();

        let staged = stage_proof_artifacts(&store, &[receipt.clone()], None)
            .await
            .unwrap()
            .unwrap();
        assert!(!staged.complete);
        assert_eq!(staged.receipt_checks, 1);
        assert_eq!(staged.receipt_writes, 1);
        assert_eq!(
            fs::read(receipt_path).unwrap(),
            serde_json::to_vec_pretty(&receipt).unwrap()
        );
        assert_eq!(
            fs::read(directory.join(receipt_reconciliation_key(&set_id))).unwrap(),
            artifact_marker(&set_id, 1, "receipts_reconciled").unwrap()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn externally_quarantined_receipt_invalidates_the_in_process_snapshot() {
        let published_at = Utc::now();
        let snapshot = PublicationSnapshot {
            set_id: "set".to_owned(),
            index_digest: "a".repeat(64),
            published_count: 2,
            max_published_at: Some(published_at),
        };

        assert!(publication_snapshot_matches(
            &snapshot,
            2,
            Some(published_at)
        ));
        assert!(!publication_snapshot_matches(
            &snapshot,
            1,
            Some(published_at)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn artifact_staging_stops_between_receipt_writes() {
        let directory = env::temp_dir().join(format!("prism-proof-stage-stop-{}", Uuid::now_v7()));
        fs::create_dir_all(&directory).unwrap();
        let receipts = (1..=8)
            .map(|lease_id| {
                let mut receipt = valid_receipt(&lease_id.to_string(), 'b');
                receipt.receipt_hash = receipt_hash(&receipt).unwrap();
                receipt
            })
            .collect::<Vec<_>>();
        let receipt_directory = directory.join("receipts");
        let observed_directory = receipt_directory.clone();
        let shutdown = tokio::spawn(async move {
            loop {
                let written = fs::read_dir(&observed_directory)
                    .map(|entries| entries.filter_map(Result::ok).count())
                    .unwrap_or(0);
                if written != 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        });

        let staged = stage_proof_artifacts(
            &ArtifactStore::Local(directory.clone()),
            &receipts,
            Some(&shutdown),
        )
        .await
        .unwrap();
        shutdown.await.unwrap();

        let written = fs::read_dir(receipt_directory)
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert!(staged.is_none());
        assert!(written > 0 && written < receipts.len());
        assert!(!directory.join("index.json").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn artifact_cleanup_stops_between_receipt_deletes() {
        let directory =
            env::temp_dir().join(format!("prism-proof-cleanup-stop-{}", Uuid::now_v7()));
        let receipt_directory = directory.join("receipts");
        fs::create_dir_all(&receipt_directory).unwrap();
        fs::write(directory.join("index.json"), b"authoritative index").unwrap();
        for index in 0..8 {
            fs::write(receipt_directory.join(format!("stale-{index}.json")), b"{}").unwrap();
        }
        let observed_directory = receipt_directory.clone();
        let shutdown = tokio::spawn(async move {
            loop {
                let remaining = fs::read_dir(&observed_directory)
                    .unwrap()
                    .filter_map(Result::ok)
                    .count();
                if remaining < 8 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        });

        let completed = remove_stale_receipt_artifacts(
            &ArtifactStore::Local(directory.clone()),
            &HashSet::new(),
            Some(&shutdown),
        )
        .await
        .unwrap();
        shutdown.await.unwrap();

        let remaining = fs::read_dir(receipt_directory)
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert!(!completed);
        assert!(remaining > 0 && remaining < 8);
        assert_eq!(
            fs::read(directory.join("index.json")).unwrap(),
            b"authoritative index"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn transient_verification_preserves_the_existing_authoritative_index() {
        let directory = env::temp_dir().join(format!("prism-proof-pending-{}", Uuid::now_v7()));
        fs::create_dir_all(directory.join("receipts")).unwrap();
        fs::create_dir_all(directory.join("pages")).unwrap();
        fs::write(directory.join("index.json"), b"existing complete index").unwrap();
        fs::write(directory.join("receipts/stale.json"), b"{}").unwrap();
        fs::write(directory.join("pages/1.json"), b"{}").unwrap();
        let mut receipt = valid_receipt("1", 'b');
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(
            !publish_authoritative_index(&ArtifactStore::Local(directory.clone()), &[receipt], 1,)
                .await
                .unwrap()
        );
        assert_eq!(
            fs::read(directory.join("index.json")).unwrap(),
            b"existing complete index"
        );
        assert!(directory.join("receipts/stale.json").exists());
        assert!(directory.join("pages/1.json").exists());
        assert!(!directory.join("sets").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn receipt_revocation_does_not_replace_an_index_waiting_on_pending_rows() {
        let directory = env::temp_dir().join(format!("prism-proof-revoke-{}", Uuid::now_v7()));
        fs::create_dir_all(directory.join("receipts")).unwrap();
        fs::create_dir_all(directory.join("pages")).unwrap();
        fs::write(directory.join("index.json"), b"existing complete index").unwrap();
        fs::write(directory.join("receipts/revoked.json"), b"{}").unwrap();
        fs::write(directory.join("pages/1.json"), b"existing complete page").unwrap();

        assert!(
            remove_stale_receipt_artifacts(
                &ArtifactStore::Local(directory.clone()),
                &HashSet::new(),
                None,
            )
            .await
            .unwrap()
        );

        assert!(!directory.join("receipts/revoked.json").exists());
        assert_eq!(
            fs::read(directory.join("index.json")).unwrap(),
            b"existing complete index"
        );
        assert_eq!(
            fs::read(directory.join("pages/1.json")).unwrap(),
            b"existing complete page"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn proof_publication_waits_for_more_than_one_batch_then_publishes_the_full_set() {
        let directory = env::temp_dir().join(format!("prism-proof-load-{}", Uuid::now_v7()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("index.json"), b"existing complete index").unwrap();
        let receipts = (1..=1_001)
            .map(|lease_id| {
                let mut receipt = valid_receipt(&lease_id.to_string(), 'b');
                receipt.receipt_hash = receipt_hash(&receipt).unwrap();
                receipt
            })
            .collect::<Vec<_>>();

        validate_receipts(&receipts).unwrap();
        assert!(
            !publish_authoritative_index(&ArtifactStore::Local(directory.clone()), &receipts, 1,)
                .await
                .unwrap()
        );
        assert_eq!(
            fs::read(directory.join("index.json")).unwrap(),
            b"existing complete index"
        );
        assert!(
            publish_authoritative_index(&ArtifactStore::Local(directory.clone()), &receipts, 0,)
                .await
                .unwrap()
        );

        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["receipts"].as_array().unwrap().len(), 1_000);
        assert_eq!(index["total"], 1_001);
        assert_eq!(index["pages"], 3);
        let first_page = index["first_page"].as_str().unwrap();
        assert!(first_page.starts_with("sets/"));
        assert!(directory.join(first_page).exists());
        assert_eq!(
            fs::read_dir(directory.join("receipts"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json"))
                .count(),
            1_001
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn mutable_receipts_are_never_cached_as_immutable() {
        assert_eq!(artifact_cache_control("index.json"), "no-cache");
        assert_eq!(
            artifact_cache_control("state/sets/abc/publication-v2.json"),
            "no-cache"
        );
        assert_eq!(
            artifact_cache_control("receipts/019f.json"),
            "public, max-age=30"
        );
        assert_eq!(
            artifact_cache_control("sets/abc/pages/1.json"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            artifact_cache_control("sets/abc/receipts-v2.json"),
            "public, max-age=31536000, immutable"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_listener_observes_sigterm() {
        let mut listener = spawn_shutdown_listener().unwrap();
        let status = tokio::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .await
            .unwrap();

        assert!(status.success());
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut listener)
            .await
            .expect("SIGTERM listener timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn in_flight_artifact_operation_stops_on_shutdown() {
        let shutdown = tokio::spawn(async {});
        tokio::task::yield_now().await;

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            artifact_operation(
                Some(&shutdown),
                std::future::pending::<()>(),
                "test artifact operation",
            ),
        )
        .await
        .expect("artifact operation ignored shutdown")
        .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn s3_artifact_deletion_uses_delete_object() {
        use aws_sdk_s3::config::{Credentials, Region};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 16_384];
            let length = connection.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(
                request.starts_with("DELETE /proof/receipts/stale.json?x-id=DeleteObject "),
                "unexpected S3 request: {request}"
            );
            connection
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "proof-worker-test",
            ))
            .endpoint_url(format!("http://{address}"))
            .load()
            .await;
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        let store = ArtifactStore::S3 {
            client: S3Client::from_conf(config),
            bucket: "proof".to_owned(),
        };

        assert!(store.delete("receipts/stale.json", None).await.unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn s3_direct_receipt_put_records_digest_and_short_cache_policy() {
        use aws_sdk_s3::config::{Credentials, Region};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = b"{}".to_vec();
        let expected_digest = hex::encode(Sha256::digest(&body));
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 16_384];
            let length = connection.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]).to_ascii_lowercase();
            assert!(
                request.starts_with("put /proof/receipts/legacy.json?x-id=putobject "),
                "unexpected S3 request: {request}"
            );
            assert!(
                request.contains("\r\ncache-control: public, max-age=30\r\n"),
                "direct receipt cache policy missing from S3 request: {request}"
            );
            assert!(
                request.contains(&format!(
                    "\r\nx-amz-meta-{receipt_metadata}: {expected_digest}\r\n",
                    receipt_metadata = ARTIFACT_DIGEST_METADATA,
                )),
                "direct receipt digest missing from S3 request: {request}"
            );
            connection
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "proof-worker-test",
            ))
            .endpoint_url(format!("http://{address}"))
            .load()
            .await;
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        let store = ArtifactStore::S3 {
            client: S3Client::from_conf(config),
            bucket: "proof".to_owned(),
        };

        assert!(
            store
                .put("receipts/legacy.json", body, "application/json", None)
                .await
                .unwrap()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn s3_direct_receipt_with_legacy_cache_policy_requires_rewrite() {
        use aws_sdk_s3::config::{Credentials, Region};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = b"{}".to_vec();
        let digest = hex::encode(Sha256::digest(&body));
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 16_384];
            let length = connection.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            assert!(
                request.starts_with("HEAD /proof/receipts/legacy.json"),
                "unexpected S3 request: {request}"
            );
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nCache-Control: public, max-age=31536000, immutable\r\nx-amz-meta-{ARTIFACT_DIGEST_METADATA}: {digest}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "proof-worker-test",
            ))
            .endpoint_url(format!("http://{address}"))
            .load()
            .await;
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        let store = ArtifactStore::S3 {
            client: S3Client::from_conf(config),
            bucket: "proof".to_owned(),
        };

        assert_eq!(
            store
                .receipt_is_current("receipts/legacy.json", &body, None)
                .await
                .unwrap(),
            Some(false)
        );
        server.await.unwrap();
    }

    #[test]
    fn x_post_validation_counts_urls_at_the_shortened_length() {
        let long_url = format!("https://proof.example/{}", "a".repeat(400));
        assert!(validate_x_post(&format!("Daily proof\n{long_url}")).is_ok());
        assert!(validate_x_post(&"a".repeat(281)).is_err());
        assert!(validate_x_post("  \n").is_err());
    }

    fn attestation() -> ReceiptAttestation {
        ReceiptAttestation {
            kind: AttestationKind::NvidiaGpu,
            verdict_digest: "d".repeat(64),
            verifier_version: "prism-attestation/0.1.0".to_owned(),
        }
    }

    fn repro() -> ReproReceiptEvidence {
        ReproReceiptEvidence {
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
        }
    }

    fn valid_receipt(lease_id: &str, transaction: char) -> PublicReceipt {
        PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: lease_id.to_owned(),
            escrow_address: None,
            chain_lease_id: None,
            node_id_hash: format!("0x{}", "a".repeat(64)),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000_000,
            refunded_base_units: 0,
            provider_paid_base_units: 900_000,
            failure_class: None,
            credited_seconds: None,
            outcome: ReceiptOutcome::Finalized,
            trust_class: None,
            attestation: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: format!("0x{}", transaction.to_string().repeat(64)),
        }
    }
}
