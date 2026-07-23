//! Reconciliation monitor: continuously checks that the control plane's view of
//! leases and settlements agrees with the on-chain `LeaseEscrowV1` state, and that
//! every finalized settlement conserves USDG. It reads only — it never signs or
//! mutates — and exposes its findings as Prometheus metrics so a stuck lease, a
//! drifted state, a non-conserving settlement, or an under-funded escrow pages an
//! operator instead of surfacing after money has already moved.

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use prism_chain::{RpcClient, address, selector, word_u128};
use prism_protocol::MAX_NETWORK_LEASES;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use sqlx_core::{query_as::query_as, query_scalar::query_scalar};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

/// The live `LeaseEscrowV1` platform fee split. Kept in sync with the contract's
/// `PLATFORM_FEE_BPS`/`BPS_DENOMINATOR`; a settlement whose split disagrees is a bug.
const PLATFORM_FEE_BPS: u128 = 1_000;
const BPS_DENOMINATOR: u128 = 10_000;

/// A lease left provisioning past this window should already have been refunded on
/// chain; if the control plane still holds it open, the funds are stranded.
const PROVISION_TIMEOUT_SECONDS: i64 = 10 * 60;
const SETTLEMENT_STALL_SECONDS: i64 = 60 * 60;
const CLOSING_STALL_SECONDS: i64 = 15 * 60;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Config::from_env()?;
    let address = config.listen;
    let state = AppState {
        inner: Arc::new(config),
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "reconciliation monitor listening");
    axum::serve(listener, app).await?;
    Ok(())
}

struct Config {
    database_url: String,
    listen: SocketAddr,
    chain: Option<ChainReader>,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let listen = env::var("PRISM_RECONCILIATION_MONITOR_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9092".to_owned())
            .parse()
            .context("PRISM_RECONCILIATION_MONITOR_ADDR is not a socket address")?;
        let chain = ChainReader::from_env()?;
        if chain.is_none() {
            tracing::warn!(
                "PRISM_RPC_URL / PRISM_LEASE_ESCROW_ADDRESS unset; chain reconciliation disabled"
            );
        }
        Ok(Self {
            database_url,
            listen,
            chain,
        })
    }
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Config>,
}

async fn health(State(state): State<AppState>) -> StatusCode {
    match tokio::time::timeout(Duration::from_secs(2), connect(&state.inner.database_url)).await {
        Ok(Ok(pool)) => {
            pool.close().await;
            StatusCode::NO_CONTENT
        }
        result => {
            let error = match result {
                Ok(Err(error)) => error.to_string(),
                Err(_) => "database health query timed out".to_owned(),
                Ok(Ok(_)) => unreachable!(),
            };
            tracing::error!(%error, "reconciliation monitor health check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

async fn metrics(State(state): State<AppState>) -> Response {
    let pool = match tokio::time::timeout(
        Duration::from_secs(2),
        connect(&state.inner.database_url),
    )
    .await
    {
        Ok(Ok(pool)) => pool,
        result => {
            let error = match result {
                Ok(Err(error)) => error.to_string(),
                Err(_) => "metrics database connection timed out".to_owned(),
                Ok(Ok(_)) => unreachable!(),
            };
            tracing::error!(%error, "reconciliation metrics connection failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let report = match tokio::time::timeout(
        Duration::from_secs(20),
        reconcile(&pool, state.inner.chain.as_ref()),
    )
    .await
    {
        Ok(Ok(report)) => report,
        result => {
            pool.close().await;
            let error = match result {
                Ok(Err(error)) => error.to_string(),
                Err(_) => "reconciliation pass timed out".to_owned(),
                Ok(Ok(_)) => unreachable!(),
            };
            tracing::error!(%error, "reconciliation pass failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    pool.close().await;
    report.log_breaches();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_metrics(&report),
    )
        .into_response()
}

async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(2))
        .connect(database_url)
        .await
        .context("connect PostgreSQL")
}

// ---------------------------------------------------------------------------
// Money invariants (pure)
// ---------------------------------------------------------------------------

/// The outcome of checking a single finalized settlement against the contract's
/// conservation rules. All amounts are USDG base units.
#[derive(Debug, PartialEq, Eq)]
enum Conservation {
    Ok,
    FeeMismatch {
        expected: u128,
        found: u128,
    },
    ProviderMismatch {
        expected: u128,
        found: u128,
    },
    ChargeSplit {
        charged: u128,
        fee: u128,
        provider: u128,
    },
    Deposit {
        deposit: u128,
        charged: u128,
        refunded: u128,
    },
}

/// A finalized settlement must account for the whole deposit: the renter is
/// charged for confirmed usage, the platform takes a fixed basis-point fee of that
/// charge, the provider takes the rest, and the unused deposit is refunded.
fn check_conservation(
    deposit: u128,
    charged: u128,
    fee: u128,
    provider_paid: u128,
    refunded: u128,
) -> Conservation {
    let expected_fee = charged.saturating_mul(PLATFORM_FEE_BPS) / BPS_DENOMINATOR;
    if fee != expected_fee {
        return Conservation::FeeMismatch {
            expected: expected_fee,
            found: fee,
        };
    }
    let expected_provider = charged - expected_fee;
    if provider_paid != expected_provider {
        return Conservation::ProviderMismatch {
            expected: expected_provider,
            found: provider_paid,
        };
    }
    if fee + provider_paid != charged {
        return Conservation::ChargeSplit {
            charged,
            fee,
            provider: provider_paid,
        };
    }
    if charged + refunded != deposit {
        return Conservation::Deposit {
            deposit,
            charged,
            refunded,
        };
    }
    Conservation::Ok
}

/// On-chain `LeaseEscrowV1.LeaseStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainStatus {
    None,
    Funded,
    Active,
    SettlementProposed,
    Disputed,
    Finalized,
    Refunded,
    Unknown(u8),
}

impl ChainStatus {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Funded,
            2 => Self::Active,
            3 => Self::SettlementProposed,
            4 => Self::Disputed,
            5 => Self::Finalized,
            6 => Self::Refunded,
            other => Self::Unknown(other),
        }
    }

    /// The deposit has left escrow.
    fn is_released(self) -> bool {
        matches!(self, Self::Finalized | Self::Refunded)
    }
}

/// A control-plane lease is open while it can still consume escrow.
fn db_state_is_open(state: &str) -> bool {
    !matches!(state, "finalized" | "refunded" | "failed")
}

/// The reconciliation verdict for one lease, comparing the control-plane state to
/// the on-chain status.
#[derive(Debug, PartialEq, Eq)]
enum Agreement {
    Ok,
    /// The control plane holds the lease open, but escrow has already been released
    /// on chain. The dangerous direction: the platform believes it is still metering
    /// a lease whose funds are gone.
    DbOpenChainReleased,
    /// The control plane considers the lease settled, but escrow is still locked.
    DbSettledChainOpen,
    /// The control plane has a lease the escrow has never heard of.
    MissingOnChain,
}

fn classify_agreement(db_state: &str, chain: ChainStatus) -> Agreement {
    let open = db_state_is_open(db_state);
    match (open, chain) {
        (_, ChainStatus::None) => Agreement::MissingOnChain,
        (true, status) if status.is_released() => Agreement::DbOpenChainReleased,
        (false, status) if !matches!(status, ChainStatus::None) && !status.is_released() => {
            Agreement::DbSettledChainOpen
        }
        _ => Agreement::Ok,
    }
}

// ---------------------------------------------------------------------------
// Chain reads
// ---------------------------------------------------------------------------

struct ChainReader {
    rpc: RpcClient,
    escrow: String,
    usdg: String,
    from_block: String,
}

impl ChainReader {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let (Some(rpc_url), Some(escrow)) = (
            env::var("PRISM_RPC_URL").ok(),
            env::var("PRISM_LEASE_ESCROW_ADDRESS").ok(),
        ) else {
            return Ok(None);
        };
        let usdg = env::var("PRISM_USDG_ADDRESS")
            .unwrap_or_else(|_| "0x5fc5360d0400a0fd4f2af552add042d716f1d168".to_owned());
        address(&escrow).context("PRISM_LEASE_ESCROW_ADDRESS is not an EVM address")?;
        address(&usdg).context("PRISM_USDG_ADDRESS is not an EVM address")?;
        let from_block = env::var("PRISM_ESCROW_FROM_BLOCK").unwrap_or_else(|_| "0x0".to_owned());
        Ok(Some(Self {
            rpc: RpcClient::new(&rpc_url)?,
            escrow: escrow.to_ascii_lowercase(),
            usdg: usdg.to_ascii_lowercase(),
            from_block,
        }))
    }

    async fn eth_call(&self, to: &str, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let calldata = format!("0x{}", hex::encode(data));
        let result: String = self
            .rpc
            .call(
                "eth_call",
                serde_json::json!([{ "to": to, "data": calldata }, "latest"]),
            )
            .await?;
        decode_hex(&result)
    }

    async fn usdg_balance(&self) -> anyhow::Result<u128> {
        let mut data = selector("balanceOf(address)").to_vec();
        data.extend_from_slice(&left_pad_address(&self.escrow)?);
        let word = self.eth_call(&self.usdg, data).await?;
        Ok(tail_u128(word32(&word)?))
    }

    async fn active_lease_count(&self) -> anyhow::Result<u128> {
        let data = selector("activeLeaseCount()").to_vec();
        let word = self.eth_call(&self.escrow, data).await?;
        Ok(tail_u128(word32(&word)?))
    }

    /// The on-chain deposit and status for one lease.
    async fn lease(&self, lease_id: i64) -> anyhow::Result<(u128, ChainStatus)> {
        let mut data = selector("getLease(uint256)").to_vec();
        data.extend_from_slice(&word_u128(
            u128::try_from(lease_id).context("negative lease id")?,
        ));
        let encoded = self.eth_call(&self.escrow, data).await?;
        if encoded.len() < 14 * 32 {
            anyhow::bail!("getLease returned {} bytes", encoded.len());
        }
        let deposit = tail_u128(&encoded[128..160]);
        let status = ChainStatus::from_u8(encoded[447]);
        Ok((deposit, status))
    }

    /// Scan `LeaseFinalized` events and return the settlement breakdown per lease.
    async fn finalized_settlements(&self) -> anyhow::Result<Vec<FinalizedEvent>> {
        let topic = format!(
            "0x{}",
            hex::encode(Keccak256::digest(
                b"LeaseFinalized(uint256,uint256,uint256,uint256,uint256,bytes32)"
            ))
        );
        let logs: Vec<RawLog> = self
            .rpc
            .call(
                "eth_getLogs",
                serde_json::json!([{
                    "address": self.escrow,
                    "fromBlock": self.from_block,
                    "toBlock": "latest",
                    "topics": [topic],
                }]),
            )
            .await?;
        logs.iter().map(FinalizedEvent::decode).collect()
    }
}

#[derive(Deserialize)]
struct RawLog {
    topics: Vec<String>,
    data: String,
}

struct FinalizedEvent {
    lease_id: i64,
    charged: u128,
    fee: u128,
    provider_paid: u128,
    refunded: u128,
}

impl FinalizedEvent {
    fn decode(log: &RawLog) -> anyhow::Result<Self> {
        let lease_id = log
            .topics
            .get(1)
            .context("LeaseFinalized log is missing its indexed lease id")?;
        let lease_id = i64::try_from(tail_u128(word32(&decode_hex(lease_id)?)?))
            .context("lease id exceeds i64")?;
        let data = decode_hex(&log.data)?;
        if data.len() < 4 * 32 {
            anyhow::bail!("LeaseFinalized data is {} bytes", data.len());
        }
        Ok(Self {
            lease_id,
            charged: tail_u128(&data[0..32]),
            fee: tail_u128(&data[32..64]),
            provider_paid: tail_u128(&data[64..96]),
            refunded: tail_u128(&data[96..128]),
        })
    }
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).context("RPC returned invalid hex")
}

fn word32(bytes: &[u8]) -> anyhow::Result<&[u8]> {
    bytes
        .get(..32)
        .context("RPC returned fewer than 32 bytes for a word")
}

/// The low 128 bits of a 32-byte ABI word — every amount and count Prism uses fits.
fn tail_u128(word: &[u8]) -> u128 {
    let mut buffer = [0_u8; 16];
    buffer.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(buffer)
}

fn left_pad_address(address: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = decode_hex(address)?;
    if bytes.len() != 20 {
        anyhow::bail!("address is {} bytes", bytes.len());
    }
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&bytes);
    Ok(word)
}

// ---------------------------------------------------------------------------
// Reconciliation pass
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    chain_configured: bool,
    chain_reachable: bool,
    escrow_usdg_balance: u128,
    open_lease_deposit_sum: u128,
    chain_active_leases: u128,
    db_open_leases: i64,
    drift_missing_on_chain: u64,
    drift_db_open_chain_released: u64,
    drift_db_settled_chain_open: u64,
    conservation_checked: u64,
    conservation_violations: u64,
    stuck_provisioning: i64,
    stuck_settlement: i64,
    stuck_closing: i64,
    finalized_without_receipt: i64,
    orphan_receipts: i64,
}

impl Report {
    fn solvency_ok(&self) -> bool {
        !self.chain_reachable || self.escrow_usdg_balance >= self.open_lease_deposit_sum
    }

    fn active_bound_ok(&self) -> bool {
        !self.chain_reachable || self.chain_active_leases <= MAX_NETWORK_LEASES as u128
    }

    fn log_breaches(&self) {
        if !self.solvency_ok() {
            tracing::error!(
                balance = self.escrow_usdg_balance,
                open_deposits = self.open_lease_deposit_sum,
                "escrow balance is below the deposits the control plane believes are locked"
            );
        }
        if self.conservation_violations > 0 {
            tracing::error!(
                violations = self.conservation_violations,
                "finalized settlements do not conserve the deposit"
            );
        }
        if self.drift_db_open_chain_released > 0 {
            tracing::error!(
                leases = self.drift_db_open_chain_released,
                "leases are open in the control plane but already released on chain"
            );
        }
        if self.drift_missing_on_chain > 0 {
            tracing::error!(
                leases = self.drift_missing_on_chain,
                "control-plane leases have no matching on-chain escrow"
            );
        }
        if !self.active_bound_ok() {
            tracing::error!(
                active = self.chain_active_leases,
                cap = MAX_NETWORK_LEASES,
                "on-chain active lease count exceeds the network cap"
            );
        }
    }
}

async fn reconcile(pool: &PgPool, chain: Option<&ChainReader>) -> anyhow::Result<Report> {
    let mut report = Report::default();

    let open_leases = query_as::<_, (i64, String)>(
        "SELECT lease_id, state FROM leases \
         WHERE state NOT IN ('finalized', 'refunded', 'failed') ORDER BY lease_id",
    )
    .fetch_all(pool)
    .await?;
    report.db_open_leases = open_leases.len() as i64;

    report.stuck_provisioning = stuck(pool, "provisioning", PROVISION_TIMEOUT_SECONDS).await?;
    report.stuck_settlement = stuck(pool, "settlement_pending", SETTLEMENT_STALL_SECONDS).await?;
    report.stuck_closing = stuck(pool, "closing", CLOSING_STALL_SECONDS).await?;

    report.finalized_without_receipt = query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM leases l \
         WHERE l.state = 'finalized' \
           AND NOT EXISTS (SELECT 1 FROM proof_receipts r WHERE r.lease_id = l.lease_id)",
    )
    .fetch_one(pool)
    .await?;
    report.orphan_receipts = query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM proof_receipts r \
         JOIN leases l ON l.lease_id = r.lease_id \
         WHERE l.state NOT IN ('finalized', 'refunded')",
    )
    .fetch_one(pool)
    .await?;

    let Some(chain) = chain else {
        return Ok(report);
    };
    report.chain_configured = true;

    match reconcile_chain(chain, &open_leases).await {
        Ok(chain_report) => {
            report.chain_reachable = true;
            report.escrow_usdg_balance = chain_report.escrow_usdg_balance;
            report.open_lease_deposit_sum = chain_report.open_lease_deposit_sum;
            report.chain_active_leases = chain_report.chain_active_leases;
            report.drift_missing_on_chain = chain_report.drift_missing_on_chain;
            report.drift_db_open_chain_released = chain_report.drift_db_open_chain_released;
            report.drift_db_settled_chain_open = chain_report.drift_db_settled_chain_open;
            report.conservation_checked = chain_report.conservation_checked;
            report.conservation_violations = chain_report.conservation_violations;
        }
        Err(error) => {
            tracing::error!(error = %error, "chain reconciliation read failed");
        }
    }
    Ok(report)
}

#[derive(Default)]
struct ChainReport {
    escrow_usdg_balance: u128,
    open_lease_deposit_sum: u128,
    chain_active_leases: u128,
    drift_missing_on_chain: u64,
    drift_db_open_chain_released: u64,
    drift_db_settled_chain_open: u64,
    conservation_checked: u64,
    conservation_violations: u64,
}

async fn reconcile_chain(
    chain: &ChainReader,
    open_leases: &[(i64, String)],
) -> anyhow::Result<ChainReport> {
    let mut report = ChainReport {
        escrow_usdg_balance: chain.usdg_balance().await?,
        chain_active_leases: chain.active_lease_count().await?,
        ..ChainReport::default()
    };

    for (lease_id, db_state) in open_leases {
        let (deposit, status) = chain.lease(*lease_id).await?;
        report.open_lease_deposit_sum = report.open_lease_deposit_sum.saturating_add(deposit);
        match classify_agreement(db_state, status) {
            Agreement::Ok => {}
            Agreement::MissingOnChain => report.drift_missing_on_chain += 1,
            Agreement::DbOpenChainReleased => report.drift_db_open_chain_released += 1,
            Agreement::DbSettledChainOpen => report.drift_db_settled_chain_open += 1,
        }
    }

    for event in chain.finalized_settlements().await? {
        report.conservation_checked += 1;
        let (deposit, _status) = chain.lease(event.lease_id).await?;
        if check_conservation(
            deposit,
            event.charged,
            event.fee,
            event.provider_paid,
            event.refunded,
        ) != Conservation::Ok
        {
            report.conservation_violations += 1;
            tracing::error!(
                lease_id = event.lease_id,
                deposit,
                charged = event.charged,
                fee = event.fee,
                provider_paid = event.provider_paid,
                refunded = event.refunded,
                "settlement does not conserve the deposit"
            );
        }
    }

    Ok(report)
}

async fn stuck(pool: &PgPool, state: &str, older_than_seconds: i64) -> anyhow::Result<i64> {
    query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM leases \
         WHERE state = $1 AND updated_at < NOW() - make_interval(secs => $2)",
    )
    .bind(state)
    .bind(older_than_seconds as f64)
    .fetch_one(pool)
    .await
    .context("count stuck leases")
}

// ---------------------------------------------------------------------------
// Metrics rendering
// ---------------------------------------------------------------------------

fn render_metrics(report: &Report) -> String {
    let mut out = String::with_capacity(2048);

    gauge(
        &mut out,
        "prism_reconcile_up",
        "Reconciliation pass completed.",
        "1",
    );
    gauge(
        &mut out,
        "prism_reconcile_chain_configured",
        "An RPC endpoint and escrow address are configured.",
        bool_metric(report.chain_configured),
    );
    gauge(
        &mut out,
        "prism_reconcile_chain_reachable",
        "The chain reads for this pass succeeded.",
        bool_metric(report.chain_reachable),
    );
    gauge(
        &mut out,
        "prism_reconcile_escrow_usdg_balance_base_units",
        "USDG held by the lease escrow contract.",
        &report.escrow_usdg_balance.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_open_lease_deposit_sum_base_units",
        "Sum of on-chain deposits for leases the control plane still holds open.",
        &report.open_lease_deposit_sum.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_solvency_ok",
        "Escrow balance covers the open deposits the control plane tracks.",
        bool_metric(report.solvency_ok()),
    );
    gauge(
        &mut out,
        "prism_reconcile_chain_active_leases",
        "Active lease count reported by the escrow contract.",
        &report.chain_active_leases.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_db_open_leases",
        "Leases the control plane holds open.",
        &report.db_open_leases.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_active_lease_bound_ok",
        "On-chain active leases are within the network cap.",
        bool_metric(report.active_bound_ok()),
    );
    gauge(
        &mut out,
        "prism_reconcile_conservation_checked_total",
        "Finalized settlements inspected this pass.",
        &report.conservation_checked.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_conservation_violations_total",
        "Finalized settlements that do not conserve the deposit.",
        &report.conservation_violations.to_string(),
    );
    for (kind, value) in [
        ("missing_on_chain", report.drift_missing_on_chain),
        (
            "db_open_chain_released",
            report.drift_db_open_chain_released,
        ),
        ("db_settled_chain_open", report.drift_db_settled_chain_open),
    ] {
        out.push_str(&format!(
            "# HELP prism_reconcile_state_drift Lease state disagreements between the control plane and chain.\n\
             # TYPE prism_reconcile_state_drift gauge\n\
             prism_reconcile_state_drift{{kind=\"{kind}\"}} {value}\n"
        ));
    }
    for (phase, value) in [
        ("provisioning", report.stuck_provisioning),
        ("settlement", report.stuck_settlement),
        ("closing", report.stuck_closing),
    ] {
        out.push_str(&format!(
            "# HELP prism_reconcile_stuck_leases Leases stalled in a lifecycle phase past its timeout.\n\
             # TYPE prism_reconcile_stuck_leases gauge\n\
             prism_reconcile_stuck_leases{{phase=\"{phase}\"}} {value}\n"
        ));
    }
    gauge(
        &mut out,
        "prism_reconcile_finalized_without_receipt",
        "Finalized leases with no published proof receipt.",
        &report.finalized_without_receipt.to_string(),
    );
    gauge(
        &mut out,
        "prism_reconcile_orphan_receipts",
        "Proof receipts whose lease is not finalized or refunded.",
        &report.orphan_receipts.to_string(),
    );
    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: &str) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
    ));
}

fn bool_metric(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn split(deposit: u128, charged: u128) -> (u128, u128, u128) {
        let fee = charged * PLATFORM_FEE_BPS / BPS_DENOMINATOR;
        (fee, charged - fee, deposit - charged)
    }

    #[test]
    fn conservation_accepts_a_correct_settlement() {
        let deposit = 799_200;
        let charged = 444_000;
        let (fee, provider, refunded) = split(deposit, charged);
        assert_eq!(
            check_conservation(deposit, charged, fee, provider, refunded),
            Conservation::Ok
        );
    }

    #[test]
    fn conservation_accepts_a_full_refund() {
        let deposit = 500_000;
        let (fee, provider, refunded) = split(deposit, 0);
        assert_eq!(
            check_conservation(deposit, 0, fee, provider, refunded),
            Conservation::Ok
        );
    }

    #[test]
    fn conservation_rejects_a_skimmed_fee() {
        let deposit = 799_200;
        let charged = 444_000;
        let (fee, provider, refunded) = split(deposit, charged);
        assert!(matches!(
            check_conservation(deposit, charged, fee + 1, provider, refunded),
            Conservation::FeeMismatch { .. }
        ));
    }

    #[test]
    fn conservation_rejects_an_overpaid_provider() {
        let deposit = 799_200;
        let charged = 444_000;
        let (fee, provider, refunded) = split(deposit, charged);
        assert!(matches!(
            check_conservation(deposit, charged, fee, provider + 10, refunded),
            Conservation::ProviderMismatch { .. }
        ));
    }

    #[test]
    fn conservation_rejects_a_leaked_deposit() {
        let deposit = 799_200;
        let charged = 444_000;
        let (fee, provider, _) = split(deposit, charged);
        // Refund one unit short: the deposit is no longer fully accounted for.
        assert!(matches!(
            check_conservation(deposit, charged, fee, provider, deposit - charged - 1),
            Conservation::Deposit { .. }
        ));
    }

    #[test]
    fn open_lease_released_on_chain_is_the_dangerous_drift() {
        assert_eq!(
            classify_agreement("active", ChainStatus::Finalized),
            Agreement::DbOpenChainReleased
        );
        assert_eq!(
            classify_agreement("settlement_pending", ChainStatus::Refunded),
            Agreement::DbOpenChainReleased
        );
    }

    #[test]
    fn settled_lease_still_open_on_chain_drifts() {
        assert_eq!(
            classify_agreement("finalized", ChainStatus::Active),
            Agreement::DbSettledChainOpen
        );
    }

    #[test]
    fn matching_states_agree() {
        assert_eq!(
            classify_agreement("active", ChainStatus::Active),
            Agreement::Ok
        );
        assert_eq!(
            classify_agreement("finalized", ChainStatus::Finalized),
            Agreement::Ok
        );
        assert_eq!(
            classify_agreement("refunded", ChainStatus::Refunded),
            Agreement::Ok
        );
    }

    #[test]
    fn unknown_lease_on_chain_is_missing() {
        assert_eq!(
            classify_agreement("funded", ChainStatus::None),
            Agreement::MissingOnChain
        );
    }

    #[test]
    fn tail_u128_reads_the_low_bytes_of_a_word() {
        let mut word = [0_u8; 32];
        word[16..].copy_from_slice(&50_000_000_u128.to_be_bytes());
        assert_eq!(tail_u128(&word), 50_000_000);
    }

    #[test]
    fn left_pad_address_right_aligns_twenty_bytes() {
        let word = left_pad_address("0x5fc5360d0400a0fd4f2af552add042d716f1d168").unwrap();
        assert_eq!(&word[..12], &[0_u8; 12]);
        assert_eq!(word[12], 0x5f);
        assert_eq!(word[31], 0x68);
    }
}
