use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use k256::ecdsa::{
    RecoveryId, Signature as EthereumSignature, VerifyingKey as EthereumVerifyingKey,
};
use prism_chain::{
    EthereumSigner, Finality, PreparedTransaction, RpcClient, address, selector, word_bytes32,
    word_u128,
};
use prism_protocol::{
    AttestationVerdict, CommandResult, CredentialCipher, ExecutionEvidence, GpuReproSpec,
    LeaseAttestationVerdict, LeaseRecord, LeaseState, ManagedCommandReport, ManagedProvider,
    NodeCommand, NodeCommandKind, NodeCommandOutcome, NodeCommandReport, NodeOffer, NodeTelemetry,
    PublicReceipt, ROBINHOOD_CHAIN_ID, ReceiptAttestation, ReceiptOutcome, ReproExecutionEvidence,
    ReproExecutionReport, ReproExecutor, SettlementEvidence, TrustClass, node_id, receipt_hash,
    validate_receipt_identity, verdict_digest, verifying_key,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    acquire::Acquire, query::query, query_as::query_as, query_scalar::query_scalar,
    types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod vast;

use vast::VastBroker;

const SIGNER_LOCK: i64 = 4_663_001;
const SCHEDULER_LOCK: i64 = 4_663;
/// How many Vast hosts a single lease may burn through before the provisioning
/// attempt is abandoned and the escrow refunded.
const MAX_REJECTED_MACHINES: usize = 4;
/// How long a host gets to boot before the lease abandons it for another.
///
/// The escrow's PROVISION_TIMEOUT is ten minutes and cannot be raised without
/// redeploying it, so the only way to survive a slow host is to stop waiting on
/// one. A healthy box is reachable inside two minutes; past this it is very
/// unlikely to make the window, and burning the whole window on it refunds a
/// lease that a different machine would have served.
/// How long a host gets to reach a usable state before the broker gives up on
/// it and rents another. Measured against real Vast hosts: a cold image pull
/// puts a healthy machine past three minutes, and the previous 180s budget was
/// refusing hosts that were simply still booting. Half the provisioning window,
/// so one bad host still leaves room to try a second.
const HOST_BOOT_BUDGET_SECONDS: i64 = 300;
/// How long a machine stays on the shared rejection list. A host that reserves
/// no forwarded ports is usually misconfigured rather than busy, but hosts do
/// get fixed, so the list forgets rather than banning anyone permanently.
const MACHINE_REJECTION_MEMORY_HOURS: i64 = 6;
/// Ranked offers tried per provisioning pass. Retries supply the rest of the
/// breadth, and a pass that spends the whole window is a refund.
const CREATES_PER_PASS: usize = 2;
/// The escrow's own PROVISION_TIMEOUT. A funded lease older than this can be
/// expired by anyone, which refunds the renter and frees the node.
const PROVISION_TIMEOUT_SECONDS: u64 = 600;
/// How far back to look for leases the escrow knows about and we do not.
const ORPHAN_SCAN_DEPTH: u64 = 32;
const ORPHAN_SCAN_INTERVAL_SECONDS: u64 = 300;
/// How often a rented machine is asked whether it is still alive. Every active
/// lease costs one provider call, so this is paced well under the staleness
/// window that closes a lease, leaving room to miss a round to a flaky API
/// without ending someone's job.
const CLOUD_OBSERVATION_INTERVAL_SECONDS: u64 = 45;
const CLOUD_CAPACITY_REFRESH_INTERVAL_SECONDS: u64 = 30;
const CLOUD_CLEANUP_RETRY_SECONDS: u64 = 60;
const RPC_TRANSIENT_RETRY_SECONDS: u64 = 15;
const TRANSACTION_REPREPARE_RETRY_SECONDS: u64 = 5;
const TRANSACTION_BROADCAST_LIMIT_RETRY_SECONDS: u64 = 300;
const RPC_MAINTENANCE_PACE_MILLIS: u64 = 150;
/// LeaseStatus.Funded in the escrow's enum.
const LEASE_STATUS_FUNDED: u8 = 1;
const LEASE_STATUS_ACTIVE: u8 = 2;
const LEASE_STATUS_FINALIZED: u8 = 5;
const LEASE_STATUS_REFUNDED: u8 = 6;

/// What a lease pays for an hour, which is the most the broker can spend on one
/// without the settlement worker refusing the receipt.
fn retail_hourly(rate_per_second: u64) -> u64 {
    rate_per_second.saturating_mul(3_600)
}

fn provider_failure_state(error: &anyhow::Error) -> (&'static str, &'static str) {
    match vast::failure_scope(error) {
        Some(vast::FailureScope::Credit) => ("credit_blocked", "provider_credit"),
        Some(vast::FailureScope::Auth) => ("auth_blocked", "provider_auth"),
        Some(vast::FailureScope::Transient | vast::FailureScope::Resource) => {
            ("transient_blocked", "provider_transient")
        }
        Some(vast::FailureScope::Permanent) | None => ("permanent_blocked", "provider_response"),
    }
}

fn provider_state_is_latched(state: &str) -> bool {
    matches!(
        state,
        "auth_blocked" | "permanent_blocked" | "operator_maintenance"
    )
}

fn validated_provider_offer_ids(ids: Vec<u64>) -> anyhow::Result<Vec<u64>> {
    if ids.len() > 64 || ids.contains(&0) {
        anyhow::bail!("lifecycle action contains invalid failed provider offer IDs");
    }
    let mut seen = BTreeSet::new();
    Ok(ids
        .into_iter()
        .filter(|offer_id| seen.insert(*offer_id))
        .collect())
}
const CLOUD_CAPACITY_UPSERT: &str = "
    INSERT INTO cloud_capacity
        (node_id, provider, available, provider_offer_id, hourly_cost_micros, observed_at)
    VALUES ($1, 'vast', $2, $3, $4, NOW())
    ON CONFLICT (node_id) DO UPDATE SET
        provider = 'vast',
        available = EXCLUDED.available,
        provider_offer_id = EXCLUDED.provider_offer_id,
        hourly_cost_micros = EXCLUDED.hourly_cost_micros,
        observed_at = NOW(),
        updated_at = NOW()
";
// A superseded escrow's unfinished row no longer reserves this deployment, but
// a provider machine keeps billing until it is actually destroyed.
const BROKER_COMMITMENTS_QUERY: &str = "
    SELECT count(*) FROM (
        SELECT l.lease_id FROM leases l
        WHERE l.escrow_address = $1
          AND l.state NOT IN ('finalized', 'refunded')
          AND EXISTS (
              SELECT 1 FROM cloud_capacity cc
              WHERE cc.node_id = l.document->>'node_id' AND cc.provider = 'vast'
          )
        UNION
        SELECT ci.lease_id FROM cloud_instances ci
        WHERE ci.provider = 'vast' AND ci.status <> 'destroyed'
    ) commitments
";
const BROKER_BUSY_NODES_QUERY: &str = "
    SELECT l.document->>'node_id' FROM leases l
    WHERE l.escrow_address = $1
      AND l.state NOT IN ('finalized', 'refunded')
    UNION
    SELECT l.document->>'node_id' FROM leases l
    JOIN cloud_instances ci ON ci.lease_id = l.lease_id
    WHERE ci.status <> 'destroyed'
";

struct Worker {
    pool: PgPool,
    chain: RpcClient,
    signer: EthereumSigner,
    escrow: [u8; 20],
    registry: [u8; 20],
    confirmations: u64,
    gateway: GatewayClient,
    cipher: CredentialCipher,
    vast: Option<VastBroker>,
    supply_note: tokio::sync::Mutex<Option<String>>,
    last_cloud_capacity_refresh: tokio::sync::Mutex<Option<std::time::Instant>>,
    last_orphan_sweep: tokio::sync::Mutex<Option<std::time::Instant>>,
    last_cloud_observation: tokio::sync::Mutex<Option<std::time::Instant>>,
}

#[derive(Clone, Default)]
struct Shutdown {
    requested: Arc<AtomicBool>,
    claim_gate: Arc<tokio::sync::Mutex<()>>,
    notify: Arc<tokio::sync::Notify>,
}

impl Shutdown {
    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    async fn request(&self) {
        let _gate = self.claim_gate.lock().await;
        if !self.requested.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    async fn claim_permit(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let permit = self.claim_gate.clone().lock_owned().await;
        (!self.is_requested()).then_some(permit)
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

/// An id the escrow issued. Kept distinct from the internal `lease_id` in the
/// type system because the escrow's counter restarts whenever it is redeployed,
/// and passing the wrong one addresses a chain call to another lease or to none
/// at all. Both mistakes have reached production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainLeaseId(u64);

impl ChainLeaseId {
    fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct Action {
    action_id: Uuid,
    claim_generation: i64,
    lease_id: u64,
    /// What the escrow numbered this lease. Escrow counters restart on
    /// redeployment, so this differs from `lease_id` and is the only value a
    /// chain call may carry.
    chain_lease_id: ChainLeaseId,
    kind: ActionKind,
    transaction: Option<PreparedTransaction>,
    failed_provider_offer_ids: Vec<u64>,
}

#[derive(Debug)]
struct ConfirmedAttempt {
    transaction: PreparedTransaction,
    block_number: u64,
    block_hash: String,
}

#[derive(Debug)]
enum AttemptObservation {
    Confirmed(ConfirmedAttempt),
    Pending(PreparedTransaction),
    None,
}

#[derive(Debug, Default, Deserialize)]
struct ActionDocument {
    #[serde(default)]
    failed_provider_offer_ids: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    StartAccess,
    RefreshGrant,
    CloseAccess,
    ExpireProvision,
    Finalize,
    CleanupCloud,
}

#[derive(Clone)]
struct GatewayClient {
    client: reqwest::Client,
    base_url: url::Url,
    token: Arc<String>,
}

#[derive(Serialize)]
struct ProbeRequest<'a> {
    node_id: &'a str,
    connection_id: &'a str,
}

#[derive(Deserialize)]
struct ProbeResponse {
    node_id: String,
    connection_id: String,
    cuda_ready_at: DateTime<Utc>,
    interactive_access_ready_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct GrantRequest<'a> {
    token_id: Uuid,
    lease_id: String,
    node_id: &'a str,
    connection_id: &'a str,
    ttl_seconds: u32,
    /// What the lease was sold as, and the evidence for it. The gateway refuses
    /// anything above `Open` without a verdict that matches, so a lease quoted
    /// on hardware evidence stops being servable the moment that evidence is
    /// missing rather than degrading quietly to a weaker guarantee.
    trust_class: TrustClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<LeaseAttestationVerdict>,
}

#[derive(Deserialize)]
struct GrantResponse {
    token: String,
    grant: Grant,
}

#[derive(Deserialize)]
struct Grant {
    token_id: Uuid,
    lease_id: String,
    node_id: String,
    connection_id: String,
    expires_at: DateTime<Utc>,
}

/// A box that is still booting has not failed, and the retry backoff is
/// quadratic. Left undistinguished, a ninety second boot costs the renter
/// eight minutes of a lease they are already paying for.
#[derive(Debug)]
struct StillProvisioning;

impl std::fmt::Display for StillProvisioning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Vast instance is not ready")
    }
}

impl std::error::Error for StillProvisioning {}

#[derive(Debug)]
struct CloudCleanupPending(String);

impl std::fmt::Display for CloudCleanupPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CloudCleanupPending {}

#[derive(Debug)]
struct TransactionOutcomePending;

impl std::fmt::Display for TransactionOutcomePending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a prior lifecycle transaction is still reconciling")
    }
}

impl std::error::Error for TransactionOutcomePending {}

#[derive(Debug)]
struct TransactionRepreparePending;

impl std::fmt::Display for TransactionRepreparePending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("transaction history is reconciled and a replacement can be prepared")
    }
}

impl std::error::Error for TransactionRepreparePending {}

#[derive(Debug)]
struct TransactionBroadcastLimitReached;

impl std::fmt::Display for TransactionBroadcastLimitReached {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("lifecycle transaction reached its broadcast-attempt limit")
    }
}

impl std::error::Error for TransactionBroadcastLimitReached {}

#[derive(Debug)]
struct TransactionBindingError {
    reason: &'static str,
    detail: String,
}

impl TransactionBindingError {
    fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for TransactionBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "lifecycle transaction binding failed ({}): {}",
            self.reason, self.detail
        )
    }
}

impl std::error::Error for TransactionBindingError {}

#[derive(Debug, PartialEq, Eq)]
struct DecodedLegacyTransaction {
    nonce: u64,
    chain_id: u64,
    destination: [u8; 20],
    data: Vec<u8>,
    signer: [u8; 20],
    transaction_hash: String,
}

#[derive(Debug)]
struct AccessReadinessPending;

impl std::fmt::Display for AccessReadinessPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("onchain access is active while local gateway readiness is pending")
    }
}

impl std::error::Error for AccessReadinessPending {}

/// Whether a host has used up its boot budget. `ssh_key_attached_at` is set
/// once per instance right after it is created and cleared whenever one is
/// dropped, which makes it the point this lease started waiting on this
/// machine. No timestamp means nothing is booting yet, so nothing has stalled.
/// Why this machine cannot serve the lease, or `None` to keep it.
///
/// Ordering matters more than it looks. Vast reports `direct_port_start` as -1
/// until a host finishes booting, so reading the port before the boot budget
/// expires condemns a healthy slow host as one that reserved no ports, and the
/// broker then destroys and blacklists every candidate in turn. A host is only
/// judged on its ports once it says it is running.
fn candidate_refusal(
    instance: &vast::Instance,
    admits_class: bool,
    min_vram_mib: u32,
    ceiling: u64,
    rejected: &[i64],
    stalled: bool,
) -> Option<String> {
    let timed_out = || {
        Some(format!(
            "host was still {} after {HOST_BOOT_BUDGET_SECONDS}s of boot budget",
            instance.status
        ))
    };
    if !admits_class {
        return Some(format!(
            "{} with {} MiB is not a class this broker rents",
            instance.gpu_name, instance.gpu_ram
        ));
    }
    if instance.gpu_ram < u64::from(min_vram_mib) {
        return Some(format!(
            "{} MiB is short of the {} MiB this lease asked for",
            instance.gpu_ram, min_vram_mib
        ));
    }
    if !instance.verification.eq_ignore_ascii_case("verified") {
        return Some(format!("host is {}, not verified", instance.verification));
    }
    if instance.hourly_micros > ceiling {
        return Some(format!(
            "{} micros/hr is over the {} ceiling",
            instance.hourly_micros, ceiling
        ));
    }
    if rejected.contains(&(instance.machine_id as i64)) {
        return Some("this lease already rejected the machine".to_owned());
    }
    if instance.status != "running" {
        return if stalled { timed_out() } else { None };
    }
    // Vast fills the forwarded port in some seconds after it starts reporting
    // the instance as running, so a missing port is only a fault once the host
    // has had its whole budget to produce one. Machine 23779 was refused for
    // this and served the very next lease it was offered.
    if instance.direct_port_start <= 0 {
        return if stalled {
            Some("host reserved no forwarded ports, so sshd is unreachable".to_owned())
        } else {
            None
        };
    }
    if stalled { timed_out() } else { None }
}

/// Whether an SSH server is listening at the address a host advertises. Only
/// the banner is read; nothing is sent, so a host that answers has been given
/// nothing it could use.
async fn sshd_answers(host: &str, port: u16) -> bool {
    use tokio::io::AsyncReadExt;

    let connect = tokio::net::TcpStream::connect((host, port));
    let Ok(Ok(mut stream)) = tokio::time::timeout(Duration::from_secs(5), connect).await else {
        return false;
    };
    let mut banner = [0u8; 4];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut banner)).await,
        Ok(Ok(_)) if &banner == b"SSH-"
    )
}

fn boot_budget_exhausted(attached_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    attached_at.is_some_and(|attached| {
        now.signed_duration_since(attached).num_seconds() > HOST_BOOT_BUDGET_SECONDS
    })
}

fn managed_runner_is_ready(
    status: &str,
    transport_host_key_sha256: Option<&str>,
) -> anyhow::Result<bool> {
    match status {
        "queued" | "preparing" => Ok(false),
        "ready" if transport_host_key_sha256.is_some_and(is_lower_sha256) => Ok(true),
        "ready" => {
            anyhow::bail!("managed repro runner is ready without a valid transport host key")
        }
        "failed" => anyhow::bail!("managed repro runner failed before activation"),
        other => anyhow::bail!("managed repro runner reached invalid pre-activation state {other}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn cloud_write_fence_matches(
    lease_state: &str,
    action_kind: &str,
    action_status: &str,
    claim_live: bool,
    claim_generation: i64,
    expected_generation: i64,
    current_instance_id: Option<i64>,
    expected_instance_id: Option<i64>,
    current_status: &str,
    expected_status: &str,
) -> bool {
    matches!(lease_state, "funded" | "provisioning" | "ready")
        && action_kind == "start_access"
        && action_status == "processing"
        && claim_live
        && claim_generation == expected_generation
        && current_instance_id == expected_instance_id
        && current_status == expected_status
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedRefusal {
    machine_id: i64,
    reason: String,
}

impl StagedRefusal {
    fn note(&self) -> String {
        format!("machine {} refused: {}", self.machine_id, self.reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusedCleanupOutcome {
    Replace,
    Exhausted,
}

fn staged_refusal(last_error: Option<&str>, rejected: &[i64]) -> Option<StagedRefusal> {
    let (machine, reason) = last_error?
        .strip_prefix("machine ")?
        .split_once(" refused: ")?;
    let machine_id = machine.parse().ok()?;
    if reason.is_empty() || !rejected.contains(&machine_id) {
        return None;
    }
    Some(StagedRefusal {
        machine_id,
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
fn refused_cleanup_outcome(recorded_rejections: usize) -> RefusedCleanupOutcome {
    if recorded_rejections >= MAX_REJECTED_MACHINES {
        RefusedCleanupOutcome::Exhausted
    } else {
        RefusedCleanupOutcome::Replace
    }
}

fn cloud_lease_lock_key(lease_id: u64) -> anyhow::Result<i64> {
    Ok(!i64::try_from(lease_id)?)
}

fn labelled_instance_plan(
    found: Vec<u64>,
    current: Option<i64>,
    prepared: Option<i64>,
) -> anyhow::Result<(Option<u64>, Vec<u64>)> {
    let current = current.map(u64::try_from).transpose()?;
    let prepared = prepared.map(u64::try_from).transpose()?;
    let adopted = prepared
        .filter(|instance_id| found.contains(instance_id))
        .or_else(|| current.filter(|instance_id| found.contains(instance_id)))
        .or_else(|| found.first().copied());
    let orphans = found
        .into_iter()
        .filter(|instance_id| {
            Some(*instance_id) != adopted
                && Some(*instance_id) != current
                && Some(*instance_id) != prepared
        })
        .collect();
    Ok((adopted, orphans))
}

fn should_issue_gateway_access(cloud: bool, batch: bool) -> bool {
    !cloud && !batch
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshDecision {
    /// The gateway is shut on this lease: the meter stopped with it, and a
    /// fresh hour of access minted now is compute nobody pays for. A refresh
    /// queued before the close, or claimed alongside it by a second worker,
    /// arrives here.
    Drop,
    Rotate,
    /// Cloud and batch leases carry no gateway session to rotate.
    Nothing,
}

fn refresh_decision(access_closed: bool, cloud: bool, batch: bool) -> RefreshDecision {
    if access_closed {
        RefreshDecision::Drop
    } else if should_issue_gateway_access(cloud, batch) {
        RefreshDecision::Rotate
    } else {
        RefreshDecision::Nothing
    }
}

/// `getLease` returns the struct as fourteen words. `createdAt` is the seventh
/// and `status` the last, both right aligned in their word.
fn decode_lease(bytes: &[u8]) -> anyhow::Result<OnchainLease> {
    if bytes.len() != 32 * 14 {
        anyhow::bail!("escrow returned an invalid lease");
    }
    let mut created = [0u8; 8];
    created.copy_from_slice(&bytes[32 * 7 - 8..32 * 7]);
    let mut started = [0u8; 8];
    started.copy_from_slice(&bytes[32 * 8 - 8..32 * 8]);
    let mut ended = [0u8; 8];
    ended.copy_from_slice(&bytes[32 * 9 - 8..32 * 9]);
    Ok(OnchainLease {
        created_at: u64::from_be_bytes(created),
        access_started_at: u64::from_be_bytes(started),
        access_ended_at: u64::from_be_bytes(ended),
        status: bytes[32 * 14 - 1],
    })
}

/// Only a lease still waiting to be provisioned can be expired, and only once
/// the escrow's own window has closed. Anything else belongs to a renter.
fn expirable(lease: OnchainLease, now: u64) -> bool {
    lease.status == LEASE_STATUS_FUNDED && now > lease.created_at + PROVISION_TIMEOUT_SECONDS
}

#[derive(Debug, Clone, Copy)]
struct OnchainLease {
    created_at: u64,
    access_started_at: u64,
    /// Zero until access is closed. A renter can set this themselves with
    /// forceClose, so it moves without this worker doing anything.
    access_ended_at: u64,
    status: u8,
}

#[derive(Debug)]
struct LeaseContext {
    lease: LeaseRecord,
    offer: NodeOffer,
    /// What the renter actually asked for. The offer carries whatever class the
    /// broker last sourced, which moves between refreshes and says nothing
    /// about the promise this lease was sold on.
    min_vram_mib: u32,
    connection_id: Option<String>,
    node_ready_at: Option<DateTime<Utc>>,
    cuda_ready_at: Option<DateTime<Utc>>,
    gateway_ready_at: Option<DateTime<Utc>>,
    access_started_at: Option<DateTime<Utc>>,
    access_ended_at: Option<DateTime<Utc>>,
    gateway_closed_at: Option<DateTime<Utc>>,
    grant_token_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedReproBinding {
    provider_instance_id: u64,
    hourly_cost_micros: u64,
    gpu_model: String,
    gpu_vram_mib: u32,
    transport_host_key_sha256: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    let database_url = required_env("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .context("connect lifecycle database")?;
    verify_schema(&pool).await?;
    record_service_version(&pool, "lifecycle-worker").await?;

    let chain = RpcClient::new(&required_env("PRISM_RPC_URL")?)?;
    if chain.chain_id().await? != ROBINHOOD_CHAIN_ID {
        anyhow::bail!("lifecycle RPC is not Robinhood Chain");
    }
    let confirmations = env::var("PRISM_LIFECYCLE_CONFIRMATIONS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(12);
    if confirmations == 0 || confirmations > 10_000 {
        anyhow::bail!("lifecycle confirmation threshold is invalid");
    }
    let worker = Worker {
        pool,
        chain,
        signer: EthereumSigner::from_environment("PRISM_GATEWAY_KMS_KEY_ID").await?,
        escrow: address(&required_env("PRISM_LEASE_ESCROW_ADDRESS")?)?,
        registry: address(&required_env("PRISM_NODE_REGISTRY_ADDRESS")?)?,
        confirmations,
        gateway: GatewayClient::from_environment()?,
        cipher: CredentialCipher::from_hex(&required_env("PRISM_ACCESS_CREDENTIAL_KEY")?)
            .context("PRISM_ACCESS_CREDENTIAL_KEY must be 32 bytes of hex")?,
        vast: VastBroker::from_environment()?,
        supply_note: tokio::sync::Mutex::new(None),
        last_cloud_capacity_refresh: tokio::sync::Mutex::new(None),
        last_orphan_sweep: tokio::sync::Mutex::new(None),
        last_cloud_observation: tokio::sync::Mutex::new(None),
    };
    worker.audit_historical_transaction_bindings().await?;
    if let Some(vast) = worker.vast.as_ref() {
        tracing::info!(
            slots = vast.node_ids.len(),
            "broker will rent {}",
            vast.policy()
        );
    }
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    let shutdown = Shutdown::default();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        if let Err(error) = shutdown_signal().await {
            tracing::error!(%error, "failed to install lifecycle shutdown signal");
        }
        signal.request().await;
    });
    run(&worker, run_once, &shutdown).await
}

async fn run(worker: &Worker, run_once: bool, shutdown: &Shutdown) -> anyhow::Result<()> {
    loop {
        if shutdown.is_requested() {
            tracing::info!("lifecycle shutdown complete before the next scan");
            return Ok(());
        }
        if let Err(error) = worker.scan().await {
            tracing::error!(%error, "lifecycle scan failed");
        }
        let Some(claim_permit) = shutdown.claim_permit().await else {
            tracing::info!("lifecycle shutdown complete before the next claim");
            return Ok(());
        };
        let claimed = match worker.claim().await {
            Ok(claimed) => claimed,
            Err(error) => {
                tracing::error!(%error, "lifecycle claim failed");
                None
            }
        };
        drop(claim_permit);
        let Some(action) = claimed else {
            if run_once {
                return Ok(());
            }
            tokio::select! {
                () = shutdown.wait() => {
                    tracing::info!("lifecycle shutdown complete while idle");
                    return Ok(());
                }
                () = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
            continue;
        };
        let action_id = action.action_id;
        let claim_generation = action.claim_generation;
        if let Err(error) = worker.process(action).await {
            if error.downcast_ref::<StillProvisioning>().is_some() {
                tracing::debug!(%action_id, "waiting on the box to boot");
            } else {
                tracing::error!(%action_id, %error, "lifecycle action failed");
            }
            if let Err(error) = worker.retry(action_id, claim_generation, &error).await {
                tracing::error!(%action_id, %error, "recording the failed action failed");
            }
        }
        if run_once {
            return Ok(());
        }
        if shutdown.is_requested() {
            tracing::info!(%action_id, "lifecycle shutdown complete after the claimed action");
            return Ok(());
        }
    }
}

impl Worker {
    fn escrow_address(&self) -> String {
        format!("0x{}", hex::encode(self.escrow))
    }

    fn validate_transaction_binding(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> Result<String, TransactionBindingError> {
        validate_lifecycle_transaction_binding(
            transaction,
            ROBINHOOD_CHAIN_ID,
            self.escrow,
            self.signer.address(),
            &action.kind.calldata(action.chain_lease_id),
        )
    }

    async fn escrow_gateway(&self) -> anyhow::Result<[u8; 20]> {
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": self.escrow_address(),
                    "data": format!("0x{}", hex::encode(selector("gateway()")))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
            anyhow::bail!("escrow returned an invalid gateway address");
        }
        let mut gateway = [0_u8; 20];
        gateway.copy_from_slice(&bytes[12..]);
        Ok(gateway)
    }

    async fn audit_historical_transaction_bindings(&self) -> anyhow::Result<()> {
        let gateway = self
            .escrow_gateway()
            .await
            .context("read the configured escrow gateway before transaction audit")?;
        if gateway != self.signer.address() {
            anyhow::bail!("configured lifecycle signer does not match the on-chain escrow gateway");
        }
        let mut database = self.pool.begin().await?;
        query("SELECT pg_advisory_xact_lock($1)")
            .bind(SIGNER_LOCK)
            .execute(&mut *database)
            .await?;
        let attempts = query_as::<
            _,
            (
                String,
                String,
                i64,
                Uuid,
                String,
                String,
                i64,
                Option<String>,
                Option<String>,
                Option<i64>,
                String,
                String,
            ),
        >(
            "SELECT attempt.transaction_hash, attempt.raw_transaction, \
                    attempt.transaction_nonce, action.action_id, action.kind, \
                    lease.escrow_address, lease.chain_lease_id, action.raw_transaction, \
                    action.transaction_hash, action.transaction_nonce, action.status, lease.state \
             FROM lifecycle_transaction_attempts AS attempt \
             JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id \
             JOIN leases AS lease ON lease.lease_id = action.lease_id \
             WHERE attempt.generation_binding_state = 'pending' \
               AND lease.escrow_address = $1 \
             ORDER BY attempt.prepared_at, attempt.transaction_hash \
             FOR UPDATE OF attempt, action, lease",
        )
        .bind(self.escrow_address())
        .fetch_all(&mut *database)
        .await?;
        let mut verified = 0_u64;
        let mut quarantined = 0_u64;
        for (
            transaction_hash,
            raw_transaction,
            transaction_nonce,
            action_id,
            kind,
            escrow_address,
            chain_lease_id,
            action_raw,
            action_hash,
            action_nonce,
            action_status,
            lease_state,
        ) in attempts
        {
            let prepared = PreparedTransaction {
                nonce: u64::try_from(transaction_nonce)?,
                raw_transaction,
                transaction_hash: transaction_hash.clone(),
            };
            let expected = ActionKind::parse(&kind).and_then(|kind| {
                Ok((
                    address(&escrow_address)?,
                    kind.calldata(ChainLeaseId(u64::try_from(chain_lease_id)?)),
                ))
            });
            let audit = expected
                .map_err(|error| {
                    TransactionBindingError::new(
                        "invalid_signed_transaction",
                        format!("stored lifecycle identity is invalid: {error:#}"),
                    )
                })
                .and_then(|(escrow, calldata)| {
                    validate_lifecycle_transaction_binding(
                        &prepared,
                        ROBINHOOD_CHAIN_ID,
                        escrow,
                        self.signer.address(),
                        &calldata,
                    )
                });
            match audit {
                Ok(signer) => {
                    let updated = query(
                        "UPDATE lifecycle_transaction_attempts AS attempt \
                         SET signer_address = $2, generation_binding_state = 'verified' \
                         FROM lifecycle_outbox AS action, leases AS lease \
                         WHERE attempt.transaction_hash = $1 \
                           AND attempt.action_id = action.action_id \
                           AND action.action_id = $3 \
                           AND action.lease_id = lease.lease_id \
                           AND lease.escrow_address = $4 \
                           AND lease.chain_lease_id = $5 \
                           AND attempt.signer_address IS NULL \
                           AND attempt.generation_binding_state = 'pending'",
                    )
                    .bind(&transaction_hash)
                    .bind(signer)
                    .bind(action_id)
                    .bind(&escrow_address)
                    .bind(chain_lease_id)
                    .execute(&mut *database)
                    .await?;
                    if updated.rows_affected() != 1 {
                        anyhow::bail!(
                            "historical lifecycle attempt {transaction_hash} changed during audit"
                        );
                    }
                    verified += 1;
                }
                Err(error) => {
                    let reason = error.reason;
                    let updated = query(
                        "UPDATE lifecycle_transaction_attempts AS attempt \
                         SET generation_binding_state = 'quarantined', \
                             generation_binding_reason = $2 \
                         FROM lifecycle_outbox AS action, leases AS lease \
                         WHERE attempt.transaction_hash = $1 \
                           AND attempt.action_id = action.action_id \
                           AND action.action_id = $3 \
                           AND action.lease_id = lease.lease_id \
                           AND lease.escrow_address = $4 \
                           AND lease.chain_lease_id = $5 \
                           AND attempt.generation_binding_state = 'pending'",
                    )
                    .bind(&transaction_hash)
                    .bind(reason)
                    .bind(action_id)
                    .bind(&escrow_address)
                    .bind(chain_lease_id)
                    .execute(&mut *database)
                    .await?;
                    if updated.rows_affected() != 1 {
                        anyhow::bail!(
                            "historical lifecycle attempt {transaction_hash} changed during quarantine"
                        );
                    }
                    let cursor_matches = action_hash.as_deref() == Some(&transaction_hash)
                        && action_raw.as_deref() == Some(prepared.raw_transaction.as_str())
                        && action_nonce == Some(transaction_nonce);
                    if cursor_matches {
                        let rebuild = !matches!(lease_state.as_str(), "finalized" | "refunded")
                            && action_status != "completed";
                        let detached = query(
                            "UPDATE lifecycle_outbox \
                             SET raw_transaction = NULL, transaction_hash = NULL, \
                                 transaction_nonce = NULL, confirmed_block = NULL, \
                                 confirmed_block_hash = NULL, \
                                 status = CASE WHEN $3 THEN 'queued' ELSE 'failed' END, \
                                 attempts = CASE WHEN $3 THEN 0 ELSE attempts END, \
                                 available_at = CASE WHEN $3 THEN NOW() ELSE available_at END, \
                                 lease_until = NULL, \
                                 last_error = $4, updated_at = NOW() \
                             WHERE action_id = $1 AND transaction_hash = $2 \
                               AND lease_id IN ( \
                                   SELECT lease_id FROM leases \
                                   WHERE escrow_address = $5 AND chain_lease_id = $6 \
                               )",
                        )
                        .bind(action_id)
                        .bind(&transaction_hash)
                        .bind(rebuild)
                        .bind(format!("historical lifecycle cursor quarantined: {reason}"))
                        .bind(&escrow_address)
                        .bind(chain_lease_id)
                        .execute(&mut *database)
                        .await?;
                        if detached.rows_affected() != 1 {
                            anyhow::bail!(
                                "unsafe lifecycle cursor {transaction_hash} could not be detached"
                            );
                        }
                    }
                    tracing::error!(
                        %transaction_hash,
                        %action_id,
                        reason,
                        detail = %error.detail,
                        "quarantined historical lifecycle transaction"
                    );
                    quarantined += 1;
                }
            }
        }
        let pending: i64 = query_scalar(
            "SELECT COUNT(*) FROM lifecycle_transaction_attempts AS attempt \
             JOIN lifecycle_outbox AS action ON action.action_id = attempt.action_id \
             JOIN leases AS lease ON lease.lease_id = action.lease_id \
             WHERE attempt.generation_binding_state = 'pending' \
               AND lease.escrow_address = $1",
        )
        .bind(self.escrow_address())
        .fetch_one(&mut *database)
        .await?;
        if pending != 0 {
            anyhow::bail!("lifecycle transaction binding audit is incomplete");
        }
        database.commit().await?;
        if verified > 0 || quarantined > 0 {
            tracing::info!(
                verified,
                quarantined,
                "audited historical lifecycle transactions"
            );
        }
        Ok(())
    }

    async fn scan(&self) -> anyhow::Result<()> {
        if let Err(error) = self.refresh_cloud_capacity().await {
            tracing::error!(%error, "cloud capacity refresh failed");
        }
        if let Err(error) = self.expire_orphaned_leases().await {
            tracing::error!(%error, "orphaned lease sweep failed");
        }
        if let Err(error) = self.observe_cloud_instances().await {
            tracing::error!(%error, "cloud liveness sweep failed");
        }
        query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
             SELECT md5(lease_id::text || ':expire_provision')::uuid, lease_id, 'expire_provision', \
                    GREATEST(NOW(), created_at + INTERVAL '10 minutes') \
             FROM leases \
             WHERE state IN ('funded', 'provisioning', 'ready') \
               AND escrow_address = $1 \
               AND created_at <= NOW() - INTERVAL '10 minutes' \
             ON CONFLICT (lease_id, kind) DO NOTHING",
        )
        .bind(self.escrow_address())
        .execute(&self.pool)
        .await?;
        // Reconcile after the new worker starts, rather than in the schema
        // migration, so an older worker cannot claim an action kind it does not
        // understand during a staged rollout.
        query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind) \
             SELECT md5(l.lease_id::text || ':cleanup_cloud')::uuid, l.lease_id, 'cleanup_cloud' \
             FROM leases l JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
             WHERE l.state IN ('finalized', 'refunded') AND ci.status <> 'destroyed' \
             ON CONFLICT (lease_id, kind) DO UPDATE \
               SET status = 'queued', attempts = 0, available_at = NOW(), \
                   lease_until = NULL, last_error = NULL, updated_at = NOW() \
             WHERE lifecycle_outbox.status = 'failed'",
        )
        .execute(&self.pool)
        .await?;
        query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind) \
             SELECT md5(l.lease_id::text || ':close_access')::uuid, l.lease_id, 'close_access' \
             FROM leases l \
             JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
             LEFT JOIN node_telemetry nt ON nt.node_id = l.document->>'node_id' \
             LEFT JOIN node_tunnels t ON t.node_id = l.document->>'node_id' \
             LEFT JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
             WHERE l.state = 'active' \
               AND l.escrow_address = $1 \
               AND (lc.access_started_at + \
                    make_interval(secs => (l.document->>'duration_seconds')::int) <= NOW() \
                    OR (ci.lease_id IS NULL AND ( \
                        nt.observed_at IS NULL \
                        OR nt.observed_at < NOW() - INTERVAL '90 seconds' \
                        OR t.observed_at IS NULL \
                        OR t.observed_at < NOW() - INTERVAL '90 seconds')) \
                    OR (ci.lease_id IS NOT NULL AND ( \
                        ci.status NOT IN ('running', 'destroying') \
                        OR ci.observed_at IS NULL \
                        OR ci.observed_at < NOW() - INTERVAL '150 seconds'))) \
             ON CONFLICT (lease_id, kind) DO NOTHING",
        )
        .bind(self.escrow_address())
        .execute(&self.pool)
        .await?;
        // A lease with a close queued keeps `state = 'active'` until that close
        // confirms, and a renter can queue one at any point in the window. The
        // grant is not extended past that: the meter stops at the close, and a
        // fresh hour of access minted after it is compute nobody pays for.
        query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind) \
             SELECT md5(l.lease_id::text || ':refresh_grant')::uuid, l.lease_id, 'refresh_grant' \
             FROM leases l JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
             WHERE l.state = 'active' \
               AND l.escrow_address = $1 \
               AND lc.grant_expires_at <= NOW() + INTERVAL '10 minutes' \
               AND lc.access_started_at + \
                   make_interval(secs => (l.document->>'duration_seconds')::int) \
                   > NOW() + INTERVAL '10 minutes' \
               AND NOT EXISTS ( \
                   SELECT 1 FROM lifecycle_outbox c \
                   WHERE c.lease_id = l.lease_id AND c.kind = 'close_access') \
             ON CONFLICT (lease_id, kind) DO UPDATE \
               SET status = 'queued', available_at = NOW(), lease_until = NULL, \
                   last_error = NULL, document = '{}'::jsonb, updated_at = NOW() \
             WHERE lifecycle_outbox.status = 'completed'",
        )
        .bind(self.escrow_address())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A renter can fund a lease on chain and never reach `/leases/confirm`: the
    /// wallet call succeeds, the request that would have recorded it does not.
    /// Nothing else looks at those. They hold their node until someone notices,
    /// and the renter's deposit sits in the escrow with nothing tracking it.
    /// `expireProvision` is permissionless once the provisioning window closes,
    /// so the network can clean up after itself.
    async fn expire_orphaned_leases(&self) -> anyhow::Result<()> {
        {
            let mut last = self.last_orphan_sweep.lock().await;
            let due = last.is_none_or(|at| {
                at.elapsed() >= std::time::Duration::from_secs(ORPHAN_SCAN_INTERVAL_SECONDS)
            });
            if !due {
                return Ok(());
            }
            *last = Some(std::time::Instant::now());
        }

        let highest = self.lease_count().await?;
        if highest == 0 {
            return Ok(());
        }
        let floor = highest.saturating_sub(ORPHAN_SCAN_DEPTH).max(1);
        // Ids from the escrow, compared against ids the escrow issued. Reading
        // the internal key here would make every recorded lease look orphaned
        // and refund leases that are running.
        let known: Vec<i64> = query_scalar(
            "SELECT chain_lease_id FROM leases \
             WHERE escrow_address = $1 AND chain_lease_id >= $2",
        )
        .bind(format!("0x{}", hex::encode(self.escrow)))
        .bind(floor as i64)
        .fetch_all(&self.pool)
        .await?;
        let now = Utc::now().timestamp() as u64;

        for lease_id in floor..=highest {
            if known.contains(&(lease_id as i64)) {
                continue;
            }
            let lease = self.lease_summary(ChainLeaseId(lease_id)).await?;
            if !expirable(lease, now) {
                continue;
            }
            tracing::warn!(
                lease_id,
                "expiring a lease the escrow holds and this control plane never recorded"
            );
            self.expire_provision_onchain(ChainLeaseId(lease_id))
                .await?;
        }
        Ok(())
    }

    async fn lease_count(&self) -> anyhow::Result<u64> {
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("0x{}", hex::encode(self.escrow)),
                    "data": format!("0x{}", hex::encode(selector("leaseCount()")))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        if bytes.len() != 32 {
            anyhow::bail!("escrow returned an invalid lease count");
        }
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[24..32]);
        Ok(u64::from_be_bytes(word))
    }

    /// What the registry says this node charges. The escrow bills from this
    /// number, so an offer advertising anything else quotes a price the chain
    /// will not honour and funding is rejected against the quote.
    async fn registered_rate(&self, node_id: &str) -> anyhow::Result<u64> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("getNode(bytes32)"));
        data.extend_from_slice(&word_bytes32(bytes32(node_id)?));
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("0x{}", hex::encode(self.registry)),
                    "data": format!("0x{}", hex::encode(data))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        // operator, payout, deviceHash, metadataHash, ratePerSecond, ...
        let rate = bytes
            .get(128..160)
            .context("registry returned a short node record")?;
        let mut word = [0_u8; 8];
        word.copy_from_slice(&rate[24..32]);
        Ok(u64::from_be_bytes(word))
    }

    /// Whether the registry will still accept a lease on this node. The escrow
    /// asks the same question at createLease, so a node that fails here can only
    /// produce a revert and a renter who paid for nothing.
    async fn is_schedulable(&self, node_id: &str) -> anyhow::Result<bool> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("isSchedulable(bytes32)"));
        data.extend_from_slice(&word_bytes32(bytes32(node_id)?));
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("0x{}", hex::encode(self.registry)),
                    "data": format!("0x{}", hex::encode(data))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        Ok(bytes.last().is_some_and(|byte| *byte == 1))
    }

    async fn lease_summary(&self, lease_id: ChainLeaseId) -> anyhow::Result<OnchainLease> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("getLease(uint256)"));
        data.extend_from_slice(&word_u128(u128::from(lease_id.get())));
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("0x{}", hex::encode(self.escrow)),
                    "data": format!("0x{}", hex::encode(data))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        decode_lease(&bytes)
    }

    async fn expire_provision_onchain(&self, lease_id: ChainLeaseId) -> anyhow::Result<()> {
        let reason: [u8; 32] =
            Keccak256::digest(b"prism: funded on chain, never confirmed to the control plane")
                .into();
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&selector("expireProvision(uint256,bytes32)"));
        data.extend_from_slice(&word_u128(u128::from(lease_id.get())));
        data.extend_from_slice(&word_bytes32(reason));

        let mut connection = self.pool.acquire().await?;
        query("SELECT pg_advisory_lock($1)")
            .bind(SIGNER_LOCK)
            .execute(&mut *connection)
            .await?;
        let result = async {
            let prepared = self
                .chain
                .prepare_transaction(&self.signer, self.escrow, &data, ROBINHOOD_CHAIN_ID)
                .await?;
            self.chain.submit(&prepared).await?;
            Ok::<_, anyhow::Error>(prepared.transaction_hash)
        }
        .await;
        let unlock = query("SELECT pg_advisory_unlock($1)")
            .bind(SIGNER_LOCK)
            .execute(&mut *connection)
            .await;
        unlock?;
        let hash = result?;
        tracing::warn!(lease_id = lease_id.get(), %hash, "refunded an unrecorded lease and released its node");
        Ok(())
    }

    /// Keeps watching a rented machine for as long as the renter is paying for
    /// it. Provisioning writes `running` once and then stops looking, so before
    /// this a host that rebooted, was preempted, or whose container exited
    /// stayed `running` in our table until the lease ran out on its own, and
    /// settlement billed the whole window. A self-hosted node has proved itself
    /// every few seconds all along; this is the same guarantee for brokered
    /// capacity.
    async fn observe_cloud_instances(&self) -> anyhow::Result<()> {
        let Some(vast) = self.vast.as_ref() else {
            return Ok(());
        };
        {
            let mut last = self.last_cloud_observation.lock().await;
            let due = last.is_none_or(|at| {
                at.elapsed() >= std::time::Duration::from_secs(CLOUD_OBSERVATION_INTERVAL_SECONDS)
            });
            if !due {
                return Ok(());
            }
            *last = Some(std::time::Instant::now());
        }
        let instances = query_as::<_, (i64, i64)>(
            "SELECT ci.lease_id, ci.provider_instance_id \
             FROM cloud_instances ci JOIN leases l ON l.lease_id = ci.lease_id \
             WHERE l.state IN ('ready', 'active') \
               AND ci.provider_instance_id IS NOT NULL \
               AND ci.status = 'running'",
        )
        .fetch_all(&self.pool)
        .await?;
        for (lease_id, instance_id) in instances {
            let observed = match vast.instance(u64::try_from(instance_id)?).await {
                Ok(instance) => instance.status,
                // A provider that cannot be reached is not evidence the machine
                // died. Leaving `observed_at` alone lets the staleness window
                // close the lease only if this keeps failing.
                Err(error) => {
                    if self.block_provider_failure(&error).await? {
                        return Err(error);
                    }
                    tracing::warn!(lease_id, %error, "could not observe a rented machine");
                    continue;
                }
            };
            let alive = observed == "running";
            let updated = query(
                "UPDATE cloud_instances \
                 SET status = CASE WHEN $2 THEN status ELSE 'failed' END, \
                     last_error = CASE WHEN $2 THEN last_error \
                                  ELSE 'provider reports ' || $3 END, \
                     observed_at = NOW(), updated_at = NOW() \
                 WHERE lease_id = $1 AND provider_instance_id = $4 AND status = 'running'",
            )
            .bind(lease_id)
            .bind(alive)
            .bind(&observed)
            .bind(instance_id)
            .execute(&self.pool)
            .await?;
            if !alive && updated.rows_affected() == 1 {
                tracing::warn!(
                    lease_id,
                    status = %observed,
                    "rented machine stopped running; closing the lease early"
                );
            }
        }
        Ok(())
    }

    async fn refresh_cloud_capacity(&self) -> anyhow::Result<()> {
        let Some(vast) = &self.vast else {
            return Ok(());
        };
        {
            let mut last = self.last_cloud_capacity_refresh.lock().await;
            let due = last.is_none_or(|at| {
                at.elapsed()
                    >= std::time::Duration::from_secs(CLOUD_CAPACITY_REFRESH_INTERVAL_SECONDS)
            });
            if !due {
                return Ok(());
            }
            *last = Some(std::time::Instant::now());
        }

        // Nodes with a lease on them are not for sale, so they are neither
        // advertised nor counted against the hosts we found. A settled lease
        // whose provider cleanup is unfinished also keeps its slot closed.
        let busy: BTreeSet<String> = query_scalar::<_, String>(BROKER_BUSY_NODES_QUERY)
            .bind(self.escrow_address())
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .collect();
        let committed = self.broker_commitments().await?;
        let free: Vec<&String> = vast
            .node_ids
            .iter()
            .filter(|node_id| !busy.contains(*node_id))
            .collect();
        if free.is_empty() {
            self.disable_cloud_capacity(vast.node_ids.as_slice())
                .await?;
            return Ok(());
        }

        if self.provider_breaker_is_latched().await? {
            self.disable_cloud_capacity(vast.node_ids.as_slice())
                .await?;
            tracing::error!("Vast provider breaker is latched; capacity remains disabled");
            return Ok(());
        }
        let balance = match vast.account_balance_micros().await {
            Ok(balance) => balance,
            Err(error) => {
                let (state, class) = provider_failure_state(&error);
                self.block_cloud_provider(None, state, class).await?;
                return Err(error);
            }
        };
        let funded_slots = vast.funded_slots(balance, committed).min(free.len());
        if funded_slots == 0 {
            self.block_cloud_provider(Some(balance), "credit_blocked", "insufficient_balance")
                .await?;
            tracing::warn!(
                balance_micros = balance,
                committed,
                reserve_per_slot_micros = vast.credit_per_slot_micros,
                "Vast balance cannot cover another broker slot"
            );
            return Ok(());
        }
        self.record_healthy_cloud_provider(balance).await?;

        let offers = query_as::<_, (String, SqlJson<NodeOffer>)>(
            "SELECT node_id, document FROM node_offers WHERE node_id = ANY($1)",
        )
        .bind(vast.node_ids.as_slice())
        .fetch_all(&self.pool)
        .await?;
        if offers.is_empty() {
            self.disable_cloud_capacity(vast.node_ids.as_slice())
                .await?;
            tracing::warn!("no Vast broker node is enrolled; cloud capacity is disabled");
            return Ok(());
        }

        // Rates come from the registry, never from the stored document. An
        // operator can reprice a node on chain at any time, and the escrow bills
        // from that number: an offer carrying a stale rate quotes a price the
        // chain will not honour, and confirmation rejects the funding.
        let mut rates: BTreeMap<String, u64> = BTreeMap::new();
        for (node_id, _) in &offers {
            match self.registered_rate(node_id).await {
                Ok(rate) if rate > 0 => {
                    rates.insert(node_id.clone(), rate);
                }
                Ok(_) => tracing::warn!(node_id, "registry reports a zero rate; skipping"),
                Err(error) if prism_chain::is_transient_error(&error) => {
                    self.disable_cloud_capacity(vast.node_ids.as_slice())
                        .await?;
                    return Err(error.context("registry rate refresh was rate-limited"));
                }
                Err(error) => tracing::warn!(node_id, %error, "could not read the registered rate"),
            }
            tokio::time::sleep(Duration::from_millis(RPC_MAINTENANCE_PACE_MILLIS)).await;
        }
        if rates.is_empty() {
            self.disable_cloud_capacity(vast.node_ids.as_slice())
                .await?;
            tracing::warn!("no broker node has a readable rate; cloud capacity is disabled");
            return Ok(());
        }

        // Source against the cheapest node in the pool. A host affordable for
        // the lowest rate is affordable for every other, whereas sourcing at the
        // highest would buy machines the cheap nodes cannot cover.
        let rate = rates.values().copied().min().unwrap_or_default();

        // One search for the whole pool. Advertise as many slots as there are
        // distinct hosts to fill them with, so the market never lists capacity
        // that a second renter would find already taken.
        let survey = match vast.survey_many(retail_hourly(rate), funded_slots).await {
            Ok(survey) => survey,
            Err(error) => {
                let (state, class) = provider_failure_state(&error);
                self.block_cloud_provider(Some(balance), state, class)
                    .await?;
                return Err(error);
            }
        };
        self.report_supply(vast, &survey).await;

        let mut validated = Vec::new();
        for node_id in &free {
            let Some((_, SqlJson(offer))) = offers.iter().find(|(id, _)| id == *node_id) else {
                tracing::warn!(node_id = %node_id, "broker node has no enrolled offer");
                continue;
            };
            let Some(registered) = rates.get(*node_id).copied() else {
                tracing::warn!(node_id = %node_id, "broker node has no current registry rate");
                continue;
            };
            let mut offer = offer.clone();
            offer.rate_per_second = registered;
            // The bonded flag was written once at enrolment and never revisited.
            // A broker node sends no telemetry, so nothing else refreshes it: a
            // node the registry had taken out of service, by a bond change or a
            // slash, stayed in the catalogue and every lease matched to it
            // reverted with LeaseNotReady after the renter had paid. Ask the
            // registry the same question the escrow will ask.
            let schedulable = match self.is_schedulable(node_id).await {
                Ok(schedulable) => schedulable,
                Err(error) if prism_chain::is_transient_error(&error) => {
                    self.disable_cloud_capacity(vast.node_ids.as_slice())
                        .await?;
                    return Err(error.context("registry eligibility refresh was rate-limited"));
                }
                Err(error) => {
                    tracing::warn!(node_id, %error, "could not confirm the node is still bonded");
                    false
                }
            };
            tokio::time::sleep(Duration::from_millis(RPC_MAINTENANCE_PACE_MILLIS)).await;
            if !schedulable {
                tracing::warn!(node_id = %node_id, "broker node is not schedulable");
                continue;
            }
            offer.bonded = true;
            offer.online = true;
            offer.updated_at = Utc::now();
            validated.push(((*node_id).clone(), offer));
        }

        // Matching and confirmation use the same transaction lock. Re-read
        // commitments only after taking it, then make the offer document and
        // capacity row visible together. A funding confirmation that wins the
        // lock is therefore counted before another slot can be advertised.
        let mut transaction = self.pool.begin().await?;
        query("SELECT pg_advisory_xact_lock($1)")
            .bind(SCHEDULER_LOCK)
            .execute(&mut *transaction)
            .await?;
        query(
            "UPDATE cloud_capacity SET available = FALSE, updated_at = NOW() \
             WHERE provider = 'vast' AND node_id = ANY($1)",
        )
        .bind(vast.node_ids.as_slice())
        .execute(&mut *transaction)
        .await?;
        let provider_healthy: bool = query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM cloud_provider_state \
                 WHERE provider = 'vast' AND state = 'healthy' \
                   AND observed_at >= NOW() - INTERVAL '90 seconds' \
             )",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !provider_healthy {
            transaction.commit().await?;
            return Ok(());
        }
        let current_busy: BTreeSet<String> = query_scalar::<_, String>(BROKER_BUSY_NODES_QUERY)
            .bind(self.escrow_address())
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .collect();
        let committed: i64 = query_scalar(BROKER_COMMITMENTS_QUERY)
            .bind(self.escrow_address())
            .fetch_one(&mut *transaction)
            .await?;
        let funded_slots = vast
            .funded_slots(balance, usize::try_from(committed)?)
            .min(survey.hosts.len());
        let current_free = validated
            .into_iter()
            .filter(|(node_id, _)| !current_busy.contains(node_id));
        for ((node_id, mut offer), host) in current_free.take(funded_slots).zip(survey.hosts.iter())
        {
            // Advertise the class that will actually be handed over, not the one
            // the broker enrolled with.
            offer.gpu.model = host.gpu_name.clone();
            offer.gpu.vram_mib = u32::try_from(host.gpu_ram)?;
            let provider_offer_id = i64::try_from(host.id)?;
            let hourly_micros = i64::try_from(vast::hourly_micros(host.dph_total)?)?;
            query(CLOUD_CAPACITY_UPSERT)
                .bind(&node_id)
                .bind(true)
                .bind(provider_offer_id)
                .bind(hourly_micros)
                .execute(&mut *transaction)
                .await?;
            query("UPDATE node_offers SET document = $2, updated_at = NOW() WHERE node_id = $1")
                .bind(&node_id)
                .bind(SqlJson(offer))
                .execute(&mut *transaction)
                .await?;
            let price_unchanged: bool = query_scalar(
                "SELECT EXISTS ( \
                     SELECT 1 FROM capacity_prices \
                     WHERE node_id = $1 \
                       AND hourly_cost_micros = $2 \
                       AND provider_offer_id IS NOT DISTINCT FROM $3 \
                       AND id = (SELECT max(id) FROM capacity_prices WHERE node_id = $1) \
                 )",
            )
            .bind(&node_id)
            .bind(hourly_micros)
            .bind(provider_offer_id)
            .fetch_one(&mut *transaction)
            .await?;
            if !price_unchanged {
                query(
                    "INSERT INTO capacity_prices \
                         (node_id, provider, gpu_model, vram_mib, provider_offer_id, \
                          hourly_cost_micros) \
                     VALUES ($1, 'vast', $2, $3, $4, $5)",
                )
                .bind(&node_id)
                .bind(&host.gpu_name)
                .bind(i32::try_from(host.gpu_ram)?)
                .bind(provider_offer_id)
                .bind(hourly_micros)
                .execute(&mut *transaction)
                .await?;
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn provider_breaker_is_latched(&self) -> anyhow::Result<bool> {
        let state: Option<String> = query_scalar::<_, String>(
            "SELECT state FROM cloud_provider_state WHERE provider = 'vast'",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(state.as_deref().is_some_and(provider_state_is_latched))
    }

    async fn create_vast_instance(
        &self,
        vast: &VastBroker,
        offer_id: u64,
        image: &str,
        lease_id: u64,
    ) -> anyhow::Result<u64> {
        let mut exclusion = self.pool.acquire().await?;
        query("SELECT pg_advisory_lock($1)")
            .bind(SCHEDULER_LOCK)
            .execute(&mut *exclusion)
            .await?;
        let result = async {
            let state: Option<String> =
                query_scalar("SELECT state FROM cloud_provider_state WHERE provider = 'vast'")
                    .fetch_optional(&mut *exclusion)
                    .await?;
            if state.as_deref().is_some_and(provider_state_is_latched) {
                anyhow::bail!("Vast provider breaker is latched");
            }
            vast.create(offer_id, image, lease_id).await
        }
        .await;
        let unlock = query("SELECT pg_advisory_unlock($1)")
            .bind(SCHEDULER_LOCK)
            .execute(&mut *exclusion)
            .await;
        unlock?;
        result
    }

    async fn broker_commitments(&self) -> anyhow::Result<usize> {
        let committed: i64 = query_scalar(BROKER_COMMITMENTS_QUERY)
            .bind(self.escrow_address())
            .fetch_one(&self.pool)
            .await?;
        Ok(usize::try_from(committed)?)
    }

    async fn record_healthy_cloud_provider(&self, balance_micros: i64) -> anyhow::Result<()> {
        let recorded = query(
            "INSERT INTO cloud_provider_state \
                 (provider, balance_micros, state, observed_at) \
             VALUES ('vast', $1, 'healthy', NOW()) \
             ON CONFLICT (provider) DO UPDATE SET \
                 balance_micros = EXCLUDED.balance_micros, state = 'healthy', \
                 failure_class = NULL, blocked_at = NULL, \
                 observed_at = NOW(), consecutive_failures = 0, updated_at = NOW() \
             WHERE cloud_provider_state.state NOT IN ( \
                 'auth_blocked', 'permanent_blocked', 'operator_maintenance' \
             )",
        )
        .bind(balance_micros)
        .execute(&self.pool)
        .await?;
        if recorded.rows_affected() != 1 {
            anyhow::bail!("Vast provider breaker is latched");
        }
        Ok(())
    }

    async fn block_cloud_provider(
        &self,
        balance_micros: Option<i64>,
        state: &str,
        failure_class: &str,
    ) -> anyhow::Result<()> {
        let mut transaction = self.pool.begin().await?;
        query(
            "INSERT INTO cloud_provider_state \
                 (provider, balance_micros, state, failure_class, blocked_at, \
                  observed_at, consecutive_failures) \
             VALUES ('vast', $1, $2, $3, NOW(), NOW(), 1) \
             ON CONFLICT (provider) DO UPDATE SET \
                 balance_micros = COALESCE(EXCLUDED.balance_micros, \
                                           cloud_provider_state.balance_micros), \
                 state = CASE \
                     WHEN cloud_provider_state.state = 'operator_maintenance' \
                     THEN cloud_provider_state.state \
                     WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked') \
                      AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked') \
                     THEN cloud_provider_state.state ELSE EXCLUDED.state END, \
                 failure_class = CASE \
                     WHEN cloud_provider_state.state = 'operator_maintenance' \
                     THEN cloud_provider_state.failure_class \
                     WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked') \
                      AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked') \
                     THEN cloud_provider_state.failure_class ELSE EXCLUDED.failure_class END, \
                 blocked_at = CASE \
                     WHEN cloud_provider_state.state = 'operator_maintenance' \
                     THEN cloud_provider_state.blocked_at \
                     WHEN cloud_provider_state.state IN ('auth_blocked', 'permanent_blocked') \
                      AND EXCLUDED.state NOT IN ('auth_blocked', 'permanent_blocked') \
                     THEN cloud_provider_state.blocked_at \
                     WHEN cloud_provider_state.state = EXCLUDED.state \
                     THEN cloud_provider_state.blocked_at ELSE NOW() END, \
                 observed_at = NOW(), \
                 consecutive_failures = cloud_provider_state.consecutive_failures + 1, \
                 updated_at = NOW()",
        )
        .bind(balance_micros)
        .bind(state)
        .bind(failure_class)
        .execute(&mut *transaction)
        .await?;
        query("UPDATE cloud_capacity SET available = FALSE, updated_at = NOW() WHERE provider = 'vast'")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn block_provider_failure(&self, error: &anyhow::Error) -> anyhow::Result<bool> {
        match vast::failure_scope(error) {
            None | Some(vast::FailureScope::Resource) => Ok(false),
            Some(_) => {
                let (state, class) = provider_failure_state(error);
                self.block_cloud_provider(None, state, class).await?;
                Ok(true)
            }
        }
    }

    async fn disable_cloud_capacity(&self, node_ids: &[String]) -> anyhow::Result<()> {
        query(
            "UPDATE cloud_capacity SET available = FALSE, updated_at = NOW() \
             WHERE provider = 'vast' AND node_id = ANY($1)",
        )
        .bind(node_ids)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// An empty marketplace looks the same from outside whether the provider had
    /// nothing, this broker rents the wrong classes, or everything on offer costs
    /// more than a lease earns. Say which, once per change rather than per poll.
    async fn report_supply(&self, vast: &VastBroker, survey: &vast::Survey) {
        let mut last = self.supply_note.lock().await;
        let note = match (survey.hosts.first(), survey.cheapest_of_class) {
            (Some(offer), _) => format!(
                "sourcing {} for {} of {} slots at {} micros/hr",
                offer.gpu_name,
                survey.hosts.len(),
                vast.node_ids.len(),
                vast::hourly_micros(offer.dph_total).unwrap_or_default()
            ),
            (None, None) if survey.listed == 0 => {
                format!(
                    "no capacity: the provider lists nothing matching {}",
                    vast.policy()
                )
            }
            (None, None) => format!(
                "no capacity: {} offers listed, none of the classes this broker rents ({})",
                survey.listed,
                vast.policy()
            ),
            // Saying "over the ceiling" about a host that is under it sends the
            // next reader to the price policy, which is the one thing that is
            // not wrong. Only price gets blamed for price.
            (None, Some(cheapest)) if survey.affordable == 0 => format!(
                "no capacity: cheapest of {} eligible hosts is {} micros/hr, over the {} ceiling",
                survey.of_our_class, cheapest, survey.ceiling
            ),
            (None, Some(cheapest)) => format!(
                "no capacity: {} of {} eligible hosts are within the {} ceiling (cheapest {} micros/hr), \
                 but none passed the throughput floor or the rejected-machine list",
                survey.affordable, survey.of_our_class, survey.ceiling, cheapest
            ),
        };
        if last.as_deref() != Some(note.as_str()) {
            tracing::info!("{note}");
            *last = Some(note);
        }
    }

    async fn claim(&self) -> anyhow::Result<Option<Action>> {
        let mut transaction = self.pool.begin().await?;
        let row = query_as::<
            _,
            (
                Uuid,
                i64,
                i64,
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
                SqlJson<ActionDocument>,
                i64,
            ),
        >(
            "SELECT o.action_id, o.lease_id, l.chain_lease_id, o.kind, \
                    o.raw_transaction, o.transaction_hash, o.transaction_nonce, o.document, \
                    o.claim_generation \
             FROM lifecycle_outbox o JOIN leases l ON l.lease_id = o.lease_id \
             WHERE (o.attempts < 100 OR o.status = 'submitted' \
                    OR o.kind IN ('close_access', 'expire_provision', 'finalize')) \
               AND (o.kind = 'cleanup_cloud' OR l.escrow_address = $1) \
               AND o.available_at <= NOW() \
               AND (o.status IN ('queued', 'submitted') \
                    OR (o.status = 'processing' AND o.lease_until <= NOW())) \
             ORDER BY o.available_at, o.created_at LIMIT 1 \
             FOR UPDATE OF o SKIP LOCKED",
        )
        .bind(self.escrow_address())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((
            action_id,
            lease_id,
            chain_lease_id,
            kind,
            raw,
            hash,
            nonce,
            document,
            generation,
        )) = row
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let claim_generation: i64 = query_scalar(
            "UPDATE lifecycle_outbox SET status = 'processing', \
                 attempts = LEAST(100, attempts + CASE WHEN status = 'submitted' THEN 0 ELSE 1 END), \
                 claim_generation = claim_generation + 1, \
                 lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
             RETURNING claim_generation",
        )
        .bind(action_id)
        .bind(generation)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let parsed = (|| {
            let SqlJson(document) = document;
            let failed_provider_offer_ids =
                validated_provider_offer_ids(document.failed_provider_offer_ids)?;
            let transaction = match (raw, hash, nonce) {
                (Some(raw_transaction), Some(transaction_hash), Some(nonce)) => {
                    Some(PreparedTransaction {
                        nonce: u64::try_from(nonce)?,
                        raw_transaction,
                        transaction_hash,
                    })
                }
                (None, None, None) => None,
                _ => anyhow::bail!("lifecycle action contains a partial transaction"),
            };
            Ok(Action {
                action_id,
                claim_generation,
                lease_id: u64::try_from(lease_id)?,
                chain_lease_id: ChainLeaseId(u64::try_from(chain_lease_id)?),
                kind: ActionKind::parse(&kind)?,
                transaction,
                failed_provider_offer_ids,
            })
        })();
        match parsed {
            Ok(action) => Ok(Some(action)),
            Err(error) => {
                tracing::error!(%action_id, %error, "lifecycle action is unreadable");
                self.retry(action_id, claim_generation, &error).await?;
                Ok(None)
            }
        }
    }

    async fn process(&self, mut action: Action) -> anyhow::Result<()> {
        if action.kind == ActionKind::CleanupCloud {
            self.destroy_cloud_instance(action.lease_id)
                .await
                .map_err(|error| CloudCleanupPending(format!("{error:#}")))?;
            return self.skip_action(&action).await;
        }
        self.ensure_current_action(&action).await?;
        if action.kind == ActionKind::RefreshGrant {
            return self.refresh_grant(&action).await;
        }
        if action.kind == ActionKind::StartAccess {
            // Reconcile every signed attempt before preparing or rebroadcasting
            // one. An RPC can reject bytes as stale while another node is still
            // propagating them; if those bytes land later, the escrow starts
            // billing even though the outbox has moved on to a replacement.
            let onchain = self.lease_summary(action.chain_lease_id).await?;
            match onchain.status {
                LEASE_STATUS_FUNDED if action.transaction.is_none() => self.probe(&action).await?,
                LEASE_STATUS_FUNDED => {}
                LEASE_STATUS_ACTIVE => {
                    if onchain.access_started_at == 0 {
                        anyhow::bail!("active escrow lease has no access start timestamp");
                    }
                    if let Some(confirmed) = self.confirmed_start_attempt(&action).await? {
                        action.transaction = Some(confirmed.transaction);
                        self.complete(
                            action,
                            confirmed.block_number,
                            &confirmed.block_hash,
                            onchain.access_started_at,
                        )
                        .await?;
                        return Ok(());
                    }
                    self.reschedule_start_reconciliation(&action).await?;
                    return Ok(());
                }
                settled @ (LEASE_STATUS_FINALIZED | LEASE_STATUS_REFUNDED) => {
                    return self.adopt_settled_lease(&action, settled).await;
                }
                // Disputed or settlement-proposed leases cannot be started.
                // Their own actions will reconcile the money without issuing
                // access this start never established.
                status => {
                    tracing::warn!(
                        lease_id = action.lease_id,
                        status,
                        "skipping start_access for a lease the escrow has moved past"
                    );
                    return self.skip_action(&action).await;
                }
            }
        }
        if action.kind == ActionKind::CloseAccess && action.transaction.is_none() {
            self.revoke_access(action.lease_id).await?;
            // closeAccess reverts unless the lease is Active with access still
            // open, and a renter can close their own access with forceClose. A
            // transaction built anyway reverts on every attempt until the action
            // gives up, and giving up is what strands the deposit. Skipping is
            // not enough either: completing this action is what records the
            // close and queues settlement, so adopt the close the chain already
            // has and queue settlement from that.
            let onchain = self.lease_summary(action.chain_lease_id).await?;
            if onchain.status != LEASE_STATUS_ACTIVE {
                tracing::warn!(
                    lease_id = action.lease_id,
                    status = onchain.status,
                    "skipping close_access for a lease the escrow no longer has open"
                );
                return self.skip_action(&action).await;
            }
            if onchain.access_ended_at != 0 {
                tracing::warn!(
                    lease_id = action.lease_id,
                    "access was closed on chain by someone else; settling from that"
                );
                self.adopt_closed_access(&action, onchain.access_ended_at)
                    .await?;
                return self.skip_action(&action).await;
            }
        }
        if action.kind == ActionKind::ExpireProvision && action.transaction.is_none() {
            match self.lease_status(action.chain_lease_id).await? {
                1 => {}
                // expireProvision is permissionless, so anyone may have already
                // released this deposit. Skipping the action alone would leave
                // the lease open in the database against an escrow that no
                // longer holds anything for it, which reads as insolvency and
                // keeps that alarm lit until someone edits the row by hand.
                status @ (LEASE_STATUS_FINALIZED | LEASE_STATUS_REFUNDED) => {
                    return self.adopt_settled_lease(&action, status).await;
                }
                // Anything else belongs to a renter who is still using it.
                _ => return self.skip_action(&action).await,
            }
        }
        if action.kind == ActionKind::Finalize && action.transaction.is_none() {
            match self.lease_status(action.chain_lease_id).await? {
                4 => {
                    self.mark_disputed(&action).await?;
                    return Ok(());
                }
                3 => {}
                // The escrow has already settled this one. Retrying cannot
                // un-settle it, so catch the bookkeeping up instead of asking
                // a hundred more times.
                status @ (LEASE_STATUS_FINALIZED | LEASE_STATUS_REFUNDED) => {
                    self.adopt_settled_lease(&action, status).await?;
                    return Ok(());
                }
                status => anyhow::bail!("lease cannot be finalized from onchain status {status}"),
            }
        }
        let prepared_here = action.transaction.is_none();
        if prepared_here {
            action.transaction = Some(self.prepare(&action).await?);
        }
        let transaction = action
            .transaction
            .as_ref()
            .context("lifecycle transaction was not prepared")?;
        if !prepared_here {
            self.submit_prepared_transaction(&action, transaction)
                .await?;
        }
        match self
            .chain
            .finality(&transaction.transaction_hash, self.confirmations)
            .await?
        {
            Finality::Pending => {
                self.reschedule_submitted(&action).await?;
            }
            Finality::Reverted { .. } => {
                // Drop the prepared transaction so the next attempt reads the
                // chain again and builds a new one. Keeping it meant every
                // retry resubmitted the identical bytes, the node returned the
                // same receipt, and the action could only re-observe its own
                // revert until it exhausted its attempts. The lease was then
                // marked failed while the escrow still held the deposit and the
                // registry still held the node, so a transient revert became a
                // permanent loss.
                if self.reconcile_before_reprepare(&action).await? {
                    return Err(TransactionOutcomePending.into());
                }
                self.discard_reverted_transaction(&action, transaction)
                    .await?;
                anyhow::bail!("lifecycle transaction reverted");
            }
            Finality::Confirmed {
                block_number,
                block_hash,
            } => {
                if matches!(
                    action.kind,
                    ActionKind::ExpireProvision | ActionKind::Finalize
                ) {
                    self.record_terminal_settlement(&action).await?;
                }
                let block_time = if matches!(
                    action.kind,
                    ActionKind::StartAccess | ActionKind::CloseAccess
                ) {
                    self.chain.block_timestamp(block_number).await?
                } else {
                    0
                };
                self.complete(action, block_number, &block_hash, block_time)
                    .await?;
            }
        }
        Ok(())
    }

    async fn probe(&self, action: &Action) -> anyhow::Result<()> {
        let context = self.lease_context(action.lease_id).await?;
        if context.lease.command.is_some() {
            if self.is_cloud_lease(action.lease_id).await? {
                if !self.ensure_cloud_ready(action).await? {
                    anyhow::bail!("managed repro lease has no cloud instance");
                }
                return Ok(());
            }
            if context.lease.state != LeaseState::Ready {
                anyhow::bail!("batch lease is not ready for activation");
            }
            let ready_at = context
                .node_ready_at
                .context("batch command has no signed readiness report")?;
            query(
                "UPDATE lease_lifecycle SET gateway_ready_at = $2, cuda_ready_at = $2, \
                     updated_at = NOW() WHERE lease_id = $1",
            )
            .bind(action.lease_id as i64)
            .bind(ready_at)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if self.ensure_cloud_ready(action).await? {
            return Ok(());
        }
        if context.lease.state != LeaseState::Ready {
            anyhow::bail!("lease is not ready for an access probe");
        }
        let connection_id = context
            .connection_id
            .context("node has no gateway tunnel connection")?;
        let result = self
            .gateway
            .probe(&context.lease.node_id, &connection_id)
            .await?;
        if result.node_id != context.lease.node_id || result.connection_id != connection_id {
            anyhow::bail!("gateway probe identity does not match the lease");
        }
        query(
            "UPDATE lease_lifecycle SET gateway_ready_at = $2, cuda_ready_at = $3, \
                 updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .bind(result.interactive_access_ready_at)
        .bind(result.cuda_ready_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn ensure_cloud_ready(&self, action: &Action) -> anyhow::Result<bool> {
        let lock_key = cloud_lease_lock_key(action.lease_id)?;
        let mut lock = self.pool.acquire().await?;
        query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock)
            .await?;
        let result = self.ensure_cloud_ready_locked(action).await;
        let unlock = query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock)
            .await;
        unlock?;
        if let Err(error) = &result {
            self.block_provider_failure(error).await?;
        }
        result
    }

    async fn stage_refused_cloud_instance(
        &self,
        action: &Action,
        instance_id: u64,
        expected_status: &str,
        machine_id: u64,
        reason: &str,
    ) -> anyhow::Result<StagedRefusal> {
        let machine_id = i64::try_from(machine_id)?;
        if machine_id <= 0 {
            anyhow::bail!("Vast refused instance has no valid machine ID");
        }
        let refusal = StagedRefusal {
            machine_id,
            reason: reason.chars().take(900).collect(),
        };
        let note = refusal.note();
        let mut transaction = self.pool.begin().await?;
        let staged = query(
            "UPDATE cloud_instances \
             SET status = 'destroying', \
                 rejected_machines = CASE WHEN $3 = ANY(rejected_machines) \
                     THEN rejected_machines ELSE array_append(rejected_machines, $3) END, \
                 last_error = $4, updated_at = NOW() \
             WHERE lease_id = $1 AND provider_instance_id = $2 AND status = $5 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM managed_repro_jobs j \
                   WHERE j.lease_id = $1 AND j.prepared_provider_instance_id = $2 \
               ) \
               AND EXISTS ( \
                   SELECT 1 FROM leases l \
                   JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                   WHERE l.lease_id = $1 \
                     AND l.state IN ('funded', 'provisioning', 'ready') \
                     AND o.action_id = $6 AND o.kind = 'start_access' \
                     AND o.status = 'processing' \
                     AND o.claim_generation = $7 \
                     AND o.lease_until > NOW() \
               )",
        )
        .bind(action.lease_id as i64)
        .bind(i64::try_from(instance_id)?)
        .bind(machine_id)
        .bind(&note)
        .bind(expected_status)
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&mut *transaction)
        .await?;
        if staged.rows_affected() != 1 {
            return Err(StillProvisioning.into());
        }
        query(
            "INSERT INTO cloud_machine_rejections (machine_id, reason) VALUES ($1, $2) \
             ON CONFLICT (machine_id) DO UPDATE \
             SET reason = EXCLUDED.reason, \
                 rejections = cloud_machine_rejections.rejections + 1, \
                 last_rejected_at = NOW()",
        )
        .bind(machine_id)
        .bind(&refusal.reason)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(refusal)
    }

    async fn finish_refused_cloud_instance(
        &self,
        action: &Action,
        instance_id: u64,
        refusal: Option<&StagedRefusal>,
    ) -> anyhow::Result<RefusedCleanupOutcome> {
        let unrecorded = i32::from(refusal.is_none());
        let note = refusal.map_or_else(
            || "provider instance destroyed while recovering an unstaged refusal".to_owned(),
            StagedRefusal::note,
        );
        let reason = refusal.map_or("unrecorded provider refusal", |value| value.reason.as_str());
        let status = query_scalar::<_, String>(
            "UPDATE cloud_instances ci \
             SET status = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 THEN 'failed' \
                     ELSE 'provisioning' END, \
                 provider_instance_id = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 \
                     THEN provider_instance_id ELSE NULL END, \
                 provider_offer_id = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 \
                     THEN provider_offer_id ELSE NULL END, \
                 ssh_key_attached_at = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 \
                     THEN ssh_key_attached_at ELSE NULL END, \
                 destroyed_at = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 \
                     THEN COALESCE(destroyed_at, NOW()) ELSE destroyed_at END, \
                 last_error = CASE \
                     WHEN cardinality(rejected_machines) + $3 >= $4 THEN $5 ELSE $6 END, \
                 updated_at = NOW() \
             WHERE ci.lease_id = $1 AND ci.provider_instance_id = $2 \
               AND ci.status = 'destroying' \
               AND ($7::text IS NULL OR ci.last_error = $7) \
               AND EXISTS ( \
                   SELECT 1 FROM leases l \
                   JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                   WHERE l.lease_id = ci.lease_id \
                     AND l.state IN ('funded', 'provisioning', 'ready') \
                     AND o.action_id = $8 AND o.kind = 'start_access' \
                     AND o.status = 'processing' \
                     AND o.claim_generation = $9 \
                     AND o.lease_until > NOW() \
               ) \
             RETURNING status",
        )
        .bind(action.lease_id as i64)
        .bind(i64::try_from(instance_id)?)
        .bind(unrecorded)
        .bind(i32::try_from(MAX_REJECTED_MACHINES)?)
        .bind(format!("every candidate host was refused, last: {reason}"))
        .bind(note)
        .bind(refusal.map(StagedRefusal::note))
        .bind(action.action_id)
        .bind(action.claim_generation)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StillProvisioning)?;
        match status.as_str() {
            "provisioning" => Ok(RefusedCleanupOutcome::Replace),
            "failed" => Ok(RefusedCleanupOutcome::Exhausted),
            _ => anyhow::bail!("refused cloud instance reached invalid state {status}"),
        }
    }

    async fn ensure_cloud_ready_locked(&self, action: &Action) -> anyhow::Result<bool> {
        let lease_id = action.lease_id;
        let row = query_as::<
            _,
            (
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<DateTime<Utc>>,
                String,
                Vec<i64>,
                Option<String>,
            ),
        >(
            "SELECT provider_instance_id, provider_offer_id, ssh_authorized_key, \
                    ssh_key_attached_at, status, rejected_machines, last_error \
             FROM cloud_instances WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let Some((
            stored_instance_id,
            _,
            ssh_key,
            ssh_key_attached_at,
            status,
            rejected,
            last_error,
        )) = row
        else {
            return Ok(false);
        };
        let managed_job = query_as::<_, (Option<String>, String)>(
            "SELECT runner_public_key, status FROM managed_repro_jobs WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let ssh_key = match managed_job.as_ref() {
            Some((_, managed_status)) if managed_status == "failed" && status != "destroying" => {
                anyhow::bail!("managed repro runner failed before provisioning")
            }
            Some((Some(runner_public_key), _)) => {
                if ssh_key
                    .as_ref()
                    .is_some_and(|stored| stored != runner_public_key)
                {
                    anyhow::bail!("managed repro runner key changed after it was assigned");
                }
                if ssh_key.is_none() {
                    let installed = query(
                        "UPDATE cloud_instances SET ssh_authorized_key = $2, updated_at = NOW() \
                         WHERE lease_id = $1 AND ssh_authorized_key IS NULL \
                           AND provider_instance_id IS NOT DISTINCT FROM $3 AND status = $4 \
                           AND EXISTS ( \
                               SELECT 1 FROM leases l \
                               JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                               WHERE l.lease_id = $1 \
                                 AND l.state IN ('funded', 'provisioning', 'ready') \
                                 AND o.action_id = $5 AND o.kind = 'start_access' \
                                 AND o.status = 'processing' \
                                 AND o.claim_generation = $6 \
                                 AND o.lease_until > NOW() \
                           )",
                    )
                    .bind(lease_id as i64)
                    .bind(runner_public_key)
                    .bind(stored_instance_id)
                    .bind(&status)
                    .bind(action.action_id)
                    .bind(action.claim_generation)
                    .execute(&self.pool)
                    .await?;
                    if installed.rows_affected() != 1 {
                        return Err(StillProvisioning.into());
                    }
                }
                runner_public_key.clone()
            }
            Some((None, _)) => return Err(StillProvisioning.into()),
            None => ssh_key.context("interactive cloud lease has no SSH authorized key")?,
        };
        let vast = self
            .vast
            .as_ref()
            .context("Vast is not configured for this cloud lease")?;
        let context = self.lease_context(lease_id).await?;
        if !vast.owns(&context.lease.node_id) {
            anyhow::bail!("cloud lease node is not brokered by this worker");
        }
        let retail = retail_hourly(context.lease.rate_per_second);
        if matches!(status.as_str(), "destroyed" | "failed") {
            anyhow::bail!("cloud instance is in terminal state {status}");
        }
        // The reservation is committed before the provider call. A rate-limited
        // DELETE must resume the same instance, not strand a billing machine or
        // let a replacement race it.
        if status == "destroying" {
            let instance_id = stored_instance_id
                .and_then(|value| u64::try_from(value).ok())
                .context("destroying cloud instance has no provider instance ID")?;
            let refusal = match staged_refusal(last_error.as_deref(), &rejected) {
                Some(refusal) => Some(refusal),
                None => match vast.instance(instance_id).await {
                    Ok(instance) => {
                        let stalled = boot_budget_exhausted(ssh_key_attached_at, Utc::now());
                        let reason = candidate_refusal(
                            &instance,
                            vast.admits(&instance.gpu_name, instance.gpu_ram),
                            context.min_vram_mib,
                            vast.ceiling(retail),
                            &rejected,
                            stalled,
                        )
                        .context("destroying cloud instance has no recoverable refusal")?;
                        Some(
                            self.stage_refused_cloud_instance(
                                action,
                                instance_id,
                                "destroying",
                                instance.machine_id,
                                &reason,
                            )
                            .await?,
                        )
                    }
                    Err(error)
                        if matches!(
                            vast::failure_scope(&error),
                            Some(vast::FailureScope::Resource | vast::FailureScope::Permanent)
                        ) =>
                    {
                        None
                    }
                    Err(error) => {
                        return Err(error.context(CloudCleanupPending(format!(
                            "Vast instance {instance_id} refusal recovery is pending"
                        ))));
                    }
                },
            };
            vast.destroy(instance_id).await.with_context(|| {
                CloudCleanupPending(format!(
                    "Vast instance {instance_id} refusal cleanup is pending"
                ))
            })?;
            let outcome = self
                .finish_refused_cloud_instance(action, instance_id, refusal.as_ref())
                .await?;
            match outcome {
                RefusedCleanupOutcome::Replace => {
                    let detail = refusal
                        .as_ref()
                        .map_or("provider instance was already absent".to_owned(), |value| {
                            format!("machine {} refused: {}", value.machine_id, value.reason)
                        });
                    anyhow::bail!("Vast {detail}")
                }
                RefusedCleanupOutcome::Exhausted => {
                    let reason = refusal
                        .as_ref()
                        .map_or("unrecorded provider refusal", |value| value.reason.as_str());
                    anyhow::bail!("every candidate Vast host was refused, last: {reason}")
                }
            }
        }

        // The escrow measures this window from the block that funded the lease.
        // This row is written later, after the funding reaches its confirmation
        // depth and the client gets around to calling confirm, so measuring from
        // it hands out time the escrow has already spent. The worker then keeps
        // renting hosts for a lease the escrow will refund underneath it, and
        // the renter waits out a window that closed before they were told.
        let opened_at = match self
            .lease_summary(ChainLeaseId(context.lease.chain_lease_id))
            .await
        {
            Ok(lease) if lease.created_at > 0 => {
                DateTime::from_timestamp(lease.created_at as i64, 0)
                    .unwrap_or(context.lease.created_at)
            }
            // Falling back to the row is the old behaviour, which errs towards
            // giving a renter longer rather than cutting them off early.
            _ => context.lease.created_at,
        };
        if Utc::now() >= opened_at + chrono::Duration::seconds(PROVISION_TIMEOUT_SECONDS as i64) {
            anyhow::bail!("the provisioning window for this lease has closed");
        }
        let label = format!("prism-lease-{lease_id}");
        let (instance_id, selected_offer, launched_here) = match stored_instance_id {
            Some(instance_id) => (u64::try_from(instance_id)?, None, false),
            None => match self.adopt_labelled(vast, lease_id, &label).await? {
                Some(instance_id) => (instance_id, None, false),
                None => {
                    if self.provider_breaker_is_latched().await? {
                        anyhow::bail!("Vast provider breaker is latched");
                    }
                    let committed = self.broker_commitments().await?;
                    let balance = vast.require_funded_slots(committed).await?;
                    self.record_healthy_cloud_provider(balance).await?;
                    // Machines this lease has already refused, plus the ones other
                    // leases refused recently. Without the second set every lease
                    // spends its attempts rediscovering the same broken hosts.
                    let mut avoided = rejected.clone();
                    for machine in self.recently_rejected_machines().await? {
                        if !avoided.contains(&machine) {
                            avoided.push(machine);
                        }
                    }
                    let mut failed_offers = action.failed_provider_offer_ids.clone();
                    let mut candidates = vast
                        .ranked(CREATES_PER_PASS, &avoided, &failed_offers, retail)
                        .await?;
                    if candidates.is_empty() && avoided.len() > rejected.len() {
                        // The shared list is an optimisation, not a gate. If honouring
                        // it leaves nothing rentable, a known-bad host still beats
                        // refunding the renter without trying.
                        tracing::warn!(
                            lease_id,
                            avoided = avoided.len(),
                            "no candidate outside the shared rejection list, falling back"
                        );
                        candidates = vast
                            .ranked(CREATES_PER_PASS, &rejected, &failed_offers, retail)
                            .await?;
                    }
                    if candidates.is_empty() {
                        anyhow::bail!(
                            "no verified {} is available under the cost ceiling",
                            vast.gpu_models.join(" or ")
                        );
                    }
                    // Vast can reject a create even when the offer showed rentable, because
                    // another renter took the machine in between. A lost response means the
                    // opposite though: the machine is ours and billing, so look for it under
                    // the lease label before spending on a second one.
                    let mut launched = None;
                    let mut last_error = None;
                    for offer in candidates {
                        match self
                            .create_vast_instance(vast, offer.id, &context.lease.image, lease_id)
                            .await
                        {
                            Ok(instance_id) => {
                                launched = Some((instance_id, offer, true));
                                break;
                            }
                            Err(error) => {
                                let scope = vast::failure_scope(&error);
                                tracing::warn!(
                                    lease_id,
                                    offer_id = offer.id,
                                    %error,
                                    "Vast offer unavailable, trying next candidate"
                                );
                                if let Some(instance_id) =
                                    self.adopt_labelled(vast, lease_id, &label).await?
                                {
                                    launched = Some((instance_id, offer, false));
                                    break;
                                }
                                last_error = Some(error);
                                match scope {
                                    Some(vast::FailureScope::Resource) => {
                                        self.remember_failed_provider_offer(
                                            action,
                                            &mut failed_offers,
                                            offer.id,
                                        )
                                        .await?;
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    let (instance_id, offer, launched_here) = launched.ok_or_else(|| {
                        last_error
                            .unwrap_or_else(|| anyhow::anyhow!("all candidate Vast offers failed"))
                    })?;
                    (instance_id, Some(offer), launched_here)
                }
            },
        };
        let assigned_status = if status == "running" {
            "running"
        } else {
            "provisioning"
        };
        let assigned = query(
            "UPDATE cloud_instances SET provider_instance_id = $2, \
                 provider_offer_id = COALESCE($3, provider_offer_id), \
                 hourly_cost_micros = COALESCE($4, hourly_cost_micros), \
                 status = CASE WHEN status = 'running' THEN status ELSE 'provisioning' END, \
                 last_error = NULL, updated_at = NOW() \
             WHERE lease_id = $1 \
               AND provider_instance_id IS NOT DISTINCT FROM $5 \
               AND status = $6 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM managed_repro_jobs j \
                   WHERE j.lease_id = $1 \
                     AND j.prepared_provider_instance_id IS NOT NULL \
                     AND j.prepared_provider_instance_id <> $2 \
               ) \
               AND EXISTS ( \
                   SELECT 1 FROM leases l \
                   JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                   WHERE l.lease_id = $1 \
                     AND l.state IN ('funded', 'provisioning', 'ready') \
                     AND o.action_id = $7 \
                     AND o.kind = 'start_access' \
                     AND o.status = 'processing' \
                     AND o.claim_generation = $8 \
                     AND o.lease_until > NOW() \
               )",
        )
        .bind(lease_id as i64)
        .bind(i64::try_from(instance_id)?)
        .bind(
            selected_offer
                .as_ref()
                .map(|offer| i64::try_from(offer.id))
                .transpose()?,
        )
        .bind(
            selected_offer
                .as_ref()
                .map(|offer| vast::hourly_micros(offer.dph_total))
                .transpose()?
                .map(i64::try_from)
                .transpose()?,
        )
        .bind(stored_instance_id)
        .bind(&status)
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if assigned.rows_affected() != 1 {
            if launched_here {
                self.destroy_unclaimed_cloud_instance(vast, lease_id, instance_id)
                    .await?;
            }
            return Err(StillProvisioning.into());
        }

        if ssh_key_attached_at.is_none() {
            vast.attach_ssh_key(instance_id, &ssh_key).await?;
            let attached = query(
                "UPDATE cloud_instances SET ssh_key_attached_at = NOW(), updated_at = NOW() \
                 WHERE lease_id = $1 AND provider_instance_id = $2 AND status = $3 \
                   AND EXISTS ( \
                       SELECT 1 FROM leases l \
                       JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                       WHERE l.lease_id = $1 \
                         AND l.state IN ('funded', 'provisioning', 'ready') \
                         AND o.action_id = $4 AND o.kind = 'start_access' \
                         AND o.status = 'processing' \
                         AND o.claim_generation = $5 \
                         AND o.lease_until > NOW() \
                   )",
            )
            .bind(lease_id as i64)
            .bind(i64::try_from(instance_id)?)
            .bind(assigned_status)
            .bind(action.action_id)
            .bind(action.claim_generation)
            .execute(&self.pool)
            .await?;
            if attached.rows_affected() != 1 {
                return Err(StillProvisioning.into());
            }
        }

        let instance = vast.instance(instance_id).await?;
        let stalled = boot_budget_exhausted(ssh_key_attached_at, Utc::now());
        if instance.status != "running" {
            if matches!(
                instance.status.as_str(),
                "exited" | "destroyed" | "failed" | "offline"
            ) {
                let failed = query(
                    "UPDATE cloud_instances SET status = 'failed', last_error = $2, \
                         updated_at = NOW() \
                     WHERE lease_id = $1 AND provider_instance_id = $3 AND status = $4 \
                       AND EXISTS ( \
                           SELECT 1 FROM leases l \
                           JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
                           WHERE l.lease_id = $1 \
                             AND l.state IN ('funded', 'provisioning', 'ready') \
                             AND o.action_id = $5 AND o.kind = 'start_access' \
                             AND o.status = 'processing' \
                             AND o.claim_generation = $6 \
                             AND o.lease_until > NOW() \
                       )",
                )
                .bind(lease_id as i64)
                .bind(format!("Vast instance entered {}", instance.status))
                .bind(i64::try_from(instance_id)?)
                .bind(assigned_status)
                .bind(action.action_id)
                .bind(action.claim_generation)
                .execute(&self.pool)
                .await?;
                if failed.rows_affected() != 1 {
                    return Err(StillProvisioning.into());
                }
                anyhow::bail!("Vast instance entered terminal state {}", instance.status);
            }
            if !stalled {
                return Err(StillProvisioning.into());
            }
            // Out of boot budget. Fall through so this machine is destroyed,
            // blacklisted for this lease and replaced, exactly as a refusal is.
        }
        let mut refusal = candidate_refusal(
            &instance,
            vast.admits(&instance.gpu_name, instance.gpu_ram),
            context.min_vram_mib,
            vast.ceiling(retail),
            &rejected,
            stalled,
        );
        // A forwarded port Vast reports is a promise, not a listener: hosts
        // have answered "running" with a port that refused every connection
        // for the whole window, and a renter handed that address pays for a
        // machine they cannot enter. Access opens only once something speaks
        // SSH on it, and a host that never does is refused inside the boot
        // budget and replaced like any other.
        if refusal.is_none()
            && instance.status == "running"
            && instance.direct_port_start > 0
            && let (Some(host), Some(port)) = (instance.ssh_host.as_deref(), instance.ssh_port)
            && !sshd_answers(host, port).await
        {
            if !stalled {
                return Err(StillProvisioning.into());
            }
            refusal = Some(format!(
                "nothing answered on {host}:{port} after {HOST_BOOT_BUDGET_SECONDS}s of boot budget"
            ));
        }
        if let Some(refusal) = refusal {
            let refusal = self
                .stage_refused_cloud_instance(
                    action,
                    instance_id,
                    assigned_status,
                    instance.machine_id,
                    &refusal,
                )
                .await?;
            vast.destroy(instance_id).await.with_context(|| {
                CloudCleanupPending(format!(
                    "Vast instance {instance_id} refusal cleanup is pending"
                ))
            })?;
            let outcome = self
                .finish_refused_cloud_instance(action, instance_id, Some(&refusal))
                .await?;
            match outcome {
                RefusedCleanupOutcome::Replace => anyhow::bail!(
                    "Vast machine {} refused: {}",
                    refusal.machine_id,
                    refusal.reason
                ),
                RefusedCleanupOutcome::Exhausted => anyhow::bail!(
                    "every candidate Vast host was refused, last: {}",
                    refusal.reason
                ),
            }
        }
        // Not refused, but not usable yet either. A host reports its forwarded
        // port some seconds after it starts reporting itself as running, and
        // the proxy address it advertises in the meantime does not reach sshd.
        // Handing that address to a renter gives them a machine they are paying
        // for and cannot log in to, so the lease stays provisioning until the
        // port is real. If it never becomes real the boot budget refuses the
        // host on a later pass, which is what `stalled` above is for.
        if instance.direct_port_start <= 0 {
            return Err(StillProvisioning.into());
        }
        let host = instance.ssh_host.context("Vast instance has no SSH host")?;
        let port = instance
            .ssh_port
            .filter(|port| *port > 0)
            .context("Vast instance has no SSH port")?;
        let gpu_vram_mib = i32::try_from(instance.gpu_ram)?;
        let mut transaction = self.pool.begin().await?;
        let fence = query_as::<_, (String, String, String, bool, i64, Option<i64>, String)>(
            "SELECT l.state, o.kind, o.status, COALESCE(o.lease_until > NOW(), FALSE), \
                    o.claim_generation, ci.provider_instance_id, ci.status \
             FROM leases l \
             JOIN lifecycle_outbox o ON o.lease_id = l.lease_id \
             JOIN cloud_instances ci ON ci.lease_id = l.lease_id \
             WHERE l.lease_id = $1 AND o.action_id = $2 \
             FOR UPDATE OF l, o, ci",
        )
        .bind(lease_id as i64)
        .bind(action.action_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((
            lease_state,
            action_kind,
            action_status,
            claim_live,
            claim_generation,
            current_id,
            current_status,
        )) = fence
        else {
            return Err(StillProvisioning.into());
        };
        if !cloud_write_fence_matches(
            &lease_state,
            &action_kind,
            &action_status,
            claim_live,
            claim_generation,
            action.claim_generation,
            current_id,
            Some(i64::try_from(instance_id)?),
            &current_status,
            assigned_status,
        ) {
            return Err(StillProvisioning.into());
        }
        let running = query(
            "UPDATE cloud_instances SET hourly_cost_micros = $2, ssh_host = $3, ssh_port = $4, \
                 status = 'running', started_at = COALESCE(started_at, $5), \
                 gpu_model = COALESCE(gpu_model, $6), \
                 gpu_vram_mib = COALESCE(gpu_vram_mib, $7), \
                 last_error = NULL, observed_at = NOW(), updated_at = NOW() \
             WHERE lease_id = $1 AND provider_instance_id = $8 AND status = $9",
        )
        .bind(lease_id as i64)
        .bind(i64::try_from(instance.hourly_micros)?)
        .bind(host)
        .bind(i32::from(port))
        .bind(Utc::now())
        .bind(&instance.gpu_name)
        .bind(gpu_vram_mib)
        .bind(i64::try_from(instance_id)?)
        .bind(assigned_status)
        .execute(&mut *transaction)
        .await?;
        if running.rows_affected() != 1 {
            return Err(StillProvisioning.into());
        }
        if managed_job.is_some() {
            query(
                "UPDATE managed_repro_jobs \
                 SET gpu_model = COALESCE(gpu_model, $2), \
                     gpu_vram_mib = COALESCE(gpu_vram_mib, $3) \
                 WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .bind(&instance.gpu_name)
            .bind(gpu_vram_mib)
            .execute(&mut *transaction)
            .await?;
            let (
                job_status,
                transport_host_key_sha256,
                runner_ready_at,
                prepared_instance_id,
                prepared_hourly_cost_micros,
            ) = query_as::<
                _,
                (
                    String,
                    Option<String>,
                    DateTime<Utc>,
                    Option<i64>,
                    Option<i64>,
                ),
            >(
                "SELECT status, transport_host_key_sha256, updated_at, \
                            prepared_provider_instance_id, prepared_hourly_cost_micros \
                 FROM managed_repro_jobs WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .fetch_one(&mut *transaction)
            .await?;
            if !managed_runner_is_ready(&job_status, transport_host_key_sha256.as_deref())? {
                transaction.commit().await?;
                return Err(StillProvisioning.into());
            }
            if prepared_instance_id != Some(i64::try_from(instance_id)?)
                || prepared_hourly_cost_micros != Some(i64::try_from(instance.hourly_micros)?)
            {
                anyhow::bail!("managed repro runner is not bound to the active provider terms");
            }
            query(
                "UPDATE lease_lifecycle SET connection_id = $2, node_ready_at = $3, \
                     cuda_ready_at = $3, gateway_ready_at = $3, updated_at = NOW() \
                 WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .bind(format!("vast:{instance_id}"))
            .bind(runner_ready_at)
            .execute(&mut *transaction)
            .await?;
            set_lease_state_in(&mut transaction, lease_id, LeaseState::Ready).await?;
            transaction.commit().await?;
            return Ok(true);
        }
        let ready_at = Utc::now();
        query(
            "UPDATE lease_lifecycle SET connection_id = $2, cuda_ready_at = $3, \
                 gateway_ready_at = $3, updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .bind(format!("vast:{instance_id}"))
        .bind(ready_at)
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(&mut transaction, lease_id, LeaseState::Ready).await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn prepare(&self, action: &Action) -> anyhow::Result<PreparedTransaction> {
        let mut connection = self.pool.acquire().await?;
        query("SELECT pg_advisory_lock($1)")
            .bind(SIGNER_LOCK)
            .execute(&mut *connection)
            .await?;
        let result = async {
            let existing = query_as::<_, (Option<String>, Option<String>, Option<i64>)>(
                "SELECT action.raw_transaction, action.transaction_hash, action.transaction_nonce \
                 FROM lifecycle_outbox AS action \
                 JOIN leases AS lease ON lease.lease_id = action.lease_id \
                 WHERE action.action_id = $1 AND action.claim_generation = $2 \
                   AND action.status = 'processing' AND action.lease_until > NOW() \
                   AND lease.escrow_address = $3",
            )
            .bind(action.action_id)
            .bind(action.claim_generation)
            .bind(self.escrow_address())
            .fetch_optional(&mut *connection)
            .await?
            .context("lifecycle action claim expired before transaction preparation")?;
            if let (Some(raw_transaction), Some(transaction_hash), Some(nonce)) = existing {
                let prepared = PreparedTransaction {
                    nonce: u64::try_from(nonce)?,
                    raw_transaction,
                    transaction_hash,
                };
                self.validate_transaction_binding(action, &prepared)?;
                self.ensure_attempt_recorded(action, &prepared).await?;
                return Ok(prepared);
            }
            let data = action.kind.calldata(action.chain_lease_id);
            let prepared = self
                .chain
                .prepare_transaction(&self.signer, self.escrow, &data, ROBINHOOD_CHAIN_ID)
                .await?;
            let signer_address = self.validate_transaction_binding(action, &prepared)?;
            let mut database = connection.begin().await?;
            let preserved: bool = query_scalar(
                "WITH inserted AS ( \
                     INSERT INTO lifecycle_transaction_attempts ( \
                         transaction_hash, action_id, claim_generation, transaction_nonce, \
                         signer_address, raw_transaction, status) \
                     VALUES ($1, $2, $3, $4, $5, $6, 'prepared') \
                     ON CONFLICT (transaction_hash) DO NOTHING \
                     RETURNING transaction_hash \
                 ) \
                 SELECT EXISTS (SELECT 1 FROM inserted) OR EXISTS ( \
                     SELECT 1 FROM lifecycle_transaction_attempts \
                     WHERE transaction_hash = $1 AND action_id = $2 \
                       AND transaction_nonce = $4 \
                       AND signer_address = $5 \
                       AND generation_binding_state = 'verified' \
                       AND raw_transaction = $6 \
                 )",
            )
            .bind(&prepared.transaction_hash)
            .bind(action.action_id)
            .bind(action.claim_generation)
            .bind(i64::try_from(prepared.nonce)?)
            .bind(&signer_address)
            .bind(&prepared.raw_transaction)
            .fetch_one(&mut *database)
            .await?;
            if !preserved {
                database.rollback().await?;
                anyhow::bail!("prepared lifecycle transaction was not preserved in history");
            }
            let stored = query(
                "UPDATE lifecycle_outbox \
                 SET raw_transaction = $2, transaction_hash = $3, \
                     transaction_nonce = $4, status = 'submitted', lease_until = NULL, \
                     updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $5 \
                   AND status = 'processing' AND lease_until > NOW()",
            )
            .bind(action.action_id)
            .bind(&prepared.raw_transaction)
            .bind(&prepared.transaction_hash)
            .bind(i64::try_from(prepared.nonce)?)
            .bind(action.claim_generation)
            .execute(&mut *database)
            .await?;
            if stored.rows_affected() != 1 {
                database.rollback().await?;
                anyhow::bail!("lifecycle action claim expired while preparing its transaction");
            }
            database.commit().await?;
            self.submit_prepared_transaction(action, &prepared).await?;
            Ok::<_, anyhow::Error>(prepared)
        }
        .await;
        let unlock = query("SELECT pg_advisory_unlock($1)")
            .bind(SIGNER_LOCK)
            .execute(&mut *connection)
            .await;
        unlock?;
        result
    }

    async fn submit_prepared_transaction(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        self.validate_transaction_binding(action, transaction)?;
        self.ensure_current_action(action).await?;
        self.ensure_attempt_recorded(action, transaction).await?;
        let status: String = query_scalar(
            "SELECT status FROM lifecycle_transaction_attempts \
             WHERE transaction_hash = $1 AND action_id = $2",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .fetch_one(&self.pool)
        .await?;
        if status == "confirmed" {
            return Ok(());
        }
        if status == "superseded" {
            if self.reconcile_before_reprepare(action).await? {
                return Err(TransactionOutcomePending.into());
            }
            self.supersede_prepared_transaction(action, transaction)
                .await?;
            return Err(TransactionRepreparePending.into());
        }
        if status == "reverted" {
            if self.reconcile_before_reprepare(action).await? {
                return Err(TransactionOutcomePending.into());
            }
            self.discard_reverted_transaction(action, transaction)
                .await?;
            return Err(TransactionRepreparePending.into());
        }
        if self
            .chain
            .transaction_observed(&transaction.transaction_hash)
            .await?
        {
            return Ok(());
        }
        if let Err(error) = self.record_submission(action, transaction).await {
            if error
                .downcast_ref::<TransactionBroadcastLimitReached>()
                .is_some()
                && self.reconcile_before_reprepare(action).await?
            {
                return Err(TransactionOutcomePending.into());
            }
            return Err(error);
        }
        let result = self.chain.broadcast(transaction).await;
        if let Err(error) = result {
            if prism_chain::requires_transaction_reprepare(&error) {
                if self.reconcile_before_reprepare(action).await? {
                    return Err(TransactionOutcomePending.into());
                }
                self.supersede_prepared_transaction(action, transaction)
                    .await
                    .context("preserve and supersede stale lifecycle transaction")?;
            }
            return Err(error);
        }
        Ok(())
    }

    async fn ensure_attempt_recorded(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        let signer_address = self.validate_transaction_binding(action, transaction)?;
        let preserved: bool = query_scalar(
            "WITH inserted AS ( \
                 INSERT INTO lifecycle_transaction_attempts ( \
                     transaction_hash, action_id, claim_generation, transaction_nonce, \
                     signer_address, raw_transaction, status) \
                 VALUES ($1, $2, $3, $4, $6, $5, 'prepared') \
                 ON CONFLICT (transaction_hash) DO NOTHING \
                 RETURNING transaction_hash \
             ) \
             SELECT EXISTS (SELECT 1 FROM inserted) OR EXISTS ( \
                 SELECT 1 FROM lifecycle_transaction_attempts \
                 WHERE transaction_hash = $1 AND action_id = $2 \
                   AND transaction_nonce = $4 \
                   AND signer_address = $6 \
                   AND generation_binding_state = 'verified' \
                   AND raw_transaction = $5 \
             )",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .bind(action.claim_generation)
        .bind(i64::try_from(transaction.nonce)?)
        .bind(transaction.raw_transaction.to_ascii_lowercase())
        .bind(signer_address)
        .fetch_one(&self.pool)
        .await?;
        if !preserved {
            anyhow::bail!("lifecycle transaction hash conflicts with preserved evidence");
        }
        Ok(())
    }

    async fn record_submission(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        self.ensure_attempt_recorded(action, transaction).await?;
        let submitted = query_scalar::<_, i16>(
            "UPDATE lifecycle_transaction_attempts \
             SET status = 'submitted', submitted_at = COALESCE(submitted_at, NOW()), \
                 submission_count = submission_count + 1 \
             WHERE transaction_hash = $1 AND action_id = $2 \
               AND status IN ('prepared', 'submitted') AND submission_count < 100 \
             RETURNING submission_count",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .fetch_optional(&self.pool)
        .await?;
        if submitted.is_some() {
            return Ok(());
        }
        let capped: bool = query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lifecycle_transaction_attempts \
                 WHERE transaction_hash = $1 AND action_id = $2 \
                   AND status IN ('prepared', 'submitted') \
                   AND submission_count >= 100 \
             )",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .fetch_one(&self.pool)
        .await?;
        if capped {
            return Err(TransactionBroadcastLimitReached.into());
        }
        anyhow::bail!("lifecycle transaction attempt cannot be submitted from its outcome")
    }

    async fn transaction_attempts(
        &self,
        action: &Action,
    ) -> anyhow::Result<Vec<PreparedTransaction>> {
        query_as::<_, (String, i64, String)>(
            "SELECT raw_transaction, transaction_nonce, transaction_hash \
             FROM lifecycle_transaction_attempts \
             WHERE action_id = $1 \
               AND signer_address = $2 \
               AND generation_binding_state = 'verified' \
             ORDER BY prepared_at, transaction_hash",
        )
        .bind(action.action_id)
        .bind(format!("0x{}", hex::encode(self.signer.address())))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(raw_transaction, nonce, transaction_hash)| {
            let transaction = PreparedTransaction {
                nonce: u64::try_from(nonce)?,
                raw_transaction,
                transaction_hash,
            };
            self.validate_transaction_binding(action, &transaction)?;
            Ok(transaction)
        })
        .collect()
    }

    async fn observe_transaction_attempts(
        &self,
        action: &Action,
    ) -> anyhow::Result<AttemptObservation> {
        let mut pending = None;
        for transaction in self.transaction_attempts(action).await? {
            match self
                .chain
                .finality(&transaction.transaction_hash, self.confirmations)
                .await?
            {
                Finality::Confirmed {
                    block_number,
                    block_hash,
                } => {
                    self.record_confirmed_attempt(action, &transaction, block_number, &block_hash)
                        .await?;
                    return Ok(AttemptObservation::Confirmed(ConfirmedAttempt {
                        transaction,
                        block_number,
                        block_hash,
                    }));
                }
                Finality::Reverted { .. } => {
                    self.record_reverted_attempt(action, &transaction).await?;
                }
                Finality::Pending => {
                    if pending.is_none()
                        && self
                            .chain
                            .transaction_observed(&transaction.transaction_hash)
                            .await?
                    {
                        pending = Some(transaction);
                    }
                }
            }
        }
        Ok(pending
            .map(AttemptObservation::Pending)
            .unwrap_or(AttemptObservation::None))
    }

    async fn confirmed_start_attempt(
        &self,
        action: &Action,
    ) -> anyhow::Result<Option<ConfirmedAttempt>> {
        match self.observe_transaction_attempts(action).await? {
            AttemptObservation::Confirmed(confirmed) => {
                let block_time = self.chain.block_timestamp(confirmed.block_number).await?;
                let onchain = self.lease_summary(action.chain_lease_id).await?;
                if onchain.status != LEASE_STATUS_ACTIVE
                    || onchain.access_started_at == 0
                    || block_time != onchain.access_started_at
                {
                    anyhow::bail!(
                        "confirmed start transaction does not match the escrow access timestamp"
                    );
                }
                Ok(Some(confirmed))
            }
            AttemptObservation::Pending(_) | AttemptObservation::None => Ok(None),
        }
    }

    async fn reconcile_before_reprepare(&self, action: &Action) -> anyhow::Result<bool> {
        match self.observe_transaction_attempts(action).await? {
            AttemptObservation::Confirmed(confirmed) => {
                self.select_canonical_attempt(action, &confirmed.transaction)
                    .await?;
                Ok(true)
            }
            AttemptObservation::Pending(transaction) => {
                self.select_canonical_attempt(action, &transaction).await?;
                Ok(true)
            }
            AttemptObservation::None if action.kind == ActionKind::StartAccess => {
                Ok(self.lease_summary(action.chain_lease_id).await?.status == LEASE_STATUS_ACTIVE)
            }
            AttemptObservation::None => Ok(false),
        }
    }

    async fn select_canonical_attempt(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        let selected = query(
            "UPDATE lifecycle_outbox \
             SET raw_transaction = $3, transaction_hash = $4, transaction_nonce = $5, \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status IN ('processing', 'submitted')",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .bind(&transaction.raw_transaction)
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(i64::try_from(transaction.nonce)?)
        .execute(&self.pool)
        .await?;
        if selected.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed during transaction reconciliation");
        }
        Ok(())
    }

    async fn record_confirmed_attempt(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
        block_number: u64,
        block_hash: &str,
    ) -> anyhow::Result<()> {
        let recorded = query(
            "UPDATE lifecycle_transaction_attempts \
             SET status = 'confirmed', confirmed_at = COALESCE(confirmed_at, NOW()), \
                 confirmed_block = COALESCE(confirmed_block, $3), \
                 confirmed_block_hash = COALESCE(confirmed_block_hash, $4) \
             WHERE transaction_hash = $1 AND action_id = $2 \
               AND status IN ('prepared', 'submitted', 'superseded', 'confirmed') \
               AND (confirmed_block IS NULL OR confirmed_block = $3) \
               AND (confirmed_block_hash IS NULL OR confirmed_block_hash = $4)",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .bind(i64::try_from(block_number)?)
        .bind(block_hash.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        if recorded.rows_affected() != 1 {
            anyhow::bail!("confirmed lifecycle transaction conflicts with attempt history");
        }
        Ok(())
    }

    async fn record_reverted_attempt(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        let recorded = query(
            "UPDATE lifecycle_transaction_attempts \
             SET status = 'reverted', reverted_at = COALESCE(reverted_at, NOW()) \
             WHERE transaction_hash = $1 AND action_id = $2 \
               AND status IN ('prepared', 'submitted', 'superseded', 'reverted')",
        )
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(action.action_id)
        .execute(&self.pool)
        .await?;
        if recorded.rows_affected() != 1 {
            anyhow::bail!("reverted lifecycle transaction conflicts with attempt history");
        }
        Ok(())
    }

    async fn ensure_current_action(&self, action: &Action) -> anyhow::Result<()> {
        let current: bool = query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lifecycle_outbox AS outbox \
                 JOIN leases AS lease ON lease.lease_id = outbox.lease_id \
                 WHERE outbox.action_id = $1 \
                   AND outbox.claim_generation = $2 \
                   AND lease.escrow_address = $3 \
                   AND (outbox.status = 'submitted' \
                        OR (outbox.status = 'processing' AND outbox.lease_until > NOW())) \
             )",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .bind(self.escrow_address())
        .fetch_one(&self.pool)
        .await?;
        if !current {
            anyhow::bail!("lifecycle action is not live for the configured escrow");
        }
        Ok(())
    }

    async fn complete(
        &self,
        action: Action,
        block_number: u64,
        block_hash: &str,
        block_time: u64,
    ) -> anyhow::Result<()> {
        match action.kind {
            ActionKind::StartAccess => self.complete_start(&action, block_time).await?,
            ActionKind::CloseAccess => self.complete_close(&action, block_time).await?,
            ActionKind::ExpireProvision => {
                self.complete_refund(&action, block_number, block_hash)
                    .await?
            }
            ActionKind::Finalize => {
                self.complete_finalization(&action, block_number, block_hash)
                    .await?
            }
            ActionKind::RefreshGrant | ActionKind::CleanupCloud => unreachable!(),
        }
        let transaction = action
            .transaction
            .as_ref()
            .context("completed lifecycle action has no transaction")?;
        self.record_confirmed_attempt(&action, transaction, block_number, block_hash)
            .await?;
        query(
            "UPDATE lifecycle_transaction_attempts \
             SET status = 'superseded', superseded_at = COALESCE(superseded_at, NOW()) \
             WHERE action_id = $1 AND transaction_hash <> $2 \
               AND status IN ('prepared', 'submitted', 'superseded')",
        )
        .bind(action.action_id)
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        let completed = query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 confirmed_block = $2, confirmed_block_hash = $3, last_error = NULL, \
                 raw_transaction = $5, transaction_hash = $6, transaction_nonce = $7, \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $4 \
               AND status IN ('processing', 'submitted')",
        )
        .bind(action.action_id)
        .bind(i64::try_from(block_number)?)
        .bind(block_hash.to_ascii_lowercase())
        .bind(action.claim_generation)
        .bind(&transaction.raw_transaction)
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .bind(i64::try_from(transaction.nonce)?)
        .execute(&self.pool)
        .await?;
        if completed.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed before completion");
        }
        Ok(())
    }

    async fn complete_start(&self, action: &Action, block_time: u64) -> anyhow::Result<()> {
        let started_at = DateTime::from_timestamp(i64::try_from(block_time)?, 0)
            .context("access start timestamp is invalid")?;
        let transaction_hash = action
            .transaction
            .as_ref()
            .context("start transaction is missing")?
            .transaction_hash
            .to_ascii_lowercase();
        let mut database = self.pool.begin().await?;
        let state: String = query_scalar("SELECT state FROM leases WHERE lease_id = $1 FOR UPDATE")
            .bind(i64::try_from(action.lease_id)?)
            .fetch_one(&mut *database)
            .await?;
        if !matches!(
            state.as_str(),
            "funded" | "provisioning" | "ready" | "active"
        ) {
            anyhow::bail!("local lease cannot adopt an onchain access start from state {state}");
        }
        query(
            "UPDATE lease_lifecycle SET access_started_at = COALESCE(access_started_at, $2), \
                 start_transaction_hash = $3, updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(i64::try_from(action.lease_id)?)
        .bind(started_at)
        .bind(transaction_hash)
        .execute(&mut *database)
        .await?;
        set_lease_state_in(&mut database, action.lease_id, LeaseState::Active).await?;
        database.commit().await?;

        if should_issue_gateway_access(
            self.is_cloud_lease(action.lease_id).await?,
            self.is_batch_lease(action.lease_id).await?,
        ) {
            let context = self.lease_context(action.lease_id).await?;
            if context.connection_id.is_none()
                || context.node_ready_at.is_none()
                || context.cuda_ready_at.is_none()
                || context.gateway_ready_at.is_none()
            {
                return Err(AccessReadinessPending.into());
            }
            let ends_at =
                started_at + chrono::Duration::seconds(i64::from(context.lease.duration_seconds));
            if ends_at > Utc::now() {
                self.issue_grant(action.lease_id, false).await?;
            } else {
                tracing::warn!(
                    lease_id = action.lease_id,
                    "adopted access after its grant window elapsed"
                );
            }
        }
        Ok(())
    }

    /// Records a close this worker did not perform and queues settlement from
    /// it. Without this a renter who closes their own access leaves the lease
    /// with no settlement job, so nobody is ever paid and the deposit sits in
    /// the escrow. There is no close transaction of ours to name, so the hash
    /// stays null and the receipt names the settling transaction instead.
    async fn adopt_closed_access(&self, action: &Action, ended_at: u64) -> anyhow::Result<()> {
        let ended_at = DateTime::from_timestamp(ended_at as i64, 0)
            .context("on-chain access close timestamp is invalid")?;
        query(
            "UPDATE lease_lifecycle SET access_ended_at = COALESCE(access_ended_at, $2), \
                 updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .bind(ended_at)
        .execute(&self.pool)
        .await?;
        let evidence = self.settlement_evidence(action.lease_id).await?;
        let mut transaction = self.pool.begin().await?;
        query(
            "INSERT INTO settlement_jobs (lease_id, evidence) VALUES ($1, $2) \
             ON CONFLICT (lease_id) DO NOTHING",
        )
        .bind(action.lease_id as i64)
        .bind(SqlJson(evidence))
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(
            &mut transaction,
            action.lease_id,
            LeaseState::SettlementPending,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn complete_close(&self, action: &Action, block_time: u64) -> anyhow::Result<()> {
        let ended_at = DateTime::from_timestamp(block_time as i64, 0)
            .context("access close timestamp is invalid")?;
        query(
            "UPDATE lease_lifecycle SET access_ended_at = COALESCE(access_ended_at, $2), \
                 close_transaction_hash = $3, updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .bind(ended_at)
        .bind(
            action
                .transaction
                .as_ref()
                .context("close transaction is missing")?
                .transaction_hash
                .to_ascii_lowercase(),
        )
        .execute(&self.pool)
        .await?;
        let evidence = self.settlement_evidence(action.lease_id).await?;
        let mut transaction = self.pool.begin().await?;
        query(
            "INSERT INTO settlement_jobs (lease_id, evidence) VALUES ($1, $2) \
             ON CONFLICT (lease_id) DO NOTHING",
        )
        .bind(action.lease_id as i64)
        .bind(SqlJson(evidence))
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(
            &mut transaction,
            action.lease_id,
            LeaseState::SettlementPending,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn complete_refund(
        &self,
        action: &Action,
        block_number: u64,
        block_hash: &str,
    ) -> anyhow::Result<()> {
        let context = self.lease_context(action.lease_id).await?;
        let transaction_hash = &action
            .transaction
            .as_ref()
            .context("refund transaction is missing")?
            .transaction_hash;
        let attestation = self.receipt_attestation(&context).await?;
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            // What the escrow numbered it, so a reader can find this lease on
            // chain. The internal id means nothing outside this database.
            lease_id: action.chain_lease_id.get().to_string(),
            escrow_address: Some(self.escrow_address()),
            chain_lease_id: Some(action.chain_lease_id.get().to_string()),
            node_id_hash: format!(
                "0x{}",
                hex::encode(Sha256::digest(context.lease.node_id.as_bytes()))
            ),
            gpu_model: context.offer.gpu.model,
            runtime_seconds: 0,
            charged_base_units: 0,
            refunded_base_units: context.lease.maximum_escrow,
            provider_paid_base_units: 0,
            failure_class: Some("provisioning_timeout".to_owned()),
            outcome: ReceiptOutcome::Refunded,
            trust_class: Some(context.lease.trust_class),
            attestation,
            // A machine that never arrived was never billed, so there is
            // nothing to credit back and nothing to say here.
            credited_seconds: None,
            repro: None,
            receipt_hash: String::new(),
            transaction_hash: transaction_hash.clone(),
        };
        receipt.receipt_hash = receipt_hash(&receipt)?;
        self.insert_receipt(action.lease_id, &receipt, block_number, block_hash)
            .await?;
        Ok(())
    }

    async fn complete_finalization(
        &self,
        action: &Action,
        block_number: u64,
        block_hash: &str,
    ) -> anyhow::Result<()> {
        let proposal: serde_json::Value = query_scalar(
            "SELECT proposal FROM settlement_jobs WHERE lease_id = $1 AND proposal IS NOT NULL",
        )
        .bind(action.lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        let mut receipt: PublicReceipt = serde_json::from_value(
            proposal
                .pointer("/proposal/receipt")
                .or_else(|| proposal.get("receipt"))
                .cloned()
                .context("settlement proposal contains no receipt")?,
        )?;
        self.enrich_receipt_identity(&mut receipt, action.chain_lease_id)?;
        receipt.transaction_hash = action
            .transaction
            .as_ref()
            .context("finalization transaction is missing")?
            .transaction_hash
            .clone();
        self.insert_receipt(action.lease_id, &receipt, block_number, block_hash)
            .await?;
        query(
            "UPDATE settlement_jobs SET status = 'finalized', updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_terminal_settlement(&self, action: &Action) -> anyhow::Result<()> {
        let state = match action.kind {
            ActionKind::ExpireProvision => LeaseState::Refunded,
            ActionKind::Finalize => LeaseState::Finalized,
            _ => anyhow::bail!("lifecycle action is not a terminal settlement"),
        };
        let mut transaction = self.pool.begin().await?;
        set_lease_state_in(&mut transaction, action.lease_id, state).await?;
        enqueue_cloud_cleanup_in(&mut transaction, action.lease_id).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn refresh_grant(&self, action: &Action) -> anyhow::Result<()> {
        let decision = refresh_decision(
            self.access_is_closed(action.lease_id).await?,
            self.is_cloud_lease(action.lease_id).await?,
            self.is_batch_lease(action.lease_id).await?,
        );
        match decision {
            RefreshDecision::Drop => return self.skip_action(action).await,
            RefreshDecision::Rotate => self.issue_grant(action.lease_id, true).await?,
            RefreshDecision::Nothing => {}
        }
        let completed = query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 last_error = NULL, updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status = 'processing'",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if completed.rows_affected() != 1 {
            anyhow::bail!("refresh-grant action claim changed before completion");
        }
        Ok(())
    }

    /// The verdict recorded for this lease, if the guest has been attested.
    /// Read rather than derived: the gateway checks it against what the lease
    /// was sold as, and a worker that could synthesise one would defeat the
    /// check it is feeding.
    async fn lease_verdict(
        &self,
        lease_id: u64,
    ) -> anyhow::Result<Option<LeaseAttestationVerdict>> {
        let row = query_scalar::<_, SqlJson<LeaseAttestationVerdict>>(
            "SELECT document FROM lease_attestation_verdicts WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|SqlJson(verdict)| verdict))
    }

    /// Whether the gateway has already been shut on this lease. Set once, by
    /// `revoke_access`, and never cleared: the close it belongs to is what stops
    /// the meter.
    async fn access_is_closed(&self, lease_id: u64) -> anyhow::Result<bool> {
        query_scalar(
            "SELECT COALESCE((SELECT gateway_closed_at IS NOT NULL FROM lease_lifecycle \
                              WHERE lease_id = $1), FALSE)",
        )
        .bind(lease_id as i64)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    async fn issue_grant(&self, lease_id: u64, rotate: bool) -> anyhow::Result<()> {
        if !should_issue_gateway_access(
            self.is_cloud_lease(lease_id).await?,
            self.is_batch_lease(lease_id).await?,
        ) {
            anyhow::bail!("gateway access is unavailable for cloud and batch leases");
        }
        let context = self.lease_context(lease_id).await?;
        if context.gateway_closed_at.is_some() {
            anyhow::bail!("access for this lease has already been closed");
        }
        let connection_id = context
            .connection_id
            .as_deref()
            .context("lease has no gateway connection")?;
        let started_at = context.access_started_at.unwrap_or_else(Utc::now);
        let ends_at =
            started_at + chrono::Duration::seconds(i64::from(context.lease.duration_seconds));
        let remaining = ends_at.signed_duration_since(Utc::now()).num_seconds();
        if remaining <= 0 {
            anyhow::bail!("lease access duration has elapsed");
        }
        let ttl_seconds = u32::try_from(remaining.clamp(60, 3_600))?;
        let token_id = if rotate || context.grant_token_id.is_none() {
            let token_id = Uuid::now_v7();
            query(
                "UPDATE lease_lifecycle SET grant_token_id = $2, updated_at = NOW() \
                 WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .bind(token_id)
            .execute(&self.pool)
            .await?;
            token_id
        } else {
            context
                .grant_token_id
                .context("grant token ID is missing")?
        };
        let response = self
            .gateway
            .issue_grant(
                token_id,
                lease_id,
                &context.lease.node_id,
                connection_id,
                ttl_seconds,
                context.lease.trust_class,
                self.lease_verdict(lease_id).await?,
            )
            .await?;
        if response.grant.token_id != token_id
            || response.grant.lease_id != lease_id.to_string()
            || response.grant.node_id != context.lease.node_id
            || response.grant.connection_id != connection_id
        {
            anyhow::bail!("gateway returned a grant for a different lease");
        }
        let encrypted = self.cipher.encrypt(&response.token)?;
        query(
            "UPDATE lease_lifecycle SET grant_token = $2, grant_expires_at = $3, \
                 updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .bind(SqlJson(encrypted))
        .bind(response.grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn revoke_access(&self, lease_id: u64) -> anyhow::Result<()> {
        if self.destroy_cloud_instance(lease_id).await? {
            query(
                "UPDATE lease_lifecycle SET gateway_closed_at = COALESCE(gateway_closed_at, NOW()), \
                     grant_token = NULL, grant_expires_at = NULL, updated_at = NOW() \
                 WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        let context = self.lease_context(lease_id).await?;
        if let Some(token_id) = context.grant_token_id {
            self.gateway.revoke(token_id).await?;
        }
        query(
            "UPDATE lease_lifecycle SET gateway_closed_at = COALESCE(gateway_closed_at, NOW()), \
                 grant_token = NULL, grant_expires_at = NULL, updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn is_cloud_lease(&self, lease_id: u64) -> anyhow::Result<bool> {
        query_scalar("SELECT EXISTS (SELECT 1 FROM cloud_instances WHERE lease_id = $1)")
            .bind(lease_id as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    async fn is_batch_lease(&self, lease_id: u64) -> anyhow::Result<bool> {
        query_scalar("SELECT document->>'command' IS NOT NULL FROM leases WHERE lease_id = $1")
            .bind(lease_id as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// A create whose response was lost still leaves a machine running and
    /// billing, and the label is the only handle left on it. The caller holds
    /// the lease advisory lock so another claimant cannot bind an orphan while
    /// this method is destroying it.
    async fn adopt_labelled(
        &self,
        vast: &VastBroker,
        lease_id: u64,
        label: &str,
    ) -> anyhow::Result<Option<u64>> {
        let found = vast.find_by_label(label).await?;
        let binding = query_as::<_, (Option<i64>, Option<i64>)>(
            "SELECT ci.provider_instance_id, j.prepared_provider_instance_id \
             FROM cloud_instances ci \
             LEFT JOIN managed_repro_jobs j ON j.lease_id = ci.lease_id \
             WHERE ci.lease_id = $1",
        )
        .bind(i64::try_from(lease_id)?)
        .fetch_optional(&self.pool)
        .await?;
        let (current, prepared) = binding.unwrap_or((None, None));
        let (adopted, orphans) = labelled_instance_plan(found, current, prepared)?;
        for orphan in orphans {
            tracing::warn!(
                orphan,
                label,
                "destroying a duplicate instance for this lease"
            );
            vast.destroy(orphan).await?;
        }
        Ok(adopted)
    }

    async fn destroy_unclaimed_cloud_instance(
        &self,
        vast: &VastBroker,
        lease_id: u64,
        instance_id: u64,
    ) -> anyhow::Result<()> {
        // Provisioning and close paths hold the same lease advisory lock through
        // this recheck and provider call. Without it, a replacement claimant can
        // bind this label after the query and lose its current instance here.
        let binding = query_as::<_, (Option<i64>, Option<i64>)>(
            "SELECT ci.provider_instance_id, j.prepared_provider_instance_id \
             FROM cloud_instances ci \
             LEFT JOIN managed_repro_jobs j ON j.lease_id = ci.lease_id \
             WHERE ci.lease_id = $1",
        )
        .bind(i64::try_from(lease_id)?)
        .fetch_optional(&self.pool)
        .await?;
        let instance_id_i64 = i64::try_from(instance_id)?;
        if binding.is_some_and(|(current, prepared)| {
            current == Some(instance_id_i64) || prepared == Some(instance_id_i64)
        }) {
            return Ok(());
        }
        tracing::warn!(
            lease_id,
            instance_id,
            "destroying an instance launched by a stale claim"
        );
        vast.destroy(instance_id).await
    }

    async fn destroy_cloud_instance(&self, lease_id: u64) -> anyhow::Result<bool> {
        let lock_key = cloud_lease_lock_key(lease_id)?;
        let mut lock = self.pool.acquire().await?;
        query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock)
            .await?;
        let result = self.destroy_cloud_instance_locked(lease_id).await;
        let unlock = query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock)
            .await;
        unlock?;
        if let Err(error) = &result {
            self.block_provider_failure(error).await?;
        }
        result
    }

    async fn destroy_cloud_instance_locked(&self, lease_id: u64) -> anyhow::Result<bool> {
        let row = query_as::<_, (Option<i64>, String, Option<i64>, bool)>(
            "SELECT ci.provider_instance_id, ci.status, j.prepared_provider_instance_id, \
                    j.command_id IS NOT NULL \
             FROM cloud_instances ci \
             LEFT JOIN managed_repro_jobs j ON j.lease_id = ci.lease_id \
             WHERE ci.lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let Some((instance_id, status, prepared_instance_id, managed)) = row else {
            return Ok(false);
        };
        if status == "destroyed" && !managed {
            return Ok(true);
        }
        query(
            "UPDATE cloud_instances SET status = 'destroying', updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .execute(&self.pool)
        .await?;
        let vast = self
            .vast
            .as_ref()
            .context("Vast is not configured for this cloud lease")?;
        let labelled = if managed || instance_id.is_none() {
            vast.find_by_label(&format!("prism-lease-{lease_id}"))
                .await?
        } else {
            Vec::new()
        };
        for target in
            cloud_destruction_targets(instance_id, prepared_instance_id, managed, labelled)?
        {
            if managed && prepared_instance_id != Some(i64::try_from(target)?) {
                tracing::warn!(lease_id, target, "destroying a drifted managed instance");
            }
            vast.destroy(target).await?;
        }
        query(
            "UPDATE cloud_instances SET status = 'destroyed', destroyed_at = COALESCE(destroyed_at, NOW()), \
                 ssh_host = NULL, ssh_port = NULL, last_error = NULL, updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    /// The verdict the lease's class rests on, as a digest. Only a class above
    /// `Open` was earned from one, and a digest hung off an Open lease would
    /// read as a claim nobody made, so nothing is looked up in that case.
    async fn receipt_attestation(
        &self,
        context: &LeaseContext,
    ) -> anyhow::Result<Option<ReceiptAttestation>> {
        if context.lease.trust_class <= TrustClass::Open {
            return Ok(None);
        }
        let verdict = query_scalar::<_, SqlJson<AttestationVerdict>>(
            "SELECT document FROM node_attestation_verdicts WHERE node_id = $1",
        )
        .bind(&context.lease.node_id)
        .fetch_optional(&self.pool)
        .await?;
        verdict
            .map(|SqlJson(verdict)| {
                Ok(ReceiptAttestation {
                    kind: verdict.kind,
                    verdict_digest: verdict_digest(&verdict)?,
                    verifier_version: verdict.verifier_version,
                })
            })
            .transpose()
    }

    async fn settlement_evidence(&self, lease_id: u64) -> anyhow::Result<SettlementEvidence> {
        let context = self.lease_context(lease_id).await?;
        let (repro, managed_binding) = self.repro_execution_evidence(&context).await?;
        let managed_finished_at = repro
            .as_ref()
            .and_then(|evidence| match &evidence.report {
                ReproExecutionReport::Managed { report } => Some(report),
                ReproExecutionReport::Node { .. } => None,
            })
            .map(|report| report.finished_at);
        let cloud = query_as::<
            _,
            (
                Option<i64>,
                Option<i64>,
                String,
                Option<DateTime<Utc>>,
                Option<String>,
                Option<i32>,
            ),
        >(
            "SELECT provider_instance_id, hourly_cost_micros, status, observed_at, \
                    gpu_model, gpu_vram_mib \
             FROM cloud_instances \
             WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        // The last time anything confirmed the machine was still there. For a
        // cloud instance that is the provider poll; for a node of our own it is
        // the newest telemetry it signed. Settlement meters up to this rather
        // than to the close, so the renter does not pay for the gap between a
        // machine going away and us noticing.
        let mut last_observed_at = cloud
            .as_ref()
            .and_then(|(_, _, _, observed_at, _, _)| *observed_at);
        let (execution, gpu_model) = match cloud {
            Some((instance_id, hourly_cost_micros, status, _, gpu_model, gpu_vram_mib)) => {
                if status != "destroyed" {
                    anyhow::bail!("cloud instance was not destroyed before settlement");
                }
                if managed_binding.is_some() {
                    last_observed_at = managed_finished_at;
                }
                cloud_execution_terms(
                    instance_id,
                    hourly_cost_micros,
                    gpu_model,
                    gpu_vram_mib,
                    managed_binding.as_ref(),
                )?
            }
            None if managed_binding.is_some() => {
                anyhow::bail!("managed repro lease has no cloud execution record")
            }
            None => (ExecutionEvidence::Physical, context.offer.gpu.model.clone()),
        };
        let telemetry = query_scalar::<_, SqlJson<NodeTelemetry>>(
            "SELECT document FROM lease_telemetry WHERE lease_id = $1 ORDER BY sequence",
        )
        .bind(lease_id as i64)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|SqlJson(value)| value)
        .collect::<Vec<NodeTelemetry>>();
        if last_observed_at.is_none() {
            last_observed_at = telemetry.iter().map(|record| record.observed_at).max();
        }
        let timestamp = |value: Option<DateTime<Utc>>, name: &str| {
            value
                .with_context(|| format!("{name} is missing"))
                .and_then(|value| u64::try_from(value.timestamp()).map_err(Into::into))
        };
        Ok(SettlementEvidence {
            lease_id,
            chain_lease_id: context.lease.chain_lease_id,
            lease_nonce: 1,
            node_id: context.lease.node_id,
            device_public_key: context.offer.device_public_key,
            gpu_model,
            image_digest: context
                .lease
                .image
                .rsplit_once('@')
                .map(|(_, digest)| digest.to_owned())
                .context("lease image has no immutable digest")?,
            rate_per_second: context.lease.rate_per_second,
            deposit_base_units: context.lease.maximum_escrow,
            duration_seconds: context.lease.duration_seconds,
            access_started_at: timestamp(context.access_started_at, "access start")?,
            access_ended_at: timestamp(context.access_ended_at, "access end")?,
            cuda_ready_at: timestamp(context.cuda_ready_at, "CUDA readiness")?,
            interactive_access_ready_at: timestamp(
                context.gateway_ready_at,
                "interactive readiness",
            )?,
            gateway_closed_at: timestamp(context.gateway_closed_at, "gateway close")?,
            last_observed_at: last_observed_at
                .and_then(|value| u64::try_from(value.timestamp()).ok()),
            trust_class: Some(context.lease.trust_class),
            execution,
            node_telemetry: telemetry,
            repro,
        })
    }

    async fn repro_execution_evidence(
        &self,
        context: &LeaseContext,
    ) -> anyhow::Result<(Option<ReproExecutionEvidence>, Option<ManagedReproBinding>)> {
        let Some(capability) = context.lease.repro.clone() else {
            return Ok((None, None));
        };
        let expected_command = context
            .lease
            .command
            .as_deref()
            .context("repro lease has no batch command")?;
        let spec = GpuReproSpec {
            image: context.lease.image.clone(),
            command: expected_command.to_owned(),
            duration_seconds: context.lease.duration_seconds,
            min_vram_mib: context.min_vram_mib,
            expected_exit_code: capability.expected_exit_code,
        };
        if spec.hash()? != capability.spec_hash {
            anyhow::bail!("repro capability does not match its lease contract");
        }
        let validate_command = |command: &NodeCommand| -> anyhow::Result<()> {
            if command.node_id != context.lease.node_id
                || command.lease_id != context.lease.lease_id
            {
                anyhow::bail!("repro command does not belong to its lease");
            }
            let NodeCommandKind::Batch {
                image,
                command: program,
                duration_seconds,
            } = &command.kind
            else {
                anyhow::bail!("repro lease command is not a batch run");
            };
            if image != &context.lease.image
                || program != expected_command
                || *duration_seconds != context.lease.duration_seconds
            {
                anyhow::bail!("repro command does not match its lease contract");
            }
            Ok(())
        };

        let managed = query_as::<
            _,
            (
                String,
                SqlJson<NodeCommand>,
                Option<SqlJson<ManagedCommandReport>>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<i32>,
                Option<String>,
            ),
        >(
            "SELECT j.status, j.command, j.report, j.prepared_provider_instance_id, \
                    j.prepared_hourly_cost_micros, \
                    j.gpu_model, j.gpu_vram_mib, j.transport_host_key_sha256 \
             FROM managed_repro_jobs j WHERE j.lease_id = $1",
        )
        .bind(context.lease.lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        if let Some((
            status,
            SqlJson(command),
            report,
            provider_instance_id,
            hourly_cost_micros,
            gpu_model,
            gpu_vram_mib,
            transport_host_key_sha256,
        )) = managed
        {
            if capability.executor != ReproExecutor::Managed {
                anyhow::bail!("managed repro job does not match its approved executor");
            }
            validate_command(&command)?;
            let binding = managed_repro_binding(
                provider_instance_id,
                hourly_cost_micros,
                gpu_model,
                gpu_vram_mib,
                transport_host_key_sha256,
            );
            if reportless_failure(&status, report.is_some()) {
                return Ok((None, binding.ok()));
            }
            let binding = binding?;
            let report = report
                .map(|SqlJson(report)| report)
                .context("managed repro command has no signed final report")?;
            if !managed_report_matches_binding(
                &report,
                command.command_id,
                context.lease.lease_id,
                &binding,
            ) || report.started_at > report.finished_at
                || !terminal_report_shape(
                    &report.outcome,
                    report.error.as_deref(),
                    report.result.as_ref(),
                )
                || report.verify().is_err()
            {
                anyhow::bail!("managed repro has no valid terminal signed report");
            }
            return Ok((
                Some(ReproExecutionEvidence {
                    capability,
                    spec,
                    command,
                    report: ReproExecutionReport::Managed { report },
                }),
                Some(binding),
            ));
        }
        if self.is_cloud_lease(context.lease.lease_id).await? {
            anyhow::bail!("cloud repro lease has no managed job");
        }
        if capability.executor != ReproExecutor::Node {
            anyhow::bail!("node repro job does not match its approved executor");
        }

        let (status, SqlJson(command), report) = query_as::<
            _,
            (
                String,
                SqlJson<NodeCommand>,
                Option<SqlJson<NodeCommandReport>>,
            ),
        >(
            "SELECT status, document, verified_report FROM node_commands WHERE lease_id = $1",
        )
        .bind(context.lease.lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        validate_command(&command)?;
        if reportless_failure(&status, report.is_some()) {
            return Ok((None, None));
        }
        let report = report
            .map(|SqlJson(report)| report)
            .context("repro command has no verified final report")?;
        let key = verifying_key(&context.offer.device_public_key)?;
        if node_id(&key) != context.lease.node_id
            || report.node_id != context.lease.node_id
            || report.device_public_key != context.offer.device_public_key
            || report.command_id != command.command_id
            || !terminal_report_shape(
                &report.outcome,
                report.error.as_deref(),
                report.result.as_ref(),
            )
            || report.verify(&key).is_err()
        {
            anyhow::bail!("repro command has no valid terminal node report");
        }
        Ok((
            Some(ReproExecutionEvidence {
                capability,
                spec,
                command,
                report: ReproExecutionReport::Node { report },
            }),
            None,
        ))
    }

    async fn lease_context(&self, lease_id: u64) -> anyhow::Result<LeaseContext> {
        let row = query_as::<
            _,
            (
                SqlJson<LeaseRecord>,
                SqlJson<NodeOffer>,
                Option<String>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Option<Uuid>,
                i32,
            ),
        >(
            "SELECT l.document, o.document, lc.connection_id, \
                    lc.node_ready_at, lc.cuda_ready_at, lc.gateway_ready_at, lc.access_started_at, \
                    lc.access_ended_at, lc.gateway_closed_at, lc.grant_token_id, \
                    COALESCE((q.document->>'min_vram_mib')::int, 0) \
             FROM leases l \
             JOIN node_offers o ON o.node_id = l.document->>'node_id' \
             JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
             LEFT JOIN lease_quotes q ON q.quote_id = (l.document->>'quote_id')::uuid \
             WHERE l.lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        Ok(LeaseContext {
            lease: row.0.0,
            offer: row.1.0,
            min_vram_mib: u32::try_from(row.10).unwrap_or(0),
            connection_id: row.2,
            node_ready_at: row.3,
            cuda_ready_at: row.4,
            gateway_ready_at: row.5,
            access_started_at: row.6,
            access_ended_at: row.7,
            gateway_closed_at: row.8,
            grant_token_id: row.9,
        })
    }

    async fn lease_status(&self, lease_id: ChainLeaseId) -> anyhow::Result<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("getLease(uint256)"));
        data.extend_from_slice(&word_u128(u128::from(lease_id.get())));
        let encoded: String = self
            .chain
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("0x{}", hex::encode(self.escrow)),
                    "data": format!("0x{}", hex::encode(data))
                }, "latest"]),
            )
            .await?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))?;
        if bytes.len() != 32 * 14 {
            anyhow::bail!("escrow returned an invalid lease");
        }
        Ok(bytes[32 * 14 - 1])
    }

    /// `internal_lease_id` is the row this receipt belongs to; the receipt's own
    /// `lease_id` is the escrow's, which is what a reader checks on chain. They
    /// are different numbers and the foreign key needs ours, so it is passed
    /// rather than parsed back out of the published document.
    async fn insert_receipt(
        &self,
        internal_lease_id: u64,
        receipt: &PublicReceipt,
        block_number: u64,
        block_hash: &str,
    ) -> anyhow::Result<()> {
        validate_receipt_identity(receipt)?;
        let escrow_address = receipt
            .escrow_address
            .as_deref()
            .context("receipt escrow identity is missing")?;
        let chain_lease_id = receipt
            .chain_lease_id
            .as_deref()
            .context("receipt chain identity is missing")?
            .parse::<u64>()?;
        let inserted = query_scalar::<_, Uuid>(
            "INSERT INTO proof_receipts \
                 (receipt_id, lease_id, escrow_address, chain_lease_id, document, \
                  transaction_hash, block_number, block_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (lease_id) DO UPDATE SET receipt_id = proof_receipts.receipt_id \
             WHERE proof_receipts.receipt_id = EXCLUDED.receipt_id \
               AND proof_receipts.escrow_address = EXCLUDED.escrow_address \
               AND proof_receipts.chain_lease_id = EXCLUDED.chain_lease_id \
               AND proof_receipts.document = EXCLUDED.document \
               AND proof_receipts.transaction_hash = EXCLUDED.transaction_hash \
               AND proof_receipts.block_number = EXCLUDED.block_number \
               AND proof_receipts.block_hash = EXCLUDED.block_hash \
             RETURNING receipt_id",
        )
        .bind(receipt.receipt_id)
        .bind(internal_lease_id as i64)
        .bind(escrow_address)
        .bind(i64::try_from(chain_lease_id)?)
        .bind(SqlJson(receipt.clone()))
        .bind(receipt.transaction_hash.to_ascii_lowercase())
        .bind(block_number as i64)
        .bind(block_hash.to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        if inserted.is_none() {
            anyhow::bail!("proof receipt conflicts with existing lease identity or evidence");
        }
        Ok(())
    }

    fn enrich_receipt_identity(
        &self,
        receipt: &mut PublicReceipt,
        chain_lease_id: ChainLeaseId,
    ) -> anyhow::Result<()> {
        let escrow_address = self.escrow_address();
        let chain_lease_id = chain_lease_id.get().to_string();
        if receipt.lease_id != chain_lease_id {
            anyhow::bail!("settlement receipt lease identity does not match lifecycle action");
        }
        if receipt
            .escrow_address
            .as_ref()
            .is_some_and(|value| value != &escrow_address)
            || receipt
                .chain_lease_id
                .as_ref()
                .is_some_and(|value| value != &chain_lease_id)
        {
            anyhow::bail!("settlement receipt carries a conflicting chain identity");
        }
        receipt.escrow_address = Some(escrow_address);
        receipt.chain_lease_id = Some(chain_lease_id);
        validate_receipt_identity(receipt)?;
        Ok(())
    }

    /// Mark an action done without acting on it, for a lease the chain has
    /// already moved past.
    async fn skip_action(&self, action: &Action) -> anyhow::Result<()> {
        let skipped = query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 last_error = NULL, updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status = 'processing'",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if skipped.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed before it could be skipped");
        }
        Ok(())
    }

    /// Record a lease the escrow settled without us seeing the transaction that
    /// did it. The money has moved and the node is already free; what is left is
    /// our own state. The public receipt is not published here, because a
    /// receipt names the settling transaction and we never observed one.
    async fn adopt_settled_lease(&self, action: &Action, status: u8) -> anyhow::Result<()> {
        let state = if status == LEASE_STATUS_FINALIZED {
            LeaseState::Finalized
        } else {
            LeaseState::Refunded
        };
        let mut transaction = self.pool.begin().await?;
        query(
            "UPDATE settlement_jobs SET status = 'failed', \
                 last_error = 'settled on chain without an observed transaction', \
                 updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(&mut transaction, action.lease_id, state).await?;
        enqueue_cloud_cleanup_in(&mut transaction, action.lease_id).await?;
        let completed = query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status = 'processing'",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&mut *transaction)
        .await?;
        if completed.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed while adopting settled lease");
        }
        transaction.commit().await?;
        tracing::warn!(
            lease_id = action.lease_id,
            status,
            "escrow had already settled this lease; adopted the outcome without a public receipt"
        );
        Ok(())
    }

    async fn mark_disputed(&self, action: &Action) -> anyhow::Result<()> {
        let mut transaction = self.pool.begin().await?;
        query(
            "UPDATE settlement_jobs SET status = 'disputed', updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(&mut transaction, action.lease_id, LeaseState::Disputed).await?;
        let completed = query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status = 'processing'",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&mut *transaction)
        .await?;
        if completed.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed while recording dispute");
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Machines other leases refused recently. Shared because a host that
    /// reserved no forwarded ports will reserve none for the next lease either.
    /// Machines that refused recently, with a repeat offender kept out longer.
    ///
    /// A host that reserves no forwarded ports is misconfigured, not briefly
    /// busy, so it refuses again the next time it is picked. On a flat window
    /// the same handful cycle back into the pool every few hours and a renter
    /// pays for the discovery: three of them in a row exhausts the attempts and
    /// the lease refunds without ever reaching a machine. Each further refusal
    /// doubles the exile, to a month.
    async fn recently_rejected_machines(&self) -> anyhow::Result<Vec<i64>> {
        Ok(query_scalar::<_, i64>(
            "SELECT machine_id FROM cloud_machine_rejections \
             WHERE last_rejected_at > NOW() - LEAST( \
                     make_interval(secs => $1 * POWER(2, LEAST(rejections, 10) - 1)), \
                     make_interval(days => 30)) \
             ORDER BY last_rejected_at DESC",
        )
        // secs, not hours: make_interval's hours argument is an int, and binding a
        // float to it fails at runtime rather than at compile time. Every call
        // errored, start_access failed with it, and every lease refunded.
        .bind((MACHINE_REJECTION_MEMORY_HOURS * 3600) as f64)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn remember_failed_provider_offer(
        &self,
        action: &Action,
        failed: &mut Vec<u64>,
        offer_id: u64,
    ) -> anyhow::Result<()> {
        if failed.contains(&offer_id) {
            return Ok(());
        }
        if failed.len() == 64 {
            failed.remove(0);
        }
        failed.push(offer_id);
        let encoded = failed
            .iter()
            .copied()
            .map(i64::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let updated = query(
            "UPDATE lifecycle_outbox \
             SET document = jsonb_set( \
                     document, '{failed_provider_offer_ids}', to_jsonb($2::bigint[]), TRUE), \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $3 \
               AND status = 'processing' AND lease_until > NOW()",
        )
        .bind(action.action_id)
        .bind(encoded)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StillProvisioning.into());
        }
        Ok(())
    }

    async fn supersede_prepared_transaction(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        let (preserved, discarded): (bool, bool) = query_as(
            "WITH preserved AS ( \
                 UPDATE lifecycle_transaction_attempts \
                 SET status = CASE WHEN status = 'reverted' THEN status ELSE 'superseded' END, \
                     superseded_at = CASE WHEN status = 'reverted' \
                         THEN superseded_at ELSE COALESCE(superseded_at, NOW()) END \
                 WHERE transaction_hash = $3 AND action_id = $1 \
                   AND status IN ('prepared', 'submitted', 'superseded', 'reverted') \
                 RETURNING transaction_hash \
             ), discarded AS ( \
                 UPDATE lifecycle_outbox \
                 SET raw_transaction = NULL, transaction_hash = NULL, \
                     transaction_nonce = NULL, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $2 \
                   AND transaction_hash = $3 \
                   AND status IN ('processing', 'submitted') \
                 RETURNING action_id \
             ) \
             SELECT EXISTS (SELECT 1 FROM preserved), EXISTS (SELECT 1 FROM discarded)",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .fetch_one(&self.pool)
        .await?;
        if !preserved {
            anyhow::bail!("lifecycle transaction outcome changed before supersession");
        }
        if !discarded {
            anyhow::bail!("lifecycle action claim changed before transaction supersession");
        }
        Ok(())
    }

    async fn discard_reverted_transaction(
        &self,
        action: &Action,
        transaction: &PreparedTransaction,
    ) -> anyhow::Result<()> {
        let (preserved, discarded): (bool, bool) = query_as(
            "WITH preserved AS ( \
                 UPDATE lifecycle_transaction_attempts \
                 SET status = 'reverted', reverted_at = COALESCE(reverted_at, NOW()) \
                 WHERE transaction_hash = $3 AND action_id = $1 \
                   AND status IN ('prepared', 'submitted', 'superseded', 'reverted') \
                 RETURNING transaction_hash \
             ), discarded AS ( \
                 UPDATE lifecycle_outbox \
                 SET raw_transaction = NULL, transaction_hash = NULL, \
                     transaction_nonce = NULL, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $2 \
                   AND transaction_hash = $3 \
                   AND status IN ('processing', 'submitted') \
                 RETURNING action_id \
             ) \
             SELECT EXISTS (SELECT 1 FROM preserved), EXISTS (SELECT 1 FROM discarded)",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .bind(transaction.transaction_hash.to_ascii_lowercase())
        .fetch_one(&self.pool)
        .await?;
        if !preserved || !discarded {
            anyhow::bail!("reverted lifecycle transaction could not be preserved and released");
        }
        Ok(())
    }

    async fn reschedule_submitted(&self, action: &Action) -> anyhow::Result<()> {
        let rescheduled = query(
            "UPDATE lifecycle_outbox SET status = 'submitted', lease_until = NULL, \
                 available_at = NOW() + INTERVAL '5 seconds', updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status IN ('processing', 'submitted')",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if rescheduled.rows_affected() != 1 {
            anyhow::bail!("lifecycle action claim changed before rescheduling");
        }
        Ok(())
    }

    async fn reschedule_start_reconciliation(&self, action: &Action) -> anyhow::Result<()> {
        let rescheduled = query(
            "UPDATE lifecycle_outbox \
             SET status = 'submitted', lease_until = NULL, \
                 attempts = GREATEST(0, attempts - 1), \
                 available_at = NOW() + INTERVAL '5 seconds', \
                 last_error = 'waiting for the confirmed access-start transaction', \
                 updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $2 \
               AND status IN ('processing', 'submitted')",
        )
        .bind(action.action_id)
        .bind(action.claim_generation)
        .execute(&self.pool)
        .await?;
        if rescheduled.rows_affected() != 1 {
            anyhow::bail!("start-access action claim changed during reconciliation");
        }
        Ok(())
    }

    async fn retry(
        &self,
        action_id: Uuid,
        claim_generation: i64,
        error: &anyhow::Error,
    ) -> anyhow::Result<()> {
        let message: String = format!("{error:#}").chars().take(1_024).collect();
        if error.downcast_ref::<CloudCleanupPending>().is_some() {
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + make_interval(secs => $2), \
                     last_error = $3, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $4 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(CLOUD_CLEANUP_RETRY_SECONDS as f64)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if error.downcast_ref::<TransactionOutcomePending>().is_some() {
            query(
                "UPDATE lifecycle_outbox SET status = 'submitted', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + INTERVAL '1 second', \
                     last_error = $2, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $3 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if error.downcast_ref::<AccessReadinessPending>().is_some() {
            query(
                "UPDATE lifecycle_outbox SET status = 'submitted', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + INTERVAL '5 seconds', \
                     last_error = $2, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $3 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if error
            .downcast_ref::<TransactionRepreparePending>()
            .is_some()
        {
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + make_interval(secs => $2), \
                     last_error = $3, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $4 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(TRANSACTION_REPREPARE_RETRY_SECONDS as f64)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if error
            .downcast_ref::<TransactionBroadcastLimitReached>()
            .is_some()
        {
            query(
                "UPDATE lifecycle_outbox SET status = 'submitted', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + make_interval(secs => $2), \
                     last_error = $3, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $4 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(TRANSACTION_BROADCAST_LIMIT_RETRY_SECONDS as f64)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if prism_chain::requires_transaction_reprepare(error) {
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + make_interval(secs => $2), \
                     last_error = $3, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $4 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(TRANSACTION_REPREPARE_RETRY_SECONDS as f64)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if prism_chain::is_transient_error(error) {
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + make_interval(secs => $2), \
                     last_error = $3, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $4 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(RPC_TRANSIENT_RETRY_SECONDS as f64)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        if error.downcast_ref::<StillProvisioning>().is_some() {
            // Waiting is not an attempt, and `expire_provision` already bounds
            // how long the whole thing may take.
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + INTERVAL '5 seconds', \
                     last_error = $2, updated_at = NOW() \
                 WHERE action_id = $1 AND claim_generation = $3 \
                   AND status IN ('processing', 'submitted')",
            )
            .bind(action_id)
            .bind(message)
            .bind(claim_generation)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        let exhausted = query_scalar::<_, Option<i64>>(
            "UPDATE lifecycle_outbox SET \
                 status = CASE \
                     WHEN attempts >= 100 \
                      AND kind NOT IN ('close_access', 'expire_provision', 'finalize') \
                     THEN 'failed' ELSE 'queued' END, \
                 lease_until = NULL, \
                 available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)), \
                 last_error = $2, updated_at = NOW() \
             WHERE action_id = $1 AND claim_generation = $3 \
               AND status IN ('processing', 'submitted') \
             RETURNING CASE \
                 WHEN attempts >= 100 \
                  AND kind NOT IN ('close_access', 'expire_provision', 'finalize') \
                 THEN lease_id END",
        )
        .bind(action_id)
        .bind(message)
        .bind(claim_generation)
        .fetch_optional(&self.pool)
        .await?
        .flatten();
        if let Some(lease_id) = exhausted {
            let lease_id = u64::try_from(lease_id)?;
            tracing::error!(lease_id, "lifecycle action exhausted its attempts");
        }
        Ok(())
    }
}

impl ActionKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "start_access" => Ok(Self::StartAccess),
            "refresh_grant" => Ok(Self::RefreshGrant),
            "close_access" => Ok(Self::CloseAccess),
            "expire_provision" => Ok(Self::ExpireProvision),
            "finalize" => Ok(Self::Finalize),
            "cleanup_cloud" => Ok(Self::CleanupCloud),
            _ => anyhow::bail!("unknown lifecycle action {value}"),
        }
    }

    fn calldata(self, lease_id: ChainLeaseId) -> Vec<u8> {
        let (signature, reason) = match self {
            Self::StartAccess => ("startAccess(uint256)", None),
            Self::CloseAccess => ("closeAccess(uint256)", None),
            Self::ExpireProvision => (
                "expireProvision(uint256,bytes32)",
                Some(Keccak256::digest(b"prism.provisioning-timeout.v1")),
            ),
            Self::Finalize => ("finalize(uint256)", None),
            Self::RefreshGrant | Self::CleanupCloud => unreachable!(),
        };
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&selector(signature));
        data.extend_from_slice(&word_u128(u128::from(lease_id.get())));
        if let Some(reason) = reason {
            data.extend_from_slice(&reason);
        }
        data
    }
}

impl GatewayClient {
    fn from_environment() -> anyhow::Result<Self> {
        let value = required_env("PRISM_GATEWAY_CONTROL_URL")?;
        let base_url = url::Url::parse(&value)?;
        let local_http = base_url.scheme() == "http"
            && base_url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        let private_http = env::var("PRISM_ALLOW_PRIVATE_GATEWAY_HTTP").as_deref() == Ok("1")
            && base_url.scheme() == "http"
            && base_url.host_str().is_some_and(private_gateway_host);
        if base_url.scheme() != "https" && !local_http && !private_http {
            anyhow::bail!(
                "PRISM_GATEWAY_CONTROL_URL must use HTTPS unless private HTTP is explicitly enabled"
            );
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?,
            base_url,
            token: Arc::new(required_env("PRISM_GATEWAY_CONTROL_TOKEN")?),
        })
    }

    async fn probe(&self, node_id: &str, connection_id: &str) -> anyhow::Result<ProbeResponse> {
        self.client
            .post(self.base_url.join("v1/probes")?)
            .bearer_auth(self.token.as_str())
            .json(&ProbeRequest {
                node_id,
                connection_id,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decode gateway probe response")
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_grant(
        &self,
        token_id: Uuid,
        lease_id: u64,
        node_id: &str,
        connection_id: &str,
        ttl_seconds: u32,
        trust_class: TrustClass,
        verdict: Option<LeaseAttestationVerdict>,
    ) -> anyhow::Result<GrantResponse> {
        self.client
            .post(self.base_url.join("v1/grants")?)
            .bearer_auth(self.token.as_str())
            .json(&GrantRequest {
                token_id,
                lease_id: lease_id.to_string(),
                node_id,
                connection_id,
                ttl_seconds,
                trust_class,
                verdict,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decode gateway grant response")
    }

    async fn revoke(&self, token_id: Uuid) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(self.base_url.join(&format!("v1/grants/{token_id}"))?)
            .bearer_auth(self.token.as_str())
            .send()
            .await?;
        // A grant the gateway never issued, or has already expired, is the state
        // close_access was asking for.
        if response.status() != reqwest::StatusCode::NOT_FOUND {
            response.error_for_status()?;
        }
        Ok(())
    }
}

fn private_gateway_host(host: &str) -> bool {
    host == "access-gateway"
        || host.ends_with(".prism.internal")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| match address {
                std::net::IpAddr::V4(address) => address.is_private(),
                std::net::IpAddr::V6(address) => address.is_unique_local(),
            })
}

async fn set_lease_state_in(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    lease_id: u64,
    state: LeaseState,
) -> anyhow::Result<()> {
    let SqlJson(mut lease) = query_scalar::<_, SqlJson<LeaseRecord>>(
        "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
    )
    .bind(lease_id as i64)
    .fetch_one(&mut **transaction)
    .await?;
    // The escrow has the last word on the money. Once a lease has refunded or
    // finalized, a straggler action giving up afterwards cannot make it a
    // failure: lease 38 refunded correctly and then read `failed` to its renter.
    if matches!(state, LeaseState::Failed)
        && matches!(lease.state, LeaseState::Finalized | LeaseState::Refunded)
    {
        return Ok(());
    }
    lease.state = state;
    lease.updated_at = Utc::now();
    query("UPDATE leases SET document = $2, state = $3, updated_at = NOW() WHERE lease_id = $1")
        .bind(lease_id as i64)
        .bind(SqlJson(lease.clone()))
        .bind(lease_state_name(&lease.state))
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn enqueue_cloud_cleanup_in(
    transaction: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    lease_id: u64,
) -> anyhow::Result<()> {
    query(
        "INSERT INTO lifecycle_outbox (action_id, lease_id, kind) \
         SELECT md5($1::text || ':cleanup_cloud')::uuid, $1, 'cleanup_cloud' \
         WHERE EXISTS (SELECT 1 FROM cloud_instances WHERE lease_id = $1) \
         ON CONFLICT (lease_id, kind) DO UPDATE \
           SET status = 'queued', attempts = 0, available_at = NOW(), lease_until = NULL, \
               last_error = NULL, updated_at = NOW() \
         WHERE lifecycle_outbox.status = 'failed'",
    )
    .bind(i64::try_from(lease_id)?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
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

async fn verify_schema(pool: &PgPool) -> anyhow::Result<()> {
    let present: Option<String> =
        query_scalar("SELECT to_regclass('public.lifecycle_outbox')::text")
            .fetch_one(pool)
            .await?;
    let rejections: bool = query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM information_schema.columns \
             WHERE table_name = 'cloud_instances' AND column_name = 'rejected_machines' \
         )",
    )
    .fetch_one(pool)
    .await?;
    let managed_jobs: Option<String> =
        query_scalar("SELECT to_regclass('public.managed_repro_jobs')::text")
            .fetch_one(pool)
            .await?;
    let provider_state: Option<String> =
        query_scalar("SELECT to_regclass('public.cloud_provider_state')::text")
            .fetch_one(pool)
            .await?;
    let provider_maintenance_state: bool = query_scalar(
        "SELECT COALESCE(( \
             SELECT POSITION('operator_maintenance' IN pg_get_constraintdef(oid)) > 0 \
             FROM pg_constraint \
             WHERE conrelid = 'cloud_provider_state'::regclass \
               AND conname = 'cloud_provider_state_state_check' \
         ), FALSE)",
    )
    .fetch_one(pool)
    .await?;
    let managed_schema: bool = query_scalar(
        "SELECT \
             EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'managed_repro_jobs' \
                   AND column_name = 'runner_public_key' \
             ) \
             AND EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'lifecycle_outbox' \
                   AND column_name = 'claim_generation' \
             ) \
             AND EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'managed_repro_jobs' \
                   AND column_name = 'prepared_hourly_cost_micros' \
             ) \
             AND EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'cloud_instances' \
                   AND column_name = 'ssh_authorized_key' \
                   AND is_nullable = 'YES' \
             ) \
             AND EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'cloud_instances' \
                   AND column_name = 'gpu_model' \
             ) \
             AND EXISTS ( \
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_name = 'cloud_instances' \
                   AND column_name = 'gpu_vram_mib' \
             )",
    )
    .fetch_one(pool)
    .await?;
    let transaction_attempts: Option<String> =
        query_scalar("SELECT to_regclass('public.lifecycle_transaction_attempts')::text")
            .fetch_one(pool)
            .await?;
    if present.is_none()
        || !rejections
        || managed_jobs.is_none()
        || provider_state.is_none()
        || !provider_maintenance_state
        || !managed_schema
        || transaction_attempts.is_none()
    {
        anyhow::bail!("control-plane lifecycle migrations have not been applied");
    }
    Ok(())
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn managed_repro_binding(
    provider_instance_id: Option<i64>,
    hourly_cost_micros: Option<i64>,
    gpu_model: Option<String>,
    gpu_vram_mib: Option<i32>,
    transport_host_key_sha256: Option<String>,
) -> anyhow::Result<ManagedReproBinding> {
    let provider_instance_id = provider_instance_id
        .and_then(|value| u64::try_from(value).ok())
        .context("managed repro has no prepared provider instance")?;
    let hourly_cost_micros = hourly_cost_micros
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .context("managed repro has no captured provider cost")?;
    let gpu_model = gpu_model
        .filter(|value| !value.trim().is_empty() && value.len() <= 128)
        .context("managed repro has no valid captured GPU model")?;
    let gpu_vram_mib = gpu_vram_mib
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= 196_608)
        .context("managed repro has no valid captured GPU memory")?;
    let transport_host_key_sha256 = transport_host_key_sha256
        .filter(|value| is_lower_sha256(value))
        .context("managed repro has no valid captured host-key commitment")?;
    Ok(ManagedReproBinding {
        provider_instance_id,
        hourly_cost_micros,
        gpu_model,
        gpu_vram_mib,
        transport_host_key_sha256,
    })
}

fn cloud_execution_terms(
    current_instance_id: Option<i64>,
    current_hourly_cost_micros: Option<i64>,
    current_gpu_model: Option<String>,
    current_gpu_vram_mib: Option<i32>,
    managed: Option<&ManagedReproBinding>,
) -> anyhow::Result<(ExecutionEvidence, String)> {
    if let Some(binding) = managed {
        return Ok((
            ExecutionEvidence::Vast {
                instance_id: binding.provider_instance_id,
                hourly_cost_micros: binding.hourly_cost_micros,
            },
            binding.gpu_model.clone(),
        ));
    }
    let instance_id = current_instance_id
        .and_then(|value| u64::try_from(value).ok())
        .context("cloud instance has no provider instance")?;
    let hourly_cost_micros = current_hourly_cost_micros
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .context("cloud instance has no provider cost")?;
    let gpu_model = current_gpu_model.context("cloud instance has no recorded GPU model")?;
    let _gpu_vram_mib = current_gpu_vram_mib
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .context("cloud instance has no recorded GPU memory")?;
    Ok((
        ExecutionEvidence::Vast {
            instance_id,
            hourly_cost_micros,
        },
        gpu_model,
    ))
}

fn cloud_destruction_targets(
    current_instance_id: Option<i64>,
    prepared_instance_id: Option<i64>,
    managed: bool,
    labelled: Vec<u64>,
) -> anyhow::Result<Vec<u64>> {
    let mut targets = Vec::new();
    let primary = if managed && prepared_instance_id.is_some() {
        prepared_instance_id
    } else {
        current_instance_id
    };
    if let Some(instance_id) = primary {
        targets.push(u64::try_from(instance_id)?);
    }
    for instance_id in labelled {
        if !targets.contains(&instance_id) {
            targets.push(instance_id);
        }
    }
    Ok(targets)
}

fn managed_report_matches_binding(
    report: &ManagedCommandReport,
    command_id: Uuid,
    lease_id: u64,
    binding: &ManagedReproBinding,
) -> bool {
    report.command_id == command_id
        && report.lease_id == lease_id
        && report.provider == ManagedProvider::Vast
        && report.provider_instance_id == binding.provider_instance_id
        && report.gpu_model == binding.gpu_model
        && report.gpu_vram_mib == binding.gpu_vram_mib
        && report.transport_host_key_sha256 == binding.transport_host_key_sha256
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

fn reportless_failure(status: &str, has_report: bool) -> bool {
    status == "failed" && !has_report
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

fn bytes32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("node id must contain 32 bytes"))
}

fn decode_legacy_transaction(raw: &str) -> anyhow::Result<DecodedLegacyTransaction> {
    let encoded = raw
        .strip_prefix("0x")
        .context("lifecycle transaction must start with 0x")?;
    let bytes = hex::decode(encoded)?;
    let transaction = rlp::Rlp::new(&bytes);
    if !transaction.is_list() || transaction.item_count()? != 9 {
        anyhow::bail!("lifecycle transaction is not a signed legacy transaction");
    }
    let nonce: u64 = transaction.at(0)?.as_val()?;
    let gas_price: u64 = transaction.at(1)?.as_val()?;
    let gas_limit: u64 = transaction.at(2)?.as_val()?;
    let destination = transaction.at(3)?.data()?;
    let destination: [u8; 20] = destination
        .try_into()
        .map_err(|_| anyhow::anyhow!("lifecycle transaction destination is invalid"))?;
    let value: u64 = transaction.at(4)?.as_val()?;
    if value != 0 {
        anyhow::bail!("lifecycle transaction unexpectedly transfers value");
    }
    let data = transaction.at(5)?.data()?.to_vec();
    let v: u64 = transaction.at(6)?.as_val()?;
    let eip155 = v
        .checked_sub(35)
        .context("lifecycle transaction has no EIP-155 replay protection")?;
    let chain_id = eip155 / 2;
    let recovery_id = RecoveryId::from_byte((eip155 % 2) as u8)
        .context("lifecycle transaction recovery id is invalid")?;
    let signature = EthereumSignature::from_scalars(
        padded_transaction_scalar(transaction.at(7)?.data()?)?,
        padded_transaction_scalar(transaction.at(8)?.data()?)?,
    )?;
    if signature.normalize_s().is_some() {
        anyhow::bail!("lifecycle transaction signature is not canonical");
    }
    let mut unsigned = rlp::RlpStream::new_list(9);
    unsigned.append(&nonce);
    unsigned.append(&gas_price);
    unsigned.append(&gas_limit);
    unsigned.append(&destination.as_slice());
    unsigned.append(&0_u8);
    unsigned.append(&data.as_slice());
    unsigned.append(&chain_id);
    unsigned.append(&0_u8);
    unsigned.append(&0_u8);
    let digest: [u8; 32] = Keccak256::digest(unsigned.out()).into();
    let public_key = EthereumVerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)?;
    let point = public_key.to_encoded_point(false);
    let signer: [u8; 20] = Keccak256::digest(&point.as_bytes()[1..])[12..]
        .try_into()
        .expect("Ethereum address is 20 bytes");
    Ok(DecodedLegacyTransaction {
        nonce,
        chain_id,
        destination,
        data,
        signer,
        transaction_hash: format!("0x{}", hex::encode(Keccak256::digest(bytes))),
    })
}

fn padded_transaction_scalar(value: &[u8]) -> anyhow::Result<[u8; 32]> {
    if value.is_empty() || value.len() > 32 {
        anyhow::bail!("lifecycle transaction signature scalar is invalid");
    }
    let mut padded = [0_u8; 32];
    padded[32 - value.len()..].copy_from_slice(value);
    Ok(padded)
}

fn validate_lifecycle_transaction_binding(
    transaction: &PreparedTransaction,
    expected_chain_id: u64,
    expected_escrow: [u8; 20],
    expected_signer: [u8; 20],
    expected_calldata: &[u8],
) -> Result<String, TransactionBindingError> {
    let decoded = decode_legacy_transaction(&transaction.raw_transaction).map_err(|error| {
        TransactionBindingError::new("invalid_signed_transaction", format!("{error:#}"))
    })?;
    if decoded.transaction_hash != transaction.transaction_hash {
        return Err(TransactionBindingError::new(
            "transaction_hash_mismatch",
            "stored hash does not commit to the signed bytes",
        ));
    }
    if decoded.nonce != transaction.nonce {
        return Err(TransactionBindingError::new(
            "signed_nonce_mismatch",
            "stored nonce does not match the signed nonce",
        ));
    }
    if decoded.chain_id != expected_chain_id {
        return Err(TransactionBindingError::new(
            "signed_chain_mismatch",
            "signed transaction targets another chain",
        ));
    }
    if decoded.destination != expected_escrow {
        return Err(TransactionBindingError::new(
            "signed_escrow_mismatch",
            "signed transaction targets another escrow",
        ));
    }
    if decoded.signer != expected_signer {
        return Err(TransactionBindingError::new(
            "signed_signer_mismatch",
            "signed transaction was produced by another signer",
        ));
    }
    if decoded.data != expected_calldata {
        return Err(TransactionBindingError::new(
            "calldata_mismatch",
            "signed transaction targets another action or chain lease",
        ));
    }
    Ok(format!("0x{}", hex::encode(decoded.signer)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a listener that speaks SSH counts. A port that accepts and says
    /// nothing is exactly the Vast relay a renter waits out, and a closed port
    /// is the host that never started sshd.
    #[tokio::test]
    async fn an_ssh_banner_is_the_only_answer_that_opens_access() {
        use tokio::io::AsyncWriteExt;

        let speaks = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let speaking_port = speaks.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = speaks.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        });
        assert!(sshd_answers("127.0.0.1", speaking_port).await);

        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_port = silent.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_stream, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        assert!(!sshd_answers("127.0.0.1", silent_port).await);

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(!sshd_answers("127.0.0.1", closed_port).await);
    }

    async fn signed_lifecycle_transaction(
        key: &str,
        destination: [u8; 20],
        calldata: &[u8],
        chain_id: u64,
        nonce: u64,
    ) -> (PreparedTransaction, [u8; 20]) {
        let signer = EthereumSigner::local(key).unwrap();
        let gas_price = 1_u64;
        let gas_limit = 200_000_u64;
        let mut unsigned = rlp::RlpStream::new_list(9);
        unsigned.append(&nonce);
        unsigned.append(&gas_price);
        unsigned.append(&gas_limit);
        unsigned.append(&destination.as_slice());
        unsigned.append(&0_u8);
        unsigned.append(&calldata);
        unsigned.append(&chain_id);
        unsigned.append(&0_u8);
        unsigned.append(&0_u8);
        let digest: [u8; 32] = Keccak256::digest(unsigned.out()).into();
        let signature = signer.sign_digest(&digest).await.unwrap();
        let v = chain_id * 2 + 35 + u64::from(signature[64] - 27);
        let mut signed = rlp::RlpStream::new_list(9);
        signed.append(&nonce);
        signed.append(&gas_price);
        signed.append(&gas_limit);
        signed.append(&destination.as_slice());
        signed.append(&0_u8);
        signed.append(&calldata);
        signed.append(&v);
        signed.append(&signature_scalar(&signature[..32]));
        signed.append(&signature_scalar(&signature[32..64]));
        let raw = signed.out().to_vec();
        (
            PreparedTransaction {
                nonce,
                transaction_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw))),
                raw_transaction: format!("0x{}", hex::encode(raw)),
            },
            signer.address(),
        )
    }

    fn signature_scalar(value: &[u8]) -> &[u8] {
        let first = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len() - 1);
        &value[first..]
    }

    #[tokio::test]
    async fn signed_lifecycle_binding_covers_every_execution_identity() {
        let escrow = [0x11; 20];
        let calldata = ActionKind::Finalize.calldata(ChainLeaseId(42));
        let (transaction, signer) = signed_lifecycle_transaction(
            "0000000000000000000000000000000000000000000000000000000000000002",
            escrow,
            &calldata,
            ROBINHOOD_CHAIN_ID,
            7,
        )
        .await;
        assert_eq!(
            validate_lifecycle_transaction_binding(
                &transaction,
                ROBINHOOD_CHAIN_ID,
                escrow,
                signer,
                &calldata,
            )
            .unwrap(),
            format!("0x{}", hex::encode(signer))
        );

        let cases = [
            (
                validate_lifecycle_transaction_binding(
                    &transaction,
                    ROBINHOOD_CHAIN_ID + 1,
                    escrow,
                    signer,
                    &calldata,
                ),
                "signed_chain_mismatch",
            ),
            (
                validate_lifecycle_transaction_binding(
                    &transaction,
                    ROBINHOOD_CHAIN_ID,
                    [0x22; 20],
                    signer,
                    &calldata,
                ),
                "signed_escrow_mismatch",
            ),
            (
                validate_lifecycle_transaction_binding(
                    &transaction,
                    ROBINHOOD_CHAIN_ID,
                    escrow,
                    [0x33; 20],
                    &calldata,
                ),
                "signed_signer_mismatch",
            ),
            (
                validate_lifecycle_transaction_binding(
                    &transaction,
                    ROBINHOOD_CHAIN_ID,
                    escrow,
                    signer,
                    &ActionKind::Finalize.calldata(ChainLeaseId(43)),
                ),
                "calldata_mismatch",
            ),
        ];
        for (result, reason) in cases {
            assert_eq!(result.unwrap_err().reason, reason);
        }

        let mut wrong_nonce = transaction.clone();
        wrong_nonce.nonce += 1;
        assert_eq!(
            validate_lifecycle_transaction_binding(
                &wrong_nonce,
                ROBINHOOD_CHAIN_ID,
                escrow,
                signer,
                &calldata,
            )
            .unwrap_err()
            .reason,
            "signed_nonce_mismatch"
        );
        let mut wrong_hash = transaction;
        wrong_hash.transaction_hash = format!("0x{}", "00".repeat(32));
        assert_eq!(
            validate_lifecycle_transaction_binding(
                &wrong_hash,
                ROBINHOOD_CHAIN_ID,
                escrow,
                signer,
                &calldata,
            )
            .unwrap_err()
            .reason,
            "transaction_hash_mismatch"
        );
    }

    #[test]
    fn malformed_signed_lifecycle_bytes_are_rejected_before_rebroadcast() {
        let transaction = PreparedTransaction {
            nonce: 0,
            raw_transaction: "0x04".to_owned(),
            transaction_hash: format!("0x{}", "00".repeat(32)),
        };
        assert_eq!(
            validate_lifecycle_transaction_binding(
                &transaction,
                ROBINHOOD_CHAIN_ID,
                [0x11; 20],
                [0x22; 20],
                &[],
            )
            .unwrap_err()
            .reason,
            "invalid_signed_transaction"
        );
    }

    #[tokio::test]
    async fn shutdown_closes_the_claim_gate_and_wakes_waiters() {
        let shutdown = Shutdown::default();
        let permit = shutdown.claim_permit().await.unwrap();
        let requester = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { shutdown.request().await })
        };
        tokio::task::yield_now().await;
        assert!(!shutdown.is_requested());

        drop(permit);
        requester.await.unwrap();
        assert!(shutdown.is_requested());
        assert!(shutdown.claim_permit().await.is_none());
        tokio::time::timeout(Duration::from_millis(50), shutdown.wait())
            .await
            .unwrap();
    }

    /// The retry path tells a booting box apart from a broken one by downcast,
    /// so it has to survive whatever context a caller adds on the way up.
    #[test]
    fn a_host_keeps_its_boot_budget_then_loses_it() {
        let now = Utc::now();

        assert!(!boot_budget_exhausted(None, now));
        assert!(!boot_budget_exhausted(Some(now), now));
        assert!(!boot_budget_exhausted(
            Some(now - chrono::Duration::seconds(HOST_BOOT_BUDGET_SECONDS)),
            now
        ));
        assert!(boot_budget_exhausted(
            Some(now - chrono::Duration::seconds(HOST_BOOT_BUDGET_SECONDS + 1)),
            now
        ));
    }

    #[test]
    fn a_booting_box_stays_recognisable_through_added_context() {
        let error = anyhow::Error::from(StillProvisioning).context("start access for lease 39");
        assert!(error.downcast_ref::<StillProvisioning>().is_some());
        assert!(
            anyhow::anyhow!("Vast instance entered terminal state exited")
                .downcast_ref::<StillProvisioning>()
                .is_none()
        );
    }

    #[test]
    fn a_failed_provider_delete_leaves_a_resumable_refusal() {
        let refusal = StagedRefusal {
            machine_id: 24_733,
            reason: "host was still loading after 300s of boot budget".to_owned(),
        };
        let note = refusal.note();

        assert_eq!(
            staged_refusal(Some(&note), &[11_111, refusal.machine_id]),
            Some(refusal)
        );
        assert_eq!(staged_refusal(Some(&note), &[11_111]), None);
        assert_eq!(
            refused_cleanup_outcome(MAX_REJECTED_MACHINES - 1),
            RefusedCleanupOutcome::Replace
        );
        assert_eq!(
            refused_cleanup_outcome(MAX_REJECTED_MACHINES),
            RefusedCleanupOutcome::Exhausted
        );

        let error = anyhow::Error::from(StillProvisioning).context(CloudCleanupPending(
            "provider rate limited cleanup".to_owned(),
        ));
        assert!(error.downcast_ref::<CloudCleanupPending>().is_some());
        assert!(error.downcast_ref::<StillProvisioning>().is_some());
    }

    #[test]
    fn active_access_readiness_wait_stays_recognisable_through_context() {
        let error = anyhow::Error::from(AccessReadinessPending)
            .context("adopt onchain access for lease 39");
        assert!(error.downcast_ref::<AccessReadinessPending>().is_some());
    }

    /// A renter can release at any point in the window, and the close that
    /// follows stops the meter. A refresh that still ran after it would hand
    /// back an hour of session on compute settlement will not bill.
    #[test]
    fn a_refresh_after_the_gateway_closed_is_dropped() {
        for cloud in [false, true] {
            for batch in [false, true] {
                assert_eq!(
                    refresh_decision(true, cloud, batch),
                    RefreshDecision::Drop,
                    "cloud {cloud} batch {batch}"
                );
            }
        }
        assert_eq!(
            refresh_decision(false, false, false),
            RefreshDecision::Rotate
        );
        assert_eq!(
            refresh_decision(false, true, false),
            RefreshDecision::Nothing
        );
        assert_eq!(
            refresh_decision(false, false, true),
            RefreshDecision::Nothing
        );
    }

    #[test]
    fn managed_start_waits_for_a_transport_bound_runner() {
        assert!(!managed_runner_is_ready("queued", None).unwrap());
        assert!(!managed_runner_is_ready("preparing", None).unwrap());
        assert!(managed_runner_is_ready("ready", Some(&"a".repeat(64))).unwrap());
        assert!(managed_runner_is_ready("ready", Some(&"A".repeat(64))).is_err());
        assert!(managed_runner_is_ready("failed", Some(&"a".repeat(64))).is_err());
    }

    #[test]
    fn cloud_ready_writes_require_the_current_live_start_claim() {
        assert!(cloud_write_fence_matches(
            "provisioning",
            "start_access",
            "processing",
            true,
            7,
            7,
            Some(42),
            Some(42),
            "provisioning",
            "provisioning",
        ));
        assert!(cloud_write_fence_matches(
            "ready",
            "start_access",
            "processing",
            true,
            7,
            7,
            Some(42),
            Some(42),
            "running",
            "running",
        ));

        for (lease_state, kind, action_status, claim_live, generation, instance_id, status) in [
            (
                "active",
                "start_access",
                "processing",
                true,
                7,
                Some(42),
                "provisioning",
            ),
            (
                "closing",
                "start_access",
                "processing",
                true,
                7,
                Some(42),
                "provisioning",
            ),
            (
                "provisioning",
                "close_access",
                "processing",
                true,
                7,
                Some(42),
                "provisioning",
            ),
            (
                "provisioning",
                "start_access",
                "queued",
                true,
                7,
                Some(42),
                "provisioning",
            ),
            (
                "provisioning",
                "start_access",
                "processing",
                false,
                7,
                Some(42),
                "provisioning",
            ),
            (
                "provisioning",
                "start_access",
                "processing",
                true,
                8,
                Some(42),
                "provisioning",
            ),
            (
                "provisioning",
                "start_access",
                "processing",
                true,
                7,
                Some(43),
                "provisioning",
            ),
            (
                "provisioning",
                "start_access",
                "processing",
                true,
                7,
                Some(42),
                "destroyed",
            ),
        ] {
            assert!(
                !cloud_write_fence_matches(
                    lease_state,
                    kind,
                    action_status,
                    claim_live,
                    generation,
                    7,
                    instance_id,
                    Some(42),
                    status,
                    "provisioning",
                ),
                "unsafe cloud write fence was accepted: {lease_state}/{kind}/{action_status}/{claim_live}/{generation}/{instance_id:?}/{status}",
            );
        }
    }

    #[test]
    fn labelled_cleanup_preserves_current_and_prepared_instances() {
        assert_eq!(
            labelled_instance_plan(vec![43, 42, 41], Some(42), None).unwrap(),
            (Some(42), vec![43, 41])
        );
        assert_eq!(
            labelled_instance_plan(vec![43, 42, 41], Some(43), Some(42)).unwrap(),
            (Some(42), vec![41])
        );
        assert_eq!(
            labelled_instance_plan(vec![43, 42, 41], None, None).unwrap(),
            (Some(43), vec![42, 41])
        );
    }

    #[test]
    fn managed_reports_match_only_the_preflight_instance_and_hardware() {
        let command_id = Uuid::now_v7();
        let binding = ManagedReproBinding {
            provider_instance_id: 42,
            hourly_cost_micros: 600_000,
            gpu_model: "NVIDIA L40S".to_owned(),
            gpu_vram_mib: 49_152,
            transport_host_key_sha256: "a".repeat(64),
        };
        let report = ManagedCommandReport {
            report_id: Uuid::now_v7(),
            signer: "0x0000000000000000000000000000000000000000".to_owned(),
            command_id,
            lease_id: 7,
            provider: ManagedProvider::Vast,
            provider_instance_id: binding.provider_instance_id,
            gpu_model: binding.gpu_model.clone(),
            gpu_vram_mib: binding.gpu_vram_mib,
            transport_host_key_sha256: binding.transport_host_key_sha256.clone(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            outcome: NodeCommandOutcome::Completed,
            error: None,
            result: Some(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
            }),
            signature: "0x".to_owned(),
        };

        assert!(managed_report_matches_binding(
            &report, command_id, 7, &binding
        ));
        for changed in [
            ManagedReproBinding {
                provider_instance_id: 43,
                ..binding.clone()
            },
            ManagedReproBinding {
                gpu_model: "NVIDIA H100".to_owned(),
                ..binding.clone()
            },
            ManagedReproBinding {
                gpu_vram_mib: binding.gpu_vram_mib + 1,
                ..binding.clone()
            },
            ManagedReproBinding {
                transport_host_key_sha256: "b".repeat(64),
                ..binding.clone()
            },
        ] {
            assert!(!managed_report_matches_binding(
                &report, command_id, 7, &changed
            ));
        }
    }

    #[test]
    fn managed_settlement_uses_preflight_terms_after_instance_drift() {
        let binding = ManagedReproBinding {
            provider_instance_id: 42,
            hourly_cost_micros: 600_000,
            gpu_model: "NVIDIA L40S".to_owned(),
            gpu_vram_mib: 49_152,
            transport_host_key_sha256: "a".repeat(64),
        };
        let (execution, gpu_model) = cloud_execution_terms(
            Some(99),
            Some(900_000),
            Some("NVIDIA H100".to_owned()),
            Some(81_920),
            Some(&binding),
        )
        .unwrap();

        assert_eq!(
            execution,
            ExecutionEvidence::Vast {
                instance_id: 42,
                hourly_cost_micros: 600_000,
            }
        );
        assert_eq!(gpu_model, "NVIDIA L40S");
    }

    #[test]
    fn managed_close_targets_preflight_and_labelled_drift_instances() {
        assert_eq!(
            cloud_destruction_targets(Some(99), Some(42), true, vec![99]).unwrap(),
            vec![42, 99]
        );
        assert_eq!(
            cloud_destruction_targets(Some(99), Some(42), true, Vec::new()).unwrap(),
            vec![42]
        );
    }

    #[test]
    fn batch_and_cloud_leases_never_receive_gateway_credentials() {
        assert!(should_issue_gateway_access(false, false));
        assert!(!should_issue_gateway_access(false, true));
        assert!(!should_issue_gateway_access(true, false));
        assert!(!should_issue_gateway_access(true, true));
    }

    #[test]
    fn lifecycle_calldata_uses_exact_contract_selectors() {
        let data = ActionKind::StartAccess.calldata(ChainLeaseId(7));
        assert_eq!(&data[..4], &selector("startAccess(uint256)"));
        assert_eq!(&data[4..], &word_u128(7));

        let expiry = ActionKind::ExpireProvision.calldata(ChainLeaseId(7));
        assert_eq!(&expiry[..4], &selector("expireProvision(uint256,bytes32)"));
        assert_eq!(expiry.len(), 68);
    }

    /// Lease 37 was funded on chain, never confirmed to the control plane, and
    /// held the only node in the network until someone read the registry by hand.
    #[test]
    fn only_an_unprovisioned_lease_past_its_window_is_expirable() {
        let now = 1_000_000u64;
        let funded_and_stale = OnchainLease {
            access_started_at: 0,
            access_ended_at: 0,
            created_at: now - PROVISION_TIMEOUT_SECONDS - 1,
            status: 1,
        };
        assert!(expirable(funded_and_stale, now));

        let funded_but_fresh = OnchainLease {
            access_started_at: 0,
            access_ended_at: 0,
            created_at: now - 60,
            status: 1,
        };
        assert!(
            !expirable(funded_but_fresh, now),
            "still inside the provisioning window"
        );

        for status in [0u8, 2, 3, 4, 5, 6] {
            let other = OnchainLease {
                access_started_at: 0,
                access_ended_at: 0,
                created_at: now - PROVISION_TIMEOUT_SECONDS - 1,
                status,
            };
            assert!(
                !expirable(other, now),
                "status {status} belongs to a renter"
            );
        }
    }

    #[test]
    fn a_lease_decodes_from_the_words_the_escrow_returns() {
        let mut blob = vec![0u8; 32 * 14];
        blob[32 * 7 - 8..32 * 7].copy_from_slice(&1_754_000_000u64.to_be_bytes());
        blob[32 * 14 - 1] = 5;

        let lease = decode_lease(&blob).unwrap();
        assert_eq!(lease.created_at, 1_754_000_000);
        assert_eq!(lease.status, 5);
        assert!(decode_lease(&blob[..32 * 13]).is_err());
    }

    #[test]
    fn provider_latches_block_new_cloud_instances() {
        for state in ["auth_blocked", "permanent_blocked", "operator_maintenance"] {
            assert!(provider_state_is_latched(state), "{state} must latch");
        }
        for state in ["healthy", "credit_blocked", "transient_blocked"] {
            assert!(!provider_state_is_latched(state), "{state} may recover");
        }
    }

    #[test]
    fn lease_state_names_match_the_database_contract() {
        assert_eq!(
            lease_state_name(&LeaseState::SettlementPending),
            "settlement_pending"
        );
        assert_eq!(lease_state_name(&LeaseState::Refunded), "refunded");
    }

    #[test]
    fn private_gateway_hosts_are_narrowly_scoped() {
        assert!(private_gateway_host("access-gateway"));
        assert!(private_gateway_host("gateway.prism.internal"));
        assert!(private_gateway_host("10.48.2.4"));
        assert!(private_gateway_host("fd00::2"));
        assert!(!private_gateway_host("gateway.example.com"));
        assert!(!private_gateway_host("203.0.113.6"));
    }

    // getNode returns operator, payout, deviceHash, metadataHash, ratePerSecond,
    // bond, activeLeaseId, status. Reading the wrong word gives a number that
    // looks like a rate: the bond decodes as an enormous one and the lease id as
    // zero, and neither errors. Pin the offset against a hand-built record.
    #[test]
    fn the_registered_rate_is_read_from_the_right_word() {
        let mut record = Vec::new();
        let mut word = |value: u128| {
            let mut w = [0_u8; 32];
            w[16..].copy_from_slice(&value.to_be_bytes());
            record.extend_from_slice(&w);
        };
        word(0x1111); // operator
        word(0x2222); // payout
        word(0x3333); // deviceHash
        word(0x4444); // metadataHash
        word(177); // ratePerSecond
        word(39_864_000_000); // bond
        word(0); // activeLeaseId
        word(1); // status

        let rate = record.get(128..160).expect("record covers the rate word");
        let mut value = [0_u8; 8];
        value.copy_from_slice(&rate[24..32]);

        assert_eq!(u64::from_be_bytes(value), 177);
    }

    fn booting_instance(status: &str, direct_port_start: i64) -> vast::Instance {
        vast::Instance {
            status: status.to_owned(),
            gpu_name: "RTX A6000".to_owned(),
            gpu_ram: 49_140,
            verification: "verified".to_owned(),
            hourly_micros: 400_000,
            ssh_host: Some("ssh7.vast.ai".to_owned()),
            ssh_port: Some(21_238),
            direct_port_start,
            machine_id: 37_509,
        }
    }

    /// Production regression, caught by renting a machine and failing to log
    /// into it. A host that reports itself running before it has a forwarded
    /// port advertises a proxy address that does not reach sshd. Treating that
    /// as ready handed a renter a box they were paying for and could not use.
    /// Not refusing it is right; declaring it ready is not.
    #[test]
    fn a_running_host_without_a_port_is_neither_refused_nor_ready() {
        let no_port = booting_instance("running", -1);
        assert_eq!(
            candidate_refusal(&no_port, true, 16_000, 640_000, &[], false),
            None,
            "inside its budget the host keeps its place in the queue"
        );
        assert!(
            no_port.direct_port_start <= 0,
            "and the readiness gate holds the lease on exactly this"
        );

        let with_port = booting_instance("running", 19_300);
        assert_eq!(
            candidate_refusal(&with_port, true, 16_000, 640_000, &[], false),
            None
        );
        assert!(with_port.direct_port_start > 0, "only this one is usable");
    }

    /// The escrow returns the lease as fourteen words. `accessEndedAt` is the
    /// ninth, and reading the wrong one would silently return another
    /// timestamp: `accessStartedAt` before it, `proposedUsageSeconds` after.
    /// Either would make a lease look closed when it is not, or the reverse.
    #[test]
    fn a_lease_decodes_the_word_that_actually_holds_access_ended_at() {
        let mut bytes = vec![0u8; 32 * 14];
        bytes[32 * 7 - 8..32 * 7].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        bytes[32 * 8 - 8..32 * 8].copy_from_slice(&1_700_000_111u64.to_be_bytes());
        bytes[32 * 9 - 8..32 * 9].copy_from_slice(&1_700_000_222u64.to_be_bytes());
        bytes[32 * 10 - 8..32 * 10].copy_from_slice(&999u64.to_be_bytes());
        bytes[32 * 14 - 1] = LEASE_STATUS_ACTIVE;

        let lease = decode_lease(&bytes).unwrap();
        assert_eq!(lease.created_at, 1_700_000_000);
        assert_eq!(lease.access_started_at, 1_700_000_111);
        assert_eq!(lease.access_ended_at, 1_700_000_222);
        assert_eq!(lease.status, LEASE_STATUS_ACTIVE);

        // Access still open is the case that must not read as closed.
        let mut open = bytes.clone();
        open[32 * 9 - 8..32 * 9].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(decode_lease(&open).unwrap().access_ended_at, 0);
    }

    /// Production regression. Vast reports `direct_port_start` as -1 until a
    /// host finishes booting. Reading the port before the boot budget expired
    /// condemned healthy hosts as having reserved no ports, so the broker
    /// destroyed and blacklisted every candidate in turn and no lease could be
    /// provisioned at all.
    #[test]
    fn a_host_that_is_still_booting_is_not_blamed_for_its_ports() {
        let loading = booting_instance("loading", -1);
        assert_eq!(
            candidate_refusal(&loading, true, 16_000, 640_000, &[], false),
            None,
            "a host inside its boot budget is kept, whatever port it reports"
        );
        let refusal = candidate_refusal(&loading, true, 16_000, 640_000, &[], true)
            .expect("a host past its budget is refused");
        assert!(
            refusal.contains("boot budget"),
            "a timeout must be reported as a timeout, got: {refusal}"
        );

        // The port arrives some seconds after the instance starts reporting
        // itself as running, so it is only a fault once the budget is spent.
        // Machine 23779 was refused inside this gap and then served the very
        // next lease it was offered.
        let running = booting_instance("running", -1);
        assert_eq!(
            candidate_refusal(&running, true, 16_000, 640_000, &[], false),
            None,
            "a host that just came up is still settling, not portless"
        );
        let refusal = candidate_refusal(&running, true, 16_000, 640_000, &[], true)
            .expect("a running host with no port after its whole budget is unusable");
        assert!(refusal.contains("forwarded ports"), "got: {refusal}");
        assert_eq!(
            candidate_refusal(
                &booting_instance("running", 19_300),
                true,
                16_000,
                640_000,
                &[],
                false
            ),
            None
        );
    }

    #[test]
    fn a_short_registry_record_is_an_error_not_a_zero_rate() {
        let truncated = [0_u8; 96];

        assert!(truncated.get(128..160).is_none());
    }

    #[test]
    fn a_signed_terminal_failure_does_not_need_a_fabricated_result() {
        assert!(terminal_report_shape(
            &NodeCommandOutcome::Failed,
            Some("managed result became unavailable"),
            None,
        ));
        assert!(!terminal_report_shape(
            &NodeCommandOutcome::Failed,
            None,
            None,
        ));
        assert!(!terminal_report_shape(
            &NodeCommandOutcome::Completed,
            None,
            None,
        ));
        assert!(reportless_failure("failed", false));
        assert!(!reportless_failure("failed", true));
        assert!(!reportless_failure("running", false));
    }
}
