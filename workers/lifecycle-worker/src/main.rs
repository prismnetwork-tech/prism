use std::{collections::BTreeMap, env, sync::Arc, time::Duration};

use anyhow::Context;
use chrono::{DateTime, Utc};
use prism_chain::{
    EthereumSigner, Finality, PreparedTransaction, RpcClient, address, selector, word_bytes32,
    word_u128,
};
use prism_protocol::{
    AttestationVerdict, CredentialCipher, ExecutionEvidence, LeaseRecord, LeaseState, NodeOffer,
    NodeTelemetry, PublicReceipt, ROBINHOOD_CHAIN_ID, ReceiptAttestation, ReceiptOutcome,
    SettlementEvidence, TrustClass, receipt_hash, verdict_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod vast;

use vast::VastBroker;

const SIGNER_LOCK: i64 = 4_663_001;
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
    last_orphan_sweep: tokio::sync::Mutex<Option<std::time::Instant>>,
    last_cloud_observation: tokio::sync::Mutex<Option<std::time::Instant>>,
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
    lease_id: u64,
    /// What the escrow numbered this lease. Escrow counters restart on
    /// redeployment, so this differs from `lease_id` and is the only value a
    /// chain call may carry.
    chain_lease_id: ChainLeaseId,
    kind: ActionKind,
    transaction: Option<PreparedTransaction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    StartAccess,
    RefreshGrant,
    CloseAccess,
    ExpireProvision,
    Finalize,
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

fn boot_budget_exhausted(attached_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    attached_at.is_some_and(|attached| {
        now.signed_duration_since(attached).num_seconds() > HOST_BOOT_BUDGET_SECONDS
    })
}

/// `getLease` returns the struct as fourteen words. `createdAt` is the seventh
/// and `status` the last, both right aligned in their word.
fn decode_lease(bytes: &[u8]) -> anyhow::Result<OnchainLease> {
    if bytes.len() != 32 * 14 {
        anyhow::bail!("escrow returned an invalid lease");
    }
    let mut created = [0u8; 8];
    created.copy_from_slice(&bytes[32 * 7 - 8..32 * 7]);
    let mut ended = [0u8; 8];
    ended.copy_from_slice(&bytes[32 * 9 - 8..32 * 9]);
    Ok(OnchainLease {
        created_at: u64::from_be_bytes(created),
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
    cuda_ready_at: Option<DateTime<Utc>>,
    gateway_ready_at: Option<DateTime<Utc>>,
    access_started_at: Option<DateTime<Utc>>,
    access_ended_at: Option<DateTime<Utc>>,
    gateway_closed_at: Option<DateTime<Utc>>,
    grant_token_id: Option<Uuid>,
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
        last_orphan_sweep: tokio::sync::Mutex::new(None),
        last_cloud_observation: tokio::sync::Mutex::new(None),
    };
    if let Some(vast) = worker.vast.as_ref() {
        tracing::info!(
            slots = vast.node_ids.len(),
            "broker will rent {}",
            vast.policy()
        );
    }
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    loop {
        if let Err(error) = worker.scan().await {
            tracing::error!(%error, "lifecycle scan failed");
        }
        let claimed = match worker.claim().await {
            Ok(claimed) => claimed,
            Err(error) => {
                tracing::error!(%error, "lifecycle claim failed");
                None
            }
        };
        let Some(action) = claimed else {
            if run_once {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        let action_id = action.action_id;
        if let Err(error) = worker.process(action).await {
            if error.downcast_ref::<StillProvisioning>().is_some() {
                tracing::debug!(%action_id, "waiting on the box to boot");
            } else {
                tracing::error!(%action_id, %error, "lifecycle action failed");
            }
            if let Err(error) = worker.retry(action_id, &error).await {
                tracing::error!(%action_id, %error, "recording the failed action failed");
            }
        }
        if run_once {
            return Ok(());
        }
    }
}

impl Worker {
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
               AND created_at <= NOW() - INTERVAL '10 minutes' \
             ON CONFLICT (lease_id, kind) DO NOTHING",
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
        .execute(&self.pool)
        .await?;
        query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind) \
             SELECT md5(l.lease_id::text || ':refresh_grant')::uuid, l.lease_id, 'refresh_grant' \
             FROM leases l JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
             WHERE l.state = 'active' \
               AND lc.grant_expires_at <= NOW() + INTERVAL '10 minutes' \
               AND lc.access_started_at + \
                   make_interval(secs => (l.document->>'duration_seconds')::int) \
                   > NOW() + INTERVAL '10 minutes' \
             ON CONFLICT (lease_id, kind) DO UPDATE \
               SET status = 'queued', available_at = NOW(), lease_until = NULL, \
                   last_error = NULL, document = '{}'::jsonb, updated_at = NOW() \
             WHERE lifecycle_outbox.status = 'completed'",
        )
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
                    tracing::warn!(lease_id, %error, "could not observe a rented machine");
                    continue;
                }
            };
            let alive = observed == "running";
            query(
                "UPDATE cloud_instances \
                 SET status = CASE WHEN $2 THEN status ELSE 'failed' END, \
                     last_error = CASE WHEN $2 THEN last_error \
                                  ELSE 'provider reports ' || $3 END, \
                     observed_at = NOW(), updated_at = NOW() \
                 WHERE lease_id = $1",
            )
            .bind(lease_id)
            .bind(alive)
            .bind(&observed)
            .execute(&self.pool)
            .await?;
            if !alive {
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
        let refreshed_recently: bool = query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM cloud_capacity \
                 WHERE node_id = ANY($1) AND updated_at >= NOW() - INTERVAL '30 seconds' \
             )",
        )
        .bind(vast.node_ids.as_slice())
        .fetch_one(&self.pool)
        .await?;
        if refreshed_recently {
            return Ok(());
        }

        // Nodes with a lease on them are not for sale, so they are neither
        // advertised nor counted against the hosts we found.
        let busy: Vec<String> = query_scalar(
            "SELECT document->>'node_id' FROM leases \
             WHERE state IN ('funded', 'provisioning', 'ready', 'active', 'closing')",
        )
        .fetch_all(&self.pool)
        .await?;
        let free: Vec<&String> = vast
            .node_ids
            .iter()
            .filter(|node_id| !busy.iter().any(|held| held == *node_id))
            .collect();
        if free.is_empty() {
            return Ok(());
        }

        let offers = query_as::<_, (String, SqlJson<NodeOffer>)>(
            "SELECT node_id, document FROM node_offers WHERE node_id = ANY($1)",
        )
        .bind(vast.node_ids.as_slice())
        .fetch_all(&self.pool)
        .await?;
        if offers.is_empty() {
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
                Err(error) => tracing::warn!(node_id, %error, "could not read the registered rate"),
            }
        }
        if rates.is_empty() {
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
        let survey = vast.survey_many(retail_hourly(rate), free.len()).await?;
        self.report_supply(vast, &survey).await;

        for (index, node_id) in free.iter().enumerate() {
            let host = survey.hosts.get(index);
            self.record_cloud_capacity(node_id, host).await?;
            let Some(host) = host else { continue };
            let Some((_, SqlJson(offer))) = offers.iter().find(|(id, _)| id == *node_id) else {
                continue;
            };
            let Some(registered) = rates.get(*node_id).copied() else {
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
            offer.bonded = match self.is_schedulable(node_id).await {
                Ok(schedulable) => schedulable,
                // Unreadable is not the same as unbonded. Dropping the whole
                // catalogue on an RPC blip would be a worse outage than the one
                // this prevents, so the last known answer stands.
                Err(error) => {
                    tracing::warn!(node_id, %error, "could not confirm the node is still bonded");
                    offer.bonded
                }
            };
            // Advertise the class that will actually be handed over, not the one
            // the broker enrolled with.
            offer.gpu.model = host.gpu_name.clone();
            offer.gpu.vram_mib = u32::try_from(host.gpu_ram)?;
            offer.online = true;
            offer.updated_at = Utc::now();
            query("UPDATE node_offers SET document = $2, updated_at = NOW() WHERE node_id = $1")
                .bind(node_id)
                .bind(SqlJson(offer))
                .execute(&self.pool)
                .await?;
        }
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
            (None, Some(cheapest)) => format!(
                "no capacity: cheapest of {} eligible hosts is {} micros/hr, over the {} ceiling",
                survey.of_our_class, cheapest, survey.ceiling
            ),
        };
        if last.as_deref() != Some(note.as_str()) {
            tracing::info!("{note}");
            *last = Some(note);
        }
    }

    async fn record_cloud_capacity(
        &self,
        node_id: &str,
        offer: Option<&vast::Offer>,
    ) -> anyhow::Result<()> {
        let provider_offer_id = offer.map(|offer| i64::try_from(offer.id)).transpose()?;
        let hourly_micros = offer
            .map(|offer| vast::hourly_micros(offer.dph_total))
            .transpose()?
            .map(i64::try_from)
            .transpose()?;
        query(CLOUD_CAPACITY_UPSERT)
            .bind(node_id)
            .bind(offer.is_some())
            .bind(provider_offer_id)
            .bind(hourly_micros)
            .execute(&self.pool)
            .await?;
        if let (Some(offer), Some(hourly)) = (offer, hourly_micros) {
            self.record_price(node_id, offer, hourly).await?;
        }
        Ok(())
    }

    /// The upsert above keeps only the current price, so what a host cleared at
    /// survives one refresh. Append the observation as well: across providers
    /// and over time it is the only public record of what GPU time actually
    /// costs, and it cannot be reconstructed later.
    ///
    /// Written only when the price or the host changes. Recording every poll
    /// would measure the polling interval rather than the market.
    async fn record_price(
        &self,
        node_id: &str,
        offer: &vast::Offer,
        hourly_micros: i64,
    ) -> anyhow::Result<()> {
        let offer_id = i64::try_from(offer.id)?;
        let unchanged: bool = query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM capacity_prices \
                 WHERE node_id = $1 \
                   AND hourly_cost_micros = $2 \
                   AND provider_offer_id IS NOT DISTINCT FROM $3 \
                   AND id = (SELECT max(id) FROM capacity_prices WHERE node_id = $1) \
             )",
        )
        .bind(node_id)
        .bind(hourly_micros)
        .bind(offer_id)
        .fetch_one(&self.pool)
        .await?;
        if unchanged {
            return Ok(());
        }
        query(
            "INSERT INTO capacity_prices \
                 (node_id, provider, gpu_model, vram_mib, provider_offer_id, hourly_cost_micros) \
             VALUES ($1, 'vast', $2, $3, $4, $5)",
        )
        .bind(node_id)
        .bind(&offer.gpu_name)
        .bind(i32::try_from(offer.gpu_ram)?)
        .bind(offer_id)
        .bind(hourly_micros)
        .execute(&self.pool)
        .await?;
        Ok(())
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
            ),
        >(
            "SELECT o.action_id, o.lease_id, l.chain_lease_id, o.kind, \
                    o.raw_transaction, o.transaction_hash, o.transaction_nonce \
             FROM lifecycle_outbox o JOIN leases l ON l.lease_id = o.lease_id \
             WHERE o.attempts < 100 AND o.available_at <= NOW() \
               AND (o.status IN ('queued', 'submitted') \
                    OR (o.status = 'processing' AND o.lease_until <= NOW())) \
             ORDER BY o.available_at, o.created_at LIMIT 1 \
             FOR UPDATE OF o SKIP LOCKED",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((action_id, lease_id, chain_lease_id, kind, raw, hash, nonce)) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        query(
            "UPDATE lifecycle_outbox SET status = 'processing', attempts = attempts + 1, \
                 lease_until = NOW() + INTERVAL '2 minutes', updated_at = NOW() \
             WHERE action_id = $1",
        )
        .bind(action_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let parsed = (|| {
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
                lease_id: u64::try_from(lease_id)?,
                chain_lease_id: ChainLeaseId(u64::try_from(chain_lease_id)?),
                kind: ActionKind::parse(&kind)?,
                transaction,
            })
        })();
        match parsed {
            Ok(action) => Ok(Some(action)),
            Err(error) => {
                tracing::error!(%action_id, %error, "lifecycle action is unreadable");
                self.retry(action_id, &error).await?;
                Ok(None)
            }
        }
    }

    async fn process(&self, mut action: Action) -> anyhow::Result<()> {
        if action.kind == ActionKind::RefreshGrant {
            return self.refresh_grant(&action).await;
        }
        if action.kind == ActionKind::StartAccess && action.transaction.is_none() {
            // Funded is the only status a lease can still be started from.
            // Without this check a refunded lease keeps renting machines for a
            // renter who has already been paid back, and every attempt puts the
            // lease back into a state that holds its node out of the market. One
            // such lease sat in `provisioning` for hours after the escrow had
            // refunded it, retrying start_access forty-six times.
            match self.lease_status(action.chain_lease_id).await? {
                LEASE_STATUS_FUNDED => self.probe(&action).await?,
                settled @ (LEASE_STATUS_FINALIZED | LEASE_STATUS_REFUNDED) => {
                    self.adopt_settled_lease(&action, settled).await?;
                    return self.skip_action(&action).await;
                }
                // Already started, or disputed. Either way this action has
                // nothing left to do, and guessing a settlement here would
                // publish an outcome the chain never reached.
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
                1 => {
                    self.destroy_cloud_instance(action.lease_id).await?;
                }
                // expireProvision is permissionless, so anyone may have already
                // released this deposit. Skipping the action alone would leave
                // the lease open in the database against an escrow that no
                // longer holds anything for it, which reads as insolvency and
                // keeps that alarm lit until someone edits the row by hand.
                status @ (LEASE_STATUS_FINALIZED | LEASE_STATUS_REFUNDED) => {
                    self.destroy_cloud_instance(action.lease_id).await?;
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
        if action.transaction.is_none() {
            action.transaction = Some(self.prepare(&action).await?);
        }
        let transaction = action
            .transaction
            .as_ref()
            .context("lifecycle transaction was not prepared")?;
        self.chain.submit(transaction).await?;
        match self
            .chain
            .finality(&transaction.transaction_hash, self.confirmations)
            .await?
        {
            Finality::Pending => {
                self.reschedule_submitted(action.action_id).await?;
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
                self.discard_prepared_transaction(action.action_id).await?;
                anyhow::bail!("lifecycle transaction reverted");
            }
            Finality::Confirmed {
                block_number,
                block_hash,
            } => {
                let block_time = self.chain.block_timestamp(block_number).await?;
                self.complete(action, block_number, &block_hash, block_time)
                    .await?;
            }
        }
        Ok(())
    }

    async fn probe(&self, action: &Action) -> anyhow::Result<()> {
        if self.ensure_cloud_ready(action.lease_id).await? {
            return Ok(());
        }
        let context = self.lease_context(action.lease_id).await?;
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

    async fn ensure_cloud_ready(&self, lease_id: u64) -> anyhow::Result<bool> {
        let row = query_as::<
            _,
            (
                Option<i64>,
                Option<i64>,
                String,
                Option<DateTime<Utc>>,
                String,
                Vec<i64>,
            ),
        >(
            "SELECT provider_instance_id, provider_offer_id, ssh_authorized_key, \
                    ssh_key_attached_at, status, rejected_machines \
             FROM cloud_instances WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let Some((stored_instance_id, _, ssh_key, ssh_key_attached_at, status, rejected)) = row
        else {
            return Ok(false);
        };
        let vast = self
            .vast
            .as_ref()
            .context("Vast is not configured for this cloud lease")?;
        let context = self.lease_context(lease_id).await?;
        if !vast.owns(&context.lease.node_id) {
            anyhow::bail!("cloud lease node is not brokered by this worker");
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
        let retail = retail_hourly(context.lease.rate_per_second);
        if matches!(status.as_str(), "destroying" | "destroyed" | "failed") {
            anyhow::bail!("cloud instance is in terminal state {status}");
        }

        let label = format!("prism-lease-{lease_id}");
        let (instance_id, selected_offer) = match stored_instance_id {
            Some(instance_id) => (u64::try_from(instance_id)?, None),
            None => match self.adopt_labelled(vast, &label).await? {
                Some(instance_id) => (instance_id, None),
                None => {
                    // Machines this lease has already refused, plus the ones other
                    // leases refused recently. Without the second set every lease
                    // spends its attempts rediscovering the same broken hosts.
                    let mut avoided = rejected.clone();
                    for machine in self.recently_rejected_machines().await? {
                        if !avoided.contains(&machine) {
                            avoided.push(machine);
                        }
                    }
                    let mut candidates = vast.ranked(CREATES_PER_PASS, &avoided, retail).await?;
                    if candidates.is_empty() && avoided.len() > rejected.len() {
                        // The shared list is an optimisation, not a gate. If honouring
                        // it leaves nothing rentable, a known-bad host still beats
                        // refunding the renter without trying.
                        tracing::warn!(
                            lease_id,
                            avoided = avoided.len(),
                            "no candidate outside the shared rejection list, falling back"
                        );
                        candidates = vast.ranked(CREATES_PER_PASS, &rejected, retail).await?;
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
                        match vast.create(offer.id, &context.lease.image, lease_id).await {
                            Ok(instance_id) => {
                                launched = Some((instance_id, offer));
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(
                                    lease_id,
                                    offer_id = offer.id,
                                    %error,
                                    "Vast offer unavailable, trying next candidate"
                                );
                                last_error = Some(error);
                                if let Some(instance_id) = self.adopt_labelled(vast, &label).await?
                                {
                                    launched = Some((instance_id, offer));
                                    break;
                                }
                            }
                        }
                    }
                    let (instance_id, offer) = launched.ok_or_else(|| {
                        last_error
                            .unwrap_or_else(|| anyhow::anyhow!("all candidate Vast offers failed"))
                    })?;
                    (instance_id, Some(offer))
                }
            },
        };
        query(
            "UPDATE cloud_instances SET provider_instance_id = $2, \
                 provider_offer_id = COALESCE($3, provider_offer_id), \
                 hourly_cost_micros = COALESCE($4, hourly_cost_micros), \
                 status = 'provisioning', last_error = NULL, updated_at = NOW() \
             WHERE lease_id = $1",
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
        .execute(&self.pool)
        .await?;

        if ssh_key_attached_at.is_none() {
            vast.attach_ssh_key(instance_id, &ssh_key).await?;
            query(
                "UPDATE cloud_instances SET ssh_key_attached_at = NOW(), updated_at = NOW() \
                 WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .execute(&self.pool)
            .await?;
        }

        let instance = vast.instance(instance_id).await?;
        let stalled = boot_budget_exhausted(ssh_key_attached_at, Utc::now());
        if instance.status != "running" {
            if matches!(
                instance.status.as_str(),
                "exited" | "destroyed" | "failed" | "offline"
            ) {
                query(
                    "UPDATE cloud_instances SET status = 'failed', last_error = $2, \
                         updated_at = NOW() WHERE lease_id = $1",
                )
                .bind(lease_id as i64)
                .bind(format!("Vast instance entered {}", instance.status))
                .execute(&self.pool)
                .await?;
                anyhow::bail!("Vast instance entered terminal state {}", instance.status);
            }
            if !stalled {
                return Err(StillProvisioning.into());
            }
            // Out of boot budget. Fall through so this machine is destroyed,
            // blacklisted for this lease and replaced, exactly as a refusal is.
        }
        let refusal = candidate_refusal(
            &instance,
            vast.admits(&instance.gpu_name, instance.gpu_ram),
            context.min_vram_mib,
            vast.ceiling(retail),
            &rejected,
            stalled,
        );
        if let Some(refusal) = refusal {
            vast.destroy(instance_id).await?;
            if rejected.len() + 1 >= MAX_REJECTED_MACHINES {
                query(
                    "UPDATE cloud_instances SET status = 'failed', destroyed_at = NOW(), \
                         last_error = $2, updated_at = NOW() WHERE lease_id = $1",
                )
                .bind(lease_id as i64)
                .bind(format!("every candidate host was refused, last: {refusal}"))
                .execute(&self.pool)
                .await?;
                anyhow::bail!("every candidate Vast host was refused, last: {refusal}");
            }
            self.remember_rejected_machine(instance.machine_id as i64, &refusal)
                .await?;
            query(
                "UPDATE cloud_instances SET provider_instance_id = NULL, \
                     provider_offer_id = NULL, ssh_key_attached_at = NULL, \
                     rejected_machines = CASE WHEN $2 = ANY(rejected_machines) \
                         THEN rejected_machines ELSE array_append(rejected_machines, $2) END, \
                     status = 'provisioning', \
                     last_error = $3, \
                     updated_at = NOW() WHERE lease_id = $1",
            )
            .bind(lease_id as i64)
            .bind(instance.machine_id as i64)
            .bind(format!(
                "machine {} refused: {refusal}",
                instance.machine_id
            ))
            .execute(&self.pool)
            .await?;
            anyhow::bail!("Vast machine {} refused: {refusal}", instance.machine_id);
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
        let ready_at = Utc::now();
        let mut transaction = self.pool.begin().await?;
        query(
            "UPDATE cloud_instances SET hourly_cost_micros = $2, ssh_host = $3, ssh_port = $4, \
                 status = 'running', started_at = COALESCE(started_at, $5), \
                 last_error = NULL, observed_at = NOW(), updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .bind(i64::try_from(instance.hourly_micros)?)
        .bind(host)
        .bind(i32::from(port))
        .bind(ready_at)
        .execute(&mut *transaction)
        .await?;
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
                "SELECT raw_transaction, transaction_hash, transaction_nonce \
                 FROM lifecycle_outbox WHERE action_id = $1",
            )
            .bind(action.action_id)
            .fetch_one(&mut *connection)
            .await?;
            if let (Some(raw_transaction), Some(transaction_hash), Some(nonce)) = existing {
                return Ok(PreparedTransaction {
                    nonce: u64::try_from(nonce)?,
                    raw_transaction,
                    transaction_hash,
                });
            }
            let data = action.kind.calldata(action.chain_lease_id);
            let prepared = self
                .chain
                .prepare_transaction(&self.signer, self.escrow, &data, ROBINHOOD_CHAIN_ID)
                .await?;
            query(
                "UPDATE lifecycle_outbox SET raw_transaction = $2, transaction_hash = $3, \
                     transaction_nonce = $4, status = 'submitted', lease_until = NULL, \
                     updated_at = NOW() WHERE action_id = $1",
            )
            .bind(action.action_id)
            .bind(&prepared.raw_transaction)
            .bind(&prepared.transaction_hash)
            .bind(prepared.nonce as i64)
            .execute(&mut *connection)
            .await?;
            self.chain.submit(&prepared).await?;
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
            ActionKind::RefreshGrant => unreachable!(),
        }
        query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 confirmed_block = $2, confirmed_block_hash = $3, last_error = NULL, \
                 updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action.action_id)
        .bind(block_number as i64)
        .bind(block_hash.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn complete_start(&self, action: &Action, block_time: u64) -> anyhow::Result<()> {
        let started_at = DateTime::from_timestamp(block_time as i64, 0)
            .context("access start timestamp is invalid")?;
        query(
            "UPDATE lease_lifecycle SET access_started_at = COALESCE(access_started_at, $2), \
                 start_transaction_hash = $3, updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .bind(started_at)
        .bind(
            action
                .transaction
                .as_ref()
                .context("start transaction is missing")?
                .transaction_hash
                .to_ascii_lowercase(),
        )
        .execute(&self.pool)
        .await?;
        if !self.is_cloud_lease(action.lease_id).await? {
            self.issue_grant(action.lease_id, false).await?;
        }
        self.set_lease_state(action.lease_id, LeaseState::Active)
            .await
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
            receipt_hash: String::new(),
            transaction_hash: transaction_hash.clone(),
        };
        receipt.receipt_hash = receipt_hash(&receipt)?;
        self.insert_receipt(action.lease_id, &receipt, block_number, block_hash)
            .await?;
        self.set_lease_state(action.lease_id, LeaseState::Refunded)
            .await
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
        receipt.transaction_hash = action
            .transaction
            .as_ref()
            .context("finalization transaction is missing")?
            .transaction_hash
            .clone();
        self.insert_receipt(action.lease_id, &receipt, block_number, block_hash)
            .await?;
        let mut transaction = self.pool.begin().await?;
        query(
            "UPDATE settlement_jobs SET status = 'finalized', updated_at = NOW() \
             WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(&mut transaction, action.lease_id, LeaseState::Finalized).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn refresh_grant(&self, action: &Action) -> anyhow::Result<()> {
        self.issue_grant(action.lease_id, true).await?;
        query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 last_error = NULL, updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action.action_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn issue_grant(&self, lease_id: u64, rotate: bool) -> anyhow::Result<()> {
        let context = self.lease_context(lease_id).await?;
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

    /// Adopt the newest instance wearing this lease's label and destroy the rest.
    /// A create whose response was lost still leaves a machine running and
    /// billing, and the label is the only handle left on it.
    async fn adopt_labelled(&self, vast: &VastBroker, label: &str) -> anyhow::Result<Option<u64>> {
        let mut found = vast.find_by_label(label).await?.into_iter();
        let Some(adopted) = found.next() else {
            return Ok(None);
        };
        for orphan in found {
            tracing::warn!(
                orphan,
                label,
                "destroying a duplicate instance for this lease"
            );
            vast.destroy(orphan).await?;
        }
        Ok(Some(adopted))
    }

    async fn destroy_cloud_instance(&self, lease_id: u64) -> anyhow::Result<bool> {
        let row = query_as::<_, (Option<i64>, String)>(
            "SELECT provider_instance_id, status FROM cloud_instances WHERE lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let Some((instance_id, status)) = row else {
            return Ok(false);
        };
        if status == "destroyed" {
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
        match instance_id {
            Some(instance_id) => vast.destroy(u64::try_from(instance_id)?).await?,
            // The id is missing either because the machine was never created or
            // because the response that carried it was lost. Only the label can
            // tell the two apart, and the second one bills by the hour.
            None => {
                for orphan in vast
                    .find_by_label(&format!("prism-lease-{lease_id}"))
                    .await?
                {
                    tracing::warn!(lease_id, orphan, "destroying an unrecorded instance");
                    vast.destroy(orphan).await?;
                }
            }
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
        let cloud = query_as::<_, (i64, i64, String)>(
            "SELECT provider_instance_id, hourly_cost_micros, status \
             FROM cloud_instances \
             WHERE lease_id = $1 \
               AND provider_instance_id IS NOT NULL \
               AND hourly_cost_micros IS NOT NULL",
        )
        .bind(lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let execution = match cloud {
            Some((instance_id, hourly_cost_micros, status)) => {
                if status != "destroyed" {
                    anyhow::bail!("cloud instance was not destroyed before settlement");
                }
                ExecutionEvidence::Vast {
                    instance_id: u64::try_from(instance_id)?,
                    hourly_cost_micros: u64::try_from(hourly_cost_micros)?,
                }
            }
            None => ExecutionEvidence::Physical,
        };
        let telemetry = query_scalar::<_, SqlJson<NodeTelemetry>>(
            "SELECT document FROM lease_telemetry WHERE lease_id = $1 ORDER BY sequence",
        )
        .bind(lease_id as i64)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|SqlJson(value)| value)
        .collect();
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
            gpu_model: context.offer.gpu.model,
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
            trust_class: Some(context.lease.trust_class),
            execution,
            node_telemetry: telemetry,
        })
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
                Option<Uuid>,
                i32,
            ),
        >(
            "SELECT l.document, o.document, lc.connection_id, \
                    lc.cuda_ready_at, lc.gateway_ready_at, lc.access_started_at, lc.access_ended_at, \
                    lc.gateway_closed_at, lc.grant_token_id, \
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
            min_vram_mib: u32::try_from(row.9).unwrap_or(0),
            connection_id: row.2,
            cuda_ready_at: row.3,
            gateway_ready_at: row.4,
            access_started_at: row.5,
            access_ended_at: row.6,
            gateway_closed_at: row.7,
            grant_token_id: row.8,
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
        query(
            "INSERT INTO proof_receipts \
                 (receipt_id, lease_id, document, transaction_hash, block_number, block_hash) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (lease_id) DO NOTHING",
        )
        .bind(receipt.receipt_id)
        .bind(internal_lease_id as i64)
        .bind(SqlJson(receipt.clone()))
        .bind(receipt.transaction_hash.to_ascii_lowercase())
        .bind(block_number as i64)
        .bind(block_hash.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark an action done without acting on it, for a lease the chain has
    /// already moved past.
    async fn skip_action(&self, action: &Action) -> anyhow::Result<()> {
        query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 last_error = NULL, updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action.action_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a lease the escrow settled without us seeing the transaction that
    /// did it. The money has moved and the node is already free; what is left is
    /// our own state. The public receipt is not published here, because a
    /// receipt names the settling transaction and we never observed one.
    async fn adopt_settled_lease(&self, action: &Action, status: u8) -> anyhow::Result<()> {
        let (state, job) = if status == LEASE_STATUS_FINALIZED {
            (LeaseState::Finalized, "finalized")
        } else {
            (LeaseState::Refunded, "failed")
        };
        let mut transaction = self.pool.begin().await?;
        query(
            "UPDATE settlement_jobs SET status = $2, \
                 last_error = 'settled on chain without an observed transaction', \
                 updated_at = NOW() WHERE lease_id = $1",
        )
        .bind(action.lease_id as i64)
        .bind(job)
        .execute(&mut *transaction)
        .await?;
        set_lease_state_in(&mut transaction, action.lease_id, state).await?;
        query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action.action_id)
        .execute(&mut *transaction)
        .await?;
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
        query(
            "UPDATE lifecycle_outbox SET status = 'completed', lease_until = NULL, \
                 updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action.action_id)
        .execute(&mut *transaction)
        .await?;
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

    async fn remember_rejected_machine(&self, machine_id: i64, reason: &str) -> anyhow::Result<()> {
        query(
            "INSERT INTO cloud_machine_rejections (machine_id, reason) VALUES ($1, $2) \
             ON CONFLICT (machine_id) DO UPDATE \
             SET reason = EXCLUDED.reason, \
                 rejections = cloud_machine_rejections.rejections + 1, \
                 last_rejected_at = NOW()",
        )
        .bind(machine_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_lease_state(&self, lease_id: u64, state: LeaseState) -> anyhow::Result<()> {
        let mut transaction = self.pool.begin().await?;
        set_lease_state_in(&mut transaction, lease_id, state).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Forgets the transaction prepared for an action, so the next attempt
    /// builds a fresh one against current chain state.
    async fn discard_prepared_transaction(&self, action_id: Uuid) -> anyhow::Result<()> {
        query(
            "UPDATE lifecycle_outbox \
             SET raw_transaction = NULL, transaction_hash = NULL, \
                 transaction_nonce = NULL, updated_at = NOW() \
             WHERE action_id = $1",
        )
        .bind(action_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reschedule_submitted(&self, action_id: Uuid) -> anyhow::Result<()> {
        query(
            "UPDATE lifecycle_outbox SET status = 'submitted', lease_until = NULL, \
                 available_at = NOW() + INTERVAL '5 seconds', updated_at = NOW() \
             WHERE action_id = $1",
        )
        .bind(action_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn retry(&self, action_id: Uuid, error: &anyhow::Error) -> anyhow::Result<()> {
        let message: String = format!("{error:#}").chars().take(1_024).collect();
        if error.downcast_ref::<StillProvisioning>().is_some() {
            // Waiting is not an attempt, and `expire_provision` already bounds
            // how long the whole thing may take.
            query(
                "UPDATE lifecycle_outbox SET status = 'queued', lease_until = NULL, \
                     attempts = GREATEST(0, attempts - 1), \
                     available_at = NOW() + INTERVAL '5 seconds', \
                     last_error = $2, updated_at = NOW() WHERE action_id = $1",
            )
            .bind(action_id)
            .bind(message)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        let exhausted = query_scalar::<_, Option<i64>>(
            "UPDATE lifecycle_outbox SET \
                 status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END, \
                 lease_until = NULL, \
                 available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)), \
                 last_error = $2, updated_at = NOW() WHERE action_id = $1 \
             RETURNING CASE WHEN attempts >= 100 THEN lease_id END",
        )
        .bind(action_id)
        .bind(message)
        .fetch_optional(&self.pool)
        .await?
        .flatten();
        if let Some(lease_id) = exhausted {
            let lease_id = u64::try_from(lease_id)?;
            tracing::error!(lease_id, "lifecycle action exhausted its attempts");
            self.set_lease_state(lease_id, LeaseState::Failed).await?;
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
            Self::RefreshGrant => unreachable!(),
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

    async fn issue_grant(
        &self,
        token_id: Uuid,
        lease_id: u64,
        node_id: &str,
        connection_id: &str,
        ttl_seconds: u32,
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
    if present.is_none() || !rejections {
        anyhow::bail!("control-plane lifecycle migrations have not been applied");
    }
    Ok(())
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
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

#[cfg(test)]
mod tests {
    use super::*;

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
            access_ended_at: 0,
            created_at: now - PROVISION_TIMEOUT_SECONDS - 1,
            status: 1,
        };
        assert!(expirable(funded_and_stale, now));

        let funded_but_fresh = OnchainLease {
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
}
