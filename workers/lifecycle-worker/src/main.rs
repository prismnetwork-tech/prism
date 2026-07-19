use std::{env, sync::Arc, time::Duration};

use anyhow::Context;
use chrono::{DateTime, Utc};
use prism_chain::{
    EthereumSigner, Finality, PreparedTransaction, RpcClient, address, selector, word_u128,
};
use prism_protocol::{
    CredentialCipher, LeaseRecord, LeaseState, NodeOffer, NodeTelemetry, PublicReceipt,
    ROBINHOOD_CHAIN_ID, ReceiptOutcome, SettlementEvidence, receipt_hash,
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

const SIGNER_LOCK: i64 = 4_663_001;

struct Worker {
    pool: PgPool,
    chain: RpcClient,
    signer: EthereumSigner,
    escrow: [u8; 20],
    confirmations: u64,
    gateway: GatewayClient,
    cipher: CredentialCipher,
}

#[derive(Debug)]
struct Action {
    action_id: Uuid,
    lease_id: u64,
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

#[derive(Debug)]
struct LeaseContext {
    lease: LeaseRecord,
    offer: NodeOffer,
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
        .with_env_filter(EnvFilter::from_default_env())
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
        confirmations,
        gateway: GatewayClient::from_environment()?,
        cipher: CredentialCipher::from_hex(&required_env("PRISM_ACCESS_CREDENTIAL_KEY")?)
            .context("PRISM_ACCESS_CREDENTIAL_KEY must be 32 bytes of hex")?,
    };
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");
    loop {
        worker.scan().await?;
        let Some(action) = worker.claim().await? else {
            if run_once {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        let action_id = action.action_id;
        if let Err(error) = worker.process(action).await {
            tracing::error!(%action_id, %error, "lifecycle action failed");
            worker.retry(action_id, &error).await?;
        }
        if run_once {
            return Ok(());
        }
    }
}

impl Worker {
    async fn scan(&self) -> anyhow::Result<()> {
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
             WHERE l.state = 'active' \
               AND (lc.access_started_at + \
                    make_interval(secs => (l.document->>'duration_seconds')::int) <= NOW() \
                    OR nt.observed_at IS NULL \
                    OR nt.observed_at < NOW() - INTERVAL '90 seconds' \
                    OR t.observed_at IS NULL \
                    OR t.observed_at < NOW() - INTERVAL '90 seconds') \
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

    async fn claim(&self) -> anyhow::Result<Option<Action>> {
        let mut transaction = self.pool.begin().await?;
        let row = query_as::<
            _,
            (
                Uuid,
                i64,
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
            ),
        >(
            "SELECT action_id, lease_id, kind, raw_transaction, transaction_hash, transaction_nonce \
             FROM lifecycle_outbox \
             WHERE attempts < 100 AND available_at <= NOW() \
               AND (status IN ('queued', 'submitted') \
                    OR (status = 'processing' AND lease_until <= NOW())) \
             ORDER BY available_at, created_at LIMIT 1 \
             FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((action_id, lease_id, kind, raw, hash, nonce)) = row else {
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
        Ok(Some(Action {
            action_id,
            lease_id: u64::try_from(lease_id)?,
            kind: ActionKind::parse(&kind)?,
            transaction,
        }))
    }

    async fn process(&self, mut action: Action) -> anyhow::Result<()> {
        if action.kind == ActionKind::RefreshGrant {
            return self.refresh_grant(&action).await;
        }
        if action.kind == ActionKind::StartAccess && action.transaction.is_none() {
            self.probe(&action).await?;
        }
        if action.kind == ActionKind::CloseAccess && action.transaction.is_none() {
            self.revoke_access(action.lease_id).await?;
        }
        if action.kind == ActionKind::Finalize && action.transaction.is_none() {
            match self.lease_status(action.lease_id).await? {
                4 => {
                    self.mark_disputed(&action).await?;
                    return Ok(());
                }
                3 => {}
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
            let data = action.kind.calldata(action.lease_id);
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
        self.issue_grant(action.lease_id, false).await?;
        self.set_lease_state(action.lease_id, LeaseState::Active)
            .await
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
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: action.lease_id.to_string(),
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
            receipt_hash: String::new(),
            transaction_hash: transaction_hash.clone(),
        };
        receipt.receipt_hash = receipt_hash(&receipt)?;
        self.insert_receipt(&receipt, block_number, block_hash)
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
        self.insert_receipt(&receipt, block_number, block_hash)
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

    async fn settlement_evidence(&self, lease_id: u64) -> anyhow::Result<SettlementEvidence> {
        let context = self.lease_context(lease_id).await?;
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
            ),
        >(
            "SELECT l.document, o.document, lc.connection_id, \
                    lc.cuda_ready_at, lc.gateway_ready_at, lc.access_started_at, lc.access_ended_at, \
                    lc.gateway_closed_at, lc.grant_token_id \
             FROM leases l \
             JOIN node_offers o ON o.node_id = l.document->>'node_id' \
             JOIN lease_lifecycle lc ON lc.lease_id = l.lease_id \
             WHERE l.lease_id = $1",
        )
        .bind(lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        Ok(LeaseContext {
            lease: row.0.0,
            offer: row.1.0,
            connection_id: row.2,
            cuda_ready_at: row.3,
            gateway_ready_at: row.4,
            access_started_at: row.5,
            access_ended_at: row.6,
            gateway_closed_at: row.7,
            grant_token_id: row.8,
        })
    }

    async fn lease_status(&self, lease_id: u64) -> anyhow::Result<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("getLease(uint256)"));
        data.extend_from_slice(&word_u128(u128::from(lease_id)));
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

    async fn insert_receipt(
        &self,
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
        .bind(receipt.lease_id.parse::<i64>()?)
        .bind(SqlJson(receipt.clone()))
        .bind(receipt.transaction_hash.to_ascii_lowercase())
        .bind(block_number as i64)
        .bind(block_hash.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
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

    async fn set_lease_state(&self, lease_id: u64, state: LeaseState) -> anyhow::Result<()> {
        let mut transaction = self.pool.begin().await?;
        set_lease_state_in(&mut transaction, lease_id, state).await?;
        transaction.commit().await?;
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
        query(
            "UPDATE lifecycle_outbox SET \
                 status = CASE WHEN attempts >= 100 THEN 'failed' ELSE 'queued' END, \
                 lease_until = NULL, \
                 available_at = NOW() + make_interval(secs => LEAST(300, attempts * attempts)), \
                 last_error = $2, updated_at = NOW() WHERE action_id = $1",
        )
        .bind(action_id)
        .bind(message)
        .execute(&self.pool)
        .await?;
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

    fn calldata(self, lease_id: u64) -> Vec<u8> {
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
        data.extend_from_slice(&word_u128(u128::from(lease_id)));
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
        self.client
            .delete(self.base_url.join(&format!("v1/grants/{token_id}"))?)
            .bearer_auth(self.token.as_str())
            .send()
            .await?
            .error_for_status()?;
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
    if present.is_none() {
        anyhow::bail!("control-plane lifecycle migrations have not been applied");
    }
    Ok(())
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_calldata_uses_exact_contract_selectors() {
        let data = ActionKind::StartAccess.calldata(7);
        assert_eq!(&data[..4], &selector("startAccess(uint256)"));
        assert_eq!(&data[4..], &word_u128(7));

        let expiry = ActionKind::ExpireProvision.calldata(7);
        assert_eq!(&expiry[..4], &selector("expireProvision(uint256,bytes32)"));
        assert_eq!(expiry.len(), 68);
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
}
