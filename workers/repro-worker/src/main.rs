use std::{env, fs, os::unix::fs::PermissionsExt, process::Stdio, time::Duration};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use prism_chain::EthereumSigner;
use prism_protocol::{
    CommandResult, CredentialCipher, EncryptedSecret, LeaseQuote, LeaseRecord, LeaseState,
    ManagedCommandReport, ManagedCommandReportPayload, ManagedProvider, NodeCommand,
    NodeCommandOutcome, ReproExecutor, managed_command_report_digest,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx_core::{
    query::query, query_as::query_as, query_scalar::query_scalar, types::Json as SqlJson,
};
use sqlx_postgres::{PgPool, PgPoolOptions};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const CLAIM_SECONDS: i64 = 45;
const SLOW_CLAIM_SECONDS: i64 = 120;
const SSH_TIMEOUT_SECONDS: u64 = 25;
const SSH_OUTPUT_LIMIT: u64 = 256 * 1024;
const EXECUTION_CLOSE_MARGIN_SECONDS: i64 = 15;
const UNREACHABLE_REPORT_MARGIN_SECONDS: i64 = SSH_TIMEOUT_SECONDS as i64 + 5;
const SSH_FAILURE_REPORT_MARGIN_SECONDS: i64 = 5;
const MAX_GPU_VRAM_MIB: u32 = 196_608;
const MAX_QUEUED_ATTEMPTS: i16 = 5;
const MAX_PREPARE_ATTEMPTS: i16 = 30;
const MAX_READY_ATTEMPTS: i16 = 12;
const MAX_LAUNCHING_ATTEMPTS: i16 = 20;
const MAX_RUNNING_ATTEMPTS: i16 = 120;

#[derive(Clone)]
struct Worker {
    pool: PgPool,
    cipher: CredentialCipher,
    signer: std::sync::Arc<EthereumSigner>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Claim {
    command_id: Uuid,
    token: Uuid,
    generation: i64,
}

struct Job {
    command: NodeCommand,
    status: String,
    private_key: Option<EncryptedSecret>,
    host_key: Option<String>,
    host_key_sha256: Option<String>,
    gpu_model: Option<String>,
    gpu_vram_mib: Option<u32>,
    started_at: Option<DateTime<Utc>>,
    prepared_instance_id: Option<u64>,
    lease: LeaseRecord,
    quote: LeaseQuote,
    access_started_at: Option<DateTime<Utc>>,
    access_ended_at: Option<DateTime<Utc>>,
    instance_id: Option<u64>,
    ssh_host: Option<String>,
    ssh_port: Option<u16>,
    cloud_status: Option<String>,
}

struct SshOutput {
    stdout: Vec<u8>,
    known_hosts: String,
}

#[derive(Debug, PartialEq, Eq)]
enum StartState {
    Launching,
    Started(DateTime<Utc>),
    Finished {
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        result: CommandResult,
    },
    Expired,
    Drifted,
}

#[derive(Debug, PartialEq, Eq)]
enum RemoteState {
    Launching,
    Running(DateTime<Utc>),
    Missing,
    Done {
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        result: CommandResult,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&required_env("DATABASE_URL")?)
        .await
        .context("connect repro database")?;
    verify_schema(&pool).await?;
    record_service_version(&pool).await?;

    let worker = Worker {
        pool,
        cipher: CredentialCipher::from_hex(&required_env("PRISM_ACCESS_CREDENTIAL_KEY")?)
            .context("PRISM_ACCESS_CREDENTIAL_KEY must be 32 bytes of hex")?,
        signer: std::sync::Arc::new(
            EthereumSigner::from_environment("PRISM_GATEWAY_KMS_KEY_ID").await?,
        ),
    };
    let run_once = env::var("PRISM_RUN_ONCE").as_deref() == Ok("1");

    loop {
        let Some(claim) = worker.claim().await? else {
            if run_once {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        if let Err(error) = worker.process(claim).await {
            tracing::error!(command_id = %claim.command_id, %error, "managed repro pass failed");
            if let Err(record_error) = worker.retry(claim).await {
                tracing::error!(command_id = %claim.command_id, %record_error, "managed repro retry failed");
            }
        }
        if run_once {
            return Ok(());
        }
    }
}

impl Worker {
    async fn claim(&self) -> anyhow::Result<Option<Claim>> {
        let token = Uuid::now_v7();
        let row = query_as::<_, (Uuid, i64)>(
            "WITH candidate AS ( \
                 SELECT command_id FROM managed_repro_jobs \
                 WHERE status IN ('queued', 'preparing', 'ready', 'launching', 'running') \
                   AND available_at <= NOW() \
                   AND (lease_until IS NULL OR lease_until <= NOW()) \
                 ORDER BY available_at, created_at LIMIT 1 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE managed_repro_jobs j \
             SET claim_token = $2, claim_generation = claim_generation + 1, \
                 lease_until = NOW() + make_interval(secs => $1), updated_at = NOW() \
             FROM candidate WHERE j.command_id = candidate.command_id \
             RETURNING j.command_id, j.claim_generation",
        )
        .bind(CLAIM_SECONDS as f64)
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(command_id, generation)| Claim {
            command_id,
            token,
            generation,
        }))
    }

    async fn process(&self, claim: Claim) -> anyhow::Result<()> {
        let job = self.load(claim).await?;
        match job.status.as_str() {
            "queued" => self.generate_key(claim, &job).await,
            "preparing" => self.preflight(claim, &job).await,
            "ready" | "launching" | "running" => self.execute(claim, &job).await,
            status => anyhow::bail!("managed repro job has unsupported status {status}"),
        }
    }

    async fn load(&self, claim: Claim) -> anyhow::Result<Job> {
        let (
            SqlJson(command),
            status,
            private_key,
            host_key,
            host_key_sha256,
            gpu_model,
            gpu_vram_mib,
            started_at,
            prepared_instance_id,
        ) = query_as::<
            _,
            (
                SqlJson<NodeCommand>,
                String,
                Option<SqlJson<EncryptedSecret>>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<i32>,
                Option<DateTime<Utc>>,
                Option<i64>,
            ),
        >(
            "SELECT command, status, runner_private_key, transport_host_key, \
                    transport_host_key_sha256, gpu_model, gpu_vram_mib, started_at, \
                    prepared_provider_instance_id \
             FROM managed_repro_jobs WHERE command_id = $1 AND claim_token = $2 \
               AND claim_generation = $3",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .fetch_one(&self.pool)
        .await?;
        let SqlJson(lease) = query_scalar::<_, SqlJson<LeaseRecord>>(
            "SELECT document FROM leases WHERE lease_id = $1",
        )
        .bind(command.lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        let SqlJson(quote) = query_scalar::<_, SqlJson<LeaseQuote>>(
            "SELECT document FROM lease_quotes WHERE quote_id = $1",
        )
        .bind(lease.quote_id)
        .fetch_one(&self.pool)
        .await?;
        let (access_started_at, access_ended_at) = query_as::<
            _,
            (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
        >(
            "SELECT access_started_at, access_ended_at FROM lease_lifecycle WHERE lease_id = $1",
        )
        .bind(command.lease_id as i64)
        .fetch_one(&self.pool)
        .await?;
        let cloud = query_as::<_, (Option<i64>, Option<String>, Option<i32>, String)>(
            "SELECT provider_instance_id, ssh_host, ssh_port, status \
             FROM cloud_instances WHERE lease_id = $1",
        )
        .bind(command.lease_id as i64)
        .fetch_optional(&self.pool)
        .await?;
        let (instance_id, ssh_host, ssh_port, cloud_status) = match cloud {
            Some((instance_id, host, port, status)) => (
                instance_id.map(u64::try_from).transpose()?,
                host,
                port.map(u16::try_from).transpose()?,
                Some(status),
            ),
            None => (None, None, None, None),
        };

        Ok(Job {
            command,
            status,
            private_key: private_key.map(|SqlJson(value)| value),
            host_key,
            host_key_sha256,
            gpu_model,
            gpu_vram_mib: gpu_vram_mib.map(u32::try_from).transpose()?,
            started_at,
            prepared_instance_id: prepared_instance_id.map(u64::try_from).transpose()?,
            lease,
            quote,
            access_started_at,
            access_ended_at,
            instance_id,
            ssh_host,
            ssh_port,
            cloud_status,
        })
    }

    async fn generate_key(&self, claim: Claim, job: &Job) -> anyhow::Result<()> {
        ensure_prestart(job)?;
        if Utc::now() >= job.command.expires_at {
            return self
                .fail_terminal(claim, job, "managed command expired before provisioning")
                .await;
        }
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        let public_key = key.public_key().to_openssh()?;
        let private_key = key.to_openssh(LineEnding::LF)?;
        let encrypted = self.cipher.encrypt(private_key.as_str())?;

        let mut transaction = self.pool.begin().await?;
        let cloud = query(
            "UPDATE cloud_instances SET ssh_authorized_key = $2, updated_at = NOW() \
             WHERE lease_id = $1 AND (ssh_authorized_key IS NULL OR ssh_authorized_key = $2)",
        )
        .bind(job.command.lease_id as i64)
        .bind(&public_key)
        .execute(&mut *transaction)
        .await?;
        expect_one(cloud.rows_affected(), "install managed SSH key")?;
        let updated = query(
            "UPDATE managed_repro_jobs \
             SET runner_private_key = $4, runner_public_key = $5, status = 'preparing', \
                 attempts = 0, claim_token = NULL, lease_until = NULL, available_at = NOW(), \
                 last_error = NULL, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'queued'",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(SqlJson(encrypted))
        .bind(&public_key)
        .execute(&mut *transaction)
        .await?;
        expect_one(
            updated.rows_affected(),
            "advance managed repro to preflight",
        )?;
        transaction.commit().await?;
        Ok(())
    }

    async fn preflight(&self, claim: Claim, job: &Job) -> anyhow::Result<()> {
        ensure_prestart(job)?;
        if Utc::now() >= job.command.expires_at {
            return self
                .fail_terminal(claim, job, "managed command expired before preflight")
                .await;
        }
        if matches!(job.cloud_status.as_deref(), Some("failed" | "destroyed")) {
            return self
                .fail_terminal(claim, job, "managed GPU provisioning failed")
                .await;
        }
        let Some(instance_id) = job.instance_id else {
            return self.release(claim, 2, false).await;
        };
        let Some((host, port)) = target(job) else {
            return self.release(claim, 2, false).await;
        };
        if job.cloud_status.as_deref() != Some("running") {
            return self.release(claim, 2, false).await;
        }
        let private_key = self.decrypt_key(job)?;
        let output = self
            .run_ssh(claim, &private_key, None, host, port, PREFLIGHT_SCRIPT)
            .await?;
        let known_hosts = output.known_hosts.trim().to_owned();
        let host_key_sha256 = known_hosts_fingerprint(&known_hosts)?;
        let (gpu_model, gpu_vram_mib) = parse_gpu(&output.stdout)?;
        if gpu_vram_mib < job.quote.min_vram_mib {
            return self
                .fail_terminal(
                    claim,
                    job,
                    "managed GPU has less VRAM than the signed repro",
                )
                .await;
        }

        let instance_id = i64::try_from(instance_id)?;
        let gpu_vram_mib = i32::try_from(gpu_vram_mib)?;
        let mut transaction = self.pool.begin().await?;
        let cloud = query(
            "UPDATE cloud_instances SET gpu_model = $3, gpu_vram_mib = $4, updated_at = NOW() \
             WHERE lease_id = $1 AND provider_instance_id = $2 AND status = 'running'",
        )
        .bind(job.command.lease_id as i64)
        .bind(instance_id)
        .bind(&gpu_model)
        .bind(gpu_vram_mib)
        .execute(&mut *transaction)
        .await?;
        expect_one(cloud.rows_affected(), "bind preflight to provider instance")?;
        let updated = query(
            "UPDATE managed_repro_jobs \
             SET transport_host_key = $4, transport_host_key_sha256 = $5, \
                 gpu_model = $6, gpu_vram_mib = $7, prepared_provider_instance_id = $8, \
                 status = 'ready', attempts = 0, claim_token = NULL, lease_until = NULL, \
                 available_at = NOW(), last_error = NULL, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'preparing'",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(&known_hosts)
        .bind(&host_key_sha256)
        .bind(&gpu_model)
        .bind(gpu_vram_mib)
        .bind(instance_id)
        .execute(&mut *transaction)
        .await?;
        expect_one(updated.rows_affected(), "complete managed repro preflight")?;
        transaction.commit().await?;
        Ok(())
    }

    async fn execute(&self, claim: Claim, job: &Job) -> anyhow::Result<()> {
        ensure_job_contract(job)?;
        let prepared_instance_id = job
            .prepared_instance_id
            .context("managed repro has no preflight instance binding")?;
        if job.instance_id != Some(prepared_instance_id) {
            return if job.status == "ready" {
                self.reset_preflight(claim, job).await
            } else {
                self.fail_terminal(
                    claim,
                    job,
                    "provider instance changed after managed execution started",
                )
                .await
            };
        }
        if matches!(
            job.lease.state,
            LeaseState::Funded | LeaseState::Provisioning | LeaseState::Ready
        ) {
            return self.release(claim, 2, true).await;
        }
        if matches!(
            job.lease.state,
            LeaseState::Refunded | LeaseState::Finalized | LeaseState::Disputed
        ) {
            return self
                .fail_terminal(claim, job, "lease ended before managed execution")
                .await;
        }

        let window_start = job
            .access_started_at
            .context("active managed repro has no access start")?;
        let deadline = execution_deadline(job, window_start)?;
        let now = Utc::now();
        let unreachable_cutoff =
            deadline - chrono::Duration::seconds(UNREACHABLE_REPORT_MARGIN_SECONDS);
        let remote_cutoff = deadline - chrono::Duration::seconds(EXECUTION_CLOSE_MARGIN_SECONDS);
        let ssh_failure_cutoff =
            deadline - chrono::Duration::seconds(SSH_FAILURE_REPORT_MARGIN_SECONDS);
        let closing = matches!(
            job.lease.state,
            LeaseState::Closing | LeaseState::SettlementPending | LeaseState::Failed
        );
        let Some((host, port)) = target(job) else {
            return if closing || (job.status != "ready" && now >= unreachable_cutoff) {
                self.fail_terminal(claim, job, "managed GPU became unreachable")
                    .await
            } else {
                anyhow::bail!("managed GPU has no SSH target")
            };
        };
        if job.cloud_status.as_deref() != Some("running") {
            return if closing || (job.status != "ready" && now >= unreachable_cutoff) {
                self.fail_terminal(claim, job, "managed GPU stopped before result retrieval")
                    .await
            } else {
                anyhow::bail!("managed GPU is not running")
            };
        }

        let private_key = self.decrypt_key(job)?;
        let host_key = job
            .host_key
            .as_deref()
            .context("managed repro has no pinned host key")?;

        if job.status == "ready" {
            if now >= job.command.expires_at {
                return self
                    .fail_terminal(claim, job, "managed command expired before launch")
                    .await;
            }
            let remaining = (deadline - now).num_seconds() - EXECUTION_CLOSE_MARGIN_SECONDS;
            if remaining <= 0 {
                return self
                    .fail_terminal(claim, job, "no execution window remained before launch")
                    .await;
            }
            let script = start_script(
                &job.command,
                remaining as u64,
                window_start,
                deadline,
                job.gpu_model
                    .as_deref()
                    .context("managed repro has no preflight GPU model")?,
                job.gpu_vram_mib
                    .context("managed repro has no preflight GPU memory")?,
            )?;
            let output = self
                .run_ssh(claim, &private_key, Some(host_key), host, port, &script)
                .await?;
            return match parse_start_state(&output.stdout)? {
                StartState::Expired => {
                    self.fail_terminal(claim, job, "remote command authorization expired")
                        .await
                }
                StartState::Drifted => self.reset_preflight(claim, job).await,
                StartState::Launching => self.advance_launching(claim, job).await,
                StartState::Started(started_at) => {
                    validate_execution_times(job, started_at, None)?;
                    self.advance_running_from_ready(claim, job, started_at)
                        .await
                }
                StartState::Finished {
                    started_at,
                    finished_at,
                    result,
                } => {
                    self.finish(claim, job, result, started_at, finished_at)
                        .await
                }
            };
        }

        let script = poll_script(job.command.command_id);
        let polled = self
            .run_ssh(claim, &private_key, Some(host_key), host, port, &script)
            .await;
        match polled.and_then(|output| parse_remote_state(&output.stdout)) {
            Ok(RemoteState::Done {
                started_at,
                finished_at,
                result,
            }) => {
                self.finish(claim, job, result, started_at, finished_at)
                    .await
            }
            Ok(RemoteState::Running(started_at)) => {
                validate_execution_times(job, started_at, None)?;
                if job.status == "launching" {
                    return self.advance_started(claim, job, started_at).await;
                }
                if closing || Utc::now() >= remote_cutoff {
                    self.fail_terminal(claim, job, "managed command exceeded its execution window")
                        .await
                } else {
                    self.release_running(claim, Some(started_at), 2).await
                }
            }
            Ok(RemoteState::Launching) => {
                if closing || Utc::now() >= remote_cutoff {
                    self.fail_terminal(
                        claim,
                        job,
                        "managed supervisor did not start within its execution window",
                    )
                    .await
                } else {
                    self.release(claim, 2, true).await
                }
            }
            Ok(RemoteState::Missing) => {
                if closing || Utc::now() >= remote_cutoff {
                    self.fail_terminal(claim, job, "managed command state was lost")
                        .await
                } else {
                    anyhow::bail!("managed command has no remote state")
                }
            }
            Err(error) if closing || Utc::now() >= ssh_failure_cutoff => {
                tracing::warn!(command_id = %job.command.command_id, %error, "managed repro result unavailable at close");
                self.fail_terminal(claim, job, "managed result could not be retrieved")
                    .await
            }
            Err(error) => Err(error),
        }
    }

    async fn finish(
        &self,
        claim: Claim,
        job: &Job,
        result: CommandResult,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        validate_execution_times(job, started_at, Some(finished_at))?;
        if let Some(recorded) = job.started_at
            && recorded != started_at
        {
            anyhow::bail!("managed supervisor start time changed");
        }
        let instance_id = job
            .prepared_instance_id
            .context("managed repro has no preflight instance binding")?;
        if job.instance_id != Some(instance_id) {
            anyhow::bail!("provider instance changed before managed report signing");
        }
        let gpu_model = job
            .gpu_model
            .clone()
            .context("managed repro has no GPU model")?;
        let gpu_vram_mib = job
            .gpu_vram_mib
            .context("managed repro has no GPU memory")?;
        let host_key_sha256 = job
            .host_key_sha256
            .clone()
            .context("managed repro has no host-key commitment")?;
        let signer = format!("0x{}", hex::encode(self.signer.address()));
        let payload = ManagedCommandReportPayload {
            report_id: Uuid::now_v7(),
            signer: signer.clone(),
            command_id: job.command.command_id,
            lease_id: job.command.lease_id,
            provider: ManagedProvider::Vast,
            provider_instance_id: instance_id,
            gpu_model: gpu_model.clone(),
            gpu_vram_mib,
            transport_host_key_sha256: host_key_sha256.clone(),
            started_at,
            finished_at,
            outcome: NodeCommandOutcome::Completed,
            error: None,
            result: Some(result.clone()),
        };
        self.extend_claim(claim, SLOW_CLAIM_SECONDS).await?;
        let signature = self
            .signer
            .sign_digest(&managed_command_report_digest(&payload)?)
            .await?;
        self.extend_claim(claim, CLAIM_SECONDS).await?;
        let report = ManagedCommandReport {
            report_id: payload.report_id,
            signer,
            command_id: payload.command_id,
            lease_id: payload.lease_id,
            provider: payload.provider,
            provider_instance_id: payload.provider_instance_id,
            gpu_model,
            gpu_vram_mib,
            transport_host_key_sha256: host_key_sha256,
            started_at,
            finished_at,
            outcome: NodeCommandOutcome::Completed,
            error: None,
            result: Some(result),
            signature: format!("0x{}", hex::encode(signature)),
        };
        report.verify()?;

        let mut transaction = self.pool.begin().await?;
        let completed = query(
            "UPDATE managed_repro_jobs SET status = 'completed', report = $2, \
                 started_at = $3, finished_at = $4, attempts = 0, claim_token = NULL, \
                 lease_until = NULL, last_error = NULL, runner_private_key = NULL, \
                 updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $5 AND claim_generation = $6 \
               AND status IN ('ready', 'launching', 'running') AND report IS NULL \
               AND prepared_provider_instance_id = $7 \
               AND EXISTS (SELECT 1 FROM cloud_instances ci \
                   WHERE ci.lease_id = managed_repro_jobs.lease_id \
                     AND ci.provider_instance_id = $7 \
                     AND ci.gpu_model = managed_repro_jobs.gpu_model \
                     AND ci.gpu_vram_mib = managed_repro_jobs.gpu_vram_mib)",
        )
        .bind(job.command.command_id)
        .bind(SqlJson(report))
        .bind(started_at)
        .bind(finished_at)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(i64::try_from(instance_id)?)
        .execute(&mut *transaction)
        .await?;
        expect_one(completed.rows_affected(), "persist signed managed report")?;
        let SqlJson(mut lease) = query_scalar::<_, SqlJson<LeaseRecord>>(
            "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
        )
        .bind(job.command.lease_id as i64)
        .fetch_one(&mut *transaction)
        .await?;
        if lease.state == LeaseState::Active {
            lease.state = LeaseState::Closing;
            lease.updated_at = Utc::now();
            let closed = query(
                "UPDATE leases SET document = $2, state = 'closing', updated_at = NOW() \
                 WHERE lease_id = $1 AND state = 'active'",
            )
            .bind(job.command.lease_id as i64)
            .bind(SqlJson(lease))
            .execute(&mut *transaction)
            .await?;
            expect_one(closed.rows_affected(), "close completed managed lease")?;
        }
        let outbox = query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
             VALUES ($1, $2, 'close_access', NOW()) \
             ON CONFLICT (lease_id, kind) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(job.command.lease_id as i64)
        .execute(&mut *transaction)
        .await?;
        expect_at_most_one(outbox.rows_affected(), "queue managed access close")?;
        transaction.commit().await?;
        Ok(())
    }

    async fn finish_failed(&self, claim: Claim, job: &Job, reason: &str) -> anyhow::Result<()> {
        let started_at = job
            .started_at
            .context("started managed repro has no supervisor start time")?;
        let finished_at = job.access_ended_at.unwrap_or_else(Utc::now);
        validate_execution_times(job, started_at, Some(finished_at))?;
        let instance_id = job
            .prepared_instance_id
            .context("managed repro has no preflight instance binding")?;
        let gpu_model = job
            .gpu_model
            .clone()
            .context("managed repro has no GPU model")?;
        let gpu_vram_mib = job
            .gpu_vram_mib
            .context("managed repro has no GPU memory")?;
        let host_key_sha256 = job
            .host_key_sha256
            .clone()
            .context("managed repro has no host-key commitment")?;
        let signer = format!("0x{}", hex::encode(self.signer.address()));
        let payload = ManagedCommandReportPayload {
            report_id: Uuid::now_v7(),
            signer: signer.clone(),
            command_id: job.command.command_id,
            lease_id: job.command.lease_id,
            provider: ManagedProvider::Vast,
            provider_instance_id: instance_id,
            gpu_model: gpu_model.clone(),
            gpu_vram_mib,
            transport_host_key_sha256: host_key_sha256.clone(),
            started_at,
            finished_at,
            outcome: NodeCommandOutcome::Failed,
            error: Some(reason.to_owned()),
            result: None,
        };
        self.extend_claim(claim, SLOW_CLAIM_SECONDS).await?;
        let signature = self
            .signer
            .sign_digest(&managed_command_report_digest(&payload)?)
            .await?;
        self.extend_claim(claim, CLAIM_SECONDS).await?;
        let report = ManagedCommandReport {
            report_id: payload.report_id,
            signer,
            command_id: payload.command_id,
            lease_id: payload.lease_id,
            provider: payload.provider,
            provider_instance_id: payload.provider_instance_id,
            gpu_model,
            gpu_vram_mib,
            transport_host_key_sha256: host_key_sha256,
            started_at,
            finished_at,
            outcome: NodeCommandOutcome::Failed,
            error: Some(reason.to_owned()),
            result: None,
            signature: format!("0x{}", hex::encode(signature)),
        };
        report.verify()?;

        let mut transaction = self.pool.begin().await?;
        let failed = query(
            "UPDATE managed_repro_jobs SET status = 'failed', report = $2, \
                 finished_at = $3, claim_token = NULL, lease_until = NULL, \
                 runner_private_key = NULL, last_error = $4, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $5 AND claim_generation = $6 \
               AND status = 'running' AND started_at = $7 AND report IS NULL \
               AND prepared_provider_instance_id = $8",
        )
        .bind(job.command.command_id)
        .bind(SqlJson(report))
        .bind(finished_at)
        .bind(reason)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(started_at)
        .bind(i64::try_from(instance_id)?)
        .execute(&mut *transaction)
        .await?;
        expect_one(failed.rows_affected(), "persist signed managed failure")?;

        let SqlJson(mut lease) = query_scalar::<_, SqlJson<LeaseRecord>>(
            "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
        )
        .bind(job.command.lease_id as i64)
        .fetch_one(&mut *transaction)
        .await?;
        if lease.state == LeaseState::Active {
            lease.state = LeaseState::Closing;
            lease.updated_at = Utc::now();
            let closed = query(
                "UPDATE leases SET document = $2, state = 'closing', updated_at = NOW() \
                 WHERE lease_id = $1 AND state = 'active'",
            )
            .bind(job.command.lease_id as i64)
            .bind(SqlJson(lease))
            .execute(&mut *transaction)
            .await?;
            expect_one(closed.rows_affected(), "close failed managed lease")?;
        }
        let outbox = query(
            "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
             VALUES ($1, $2, 'close_access', NOW()) \
             ON CONFLICT (lease_id, kind) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(job.command.lease_id as i64)
        .execute(&mut *transaction)
        .await?;
        expect_at_most_one(outbox.rows_affected(), "queue failed managed access close")?;
        transaction.commit().await?;
        Ok(())
    }

    async fn advance_launching(&self, claim: Claim, job: &Job) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET status = 'launching', attempts = 0, \
                 claim_token = NULL, lease_until = NULL, \
                 available_at = NOW() + INTERVAL '1 second', last_error = NULL, \
                 updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'ready' AND prepared_provider_instance_id = $4",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(i64::try_from(
            job.prepared_instance_id
                .context("missing instance binding")?,
        )?)
        .execute(&self.pool)
        .await?;
        expect_one(
            updated.rows_affected(),
            "record managed repro launch intent",
        )
    }

    async fn advance_running_from_ready(
        &self,
        claim: Claim,
        job: &Job,
        started_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET status = 'running', \
                 started_at = $4, attempts = 0, claim_token = NULL, \
                 lease_until = NULL, available_at = NOW() + INTERVAL '1 second', \
                 last_error = NULL, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'ready' AND prepared_provider_instance_id = $5",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(started_at)
        .bind(i64::try_from(
            job.prepared_instance_id
                .context("missing instance binding")?,
        )?)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "advance managed repro to running")
    }

    async fn advance_started(
        &self,
        claim: Claim,
        job: &Job,
        started_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET status = 'running', started_at = $4, \
                 attempts = 0, claim_token = NULL, lease_until = NULL, \
                 available_at = NOW(), last_error = NULL, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'launching' AND started_at IS NULL \
               AND prepared_provider_instance_id = $5",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(started_at)
        .bind(i64::try_from(
            job.prepared_instance_id
                .context("missing instance binding")?,
        )?)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "record managed supervisor start")
    }

    async fn release_running(
        &self,
        claim: Claim,
        started_at: Option<DateTime<Utc>>,
        seconds: i64,
    ) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET started_at = COALESCE(started_at, $4), \
                 attempts = 0, claim_token = NULL, lease_until = NULL, last_error = NULL, \
                 available_at = NOW() + make_interval(secs => $5), updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'running' AND (started_at IS NULL OR started_at = $4 OR $4 IS NULL)",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(started_at)
        .bind(seconds as f64)
        .execute(&self.pool)
        .await?;
        expect_one(
            updated.rows_affected(),
            "release running managed repro claim",
        )
    }

    async fn reset_preflight(&self, claim: Claim, job: &Job) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET status = 'preparing', \
                 prepared_provider_instance_id = NULL, transport_host_key = NULL, \
                 transport_host_key_sha256 = NULL, gpu_model = NULL, gpu_vram_mib = NULL, \
                 started_at = NULL, finished_at = NULL, attempts = 0, claim_token = NULL, \
                 lease_until = NULL, available_at = NOW(), last_error = NULL, updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = 'ready' AND prepared_provider_instance_id = $4",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(i64::try_from(
            job.prepared_instance_id
                .context("missing instance binding")?,
        )?)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "reset drifted managed preflight")
    }

    async fn retry(&self, claim: Claim) -> anyhow::Result<()> {
        let job = self.load(claim).await?;
        let next_attempt = job_attempts(&self.pool, claim).await?.saturating_add(1);
        if next_attempt >= stage_attempt_cap(&job.status)? {
            let reason = match job.status.as_str() {
                "queued" => "managed runner key generation exhausted its retry limit",
                "preparing" => "managed GPU did not pass preflight",
                "ready" => "managed command launch exhausted its retry limit",
                "launching" => "managed supervisor start exhausted its retry limit",
                "running" => "managed result retrieval exhausted its retry limit",
                _ => "managed execution exhausted its retry limit",
            };
            return self.fail_terminal(claim, &job, reason).await;
        }
        let delay = stage_backoff_seconds(&job.status, next_attempt)?;
        let updated = query(
            "UPDATE managed_repro_jobs SET attempts = $4, claim_token = NULL, \
                 lease_until = NULL, available_at = NOW() + make_interval(secs => $5), \
                 last_error = 'managed execution pass failed', updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = $6",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(next_attempt)
        .bind(delay as f64)
        .bind(&job.status)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "schedule managed repro retry")
    }

    async fn release(
        &self,
        claim: Claim,
        seconds: i64,
        reset_attempts: bool,
    ) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs SET attempts = CASE WHEN $4 THEN 0 ELSE attempts END, \
                 claim_token = NULL, lease_until = NULL, \
                 last_error = CASE WHEN $4 THEN NULL ELSE last_error END, \
                 available_at = NOW() + make_interval(secs => $5), updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(reset_attempts)
        .bind(seconds as f64)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "release managed repro claim")
    }

    async fn fail_terminal(&self, claim: Claim, job: &Job, reason: &str) -> anyhow::Result<()> {
        if job.status == "running" {
            return self.finish_failed(claim, job, reason).await;
        }
        let mut transaction = self.pool.begin().await?;
        let failed = query(
            "UPDATE managed_repro_jobs SET status = 'failed', claim_token = NULL, \
                 lease_until = NULL, runner_private_key = NULL, last_error = $4, \
                 updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status = $5",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(reason)
        .bind(&job.status)
        .execute(&mut *transaction)
        .await?;
        expect_one(failed.rows_affected(), "fail managed repro")?;

        let active = matches!(
            job.lease.state,
            LeaseState::Active
                | LeaseState::Closing
                | LeaseState::SettlementPending
                | LeaseState::Failed
        );
        if active {
            if job.lease.state == LeaseState::Active {
                let SqlJson(mut lease) = query_scalar::<_, SqlJson<LeaseRecord>>(
                    "SELECT document FROM leases WHERE lease_id = $1 FOR UPDATE",
                )
                .bind(job.command.lease_id as i64)
                .fetch_one(&mut *transaction)
                .await?;
                if lease.state == LeaseState::Active {
                    lease.state = LeaseState::Closing;
                    lease.updated_at = Utc::now();
                    let closed = query(
                        "UPDATE leases SET document = $2, state = 'closing', updated_at = NOW() \
                         WHERE lease_id = $1 AND state = 'active'",
                    )
                    .bind(job.command.lease_id as i64)
                    .bind(SqlJson(lease))
                    .execute(&mut *transaction)
                    .await?;
                    expect_one(closed.rows_affected(), "close failed managed lease")?;
                }
            }
            let outbox = query(
                "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
                 VALUES ($1, $2, 'close_access', NOW()) \
                 ON CONFLICT (lease_id, kind) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(job.command.lease_id as i64)
            .execute(&mut *transaction)
            .await?;
            expect_at_most_one(outbox.rows_affected(), "queue failed managed access close")?;
        } else {
            let outbox = query(
                "INSERT INTO lifecycle_outbox (action_id, lease_id, kind, available_at) \
                 SELECT $1, $2, 'expire_provision', \
                        GREATEST(NOW(), created_at + INTERVAL '10 minutes') \
                 FROM leases WHERE lease_id = $2 \
                 ON CONFLICT (lease_id, kind) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(job.command.lease_id as i64)
            .execute(&mut *transaction)
            .await?;
            expect_at_most_one(outbox.rows_affected(), "queue managed provision expiry")?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn extend_claim(&self, claim: Claim, seconds: i64) -> anyhow::Result<()> {
        let updated = query(
            "UPDATE managed_repro_jobs \
             SET lease_until = NOW() + make_interval(secs => $4), updated_at = NOW() \
             WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3 \
               AND status IN ('queued', 'preparing', 'ready', 'launching', 'running')",
        )
        .bind(claim.command_id)
        .bind(claim.token)
        .bind(claim.generation)
        .bind(seconds as f64)
        .execute(&self.pool)
        .await?;
        expect_one(updated.rows_affected(), "extend managed repro claim")
    }

    async fn run_ssh(
        &self,
        claim: Claim,
        private_key: &str,
        known_hosts: Option<&str>,
        host: &str,
        port: u16,
        script: &str,
    ) -> anyhow::Result<SshOutput> {
        self.extend_claim(claim, SLOW_CLAIM_SECONDS).await?;
        let result = run_ssh(private_key, known_hosts, host, port, script).await;
        self.extend_claim(claim, CLAIM_SECONDS).await?;
        result
    }

    fn decrypt_key(&self, job: &Job) -> anyhow::Result<String> {
        self.cipher
            .decrypt(
                job.private_key
                    .as_ref()
                    .context("managed repro has no runner key")?,
            )
            .context("decrypt managed runner key")
    }
}

fn ensure_prestart(job: &Job) -> anyhow::Result<()> {
    if !matches!(
        job.lease.state,
        LeaseState::Funded | LeaseState::Provisioning | LeaseState::Ready
    ) {
        anyhow::bail!("managed repro is no longer in preflight");
    }
    if job.lease.repro.is_none() || job.lease.command.is_none() {
        anyhow::bail!("managed job is not a repro lease");
    }
    Ok(())
}

fn ensure_job_contract(job: &Job) -> anyhow::Result<()> {
    let repro = job
        .lease
        .repro
        .as_ref()
        .context("managed job has no repro capability")?;
    let prism_protocol::NodeCommandKind::Batch {
        image,
        command,
        duration_seconds,
    } = &job.command.kind
    else {
        anyhow::bail!("managed repro command is not a batch");
    };
    if job.command.lease_id != job.lease.lease_id
        || job.command.node_id != job.lease.node_id
        || image != &job.lease.image
        || job.lease.command.as_ref() != Some(command)
        || duration_seconds != &job.lease.duration_seconds
        || job.quote.image != job.lease.image
        || job.quote.command.as_ref() != Some(command)
        || job.quote.duration_seconds != *duration_seconds
        || job.quote.repro.as_ref() != Some(repro)
        || repro.executor != ReproExecutor::Managed
        || job.quote.min_vram_mib == 0
        || job.quote.min_vram_mib > MAX_GPU_VRAM_MIB
    {
        anyhow::bail!("managed job does not match its signed repro contract");
    }
    Ok(())
}

fn execution_duration_seconds(job: &Job) -> anyhow::Result<u32> {
    match &job.command.kind {
        prism_protocol::NodeCommandKind::Batch {
            duration_seconds, ..
        } => Ok(*duration_seconds),
        _ => anyhow::bail!("managed repro command is not a batch"),
    }
}

fn execution_deadline(job: &Job, window_start: DateTime<Utc>) -> anyhow::Result<DateTime<Utc>> {
    let duration = execution_duration_seconds(job)?;
    if duration == 0 || duration != job.lease.duration_seconds {
        anyhow::bail!("managed execution duration does not match its lease");
    }
    Ok(window_start + chrono::Duration::seconds(i64::from(duration)))
}

fn validate_execution_times(
    job: &Job,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let window_start = job
        .access_started_at
        .context("managed repro has no access start")?;
    let deadline = execution_deadline(job, window_start)?;
    if started_at < window_start
        || started_at < job.command.issued_at
        || started_at >= job.command.expires_at
        || started_at > deadline
    {
        anyhow::bail!("managed supervisor start is outside the authorized window");
    }
    let Some(finished_at) = finished_at else {
        return Ok(());
    };
    if finished_at < started_at || finished_at > deadline {
        anyhow::bail!("managed supervisor finish is outside the authorized window");
    }
    if let Some(access_ended_at) = job.access_ended_at
        && finished_at > access_ended_at
    {
        anyhow::bail!("managed supervisor finished after access ended");
    }
    if finished_at - started_at
        > chrono::Duration::seconds(i64::from(execution_duration_seconds(job)?))
    {
        anyhow::bail!("managed supervisor reported an excessive runtime");
    }
    Ok(())
}

async fn job_attempts(pool: &PgPool, claim: Claim) -> anyhow::Result<i16> {
    query_scalar(
        "SELECT attempts FROM managed_repro_jobs \
         WHERE command_id = $1 AND claim_token = $2 AND claim_generation = $3",
    )
    .bind(claim.command_id)
    .bind(claim.token)
    .bind(claim.generation)
    .fetch_one(pool)
    .await
    .context("load fenced managed repro attempts")
}

fn stage_attempt_cap(status: &str) -> anyhow::Result<i16> {
    match status {
        "queued" => Ok(MAX_QUEUED_ATTEMPTS),
        "preparing" => Ok(MAX_PREPARE_ATTEMPTS),
        "ready" => Ok(MAX_READY_ATTEMPTS),
        "launching" => Ok(MAX_LAUNCHING_ATTEMPTS),
        "running" => Ok(MAX_RUNNING_ATTEMPTS),
        _ => anyhow::bail!("managed repro retry has unsupported status {status}"),
    }
}

fn stage_backoff_seconds(status: &str, attempt: i16) -> anyhow::Result<i64> {
    if attempt <= 0 {
        anyhow::bail!("managed repro retry attempt must be positive");
    }
    let base = match status {
        "queued" | "ready" => 1_i64,
        "preparing" | "launching" | "running" => 2_i64,
        _ => anyhow::bail!("managed repro retry has unsupported status {status}"),
    };
    let shift = u32::from(u16::try_from((attempt - 1).min(4))?);
    Ok((base * (1_i64 << shift)).min(30))
}

fn expect_one(rows: u64, action: &str) -> anyhow::Result<()> {
    if rows != 1 {
        anyhow::bail!("{action} affected {rows} rows; fenced claim was lost");
    }
    Ok(())
}

fn expect_at_most_one(rows: u64, action: &str) -> anyhow::Result<()> {
    if rows > 1 {
        anyhow::bail!("{action} affected {rows} rows");
    }
    Ok(())
}

fn target(job: &Job) -> Option<(&str, u16)> {
    let host = job.ssh_host.as_deref()?;
    let port = job.ssh_port?;
    valid_ssh_host(host).then_some((host, port))
}

fn valid_ssh_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

async fn run_ssh(
    private_key: &str,
    known_hosts: Option<&str>,
    host: &str,
    port: u16,
    script: &str,
) -> anyhow::Result<SshOutput> {
    if !valid_ssh_host(host) || port == 0 {
        anyhow::bail!("managed SSH target is invalid");
    }
    let directory = tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let private_key_path = directory.path().join("id_ed25519");
    let known_hosts_path = directory.path().join("known_hosts");
    fs::write(&private_key_path, private_key)?;
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
    fs::write(&known_hosts_path, known_hosts.unwrap_or_default())?;
    fs::set_permissions(&known_hosts_path, fs::Permissions::from_mode(0o600))?;

    let mut command = Command::new("ssh");
    command
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .args(["-F", "/dev/null", "-T", "-p", &port.to_string(), "-i"])
        .arg(&private_key_path)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "HashKnownHosts=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
        ])
        .arg(format!("UserKnownHostsFile={}", known_hosts_path.display()))
        .args(["-o"])
        .arg(if known_hosts.is_some() {
            "StrictHostKeyChecking=yes"
        } else {
            "StrictHostKeyChecking=accept-new"
        })
        .arg("--")
        .arg(format!("root@{host}"))
        .args(["/bin/sh", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("start managed SSH")?;
    let mut stdin = child.stdin.take().context("managed SSH has no stdin")?;
    stdin.write_all(script.as_bytes()).await?;
    stdin.shutdown().await?;

    let stdout = child.stdout.take().context("managed SSH has no stdout")?;
    let stderr = child.stderr.take().context("managed SSH has no stderr")?;
    let stdout_task = tokio::spawn(read_bounded(stdout));
    let stderr_task = tokio::spawn(read_bounded(stderr));
    let status =
        match tokio::time::timeout(Duration::from_secs(SSH_TIMEOUT_SECONDS), child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                let _ = child.kill().await;
                anyhow::bail!("managed SSH timed out");
            }
        };
    let stdout = stdout_task.await??;
    let stderr = stderr_task.await??;
    if stdout.len() as u64 > SSH_OUTPUT_LIMIT || stderr.len() as u64 > SSH_OUTPUT_LIMIT {
        anyhow::bail!("managed SSH response exceeded its limit");
    }
    if !status.success() {
        anyhow::bail!("managed SSH command exited unsuccessfully");
    }
    Ok(SshOutput {
        stdout,
        known_hosts: fs::read_to_string(&known_hosts_path)?,
    })
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(reader: R) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(SSH_OUTPUT_LIMIT + 1)
        .read_to_end(&mut output)
        .await?;
    Ok(output)
}

fn known_hosts_fingerprint(known_hosts: &str) -> anyhow::Result<String> {
    for line in known_hosts
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[0].starts_with('@') {
            continue;
        }
        let key = STANDARD
            .decode(fields[2])
            .context("decode managed SSH host key")?;
        if key.len() < 32 || key.len() > 16 * 1024 {
            anyhow::bail!("managed SSH host key is invalid");
        }
        return Ok(hex::encode(Sha256::digest(key)));
    }
    anyhow::bail!("managed SSH did not record a host key")
}

fn parse_gpu(output: &[u8]) -> anyhow::Result<(String, u32)> {
    let text = String::from_utf8_lossy(output);
    let model =
        marker(&text, "PRISM_GPU_NAME=").context("managed preflight returned no GPU name")?;
    let model = String::from_utf8(STANDARD.decode(model)?)?;
    let model = model.trim().to_owned();
    let vram = marker(&text, "PRISM_GPU_VRAM=")
        .context("managed preflight returned no GPU memory")?
        .trim()
        .parse::<u32>()?;
    if model.is_empty() || model.len() > 128 || vram == 0 || vram > MAX_GPU_VRAM_MIB {
        anyhow::bail!("managed preflight returned an invalid GPU")
    }
    Ok((model, vram))
}

fn parse_start_state(output: &[u8]) -> anyhow::Result<StartState> {
    let text = String::from_utf8_lossy(output);
    match single_marker(&text, "PRISM_STATUS=")? {
        "launching" => Ok(StartState::Launching),
        "started" => Ok(StartState::Started(parse_timestamp(single_marker(
            &text,
            "PRISM_STARTED_AT=",
        )?)?)),
        "done" => {
            let (started_at, finished_at, result) = parse_finished(&text)?;
            Ok(StartState::Finished {
                started_at,
                finished_at,
                result,
            })
        }
        "expired" => Ok(StartState::Expired),
        "drifted" => Ok(StartState::Drifted),
        _ => anyhow::bail!("managed launch status is invalid"),
    }
}

fn parse_remote_state(output: &[u8]) -> anyhow::Result<RemoteState> {
    let text = String::from_utf8_lossy(output);
    match single_marker(&text, "PRISM_STATUS=")? {
        "launching" => Ok(RemoteState::Launching),
        "running" => Ok(RemoteState::Running(parse_timestamp(single_marker(
            &text,
            "PRISM_STARTED_AT=",
        )?)?)),
        "missing" => Ok(RemoteState::Missing),
        "done" => {
            let (started_at, finished_at, result) = parse_finished(&text)?;
            Ok(RemoteState::Done {
                started_at,
                finished_at,
                result,
            })
        }
        _ => anyhow::bail!("managed result status is invalid"),
    }
}

fn parse_finished(text: &str) -> anyhow::Result<(DateTime<Utc>, DateTime<Utc>, CommandResult)> {
    let started_at = parse_timestamp(single_marker(text, "PRISM_STARTED_AT=")?)?;
    let finished_at = parse_timestamp(single_marker(text, "PRISM_FINISHED_AT=")?)?;
    let exit_code = single_marker(text, "PRISM_EXIT=")?.parse::<i32>()?;
    if !(0..=255).contains(&exit_code) {
        anyhow::bail!("managed result exit code is invalid");
    }
    let stdout = decode_stream(single_marker(text, "PRISM_STDOUT=")?)?;
    let stderr = decode_stream(single_marker(text, "PRISM_STDERR=")?)?;
    let stdout_bytes = single_marker(text, "PRISM_STDOUT_BYTES=")?.parse::<u64>()?;
    let stderr_bytes = single_marker(text, "PRISM_STDERR_BYTES=")?.parse::<u64>()?;
    if stdout_bytes < stdout.len() as u64 || stderr_bytes < stderr.len() as u64 {
        anyhow::bail!("managed result byte counts are invalid");
    }
    let mut result = CommandResult::capture(exit_code, &stdout, &stderr);
    result.truncated |= stdout_bytes > 64 * 1024 || stderr_bytes > 64 * 1024;
    Ok((started_at, finished_at, result))
}

fn parse_timestamp(value: &str) -> anyhow::Result<DateTime<Utc>> {
    if value.len() > 64 {
        anyhow::bail!("managed supervisor timestamp is too long");
    }
    Ok(DateTime::parse_from_rfc3339(value)
        .context("parse managed supervisor timestamp")?
        .with_timezone(&Utc))
}

fn decode_stream(encoded: &str) -> anyhow::Result<String> {
    let bytes = STANDARD.decode(encoded)?;
    if bytes.len() > 64 * 1024 {
        anyhow::bail!("managed result stream exceeded its limit");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn marker<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.strip_prefix(prefix))
}

fn single_marker<'a>(text: &'a str, prefix: &str) -> anyhow::Result<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values
        .next()
        .with_context(|| format!("managed response has no {prefix} marker"))?;
    if values.next().is_some() {
        anyhow::bail!("managed response repeats its {prefix} marker");
    }
    Ok(value)
}

fn start_script(
    command: &NodeCommand,
    max_run_seconds: u64,
    window_start: DateTime<Utc>,
    deadline: DateTime<Utc>,
    gpu_model: &str,
    gpu_vram_mib: u32,
) -> anyhow::Result<String> {
    let command_text = match &command.kind {
        prism_protocol::NodeCommandKind::Batch { command, .. } => command,
        _ => anyhow::bail!("managed repro command is not a batch"),
    };
    let command_base64 = STANDARD.encode(command_text.as_bytes());
    let command_sha256 = hex::encode(Sha256::digest(command_text.as_bytes()));
    let gpu_model_base64 = STANDARD.encode(gpu_model.as_bytes());
    let job = format!("/var/lib/prism-repro/{}", command.command_id);
    let work = format!("/var/tmp/prism-repro-work/{}", command.command_id);
    let command_id = command.command_id;
    let expires_ns = command
        .expires_at
        .timestamp_nanos_opt()
        .context("managed command expiry is outside nanosecond timestamp range")?;
    let window_start_ns = window_start
        .timestamp_nanos_opt()
        .context("managed access start is outside nanosecond timestamp range")?;
    let deadline_ns = deadline
        .timestamp_nanos_opt()
        .context("managed access deadline is outside nanosecond timestamp range")?;
    Ok(format!(
        r#"set -eu
umask 077
control_base='/var/lib/prism-repro'
work_base='/var/tmp/prism-repro-work'
job='{job}'
work='{work}'
install -d -m 0700 "$control_base"
install -d -m 0711 "$work_base"
lock="$control_base/.{command_id}.lock"
: > "$lock"
chmod 0600 "$lock"
exec 9>"$lock"
flock 9
if [ ! -d "$job" ]; then
  stage="$control_base/.{command_id}.prepare.$$"
  mkdir -m 0700 "$stage"
  rm -rf -- "$work"
  mkdir -m 0700 "$work"
  chown 65534:65534 "$work"
  mkdir -m 0700 "$work/tmp"
  chown 65534:65534 "$work/tmp"
  printf '%s' '{command_base64}' | base64 -d > "$stage/command"
  chmod 0400 "$stage/command"
  cat > "$stage/supervisor" <<'PRISM_SUPERVISOR'
#!/bin/sh
set -eu
umask 077
exec 9>&-
job='{job}'
work='{work}'
if [ ! -f "$job/launching" ] || [ -f "$job/started" ]; then
  exit 1
fi
started_tmp="$job/.started.$$"
date -u '+%Y-%m-%dT%H:%M:%S.%NZ' > "$started_tmp"
sync "$started_tmp"
mv "$started_tmp" "$job/started"
pid_tmp="$job/.pid.$$"
printf '%s\n' "$$" > "$pid_tmp"
mv "$pid_tmp" "$job/pid"
mkfifo "$job/stdout.raw" "$job/stdout.tail" "$job/stderr.raw" "$job/stderr.tail"
(tee "$job/stdout.tail" < "$job/stdout.raw" | wc -c > "$job/stdout.count.tmp" && mv "$job/stdout.count.tmp" "$job/stdout.count") &
stdout_count=$!
(tail -c 65536 < "$job/stdout.tail" > "$job/stdout.tmp" && mv "$job/stdout.tmp" "$job/stdout") &
stdout_tail=$!
(tee "$job/stderr.tail" < "$job/stderr.raw" | wc -c > "$job/stderr.count.tmp" && mv "$job/stderr.count.tmp" "$job/stderr.count") &
stderr_count=$!
(tail -c 65536 < "$job/stderr.tail" > "$job/stderr.tmp" && mv "$job/stderr.tmp" "$job/stderr") &
stderr_tail=$!
exec 3< "$job/command"
run_seconds="$(cat "$job/run_seconds")"
case "$run_seconds" in ''|*[!0-9]*) exit 1;; esac
[ "$run_seconds" -gt 0 ]
set +e
(cd "$work" && timeout --signal=TERM --kill-after=10s "${{run_seconds}}s" \
  env -i HOME="$work" TMPDIR="$work/tmp" PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' LC_ALL=C LANG=C \
  setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all /bin/sh /proc/self/fd/3) \
  > "$job/stdout.raw" 2> "$job/stderr.raw"
code=$?
set -e
wait "$stdout_count" "$stdout_tail" "$stderr_count" "$stderr_tail"
rm -f "$job/stdout.raw" "$job/stdout.tail" "$job/stderr.raw" "$job/stderr.tail"
printf '%s\n' "$code" > "$job/exit_code.tmp"
mv "$job/exit_code.tmp" "$job/exit_code"
finished_tmp="$job/.finished.$$"
date -u '+%Y-%m-%dT%H:%M:%S.%NZ' > "$finished_tmp"
sync "$job/stdout" "$job/stderr" "$job/stdout.count" "$job/stderr.count" "$job/exit_code" "$finished_tmp"
mv "$finished_tmp" "$job/finished"
sync "$job/finished"
PRISM_SUPERVISOR
  chmod 0700 "$stage/supervisor"
  date -u '+%Y-%m-%dT%H:%M:%S.%NZ' > "$stage/prepared.tmp"
  mv "$stage/prepared.tmp" "$stage/prepared"
  sync "$stage/command" "$stage/supervisor" "$stage/prepared"
  mv "$stage" "$job"
  sync "$control_base"
fi
actual_sha256="$(sha256sum "$job/command" | sed 's/[[:space:]].*$//')"
if [ "$actual_sha256" != '{command_sha256}' ]; then
  exit 1
fi
if [ -f "$job/finished" ]; then
  printf 'PRISM_STATUS=done\n'
  printf 'PRISM_STARTED_AT='; tr -d '[:space:]' < "$job/started"; printf '\n'
  printf 'PRISM_FINISHED_AT='; tr -d '[:space:]' < "$job/finished"; printf '\n'
  printf 'PRISM_EXIT='; tr -d '[:space:]' < "$job/exit_code"; printf '\n'
  printf 'PRISM_STDOUT='; base64 < "$job/stdout" | tr -d '\n'; printf '\n'
  printf 'PRISM_STDERR='; base64 < "$job/stderr" | tr -d '\n'; printf '\n'
  printf 'PRISM_STDOUT_BYTES='; tr -d '[:space:]' < "$job/stdout.count"; printf '\n'
  printf 'PRISM_STDERR_BYTES='; tr -d '[:space:]' < "$job/stderr.count"; printf '\n'
elif [ -f "$job/started" ]; then
  printf 'PRISM_STATUS=started\n'
  printf 'PRISM_STARTED_AT='; tr -d '[:space:]' < "$job/started"; printf '\n'
elif [ -f "$job/launching" ]; then
  printf 'PRISM_STATUS=launching\n'
else
  line="$(setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all env -i PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' LC_ALL=C nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits | head -n 1)"
  current_name="${{line%,*}}"
  current_vram="${{line##*,}}"
  current_name="$(printf '%s' "$current_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  current_name_base64="$(printf '%s' "$current_name" | base64 | tr -d '\n')"
  current_vram="$(printf '%s' "$current_vram" | tr -d '[:space:]')"
  if [ "$current_name_base64" != '{gpu_model_base64}' ] || [ "$current_vram" != '{gpu_vram_mib}' ]; then
    printf 'PRISM_STATUS=drifted\n'
    exit 0
  fi
  now_ns="$(date -u +%s%N)"
  case "$now_ns" in *[!0-9]*) exit 1;; esac
  if [ "$now_ns" -lt '{window_start_ns}' ] || [ "$now_ns" -ge '{deadline_ns}' ] || [ "$now_ns" -ge '{expires_ns}' ]; then
    printf 'PRISM_STATUS=expired\n'
    exit 0
  fi
  run_seconds=$((({deadline_ns} - now_ns) / 1000000000 - {EXECUTION_CLOSE_MARGIN_SECONDS}))
  if [ "$run_seconds" -gt '{max_run_seconds}' ]; then
    run_seconds='{max_run_seconds}'
  fi
  if [ "$run_seconds" -le 0 ]; then
    printf 'PRISM_STATUS=expired\n'
    exit 0
  fi
  run_seconds_tmp="$job/.run_seconds.$$"
  printf '%s\n' "$run_seconds" > "$run_seconds_tmp"
  sync "$run_seconds_tmp"
  mv "$run_seconds_tmp" "$job/run_seconds"
  sync "$job/run_seconds"
  launching_tmp="$job/.launching.$$"
  date -u '+%Y-%m-%dT%H:%M:%S.%NZ' > "$launching_tmp"
  sync "$launching_tmp"
  mv "$launching_tmp" "$job/launching"
  sync "$job/launching"
  nohup "$job/supervisor" > "$job/supervisor.log" 2>&1 </dev/null &
  printf 'PRISM_STATUS=launching\n'
fi
"#
    ))
}

fn poll_script(command_id: Uuid) -> String {
    let job = format!("/var/lib/prism-repro/{command_id}");
    format!(
        r#"set -eu
job='{job}'
if [ -f "$job/finished" ]; then
  printf 'PRISM_STATUS=done\n'
  printf 'PRISM_STARTED_AT='; tr -d '[:space:]' < "$job/started"; printf '\n'
  printf 'PRISM_FINISHED_AT='; tr -d '[:space:]' < "$job/finished"; printf '\n'
  printf 'PRISM_EXIT='; tr -d '[:space:]' < "$job/exit_code"; printf '\n'
  printf 'PRISM_STDOUT='; base64 < "$job/stdout" | tr -d '\n'; printf '\n'
  printf 'PRISM_STDERR='; base64 < "$job/stderr" | tr -d '\n'; printf '\n'
  printf 'PRISM_STDOUT_BYTES='; tr -d '[:space:]' < "$job/stdout.count"; printf '\n'
  printf 'PRISM_STDERR_BYTES='; tr -d '[:space:]' < "$job/stderr.count"; printf '\n'
elif [ -f "$job/started" ] && [ -f "$job/pid" ] && kill -0 "$(cat "$job/pid")" 2>/dev/null; then
  printf 'PRISM_STATUS=running\n'
  printf 'PRISM_STARTED_AT='; tr -d '[:space:]' < "$job/started"; printf '\n'
elif [ -f "$job/launching" ]; then
  printf 'PRISM_STATUS=launching\n'
else
  printf 'PRISM_STATUS=missing\n'
fi
"#
    )
}

const PREFLIGHT_SCRIPT: &str = r#"set -eu
for tool in base64 cat chmod chown date env flock head install mkdir mkfifo mv nohup nvidia-smi rm sed setpriv sha256sum sync tail tee timeout tr wc; do
  command -v "$tool" >/dev/null
done
test -x /bin/sh
line="$(setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all env -i PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' LC_ALL=C nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits | head -n 1)"
name="${line%,*}"
vram="${line##*,}"
name="$(printf '%s' "$name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
vram="$(printf '%s' "$vram" | tr -d '[:space:]')"
printf 'PRISM_GPU_NAME='; printf '%s' "$name" | base64 | tr -d '\n'; printf '\n'
printf 'PRISM_GPU_VRAM=%s\n' "$vram"
"#;

async fn verify_schema(pool: &PgPool) -> anyhow::Result<()> {
    let present: Option<String> =
        query_scalar("SELECT to_regclass('public.managed_repro_jobs')::text")
            .fetch_one(pool)
            .await?;
    if present.is_none() {
        anyhow::bail!("control-plane managed repro migration has not been applied");
    }
    Ok(())
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

async fn record_service_version(pool: &PgPool) -> anyhow::Result<()> {
    let version = prism_protocol::build_version();
    tracing::info!(service = "repro-worker", %version, "recording build version");
    query(prism_protocol::RECORD_SERVICE_VERSION_SQL)
        .bind("repro-worker")
        .bind(version)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use prism_protocol::NodeCommandKind;

    fn command(value: &str) -> NodeCommand {
        let issued_at = Utc::now();
        NodeCommand {
            command_id: Uuid::parse_str("018f62bb-fcc4-7e3d-9f3c-1a65ee60aa10").unwrap(),
            node_id: "aa".repeat(32),
            lease_id: 42,
            issued_at,
            expires_at: issued_at + Duration::minutes(10),
            kind: NodeCommandKind::Batch {
                image: format!("docker.io/library/test@sha256:{}", "11".repeat(32)),
                command: value.to_owned(),
                duration_seconds: 1_800,
            },
        }
    }

    #[test]
    fn remote_script_carries_the_command_as_data() {
        let raw = "python -c \"print('quoted $HOME')\"";
        let command = command(raw);
        let start = command.issued_at;
        let script = start_script(
            &command,
            60,
            start,
            start + Duration::minutes(5),
            "NVIDIA Test GPU",
            24_576,
        )
        .unwrap();
        assert!(!script.contains(raw));
        assert!(script.contains(&STANDARD.encode(raw)));
        assert!(script.contains("timeout --signal=TERM --kill-after=10s \"${run_seconds}s\""));
        assert!(script.contains("if [ \"$run_seconds\" -gt '60' ]; then"));
        assert!(script.contains("setpriv --reuid=65534 --regid=65534 --clear-groups"));
        assert!(script.contains("env -i HOME="));
        assert!(script.contains("/var/lib/prism-repro/"));
        assert!(script.contains("/var/tmp/prism-repro-work/"));
        assert!(script.contains("exec 3< \"$job/command\""));
        assert!(!script.contains("/bin/sh \"$job/command\""));

        let mut child = std::process::Command::new("/bin/sh")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn remote_script_records_atomic_at_most_once_states() {
        let command = command("nvidia-smi");
        let start = command.issued_at;
        let script = start_script(
            &command,
            60,
            start,
            start + Duration::minutes(5),
            "NVIDIA Test GPU",
            24_576,
        )
        .unwrap();
        let launching = script
            .find("mv \"$launching_tmp\" \"$job/launching\"")
            .unwrap();
        let launch = script.find("nohup \"$job/supervisor\"").unwrap();
        let finished = script
            .find("mv \"$finished_tmp\" \"$job/finished\"")
            .unwrap();
        assert!(launching < launch);
        assert!(script.contains("elif [ -f \"$job/launching\" ]; then"));
        assert!(script.contains("if [ ! -f \"$job/launching\" ] || [ -f \"$job/started\" ]"));
        assert!(finished < script.find("sync \"$job/finished\"").unwrap());
        assert!(script.contains("actual_sha256=\"$(sha256sum \"$job/command\""));
    }

    #[test]
    fn parses_a_bounded_remote_result() {
        let output = format!(
            "PRISM_STATUS=done\nPRISM_STARTED_AT=2026-08-30T10:00:00.123456789Z\nPRISM_FINISHED_AT=2026-08-30T10:00:02.987654321Z\nPRISM_EXIT=7\nPRISM_STDOUT={}\nPRISM_STDERR={}\nPRISM_STDOUT_BYTES=2\nPRISM_STDERR_BYTES=4\n",
            STANDARD.encode("ok"),
            STANDARD.encode("nope")
        );
        let RemoteState::Done {
            started_at,
            finished_at,
            result,
        } = parse_remote_state(output.as_bytes()).unwrap()
        else {
            panic!("not done");
        };
        assert_eq!(
            started_at.to_rfc3339(),
            "2026-08-30T10:00:00.123456789+00:00"
        );
        assert_eq!(
            finished_at.to_rfc3339(),
            "2026-08-30T10:00:02.987654321+00:00"
        );
        assert_eq!(result.exit_code, 7);
        assert_eq!(result.stdout, "ok");
        assert_eq!(result.stderr, "nope");
        assert!(!result.truncated);
    }

    #[test]
    fn preserves_the_remote_truncation_fact() {
        let output = format!(
            "PRISM_STATUS=done\nPRISM_STARTED_AT=2026-08-30T10:00:00Z\nPRISM_FINISHED_AT=2026-08-30T10:00:02Z\nPRISM_EXIT=0\nPRISM_STDOUT={}\nPRISM_STDERR=\nPRISM_STDOUT_BYTES=65537\nPRISM_STDERR_BYTES=0\n",
            STANDARD.encode("tail")
        );
        let RemoteState::Done { result, .. } = parse_remote_state(output.as_bytes()).unwrap()
        else {
            panic!("not done");
        };
        assert!(result.truncated);
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_supervisor_results() {
        let duplicate =
            b"PRISM_STATUS=running\nPRISM_STATUS=done\nPRISM_STARTED_AT=2026-08-30T10:00:00Z\n";
        assert!(parse_remote_state(duplicate).is_err());

        let missing_finish = b"PRISM_STATUS=done\nPRISM_STARTED_AT=2026-08-30T10:00:00Z\nPRISM_EXIT=0\nPRISM_STDOUT=\nPRISM_STDERR=\nPRISM_STDOUT_BYTES=0\nPRISM_STDERR_BYTES=0\n";
        assert!(parse_remote_state(missing_finish).is_err());

        let forged_count = b"PRISM_STATUS=done\nPRISM_STARTED_AT=2026-08-30T10:00:00Z\nPRISM_FINISHED_AT=2026-08-30T10:00:01Z\nPRISM_EXIT=0\nPRISM_STDOUT=b2s=\nPRISM_STDERR=\nPRISM_STDOUT_BYTES=1\nPRISM_STDERR_BYTES=0\n";
        assert!(parse_remote_state(forged_count).is_err());
    }

    #[test]
    fn parses_launch_state_and_expiry() {
        assert_eq!(
            parse_start_state(b"PRISM_STATUS=launching\n").unwrap(),
            StartState::Launching
        );
        assert_eq!(
            parse_start_state(b"PRISM_STATUS=expired\n").unwrap(),
            StartState::Expired
        );
        assert_eq!(
            parse_start_state(b"PRISM_STATUS=drifted\n").unwrap(),
            StartState::Drifted
        );
        assert!(matches!(
            parse_start_state(b"PRISM_STATUS=started\nPRISM_STARTED_AT=2026-08-30T10:00:00.1Z\n")
                .unwrap(),
            StartState::Started(_)
        ));
    }

    #[test]
    fn fingerprints_the_key_blob_not_the_provider_hostname() {
        let key = vec![9_u8; 51];
        let line = format!(
            "[ssh1.example]:1234 ssh-ed25519 {}\n",
            STANDARD.encode(&key)
        );
        assert_eq!(
            known_hosts_fingerprint(&line).unwrap(),
            hex::encode(Sha256::digest(key))
        );
    }

    #[test]
    fn parses_gpu_preflight_markers() {
        let output = format!(
            "banner\nPRISM_GPU_NAME={}\nPRISM_GPU_VRAM=49140\n",
            STANDARD.encode("NVIDIA RTX 6000 Ada")
        );
        assert_eq!(
            parse_gpu(output.as_bytes()).unwrap(),
            ("NVIDIA RTX 6000 Ada".to_owned(), 49_140)
        );
    }

    #[test]
    fn rejects_gpu_memory_above_the_protocol_limit() {
        let output = format!(
            "PRISM_GPU_NAME={}\nPRISM_GPU_VRAM={}\n",
            STANDARD.encode("Impossible GPU"),
            MAX_GPU_VRAM_MIB + 1
        );
        assert!(parse_gpu(output.as_bytes()).is_err());
    }

    #[test]
    fn rejects_an_ssh_option_as_a_host() {
        assert!(!valid_ssh_host("-oProxyCommand=sh"));
        assert!(!valid_ssh_host("host;curl.example"));
        assert!(valid_ssh_host("ssh7.vast.ai"));
        assert!(valid_ssh_host("203.0.113.10"));
    }

    #[test]
    fn retries_are_stage_bounded_and_back_off() {
        assert_eq!(stage_attempt_cap("queued").unwrap(), 5);
        assert_eq!(stage_attempt_cap("preparing").unwrap(), 30);
        assert_eq!(stage_attempt_cap("ready").unwrap(), 12);
        assert_eq!(stage_attempt_cap("launching").unwrap(), 20);
        assert_eq!(stage_attempt_cap("running").unwrap(), 120);
        assert_eq!(stage_backoff_seconds("preparing", 1).unwrap(), 2);
        assert_eq!(stage_backoff_seconds("preparing", 5).unwrap(), 30);
        assert_eq!(stage_backoff_seconds("running", 100).unwrap(), 30);
    }

    #[test]
    fn migration_requires_fenced_claims_and_bound_preflight() {
        const MIGRATION: &str =
            include_str!("../../../services/control-plane/migrations/0022_managed_repros.sql");
        assert!(MIGRATION.contains("claim_token UUID"));
        assert!(MIGRATION.contains("claim_generation BIGINT NOT NULL DEFAULT 0"));
        assert!(MIGRATION.contains("(claim_token IS NULL) = (lease_until IS NULL)"));
        assert!(MIGRATION.contains("prepared_provider_instance_id BIGINT"));
        assert!(MIGRATION.contains("gpu_vram_mib BETWEEN 1 AND 196608"));
        assert!(MIGRATION.contains("status NOT IN ('ready', 'launching', 'running', 'completed')"));
        assert!(MIGRATION.contains("status <> 'running' OR started_at IS NOT NULL"));
    }
}
