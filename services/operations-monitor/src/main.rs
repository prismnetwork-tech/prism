use std::{env, fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use sqlx_core::{query_as::query_as, query_scalar::query_scalar};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    database_url: Arc<String>,
}

#[derive(Default)]
struct Snapshot {
    active_leases: i64,
    fresh_tunnels: i64,
    stale_tunnels: i64,
    certificates_expiring: i64,
    operator_actions_24h: i64,
    last_receipt_age_seconds: f64,
    queues: Vec<QueueMetric>,
}

struct QueueMetric {
    queue: &'static str,
    status: String,
    count: i64,
    oldest_age_seconds: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let pool = connect(&database_url)
        .await
        .context("connect operations monitor database")?;
    pool.close().await;
    let state = AppState {
        database_url: Arc::new(database_url),
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
        .layer(TraceLayer::new_for_http());
    let address: SocketAddr = env::var("PRISM_OPERATIONS_MONITOR_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9091".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "operations monitor listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> StatusCode {
    match tokio::time::timeout(Duration::from_secs(2), connect(&state.database_url)).await {
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
            tracing::error!(%error, "operations monitor database health check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

async fn metrics(State(state): State<AppState>) -> Response {
    let pool =
        match tokio::time::timeout(Duration::from_secs(2), connect(&state.database_url)).await {
            Ok(Ok(pool)) => pool,
            result => {
                let error = match result {
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "metrics database connection timed out".to_owned(),
                    Ok(Ok(_)) => unreachable!(),
                };
                tracing::error!(%error, "operations metrics connection failed");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        };
    let response = match tokio::time::timeout(Duration::from_secs(5), load_snapshot(&pool)).await {
        Ok(Ok(snapshot)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            render_metrics(&snapshot),
        )
            .into_response(),
        result => {
            let error = match result {
                Ok(Err(error)) => error.to_string(),
                Err(_) => "metrics query timed out".to_owned(),
                Ok(Ok(_)) => unreachable!(),
            };
            tracing::error!(%error, "operations metrics query failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    pool.close().await;
    response
}

async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(2))
        .connect(database_url)
        .await
        .context("connect PostgreSQL")
}

async fn load_snapshot(pool: &PgPool) -> anyhow::Result<Snapshot> {
    let active_leases = query_scalar(
        "SELECT COUNT(*)::bigint FROM leases \
         WHERE state NOT IN ('finalized', 'refunded', 'failed')",
    )
    .fetch_one(pool)
    .await?;
    let fresh_tunnels = query_scalar(
        "SELECT COUNT(*)::bigint FROM node_tunnels \
         WHERE observed_at >= NOW() - INTERVAL '90 seconds'",
    )
    .fetch_one(pool)
    .await?;
    let stale_tunnels = query_scalar(
        "SELECT COUNT(*)::bigint FROM node_tunnels \
         WHERE observed_at < NOW() - INTERVAL '90 seconds'",
    )
    .fetch_one(pool)
    .await?;
    let certificates_expiring = query_scalar(
        "SELECT COUNT(*)::bigint FROM node_certificates \
         WHERE status = 'active' AND not_after <= NOW() + INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await?;
    let operator_actions_24h = query_scalar(
        "SELECT COUNT(*)::bigint FROM operator_audit_events \
         WHERE created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await?;
    let last_receipt_age_seconds = query_scalar::<_, f64>(
        "SELECT COALESCE(EXTRACT(EPOCH FROM NOW() - MAX(created_at)), 0)::float8 \
         FROM proof_receipts",
    )
    .fetch_one(pool)
    .await?;
    let mut queues = Vec::new();
    queues.extend(
        queue_metrics(
            pool,
            "lifecycle",
            "SELECT status, COUNT(*)::bigint, \
                COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at)), 0)::float8 \
         FROM lifecycle_outbox \
         WHERE status IN ('queued', 'processing', 'submitted', 'failed') \
         GROUP BY status",
        )
        .await?,
    );
    queues.extend(
        queue_metrics(
            pool,
            "settlement",
            "SELECT status, COUNT(*)::bigint, \
                COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at)), 0)::float8 \
         FROM settlement_jobs \
         WHERE status IN ('queued', 'processing', 'submitted', 'disputed', 'failed') \
         GROUP BY status",
        )
        .await?,
    );
    queues.extend(
        queue_metrics(
            pool,
            "proof_digest",
            "SELECT status, COUNT(*)::bigint, \
                COALESCE(EXTRACT(EPOCH FROM NOW() - MIN(created_at)), 0)::float8 \
         FROM proof_digest_outbox \
         WHERE status IN ('queued', 'processing', 'failed') \
         GROUP BY status",
        )
        .await?,
    );
    Ok(Snapshot {
        active_leases,
        fresh_tunnels,
        stale_tunnels,
        certificates_expiring,
        operator_actions_24h,
        last_receipt_age_seconds,
        queues,
    })
}

async fn queue_metrics(
    pool: &PgPool,
    queue: &'static str,
    statement: &str,
) -> anyhow::Result<Vec<QueueMetric>> {
    let rows = query_as::<_, (String, i64, f64)>(statement)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(status, count, oldest_age_seconds)| QueueMetric {
            queue,
            status,
            count,
            oldest_age_seconds,
        })
        .collect())
}

fn render_metrics(snapshot: &Snapshot) -> String {
    let mut output = String::with_capacity(2_048);
    metric(
        &mut output,
        "prism_active_leases",
        "Current non-terminal leases.",
        snapshot.active_leases,
    );
    metric(
        &mut output,
        "prism_fresh_node_tunnels",
        "Node tunnels observed in the scheduling window.",
        snapshot.fresh_tunnels,
    );
    metric(
        &mut output,
        "prism_stale_node_tunnels",
        "Node tunnels outside the scheduling window.",
        snapshot.stale_tunnels,
    );
    metric(
        &mut output,
        "prism_node_certificates_expiring_24h",
        "Active node certificates expiring within 24 hours.",
        snapshot.certificates_expiring,
    );
    metric(
        &mut output,
        "prism_operator_actions_24h",
        "Privileged operator actions recorded in the last 24 hours.",
        snapshot.operator_actions_24h,
    );
    let _ = writeln!(
        output,
        "# HELP prism_last_receipt_age_seconds Seconds since the most recent proof receipt.\n\
         # TYPE prism_last_receipt_age_seconds gauge\n\
         prism_last_receipt_age_seconds {}",
        snapshot.last_receipt_age_seconds.max(0.0)
    );
    output.push_str(
        "# HELP prism_queue_jobs Jobs in a non-terminal queue state.\n\
         # TYPE prism_queue_jobs gauge\n\
         # HELP prism_queue_oldest_age_seconds Age of the oldest job in a non-terminal queue state.\n\
         # TYPE prism_queue_oldest_age_seconds gauge\n",
    );
    for queue in &snapshot.queues {
        if !valid_label(&queue.status) {
            continue;
        }
        let _ = writeln!(
            output,
            "prism_queue_jobs{{queue=\"{}\",status=\"{}\"}} {}",
            queue.queue,
            queue.status,
            queue.count.max(0)
        );
        let _ = writeln!(
            output,
            "prism_queue_oldest_age_seconds{{queue=\"{}\",status=\"{}\"}} {}",
            queue.queue,
            queue.status,
            queue.oldest_age_seconds.max(0.0)
        );
    }
    output
}

fn metric(output: &mut String, name: &str, help: &str, value: i64) {
    let _ = writeln!(
        output,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}",
        value.max(0)
    );
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_only_safe_labels() {
        let snapshot = Snapshot {
            active_leases: 4,
            queues: vec![
                QueueMetric {
                    queue: "settlement",
                    status: "failed".to_owned(),
                    count: 2,
                    oldest_age_seconds: 42.0,
                },
                QueueMetric {
                    queue: "settlement",
                    status: "bad\"label".to_owned(),
                    count: 99,
                    oldest_age_seconds: 99.0,
                },
            ],
            ..Snapshot::default()
        };
        let metrics = render_metrics(&snapshot);
        assert!(metrics.contains("prism_active_leases 4"));
        assert!(metrics.contains("queue=\"settlement\",status=\"failed\""));
        assert!(!metrics.contains("bad\"label"));
    }
}
