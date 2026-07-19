use std::{collections::HashMap, env, fs, net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use prism_protocol::AccessGrant;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, watch};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod tunnel;

type HmacSha256 = Hmac<Sha256>;
type RelaySenders = HashMap<Uuid, HashMap<Uuid, watch::Sender<bool>>>;

#[derive(Clone)]
struct GatewayState {
    signing_key: Arc<Vec<u8>>,
    control_token: Arc<String>,
    grants: GrantStore,
    active_relays: ActiveRelays,
    tunnels: tunnel::TunnelPool,
}

#[derive(Clone)]
enum GrantStore {
    Memory(Arc<RwLock<HashMap<Uuid, AccessGrant>>>),
    Redis(Arc<redis::Client>),
}

#[derive(Clone, Default)]
struct ActiveRelays {
    inner: Arc<RwLock<RelaySenders>>,
}

#[derive(Deserialize)]
struct GrantRequest {
    token_id: Uuid,
    lease_id: String,
    node_id: String,
    connection_id: String,
    ttl_seconds: u32,
}

#[derive(Deserialize)]
struct ProbeRequest {
    node_id: String,
    connection_id: String,
}

#[derive(Serialize)]
struct GrantResponse {
    token: String,
    grant: AccessGrant,
}

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    version: u8,
    token_id: Uuid,
    issued_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();
    let signing_key = hex::decode(required_env("PRISM_GATEWAY_HMAC_KEY")?)?;
    if signing_key.len() < 32 {
        anyhow::bail!("PRISM_GATEWAY_HMAC_KEY must be at least 32 bytes of hex");
    }
    let control_token = required_env("PRISM_GATEWAY_CONTROL_TOKEN")?;
    if control_token.len() < 32 || control_token.len() > 512 {
        anyhow::bail!("PRISM_GATEWAY_CONTROL_TOKEN must contain 32 to 512 bytes");
    }
    let state = GatewayState {
        signing_key: Arc::new(signing_key),
        control_token: Arc::new(control_token),
        grants: GrantStore::from_environment().await?,
        active_relays: ActiveRelays::default(),
        tunnels: tunnel::TunnelPool::default(),
    };
    let tunnel = tunnel::TunnelService::from_environment(state.clone())?;
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/grants", post(issue_grant))
        .route("/v1/grants/{token_id}", delete(revoke_grant))
        .route("/v1/probes", post(probe_workspace))
        .route("/v1/access", get(validate_grant))
        .with_state(state)
        .layer(DefaultBodyLimit::max(16 * 1_024))
        .layer(TraceLayer::new_for_http());
    let address: SocketAddr = env::var("PRISM_GATEWAY_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "access gateway listening");
    let http = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());
    if let Some(tunnel) = tunnel {
        tokio::select! {
            result = http => result?,
            result = tunnel.run() => result?,
        }
    } else {
        http.await?;
    }
    Ok(())
}

async fn health(State(state): State<GatewayState>) -> StatusCode {
    match state.grants.check_health().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(error) => {
            tracing::error!(%error, "gateway grant store health check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

async fn issue_grant(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<GrantRequest>,
) -> Result<Json<GrantResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_control_token(&state, &headers)?;
    if !valid_identifier(&request.lease_id, 128)
        || !valid_node_id(&request.node_id)
        || !valid_identifier(&request.connection_id, 128)
        || !(60..=3_600).contains(&request.ttl_seconds)
    {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_grant"));
    }
    let now = Utc::now();
    let grant = AccessGrant {
        token_id: request.token_id,
        lease_id: request.lease_id,
        node_id: request.node_id,
        connection_id: request.connection_id,
        ssh_user: "workspace".to_owned(),
        jupyter_path: "/lab".to_owned(),
        issued_at: now,
        expires_at: now + Duration::seconds(i64::from(request.ttl_seconds)),
    };
    let requested = grant.clone();
    let grant = state
        .grants
        .activate(&grant)
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "grant_store_unavailable"))?;
    if grant.lease_id != requested.lease_id
        || grant.node_id != requested.node_id
        || grant.connection_id != requested.connection_id
    {
        return Err(error(StatusCode::CONFLICT, "grant_id_conflict"));
    }
    let token = sign(
        &TokenClaims {
            version: 1,
            token_id: grant.token_id,
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
        },
        &state.signing_key,
    )
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "signing_failed"))?;
    Ok(Json(GrantResponse { token, grant }))
}

async fn probe_workspace(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<ProbeRequest>,
) -> Result<Json<tunnel::ProbeResult>, (StatusCode, Json<ErrorResponse>)> {
    require_control_token(&state, &headers)?;
    if !valid_node_id(&request.node_id) || !valid_identifier(&request.connection_id, 128) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_probe"));
    }
    tunnel::probe_workspace(&state.tunnels, &request.node_id, &request.connection_id)
        .await
        .map(Json)
        .map_err(|error_value| {
            tracing::warn!(error = %error_value, "workspace readiness probe failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "workspace_not_ready")
        })
}

async fn validate_grant(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Result<Json<AccessGrant>, (StatusCode, Json<ErrorResponse>)> {
    let token = bearer_token(&headers)
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "invalid_access_token"))?;
    state.resolve_grant(&token).await.map(Json)
}

impl GatewayState {
    async fn resolve_grant(
        &self,
        token: &str,
    ) -> Result<AccessGrant, (StatusCode, Json<ErrorResponse>)> {
        let claims = verify(token, &self.signing_key)
            .map_err(|_| error(StatusCode::UNAUTHORIZED, "invalid_access_token"))?;
        let now = Utc::now();
        if claims.version != 1
            || claims.issued_at > now + Duration::seconds(5)
            || claims.expires_at <= now
            || claims.expires_at > claims.issued_at + Duration::hours(1)
        {
            return Err(error(StatusCode::UNAUTHORIZED, "expired_access_token"));
        }
        let Some(grant) = self
            .grants
            .get(claims.token_id)
            .await
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "grant_store_unavailable"))?
        else {
            return Err(error(StatusCode::UNAUTHORIZED, "revoked_access_token"));
        };
        if grant.issued_at != claims.issued_at || grant.expires_at != claims.expires_at {
            return Err(error(StatusCode::UNAUTHORIZED, "invalid_access_token"));
        }
        Ok(grant)
    }
}

async fn revoke_grant(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Path(token_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_control_token(&state, &headers)?;
    state.active_relays.revoke(token_id).await;
    state
        .grants
        .revoke(token_id)
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "grant_store_unavailable"))?;
    Ok(StatusCode::NO_CONTENT)
}

fn sign(claims: &TokenClaims, key: &[u8]) -> anyhow::Result<String> {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(payload.as_bytes());
    Ok(format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn verify(token: &str, key: &[u8]) -> anyhow::Result<TokenClaims> {
    if token.len() > 2_048 {
        anyhow::bail!("token is too large");
    }
    let (payload, signature) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid token"))?;
    let signature = URL_SAFE_NO_PAD.decode(signature)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

fn require_control_token(
    state: &GatewayState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if provided.is_some_and(|token| constant_time_eq(token, state.control_token.as_str())) {
        Ok(())
    } else {
        Err(error(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

impl GrantStore {
    async fn from_environment() -> anyhow::Result<Self> {
        let redis_url = env::var("PRISM_REDIS_URL")
            .ok()
            .filter(|value| !value.is_empty());
        match redis_url {
            Some(url) => {
                if !url.starts_with("rediss://") {
                    anyhow::bail!(
                        "PRISM_REDIS_URL must use rediss:// for encrypted Redis transport"
                    );
                }
                let client = match env::var("PRISM_REDIS_CA_FILE")
                    .ok()
                    .filter(|path| !path.is_empty())
                {
                    Some(path) => redis::Client::build_with_tls(
                        url,
                        redis::TlsCertificates {
                            client_tls: None,
                            root_cert: Some(fs::read(path)?),
                        },
                    )?,
                    None => redis::Client::open(url)?,
                };
                let mut connection = client.get_multiplexed_async_connection().await?;
                let _: String = redis::cmd("PING").query_async(&mut connection).await?;
                Ok(Self::Redis(Arc::new(client)))
            }
            None if env::var("PRISM_ALLOW_DEVELOPMENT_GRANT_STORE").as_deref() == Ok("1") => {
                tracing::warn!("using the development-only in-memory grant store");
                Ok(Self::Memory(Arc::new(RwLock::new(HashMap::new()))))
            }
            None => anyhow::bail!(
                "PRISM_REDIS_URL is required outside development; set PRISM_ALLOW_DEVELOPMENT_GRANT_STORE=1 only for local work"
            ),
        }
    }

    async fn activate(&self, grant: &AccessGrant) -> anyhow::Result<AccessGrant> {
        match self {
            Self::Memory(grants) => {
                let mut grants = grants.write().await;
                let current = grants
                    .entry(grant.token_id)
                    .or_insert_with(|| grant.clone())
                    .clone();
                Ok(current)
            }
            Self::Redis(client) => {
                let ttl = (grant.expires_at - Utc::now()).num_seconds().max(1) as u64;
                let mut connection = client.get_multiplexed_async_connection().await?;
                let inserted: Option<String> = redis::cmd("SET")
                    .arg(grant_key(grant.token_id))
                    .arg(serde_json::to_string(grant)?)
                    .arg("NX")
                    .arg("EX")
                    .arg(ttl)
                    .query_async(&mut connection)
                    .await?;
                if inserted.is_some() {
                    return Ok(grant.clone());
                }
                self.get(grant.token_id)
                    .await?
                    .context("existing grant expired during idempotent issue")
            }
        }
    }

    async fn get(&self, token_id: Uuid) -> anyhow::Result<Option<AccessGrant>> {
        match self {
            Self::Memory(grants) => {
                let mut grants = grants.write().await;
                grants.retain(|_, current| current.expires_at > Utc::now());
                Ok(grants.get(&token_id).cloned())
            }
            Self::Redis(client) => {
                let mut connection = client.get_multiplexed_async_connection().await?;
                let stored: Option<String> = connection.get(grant_key(token_id)).await?;
                stored
                    .map(|value| serde_json::from_str::<AccessGrant>(&value))
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    async fn check_health(&self) -> anyhow::Result<()> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Redis(client) => {
                let mut connection = client.get_multiplexed_async_connection().await?;
                let response: String = redis::cmd("PING").query_async(&mut connection).await?;
                anyhow::ensure!(response == "PONG", "unexpected Redis PING response");
                Ok(())
            }
        }
    }

    async fn revoke(&self, token_id: Uuid) -> anyhow::Result<()> {
        match self {
            Self::Memory(grants) => {
                grants.write().await.remove(&token_id);
                Ok(())
            }
            Self::Redis(client) => {
                let mut connection = client.get_multiplexed_async_connection().await?;
                let _: usize = connection.del(grant_key(token_id)).await?;
                Ok(())
            }
        }
    }
}

impl ActiveRelays {
    async fn register(&self, token_id: Uuid) -> (Uuid, watch::Receiver<bool>) {
        let relay_id = Uuid::now_v7();
        let (sender, receiver) = watch::channel(false);
        self.inner
            .write()
            .await
            .entry(token_id)
            .or_default()
            .insert(relay_id, sender);
        (relay_id, receiver)
    }

    async fn unregister(&self, token_id: Uuid, relay_id: Uuid) {
        let mut relays = self.inner.write().await;
        let Some(active) = relays.get_mut(&token_id) else {
            return;
        };
        active.remove(&relay_id);
        if active.is_empty() {
            relays.remove(&token_id);
        }
    }

    async fn revoke(&self, token_id: Uuid) {
        let active = self.inner.write().await.remove(&token_id);
        for sender in active.into_iter().flat_map(HashMap::into_values) {
            let _ = sender.send(true);
        }
    }
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
}

fn valid_node_id(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn grant_key(token_id: Uuid) -> String {
    format!("prism:grant:{token_id}")
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("{key} is required"))
}

fn error(status: StatusCode, code: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { code }))
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> AccessGrant {
        AccessGrant {
            token_id: Uuid::now_v7(),
            lease_id: "lease-1".to_owned(),
            node_id: "node-1".to_owned(),
            connection_id: "connection-1".to_owned(),
            ssh_user: "workspace".to_owned(),
            jupyter_path: "/lab".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    #[tokio::test]
    async fn grant_store_rejects_revoked_tokens() {
        let store = GrantStore::Memory(Arc::new(RwLock::new(HashMap::new())));
        let grant = grant();

        store.activate(&grant).await.unwrap();
        assert_eq!(
            store.get(grant.token_id).await.unwrap(),
            Some(grant.clone())
        );
        store.revoke(grant.token_id).await.unwrap();
        assert_eq!(store.get(grant.token_id).await.unwrap(), None);
    }

    #[test]
    fn signed_grant_cannot_be_tampered_with() {
        let key = vec![7; 32];
        let grant = grant();
        let claims = TokenClaims {
            version: 1,
            token_id: grant.token_id,
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
        };
        let token = sign(&claims, &key).unwrap();
        let mut decoded = verify(&token, &key).unwrap();
        decoded.token_id = Uuid::now_v7();

        assert_ne!(sign(&decoded, &key).unwrap(), token);
    }

    #[test]
    fn validates_grant_boundaries() {
        assert!(valid_identifier("lease_01", 128));
        assert!(!valid_identifier("../lease", 128));
        assert!(valid_node_id(&format!("0x{}", "a".repeat(64))));
        assert!(!valid_node_id("node-1"));
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "different"));
    }

    #[tokio::test]
    async fn revocation_notifies_every_active_relay() {
        let relays = ActiveRelays::default();
        let token_id = Uuid::now_v7();
        let (_, mut first) = relays.register(token_id).await;
        let (_, mut second) = relays.register(token_id).await;

        relays.revoke(token_id).await;
        first.changed().await.unwrap();
        second.changed().await.unwrap();
        assert!(*first.borrow());
        assert!(*second.borrow());
    }
}
