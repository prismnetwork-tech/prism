use std::{
    collections::{HashMap, VecDeque},
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use prism_protocol::{TunnelRegistration, node_id, verifying_key};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, watch},
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::{GatewayState, valid_identifier, valid_node_id};

const MAX_FRAME_BYTES: usize = 16 * 1_024;
const MAX_IDLE_TUNNELS: usize = 1_024;
const MAX_IDLE_TUNNELS_PER_CONNECTION: usize = 64;
const TUNNEL_MAX_AGE: Duration = Duration::from_secs(90);

pub struct TunnelService {
    state: GatewayState,
    node_address: String,
    relay_address: String,
    node_acceptor: TlsAcceptor,
    relay_acceptor: TlsAcceptor,
    observer: Option<GatewayObserver>,
}

#[derive(Clone, Default)]
pub(crate) struct TunnelPool {
    inner: Arc<Mutex<HashMap<TunnelKey, VecDeque<IdleTunnel>>>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TunnelKey {
    node_id: String,
    connection_id: String,
}

#[derive(Clone)]
struct GatewayObserver {
    client: reqwest::Client,
    base_url: url::Url,
    token: String,
}

#[derive(Serialize)]
struct TunnelObservation<'a> {
    connection_id: &'a str,
    certificate_fingerprint: &'a str,
    observed_at: chrono::DateTime<chrono::Utc>,
}

struct IdleTunnel {
    inserted_at: Instant,
    certificate_fingerprint: String,
    stream: TlsStream<TcpStream>,
}

struct TunnelIdentity {
    key: TunnelKey,
    certificate_fingerprint: String,
}

enum ObservationStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Deserialize)]
struct RelayRequest {
    token: String,
    service: RelayService,
}

#[derive(Debug, Serialize)]
struct RelayOpen {
    service: RelayService,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayReady {
    ready: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayService {
    Ssh,
    Jupyter,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProbeResult {
    pub node_id: String,
    pub connection_id: String,
    pub cuda_ready_at: chrono::DateTime<chrono::Utc>,
    pub interactive_access_ready_at: chrono::DateTime<chrono::Utc>,
}

impl TunnelService {
    pub fn from_environment(state: GatewayState) -> anyhow::Result<Option<Self>> {
        if env::var("PRISM_ENABLE_TUNNEL").as_deref() != Ok("1") {
            tracing::warn!("access tunnel is disabled");
            return Ok(None);
        }
        let certificate = PathBuf::from(required_env("PRISM_TUNNEL_SERVER_CERTIFICATE")?);
        let private_key = PathBuf::from(required_env("PRISM_TUNNEL_SERVER_KEY")?);
        let client_ca = PathBuf::from(required_env("PRISM_TUNNEL_CLIENT_CA")?);
        let node_acceptor = mutual_tls_acceptor(&certificate, &private_key, &client_ca)?;
        let relay_acceptor = server_tls_acceptor(&certificate, &private_key)?;
        let observer = GatewayObserver::from_environment()?;
        Ok(Some(Self {
            state,
            node_address: env::var("PRISM_TUNNEL_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:7443".to_owned()),
            relay_address: env::var("PRISM_RELAY_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:7444".to_owned()),
            node_acceptor,
            relay_acceptor,
            observer,
        }))
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let node_listener = TcpListener::bind(&self.node_address)
            .await
            .with_context(|| format!("bind node tunnel listener {}", self.node_address))?;
        let relay_listener = TcpListener::bind(&self.relay_address)
            .await
            .with_context(|| format!("bind access relay listener {}", self.relay_address))?;
        tracing::info!(
            node_address = %self.node_address,
            relay_address = %self.relay_address,
            "mTLS node tunnel and TLS access relay listening"
        );
        let state = Arc::new(self);
        if state.observer.is_some() {
            tokio::try_join!(
                accept_nodes(node_listener, state.clone()),
                accept_relays(relay_listener, state.clone()),
                refresh_observations(state),
            )?;
        } else {
            tokio::try_join!(
                accept_nodes(node_listener, state.clone()),
                accept_relays(relay_listener, state),
            )?;
        }
        Ok(())
    }
}

async fn accept_nodes(listener: TcpListener, service: Arc<TunnelService>) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(error) = register_tunnel(stream, &service).await {
                tracing::warn!(%peer, %error, "node tunnel registration failed");
            }
        });
    }
}

async fn accept_relays(listener: TcpListener, service: Arc<TunnelService>) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(error) = relay(stream, &service).await {
                tracing::warn!(%peer, %error, "access relay failed");
            }
        });
    }
}

async fn register_tunnel(stream: TcpStream, service: &TunnelService) -> anyhow::Result<()> {
    let mut stream = timeout(
        Duration::from_secs(10),
        service.node_acceptor.accept(stream),
    )
    .await
    .context("node mTLS handshake timed out")??;
    let certificate_fingerprint = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| hex::encode(Sha256::digest(certificate.as_ref())))
        .context("node mTLS peer certificate is missing")?;
    let registration: TunnelRegistration =
        timeout(Duration::from_secs(10), read_json_frame(&mut stream))
            .await
            .context("node registration timed out")??;
    validate_registration(&registration)?;
    if let Some(observer) = &service.observer {
        match observer
            .report(
                &registration.node_id,
                &registration.connection_id,
                &certificate_fingerprint,
            )
            .await?
        {
            ObservationStatus::Accepted => {}
            ObservationStatus::Rejected => {
                anyhow::bail!("control plane rejected the node certificate")
            }
        }
    }
    service
        .state
        .tunnels
        .insert(
            TunnelKey {
                node_id: registration.node_id,
                connection_id: registration.connection_id,
            },
            certificate_fingerprint,
            stream,
        )
        .await
}

async fn refresh_observations(service: Arc<TunnelService>) -> anyhow::Result<()> {
    let observer = service
        .observer
        .as_ref()
        .context("gateway observer is not configured")?;
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        for identity in service.state.tunnels.identities().await {
            match observer
                .report(
                    &identity.key.node_id,
                    &identity.key.connection_id,
                    &identity.certificate_fingerprint,
                )
                .await
            {
                Ok(ObservationStatus::Accepted) => {}
                Ok(ObservationStatus::Rejected) => {
                    service.state.tunnels.remove(&identity.key).await;
                    tracing::warn!(
                        node_id = %identity.key.node_id,
                        "control plane rejected node certificate; idle tunnels removed"
                    );
                }
                Err(error) => {
                    tracing::error!(
                        node_id = %identity.key.node_id,
                        %error,
                        "gateway observation failed"
                    );
                }
            }
        }
    }
}

async fn relay(stream: TcpStream, service: &TunnelService) -> anyhow::Result<()> {
    let mut client = timeout(
        Duration::from_secs(10),
        service.relay_acceptor.accept(stream),
    )
    .await
    .context("relay TLS handshake timed out")??;
    let request: RelayRequest = timeout(Duration::from_secs(10), read_json_frame(&mut client))
        .await
        .context("relay authorization timed out")??;
    if request.token.len() > 2_048 {
        anyhow::bail!("access token exceeds the size limit");
    }
    let grant = service
        .state
        .resolve_grant(&request.token)
        .await
        .map_err(|_| anyhow::anyhow!("access grant is invalid"))?;
    let token_id = grant.token_id;
    let (relay_id, revoked) = service.state.active_relays.register(token_id).await;
    let result = relay_active(&mut client, service, &request, grant, revoked).await;
    service
        .state
        .active_relays
        .unregister(token_id, relay_id)
        .await;
    result
}

async fn relay_active(
    client: &mut TlsStream<TcpStream>,
    service: &TunnelService,
    request: &RelayRequest,
    grant: prism_protocol::AccessGrant,
    mut revoked: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    if service.state.resolve_grant(&request.token).await.is_err() {
        anyhow::bail!("access grant was revoked before relay activation");
    }
    let key = TunnelKey {
        node_id: grant.node_id.clone(),
        connection_id: grant.connection_id.clone(),
    };
    let mut tunnel = service
        .state
        .tunnels
        .take(&key)
        .await
        .context("no outbound tunnel is ready for this lease")?;
    write_json_frame(
        &mut tunnel,
        &RelayOpen {
            service: request.service,
        },
    )
    .await?;
    let ready: RelayReady = timeout(Duration::from_secs(10), read_json_frame(&mut tunnel))
        .await
        .context("workspace readiness timed out")??;
    write_json_frame(client, &ready).await?;
    if !ready.ready {
        anyhow::bail!("workspace service is unavailable");
    }
    let remaining = (grant.expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO);
    tokio::select! {
        result = tokio::io::copy_bidirectional(client, &mut tunnel) => {
            result?;
        }
        result = revoked.changed() => {
            result.context("relay revocation channel closed")?;
        }
        () = sleep(remaining) => {}
    }
    Ok(())
}

pub(crate) async fn probe_workspace(
    pool: &TunnelPool,
    node_id: &str,
    connection_id: &str,
) -> anyhow::Result<ProbeResult> {
    let key = TunnelKey {
        node_id: node_id.to_owned(),
        connection_id: connection_id.to_owned(),
    };
    probe_service(pool, &key, RelayService::Ssh).await?;
    let cuda_ready_at = chrono::Utc::now();
    probe_service(pool, &key, RelayService::Jupyter).await?;
    Ok(ProbeResult {
        node_id: node_id.to_owned(),
        connection_id: connection_id.to_owned(),
        cuda_ready_at,
        interactive_access_ready_at: chrono::Utc::now(),
    })
}

async fn probe_service(
    pool: &TunnelPool,
    key: &TunnelKey,
    service: RelayService,
) -> anyhow::Result<()> {
    let mut tunnel = pool
        .take(key)
        .await
        .context("no fresh outbound tunnel is ready")?;
    write_json_frame(&mut tunnel, &RelayOpen { service }).await?;
    let ready: RelayReady = timeout(Duration::from_secs(10), read_json_frame(&mut tunnel))
        .await
        .context("workspace readiness probe timed out")??;
    if !ready.ready {
        anyhow::bail!(
            "workspace service probe failed: {}",
            ready.error.as_deref().unwrap_or("unavailable")
        );
    }
    Ok(())
}

fn validate_registration(registration: &TunnelRegistration) -> anyhow::Result<()> {
    if !valid_node_id(&registration.node_id)
        || !valid_identifier(&registration.connection_id, 128)
        || registration
            .issued_at
            .signed_duration_since(chrono::Utc::now())
            .num_seconds()
            .abs()
            > 300
    {
        anyhow::bail!("node tunnel registration is invalid");
    }
    let key = verifying_key(&registration.device_public_key)?;
    if node_id(&key) != registration.node_id {
        anyhow::bail!("node tunnel identity does not match its public key");
    }
    registration.verify(&key)?;
    Ok(())
}

impl TunnelPool {
    async fn insert(
        &self,
        key: TunnelKey,
        certificate_fingerprint: String,
        stream: TlsStream<TcpStream>,
    ) -> anyhow::Result<()> {
        let mut tunnels = self.inner.lock().await;
        let total = tunnels.values().map(VecDeque::len).sum::<usize>();
        let queue = tunnels.entry(key).or_default();
        if total >= MAX_IDLE_TUNNELS || queue.len() >= MAX_IDLE_TUNNELS_PER_CONNECTION {
            anyhow::bail!("tunnel capacity reached");
        }
        queue.push_back(IdleTunnel {
            inserted_at: Instant::now(),
            certificate_fingerprint,
            stream,
        });
        Ok(())
    }

    async fn take(&self, key: &TunnelKey) -> Option<TlsStream<TcpStream>> {
        let mut tunnels = self.inner.lock().await;
        let queue = tunnels.get_mut(key)?;
        while let Some(tunnel) = queue.pop_front() {
            if tunnel.inserted_at.elapsed() <= TUNNEL_MAX_AGE {
                return Some(tunnel.stream);
            }
        }
        tunnels.remove(key);
        None
    }

    async fn identities(&self) -> Vec<TunnelIdentity> {
        let tunnels = self.inner.lock().await;
        tunnels
            .iter()
            .filter_map(|(key, queue)| {
                let certificate_fingerprint = queue
                    .iter()
                    .rev()
                    .find(|tunnel| tunnel.inserted_at.elapsed() <= TUNNEL_MAX_AGE)?
                    .certificate_fingerprint
                    .clone();
                Some(TunnelIdentity {
                    key: key.clone(),
                    certificate_fingerprint,
                })
            })
            .collect()
    }

    async fn remove(&self, key: &TunnelKey) {
        self.inner.lock().await.remove(key);
    }
}

impl GatewayObserver {
    fn from_environment() -> anyhow::Result<Option<Self>> {
        let base_url = env::var("PRISM_CONTROL_PLANE_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let token = env::var("PRISM_GATEWAY_OBSERVER_TOKEN")
            .ok()
            .filter(|value| value.len() >= 32 && value.len() <= 512);
        match (base_url, token) {
            (Some(base_url), Some(token)) => {
                let base_url = url::Url::parse(&base_url)?;
                let local_http = base_url.scheme() == "http"
                    && base_url.host_str().is_some_and(|host| {
                        host == "localhost"
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|address| address.is_loopback())
                    });
                let private_http = env::var("PRISM_ALLOW_PRIVATE_CONTROL_PLANE_HTTP").as_deref()
                    == Ok("1")
                    && base_url.scheme() == "http"
                    && base_url.host_str().is_some_and(private_service_host);
                if base_url.scheme() != "https" && !local_http && !private_http {
                    anyhow::bail!(
                        "PRISM_CONTROL_PLANE_URL must use HTTPS unless private HTTP is explicitly enabled"
                    );
                }
                Ok(Some(Self {
                    client: reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .build()?,
                    base_url,
                    token,
                }))
            }
            (None, None) => {
                tracing::warn!("gateway tunnel observations are not reported to the scheduler");
                Ok(None)
            }
            _ => anyhow::bail!(
                "PRISM_CONTROL_PLANE_URL and PRISM_GATEWAY_OBSERVER_TOKEN must be configured together"
            ),
        }
    }

    async fn report(
        &self,
        node_id: &str,
        connection_id: &str,
        certificate_fingerprint: &str,
    ) -> anyhow::Result<ObservationStatus> {
        let endpoint = self
            .base_url
            .join(&format!("v1/gateway/tunnels/{node_id}"))?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(&self.token)
            .json(&TunnelObservation {
                connection_id,
                certificate_fingerprint,
                observed_at: chrono::Utc::now(),
            })
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(ObservationStatus::Accepted);
        }
        if response.status().is_client_error() {
            return Ok(ObservationStatus::Rejected);
        }
        response.error_for_status()?;
        unreachable!()
    }
}

fn private_service_host(host: &str) -> bool {
    host == "control-plane"
        || host.ends_with(".prism.internal")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| match address {
                std::net::IpAddr::V4(address) => address.is_private(),
                std::net::IpAddr::V6(address) => address.is_unique_local(),
            })
}

fn mutual_tls_acceptor(
    certificate_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> anyhow::Result<TlsAcceptor> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(client_ca_path)? {
        roots.add(certificate)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate_path)?, private_key(key_path)?)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn server_tls_acceptor(certificate_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(certificate_path)?, private_key(key_path)?)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open certificate {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certificates")
}

fn private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("parse private key {}", path.display()))
}

async fn write_json_frame<T, S>(stream: &mut S, value: &T) -> anyhow::Result<()>
where
    T: Serialize,
    S: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        anyhow::bail!("tunnel frame exceeds the size limit");
    }
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_json_frame<T, S>(stream: &mut S) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
    S: AsyncRead + Unpin,
{
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        anyhow::bail!("tunnel frame exceeds the size limit");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).context("decode tunnel frame")
}

fn required_env(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("{key} is required"))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use prism_protocol::UnsignedTunnelRegistration;

    use super::*;

    #[test]
    fn registration_requires_a_fresh_device_signature() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut registration = TunnelRegistration::sign(
            UnsignedTunnelRegistration {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                connection_id: "connection-1".to_owned(),
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();
        assert!(validate_registration(&registration).is_ok());

        registration.connection_id = "connection-2".to_owned();
        assert!(validate_registration(&registration).is_err());
    }

    #[test]
    fn private_control_plane_hosts_are_narrowly_scoped() {
        assert!(private_service_host("control-plane"));
        assert!(private_service_host("control-plane.prism.internal"));
        assert!(private_service_host("10.48.2.3"));
        assert!(private_service_host("fd00::1"));
        assert!(!private_service_host("control-plane.example.com"));
        assert!(!private_service_host("203.0.113.5"));
    }
}
