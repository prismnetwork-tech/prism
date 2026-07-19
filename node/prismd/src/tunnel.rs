use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use prism_protocol::{TunnelRegistration, UnsignedTunnelRegistration, node_id};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::sleep,
};
use tokio_rustls::TlsConnector;

const MAX_FRAME_BYTES: usize = 16 * 1_024;

#[derive(Clone)]
pub struct TunnelConfig {
    pub gateway: String,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub client_certificate: PathBuf,
    pub client_key: PathBuf,
    pub connection_id: String,
    pub ssh_target: String,
    pub jupyter_target: String,
    pub slots: u16,
}

#[derive(Debug, Deserialize)]
struct RelayOpen {
    service: RelayService,
}

#[derive(Debug, Serialize)]
struct RelayRequest {
    token: String,
    service: RelayService,
}

#[derive(Debug, Serialize, Deserialize)]
struct RelayReady {
    ready: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayService {
    Ssh,
    Jupyter,
}

#[derive(Clone)]
pub struct RelayConfig {
    pub gateway: String,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub token: String,
    pub service: RelayService,
    pub listen: String,
}

pub async fn run(config: TunnelConfig, signing_key: SigningKey) -> anyhow::Result<()> {
    validate_identifier(&config.connection_id)?;
    if config.slots == 0 || config.slots > 64 {
        anyhow::bail!("tunnel slots must be between 1 and 64");
    }
    let tls = tls_connector(
        &config.ca_certificate,
        &config.client_certificate,
        &config.client_key,
    )?;
    let config = Arc::new(config);
    let signing_key = Arc::new(signing_key);
    let mut workers = JoinSet::new();
    for _ in 0..config.slots {
        workers.spawn(worker(config.clone(), tls.clone(), signing_key.clone()));
    }

    tokio::select! {
        result = workers.join_next() => {
            match result {
                Some(Ok(Err(error))) => Err(error),
                Some(Err(error)) => Err(error.into()),
                _ => anyhow::bail!("all tunnel workers stopped"),
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal.context("install tunnel shutdown signal")?;
            workers.abort_all();
            Ok(())
        }
    }
}

pub async fn run_relay(config: RelayConfig) -> anyhow::Result<()> {
    if config.token.len() < 32 || config.token.len() > 2_048 {
        anyhow::bail!("access token has an invalid length");
    }
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind local relay {}", config.listen))?;
    let tls = server_auth_connector(&config.ca_certificate)?;
    let config = Arc::new(config);
    tracing::info!(address = %config.listen, "local access relay listening");
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (local, _) = result?;
                local.set_nodelay(true)?;
                let config = config.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Err(error) = relay_once(local, &config, &tls).await {
                        tracing::warn!(%error, "local access relay disconnected");
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("install relay shutdown signal")?;
                return Ok(());
            }
        }
    }
}

async fn worker(
    config: Arc<TunnelConfig>,
    tls: TlsConnector,
    signing_key: Arc<SigningKey>,
) -> anyhow::Result<()> {
    loop {
        if let Err(error) = serve_once(&config, &tls, &signing_key).await {
            tracing::warn!(%error, "outbound tunnel slot disconnected");
            sleep(Duration::from_secs(2)).await;
        }
    }
}

async fn serve_once(
    config: &TunnelConfig,
    tls: &TlsConnector,
    signing_key: &SigningKey,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(&config.gateway)
        .await
        .with_context(|| format!("connect tunnel gateway {}", config.gateway))?;
    stream.set_nodelay(true)?;
    let server_name = ServerName::try_from(config.server_name.clone())
        .context("tunnel server name is invalid")?;
    let mut stream = tls
        .connect(server_name, stream)
        .await
        .context("establish tunnel mTLS")?;
    let registration = TunnelRegistration::sign(
        UnsignedTunnelRegistration {
            node_id: node_id(&signing_key.verifying_key()),
            device_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            connection_id: config.connection_id.clone(),
            issued_at: Utc::now(),
        },
        signing_key,
    )?;
    write_json_frame(&mut stream, &registration).await?;
    let request: RelayOpen = read_json_frame(&mut stream).await?;
    let target = match request.service {
        RelayService::Ssh => &config.ssh_target,
        RelayService::Jupyter => &config.jupyter_target,
    };
    let mut local = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(error) => {
            write_json_frame(
                &mut stream,
                &RelayReady {
                    ready: false,
                    error: Some("workspace_unavailable".to_owned()),
                },
            )
            .await?;
            return Err(error).with_context(|| format!("connect workspace service {target}"));
        }
    };
    local.set_nodelay(true)?;
    write_json_frame(
        &mut stream,
        &RelayReady {
            ready: true,
            error: None,
        },
    )
    .await?;
    tokio::io::copy_bidirectional(&mut stream, &mut local).await?;
    Ok(())
}

async fn relay_once(
    mut local: TcpStream,
    config: &RelayConfig,
    tls: &TlsConnector,
) -> anyhow::Result<()> {
    let stream = TcpStream::connect(&config.gateway)
        .await
        .with_context(|| format!("connect access relay {}", config.gateway))?;
    stream.set_nodelay(true)?;
    let server_name =
        ServerName::try_from(config.server_name.clone()).context("relay server name is invalid")?;
    let mut relay = tls
        .connect(server_name, stream)
        .await
        .context("establish relay TLS")?;
    write_json_frame(
        &mut relay,
        &RelayRequest {
            token: config.token.clone(),
            service: config.service,
        },
    )
    .await?;
    let ready: RelayReady = read_json_frame(&mut relay).await?;
    if !ready.ready {
        anyhow::bail!(
            "workspace service is unavailable: {}",
            ready.error.as_deref().unwrap_or("unknown")
        );
    }
    tokio::io::copy_bidirectional(&mut local, &mut relay).await?;
    Ok(())
}

fn tls_connector(
    ca_path: &Path,
    certificate_path: &Path,
    key_path: &Path,
) -> anyhow::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(ca_path)? {
        roots.add(certificate)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates(certificate_path)?, private_key(key_path)?)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

fn server_auth_connector(ca_path: &Path) -> anyhow::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(ca_path)? {
        roots.add(certificate)?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
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

fn validate_identifier(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("connection identifier is invalid");
    }
    Ok(())
}
