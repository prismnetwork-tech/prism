use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use prism_protocol::{
    AttestationChallenge, AttestationKind, AttestationVerdict, GpuCcAttestation, LeaseGpuCcVerdict,
    LeaseTdxGuestVerdict, NodeAttestation, TdxLeaseAttestation, UnsignedGpuCcAttestation,
    UnsignedNodeAttestation, UnsignedTdxLeaseAttestation, attestation_report_nonce, node_id,
    tdx_lease_report_data, tdx_report_data,
};
use rand::RngCore;

use crate::{control_plane_endpoint, load_identity, require_success, runtime, signing_key};

/// Collecting a report boots a guest with the GPU attached. That is minutes on
/// a cold image, so it gets its own budget instead of the heartbeat client's.
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(120);
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(300);
const REPORT_FILE: &str = "report.bin";
const CHAIN_FILE: &str = "chain.pem";

/// Prove to the control plane which GPU this node holds, against a nonce the
/// control plane just issued. Nothing here decides a trust class: the daemon
/// collects and signs, and the verdict is the control plane's to reach.
pub async fn refresh(
    identity_path: &Path,
    control_plane: &str,
    group: &runtime::VfioGroup,
) -> anyhow::Result<()> {
    let identity = load_identity(identity_path)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let device_public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let pci_address = group
        .pci_devices
        .first()
        .context("VFIO group has no PCI devices")?
        .clone();
    let client = attestation_client()?;

    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/nodes/{node}/attestation/challenge"),
    )?;
    let response = client.get(endpoint).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    let challenge: AttestationChallenge = response
        .json()
        .await
        .context("decode the attestation challenge")?;
    if challenge.node_id != node {
        anyhow::bail!("the control plane issued a challenge for another node");
    }
    let challenge_nonce = hex::decode(&challenge.nonce).context("challenge nonce is not hex")?;
    let report_nonce = attestation_report_nonce(&challenge_nonce, &node, &device_public_key);

    let evidence = EvidenceDirectory::create()?;
    let command = runtime::attestation_command(group, evidence.path(), &hex::encode(report_nonce))?;
    tokio::task::spawn_blocking(move || collect(command))
        .await
        .context("attestation collector task failed")??;
    let report = fs::read(evidence.path().join(REPORT_FILE)).context("read the GPU report")?;
    let chain = fs::read_to_string(evidence.path().join(CHAIN_FILE))
        .context("read the GPU certificate chain")?;

    let attestation = NodeAttestation::sign(
        UnsignedNodeAttestation {
            tdx_event_log: Vec::new(),
            tdx_collateral_json: None,
            node_id: node.clone(),
            challenge_id: challenge.challenge_id,
            kind: AttestationKind::NvidiaGpu,
            evidence_base64: STANDARD.encode(&report),
            certificate_chain_base64: split_chain(&chain)?,
            capability: *crate::host_capability(),
            pci_address,
            collected_at: Utc::now(),
        },
        &key,
    )?;
    let endpoint = control_plane_endpoint(control_plane, &format!("v1/nodes/{node}/attestation"))?;
    let response = client.post(endpoint).json(&attestation).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    match response.json::<AttestationVerdict>().await {
        Ok(verdict) => tracing::info!(
            device = %verdict.device_identity,
            class = verdict.granted_class.label(),
            expires_at = %verdict.expires_at,
            "attestation verified by the control plane"
        ),
        Err(error) => tracing::info!(%error, "attestation accepted without a verdict body"),
    }
    Ok(())
}

/// Prove to the control plane what this TD booted and what it is running,
/// against a nonce the control plane just issued. The guest agent quotes our
/// challenge binding, the event log rides along for the verifier's replay,
/// and the collateral is fetched here so the control plane stays offline.
pub async fn refresh_tdx(
    identity_path: &Path,
    control_plane: &str,
    socket: &Path,
    pccs_url: &str,
) -> anyhow::Result<()> {
    let identity = load_identity(identity_path)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let device_public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let client = attestation_client()?;

    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/nodes/{node}/attestation/challenge"),
    )?;
    let response = client.get(endpoint).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    let challenge: AttestationChallenge = response
        .json()
        .await
        .context("decode the attestation challenge")?;
    if challenge.node_id != node {
        anyhow::bail!("the control plane issued a challenge for another node");
    }
    let challenge_nonce = hex::decode(&challenge.nonce).context("challenge nonce is not hex")?;
    let report_data = tdx_report_data(&challenge_nonce, &node, &device_public_key);

    let quoted = crate::dstack::get_quote(socket, &report_data)
        .await
        .context("take a quote from the dstack guest agent")?;
    let collateral = prism_pccs::PccsClient::new(pccs_url)?
        .collateral_for(&quoted.quote)
        .await
        .context("fetch collateral for the quote")?;

    let attestation = NodeAttestation::sign(
        UnsignedNodeAttestation {
            tdx_event_log: quoted.event_log,
            tdx_collateral_json: Some(collateral),
            node_id: node.clone(),
            challenge_id: challenge.challenge_id,
            kind: AttestationKind::Tdx,
            evidence_base64: STANDARD.encode(&quoted.quote),
            certificate_chain_base64: Vec::new(),
            capability: *crate::host_capability(),
            pci_address: String::new(),
            collected_at: Utc::now(),
        },
        &key,
    )?;
    let endpoint = control_plane_endpoint(control_plane, &format!("v1/nodes/{node}/attestation"))?;
    let response = client.post(endpoint).json(&attestation).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    match response.json::<AttestationVerdict>().await {
        Ok(verdict) => tracing::info!(
            device = %verdict.device_identity,
            class = verdict.granted_class.label(),
            expires_at = %verdict.expires_at,
            "TDX attestation verified by the control plane"
        ),
        Err(error) => tracing::info!(%error, "attestation accepted without a verdict body"),
    }
    Ok(())
}

/// Attest one lease at the confidential rung from inside its own dstack CVM.
///
/// This is the per-lease counterpart of [`refresh_tdx`], and it earns a lease
/// the confidential class over two independent axes. The guest half quotes the
/// TD against the lease's challenge, so a quote taken for one renter's session
/// cannot back another; the GPU half collects a fresh NVIDIA CC report bound to
/// its own challenge, so the card the lease is running on proves it holds VRAM
/// in a single-GPU confidential mode. The control plane grants Confidential
/// only when both land, so a miss on either leaves the lease at whatever the
/// evidence substantiates rather than over-granting.
///
/// Fail-closed throughout: a challenge that cannot be fetched, a guest agent
/// that does not answer, or collateral that cannot be assembled aborts the
/// attestation rather than submitting a report that could never verify.
#[allow(clippy::too_many_arguments)]
pub async fn attest_lease_confidential(
    identity_path: &Path,
    control_plane: &str,
    socket: &Path,
    pccs_url: &str,
    lease_id: u64,
    guest_channel_key: &str,
) -> anyhow::Result<()> {
    let identity = load_identity(identity_path)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let client = attestation_client()?;

    let challenge = lease_challenge(
        &client,
        control_plane,
        lease_id,
        "attestation/challenge",
        &node,
    )
    .await
    .context("fetch the lease guest challenge")?;
    let challenge_nonce =
        hex::decode(&challenge.nonce).context("lease challenge nonce is not hex")?;
    // The SSH host key the renter's session terminates on is bound into the
    // quote, so a valid quote proves the renter is inside this measured TD and
    // not a bare container beside it.
    let report_data = tdx_lease_report_data(&challenge_nonce, lease_id, &node, guest_channel_key);

    let quoted = crate::dstack::get_quote(socket, &report_data)
        .await
        .context("take a lease quote from the dstack guest agent")?;
    let collateral = prism_pccs::PccsClient::new(pccs_url)?
        .collateral_for(&quoted.quote)
        .await
        .context("fetch collateral for the lease quote")?;

    let tdx = TdxLeaseAttestation::sign(
        UnsignedTdxLeaseAttestation {
            node_id: node.clone(),
            lease_id,
            challenge_id: challenge.challenge_id,
            quote_base64: STANDARD.encode(&quoted.quote),
            tdx_event_log: quoted.event_log,
            tdx_collateral_json: collateral,
            guest_channel_key: guest_channel_key.to_owned(),
            collected_at: Utc::now(),
        },
        &key,
    )?;
    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/leases/{lease_id}/tdx-attestation"),
    )?;
    let response = client.post(endpoint).json(&tdx).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    match response.json::<LeaseTdxGuestVerdict>().await {
        Ok(verdict) => tracing::info!(
            lease_id,
            device = %verdict.device_identity,
            class = verdict.granted_class.label(),
            expires_at = %verdict.expires_at,
            "lease TDX guest verdict recorded"
        ),
        Err(error) => {
            tracing::info!(lease_id, %error, "lease TDX attestation accepted without a verdict body")
        }
    }

    let gpu_challenge = lease_challenge(
        &client,
        control_plane,
        lease_id,
        "gpu-attestation/challenge",
        &node,
    )
    .await
    .context("fetch the lease GPU-CC challenge")?;
    let gpu_nonce =
        hex::decode(&gpu_challenge.nonce).context("GPU-CC challenge nonce is not hex")?;
    let gpu_nonce: [u8; 32] = gpu_nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("GPU-CC challenge nonce is not 32 bytes"))?;

    let evidence = crate::dstack::get_gpu_evidence(socket, &gpu_nonce)
        .await
        .context("collect GPU confidential-computing evidence from the guest agent")?;
    let gpu = GpuCcAttestation::sign(
        UnsignedGpuCcAttestation {
            node_id: node.clone(),
            lease_id,
            challenge_id: gpu_challenge.challenge_id,
            report_base64: STANDARD.encode(&evidence.report),
            certificate_chain_base64: evidence.certificate_chain,
            collected_at: Utc::now(),
        },
        &key,
    )?;
    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/leases/{lease_id}/gpu-attestation"),
    )?;
    let response = client.post(endpoint).json(&gpu).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    match response.json::<LeaseGpuCcVerdict>().await {
        Ok(verdict) => tracing::info!(
            lease_id,
            device = %verdict.device_identity,
            class = verdict.granted_class.label(),
            expires_at = %verdict.expires_at,
            "lease GPU-CC verdict recorded"
        ),
        Err(error) => {
            tracing::info!(lease_id, %error, "lease GPU-CC attestation accepted without a verdict body")
        }
    }
    Ok(())
}

/// Fetch one lease challenge and confirm it names this node. A challenge issued
/// for another node means the lease is not running here, which is refused rather
/// than answered with a report that could never bind.
async fn lease_challenge(
    client: &reqwest::Client,
    control_plane: &str,
    lease_id: u64,
    suffix: &str,
    node: &str,
) -> anyhow::Result<AttestationChallenge> {
    let endpoint =
        control_plane_endpoint(control_plane, &format!("v1/leases/{lease_id}/{suffix}"))?;
    let response = client.get(endpoint).send().await?;
    if !response.status().is_success() {
        require_success(response).await?;
        unreachable!("require_success returns an error for a non-success response");
    }
    let challenge: AttestationChallenge = response
        .json()
        .await
        .context("decode the lease attestation challenge")?;
    if challenge.node_id != node {
        anyhow::bail!("the control plane issued a lease challenge for another node");
    }
    Ok(challenge)
}

fn attestation_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(ATTESTATION_TIMEOUT)
        .user_agent(concat!("prismd/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build attestation client")
}

/// A collector that hangs holds the GPU, so it gets killed rather than waited
/// on forever.
fn collect(mut command: Command) -> anyhow::Result<()> {
    let mut child = command
        .spawn()
        .context("failed to start the attestation collector through nerdctl")?;
    let deadline = Instant::now() + COLLECTOR_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                anyhow::bail!("the attestation collector exited with {status}");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("the attestation collector did not finish in time");
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// One base64 DER per certificate, which is each PEM body with its armour and
/// line breaks removed. Decoding as we go means a truncated chain fails here
/// rather than at the verifier.
pub(crate) fn split_chain(pem: &str) -> anyhow::Result<Vec<String>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let body = &rest[start + BEGIN.len()..];
        let end = body
            .find(END)
            .context("certificate chain has an unterminated certificate")?;
        let der = body[..end].split_whitespace().collect::<String>();
        STANDARD
            .decode(&der)
            .context("certificate chain is not valid base64")?;
        certificates.push(der);
        rest = &body[end + END.len()..];
    }
    if certificates.is_empty() {
        anyhow::bail!("certificate chain contains no certificates");
    }
    Ok(certificates)
}

/// Evidence is bound to a challenge the control plane consumes, so a copy left
/// on disk is only useful to someone trying to reuse it.
struct EvidenceDirectory(PathBuf);

impl EvidenceDirectory {
    fn create() -> anyhow::Result<Self> {
        let mut suffix = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let path = std::env::temp_dir().join(format!("prismd-evidence-{}", hex::encode(suffix)));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .context("create the attestation evidence directory")?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for EvidenceDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_chain_into_one_certificate_each() {
        let leaf = STANDARD.encode([0x30, 0x82, 0x01, 0x02]);
        let root = STANDARD.encode([0x30, 0x82, 0x03, 0x04]);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{leaf}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{root}\n-----END CERTIFICATE-----\n"
        );

        assert_eq!(split_chain(&pem).unwrap(), vec![leaf, root]);
        assert!(split_chain("").is_err());
        assert!(split_chain("-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
    }

    #[test]
    fn the_evidence_directory_does_not_outlive_the_collection() {
        let path = {
            let evidence = EvidenceDirectory::create().unwrap();
            fs::write(evidence.path().join(REPORT_FILE), b"report").unwrap();
            evidence.path().to_owned()
        };
        assert!(!path.exists());
    }
}
