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
    AttestationChallenge, AttestationKind, AttestationVerdict, NodeAttestation,
    UnsignedNodeAttestation, attestation_report_nonce, node_id,
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
fn split_chain(pem: &str) -> anyhow::Result<Vec<String>> {
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
