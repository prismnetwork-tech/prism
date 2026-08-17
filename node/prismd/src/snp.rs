use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use prism_protocol::{
    AttestationChallenge, AttestationKind, GuestAttestation, LeaseAttestationVerdict,
    UnsignedGuestAttestation, node_id, snp_report_data,
};
use rand::RngCore;
use uuid::Uuid;

use crate::{control_plane_endpoint, load_identity, require_success, signing_key};

const CONFIGFS_TSM_ROOT: &str = "/sys/kernel/config/tsm/report";
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
/// The evidence the guest leaves for the daemon to carry. The report is renamed
/// into place last, so a daemon that sees it also sees the rest.
const REPORT_FILE: &str = "guest-report.bin";
const CHAIN_FILE: &str = "guest-chain.b64";
const CHANNEL_KEY_FILE: &str = "guest-channel-key.pub";
/// An SNP attestation report is 1184 bytes. Anything else is not one, and the
/// guest says so where it is cheap to notice rather than letting the control
/// plane guess at a truncated read.
const SNP_REPORT_BYTES: usize = 1_184;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);

pub fn evidence_directory(workspace: &Path) -> PathBuf {
    workspace.join("evidence")
}

/// The report is renamed into place after everything it arrives with, so its
/// presence is what says the guest is done writing.
pub fn report_ready(evidence: &Path) -> bool {
    evidence.join(REPORT_FILE).exists()
}

pub struct ReportRequest<'a> {
    pub challenge_file: &'a Path,
    pub lease_id: u64,
    pub channel_key_file: &'a Path,
    pub output_directory: &'a Path,
}

/// Runs inside the guest, as part of the measured image, before anything is
/// listening. `REPORT_DATA` is the only field of the report the guest chooses,
/// so it carries the whole binding: the control plane's challenge, the lease
/// this guest was started for, and the SSH host key this guest just generated.
pub fn take_report(request: &ReportRequest<'_>) -> anyhow::Result<()> {
    let challenge = read_challenge(request.challenge_file)?;
    let channel_key = read_channel_key(request.channel_key_file)?;
    let report_data = snp_report_data(&challenge, request.lease_id, &channel_key);
    let evidence = collect(&report_data)?;
    write_evidence(request.output_directory, &evidence, &channel_key)
}

/// The challenge arrives through a mount the host controls, so nothing here
/// treats it as authority. The shape is checked because a truncated file would
/// otherwise be hashed into a report nobody can diagnose; a stale or invented
/// challenge passes this check and is refused by the control plane, which is
/// the only place that knows what it issued.
fn read_challenge(path: &Path) -> anyhow::Result<Vec<u8>> {
    let raw = fs::read_to_string(path).context("read the attestation challenge")?;
    let nonce = hex::decode(raw.trim()).context("attestation challenge is not hex")?;
    if nonce.len() != 32 {
        anyhow::bail!("attestation challenge must be 32 bytes");
    }
    Ok(nonce)
}

fn read_channel_key(path: &Path) -> anyhow::Result<String> {
    let key = fs::read_to_string(path).context("read the guest SSH host key")?;
    let key = key.trim().to_owned();
    if !key.starts_with("ssh-") || key.lines().count() != 1 {
        anyhow::bail!("the guest SSH host key is not a single OpenSSH public key line");
    }
    Ok(key)
}

struct Evidence {
    report: Vec<u8>,
    certificates: Vec<Vec<u8>>,
}

fn collect(report_data: &[u8; 64]) -> anyhow::Result<Evidence> {
    match configfs_report(Path::new(CONFIGFS_TSM_ROOT), report_data) {
        Ok(evidence) => Ok(evidence),
        Err(configfs) => sev_guest_report(Path::new(SEV_GUEST_DEVICE), report_data)
            .with_context(|| format!("configfs-tsm could not produce a report: {configfs:#}")),
    }
}

/// Reading `outblob` is what asks the firmware for the report, so the read is
/// the request and its failure is the firmware's answer.
fn configfs_report(root: &Path, report_data: &[u8; 64]) -> anyhow::Result<Evidence> {
    let entry = ConfigfsEntry::create(root)?;
    fs::write(entry.path.join("inblob"), report_data).context("write the report data")?;
    let report = fs::read(entry.path.join("outblob")).context("read the SNP report")?;
    let auxblob = fs::read(entry.path.join("auxblob")).unwrap_or_default();
    if report.len() != SNP_REPORT_BYTES {
        anyhow::bail!(
            "configfs-tsm returned {} bytes rather than an SNP report",
            report.len()
        );
    }
    Ok(Evidence {
        report,
        certificates: certificate_table(&auxblob),
    })
}

struct ConfigfsEntry {
    path: PathBuf,
}

impl ConfigfsEntry {
    fn create(root: &Path) -> anyhow::Result<Self> {
        let mut suffix = [0_u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        let path = root.join(format!("prism-{}", hex::encode(suffix)));
        fs::create_dir(&path).with_context(|| format!("open {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ConfigfsEntry {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

/// The AMD certificate blob is a table of 16-byte GUIDs with an offset and a
/// length into the same blob, terminated by a zero GUID. Splitting it here
/// keeps the daemon out of the evidence: the guest is measured software and can
/// be trusted to know its own format, the host courier is neither.
fn certificate_table(blob: &[u8]) -> Vec<Vec<u8>> {
    const ENTRY: usize = 24;
    let mut certificates = Vec::new();
    let mut cursor = 0;
    while let Some(entry) = blob.get(cursor..cursor + ENTRY) {
        if entry[..16].iter().all(|byte| *byte == 0) {
            break;
        }
        let start = u32::from_le_bytes(entry[16..20].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().unwrap()) as usize;
        if let Some(end) = start.checked_add(length)
            && length > 0
            && let Some(der) = blob.get(start..end)
        {
            certificates.push(der.to_vec());
        }
        cursor += ENTRY;
    }
    certificates
}

/// The report lands last, under a rename, because the daemon starts forwarding
/// the moment it sees that file.
fn write_evidence(directory: &Path, evidence: &Evidence, channel_key: &str) -> anyhow::Result<()> {
    fs::create_dir_all(directory).context("open the evidence directory")?;
    let chain = evidence
        .certificates
        .iter()
        .map(|der| STANDARD.encode(der))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(directory.join(CHAIN_FILE), format!("{chain}\n"))?;
    fs::write(directory.join(CHANNEL_KEY_FILE), format!("{channel_key}\n"))?;
    let pending = directory.join(format!("{REPORT_FILE}.pending"));
    fs::write(&pending, &evidence.report)?;
    fs::rename(pending, directory.join(REPORT_FILE)).context("publish the guest report")
}

/// Ask for the nonce this lease's guest has to commit to. Whether a lease gets
/// a confidential guest at all is the node's own answer, not this call's: a host
/// with no confidential runtime installed never asks, and its leases hold
/// whatever class their remaining evidence supports.
pub async fn lease_challenge(
    control_plane: &str,
    lease_id: u64,
    node: &str,
) -> anyhow::Result<AttestationChallenge> {
    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/leases/{lease_id}/attestation/challenge"),
    )?;
    let response = client()?.get(endpoint).send().await?;
    if !response.status().is_success() {
        require_success(response).await?;
        anyhow::bail!("the control plane issued no challenge for this lease");
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

/// Carry what the guest wrote to the control plane and stop there. The daemon
/// does not read the report, does not decide whether it is any good, and
/// forwards one it cannot make sense of, because the host is the party this
/// whole construction refuses to trust.
pub async fn forward(
    identity_path: &Path,
    control_plane: &str,
    lease_id: u64,
    challenge_id: Uuid,
    evidence: &Path,
) -> anyhow::Result<()> {
    let identity = load_identity(identity_path)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let report = fs::read(evidence.join(REPORT_FILE)).context("read the guest report")?;
    let channel_key =
        fs::read_to_string(evidence.join(CHANNEL_KEY_FILE)).context("read the guest host key")?;
    let attestation = GuestAttestation::sign(
        UnsignedGuestAttestation {
            node_id: node,
            lease_id,
            challenge_id,
            kind: AttestationKind::SevSnp,
            report_base64: STANDARD.encode(&report),
            certificate_chain_base64: read_chain(evidence)?,
            guest_channel_key: channel_key.trim().to_owned(),
            collected_at: Utc::now(),
        },
        &key,
    )?;

    let endpoint =
        control_plane_endpoint(control_plane, &format!("v1/leases/{lease_id}/attestation"))?;
    let response = client()?.post(endpoint).json(&attestation).send().await?;
    if !response.status().is_success() {
        return require_success(response).await;
    }
    match response.json::<LeaseAttestationVerdict>().await {
        Ok(verdict) => tracing::info!(
            lease_id,
            class = verdict.granted_class.label(),
            expires_at = %verdict.expires_at,
            "guest attestation verified by the control plane"
        ),
        Err(error) => {
            tracing::info!(lease_id, %error, "guest attestation accepted without a verdict body")
        }
    }
    // The challenge is spent and the report is bound to it, so a copy left on
    // the host is only useful to someone trying to reuse it.
    let _ = fs::remove_dir_all(evidence);
    Ok(())
}

fn read_chain(evidence: &Path) -> anyhow::Result<Vec<String>> {
    match fs::read_to_string(evidence.join(CHAIN_FILE)) {
        Ok(chain) => Ok(chain
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()),
        // A platform that hands out no certificate table is not a failure to
        // report. The verifier can resolve a VCEK from the report itself.
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).context("read the guest certificate chain"),
    }
}

fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(FORWARD_TIMEOUT)
        .user_agent(concat!("prismd/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build guest attestation client")
}

/// Kata hashes this document and the firmware writes the digest into
/// `HOST_DATA` at launch, where the host can no longer change it. Nothing else
/// on this stack chooses that field: it is the initdata digest or it is
/// whatever Kata put there, so the verifier's expectation has to be
/// `sha256(initdata_document(..))` for the lease's own image, computed from
/// these three inputs and nothing read off a report.
///
/// It is still a host input. It is worth something only because the agent
/// measured into the guest image refuses to run anything but the image named
/// here. That policy is measured into the image rather than handed in at
/// launch, so what travels is the digest the control plane pinned for it, and
/// until the policy is live the report is genuine while the workload image is
/// unverified.
pub fn initdata_document(lease_id: &str, image: &str, policy_digest: &str) -> String {
    format!(
        "version = \"0.1.0\"\n\
         algorithm = \"sha256\"\n\
         \n\
         [data]\n\
         \"prism-lease.toml\" = '''\n\
         lease_id = \"{lease_id}\"\n\
         image = \"{image}\"\n\
         agent_policy_sha256 = \"{policy_digest}\"\n\
         '''\n"
    )
}

pub fn initdata_annotation(lease_id: &str, image: &str, policy_digest: &str) -> String {
    STANDARD.encode(gzip(
        initdata_document(lease_id, image, policy_digest).as_bytes(),
    ))
}

/// Kata takes the initdata gzipped and base64'd. Stored deflate blocks are
/// valid gzip and cost one small function, which is cheaper than a compression
/// dependency for a document of a few hundred bytes.
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks = data.chunks(0xffff).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[0x01, 0, 0, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let length = u16::try_from(chunk.len()).expect("chunked below 64 KiB");
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(target_os = "linux")]
mod guest_device {
    use std::{fs::OpenOptions, os::fd::AsRawFd, path::Path};

    use anyhow::Context;

    use super::{Evidence, SNP_REPORT_BYTES};

    /// _IOWR('S', 0, struct snp_guest_request_ioctl).
    const SNP_GET_REPORT: u64 = 0xc020_5300;
    const MESSAGE_VERSION: u8 = 1;
    /// The firmware answers with a 32-byte message header in front of the
    /// report, inside a fixed 4000-byte response buffer.
    const RESPONSE_BYTES: usize = 4_000;
    const RESPONSE_HEADER_BYTES: usize = 32;

    unsafe extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }

    #[repr(C)]
    struct ReportRequest {
        user_data: [u8; 64],
        vmpl: u32,
        reserved: [u8; 28],
    }

    #[repr(C)]
    struct GuestRequest {
        message_version: u8,
        request_data: u64,
        response_data: u64,
        exit_info: u64,
    }

    /// The pre-configfs interface, kept for guests whose kernel predates
    /// `/sys/kernel/config/tsm`. It returns the report alone: a guest with no
    /// certificate table is not a guest with no evidence, because the verifier
    /// can resolve a VCEK from the report.
    pub fn report(device: &Path, report_data: &[u8; 64]) -> anyhow::Result<Evidence> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device)
            .with_context(|| format!("open {}", device.display()))?;
        let mut request = ReportRequest {
            user_data: *report_data,
            vmpl: 0,
            reserved: [0; 28],
        };
        let mut response = [0_u8; RESPONSE_BYTES];
        let mut guest_request = GuestRequest {
            message_version: MESSAGE_VERSION,
            request_data: std::ptr::from_mut(&mut request) as u64,
            response_data: response.as_mut_ptr() as u64,
            exit_info: 0,
        };
        let outcome = unsafe {
            ioctl(
                file.as_raw_fd(),
                SNP_GET_REPORT,
                std::ptr::from_mut(&mut guest_request),
            )
        };
        if outcome != 0 {
            anyhow::bail!(
                "the SEV guest device refused the report request: {} (firmware {:#x})",
                std::io::Error::last_os_error(),
                guest_request.exit_info
            );
        }
        let report = response
            .get(RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + SNP_REPORT_BYTES)
            .context("the SEV guest device returned a short report")?
            .to_vec();
        Ok(Evidence {
            report,
            certificates: Vec::new(),
        })
    }
}

#[cfg(target_os = "linux")]
fn sev_guest_report(device: &Path, report_data: &[u8; 64]) -> anyhow::Result<Evidence> {
    guest_device::report(device, report_data)
}

#[cfg(not(target_os = "linux"))]
fn sev_guest_report(_device: &Path, _report_data: &[u8; 64]) -> anyhow::Result<Evidence> {
    anyhow::bail!("SEV-SNP guest reports are only available on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "prismd-snp-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// The guest and the control plane have to derive the same 64 bytes from
    /// the same three inputs, or every report is refused for a reason nobody
    /// can see. The daemon derives nothing: it only forwards.
    #[test]
    fn the_reporter_binds_the_same_report_data_as_the_protocol() {
        let root = temporary_directory("report-data");
        let challenge = root.join("attestation_challenge");
        let channel_key = root.join("ssh_host_key.pub");
        let nonce = [0x5a_u8; 32];
        fs::write(&challenge, format!("{}\n", hex::encode(nonce))).unwrap();
        fs::write(
            &channel_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-guest\n",
        )
        .unwrap();

        let bound = snp_report_data(
            &read_challenge(&challenge).unwrap(),
            42,
            &read_channel_key(&channel_key).unwrap(),
        );
        assert_eq!(
            bound,
            snp_report_data(&nonce, 42, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-guest")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_truncated_or_unreadable_challenge_is_refused_before_it_is_hashed() {
        let root = temporary_directory("challenge");
        let path = root.join("attestation_challenge");
        fs::write(&path, "abcd\n").unwrap();
        assert!(read_challenge(&path).is_err());
        fs::write(&path, "not hex at all\n").unwrap();
        assert!(read_challenge(&path).is_err());
        fs::write(&path, hex::encode([1_u8; 32])).unwrap();
        assert!(read_challenge(&path).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_certificate_table_splits_into_one_der_each() {
        let mut blob = vec![0_u8; 72];
        blob[..16].copy_from_slice(&[0x11; 16]);
        blob[16..20].copy_from_slice(&64_u32.to_le_bytes());
        blob[20..24].copy_from_slice(&4_u32.to_le_bytes());
        blob[24..40].copy_from_slice(&[0x22; 16]);
        blob[40..44].copy_from_slice(&68_u32.to_le_bytes());
        blob[44..48].copy_from_slice(&4_u32.to_le_bytes());
        blob[64..72].copy_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xb3, 0xb4]);

        assert_eq!(
            certificate_table(&blob),
            vec![vec![0xa1, 0xa2, 0xa3, 0xa4], vec![0xb1, 0xb2, 0xb3, 0xb4]]
        );
        assert!(certificate_table(&[]).is_empty());
        assert!(certificate_table(&[0_u8; 24]).is_empty());
    }

    /// An entry pointing outside the blob is a malformed table, not a reason to
    /// invent a certificate.
    #[test]
    fn the_certificate_table_ignores_entries_that_run_off_the_end() {
        let mut blob = vec![0_u8; 48];
        blob[..16].copy_from_slice(&[0x11; 16]);
        blob[16..20].copy_from_slice(&40_u32.to_le_bytes());
        blob[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(certificate_table(&blob).is_empty());
    }

    #[test]
    fn the_report_is_published_after_everything_it_arrives_with() {
        let root = temporary_directory("evidence");
        let evidence = Evidence {
            report: vec![0x7f; SNP_REPORT_BYTES],
            certificates: vec![vec![0x30, 0x82, 0x01, 0x02]],
        };
        write_evidence(&root, &evidence, "ssh-ed25519 AAAA prism-guest").unwrap();

        assert_eq!(fs::read(root.join(REPORT_FILE)).unwrap(), evidence.report);
        assert_eq!(
            read_chain(&root).unwrap(),
            vec![STANDARD.encode([0x30, 0x82, 0x01, 0x02])]
        );
        assert!(!root.join(format!("{REPORT_FILE}.pending")).exists());
        fs::remove_dir_all(root).unwrap();
    }

    /// Kata decompresses this before it hashes it, so a document that is not
    /// valid gzip becomes a `HOST_DATA` nobody can predict.
    #[test]
    fn the_initdata_annotation_is_gzip_a_standard_tool_can_read() {
        let annotation = initdata_annotation(
            "77",
            "registry.example/runtime@sha256:aaaa",
            &"c".repeat(64),
        );
        let compressed = STANDARD.decode(&annotation).unwrap();
        let mut child = Command::new("gzip")
            .arg("-dc")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), &compressed).unwrap();
        let output = child.wait_with_output().unwrap();

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            initdata_document(
                "77",
                "registry.example/runtime@sha256:aaaa",
                &"c".repeat(64)
            )
        );
    }

    /// What the guest wrote is what the control plane receives, byte for byte,
    /// and the daemon reaches no conclusion about any of it on the way. The
    /// evidence is bound to a challenge that is now spent, so the copy on the
    /// host goes with it.
    #[tokio::test]
    async fn forwarding_carries_the_report_verbatim_and_leaves_nothing_behind() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = temporary_directory("forward");
        let identity = root.join("device.json");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        fs::write(
            &identity,
            serde_json::json!({ "signing_key_hex": hex::encode(key.to_bytes()) }).to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let evidence = root.join("evidence");
        let report = vec![0x3c_u8; SNP_REPORT_BYTES];
        write_evidence(
            &evidence,
            &Evidence {
                report: report.clone(),
                certificates: vec![vec![0x30, 0x82, 0x05, 0x06]],
            },
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-guest",
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_plane = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4_096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
                let body = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|end| end + 4);
                if read == 0 || body.is_some_and(|body| request[body..].ends_with(b"}")) {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            request
        });

        let challenge_id = Uuid::now_v7();
        forward(&identity, &control_plane, 42, challenge_id, &evidence)
            .await
            .unwrap();

        let request = String::from_utf8(server.await.unwrap()).unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        let posted: GuestAttestation = serde_json::from_str(body).unwrap();

        assert!(head.starts_with("POST /v1/leases/42/attestation "));
        assert_eq!(posted.lease_id, 42);
        assert_eq!(posted.challenge_id, challenge_id);
        assert_eq!(posted.kind, AttestationKind::SevSnp);
        assert_eq!(posted.report_base64, STANDARD.encode(&report));
        assert_eq!(
            posted.certificate_chain_base64,
            vec![STANDARD.encode([0x30, 0x82, 0x05, 0x06])]
        );
        assert_eq!(
            posted.guest_channel_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 prism-guest"
        );
        posted.verify(&key.verifying_key()).unwrap();
        assert!(!evidence.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crc32_matches_the_gzip_polynomial() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
