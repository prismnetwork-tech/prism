//! The dstack guest agent, spoken to over its unix socket.
//!
//! Inside a dstack CVM the guest agent is the only thing that can ask the
//! platform for a TDX quote, and it exposes that over `/var/run/dstack.sock`
//! as a small JSON RPC. This module carries exactly the one call the
//! attestation path needs: a quote over caller-chosen report data, together
//! with the runtime event log the verifier replays. The exchange is a single
//! POST and a single JSON body, so it is spoken directly over the socket
//! rather than through an HTTP client that cannot dial unix sockets anyway.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prism_protocol::TdxEventEntry;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Where the guest agent listens, in the order dstack deployments mount it.
const SOCKET_PATHS: [&str; 4] = [
    "/var/run/dstack.sock",
    "/run/dstack.sock",
    "/var/run/dstack/dstack.sock",
    "/run/dstack/dstack.sock",
];

/// A quote is milliseconds; the budget is for a guest agent mid-restart.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// GPU evidence collection spawns `nvattest`, which drives the device through
/// the driver and fetches reference measurements, so it gets a boot-sized
/// budget rather than a quote's.
const GPU_RPC_TIMEOUT: Duration = Duration::from_secs(120);
/// A quote plus a boot event log is tens of kilobytes. A response beyond this
/// is not the guest agent answering.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The socket this environment serves the guest agent on, if any. Presence is
/// what makes a machine a dstack CVM as far as the daemon is concerned;
/// `PRISM_DSTACK_SOCKET` overrides the probe for a non-standard mount.
pub fn socket() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PRISM_DSTACK_SOCKET") {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    SOCKET_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

pub struct QuoteResponse {
    pub quote: Vec<u8>,
    pub event_log: Vec<TdxEventEntry>,
}

#[derive(Deserialize)]
struct WireQuoteResponse {
    quote: String,
    event_log: String,
}

/// Asks the guest agent to quote these exact 64 bytes of report data and
/// returns the quote with the runtime event log it came with.
pub async fn get_quote(socket: &Path, report_data: &[u8; 64]) -> anyhow::Result<QuoteResponse> {
    let body = serde_json::json!({ "report_data": hex::encode(report_data) }).to_string();
    let raw = rpc(socket, "/GetQuote", &body, RPC_TIMEOUT).await?;
    let response: WireQuoteResponse =
        serde_json::from_slice(&raw).context("decode the GetQuote response")?;
    let quote = hex::decode(&response.quote).context("quote is not hex")?;
    let event_log: Vec<TdxEventEntry> =
        serde_json::from_str(&response.event_log).context("decode the event log")?;
    if event_log.is_empty() {
        bail!("the guest agent answered with an empty event log");
    }
    Ok(QuoteResponse { quote, event_log })
}

/// A GPU's confidential-computing evidence, as the guest agent collects it: the
/// vendor-native attestation report the device signed over the caller's nonce,
/// and the certificate chain that anchors that signature to NVIDIA's device
/// identity CA. Nothing here is a verdict; the control plane's verifier judges
/// it.
pub struct GpuEvidence {
    pub report: Vec<u8>,
    /// Leaf first, one base64 DER per certificate, the shape the wire carries.
    pub certificate_chain: Vec<String>,
}

/// The guest agent's versioned `AttestGpu` RPC lives on the v1 surface, mounted
/// at `/v1` on the internal socket, so its method path is `/v1/AttestGpu`. It
/// takes a 32-byte nonce verbatim and returns one vendor-native evidence bundle
/// per accelerator.
///
/// Source: dstack `dstack.guest.v1.DstackGuest.AttestGpu`
/// (`guest-agent/rpc/proto/agent_rpc_v1.proto`); the bundle's `evidence` is the
/// `nvidia-nvattest-collect-evidence-json-v1` array `nvattest collect-evidence`
/// emits (`guest-agent/src/gpu_attest.rs`, `nvattest/src/lib.rs`), each element
/// `{arch, nonce, evidence, certificate}` per GPU. prpc renders proto `bytes`
/// as hex over JSON (`prpc::serde_helpers::bytes_as_hex_str`), the same coding
/// `GetQuote` uses above; the NVIDIA `evidence` field inside is base64 and its
/// `certificate` is a PEM chain, both NVIDIA's own coding rather than prpc's.
const ATTEST_GPU_PATH: &str = "/v1/AttestGpu";
const NVIDIA_VENDOR: &str = "nvidia";
const NVIDIA_COLLECT_EVIDENCE_FORMAT: &str = "nvidia-nvattest-collect-evidence-json-v1";

/// Asks the guest agent to collect a fresh GPU report bound to this exact nonce
/// and returns the report with the certificate chain that anchors it. The nonce
/// is the lease challenge the control plane issued: the device signs it into the
/// report, so evidence taken for another lease answers a different challenge and
/// is refused by the verifier.
pub async fn get_gpu_evidence(socket: &Path, nonce: &[u8; 32]) -> anyhow::Result<GpuEvidence> {
    let requested = hex::encode(nonce);
    let body = serde_json::json!({ "nonce": requested }).to_string();
    let raw = rpc(socket, ATTEST_GPU_PATH, &body, GPU_RPC_TIMEOUT).await?;
    let response: WireAttestGpuResponse =
        serde_json::from_slice(&raw).context("decode the AttestGpu response")?;

    let bundle = response
        .bundles
        .into_iter()
        .find(|bundle| {
            bundle.vendor.eq_ignore_ascii_case(NVIDIA_VENDOR)
                && bundle.format == NVIDIA_COLLECT_EVIDENCE_FORMAT
        })
        .context("the guest agent returned no fresh NVIDIA GPU evidence")?;
    let evidence_json = hex::decode(bundle.evidence.trim_start_matches("0x"))
        .context("the GPU evidence bundle is not hex")?;
    let gpus: Vec<NvidiaGpuEvidence> =
        serde_json::from_slice(&evidence_json).context("decode the NVIDIA GPU evidence list")?;

    let gpu = gpus
        .into_iter()
        .find(|gpu| gpu.nonce.trim_start_matches("0x").eq_ignore_ascii_case(&requested))
        .context("no GPU answered the requested nonce")?;
    let report = STANDARD
        .decode(gpu.evidence.trim())
        .context("the GPU attestation report is not base64")?;
    if report.is_empty() {
        bail!("the guest agent returned an empty GPU report");
    }
    let certificate_chain = certificate_chain(&gpu.certificate)?;
    Ok(GpuEvidence {
        report,
        certificate_chain,
    })
}

#[derive(Deserialize)]
struct WireAttestGpuResponse {
    #[serde(default)]
    bundles: Vec<WireGpuBundle>,
}

#[derive(Deserialize)]
struct WireGpuBundle {
    vendor: String,
    format: String,
    evidence: String,
}

/// One GPU's record from the evidence array. `arch` rides along in the JSON and
/// is ignored here; the verifier reads the device off the certificate chain.
#[derive(Deserialize)]
struct NvidiaGpuEvidence {
    nonce: String,
    evidence: String,
    certificate: String,
}

/// NVIDIA carries the chain as a PEM bundle, which the SDK percent-encodes when
/// it travels in a request body. Both forms are accepted; a bare base64 DER
/// with no armour is taken as a single certificate.
fn certificate_chain(certificate: &str) -> anyhow::Result<Vec<String>> {
    let pem = percent_decode(certificate);
    if pem.contains("-----BEGIN CERTIFICATE-----") {
        return crate::attestation::split_chain(&pem);
    }
    let der: String = pem.split_whitespace().collect();
    if der.is_empty() {
        bail!("the GPU evidence carries no certificate chain");
    }
    STANDARD
        .decode(&der)
        .context("the GPU certificate is not valid base64")?;
    Ok(vec![der])
}

/// Decodes `%XX` escapes and leaves everything else untouched. A string with no
/// `%` is returned as is, so the common plain-PEM case pays nothing.
fn percent_decode(input: &str) -> String {
    if !input.contains('%') {
        return input.to_owned();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One HTTP/1.1 POST over the unix socket. The guest agent answers a single
/// JSON body and closes cleanly, so the response is read to the end of the
/// stream and the head split off at the header boundary.
async fn rpc(socket: &Path, path: &str, body: &str, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .context("connect to the dstack guest agent")?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: dstack\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() > MAX_RESPONSE_BYTES {
            bail!("the guest agent answered more than {MAX_RESPONSE_BYTES} bytes");
        }
        anyhow::Ok(response)
    };
    let response = tokio::time::timeout(timeout, exchange)
        .await
        .context("the guest agent did not answer in time")??;

    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("the guest agent answered without headers")?;
    let head =
        std::str::from_utf8(&response[..boundary]).context("response headers are not ASCII")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .context("response carries no status")?;
    if status != "200" {
        bail!("the guest agent answered HTTP {status}");
    }
    let mut payload = &response[boundary + 4..];
    // The agent may answer chunked; a single-chunk body is the practical case
    // and anything else still parses because JSON delimits itself.
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        payload = unchunk(payload)?;
    }
    Ok(payload.to_vec())
}

/// Joins chunked transfer coding in place. The guest agent sends one or two
/// chunks; this handles any count and refuses a body that does not follow
/// the framing.
fn unchunk(body: &[u8]) -> anyhow::Result<&[u8]> {
    // Single chunk is the practical case: size line, payload, then "0\r\n".
    let first_break = body
        .windows(2)
        .position(|window| window == b"\r\n")
        .context("chunked body without a size line")?;
    let size = usize::from_str_radix(
        std::str::from_utf8(&body[..first_break]).context("chunk size is not ASCII")?,
        16,
    )
    .context("chunk size is not hex")?;
    let start = first_break + 2;
    let end = start + size;
    if body.len() < end {
        bail!("chunked body is shorter than its size line");
    }
    Ok(&body[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunked_body_yields_its_first_chunk() {
        let body = b"a\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(unchunk(body).unwrap(), b"0123456789");
        assert!(unchunk(b"zz\r\nnope").is_err());
        assert!(unchunk(b"ff\r\nshort").is_err());
    }

    #[test]
    fn percent_decode_touches_only_escapes() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("done%"), "done%");
    }

    #[test]
    fn a_percent_encoded_pem_chain_is_decoded_and_split() {
        let leaf = STANDARD.encode([0x30, 0x82, 0x01, 0x02]);
        let root = STANDARD.encode([0x30, 0x82, 0x03, 0x04]);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{leaf}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{root}\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(certificate_chain(&pem).unwrap(), vec![leaf.clone(), root.clone()]);
        assert_eq!(
            certificate_chain(&pem.replace('\n', "%0A")).unwrap(),
            vec![leaf, root]
        );
    }

    #[test]
    fn a_bare_base64_certificate_is_one_entry_and_junk_is_refused() {
        let der = STANDARD.encode([0x30, 0x82, 0x05, 0x06]);
        assert_eq!(certificate_chain(&der).unwrap(), vec![der.clone()]);
        assert!(certificate_chain("   ").is_err());
        assert!(certificate_chain("not base64!!!").is_err());
    }
}
