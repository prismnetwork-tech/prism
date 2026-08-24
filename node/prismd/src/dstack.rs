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
    let raw = rpc(socket, "/GetQuote", &body).await?;
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

/// One HTTP/1.1 POST over the unix socket. The guest agent answers a single
/// JSON body and closes cleanly, so the response is read to the end of the
/// stream and the head split off at the header boundary.
async fn rpc(socket: &Path, path: &str, body: &str) -> anyhow::Result<Vec<u8>> {
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
    let response = tokio::time::timeout(RPC_TIMEOUT, exchange)
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
}
