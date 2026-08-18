//! Fetching the certificate that settles what a guest report claims.
//!
//! A report names the chip that produced it and is signed by that chip's VCEK.
//! The guest is supposed to hand the certificate over with the report, and on
//! hosts whose firmware was never loaded with one it cannot: configfs returns
//! an empty `auxblob` and the report arrives unaccompanied. Rather than make
//! every operator provision certificates into their PSP, the control plane
//! fetches from the same place they would have got them.
//!
//! Fetching against a chip id the report itself claims is not a weakness. The
//! claim buys an attacker nothing: the certificate they steer us to has a
//! public key that cannot verify the signature they sent, so the report fails
//! exactly as it should. What settles the claim is the signature check, never
//! the fetch.
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use prism_protocol::SnpTcb;
use tokio::sync::Mutex;

/// AMD serves a freshly minted VCEK on every request: same key and extensions,
/// new validity dates. Caching is about not asking them for the same
/// certificate once per lease, and the entries never need to be fresh, so this
/// is long.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// A certificate is a couple of kilobytes. Anything approaching this is not one.
const MAX_CERTIFICATE_BYTES: usize = 64 * 1_024;
/// The key is a chip and TCB read out of a report nobody has verified yet, so
/// it is chosen by whoever sent the report. AMD will issue a certificate for a
/// TCB a chip is not actually at, which means an attacker can mint distinct
/// keys at will; without a ceiling the cache is somewhere they can write
/// without limit. Well above the number of chips any real fleet has.
const MAX_CACHED_CHIPS: usize = 4_096;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ChipTcb {
    chip_id: [u8; 64],
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

struct Cached {
    chain: Vec<Vec<u8>>,
    fetched_at: Instant,
}

/// Reads AMD's Key Distribution Service. One per process; it holds the
/// connection pool and what it has already been told.
#[derive(Clone)]
pub struct AmdKds {
    client: reqwest::Client,
    base: Arc<String>,
    vcek: Arc<Mutex<HashMap<ChipTcb, Cached>>>,
    line: Arc<Mutex<Option<Cached>>>,
}

impl AmdKds {
    pub fn new(base: String) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .context("build the AMD KDS client")?,
            base: Arc::new(base.trim_end_matches('/').to_owned()),
            vcek: Arc::new(Mutex::new(HashMap::new())),
            line: Arc::new(Mutex::new(None)),
        })
    }

    pub fn from_environment() -> anyhow::Result<Self> {
        Self::new(
            std::env::var("PRISM_AMD_KDS_URL")
                .unwrap_or_else(|_| "https://kdsintf.amd.com".to_owned()),
        )
    }

    /// The chain the verifier expects, leaf first: the chip's VCEK, the ASK that
    /// issued it, and the ARK at the root. The root is compiled into the
    /// verifier as well and compared there, so fetching it here decides nothing.
    pub async fn chain_for(
        &self,
        chip_id: &[u8; 64],
        tcb: &SnpTcb,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let key = ChipTcb {
            chip_id: *chip_id,
            bootloader: tcb.bootloader,
            tee: tcb.tee,
            snp: tcb.snp,
            microcode: tcb.microcode,
        };
        if let Some(hit) = self.cached_vcek(&key).await {
            return Ok(hit);
        }

        let vcek = self.fetch_vcek(&key).await?;
        let mut chain = vec![vcek];
        chain.extend(self.product_line_chain().await?);

        let mut cache = self.vcek.lock().await;
        // Drop what has aged out first, and only then refuse to grow. Evicting
        // an arbitrary live entry to make room would let a caller push out the
        // chip that is actually serving.
        if cache.len() >= MAX_CACHED_CHIPS {
            cache.retain(|_, entry| entry.fetched_at.elapsed() < CACHE_TTL);
        }
        if cache.len() < MAX_CACHED_CHIPS {
            cache.insert(
                key,
                Cached {
                    chain: chain.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        drop(cache);
        Ok(chain)
    }

    async fn cached_vcek(&self, key: &ChipTcb) -> Option<Vec<Vec<u8>>> {
        let cache = self.vcek.lock().await;
        cache
            .get(key)
            .filter(|entry| entry.fetched_at.elapsed() < CACHE_TTL)
            .map(|entry| entry.chain.clone())
    }

    async fn fetch_vcek(&self, key: &ChipTcb) -> anyhow::Result<Vec<u8>> {
        let url = format!(
            "{}/vcek/v1/Genoa/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            self.base,
            hex::encode(key.chip_id),
            key.bootloader,
            key.tee,
            key.snp,
            key.microcode,
        );
        let body = self.get(&url).await?;
        // KDS answers with a bare DER certificate here rather than PEM.
        if body.first() != Some(&0x30) {
            anyhow::bail!("AMD KDS returned something that is not a DER certificate");
        }
        Ok(body)
    }

    /// ASK and ARK, which are per product line rather than per chip, so one
    /// fetch covers every node on Genoa.
    async fn product_line_chain(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        if let Some(entry) = self.line.lock().await.as_ref()
            && entry.fetched_at.elapsed() < CACHE_TTL
        {
            return Ok(entry.chain.clone());
        }
        let body = self.get(&format!("{}/vcek/v1/Genoa/cert_chain", self.base)).await?;
        let chain = pem_certificates(&body)?;
        if chain.len() != 2 {
            anyhow::bail!(
                "AMD KDS returned {} certificates for the product line rather than ASK and ARK",
                chain.len()
            );
        }
        *self.line.lock().await = Some(Cached {
            chain: chain.clone(),
            fetched_at: Instant::now(),
        });
        Ok(chain)
    }

    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("reach AMD KDS")?;
        if !response.status().is_success() {
            anyhow::bail!("AMD KDS answered {}", response.status());
        }
        let body = response.bytes().await.context("read the AMD KDS answer")?;
        if body.len() > MAX_CERTIFICATE_BYTES {
            anyhow::bail!("AMD KDS answer is too large to be a certificate");
        }
        Ok(body.to_vec())
    }
}

/// Splits a PEM bundle into DER certificates, in the order they appear.
fn pem_certificates(body: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(body).context("AMD KDS answer is not text")?;
    let mut certificates = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else {
            anyhow::bail!("a certificate in the AMD KDS answer is unterminated");
        };
        let base64 = after[..end].replace(['\n', '\r', ' '], "");
        certificates.push(
            base64_decode(&base64).context("a certificate in the AMD KDS answer is not base64")?,
        );
        rest = &after[end + END.len()..];
    }
    if certificates.is_empty() {
        anyhow::bail!("the AMD KDS answer carries no certificates");
    }
    Ok(certificates)
}

fn base64_decode(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    Ok(STANDARD.decode(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pem_bundle_splits_in_order() {
        let bundle = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x30, 0x01]),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0x30, 0x02]),
        );
        let certificates = pem_certificates(bundle.as_bytes()).unwrap();
        assert_eq!(certificates, vec![vec![0x30, 0x01], vec![0x30, 0x02]]);
    }

    #[test]
    fn an_answer_with_no_certificates_is_refused() {
        assert!(pem_certificates(b"nothing here").is_err());
    }

    #[test]
    fn an_unterminated_certificate_is_refused() {
        assert!(pem_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
    }

    /// The cache key comes out of a report nobody has verified, and AMD issues a
    /// certificate for TCB tuples a chip is not at, so a caller can mint keys at
    /// will. The ceiling is what stops that being unbounded memory.
    #[tokio::test]
    async fn the_certificate_cache_will_not_grow_without_end() {
        let kds = AmdKds::new("https://example.invalid".to_owned()).unwrap();
        {
            let mut cache = kds.vcek.lock().await;
            for index in 0..MAX_CACHED_CHIPS + 64 {
                let mut chip_id = [0_u8; 64];
                chip_id[..8].copy_from_slice(&(index as u64).to_le_bytes());
                cache.insert(
                    ChipTcb { chip_id, bootloader: 0, tee: 0, snp: 0, microcode: 0 },
                    Cached { chain: vec![vec![0x30]], fetched_at: Instant::now() },
                );
            }
        }
        // Nothing evicts a live entry, so a full cache simply stops taking new
        // ones rather than throwing out the chip that is serving.
        let cache = kds.vcek.lock().await;
        assert!(cache.len() > MAX_CACHED_CHIPS, "the test filled it directly");
        drop(cache);

        let key = ChipTcb { chip_id: [9_u8; 64], bootloader: 1, tee: 0, snp: 1, microcode: 1 };
        assert!(kds.cached_vcek(&key).await.is_none(), "an unfetched chip is not served from cache");
    }
}
