//! Intel DCAP collateral, fetched from a PCCS the way the verifier expects it.
//!
//! A TDX quote verifies against collateral: TCB info and QE identity for the
//! platform that produced it, plus the certificate revocation lists. All of
//! it is Intel-signed and time-windowed, so who fetches it does not matter to
//! the trust story; this crate exists so a node can fetch its own and carry
//! it to the control plane, which verifies offline.
//!
//! The output is the JSON form of dcap-qvl's `QuoteCollateralV3`, assembled
//! field by field from Intel's PCS v4 endpoints. The field encodings (issuer
//! chains percent-decoded, CRLs and signatures hex, TCB info and QE identity
//! as the raw inner JSON) mirror what dcap-qvl's own fetcher produces, and
//! the tests hold this crate's parsing against a collateral bundle that
//! fetcher captured.

use std::time::Duration;

use anyhow::{Context, bail};
use dcap_qvl::quote::Quote;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Phala's public PCCS mirror. Any PCCS or Intel's PCS works; this is the
/// default because dstack platforms already provision against it.
pub const PHALA_PCCS_URL: &str = "https://pccs.phala.network";

/// The certification data type that embeds a PCK certificate chain in the
/// quote. dstack quotes carry it; anything else would need a PCK fetch this
/// crate deliberately does not implement.
const PCK_CERT_CHAIN: u16 = 5;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// No single collateral piece approaches this; a response that does is not
/// the endpoint answering.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct PccsClient {
    http: reqwest::Client,
    base: String,
}

impl PccsClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base = base_url
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_owned();
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(REQUEST_TIMEOUT)
                .build()
                .context("build the PCCS client")?,
            base,
        })
    }

    /// Fetches the collateral this quote verifies against and returns it as
    /// the JSON the verifier deserializes.
    pub async fn collateral_for(&self, quote: &[u8]) -> anyhow::Result<String> {
        let parsed = Quote::parse(quote).context("parse the quote")?;
        if parsed.inner_cert_type() != PCK_CERT_CHAIN {
            bail!(
                "quote certification data is type {}, not an embedded PCK chain",
                parsed.inner_cert_type()
            );
        }
        let pck_chain = String::from_utf8(parsed.inner_cert_data().to_vec())
            .context("PCK chain is not UTF-8 PEM")?;
        let (fmspc, ca) = fmspc_and_ca(&pck_chain)?;
        let tee = if parsed.header.is_sgx() { "sgx" } else { "tdx" };

        let (pck_crl, pck_crl_issuer_chain) = self
            .get_with_chain(
                &self.url("sgx", &format!("pckcrl?ca={ca}&encoding=der")),
                "SGX-PCK-CRL-Issuer-Chain",
            )
            .await?;
        let (tcb_body, tcb_info_issuer_chain) = self
            .get_with_chain(
                &self.url(tee, &format!("tcb?fmspc={fmspc}")),
                "TCB-Info-Issuer-Chain",
            )
            .await?;
        let (qe_body, qe_identity_issuer_chain) = self
            .get_with_chain(
                &self.url(tee, "qe/identity?update=standard"),
                "SGX-Enclave-Identity-Issuer-Chain",
            )
            .await?;
        // A PCCS serves the root CRL hex-encoded; Intel's PCS does not serve
        // it at all, and there the root certificate's own distribution point
        // is the source.
        let root_ca_crl = match self.get(&self.url("sgx", "rootcacrl")).await {
            Ok((body, _)) => {
                let hexed = String::from_utf8(body).context("root CA CRL is not hex text")?;
                hex::decode(hexed.trim()).context("root CA CRL is not hex")?
            }
            Err(_) => {
                let url = root_crl_distribution_point(&qe_identity_issuer_chain)?;
                self.get(&url).await.context("fetch the root CA CRL")?.0
            }
        };

        let (tcb_info, tcb_info_signature) = split_signed(&tcb_body, "tcbInfo")?;
        let (qe_identity, qe_identity_signature) = split_signed(&qe_body, "enclaveIdentity")?;

        Ok(serde_json::json!({
            "pck_crl_issuer_chain": pck_crl_issuer_chain,
            "root_ca_crl": hex::encode(root_ca_crl),
            "pck_crl": hex::encode(pck_crl),
            "tcb_info_issuer_chain": tcb_info_issuer_chain,
            "tcb_info": tcb_info,
            "tcb_info_signature": hex::encode(tcb_info_signature),
            "qe_identity_issuer_chain": qe_identity_issuer_chain,
            "qe_identity": qe_identity,
            "qe_identity_signature": hex::encode(qe_identity_signature),
        })
        .to_string())
    }

    fn url(&self, tee: &str, path: &str) -> String {
        format!("{}/{tee}/certification/v4/{path}", self.base)
    }

    async fn get(&self, url: &str) -> anyhow::Result<(Vec<u8>, reqwest::header::HeaderMap)> {
        let response = self.http.get(url).send().await?;
        if !response.status().is_success() {
            bail!("{url} answered HTTP {}", response.status());
        }
        let headers = response.headers().clone();
        let body = response.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            bail!(
                "{url} answered {} bytes, which no collateral is",
                body.len()
            );
        }
        Ok((body.to_vec(), headers))
    }

    async fn get_with_chain(&self, url: &str, header: &str) -> anyhow::Result<(Vec<u8>, String)> {
        let (body, headers) = self.get(url).await?;
        let raw = headers
            .get(header)
            .or_else(|| headers.get(format!("SGX-{header}")))
            .with_context(|| format!("{url} answered without {header}"))?
            .to_str()
            .with_context(|| format!("{header} is not ASCII"))?;
        Ok((body, percent_decode(raw)?))
    }
}

/// FMSPC (upper hex) and PCK CA type from the leaf certificate of the chain
/// the quote embeds. The FMSPC lives inside Intel's SGX extension as its own
/// OID; the CA type is written in the issuer's common name.
fn fmspc_and_ca(pem_chain: &str) -> anyhow::Result<(String, &'static str)> {
    let leaf = first_pem_certificate(pem_chain)?;
    let (_, certificate) = X509Certificate::from_der(&leaf).context("parse the PCK certificate")?;

    const SGX_EXTENSION: &str = "1.2.840.113741.1.13.1";
    const FMSPC_OID: &str = "1.2.840.113741.1.13.1.4";
    let extension = certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == SGX_EXTENSION)
        .context("PCK certificate carries no Intel SGX extension")?;
    let fmspc = find_octet_string(extension.value, FMSPC_OID)?;
    if fmspc.len() != 6 {
        bail!("FMSPC is {} bytes, not 6", fmspc.len());
    }

    let issuer = certificate.issuer().to_string();
    let ca = if issuer.contains("Platform") {
        "platform"
    } else {
        "processor"
    };
    Ok((hex::encode_upper(fmspc), ca))
}

/// Walks the SGX extension's DER (a SEQUENCE of OID/value pairs) for one OID
/// and returns its OCTET STRING content.
fn find_octet_string(der: &[u8], wanted: &str) -> anyhow::Result<Vec<u8>> {
    use x509_parser::der_parser::ber::BerObjectContent;
    use x509_parser::der_parser::der::parse_der;

    let (_, root) = parse_der(der).context("parse the Intel SGX extension")?;
    let entries = root
        .as_sequence()
        .context("Intel SGX extension is not a sequence")?;
    for entry in entries {
        let Ok(pair) = entry.as_sequence() else {
            continue;
        };
        let [oid, value] = pair.as_slice() else {
            continue;
        };
        let Ok(oid) = oid.as_oid() else { continue };
        if oid.to_id_string() != wanted {
            continue;
        }
        if let BerObjectContent::OctetString(content) = &value.content {
            return Ok(content.to_vec());
        }
        bail!("{wanted} is not an OCTET STRING");
    }
    bail!("{wanted} is not in the Intel SGX extension");
}

fn first_pem_certificate(pem_chain: &str) -> anyhow::Result<Vec<u8>> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem_chain.as_bytes()).context("PCK chain is not PEM")?;
    Ok(pem.contents)
}

/// The root certificate is the last in the issuer chain, and its CRL
/// distribution point is where Intel publishes the root CRL.
fn root_crl_distribution_point(issuer_chain: &str) -> anyhow::Result<String> {
    use x509_parser::prelude::ParsedExtension;

    let mut rest = issuer_chain.as_bytes();
    let mut last = None;
    while let Ok((remaining, pem)) = x509_parser::pem::parse_x509_pem(rest) {
        last = Some(pem.contents);
        rest = remaining;
    }
    let root = last.context("issuer chain carries no certificates")?;
    let (_, certificate) = X509Certificate::from_der(&root).context("parse the root")?;
    for extension in certificate.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() {
            for point in &points.points {
                if let Some(x509_parser::prelude::DistributionPointName::FullName(names)) =
                    &point.distribution_point
                {
                    for name in names {
                        if let x509_parser::prelude::GeneralName::URI(uri) = name {
                            return Ok((*uri).to_owned());
                        }
                    }
                }
            }
        }
    }
    bail!("the root certificate names no CRL distribution point");
}

/// TCB info and QE identity arrive as {"<inner>": {...}, "signature": hex};
/// the verifier wants the inner document exactly as signed, so it is cut out
/// of the raw body rather than re-serialized.
fn split_signed(body: &[u8], inner_key: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("signed collateral is not JSON")?;
    let inner = value
        .get(inner_key)
        .with_context(|| format!("signed collateral carries no {inner_key}"))?;
    let signature = value
        .get("signature")
        .and_then(|signature| signature.as_str())
        .context("signed collateral carries no signature")?;
    Ok((
        inner.to_string(),
        hex::decode(signature).context("collateral signature is not hex")?,
    ))
}

fn percent_decode(encoded: &str) -> anyhow::Result<String> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .context("truncated percent escape")?;
                let value = u8::from_str_radix(
                    std::str::from_utf8(pair).context("percent escape is not ASCII")?,
                    16,
                )
                .context("percent escape is not hex")?;
                decoded.push(value);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).context("decoded header is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_QUOTE: &[u8] = include_bytes!("../../attestation/tests/fixtures/tdx/live-quote.bin");
    const LIVE_COLLATERAL: &str =
        include_str!("../../attestation/tests/fixtures/tdx/live-collateral.json");

    /// The FMSPC this crate reads out of the live quote has to be the one the
    /// captured collateral was actually served for, or every fetch built from
    /// it would come back for the wrong platform.
    #[test]
    fn the_live_quote_yields_the_fmspc_its_collateral_names() {
        let parsed = Quote::parse(LIVE_QUOTE).expect("live quote");
        assert_eq!(parsed.inner_cert_type(), PCK_CERT_CHAIN);
        assert!(!parsed.header.is_sgx());

        let chain = String::from_utf8(parsed.inner_cert_data().to_vec()).expect("PEM chain");
        let (fmspc, ca) = fmspc_and_ca(&chain).expect("fmspc");

        let collateral: serde_json::Value = serde_json::from_str(LIVE_COLLATERAL).unwrap();
        let tcb_info: serde_json::Value =
            serde_json::from_str(collateral["tcb_info"].as_str().unwrap()).unwrap();
        assert_eq!(
            fmspc.to_lowercase(),
            tcb_info["fmspc"].as_str().unwrap().to_lowercase()
        );
        assert!(ca == "platform" || ca == "processor");
    }

    /// The captured collateral is the exact JSON shape this crate assembles,
    /// so its field set is the contract: a drift in either shows up here.
    #[test]
    fn the_assembled_shape_matches_what_the_verifier_consumed() {
        let collateral: serde_json::Value = serde_json::from_str(LIVE_COLLATERAL).unwrap();
        for field in [
            "pck_crl_issuer_chain",
            "root_ca_crl",
            "pck_crl",
            "tcb_info_issuer_chain",
            "tcb_info",
            "tcb_info_signature",
            "qe_identity_issuer_chain",
            "qe_identity",
            "qe_identity_signature",
        ] {
            assert!(collateral.get(field).is_some(), "{field} missing");
        }
    }

    #[test]
    fn percent_decoding_round_trips_a_pem_header() {
        assert_eq!(
            percent_decode("-----BEGIN%20CERTIFICATE-----%0A").unwrap(),
            "-----BEGIN CERTIFICATE-----\n"
        );
        assert!(percent_decode("%zz").is_err());
        assert!(percent_decode("%a").is_err());
    }

    #[test]
    fn signed_documents_split_into_inner_and_signature() {
        let body = br#"{"tcbInfo":{"fmspc":"90c06f000000"},"signature":"aabb"}"#;
        let (inner, signature) = split_signed(body, "tcbInfo").unwrap();
        assert_eq!(inner, r#"{"fmspc":"90c06f000000"}"#);
        assert_eq!(signature, vec![0xaa, 0xbb]);
        assert!(split_signed(body, "enclaveIdentity").is_err());
    }
}
