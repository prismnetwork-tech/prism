//! Vectors over a genuine TDX quote.
//!
//! The quote and its collateral are vendored from Phala's dcap-qvl repository
//! (sample/tdx_quote, sample/tdx_quote_collateral.json). Intel signed the
//! quote and the collateral, so unlike the NVIDIA and SNP vectors nothing
//! here is fabricated; the price of that is a fixed clock, because the
//! collateral's revocation lists expired in July 2025 and verification at the
//! real time refuses it, which is itself one of the things asserted below.

use chrono::{DateTime, TimeZone, Utc};
use prism_attestation::{
    Policy, TDX_VERIFIER_VERSION, TdxLaunchIdentity, VerificationError, verify_tdx_attestation,
};
use prism_protocol::{AttestationKind, HostTeeCapability, NodeAttestation, TrustClass};

const QUOTE: &[u8] = include_bytes!("fixtures/tdx/quote.bin");
const COLLATERAL: &str = include_str!("fixtures/tdx/collateral.json");

const MR_TD: &str = "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7";
const RTMR0: &str = "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0";
const RTMR1: &str = "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378";
const RTMR2: &str = "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132";
const REPORT_DATA: &str = "9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20";

/// Inside the collateral's validity window; the TCB info it carries ran out on
/// 2025-07-19.
fn vector_time() -> DateTime<Utc> {
    Utc.timestamp_opt(1_751_000_000, 0).unwrap()
}

fn digest48(hexed: &str) -> [u8; 48] {
    hex::decode(hexed).unwrap().try_into().unwrap()
}

fn expected_report_data() -> [u8; 64] {
    hex::decode(REPORT_DATA).unwrap().try_into().unwrap()
}

fn quote_identity() -> TdxLaunchIdentity {
    TdxLaunchIdentity {
        mr_td: digest48(MR_TD),
        rtmr0: digest48(RTMR0),
        rtmr1: digest48(RTMR1),
        rtmr2: digest48(RTMR2),
    }
}

fn attestation() -> NodeAttestation {
    use base64::Engine as _;
    NodeAttestation {
        node_id: "0xtdxnode".into(),
        challenge_id: uuid::Uuid::nil(),
        kind: AttestationKind::Tdx,
        evidence_base64: base64::engine::general_purpose::STANDARD.encode(QUOTE),
        certificate_chain_base64: Vec::new(),
        capability: HostTeeCapability::default(),
        pci_address: String::new(),
        collected_at: vector_time(),
        signature: String::new(),
    }
}

fn accepting_policy() -> Policy {
    Policy::for_tests().with_tdx_test_identities(vec![quote_identity()])
}

#[test]
fn a_genuine_quote_verifies_and_earns_attested() {
    let verdict = verify_tdx_attestation(
        &attestation(),
        COLLATERAL,
        &expected_report_data(),
        vector_time(),
        &accepting_policy(),
    )
    .expect("vendored quote");

    assert_eq!(verdict.kind, AttestationKind::Tdx);
    assert_eq!(verdict.granted_class, TrustClass::Attested);
    assert_eq!(verdict.verifier_version, TDX_VERIFIER_VERSION);
    assert_eq!(verdict.device_identity, format!("tdx/{MR_TD}"));
    assert_eq!(verdict.node_id, "0xtdxnode");
}

/// The same quote at today's clock refuses, because the collateral's
/// revocation lists have run out. Stale collateral is indistinguishable from
/// collateral chosen to hide a revocation, so there is no grace here.
#[test]
fn expired_collateral_refuses_the_quote() {
    let now = Utc.timestamp_opt(1_787_000_000, 0).unwrap();
    let refused = verify_tdx_attestation(
        &attestation(),
        COLLATERAL,
        &expected_report_data(),
        now,
        &accepting_policy(),
    );
    assert_eq!(refused, Err(VerificationError::TdxQuoteRejected));
}

#[test]
fn report_data_binds_the_challenge() {
    let mut wrong = expected_report_data();
    wrong[0] ^= 1;
    let refused = verify_tdx_attestation(
        &attestation(),
        COLLATERAL,
        &wrong,
        vector_time(),
        &accepting_policy(),
    );
    assert_eq!(refused, Err(VerificationError::TdxReportDataMismatch));
}

/// The compiled reference set is empty, and empty refuses everything: a
/// genuine, current, correctly bound quote still earns nothing until a
/// reproduced launch identity is on file.
#[test]
fn the_shipped_reference_set_refuses_a_genuine_quote() {
    let refused = verify_tdx_attestation(
        &attestation(),
        COLLATERAL,
        &expected_report_data(),
        vector_time(),
        &Policy::for_tests(),
    );
    assert_eq!(refused, Err(VerificationError::TdxUnknownLaunchMeasurement));
}

#[test]
fn a_launch_identity_matches_as_a_whole_or_not_at_all() {
    let mut identity = quote_identity();
    identity.rtmr1[0] ^= 1;
    let refused = verify_tdx_attestation(
        &attestation(),
        COLLATERAL,
        &expected_report_data(),
        vector_time(),
        &Policy::for_tests().with_tdx_test_identities(vec![identity]),
    );
    assert_eq!(refused, Err(VerificationError::TdxUnknownLaunchMeasurement));
}

#[test]
fn a_truncated_quote_is_rejected() {
    use base64::Engine as _;
    let mut attestation = attestation();
    attestation.evidence_base64 =
        base64::engine::general_purpose::STANDARD.encode(&QUOTE[..QUOTE.len() / 2]);
    let refused = verify_tdx_attestation(
        &attestation,
        COLLATERAL,
        &expected_report_data(),
        vector_time(),
        &accepting_policy(),
    );
    assert_eq!(refused, Err(VerificationError::TdxQuoteRejected));
}

#[test]
fn malformed_collateral_is_its_own_refusal() {
    let refused = verify_tdx_attestation(
        &attestation(),
        "{\"not\": \"collateral\"}",
        &expected_report_data(),
        vector_time(),
        &accepting_policy(),
    );
    assert_eq!(refused, Err(VerificationError::TdxCollateralMalformed));
}

#[test]
fn evidence_of_another_kind_is_malformed_here() {
    let mut attestation = attestation();
    attestation.kind = AttestationKind::SevSnp;
    let refused = verify_tdx_attestation(
        &attestation,
        COLLATERAL,
        &expected_report_data(),
        vector_time(),
        &accepting_policy(),
    );
    assert_eq!(refused, Err(VerificationError::MalformedEvidence));
}
