//! Verification of hardware attestation for the Prism control plane.
//!
//! Two verifiers live here. The NVIDIA one reads a device report and says which
//! physical GPU answered and what firmware it runs. The SEV-SNP one reads a
//! report a guest took of itself and says what image that VM was launched from,
//! on which processor, at which patch level.
//!
//! The crate is a pure function over bytes: no network, no clock, no I/O beyond
//! the vendor roots and the reference values compiled into it. Either every
//! check passes and the evidence earns a class, or nothing is returned at all.
//! There is no path that yields a verdict on partial evidence.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use p384::elliptic_curve::subtle::ConstantTimeEq;
use prism_protocol::{
    AttestationKind, AttestationVerdict, AttestedGuest, GuestAttestation, LeaseAttestationVerdict,
    NodeAttestation, TrustClass,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod amd;
mod chain;
mod nvidia;
mod policy;
mod snp;

pub use policy::Policy;

#[cfg(any(test, feature = "test-vectors"))]
pub use nvidia::ReportBuilder;
#[cfg(any(test, feature = "test-vectors"))]
pub use snp::SnpReportBuilder;

/// Bumped whenever a check changes, so a verdict recorded by an older verifier
/// can be told apart from one this build would issue today.
pub const VERIFIER_VERSION: &str = "nvidia-gpu/1";
pub const SNP_VERIFIER_VERSION: &str = "sev-snp-guest/1";

/// A device report proves which GPU signed it and what firmware that GPU runs.
/// It says nothing about what host software booted, so GPU evidence stops at
/// Isolated however good it is.
pub const MAX_GRANTABLE_CLASS: TrustClass = TrustClass::Isolated;

/// A verified guest report proves what image the VM was launched from, on a
/// genuine processor at or above a pinned patch level, with host debug off. It
/// does not prove what the host software is, and it does not cover the GPU: the
/// tensors cross into shared bounce buffers on their way to the card, so this
/// is integrity of what booted and not confidentiality of what is computed.
/// That is Attested and no further.
///
/// What the network actually serves is clamped separately, in
/// [`prism_protocol::class_for_lease`]. This constant says what the evidence
/// earns; that one says what the network can substantiate.
pub const SNP_GRANTABLE_CLASS: TrustClass = TrustClass::Attested;

/// Vendor chains are short. Anything longer is either a mistake or an attempt
/// to make the walk expensive.
const MAX_CHAIN_CERTIFICATES: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("attestation evidence is malformed")]
    MalformedEvidence,
    #[error("certificate could not be parsed")]
    MalformedCertificate,
    #[error("certificate chain is longer than {MAX_CHAIN_CERTIFICATES} certificates")]
    ChainTooLong,
    #[error("certificate chain does not link up")]
    BrokenChain,
    #[error("certificate chain does not anchor at the pinned vendor root")]
    UntrustedRoot,
    #[error("certificate is outside its validity window")]
    CertificateExpired,
    #[error("signature algorithm is not ecdsa-with-SHA384")]
    WrongSignatureAlgorithm,
    #[error("device report signature does not verify under the leaf key")]
    ReportSignatureInvalid,
    #[error("device report answers a different nonce")]
    NonceMismatch,
    #[error("device report carries a measurement that is not in the reference set")]
    UnknownMeasurement,
    #[error("device is not an H100")]
    UnsupportedDevice,
    #[error("SEV-SNP report is not exactly 1184 bytes")]
    SnpReportWrongSize,
    #[error("SEV-SNP report is not the ABI version this verifier decodes")]
    SnpReportVersionUnsupported,
    #[error("SEV-SNP report is not signed with ecdsa-p384-sha384")]
    SnpReportSignatureAlgorithm,
    #[error("SEV-SNP report was not signed by a VCEK")]
    SnpReportNotVcekSigned,
    #[error("SEV-SNP signature field carries bytes above the low 48")]
    SnpSignatureFieldOutOfRange,
    #[error("SEV-SNP report signature does not verify under the VCEK key")]
    SnpReportSignatureInvalid,
    #[error("AMD chain is not VCEK, ASK, ARK")]
    SnpChainShape,
    #[error("AMD certificate could not be parsed")]
    SnpMalformedCertificate,
    #[error("AMD certificate is outside its validity window")]
    SnpCertificateExpired,
    #[error("AMD certificate is not signed with RSASSA-PSS over SHA-384")]
    SnpChainAlgorithm,
    #[error("AMD certificate key is not the pinned size")]
    SnpChainKeySize,
    #[error("AMD chain does not link up")]
    SnpChainBroken,
    #[error("AMD chain does not anchor at the pinned ARK")]
    SnpUntrustedRoot,
    #[error("VCEK is missing an AMD extension this verifier requires")]
    SnpVcekExtensionMissing,
    #[error("VCEK carries an AMD extension this verifier cannot read")]
    SnpVcekExtensionMalformed,
    #[error("VCEK was issued to a different chip than the report names")]
    SnpVcekChipMismatch,
    #[error("VCEK was issued against a different TCB than the report claims")]
    SnpVcekTcbMismatch,
    #[error("SEV-SNP report answers different report data")]
    SnpReportDataMismatch,
    #[error("SEV-SNP report was launched with different host data")]
    SnpHostDataMismatch,
    #[error("SEV-SNP report names a chip this node is not bound to")]
    SnpChipMismatch,
    #[error("SEV-SNP report carries a launch measurement that is not in the reference set")]
    SnpUnknownLaunchMeasurement,
    #[error("SEV-SNP guest was launched with debug enabled")]
    SnpDebugPolicyEnabled,
    #[error("SEV-SNP guest was launched with a migration agent allowed")]
    SnpMigrationAgentAllowed,
    #[error("SEV-SNP guest policy is not the one the reference measurement belongs to")]
    SnpGuestPolicyMismatch,
    #[error("SEV-SNP report was taken at a different VMPL")]
    SnpWrongVmpl,
    #[error("SEV-SNP platform TCB is below the pinned floor")]
    SnpTcbBelowFloor,
    #[error("guest channel key is not an OpenSSH public key line")]
    SnpChannelKeyMalformed,
}

/// Verifies one GPU attestation and, on success, returns the class it earns.
///
/// `expected_report_nonce` is the caller's binding of its own challenge to this
/// node and this device key. Comparing it here is what makes a report captured
/// from another machine worthless.
pub fn verify_nvidia_gpu_attestation(
    attestation: &NodeAttestation,
    expected_report_nonce: &[u8; 32],
    now: DateTime<Utc>,
    policy: &Policy,
) -> Result<AttestationVerdict, VerificationError> {
    if attestation.kind != AttestationKind::NvidiaGpu {
        return Err(VerificationError::MalformedEvidence);
    }

    let evidence = decode_base64(&attestation.evidence_base64)?;
    let mut certificates = Vec::with_capacity(attestation.certificate_chain_base64.len());
    for encoded in &attestation.certificate_chain_base64 {
        certificates.push(decode_base64(encoded)?);
    }

    let chain = chain::verify_chain(&certificates, now, policy)?;
    nvidia::verify_report_signature(&evidence, &chain.leaf_public_key)?;

    let report = nvidia::parse_report(&evidence)?;
    if !bool::from(report.nonce.ct_eq(expected_report_nonce)) {
        return Err(VerificationError::NonceMismatch);
    }

    if report.vendor_id != nvidia::H100_VENDOR_ID || report.device_id != nvidia::H100_DEVICE_ID {
        return Err(VerificationError::UnsupportedDevice);
    }

    check_measurements(&report)?;

    Ok(AttestationVerdict {
        node_id: attestation.node_id.clone(),
        kind: AttestationKind::NvidiaGpu,
        device_identity: format!("{}/{}", chain.leaf_common_name, report.board_serial),
        measurement_digest: measurement_digest(&report),
        claimed_capability: attestation.capability,
        granted_class: MAX_GRANTABLE_CLASS,
        verifier_version: VERIFIER_VERSION.to_string(),
        verified_at: now,
        expires_at: now + policy.verdict_ttl,
    })
}

/// What the control plane already knows before it opens a report, and what the
/// report therefore has to say.
///
/// `report_data` is the only field the guest chooses. The caller derives it
/// with [`prism_protocol::snp_report_data`] from its own challenge, the lease
/// and the channel key the guest generated; comparing it here is what ties a
/// vendor signature to one renter's session. Nothing in this crate re-derives
/// it, so a caller that builds the expectation from something other than the
/// key line it received gets a verdict whose fingerprint means nothing.
///
/// `host_data` is the digest of the workload image, fixed by the host at launch
/// and immutable afterwards. It is only worth anything because the measured
/// guest agent refuses to run anything else.
///
/// `chip_id_digest` is present once a node has been seen on a chip, and absent
/// on the first report from it.
#[derive(Debug, Clone)]
pub struct SnpExpectation {
    pub report_data: [u8; 64],
    pub host_data: [u8; 32],
    pub chip_id_digest: Option<[u8; 32]>,
}

/// Verifies one guest's SEV-SNP report and, on success, returns what that lease
/// earns.
///
/// The checks are ordered so that nothing expensive runs on unauthenticated
/// input: the report is a fixed-size structure decoded without allocating, the
/// chain walk is what turns bytes into a key, and every comparison against the
/// expectation happens only after the report has been shown to come from the
/// chip the chain names.
pub fn verify_sev_snp_attestation(
    attestation: &GuestAttestation,
    expected: &SnpExpectation,
    now: DateTime<Utc>,
    policy: &Policy,
) -> Result<LeaseAttestationVerdict, VerificationError> {
    if attestation.kind != AttestationKind::SevSnp {
        return Err(VerificationError::MalformedEvidence);
    }

    let platform = policy::snp_platform();
    let channel_key_fingerprint = channel_key_fingerprint(&attestation.guest_channel_key)?;

    let raw = decode_base64(&attestation.report_base64)?;
    let report = snp::parse_report(&raw, platform.product_line)?;

    let mut certificates = Vec::with_capacity(attestation.certificate_chain_base64.len());
    for encoded in &attestation.certificate_chain_base64 {
        certificates.push(decode_base64(encoded)?);
    }
    let vcek = amd::verify_vcek_chain(&certificates, now, policy)?;

    if !bool::from(vcek.hwid.ct_eq(&report.chip_id)) {
        return Err(VerificationError::SnpVcekChipMismatch);
    }
    if vcek.tcb != report.reported_tcb {
        return Err(VerificationError::SnpVcekTcbMismatch);
    }

    snp::verify_report_signature(&raw, &report, &vcek.public_key)?;

    if !bool::from(report.report_data.ct_eq(&expected.report_data)) {
        return Err(VerificationError::SnpReportDataMismatch);
    }
    if !bool::from(report.host_data.ct_eq(&expected.host_data)) {
        return Err(VerificationError::SnpHostDataMismatch);
    }

    let chip_id_digest: [u8; 32] = Sha256::digest(report.chip_id).into();
    if let Some(bound) = expected.chip_id_digest
        && !bool::from(chip_id_digest.ct_eq(&bound))
    {
        return Err(VerificationError::SnpChipMismatch);
    }

    if !policy::snp_launch_measurements().contains(&report.measurement) {
        return Err(VerificationError::SnpUnknownLaunchMeasurement);
    }

    if report.policy.debug() {
        return Err(VerificationError::SnpDebugPolicyEnabled);
    }
    if report.policy.migrate_ma() {
        return Err(VerificationError::SnpMigrationAgentAllowed);
    }
    // The remaining launch bits decide which machine shape the published
    // measurement belongs to, so they have to be the ones it was computed for.
    // A reference file that asked for debug or migration refuses rather than
    // grants, which keeps the two checks above from being edited away.
    if platform.guest_policy.debug
        || platform.guest_policy.migrate_ma
        || report.policy.smt() != platform.guest_policy.smt
        || report.policy.single_socket() != platform.guest_policy.single_socket
    {
        return Err(VerificationError::SnpGuestPolicyMismatch);
    }

    if report.vmpl != platform.required_vmpl {
        return Err(VerificationError::SnpWrongVmpl);
    }

    // Reported TCB is the platform as it stands now; launch TCB is what it was
    // when this guest started. Checking only the first would let a VM that
    // launched on an unpatched platform pass because the host has since patched.
    for tcb in [
        &report.reported_tcb,
        &report.committed_tcb,
        &report.launch_tcb,
        &report.current_tcb,
    ] {
        if !snp::tcb_at_least(tcb, &platform.tcb_floor) {
            return Err(VerificationError::SnpTcbBelowFloor);
        }
    }

    Ok(LeaseAttestationVerdict {
        lease_id: attestation.lease_id,
        node_id: attestation.node_id.clone(),
        kind: AttestationKind::SevSnp,
        guest: AttestedGuest {
            measurement: hex::encode(report.measurement),
            host_data: hex::encode(report.host_data),
            chip_id_digest: hex::encode(chip_id_digest),
            reported_tcb: report.reported_tcb,
            policy_debug: report.policy.debug(),
            vmpl: report.vmpl,
            channel_key_fingerprint,
            image_digest: format!("sha256:{}", hex::encode(report.host_data)),
        },
        granted_class: SNP_GRANTABLE_CLASS,
        verifier_version: SNP_VERIFIER_VERSION.to_string(),
        verified_at: now,
        expires_at: now + policy.lease_verdict_ttl,
    })
}

/// The fingerprint `ssh-keygen -lf` prints for the same key, so a renter can
/// compare what the grant names against what their client is about to trust.
fn channel_key_fingerprint(key_line: &str) -> Result<String, VerificationError> {
    let blob = key_line
        .split_whitespace()
        .nth(1)
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .ok_or(VerificationError::SnpChannelKeyMalformed)?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&blob))
    ))
}

/// Every reported measurement has to match the reference set by name and
/// digest, and the report has to cover the whole set. A report that quietly
/// drops a measurement is as unrecognised as one that invents a value.
fn check_measurements(report: &nvidia::Report) -> Result<(), VerificationError> {
    let allowlist = policy::measurement_allowlist();
    let mut matched = BTreeSet::new();

    for measurement in &report.measurements {
        let accepted = allowlist
            .accepts(measurement.index, &measurement.digest)
            .ok_or(VerificationError::UnknownMeasurement)?;
        if !accepted {
            return Err(VerificationError::UnknownMeasurement);
        }
        matched.insert(measurement.index);
    }

    if matched.len() != allowlist.len() {
        return Err(VerificationError::UnknownMeasurement);
    }

    Ok(())
}

/// Sorted by name so two reports of the same device state hash the same
/// whatever order the driver emitted them in. The CC mode is folded in because
/// a GPU that flips confidential mode is in a different state, even when its
/// measurements are unchanged.
fn measurement_digest(report: &nvidia::Report) -> String {
    let mut measurements: Vec<&nvidia::Measurement> = report.measurements.iter().collect();
    measurements.sort_by_key(|measurement| measurement.index);

    let mut hasher = Sha256::new();
    hasher.update(b"prism-attestation/nvidia-measurements/1\n");
    hasher.update(format!("cc_mode {}\n", report.cc_mode.label()));
    for measurement in measurements {
        hasher.update(format!(
            "{} {}\n",
            measurement.index,
            hex::encode(measurement.digest)
        ));
    }
    hex::encode(hasher.finalize())
}

/// Nodes and services in this tree use both base64 alphabets. Accepting either
/// is a transport convenience only; nothing downstream of the decode is lenient.
fn decode_base64(encoded: &str) -> Result<Vec<u8>, VerificationError> {
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|_| VerificationError::MalformedEvidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_evidence_stops_at_isolated() {
        assert_eq!(MAX_GRANTABLE_CLASS, TrustClass::Isolated);
        assert!(MAX_GRANTABLE_CLASS <= prism_protocol::MAX_VERIFIABLE_TRUST_CLASS);
    }

    /// The verifier says what the evidence earns and the protocol says what the
    /// network serves. They are allowed to differ, and the clamp is what keeps
    /// the served rung from outrunning the evidence. They agree today, which
    /// makes the clamp a no-op for SNP rather than absent: the assertion that
    /// matters is that a report can never earn more than the network can back.
    #[test]
    fn a_guest_report_earns_attested_and_never_outruns_the_ceiling() {
        assert_eq!(SNP_GRANTABLE_CLASS, TrustClass::Attested);
        assert!(SNP_GRANTABLE_CLASS <= prism_protocol::MAX_VERIFIABLE_TRUST_CLASS);
    }

    #[test]
    fn a_channel_key_fingerprint_matches_the_openssh_form() {
        let blob = STANDARD.encode([0x11_u8; 51]);
        let fingerprint =
            channel_key_fingerprint(&format!("ssh-ed25519 {blob} prism-lease-7")).expect("key");
        assert_eq!(
            fingerprint,
            format!(
                "SHA256:{}",
                STANDARD_NO_PAD.encode(Sha256::digest([0x11_u8; 51]))
            )
        );
        assert!(channel_key_fingerprint("ssh-ed25519").is_err());
        assert!(channel_key_fingerprint("ssh-ed25519 not base64!!").is_err());
    }

    #[test]
    fn both_base64_alphabets_decode() {
        let raw = [0xfbu8, 0xff, 0x00, 0x11];
        assert_eq!(decode_base64(&STANDARD.encode(raw)).unwrap(), raw);
        assert_eq!(decode_base64(&URL_SAFE_NO_PAD.encode(raw)).unwrap(), raw);
        assert!(decode_base64("not base64!!").is_err());
    }
}
