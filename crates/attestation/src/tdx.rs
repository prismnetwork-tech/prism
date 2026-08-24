//! Intel TDX quote verification, built on Intel's DCAP scheme.
//!
//! A TDX quote is signed by the platform's quoting enclave and chains to
//! Intel's root through collateral the caller fetches out of band: TCB info,
//! QE identity and the certificate revocation lists. The collateral is signed
//! by Intel and carries its own validity windows, so passing it in keeps this
//! crate a pure function over bytes: the caller owns the fetch, this module
//! owns every judgement about what the bytes mean.
//!
//! What a verified quote proves: a genuine Intel processor at the collateral's
//! patch level launched a TD from the measured image (`MRTD`), extended the
//! boot-time registers (`RTMR0..2`) the way the reference set expects, and the
//! guest bound our challenge into `REPORT_DATA`. What it does not prove: who
//! is running the host, what has been extended into `RTMR3` at runtime, or
//! anything about a GPU. Runtime-register replay and NVIDIA CC evidence are
//! separate checks with their own reference material; until they exist, TDX
//! evidence stops at Attested exactly like a SEV-SNP report does.

use dcap_qvl::QuoteCollateralV3;
use dcap_qvl::verify::verify as dcap_verify;
use p384::elliptic_curve::subtle::{Choice, ConstantTimeEq};

use crate::VerificationError;

/// The one TCB status this verifier accepts. Everything else (outdated,
/// configuration needed, software hardening needed) is a platform Intel has
/// published reservations about, and a reservation is a refusal here. Widening
/// this to named statuses with advisory review is a policy change, not a bug.
const ACCEPTED_TCB_STATUS: &str = "UpToDate";

/// The measured state of one TD as this verifier read it out of a quote whose
/// signature chain and collateral already checked out.
pub(crate) struct TdReport {
    pub(crate) mr_td: [u8; 48],
    pub(crate) rtmr0: [u8; 48],
    pub(crate) rtmr1: [u8; 48],
    pub(crate) rtmr2: [u8; 48],
    pub(crate) rtmr3: [u8; 48],
    pub(crate) report_data: [u8; 64],
}

/// One launch identity a TD may present: the image measurement and the three
/// boot-time runtime registers, taken together. A quote matches an entry or it
/// matches nothing; there is no per-register mixing across entries, because a
/// kernel from one image and an initrd from another is not a state anyone
/// published.
#[derive(Debug, Clone)]
pub struct TdxLaunchIdentity {
    pub mr_td: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TdxMeasurementSet {
    identities: Vec<TdxLaunchIdentity>,
}

impl TdxMeasurementSet {
    pub(crate) fn new(identities: Vec<TdxLaunchIdentity>) -> Self {
        Self { identities }
    }

    /// Whether the report names a launch identity in the set. Every entry is
    /// compared in full so the answer does not leak which one matched, or how
    /// close a mismatch came, through timing.
    pub(crate) fn accepts(&self, report: &TdReport) -> bool {
        let mut hit = Choice::from(0u8);
        for identity in &self.identities {
            hit |= identity.mr_td.ct_eq(&report.mr_td)
                & identity.rtmr0.ct_eq(&report.rtmr0)
                & identity.rtmr1.ct_eq(&report.rtmr1)
                & identity.rtmr2.ct_eq(&report.rtmr2);
        }
        bool::from(hit)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

/// Runs Intel's verification over the quote and the caller-supplied collateral
/// and reduces the outcome to the fields this crate goes on to judge.
///
/// `now` is the caller's clock in seconds since the epoch, checked against the
/// collateral's validity windows inside the DCAP walk. Expired CRLs or TCB
/// info refuse the quote outright: stale collateral is indistinguishable from
/// collateral chosen to hide a revocation.
pub(crate) fn verify_quote(
    quote: &[u8],
    collateral_json: &str,
    now_unix: u64,
) -> Result<TdReport, VerificationError> {
    let collateral: QuoteCollateralV3 = serde_json::from_str(collateral_json)
        .map_err(|_| VerificationError::TdxCollateralMalformed)?;

    let verified = dcap_verify(quote, &collateral, now_unix)
        .map_err(|_| VerificationError::TdxQuoteRejected)?;

    if verified.status != ACCEPTED_TCB_STATUS || !verified.advisory_ids.is_empty() {
        return Err(VerificationError::TdxTcbStatusNotAccepted);
    }

    let td = verified
        .report
        .as_td10()
        .ok_or(VerificationError::TdxNotTdQuote)?;

    Ok(TdReport {
        mr_td: td.mr_td,
        rtmr0: td.rt_mr0,
        rtmr1: td.rt_mr1,
        rtmr2: td.rt_mr2,
        rtmr3: td.rt_mr3,
        report_data: td.report_data,
    })
}
