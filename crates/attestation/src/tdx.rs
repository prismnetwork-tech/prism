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
use sha2::{Digest, Sha384};

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

/// One entry of a dstack event log, as the guest agent reports it.
///
/// Two kinds of entry share this shape. A firmware event carries the digest
/// the TD extended for it and nothing else worth reading. A dstack runtime
/// event carries a name and payload, and its digest is derived from them
/// rather than sent: the guest agent leaves the field empty and the client
/// computes it, though the cloud attestation endpoint fills it in. Either
/// way nothing here is trusted as received: the fold across the effective
/// digests has to land on the register the quote signed.
#[derive(Debug, Clone)]
pub struct TdxEvent {
    pub imr: u32,
    pub event_type: u32,
    pub name: String,
    /// The digest as it arrived, which is empty for a runtime event whose
    /// producer derives it. [`effective_digest`] resolves what actually folds
    /// into the register.
    pub digest: Vec<u8>,
    pub payload: Vec<u8>,
}

/// The event type dstack writes for every runtime event it extends into the
/// application register. Its digest is derived from the name and payload, not
/// carried; any other event type is a firmware event whose digest is the one
/// on the wire.
const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// The digest that actually folds into a register for this event.
///
/// For a runtime event this is `sha384(event_type_le || ":" || name || ":" ||
/// payload)`, the V1 dstack rule, computed here rather than trusted: a changed
/// payload changes this digest, which changes the fold, which no longer meets
/// the quoted register. A producer that also sent the digest (the cloud shape)
/// must have sent the one this computes, or the event is rejected before the
/// fold. For a firmware event the wire digest is authoritative and has to be a
/// full SHA-384.
fn effective_digest(event: &TdxEvent) -> Result<[u8; 48], VerificationError> {
    if event.event_type == DSTACK_RUNTIME_EVENT_TYPE {
        let mut hasher = Sha384::new();
        hasher.update(event.event_type.to_le_bytes());
        hasher.update(b":");
        hasher.update(event.name.as_bytes());
        hasher.update(b":");
        hasher.update(&event.payload);
        let computed: [u8; 48] = hasher.finalize().into();
        if !event.digest.is_empty() {
            let carried: [u8; 48] = event
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::TdxEventDigestMismatch)?;
            if !bool::from(carried.ct_eq(&computed)) {
                return Err(VerificationError::TdxEventDigestMismatch);
            }
        }
        Ok(computed)
    } else {
        event
            .digest
            .as_slice()
            .try_into()
            .map_err(|_| VerificationError::TdxEventLogMismatch)
    }
}

/// What a verified event log binds this TD to, beyond the launch identity the
/// quote already carries: which application, which instance of it, launched
/// from which compose file on which OS image, keyed by which KMS.
///
/// `instance_id` is the piece the quote alone cannot give. `MRTD` and the
/// boot registers name an image, and every TD launched from that image shares
/// them; the instance id is minted per deployment and extended into `RTMR3`,
/// so it is the value a control plane may treat as unique per node.
#[derive(Debug, Clone)]
pub(crate) struct TdxRuntimeBindings {
    pub(crate) compose_hash: [u8; 32],
    pub(crate) instance_id: Vec<u8>,
}

/// The named events a dstack log must bind exactly once. Missing means the
/// log is not from a completed dstack boot; twice means someone appended a
/// second claim after the fact, and first-wins or last-wins would each make
/// one of those claims silently authoritative.
const REQUIRED_BINDING_EVENTS: [&str; 5] = [
    "compose-hash",
    "app-id",
    "instance-id",
    "os-image-hash",
    "mr-kms",
];

/// The register dstack extends named application events into.
const APP_EVENT_IMR: u32 = 3;

/// Verifies a runtime event log against the registers a verified quote signed
/// and returns what the log binds the TD to.
///
/// Two judgements. Every register the report carries must equal the fold of
/// the log's effective digests for it, from forty-eight zero bytes through
/// `sha384(register || digest)` per event, so the log accounts for exactly
/// what the TD extended: nothing missing, nothing invented, nothing
/// reordered. A runtime event's effective digest is derived from its own name
/// and payload (see [`effective_digest`]), so a payload cannot ride on the
/// digest of a different claim and survive the fold. And each required binding
/// must appear exactly once.
///
/// The caller compares the returned `compose_hash` against the workload it
/// expected; this function establishes what the TD is bound to, not whether
/// that binding is the one the caller wanted.
pub(crate) fn verify_tdx_event_log(
    report: &TdReport,
    events: &[TdxEvent],
) -> Result<TdxRuntimeBindings, VerificationError> {
    let mut folds = [[0u8; 48]; 4];
    for event in events {
        let digest = effective_digest(event)?;
        let register = folds
            .get_mut(event.imr as usize)
            .ok_or(VerificationError::TdxEventLogMismatch)?;
        let mut hasher = Sha384::new();
        hasher.update(*register);
        hasher.update(digest);
        *register = hasher.finalize().into();
    }
    for (fold, quoted) in
        folds
            .iter()
            .zip([&report.rtmr0, &report.rtmr1, &report.rtmr2, &report.rtmr3])
    {
        if !bool::from(fold.ct_eq(quoted)) {
            return Err(VerificationError::TdxEventLogMismatch);
        }
    }

    let mut bindings: Vec<(&str, &[u8])> = Vec::new();
    for event in events {
        if event.event_type != DSTACK_RUNTIME_EVENT_TYPE || event.imr != APP_EVENT_IMR {
            continue;
        }
        if REQUIRED_BINDING_EVENTS.contains(&event.name.as_str()) {
            bindings.push((&event.name, &event.payload));
        }
    }

    let exactly_one = |name: &str| -> Result<Vec<u8>, VerificationError> {
        let mut found = bindings.iter().filter(|(n, _)| *n == name);
        let first = found
            .next()
            .ok_or(VerificationError::TdxEventLogIncomplete)?;
        if found.next().is_some() {
            return Err(VerificationError::TdxEventLogIncomplete);
        }
        Ok(first.1.to_vec())
    };

    // The bindings not carried out of here are still held to exactly-once:
    // a log that binds the application register without naming its app, OS
    // image or KMS is not a completed dstack boot, whether or not a caller
    // reads those values yet.
    exactly_one("app-id")?;
    exactly_one("os-image-hash")?;
    exactly_one("mr-kms")?;
    let compose_hash: [u8; 32] = exactly_one("compose-hash")?
        .try_into()
        .map_err(|_| VerificationError::TdxEventLogIncomplete)?;
    Ok(TdxRuntimeBindings {
        compose_hash,
        instance_id: exactly_one("instance-id")?,
    })
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
