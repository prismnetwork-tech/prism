//! The reference launch measurements the control plane accepts, and the check
//! that each one is still what its inputs produce.
//!
//! The file lives in `crates/attestation/reference` because the verifier
//! compiles it in. Its shape belongs to the verifier; what this module adds is
//! the ability to derive every value in it from artifacts on disk, so a
//! measurement in the file is a claim someone can refute.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{Cpu, MachineShape, MeasuredBoot, parse_digest, read_input, sha256_hex};

pub const SCHEMA_VERSION: u32 = 1;

/// SEV_FEATURES the network's launcher writes into every VMSA: SNPActive and
/// nothing else. The reference file has no field for it because one
/// configuration is served. A launcher that turns on another feature, debug
/// swap being the usual one, produces a measurement no entry here matches, and
/// the report fails rather than passing under someone else's assumption.
pub const GUEST_FEATURES: u64 = 0x1;

/// File names the guest build writes into its output directory. The reference
/// file records digests, so these are how a digest is resolved back to bytes.
const FIRMWARE_FILE: &str = "OVMF.fd";
const KERNEL_FILE: &str = "vmlinuz";
const INITRD_FILE: &str = "initrd.img";
const CMDLINE_FILE: &str = "cmdline";

/// sha256 of nothing, which is what the firmware records for a guest booted
/// without an initrd.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceFile {
    pub schema_version: u32,
    /// Where the measurements came from. `computed` is the only value that
    /// makes an entry usable, and it is the only value this tool will certify.
    pub provenance: String,
    pub note: String,
    pub measurements: Vec<Entry>,
}

/// One image on one machine shape. The launch digest covers the VMSA of every
/// vCPU, so eight vCPUs and sixteen vCPUs on the same image are two entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub image_version: String,
    pub vcpu_count: u32,
    pub cpu: CpuDescriptor,
    pub sha384: String,
    pub inputs: Inputs,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CpuDescriptor {
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
}

/// Digests of the four things a measured direct boot commits to. Only the
/// firmware reaches the digest as bytes; the kernel, initrd and command line
/// reach it through the hashes table, which stores exactly these sha256 values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub ovmf: String,
    pub kernel: String,
    pub initrd: String,
    pub cmdline: String,
}

impl ReferenceFile {
    pub fn parse(raw: &str) -> Result<Self> {
        let file: Self = serde_json::from_str(raw).context("reference file is not valid JSON")?;
        file.validate()?;
        Ok(file)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&raw)
    }

    pub fn claims_computed_values(&self) -> bool {
        self.provenance == "computed"
    }

    /// Everything checkable without the artifacts themselves.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "reference file schema version {} is not understood",
            self.schema_version
        );
        ensure!(
            !self.claims_computed_values() || !self.measurements.is_empty(),
            "the file says its measurements are computed but carries none"
        );

        let mut seen = BTreeSet::new();
        for entry in &self.measurements {
            ensure!(seen.insert(entry.id()), "{} is listed twice", entry.id());
            entry.validate()?;
        }
        Ok(())
    }

    /// Recomputes every entry from the artifacts on disk. Inputs are checked
    /// against their recorded digests first, so a mismatch names the input that
    /// moved rather than only the measurement it changed.
    ///
    /// A file that does not claim computed values is left alone. Recomputing a
    /// placeholder would only prove the placeholder is a placeholder, and
    /// passing it would be worse.
    pub fn check(&self, artifacts: &Path) -> Result<Vec<String>> {
        self.validate()?;
        if !self.claims_computed_values() {
            return Ok(Vec::new());
        }

        let mut checked = Vec::new();
        for entry in &self.measurements {
            let recomputed = entry.recompute(artifacts)?;
            ensure!(
                recomputed == entry.sha384,
                "{} measures {recomputed}, and the reference file says {}",
                entry.id(),
                entry.sha384
            );
            checked.push(entry.id());
        }
        Ok(checked)
    }
}

impl Entry {
    pub fn id(&self) -> String {
        format!("{} on {} vCPUs", self.image_version, self.vcpu_count)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.image_version.is_empty(),
            "an entry names no image version"
        );
        ensure!(self.vcpu_count > 0, "{} has no vCPUs", self.id());
        parse_digest(&self.sha384, 48)
            .with_context(|| format!("{} has no usable measurement", self.id()))?;
        for digest in [
            &self.inputs.ovmf,
            &self.inputs.kernel,
            &self.inputs.initrd,
            &self.inputs.cmdline,
        ] {
            sha256_of(digest).with_context(|| format!("{} has an unusable input", self.id()))?;
        }
        Ok(())
    }

    pub fn recompute(&self, artifacts: &Path) -> Result<String> {
        let initrd_digest = sha256_of(&self.inputs.initrd)?;
        let boot = MeasuredBoot {
            firmware: load(artifacts, FIRMWARE_FILE, &self.inputs.ovmf)?,
            kernel: Some(load(artifacts, KERNEL_FILE, &self.inputs.kernel)?),
            // The firmware records the hash of an absent initrd as the hash of
            // nothing, so an empty digest here means the guest boots without
            // one rather than that a file is missing.
            initrd: match initrd_digest == EMPTY_SHA256 {
                true => Some(Vec::new()),
                false => Some(load(artifacts, INITRD_FILE, &self.inputs.initrd)?),
            },
            cmdline: Some(cmdline(artifacts, &self.inputs.cmdline)?),
        };
        let shape = MachineShape {
            vcpus: self.vcpu_count,
            cpu: Cpu {
                family: self.cpu.family,
                model: self.cpu.model,
                stepping: self.cpu.stepping,
            },
            guest_features: GUEST_FEATURES,
        };
        Ok(hex::encode(crate::snp_launch_measurement(&boot, &shape)?))
    }
}

fn load(artifacts: &Path, file: &str, recorded: &str) -> Result<Vec<u8>> {
    let expected = sha256_of(recorded)?;
    let data = read_input(&artifacts.join(file))?;
    let digest = sha256_hex(&data);
    ensure!(
        digest == expected,
        "{file} hashes to {digest}, and the reference file records {expected}"
    );
    Ok(data)
}

/// The command line is the anchor for everything the digest does not cover
/// directly, because it carries the dm-verity root hash of the guest
/// filesystem. Trailing whitespace would change its hash without changing what
/// it says, so it is refused rather than trimmed.
fn cmdline(artifacts: &Path, recorded: &str) -> Result<String> {
    let raw = load(artifacts, CMDLINE_FILE, recorded)?;
    let text = String::from_utf8(raw).context("the command line is not UTF-8")?;
    ensure!(
        text.trim() == text,
        "the command line file has leading or trailing whitespace"
    );
    Ok(text)
}

fn sha256_of(value: &str) -> Result<String> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        bail!("{value} is not a sha256: prefixed digest");
    };
    parse_digest(digest, 32)?;
    Ok(digest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_claiming_computed_values_has_to_carry_some() {
        let file = ReferenceFile {
            schema_version: SCHEMA_VERSION,
            provenance: "computed".to_string(),
            note: String::new(),
            measurements: Vec::new(),
        };
        assert!(file.validate().is_err());
    }

    #[test]
    fn digests_carry_their_algorithm() {
        assert_eq!(
            sha256_of(&format!("sha256:{EMPTY_SHA256}")).unwrap(),
            EMPTY_SHA256
        );
        assert!(sha256_of(EMPTY_SHA256).is_err());
        assert!(sha256_of("sha256:abcd").is_err());
    }

    #[test]
    fn the_empty_digest_is_the_hash_of_nothing() {
        assert_eq!(sha256_hex(&[]), EMPTY_SHA256);
    }
}
