//! Computes the SEV-SNP launch measurement of the Prism workspace guest from
//! the inputs that go into it.
//!
//! The measurement in a report is whatever the machine booted. The measurement
//! in `crates/attestation/reference/snp-launch-measurements.json` is what the
//! network is willing to accept, and it is computed here from firmware, kernel,
//! command line and machine shape. Deriving the reference from a report instead
//! would produce a verifier that agrees with the host by construction, so this
//! tool never reads one.
//!
//! Scope is SEV-SNP under QEMU, which is what Kata launches. Other launch paths
//! set different initial register state and would need their own vectors before
//! anything here could be trusted for them.

use anyhow::{Context, Result, bail, ensure};

mod gctx;
mod ovmf;
pub mod reference;
mod sev_hashes;
mod vmsa;

pub use gctx::DIGEST_SIZE;
pub use vmsa::cpu_signature;

/// The processor a guest is measured against. Its CPUID signature reaches the
/// guest in RDX at reset, so the same image on a different stepping measures
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpu {
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
}

impl Cpu {
    pub fn signature(&self) -> u32 {
        cpu_signature(self.family, self.model, self.stepping)
    }
}

/// Everything outside the image bytes that changes the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineShape {
    pub vcpus: u32,
    pub cpu: Cpu,
    /// SEV_FEATURES as the VMM writes it into each VMSA. Bit 0 is SNPActive;
    /// anything else the VMM turns on lands in the measurement too.
    pub guest_features: u64,
}

/// The measured direct boot inputs. The root filesystem is deliberately absent:
/// it is covered by the dm-verity root hash carried in `cmdline`, which is
/// measured, rather than by hashing a multi-gigabyte image into this digest.
pub struct MeasuredBoot {
    pub firmware: Vec<u8>,
    pub kernel: Option<Vec<u8>>,
    pub initrd: Option<Vec<u8>>,
    pub cmdline: Option<String>,
}

pub fn snp_launch_measurement(
    boot: &MeasuredBoot,
    shape: &MachineShape,
) -> Result<[u8; DIGEST_SIZE]> {
    let firmware = ovmf::Ovmf::parse(&boot.firmware)?;
    let mut digest = gctx::LaunchDigest::new();
    digest.normal_pages(firmware.gpa(), firmware.data());

    let hashes = match &boot.kernel {
        Some(kernel) => {
            ensure!(
                firmware.has_section(ovmf::SectionType::KernelHashes),
                "a kernel was given but this firmware has no SNP kernel hashes section, so a direct boot would not be measured"
            );
            Some(sev_hashes::SevHashes::new(
                kernel,
                boot.initrd.as_deref().unwrap_or_default(),
                boot.cmdline.as_deref(),
            ))
        }
        None => {
            ensure!(
                boot.initrd.is_none() && boot.cmdline.is_none(),
                "an initrd or command line without a kernel is measured by nothing"
            );
            None
        }
    };

    for section in firmware.metadata() {
        match section.section_type {
            ovmf::SectionType::SecMem | ovmf::SectionType::SvsmCaa => {
                digest.zero_pages(section.gpa, section.size);
            }
            ovmf::SectionType::Secrets => digest.secrets_page(section.gpa),
            ovmf::SectionType::Cpuid => digest.cpuid_page(section.gpa),
            ovmf::SectionType::KernelHashes => match &hashes {
                Some(hashes) => {
                    let table_gpa = firmware.sev_hashes_table_gpa()?;
                    let page = hashes.page((table_gpa % gctx::PAGE_SIZE as u64) as usize)?;
                    ensure!(
                        section.size == page.len() as u64,
                        "the firmware reserves {} bytes for the kernel hashes page",
                        section.size
                    );
                    digest.normal_pages(section.gpa, &page);
                }
                None => digest.zero_pages(section.gpa, section.size),
            },
        }
    }

    let vmsa = vmsa::Vmsa::new(
        firmware.sev_es_reset_eip()?,
        shape.cpu.signature(),
        shape.guest_features,
    );
    for page in vmsa.pages(shape.vcpus)? {
        digest.vmsa_page(page);
    }

    Ok(digest.finish())
}

pub fn read_input(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {}", path.display()))
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Rejects anything that is not a lowercase hex digest of the expected width,
/// so a truncated or upper case value in the reference file is a failure rather
/// than a comparison that never matches.
pub fn parse_digest(value: &str, bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() == bytes * 2
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "{value} is not a lowercase {bytes} byte hex digest"
    );
    match hex::decode(value) {
        Ok(raw) => Ok(raw),
        Err(_) => bail!("{value} is not hex"),
    }
}
