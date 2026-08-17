use anyhow::{Result, ensure};

use crate::gctx::PAGE_SIZE;

/// The boot processor always starts at the architectural reset vector; the
/// application processors start wherever the firmware's reset block says.
const BSP_EIP: u32 = 0xffff_fff0;

/// Offsets into the SEV-ES save area, AMD APM volume 2 table B-4. The VMSA of
/// every vCPU is hashed into the launch measurement, so these are part of the
/// measured image even though no file on disk contains them.
const ES: usize = 0x000;
const CS: usize = 0x010;
const SS: usize = 0x020;
const DS: usize = 0x030;
const FS: usize = 0x040;
const GS: usize = 0x050;
const GDTR: usize = 0x060;
const LDTR: usize = 0x070;
const IDTR: usize = 0x080;
const TR: usize = 0x090;
const EFER: usize = 0x0d0;
const CR4: usize = 0x148;
const CR0: usize = 0x158;
const DR7: usize = 0x160;
const DR6: usize = 0x168;
const RFLAGS: usize = 0x170;
const RIP: usize = 0x178;
const G_PAT: usize = 0x268;
const RDX: usize = 0x310;
const SEV_FEATURES: usize = 0x3b0;
const XCR0: usize = 0x3e8;
const MXCSR: usize = 0x408;
const X87_FCW: usize = 0x410;

/// Reset state as KVM and QEMU leave it: SVME set in EFER, MCE set in CR4, and
/// the PAT MSR at its architectural default (APM volume 2, section A.3).
const EFER_SVME: u64 = 0x1000;
const CR4_MCE: u64 = 0x40;
const CR0_RESET: u64 = 0x10;
const DR7_RESET: u64 = 0x400;
const DR6_RESET: u64 = 0xffff_0ff0;
const RFLAGS_RESET: u64 = 0x2;
const G_PAT_RESET: u64 = 0x0007_0406_0007_0406;
const XCR0_RESET: u64 = 0x1;
const MXCSR_RESET: u32 = 0x1f80;
const X87_FCW_RESET: u16 = 0x37f;

pub struct Vmsa {
    boot: [u8; PAGE_SIZE],
    application: Option<[u8; PAGE_SIZE]>,
}

impl Vmsa {
    pub fn new(ap_eip: u32, cpu_signature: u32, guest_features: u64) -> Self {
        Self {
            boot: save_area(BSP_EIP, cpu_signature, guest_features),
            application: (ap_eip != 0).then(|| save_area(ap_eip, cpu_signature, guest_features)),
        }
    }

    /// One page per vCPU, the first for the boot processor. Adding a vCPU adds
    /// a page to the digest, which is why a reference measurement is only valid
    /// for the machine shape it was computed for.
    pub fn pages(&self, vcpus: u32) -> Result<Vec<&[u8; PAGE_SIZE]>> {
        ensure!(vcpus > 0, "a guest needs at least one vCPU");
        let mut pages: Vec<&[u8; PAGE_SIZE]> = vec![&self.boot];
        if vcpus > 1 {
            let application = self.application.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "firmware declares no SEV-ES reset address, so a guest with {vcpus} vCPUs has no measurable application processor state"
                )
            })?;
            pages.extend(std::iter::repeat_n(application, vcpus as usize - 1));
        }
        Ok(pages)
    }
}

fn save_area(eip: u32, cpu_signature: u32, guest_features: u64) -> [u8; PAGE_SIZE] {
    let mut page = [0_u8; PAGE_SIZE];

    let mut segment = |offset: usize, selector: u16, attributes: u16, limit: u32, base: u64| {
        page[offset..offset + 2].copy_from_slice(&selector.to_le_bytes());
        page[offset + 2..offset + 4].copy_from_slice(&attributes.to_le_bytes());
        page[offset + 4..offset + 8].copy_from_slice(&limit.to_le_bytes());
        page[offset + 8..offset + 16].copy_from_slice(&base.to_le_bytes());
    };

    segment(ES, 0, 0x93, 0xffff, 0);
    segment(CS, 0xf000, 0x9b, 0xffff, u64::from(eip & 0xffff_0000));
    segment(SS, 0, 0x93, 0xffff, 0);
    segment(DS, 0, 0x93, 0xffff, 0);
    segment(FS, 0, 0x93, 0xffff, 0);
    segment(GS, 0, 0x93, 0xffff, 0);
    segment(GDTR, 0, 0, 0xffff, 0);
    segment(LDTR, 0, 0x82, 0xffff, 0);
    segment(IDTR, 0, 0, 0xffff, 0);
    segment(TR, 0, 0x8b, 0xffff, 0);

    let mut quad = |offset: usize, value: u64| {
        page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };

    quad(EFER, EFER_SVME);
    quad(CR4, CR4_MCE);
    quad(CR0, CR0_RESET);
    quad(DR7, DR7_RESET);
    quad(DR6, DR6_RESET);
    quad(RFLAGS, RFLAGS_RESET);
    quad(RIP, u64::from(eip & 0xffff));
    quad(G_PAT, G_PAT_RESET);
    // QEMU hands the guest its CPUID signature in RDX at reset, so the family,
    // model and stepping of the host processor end up in the measurement.
    quad(RDX, u64::from(cpu_signature));
    quad(SEV_FEATURES, guest_features);
    quad(XCR0, XCR0_RESET);

    page[MXCSR..MXCSR + 4].copy_from_slice(&MXCSR_RESET.to_le_bytes());
    page[X87_FCW..X87_FCW + 2].copy_from_slice(&X87_FCW_RESET.to_le_bytes());

    page
}

/// CPUID Fn0000_0001_EAX family, model and stepping, packed as AMD's CPUID
/// specification (publication 25481) describes it.
pub fn cpu_signature(family: u32, model: u32, stepping: u32) -> u32 {
    let (family_low, family_high) = if family > 0xf {
        (0xf, (family - 0xf) & 0xff)
    } else {
        (family, 0)
    };
    (family_high << 20)
        | (((model >> 4) & 0xf) << 16)
        | (family_low << 8)
        | ((model & 0xf) << 4)
        | (stepping & 0xf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epyc_signatures_match_the_qemu_cpu_models() {
        assert_eq!(cpu_signature(23, 1, 2), 0x0080_0f12);
        assert_eq!(cpu_signature(25, 1, 1), 0x00a0_0f11);
        assert_eq!(cpu_signature(25, 17, 0), 0x00a1_0f10);
    }

    #[test]
    fn a_firmware_without_a_reset_address_cannot_measure_application_processors() {
        let vmsa = Vmsa::new(0, cpu_signature(25, 17, 1), 0x1);
        assert_eq!(vmsa.pages(1).unwrap().len(), 1);
        assert!(vmsa.pages(2).is_err());
    }
}
