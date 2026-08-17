//! Regression vectors for this implementation. They pin the digest this code
//! produces for a fixed input so a refactor cannot move it silently.
//!
//! Read what that is worth precisely: these values have not been confirmed
//! against a measurement taken from a guest launched on SNP hardware, so they
//! show the tool agrees with itself over time, not that it agrees with a PSP.
//! Until a report from the Dallas node is checked in as a vector, a matching
//! digest here is not evidence that a real launch would produce it.

use std::path::PathBuf;

use prism_snp_measure::{Cpu, MachineShape, MeasuredBoot, snp_launch_measurement};

/// The last page of an OVMF build from edk2 stable202405. Everything the
/// measurement needs from the firmware lives in the GUIDed footer table at the
/// end of the image, so the vectors use the tail rather than 4 MiB of padding.
fn firmware(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The AmdSevX64 build, which is the one that carries an SNP kernel hashes
/// section and can therefore boot a measured kernel.
fn amd_sev() -> Vec<u8> {
    firmware("ovmf_AmdSev_suffix.bin")
}

/// EPYC-v4 as QEMU defines it, which is what the published vectors were taken
/// with.
fn epyc_v4() -> Cpu {
    Cpu {
        family: 23,
        model: 1,
        stepping: 2,
    }
}

fn shape(vcpus: u32, guest_features: u64) -> MachineShape {
    MachineShape {
        vcpus,
        cpu: epyc_v4(),
        guest_features,
    }
}

fn direct_boot(firmware: Vec<u8>, cmdline: &str) -> MeasuredBoot {
    MeasuredBoot {
        firmware,
        kernel: Some(Vec::new()),
        initrd: Some(Vec::new()),
        cmdline: Some(cmdline.to_string()),
    }
}

fn measure(boot: &MeasuredBoot, shape: &MachineShape) -> String {
    hex::encode(snp_launch_measurement(boot, shape).expect("measurement"))
}

#[test]
fn a_measured_direct_boot_matches_the_published_vector() {
    assert_eq!(
        measure(
            &direct_boot(amd_sev(), "console=ttyS0 loglevel=7"),
            &shape(1, 0x21)
        ),
        "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb2\
         8c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"
    );
    assert_eq!(
        measure(
            &direct_boot(amd_sev(), "console=ttyS0 loglevel=7"),
            &shape(1, 0x1)
        ),
        "6d287813eb5222d770f75005c664e34c204f385ce832cc2c\
         e7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
    );
}

#[test]
fn a_firmware_only_launch_matches_the_published_vector() {
    let boot = MeasuredBoot {
        firmware: amd_sev(),
        kernel: None,
        initrd: None,
        cmdline: None,
    };
    assert_eq!(
        measure(&boot, &shape(1, 0x21)),
        "e1e1ca029dd7973ab9513295be68198472dcd4fc834bd9af\
         9b63f6e8a1674dbf281a9278a4a2ebe0eed9f22adbcd0e2b"
    );
    assert_eq!(
        measure(&boot, &shape(1, 0x1)),
        "19358ba9a7615534a9a1e2f0dfc29384dcd4dcb7062ff9c6\
         013b26869a5fc6ecabe033c48dd6f6db5d6d76e7c5df632d"
    );
}

/// The stock OvmfPkgX64 build has no kernel hashes section, so it measures a
/// different set of pages and cannot carry a measured direct boot at all.
#[test]
fn the_stock_firmware_build_matches_the_published_vector() {
    let boot = MeasuredBoot {
        firmware: firmware("ovmf_OvmfX64_suffix.bin"),
        kernel: None,
        initrd: None,
        cmdline: None,
    };
    assert_eq!(
        measure(&boot, &shape(1, 0x21)),
        "28797ae0afaba4005a81e629acebfb59e6687949d6be4400\
         7cd5506823b0dd66f146aaae26ff291eed7b493d8a64c385"
    );
    assert_eq!(
        measure(&boot, &shape(1, 0x1)),
        "da0296de8193586a5512078dcd719eccecbd87e2b825ad41\
         48c44f665dc87df21e5b49e21523a9ad993afdb6a30b4005"
    );
}

#[test]
fn a_kernel_needs_a_firmware_that_measures_one() {
    let error = snp_launch_measurement(
        &direct_boot(firmware("ovmf_OvmfX64_suffix.bin"), ""),
        &shape(1, 0x21),
    )
    .expect_err("a firmware without a kernel hashes section cannot measure a kernel");
    assert!(
        error.to_string().contains("kernel hashes section"),
        "{error}"
    );
}

/// The launch digest folds in one VMSA page per vCPU, so the reference set has
/// to be keyed by machine shape. Both values here are published vectors for the
/// same image at one and four vCPUs.
#[test]
fn two_vcpu_counts_measure_differently() {
    let boot = direct_boot(amd_sev(), "");
    let one = measure(&boot, &shape(1, 0x21));
    let four = measure(&boot, &shape(4, 0x21));

    assert_eq!(
        one,
        "329c8ce0972ae52343b64d34a434a86f245dfd74f5ed7aae\
         15d22efc78fb9683632b9b50e4e1d7fa41179ef98a7ef198"
    );
    assert_eq!(
        four,
        "4953b1fb416fa874980e8442b3706d345926d5f38879134e\
         00813c5d7abcbe78eafe7b422907be0b4698e2414a631942"
    );
    assert_ne!(one, four);

    assert_eq!(
        measure(&boot, &shape(4, 0x1)),
        "5061fffb019493a903613d56d54b94912a1a2f9e4502385f\
         5c194616753720a92441310ba6c4933de877c36e23046ad5"
    );
}

/// The command line carries the dm-verity root hash of the guest filesystem.
/// If it were outside the digest, the measured image would say nothing about
/// what the guest runs.
#[test]
fn the_command_line_reaches_the_measurement() {
    let plain = measure(&direct_boot(amd_sev(), ""), &shape(1, 0x21));
    let with_cmdline = measure(
        &direct_boot(amd_sev(), "console=ttyS0 loglevel=7"),
        &shape(1, 0x21),
    );
    assert_ne!(plain, with_cmdline);
}

/// Genoa is what the network runs on, and it is not the processor the published
/// vectors were taken on. The signature reaches the guest in RDX, so the same
/// image on a different part measures differently and needs its own entry.
#[test]
fn the_processor_reaches_the_measurement() {
    let boot = direct_boot(amd_sev(), "console=ttyS0 loglevel=7");
    let genoa = MachineShape {
        vcpus: 1,
        cpu: Cpu {
            family: 25,
            model: 17,
            stepping: 1,
        },
        guest_features: 0x21,
    };
    assert_ne!(measure(&boot, &genoa), measure(&boot, &shape(1, 0x21)));
}
