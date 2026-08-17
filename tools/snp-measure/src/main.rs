use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use prism_snp_measure::reference::{CpuDescriptor, Entry, Inputs, ReferenceFile};
use prism_snp_measure::{Cpu, MachineShape, MeasuredBoot, read_input, sha256_hex};

const DEFAULT_REFERENCE: &str = "crates/attestation/reference/snp-launch-measurements.json";

#[derive(Parser)]
#[command(
    name = "snp-measure",
    about = "Compute the SEV-SNP launch measurement of a guest from its inputs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Measure one guest image on one machine shape.
    Measure {
        #[command(flatten)]
        boot: BootArgs,
        #[command(flatten)]
        shape: ShapeArgs,
        /// Print a reference file entry for this image version instead of the
        /// bare measurement.
        #[arg(long)]
        image_version: Option<String>,
    },
    /// Recompute every entry in the reference file from its recorded inputs.
    Check {
        #[arg(long, default_value = DEFAULT_REFERENCE)]
        reference: PathBuf,
        /// Directory holding the guest build outputs the digests name.
        #[arg(long)]
        artifacts: PathBuf,
    },
}

#[derive(Args)]
struct BootArgs {
    #[arg(long)]
    firmware: PathBuf,
    #[arg(long)]
    kernel: Option<PathBuf>,
    #[arg(long, requires = "kernel")]
    initrd: Option<PathBuf>,
    #[arg(long, requires = "kernel")]
    cmdline: Option<String>,
}

#[derive(Args)]
struct ShapeArgs {
    #[arg(long)]
    vcpus: u32,
    #[arg(long)]
    cpu_family: u32,
    #[arg(long)]
    cpu_model: u32,
    #[arg(long)]
    cpu_stepping: u32,
    /// SEV_FEATURES the VMM writes into each VMSA, hex. Bit 0 is SNPActive.
    #[arg(long, default_value = "0x1")]
    guest_features: String,
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("snp-measure: {error:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Measure {
            boot,
            shape,
            image_version,
        } => measure(boot, shape, image_version),
        Command::Check {
            reference,
            artifacts,
        } => check(&reference, &artifacts),
    }
}

fn measure(boot: BootArgs, shape: ShapeArgs, image_version: Option<String>) -> Result<()> {
    let firmware = read_input(&boot.firmware)?;
    let kernel = boot.kernel.as_deref().map(read_input).transpose()?;
    let initrd = boot.initrd.as_deref().map(read_input).transpose()?;
    let guest_features = u64::from_str_radix(
        shape
            .guest_features
            .strip_prefix("0x")
            .unwrap_or(&shape.guest_features),
        16,
    )
    .context("guest features must be hex")?;

    let machine = MachineShape {
        vcpus: shape.vcpus,
        cpu: Cpu {
            family: shape.cpu_family,
            model: shape.cpu_model,
            stepping: shape.cpu_stepping,
        },
        guest_features,
    };
    let measured = MeasuredBoot {
        firmware: firmware.clone(),
        kernel: kernel.clone(),
        initrd: initrd.clone(),
        cmdline: boot.cmdline.clone(),
    };
    let sha384 = hex::encode(prism_snp_measure::snp_launch_measurement(
        &measured, &machine,
    )?);

    let Some(image_version) = image_version else {
        println!("{sha384}");
        return Ok(());
    };

    ensure!(
        guest_features == prism_snp_measure::reference::GUEST_FEATURES,
        "the reference file has no field for guest features, so it can only describe launches at {:#x}",
        prism_snp_measure::reference::GUEST_FEATURES
    );
    let kernel = kernel.context("a reference entry describes a measured direct boot")?;
    let cmdline = boot
        .cmdline
        .context("a reference entry describes a measured direct boot")?;

    let entry = Entry {
        image_version,
        vcpu_count: machine.vcpus,
        cpu: CpuDescriptor {
            family: machine.cpu.family,
            model: machine.cpu.model,
            stepping: machine.cpu.stepping,
        },
        sha384,
        inputs: Inputs {
            ovmf: digest(&firmware),
            kernel: digest(&kernel),
            initrd: digest(initrd.as_deref().unwrap_or_default()),
            cmdline: digest(cmdline.as_bytes()),
        },
    };
    println!("{}", serde_json::to_string_pretty(&entry)?);
    Ok(())
}

fn digest(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

fn check(reference: &Path, artifacts: &Path) -> Result<()> {
    let file = ReferenceFile::load(reference)?;
    let checked = file.check(artifacts)?;
    if !file.claims_computed_values() {
        println!(
            "{} says its measurements are {}, so there is nothing to recompute and no node can earn the class from them",
            reference.display(),
            file.provenance
        );
        return Ok(());
    }
    for id in checked {
        println!("{id} matches the measurement its inputs produce");
    }
    Ok(())
}
