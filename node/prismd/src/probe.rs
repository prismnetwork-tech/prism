use std::{
    ffi::{OsStr, OsString},
    fs,
    path::Path,
};

use anyhow::Context;
use prism_protocol::HostTeeCapability;

use crate::command_success;

const SYSTEM_SYSFS_ROOT: &str = "/sys";
const SYSTEM_DEVICE_ROOT: &str = "/dev";

/// The containerd runtime that starts a confidential guest, and the shim
/// binary containerd resolves it to: it strips the `io.containerd.` prefix and
/// turns the remaining dots into dashes.
pub const CONFIDENTIAL_RUNTIME: &str = "io.containerd.kata-qemu-snp.v2";
const CONFIDENTIAL_SHIM: &str = "containerd-shim-kata-qemu-snp-v2";

pub fn host_tee_capability() -> HostTeeCapability {
    host_tee_capability_at(
        Path::new(SYSTEM_SYSFS_ROOT),
        Path::new(SYSTEM_DEVICE_ROOT),
        &search_path(),
    )
}

fn host_tee_capability_at(
    sysfs_root: &Path,
    device_root: &Path,
    search_path: &OsStr,
) -> HostTeeCapability {
    let parameters = sysfs_root.join("module/kvm_amd/parameters");
    HostTeeCapability {
        sev: kernel_flag(&parameters.join("sev")),
        sev_es: kernel_flag(&parameters.join("sev_es")),
        sev_snp: kernel_flag(&parameters.join("sev_snp")),
        sev_guest_device: device_root.join("sev").exists()
            || device_root.join("sev-guest").exists(),
        kata_runtime: command_success("kata-runtime", &["--version"])
            || command_success("kata-qemu", &["--version"]),
        kata_confidential_runtime: confidential_runtime_registered_in(search_path),
    }
}

pub fn search_path() -> OsString {
    std::env::var_os("PATH").unwrap_or_default()
}

/// A Kata configuration file on disk says a confidential guest was packaged for
/// this host. It does not say containerd can start one. containerd execs a shim
/// binary by name when a runtime is asked for, so the binary resolving on the
/// path it searches is the difference between a node that can serve the class
/// and one that only looks like it.
pub(crate) fn confidential_runtime_registered_in(search_path: &OsStr) -> bool {
    std::env::split_paths(search_path)
        .any(|directory| executable(&directory.join(CONFIDENTIAL_SHIM)))
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.is_file()
}

/// A kernel that does not offer the feature has no file to read, which is how
/// 6.8 reports SEV-SNP. That is a plain no, not a probe that failed, so every
/// unreadable or unrecognized value is off.
fn kernel_flag(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|value| matches!(value.trim(), "Y" | "1"))
}

/// Which card is in the slot, rather than what class of card it is. The control
/// plane matches an attestation report against a device it can name.
pub fn pci_identity(address: &str) -> anyhow::Result<(u16, u16)> {
    pci_identity_at(Path::new(SYSTEM_SYSFS_ROOT), address)
}

fn pci_identity_at(sysfs_root: &Path, address: &str) -> anyhow::Result<(u16, u16)> {
    if address.is_empty() || address.contains('/') || address.contains("..") {
        anyhow::bail!("{address} is not a PCI address");
    }
    let device_root = sysfs_root.join("bus/pci/devices").join(address);
    Ok((
        pci_id(&device_root.join("vendor"))?,
        pci_id(&device_root.join("device"))?,
    ))
}

fn pci_id(path: &Path) -> anyhow::Result<u16> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let raw = raw.trim();
    u16::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16)
        .with_context(|| format!("{raw} is not a PCI identifier"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "prismd-probe-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(path.join("sys/module/kvm_amd/parameters")).unwrap();
        fs::create_dir_all(path.join("dev")).unwrap();
        path
    }

    fn parameter(root: &Path, name: &str, value: &str) {
        fs::write(
            root.join("sys/module/kvm_amd/parameters").join(name),
            format!("{value}\n"),
        )
        .unwrap();
    }

    /// A kernel without host SEV-SNP has no sev_snp parameter at all. Reading
    /// it must report an absent feature, not abort the probe.
    #[test]
    fn a_missing_sev_snp_parameter_reads_as_absent() {
        let root = fixture("missing-snp");
        parameter(&root, "sev", "Y");
        parameter(&root, "sev_es", "Y");

        let capability =
            host_tee_capability_at(&root.join("sys"), &root.join("dev"), OsStr::new(""));
        assert!(capability.sev);
        assert!(capability.sev_es);
        assert!(!capability.sev_snp);
        assert!(!capability.sev_guest_device);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disabled_and_enabled_parameters_read_as_written() {
        let root = fixture("parameters");
        parameter(&root, "sev", "N");
        parameter(&root, "sev_es", "1");
        parameter(&root, "sev_snp", "Y");
        fs::write(root.join("dev/sev"), []).unwrap();

        let capability =
            host_tee_capability_at(&root.join("sys"), &root.join("dev"), OsStr::new(""));
        assert!(!capability.sev);
        assert!(capability.sev_es);
        assert!(capability.sev_snp);
        assert!(capability.sev_guest_device);
        fs::remove_dir_all(root).unwrap();
    }

    /// A packaged confidential guest with no shim for containerd to exec is a
    /// node that cannot serve the class, and it has to report that rather than
    /// the packaging.
    #[test]
    #[cfg(unix)]
    fn the_confidential_runtime_needs_a_shim_containerd_can_exec() {
        use std::os::unix::fs::PermissionsExt;

        let root = fixture("confidential-runtime");
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            bin.join("configuration-qemu-snp.toml"),
            "[hypervisor.qemu]\n",
        )
        .unwrap();
        assert!(!confidential_runtime_registered_in(bin.as_os_str()));

        let shim = bin.join(CONFIDENTIAL_SHIM);
        fs::write(&shim, "#!/bin/sh\n").unwrap();
        assert!(!confidential_runtime_registered_in(bin.as_os_str()));

        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(confidential_runtime_registered_in(bin.as_os_str()));
        assert!(
            host_tee_capability_at(&root.join("sys"), &root.join("dev"), bin.as_os_str())
                .kata_confidential_runtime
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pci_identity_reads_the_vendor_and_device() {
        let root = fixture("pci");
        let device = root.join("sys/bus/pci/devices/0000:01:00.0");
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("vendor"), "0x10de\n").unwrap();
        fs::write(device.join("device"), "0x2331\n").unwrap();

        assert_eq!(
            pci_identity_at(&root.join("sys"), "0000:01:00.0").unwrap(),
            (0x10de, 0x2331)
        );
        assert!(pci_identity_at(&root.join("sys"), "../../../etc").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
