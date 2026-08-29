use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const SYSTEM_SYSFS_ROOT: &str = "/sys";
const SYSTEM_DEVICE_ROOT: &str = "/dev";
const SYSTEM_LOCK_ROOT: &str = "/run/lock/prismd";
const WORKSPACE_BOOTSTRAP: &str = include_str!("../assets/workspace-bootstrap.sh");
const WORKSPACE_BOOTSTRAP_SHARED: &str = include_str!("../assets/workspace-bootstrap-shared.sh");
const MAX_LEASE_SECONDS: u32 = 21_600;
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);
/// A workspace image is several gigabytes and a consumer uplink is not a data
/// centre one. The pull gets its own clock so it cannot eat the readiness
/// budget and fail a lease that was only ever downloading.
const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(3_600);
/// The bridge nerdctl builds for its default network, which is where a shared
/// lease lands.
const LEASE_BRIDGE: &str = "nerdctl0";
/// Everything a lease has no business reaching: the host's own networks, the
/// link-local metadata address, and the ranges a scan would walk.
const PRIVATE_DESTINATIONS: &str = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }";
const MAIL_PORTS: &str = "{ 25, 465, 587 }";

/// How the card reaches the workload.
///
/// The two modes are not variations on one launch. Under Kata the GPU is bound
/// to vfio-pci and handed to a virtual machine that the host cannot read;
/// shared leaves the card on the host under the ordinary driver and hands it to
/// a container. Everything that differs between them differs here, so neither
/// path can drift into the other by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    KataVfio { group: VfioGroup },
    Shared { gpu: crate::gpu::HostGpu },
}

impl Isolation {
    fn is_shared(&self) -> bool {
        matches!(self, Self::Shared { .. })
    }

    /// The slot the reservation lock is taken under. Kata keeps the VFIO group
    /// it has always used, so a node upgrading in place finds its own locks.
    fn reservation_slot(&self) -> DeviceSlot {
        match self {
            Self::KataVfio { group } => DeviceSlot::vfio(group.id),
            Self::Shared { gpu } => DeviceSlot::shared_gpu(&gpu.uuid),
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            Self::KataVfio { .. } => "kata-vfio",
            Self::Shared { .. } => "shared",
        }
    }

    /// What the operator sees this called in a failure. A shared lease is not
    /// a Kata workspace and saying so sends them looking for a shim that was
    /// never meant to be there.
    fn workload_noun(&self) -> &'static str {
        match self {
            Self::KataVfio { .. } => "Kata workspace",
            Self::Shared { .. } => "workspace",
        }
    }
}

/// The device a reservation is taken for: the name its lock file carries, and
/// the name an operator reads when something else already holds it.
pub struct DeviceSlot {
    lock: String,
    description: String,
}

impl DeviceSlot {
    fn vfio(group: u32) -> Self {
        Self {
            lock: format!("vfio-{group}"),
            description: format!("VFIO group {group}"),
        }
    }

    fn shared_gpu(uuid: &str) -> Self {
        Self {
            lock: format!("gpu-{uuid}"),
            description: format!("GPU {uuid}"),
        }
    }
}

/// What a shared lease is allowed to take from the host. Kata leases ignore
/// this: the guest gets the machine the hypervisor gave it and nothing on this
/// side can be spent twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseLimits {
    pub memory_mib: u32,
    pub cpus: u32,
}

impl LeaseLimits {
    /// Carried by a Kata lease and never read by one.
    pub const UNUSED: Self = Self {
        memory_mib: 0,
        cpus: 0,
    };

    /// Three quarters of memory and one core short of all of them. The host
    /// still has containerd, the daemon and the operator's own session to run,
    /// and a lease that takes the last core makes the node unreachable rather
    /// than merely busy.
    pub fn for_host() -> anyhow::Result<Self> {
        Ok(Self {
            memory_mib: host_memory_mib()? / 4 * 3,
            cpus: host_cores().saturating_sub(1).max(1),
        })
    }

    fn validate(self) -> anyhow::Result<()> {
        if self.memory_mib < 1_024 {
            anyhow::bail!("a lease needs at least 1024 MiB of memory");
        }
        if self.cpus == 0 {
            anyhow::bail!("a lease needs at least one CPU");
        }
        Ok(())
    }
}

fn host_memory_mib() -> anyhow::Result<u32> {
    let meminfo = fs::read_to_string("/proc/meminfo").context("read host memory from /proc")?;
    let kilobytes: u64 = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|value| value.split_whitespace().next())
        .context("/proc/meminfo has no MemTotal")?
        .parse()
        .context("MemTotal is not a number")?;
    u32::try_from(kilobytes / 1_024).context("host memory does not fit in a lease limit")
}

fn host_cores() -> u32 {
    std::thread::available_parallelism()
        .map(|cores| u32::try_from(cores.get()).unwrap_or(u32::MAX))
        .unwrap_or(1)
}

pub struct LaunchConfig<'a> {
    pub image: &'a str,
    pub lease_id: &'a str,
    pub workspace_root: &'a Path,
    pub state_root: &'a Path,
    pub isolation: &'a Isolation,
    /// Only read in shared mode.
    pub limits: LeaseLimits,
    pub duration_seconds: u32,
    pub ssh_authorized_key: &'a Path,
    pub jupyter_token: &'a Path,
    pub ssh_port: u16,
    pub jupyter_port: u16,
    /// The nonce the guest commits to in the report it takes of itself before
    /// anything starts listening. Present only when this node runs leases as
    /// confidential guests.
    pub attestation_challenge: Option<&'a str>,
    /// The agent policy the confidential guest must run under, named by digest
    /// so it reaches `HOST_DATA`. A lease with a challenge and no digest does
    /// not launch.
    pub agent_policy_digest: Option<&'a str>,
}

pub fn validate_image_reference(image: &str) -> anyhow::Result<()> {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        anyhow::bail!("image must be pinned to a sha256 digest");
    };
    if repository.is_empty()
        || digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("image digest is invalid");
    }
    // Quotes have no place in an OCI reference and the reference is written
    // verbatim into the document Kata hashes into HOST_DATA, so one would let a
    // registry name decide what that document says.
    if image.chars().any(char::is_whitespace) || image.contains("..") || image.contains(['\'', '"'])
    {
        anyhow::bail!("image reference contains unsafe characters");
    }
    if let Some(registry) = explicit_registry(repository)
        && is_private_registry(registry)
    {
        anyhow::bail!("private and local OCI registries are not supported");
    }
    Ok(())
}

fn explicit_registry(repository: &str) -> Option<&str> {
    let first = repository.split('/').next()?;
    (first == "localhost" || first.contains('.') || first.contains(':')).then_some(first)
}

fn is_private_registry(registry: &str) -> bool {
    let host = if let Some(bracketed) = registry.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(registry)
    } else {
        registry.split(':').next().unwrap_or(registry)
    };
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost"
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal")
    {
        return true;
    }
    match normalized.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_unspecified()
        }
        Ok(IpAddr::V6(address)) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

pub fn validate_lease_id(lease_id: &str) -> anyhow::Result<()> {
    if lease_id.is_empty()
        || lease_id.len() > 96
        || !lease_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        anyhow::bail!("lease identifier is invalid");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VfioGroup {
    pub id: u32,
    pub device: PathBuf,
    pub pci_devices: Vec<String>,
}

impl VfioGroup {
    pub fn from_system(id: u32) -> anyhow::Result<Self> {
        validate_vfio_group_at(
            Path::new(SYSTEM_SYSFS_ROOT),
            Path::new(SYSTEM_DEVICE_ROOT),
            id,
        )
    }
}

pub fn discover_vfio_gpu_groups() -> anyhow::Result<Vec<VfioGroup>> {
    discover_vfio_gpu_groups_at(Path::new(SYSTEM_SYSFS_ROOT), Path::new(SYSTEM_DEVICE_ROOT))
}

fn discover_vfio_gpu_groups_at(
    sysfs_root: &Path,
    device_root: &Path,
) -> anyhow::Result<Vec<VfioGroup>> {
    let groups_root = sysfs_root.join("kernel/iommu_groups");
    let Ok(entries) = fs::read_dir(&groups_root) else {
        return Ok(Vec::new());
    };
    let mut groups = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter_map(|id| validate_vfio_group_at(sysfs_root, device_root, id).ok())
        .collect::<Vec<_>>();
    groups.sort_by_key(|group| group.id);
    Ok(groups)
}

fn validate_vfio_group_at(
    sysfs_root: &Path,
    device_root: &Path,
    id: u32,
) -> anyhow::Result<VfioGroup> {
    let group_root = sysfs_root.join("kernel/iommu_groups").join(id.to_string());
    let devices_root = group_root.join("devices");
    let device = device_root.join("vfio").join(id.to_string());
    if !device.exists() {
        anyhow::bail!("VFIO group {id} is not exposed at {}", device.display());
    }

    let entries =
        fs::read_dir(&devices_root).with_context(|| format!("read VFIO group {id} devices"))?;
    let mut pci_devices = Vec::new();
    let mut contains_gpu = false;
    for entry in entries {
        let entry = entry?;
        let pci_address = entry.file_name().to_string_lossy().into_owned();
        let device_root = entry.path();
        let driver = fs::read_link(device_root.join("driver"))
            .with_context(|| format!("{pci_address} has no bound PCI driver"))?;
        if driver.file_name().and_then(|name| name.to_str()) != Some("vfio-pci") {
            anyhow::bail!("every device in VFIO group {id} must use vfio-pci");
        }
        let class = fs::read_to_string(device_root.join("class"))
            .with_context(|| format!("read PCI class for {pci_address}"))?;
        let class = class.trim().trim_start_matches("0x");
        let class = u32::from_str_radix(class, 16)
            .with_context(|| format!("invalid PCI class for {pci_address}"))?;
        contains_gpu |= matches!(class >> 8, 0x0300 | 0x0302);
        pci_devices.push(pci_address);
    }
    if pci_devices.is_empty() {
        anyhow::bail!("VFIO group {id} has no PCI devices");
    }
    if !contains_gpu {
        anyhow::bail!("VFIO group {id} does not contain a display or 3D controller");
    }
    pci_devices.sort();
    Ok(VfioGroup {
        id,
        device,
        pci_devices,
    })
}

pub fn kata_command(
    config: &LaunchConfig<'_>,
    control_directory: &Path,
) -> anyhow::Result<Command> {
    if config.isolation.is_shared() {
        anyhow::bail!(
            "this lease runs on a host-visible GPU and cannot be started as a Kata guest"
        );
    }
    workspace_command(config, control_directory, None)
}

/// The same workspace on a host that kept its GPU. The card is injected by the
/// container toolkit rather than passed through to a virtual machine, so the
/// operator can read everything the workload touches, and the node says so by
/// serving this at the Open trust class.
pub fn shared_command(
    config: &LaunchConfig<'_>,
    control_directory: &Path,
) -> anyhow::Result<Command> {
    if !config.isolation.is_shared() {
        anyhow::bail!("this lease runs on a passed-through GPU and needs the Kata runtime");
    }
    workspace_command(config, control_directory, None)
}

/// The same workspace, launched as a confidential guest so it can attest
/// itself. Three things separate it from the ordinary runtime. The confidential
/// shim is what actually gives the guest a report to take. Guest-side image
/// pull keeps the rootfs out of the host's hands, so what the report measures
/// is what the renter asked for rather than whatever was handed in over
/// virtiofs. And the agent policy digest travels in the document Kata hashes
/// into `HOST_DATA`, which is the only thing tying the report to the workload.
///
/// Any of the three missing is a refusal, never a quieter launch. Falling back
/// to the ordinary runtime would start a guest that produces no report at all,
/// or one that produces a genuine report about an unmeasured workload, and the
/// second is worse than the first because it looks like evidence.
///
/// Nothing here touches the guest kernel or its command line, and nothing
/// should. A passthrough H100 needs a large SWIOTLB because every DMA crosses
/// into shared bounce buffers, but the command line feeds the launch digest, so
/// a value chosen per launch is a measurement no published reference matches.
/// It belongs in the pinned guest configuration that the reference measurement
/// was computed from.
pub fn kata_snp_command(
    config: &LaunchConfig<'_>,
    control_directory: &Path,
    policy_digest: &str,
) -> anyhow::Result<Command> {
    kata_snp_command_in(
        config,
        control_directory,
        policy_digest,
        &crate::probe::search_path(),
    )
}

fn kata_snp_command_in(
    config: &LaunchConfig<'_>,
    control_directory: &Path,
    policy_digest: &str,
    search_path: &OsStr,
) -> anyhow::Result<Command> {
    if policy_digest.len() != 64
        || !policy_digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("a confidential guest needs the agent policy digest that pins its workload");
    }
    if !crate::probe::confidential_runtime_registered_in(search_path) {
        anyhow::bail!(
            "containerd has no {} shim, so this host cannot start a confidential guest",
            crate::probe::CONFIDENTIAL_RUNTIME
        );
    }
    workspace_command(config, control_directory, Some(policy_digest))
}

/// The device flags, spliced where Kata's pair of VFIO nodes sits.
///
/// `--gpus` is what nerdctl hands to containerd's NVIDIA support, and that
/// execs `nvidia-container-cli` to inject the driver and the device nodes. The
/// selector always names one card by its UUID: the node advertises one card and
/// hands over one card, and `all` on a two-card machine would quietly give a
/// renter both.
fn device_arguments(isolation: &Isolation, limits: LeaseLimits) -> anyhow::Result<Vec<String>> {
    Ok(match isolation {
        Isolation::KataVfio { group } => vec![
            "--device".to_owned(),
            "/dev/vfio/vfio".to_owned(),
            "--device".to_owned(),
            format!("/dev/vfio/{}", group.id),
        ],
        Isolation::Shared { gpu } => {
            limits.validate()?;
            let memory = format!("{}m", limits.memory_mib);
            vec![
                "--gpus".to_owned(),
                format!("device={}", gpu.uuid),
                "--memory".to_owned(),
                memory.clone(),
                // Equal to the memory limit, which is how runc is told the
                // lease gets no swap of its own. Without it a lease reaches
                // past its limit and the host pays for it in latency.
                "--memory-swap".to_owned(),
                memory,
                "--cpus".to_owned(),
                limits.cpus.to_string(),
                "--ulimit".to_owned(),
                "nofile=8192:8192".to_owned(),
            ]
        }
    })
}

struct TmpfsMounts {
    run: String,
    temporary: String,
    workspace: String,
}

impl TmpfsMounts {
    /// Under Kata these live in the guest's own memory and the hypervisor
    /// bounds them. Under runc they come out of host RAM, so they are sized to
    /// fit inside the lease's memory limit rather than the machine's.
    fn new(isolation: &Isolation, limits: LeaseLimits) -> Self {
        let sized = |options: &str, mib: u32| match isolation {
            Isolation::KataVfio { .. } => options.to_owned(),
            Isolation::Shared { .. } => format!("{options},size={mib}m"),
        };
        Self {
            run: sized("/run:rw,nosuid,nodev,mode=0755", 64),
            temporary: sized(
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                limits.memory_mib / 4,
            ),
            workspace: sized(
                "/workspace:rw,nosuid,nodev,mode=0700",
                limits.memory_mib / 2,
            ),
        }
    }
}

fn workspace_command(
    config: &LaunchConfig<'_>,
    control_directory: &Path,
    policy_digest: Option<&str>,
) -> anyhow::Result<Command> {
    validate_launch_config(config)?;
    let control_mount = format!(
        "type=bind,src={},dst=/run/prism/control,ro",
        control_directory.display()
    );
    let ssh_publish = format!("127.0.0.1:{}:2222", config.ssh_port);
    let jupyter_publish = format!("127.0.0.1:{}:8888", config.jupyter_port);
    let evidence_mount = format!(
        "type=bind,src={},dst=/run/prism/evidence",
        crate::snp::evidence_directory(control_directory).display()
    );
    let initdata = policy_digest.map(|digest| {
        format!(
            "io.katacontainers.config.hypervisor.cc_init_data={}",
            crate::snp::initdata_annotation(config.lease_id, config.image, digest)
        )
    });
    let device = device_arguments(config.isolation, config.limits)?;
    let tmpfs = TmpfsMounts::new(config.isolation, config.limits);
    let mut command = Command::new("nerdctl");
    command.args([
        "--namespace",
        "prism",
        "run",
        "--rm",
        "--pull",
        "always",
        "--runtime",
        match (policy_digest, config.isolation) {
            (Some(_), _) => crate::probe::CONFIDENTIAL_RUNTIME,
            (None, Isolation::KataVfio { .. }) => "io.containerd.kata.v2",
            // Named rather than left to the containerd default, so the log
            // line an operator reads says which runtime actually ran.
            (None, Isolation::Shared { .. }) => "io.containerd.runc.v2",
        },
        "--read-only",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "KILL",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SYS_CHROOT",
        "--pids-limit",
        "2048",
        "--user",
        "0:0",
        "--sysctl",
        "net.ipv6.conf.all.disable_ipv6=1",
    ]);
    command.args(&device);
    command.args([
        "--tmpfs",
        &tmpfs.run,
        "--tmpfs",
        &tmpfs.temporary,
        "--tmpfs",
        &tmpfs.workspace,
        "--mount",
        &control_mount,
        "--publish",
        &ssh_publish,
        "--publish",
        &jupyter_publish,
        "--hostname",
        config.lease_id,
    ]);
    if policy_digest.is_some() {
        // The only launch that prints anything the node needs to read back.
        command.stdout(Stdio::piped());
    }
    if let Some(initdata) = &initdata {
        // The rootfs is pulled by the guest rather than unpacked on the host,
        // so the image the report measures is the one the renter named.
        command.args(["--snapshotter", "nydus", "--annotation", initdata]);
        // The report has to outlive the guest, and the control mount it reads
        // the challenge from is read-only.
        command.args(["--mount", &evidence_mount]);
        // The guest kernel carries the SEV driver and configfs-tsm, but nothing
        // mounts configfs in the container, and `/dev/sev-guest` cannot be
        // passed through because nerdctl resolves a device path on the host,
        // where a guest-only node does not exist. Mounting is the way in and it
        // needs this. Only the bootstrap holds it: it takes the report before
        // anything listens, unmounts, and everything the renter reaches runs as
        // an unprivileged account with no capabilities at all.
        command.args(["--cap-add", "SYS_ADMIN"]);
    }
    command.args([
        "--entrypoint",
        "/bin/sh",
        "--name",
        config.lease_id,
        config.image,
        "/run/prism/control/bootstrap.sh",
    ]);
    Ok(command)
}

/// The collector that talks to the GPU and writes the report. Pinned by digest
/// and not configurable: a host that can choose what produces the evidence can
/// produce evidence of whatever it likes. The digest is filled in from the
/// published reporter build, and an unset one fails the pull rather than
/// resolving to a moving tag.
const ATTESTATION_IMAGE: &str = "ghcr.io/winter0x/prism/gpu-attest@sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Same isolation a lease gets, with the workspace ports and credentials
/// removed and one writable directory added. The lease control mount is
/// read-only, so the report needs a mount of its own to land in.
pub fn attestation_command(
    group: &VfioGroup,
    evidence_directory: &Path,
    nonce_hex: &str,
) -> anyhow::Result<Command> {
    validate_image_reference(ATTESTATION_IMAGE)?;
    if nonce_hex.len() != 64
        || !nonce_hex
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        anyhow::bail!("attestation nonce must be a 32-byte hex digest");
    }
    let vfio_device = group
        .device
        .to_str()
        .context("VFIO device path is not valid UTF-8")?
        .to_owned();
    let evidence_mount = format!(
        "type=bind,src={},dst=/run/prism/evidence",
        evidence_directory
            .to_str()
            .context("evidence directory is not valid UTF-8")?
    );
    let name = format!("prism-attest-{}", group.id);
    let mut command = Command::new("nerdctl");
    command.args([
        "--namespace",
        "prism",
        "run",
        "--rm",
        "--pull",
        "always",
        "--runtime",
        "io.containerd.kata.v2",
        "--read-only",
        "--net",
        "none",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "256",
        "--user",
        "0:0",
        "--device",
        "/dev/vfio/vfio",
        "--device",
        &vfio_device,
        "--tmpfs",
        "/run:rw,nosuid,nodev,mode=0755",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--mount",
        &evidence_mount,
        "--name",
        &name,
        ATTESTATION_IMAGE,
        "--nonce",
        nonce_hex,
        "--output",
        "/run/prism/evidence",
    ]);
    command.stdin(Stdio::null());
    // The report comes back through the mount, so nothing here reads the pipes.
    // Leaving stderr with the daemon keeps a failed collection diagnosable
    // without a reader that would have to drain it to avoid a stall.
    command.stdout(Stdio::null());
    Ok(command)
}

pub fn launch(config: LaunchConfig<'_>) -> anyhow::Result<()> {
    validate_launch_config(&config)?;
    // Kata resolves the group against sysfs here rather than trusting the
    // caller, which is what has always guarded a stale group number.
    let isolation = match config.isolation {
        Isolation::KataVfio { group } => Isolation::KataVfio {
            group: VfioGroup::from_system(group.id)?,
        },
        Isolation::Shared { .. } => config.isolation.clone(),
    };
    let _reservation = DeviceReservation::acquire_slot(
        Path::new(SYSTEM_LOCK_ROOT),
        &isolation.reservation_slot(),
        config.lease_id,
    )?;
    release_stale_host_ports(config.ssh_port, config.jupyter_port);
    fs::create_dir_all(config.workspace_root)?;
    fs::create_dir_all(config.state_root)?;
    let workspace = workspace_path(config.workspace_root, config.lease_id)?;
    let state_path = state_path(config.state_root, config.lease_id)?;
    if state_path.exists() {
        recover_interrupted_lease(config.lease_id, &workspace, &state_path)?;
    }
    // Before anything is written for this lease, so a pull that fails leaves no
    // state behind claiming a lease is coming up.
    if config.isolation.is_shared() {
        pull_image(config.image)?;
    }
    let mut command = match config.attestation_challenge {
        Some(_) => {
            let policy_digest = config.agent_policy_digest.context(
                "this lease needs a confidential guest and no agent policy digest is configured",
            )?;
            kata_snp_command(&config, &workspace, policy_digest)?
        }
        None => workspace_command(&config, &workspace, None)?,
    };
    fs::create_dir_all(&workspace)?;
    prepare_control_directory(&config, &workspace)?;
    persist_state(
        &state_path,
        &LeaseState::new(&config, &isolation, LeasePhase::Provisioning, None, None),
    )?;
    let mut ready_at = None;
    // Policy first, container second: the container's first process comes out
    // of the renter's image and runs the moment it exists.
    let started = install_startup_policy(&isolation).and_then(|()| {
        command.spawn().context(match config.isolation {
            Isolation::KataVfio { .. } => "failed to start the Kata workspace through nerdctl",
            Isolation::Shared { .. } => "failed to start the workspace through nerdctl",
        })
    });
    let result = match started {
        Ok(mut child) => {
            let printed = child.stdout.take().map(|stdout| {
                collect_printed_evidence(stdout, crate::snp::evidence_directory(&workspace))
            });
            let result = run_workspace(
                &config,
                &workspace,
                &state_path,
                &isolation,
                &mut child,
                &mut ready_at,
            );
            if let Some(printed) = printed {
                let _ = printed.join();
            }
            let _ = remove_egress_policy();
            if child.try_wait().ok().flatten().is_none() {
                let _ = stop_container(config.lease_id, isolation.workload_noun());
                let _ = child.wait();
            }
            result
        }
        Err(error) => {
            remove_shared_policy(&isolation);
            Err(error)
        }
    };
    let cleanup = fs::remove_dir_all(&workspace).context("remove lease workspace");
    let outcome = result.and(cleanup);
    let (phase, error) = match &outcome {
        Ok(()) => (LeasePhase::Completed, None),
        Err(error) => (LeasePhase::Failed, Some(error.to_string())),
    };
    persist_state(
        &state_path,
        &LeaseState::new(&config, &isolation, phase, error, ready_at),
    )?;
    outcome
}

/// Bring the image down before the container is asked to start.
///
/// `nerdctl run --pull always` does the same thing, but it does it inside the
/// window the readiness check is timing, so a workspace image arriving over a
/// consumer uplink reads as a lease that never came up. Pulling first costs a
/// digest check on the second pass and nothing else.
fn pull_image(image: &str) -> anyhow::Result<()> {
    validate_image_reference(image)?;
    let mut child = Command::new("nerdctl")
        .args(["--namespace", "prism", "pull", "--quiet", image])
        .stdin(Stdio::null())
        .spawn()
        .context("failed to start the image pull through nerdctl")?;
    let deadline = Instant::now() + IMAGE_PULL_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                anyhow::bail!("nerdctl could not pull the workspace image");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("the workspace image did not finish downloading within an hour");
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Drop any port forward left over from a previous workspace.
///
/// The portmap plugin is supposed to remove its DNAT rules when a container
/// goes away and on some hosts it does not, including after an explicit
/// `nerdctl rm --force`. A node publishes the same two ports for every lease it
/// ever serves, so a single leaked rule makes every later launch fail with
/// "port is already allocated" and takes the node out of service permanently.
/// One lease runs at a time here, so any rule naming these ports before we
/// start belongs to a workspace that is already gone.
///
/// Best effort by design: a host with no iptables, or one where nothing leaked,
/// should launch normally rather than fail on a cleanup that was not needed.
fn release_stale_host_ports(ssh_port: u16, jupyter_port: u16) {
    // The port list is `--dports 2222,8888` and the rule continues past it, so
    // this reads the list and compares each entry rather than matching the
    // number in place. A node with several GPUs serves several leases at once,
    // and a rule naming somebody else's ports has to survive.
    let script = format!(
        "iptables -t nat -S CNI-HOSTPORT-DNAT 2>/dev/null | while read -r rule; do \
           ports=$(printf '%s' \"$rule\" | sed -n 's/.*--dports \\([0-9,]*\\).*/\\1/p'); \
           [ -n \"$ports\" ] || continue; \
           mine=0; \
           old=$IFS; IFS=','; \
           for port in $ports; do \
             if [ \"$port\" = \"{ssh}\" ] || [ \"$port\" = \"{jupyter}\" ]; then mine=1; fi; \
           done; \
           IFS=$old; \
           [ \"$mine\" = 1 ] || continue; \
           target=$(printf '%s' \"$rule\" | grep -oE 'CNI-DN-[a-f0-9]+' || true); \
           iptables -t nat $(printf '%s' \"$rule\" | sed 's/^-A/-D/') 2>/dev/null || true; \
           [ -n \"$target\" ] || continue; \
           iptables -t nat -F \"$target\" 2>/dev/null || true; \
           iptables -t nat -X \"$target\" 2>/dev/null || true; \
         done",
        ssh = ssh_port,
        jupyter = jupyter_port,
    );
    match Command::new("sh").arg("-c").arg(script).output() {
        Ok(output) if !output.status.success() => {
            tracing::warn!(
                status = %output.status,
                "could not clear stale host port forwards; a leaked one will fail the launch"
            );
        }
        Err(error) => tracing::warn!(%error, "could not run the host port cleanup"),
        _ => {}
    }
}

fn recover_interrupted_lease(
    lease_id: &str,
    workspace: &Path,
    state_path: &Path,
) -> anyhow::Result<()> {
    let _ = Command::new("nerdctl")
        .args(["--namespace", "prism", "rm", "--force", lease_id])
        .output();
    if workspace.exists() {
        fs::remove_dir_all(workspace).context("remove interrupted lease workspace")?;
    }
    fs::remove_file(state_path).context("remove interrupted lease state")
}

fn validate_launch_config(config: &LaunchConfig<'_>) -> anyhow::Result<()> {
    validate_image_reference(config.image)?;
    validate_lease_id(config.lease_id)?;
    if config.duration_seconds == 0 || config.duration_seconds > MAX_LEASE_SECONDS {
        anyhow::bail!("lease duration must be between one second and six hours");
    }
    if config.ssh_port == 0 || config.jupyter_port == 0 || config.ssh_port == config.jupyter_port {
        anyhow::bail!("workspace access ports are invalid");
    }
    // A shared lease runs on the host's own kernel, so there is no guest to
    // take a report and nothing an attestation could measure. Refusing here
    // means no configuration mistake can produce a lease that looks attested.
    if config.isolation.is_shared() {
        config.limits.validate()?;
        if config.attestation_challenge.is_some() || config.agent_policy_digest.is_some() {
            anyhow::bail!(
                "a shared lease cannot produce a guest report; serve attested leases with --isolation kata-vfio"
            );
        }
    }
    if let Some(challenge) = config.attestation_challenge
        && (challenge.len() != 64
            || !challenge
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
    {
        anyhow::bail!("the lease attestation challenge must be a 32-byte hex nonce");
    }
    validate_authorized_key(&fs::read_to_string(config.ssh_authorized_key)?)?;
    validate_jupyter_token(&fs::read_to_string(config.jupyter_token)?)?;
    Ok(())
}

fn prepare_control_directory(config: &LaunchConfig<'_>, workspace: &Path) -> anyhow::Result<()> {
    write_secret(
        &workspace.join("authorized_keys"),
        fs::read(config.ssh_authorized_key)?.as_slice(),
    )?;
    write_secret(
        &workspace.join("jupyter_token"),
        fs::read(config.jupyter_token)?.as_slice(),
    )?;
    if let Some(challenge) = config.attestation_challenge {
        fs::create_dir_all(crate::snp::evidence_directory(workspace))
            .context("create the guest evidence directory")?;
        write_secret(
            &workspace.join("attestation_challenge"),
            format!("{challenge}\n").as_bytes(),
        )?;
        write_secret(
            &workspace.join("lease_id"),
            format!("{}\n", config.lease_id).as_bytes(),
        )?;
    }
    write_secret(
        &workspace.join("bootstrap.sh"),
        match config.isolation {
            Isolation::KataVfio { .. } => WORKSPACE_BOOTSTRAP,
            Isolation::Shared { .. } => WORKSPACE_BOOTSTRAP_SHARED,
        }
        .as_bytes(),
    )
}

fn write_secret(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

/// Catches the evidence a confidential guest prints on its way up.
///
/// The guest cannot leave it anywhere the node can read: Kata gives a
/// confidential guest a private copy of every directory the host offers, so a
/// bind mount carries data in and nothing out. Standard output is the one path
/// that does not require the host to reach into the guest, which is the thing a
/// confidential guest exists to prevent.
///
/// Relaying is safe. The processor signs the report and REPORT_DATA binds it to
/// this lease, this challenge and the key the session terminates on, so a node
/// that alters a byte produces something the control plane refuses.
fn collect_printed_evidence(
    stdout: std::process::ChildStdout,
    evidence_directory: PathBuf,
) -> thread::JoinHandle<()> {
    use std::io::{BufRead, BufReader};

    thread::spawn(move || {
        // Drained continuously whether or not anything is wanted from it: a
        // full pipe stops the workspace.
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("prism-evidence") {
                continue;
            }
            let (Some(name), Some(encoded)) = (fields.next(), fields.next()) else {
                continue;
            };
            // The name decides a path, so it is matched against what the guest
            // is allowed to send rather than joined onto a directory.
            let Some(name) = EVIDENCE_ARTIFACTS
                .iter()
                .find(|artifact| **artifact == name)
            else {
                tracing::warn!(%name, "ignoring an evidence artifact this node does not expect");
                continue;
            };
            match base64_standard(encoded) {
                Ok(bytes) => {
                    if let Err(error) = fs::create_dir_all(&evidence_directory)
                        .and_then(|()| fs::write(evidence_directory.join(name), bytes))
                    {
                        tracing::warn!(%error, %name, "could not store the printed evidence");
                    }
                }
                Err(error) => tracing::warn!(%error, %name, "printed evidence is not base64"),
            }
        }
    })
}

/// Exactly what a guest may hand back, so a name it chooses cannot decide a
/// path outside the evidence directory.
const EVIDENCE_ARTIFACTS: [&str; 3] = [
    "guest-report.bin",
    "guest-chain.b64",
    "guest-channel-key.pub",
];

fn base64_standard(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    Ok(STANDARD.decode(value)?)
}

fn run_workspace(
    config: &LaunchConfig<'_>,
    workspace: &Path,
    state_path: &Path,
    isolation: &Isolation,
    child: &mut Child,
    ready_at: &mut Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let ip = wait_for_container_ip(config.lease_id, child, READINESS_TIMEOUT, isolation)?;
    install_egress_policy(ip, isolation)?;
    write_secret(&workspace.join("network-ready"), b"ready\n")?;
    wait_for_access(config, child, READINESS_TIMEOUT, isolation)?;
    *ready_at = Some(Utc::now());
    persist_state(
        state_path,
        &LeaseState::new(config, isolation, LeasePhase::Ready, None, *ready_at),
    )?;

    let deadline = Instant::now() + Duration::from_secs(u64::from(config.duration_seconds));
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "{} exited before the lease deadline: {status}",
                isolation.workload_noun()
            );
        }
        if Instant::now() >= deadline {
            stop_container(config.lease_id, isolation.workload_noun())?;
            let _ = child.wait();
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_container_ip(
    lease_id: &str,
    child: &mut Child,
    timeout: Duration,
    isolation: &Isolation,
) -> anyhow::Result<IpAddr> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "{} exited before network policy installation: {status}",
                isolation.workload_noun()
            );
        }
        let output = Command::new("nerdctl")
            .args([
                "--namespace",
                "prism",
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                lease_id,
            ])
            .output();
        if let Ok(output) = output
            && output.status.success()
            && let Ok(value) = std::str::from_utf8(&output.stdout)
            && let Ok(ip) = value.trim().parse()
        {
            return Ok(ip);
        }
        thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!(
        "{} did not receive a network address",
        isolation.workload_noun()
    )
}

fn wait_for_access(
    config: &LaunchConfig<'_>,
    child: &mut Child,
    timeout: Duration,
    isolation: &Isolation,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let ssh = SocketAddr::from(([127, 0, 0, 1], config.ssh_port));
    let jupyter = SocketAddr::from(([127, 0, 0, 1], config.jupyter_port));
    let mut ssh_ready = false;
    let mut jupyter_ready = false;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "{} exited before access readiness: {status}",
                isolation.workload_noun()
            );
        }
        ssh_ready |= TcpStream::connect_timeout(&ssh, Duration::from_millis(500)).is_ok();
        jupyter_ready |= TcpStream::connect_timeout(&jupyter, Duration::from_millis(500)).is_ok();
        if ssh_ready && jupyter_ready {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!(
        "{} did not make SSH and Jupyter ready",
        isolation.workload_noun()
    )
}

fn stop_container(lease_id: &str, noun: &str) -> anyhow::Result<()> {
    let status = Command::new("nerdctl")
        .args(["--namespace", "prism", "stop", "--time", "10", lease_id])
        .status()
        .with_context(|| format!("stop {noun}"))?;
    if !status.success() {
        anyhow::bail!("nerdctl could not stop the {noun}");
    }
    Ok(())
}

fn install_egress_policy(source: IpAddr, isolation: &Isolation) -> anyhow::Result<()> {
    install_policy(&egress_policy(source, isolation)?)
}

/// Close the bridge before the container starts.
///
/// The container's first process comes from the renter's own image, so the wait
/// on `network-ready` in the bootstrap is the renter's code and cannot be
/// relied on. Until the address is known the same rules are keyed on the
/// interface the lease arrives over, which is the same scope while one lease
/// runs per host. `nerdctl0` is the bridge nerdctl builds for its default
/// network; a host that renames it is left with the per-address policy alone.
fn install_startup_policy(isolation: &Isolation) -> anyhow::Result<()> {
    if !isolation.is_shared() {
        return Ok(());
    }
    install_policy(&startup_policy())
}

fn startup_policy() -> String {
    format!(
        "table inet prism {{\n\
         chain forward {{\n\
         type filter hook forward priority -10; policy accept;\n\
         iifname \"{LEASE_BRIDGE}\" ip daddr {PRIVATE_DESTINATIONS} reject\n\
         iifname \"{LEASE_BRIDGE}\" tcp dport {MAIL_PORTS} reject\n\
         }}\n\
         chain input {{\n\
         type filter hook input priority -10; policy accept;\n\
         ct state established,related accept\n\
         iifname \"{LEASE_BRIDGE}\" udp dport 53 accept\n\
         iifname \"{LEASE_BRIDGE}\" tcp dport 53 accept\n\
         iifname \"{LEASE_BRIDGE}\" reject\n\
         }}\n\
         }}\n"
    )
}

fn remove_shared_policy(isolation: &Isolation) {
    if isolation.is_shared() {
        let _ = remove_egress_policy();
    }
}

/// A container the daemon has stopped following is taken down rather than left
/// running: nothing holds it to its paid deadline any more, and on a shared
/// node it sits on the host's own bridge.
fn abandon_batch(child: &mut Child, lease_id: &str, isolation: &Isolation) {
    let _ = child.kill();
    let _ = stop_container(lease_id, isolation.workload_noun());
    let _ = child.wait();
    remove_shared_policy(isolation);
}

fn install_policy(script: &str) -> anyhow::Result<()> {
    let _ = remove_egress_policy();
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("start nftables")?;
    child
        .stdin
        .take()
        .context("open nftables stdin")?
        .write_all(script.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("failed to install the workspace egress policy");
    }
    Ok(())
}

fn egress_policy(source: IpAddr, isolation: &Isolation) -> anyhow::Result<String> {
    let IpAddr::V4(source) = source else {
        anyhow::bail!("workspace network must use IPv4 with IPv6 disabled");
    };
    let forward = format!(
        "chain forward {{\n\
         type filter hook forward priority -10; policy accept;\n\
         ip saddr {source} ip daddr {PRIVATE_DESTINATIONS} reject\n\
         ip saddr {source} tcp dport {MAIL_PORTS} reject\n\
         }}\n"
    );
    // A Kata lease reaches the host across a hypervisor boundary. A shared one
    // sits on the host's own bridge, so the host is one hop away and the input
    // hook is the only thing between the workload and every service listening
    // on this machine.
    //
    // The established rule has to come first. SSH and Jupyter are published on
    // loopback and reach the container through DNAT, and the replies arrive
    // back at the input hook with the container as their source. Rejecting
    // those kills every lease on the node.
    let input = match isolation {
        Isolation::KataVfio { .. } => String::new(),
        Isolation::Shared { .. } => format!(
            "chain input {{\n\
             type filter hook input priority -10; policy accept;\n\
             ct state established,related accept\n\
             ip saddr {source} udp dport 53 accept\n\
             ip saddr {source} tcp dport 53 accept\n\
             ip saddr {source} reject\n\
             }}\n"
        ),
    };
    Ok(format!("table inet prism {{\n{forward}{input}}}\n"))
}

fn remove_egress_policy() -> anyhow::Result<()> {
    let output = Command::new("nft")
        .args(["delete", "table", "inet", "prism"])
        .output()
        .context("remove nftables workspace policy")?;
    if output.status.success() || String::from_utf8_lossy(&output.stderr).contains("No such file") {
        return Ok(());
    }
    anyhow::bail!("failed to remove the workspace egress policy")
}

fn validate_authorized_key(value: &str) -> anyhow::Result<()> {
    let value = value.trim();
    if value.len() > 16_384
        || !value.starts_with("ssh-ed25519 ")
        || value.lines().count() != 1
        || value.split_whitespace().count() < 2
    {
        anyhow::bail!("SSH access requires one Ed25519 authorized key");
    }
    Ok(())
}

fn validate_jupyter_token(value: &str) -> anyhow::Result<()> {
    let value = value.trim();
    if !(32..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("Jupyter token must be 32 to 128 URL-safe characters");
    }
    Ok(())
}

pub fn workspace_path(root: &Path, lease_id: &str) -> anyhow::Result<PathBuf> {
    validate_lease_id(lease_id)?;
    let root = root.canonicalize().context("workspace root must exist")?;
    let workspace = root.join(lease_id);
    if !workspace.starts_with(&root) {
        anyhow::bail!("workspace path escapes its root");
    }
    Ok(workspace)
}

fn state_path(root: &Path, lease_id: &str) -> anyhow::Result<PathBuf> {
    validate_lease_id(lease_id)?;
    let root = root.canonicalize().context("state root must exist")?;
    Ok(root.join(format!("{lease_id}.json")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePhase {
    Provisioning,
    Ready,
    Completed,
    Failed,
}

pub fn lease_phase(root: &Path, lease_id: &str) -> anyhow::Result<Option<LeasePhase>> {
    fs::create_dir_all(root)?;
    let path = state_path(root, lease_id)?;
    match fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice::<LeaseState>(&bytes)
                .context("read lease runtime state")?
                .phase,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseState {
    lease_id: String,
    image: String,
    /// Absent from state files written before this node served shared leases,
    /// and a daemon that restarts mid-upgrade has to be able to read those.
    #[serde(default = "kata_vfio_mode")]
    isolation: String,
    vfio_group: Option<u32>,
    pci_devices: Vec<String>,
    phase: LeasePhase,
    ssh_port: u16,
    jupyter_port: u16,
    ready_at: Option<DateTime<Utc>>,
    error: Option<String>,
    updated_at: DateTime<Utc>,
}

fn kata_vfio_mode() -> String {
    "kata-vfio".to_owned()
}

impl LeaseState {
    fn new(
        config: &LaunchConfig<'_>,
        isolation: &Isolation,
        phase: LeasePhase,
        error: Option<String>,
        ready_at: Option<DateTime<Utc>>,
    ) -> Self {
        let (vfio_group, pci_devices) = match isolation {
            Isolation::KataVfio { group } => (Some(group.id), group.pci_devices.clone()),
            Isolation::Shared { .. } => (None, Vec::new()),
        };
        Self {
            lease_id: config.lease_id.to_owned(),
            image: config.image.to_owned(),
            isolation: isolation.mode().to_owned(),
            vfio_group,
            pci_devices,
            phase,
            ssh_port: config.ssh_port,
            jupyter_port: config.jupyter_port,
            ready_at,
            error,
            updated_at: Utc::now(),
        }
    }
}

/// Whether any lease on this node was still running when its state was last
/// written. A daemon that restarted mid-lease finds one of these, and the idle
/// workload must not start on top of it.
///
/// The file is written when the lease starts and again when it ends, so one
/// that still says the lease is running is only believable for as long as a
/// lease can run. Past that it is a leftover from a node that went down mid
/// lease, and believing it would keep the idle workload off the card for as
/// long as the machine stays up.
pub fn lease_in_flight(root: &Path) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    let horizon = Utc::now() - chrono::Duration::seconds(i64::from(MAX_LEASE_SECONDS));
    entries.filter_map(Result::ok).any(|entry| {
        entry
            .path()
            .extension()
            .is_some_and(|suffix| suffix == "json")
            && fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<LeaseState>(&bytes).ok())
                .is_some_and(|state| {
                    matches!(state.phase, LeasePhase::Provisioning | LeasePhase::Ready)
                        && state.updated_at > horizon
                })
    })
}

fn persist_state(path: &Path, state: &LeaseState) -> anyhow::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

/// One lease at a time per card, held for as long as the lease runs.
///
/// The idle workload takes the same lock, so a workspace started by hand cannot
/// come up underneath a miner that is still on the GPU.
pub struct DeviceReservation {
    path: PathBuf,
}

/// Take the shared card's slot for something that is not a lease. The name has
/// to match what a shared launch would take, or the two would not exclude each
/// other.
pub fn reserve_shared_gpu(
    lock_root: &Path,
    gpu_uuid: &str,
    holder: &str,
) -> anyhow::Result<DeviceReservation> {
    DeviceReservation::acquire_slot(lock_root, &DeviceSlot::shared_gpu(gpu_uuid), holder)
}

pub fn system_lock_root() -> &'static Path {
    Path::new(SYSTEM_LOCK_ROOT)
}

#[derive(Serialize, Deserialize)]
struct ReservationRecord {
    pid: u32,
    process_start_ticks: Option<u64>,
    lease_id: String,
}

impl DeviceReservation {
    fn acquire_slot(root: &Path, slot: &DeviceSlot, lease_id: &str) -> anyhow::Result<Self> {
        validate_lease_id(lease_id)?;
        fs::create_dir_all(root).with_context(|| {
            format!(
                "create the device reservation directory at {}",
                root.display()
            )
        })?;
        let path = root.join(format!("{}.lock", slot.lock));
        let record = ReservationRecord {
            pid: process::id(),
            process_start_ticks: process_start_ticks(process::id()),
            lease_id: lease_id.to_owned(),
        };
        for _ in 0..2 {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(&serde_json::to_vec(&record)?)?;
                    file.sync_all()?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = fs::read(&path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<ReservationRecord>(&bytes).ok());
                    if existing.as_ref().is_some_and(reservation_is_live) {
                        anyhow::bail!("{} is already reserved", slot.description);
                    }
                    match fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("{} reservation changed concurrently", slot.description)
    }
}

fn reservation_is_live(record: &ReservationRecord) -> bool {
    if record.pid == process::id() {
        return record.process_start_ticks == process_start_ticks(record.pid);
    }
    record
        .process_start_ticks
        .zip(process_start_ticks(record.pid))
        .is_some_and(|(expected, actual)| expected == actual)
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.get(stat.rfind(')')? + 1..)?.split_whitespace();
    fields.nth(19)?.parse().ok()
}

impl Drop for DeviceReservation {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// A batch workload: the same Kata VM and exclusive GPU as an interactive
/// lease, but it runs one command and exits. Nothing is published and no
/// credentials are written, so there is no way in and nothing to leak.
pub struct BatchConfig<'a> {
    pub image: &'a str,
    pub lease_id: &'a str,
    pub command: &'a str,
    pub workspace_root: &'a Path,
    pub state_root: &'a Path,
    pub isolation: &'a Isolation,
    /// Only read in shared mode.
    pub limits: LeaseLimits,
    pub duration_seconds: u32,
}

pub fn batch_command(config: &BatchConfig<'_>) -> anyhow::Result<Command> {
    validate_batch_config(config)?;
    let device = device_arguments(config.isolation, config.limits)?;
    let tmpfs = TmpfsMounts::new(config.isolation, config.limits);
    let mut command = Command::new("nerdctl");
    command.args([
        "--namespace",
        "prism",
        "run",
        "--rm",
        "--pull",
        "always",
        "--runtime",
        match config.isolation {
            Isolation::KataVfio { .. } => "io.containerd.kata.v2",
            Isolation::Shared { .. } => "io.containerd.runc.v2",
        },
        "--read-only",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "2048",
        "--user",
        "0:0",
        "--sysctl",
        "net.ipv6.conf.all.disable_ipv6=1",
    ]);
    command.args(&device);
    command.args([
        "--tmpfs",
        &tmpfs.run,
        "--tmpfs",
        &tmpfs.temporary,
        "--tmpfs",
        &tmpfs.workspace,
        "--hostname",
        config.lease_id,
        "--entrypoint",
        "/bin/sh",
        "--name",
        config.lease_id,
        config.image,
        "-c",
        config.command,
    ]);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    Ok(command)
}

/// Run the command to completion, or kill it when its paid duration runs out.
/// Returns what it printed and the code it exited with; a command that fails is
/// a result, not an error, because the renter still paid for the attempt.
pub fn run_batch(config: BatchConfig<'_>) -> anyhow::Result<prism_protocol::CommandResult> {
    validate_batch_config(&config)?;
    let isolation = match config.isolation {
        Isolation::KataVfio { group } => Isolation::KataVfio {
            group: VfioGroup::from_system(group.id)?,
        },
        Isolation::Shared { .. } => config.isolation.clone(),
    };
    let _reservation = DeviceReservation::acquire_slot(
        Path::new(SYSTEM_LOCK_ROOT),
        &isolation.reservation_slot(),
        config.lease_id,
    )?;
    fs::create_dir_all(config.workspace_root)?;
    fs::create_dir_all(config.state_root)?;
    if config.isolation.is_shared() {
        pull_image(config.image)?;
    }

    let mut command = batch_command(&config)?;
    install_startup_policy(&isolation)?;
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            remove_shared_policy(&isolation);
            return Err(error).context("failed to start the batch workload through nerdctl");
        }
    };

    // A shared batch shares the host's bridge with everything else on the
    // machine, so it gets the same policy an interactive lease gets. A Kata
    // batch still runs without one: it is unreachable and it has no
    // credentials, but its outbound traffic is unfiltered, and closing that is
    // a change to the passthrough path rather than to this one.
    if config.isolation.is_shared() {
        let policed = match wait_for_container_ip(
            config.lease_id,
            &mut child,
            READINESS_TIMEOUT,
            &isolation,
        ) {
            Ok(ip) => install_egress_policy(ip, &isolation),
            // A command short enough to finish before the address is readable
            // has nothing left to police, and failing the lease over it would
            // punish work the renter already paid for and received.
            Err(error) => match child.try_wait() {
                Ok(Some(_)) => {
                    tracing::debug!(%error, "the batch workload finished before its network policy");
                    Ok(())
                }
                _ => Err(error),
            },
        };
        if let Err(error) = policed {
            abandon_batch(&mut child, config.lease_id, &isolation);
            return Err(error);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(u64::from(config.duration_seconds));
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = stop_container(config.lease_id, isolation.workload_noun());
                break true;
            }
            Ok(None) => thread::sleep(Duration::from_millis(250)),
            Err(error) => {
                abandon_batch(&mut child, config.lease_id, &isolation);
                return Err(error).context("failed to watch the batch workload");
            }
        }
    };

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            // The handle is gone with the call, so the container is all there is
            // left to take down.
            let _ = stop_container(config.lease_id, isolation.workload_noun());
            remove_shared_policy(&isolation);
            return Err(error).context("failed to collect batch output");
        }
    };
    let _ = remove_egress_policy();
    drop(isolation);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if timed_out {
        stderr.push_str("\nprism: the command was still running when its paid duration ended\n");
    }
    let exit_code = match output.status.code() {
        Some(code) if !timed_out => code,
        // A killed process has no code of its own, and reporting 0 would tell
        // the renter their command succeeded.
        _ => 124,
    };
    Ok(prism_protocol::CommandResult::capture(
        exit_code, &stdout, &stderr,
    ))
}

fn validate_batch_config(config: &BatchConfig<'_>) -> anyhow::Result<()> {
    validate_image_reference(config.image)?;
    validate_lease_id(config.lease_id)?;
    if config.duration_seconds == 0 || config.duration_seconds > MAX_LEASE_SECONDS {
        anyhow::bail!("batch duration must be between one second and six hours");
    }
    if config.command.trim().is_empty() {
        anyhow::bail!("batch command is empty");
    }
    if config.command.len() > 8 * 1024 {
        anyhow::bail!("batch command is too long");
    }
    if config.isolation.is_shared() {
        config.limits.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "prismd-{name}-{}-{}",
            process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    const TEST_IMAGE: &str = "registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_GPU_UUID: &str = "GPU-1a2b3c4d-0000-0000-0000-000000000001";
    const TEST_LIMITS: LeaseLimits = LeaseLimits {
        memory_mib: 24_576,
        cpus: 7,
    };

    fn kata_isolation(group: u32) -> Isolation {
        Isolation::KataVfio {
            group: VfioGroup {
                id: group,
                device: PathBuf::from(format!("/dev/vfio/{group}")),
                pci_devices: vec!["0000:01:00.0".to_owned()],
            },
        }
    }

    fn shared_isolation() -> Isolation {
        Isolation::Shared {
            gpu: crate::gpu::HostGpu {
                index: 0,
                uuid: TEST_GPU_UUID.to_owned(),
                model: "NVIDIA GeForce RTX 4090".to_owned(),
                vram_mib: 24_564,
            },
        }
    }

    fn launch_config<'a>(
        root: &'a Path,
        authorized_key: &'a Path,
        jupyter_token: &'a Path,
        isolation: &'a Isolation,
    ) -> LaunchConfig<'a> {
        LaunchConfig {
            image: TEST_IMAGE,
            lease_id: "lease-1",
            workspace_root: root,
            state_root: root,
            isolation,
            limits: TEST_LIMITS,
            duration_seconds: 3_600,
            ssh_authorized_key: authorized_key,
            jupyter_token,
            ssh_port: 2_222,
            jupyter_port: 8_888,
            attestation_challenge: None,
            agent_policy_digest: None,
        }
    }

    fn workspace_credentials(root: &Path) -> (PathBuf, PathBuf) {
        let authorized_key = root.join("authorized-key");
        let jupyter_token = root.join("jupyter-token");
        fs::write(
            &authorized_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest workspace\n",
        )
        .unwrap();
        fs::write(&jupyter_token, "a".repeat(32)).unwrap();
        (authorized_key, jupyter_token)
    }

    fn argv(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    /// A passthrough node upgrades by replacing the binary, so its argv is a
    /// compatibility surface rather than an implementation detail. Every
    /// argument below is pinned: the shared path may not reach any of them.
    #[test]
    fn the_kata_workspace_argv_is_what_it_has_always_been() {
        let root = temporary_directory("golden-kata");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let kata = kata_isolation(42);
        let config = launch_config(&root, &authorized_key, &jupyter_token, &kata);
        let command = kata_command(&config, &root).unwrap();

        assert_eq!(command.get_program(), "nerdctl");
        assert_eq!(
            argv(&command),
            vec![
                "--namespace",
                "prism",
                "run",
                "--rm",
                "--pull",
                "always",
                "--runtime",
                "io.containerd.kata.v2",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_OVERRIDE",
                "--cap-add",
                "KILL",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SYS_CHROOT",
                "--pids-limit",
                "2048",
                "--user",
                "0:0",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--device",
                "/dev/vfio/vfio",
                "--device",
                "/dev/vfio/42",
                "--tmpfs",
                "/run:rw,nosuid,nodev,mode=0755",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--tmpfs",
                "/workspace:rw,nosuid,nodev,mode=0700",
                "--mount",
                &format!("type=bind,src={},dst=/run/prism/control,ro", root.display()),
                "--publish",
                "127.0.0.1:2222:2222",
                "--publish",
                "127.0.0.1:8888:8888",
                "--hostname",
                "lease-1",
                "--entrypoint",
                "/bin/sh",
                "--name",
                "lease-1",
                TEST_IMAGE,
                "/run/prism/control/bootstrap.sh",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn the_confidential_workspace_argv_is_what_it_has_always_been() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("golden-snp");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let shim = bin.join("containerd-shim-kata-qemu-snp-v2");
        fs::write(&shim, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        let digest = "d".repeat(64);
        let kata = kata_isolation(42);
        let config = launch_config(&root, &authorized_key, &jupyter_token, &kata);
        let command = kata_snp_command_in(&config, &root, &digest, bin.as_os_str()).unwrap();

        assert_eq!(
            argv(&command),
            vec![
                "--namespace",
                "prism",
                "run",
                "--rm",
                "--pull",
                "always",
                "--runtime",
                "io.containerd.kata-qemu-snp.v2",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_OVERRIDE",
                "--cap-add",
                "KILL",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SYS_CHROOT",
                "--pids-limit",
                "2048",
                "--user",
                "0:0",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--device",
                "/dev/vfio/vfio",
                "--device",
                "/dev/vfio/42",
                "--tmpfs",
                "/run:rw,nosuid,nodev,mode=0755",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--tmpfs",
                "/workspace:rw,nosuid,nodev,mode=0700",
                "--mount",
                &format!("type=bind,src={},dst=/run/prism/control,ro", root.display()),
                "--publish",
                "127.0.0.1:2222:2222",
                "--publish",
                "127.0.0.1:8888:8888",
                "--hostname",
                "lease-1",
                "--snapshotter",
                "nydus",
                "--annotation",
                &format!(
                    "io.katacontainers.config.hypervisor.cc_init_data={}",
                    crate::snp::initdata_annotation(config.lease_id, config.image, &digest)
                ),
                "--mount",
                &format!(
                    "type=bind,src={},dst=/run/prism/evidence",
                    crate::snp::evidence_directory(&root).display()
                ),
                "--cap-add",
                "SYS_ADMIN",
                "--entrypoint",
                "/bin/sh",
                "--name",
                "lease-1",
                TEST_IMAGE,
                "/run/prism/control/bootstrap.sh",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_kata_batch_argv_is_what_it_has_always_been() {
        let root = temporary_directory("golden-kata-batch");
        let kata = kata_isolation(42);
        let command = batch_command(&BatchConfig {
            image: TEST_IMAGE,
            lease_id: "77",
            command: "nvidia-smi -L",
            workspace_root: &root,
            state_root: &root,
            isolation: &kata,
            limits: TEST_LIMITS,
            duration_seconds: 600,
        })
        .unwrap();

        assert_eq!(
            argv(&command),
            vec![
                "--namespace",
                "prism",
                "run",
                "--rm",
                "--pull",
                "always",
                "--runtime",
                "io.containerd.kata.v2",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--pids-limit",
                "2048",
                "--user",
                "0:0",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--device",
                "/dev/vfio/vfio",
                "--device",
                "/dev/vfio/42",
                "--tmpfs",
                "/run:rw,nosuid,nodev,mode=0755",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--tmpfs",
                "/workspace:rw,nosuid,nodev,mode=0700",
                "--hostname",
                "77",
                "--entrypoint",
                "/bin/sh",
                "--name",
                "77",
                TEST_IMAGE,
                "-c",
                "nvidia-smi -L",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// One card by UUID, the ordinary runtime named rather than assumed, and a
    /// bound on everything the lease can take from a host it is sharing.
    #[test]
    fn the_shared_workspace_argv_takes_one_card_and_bounds_the_lease() {
        let root = temporary_directory("golden-shared");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let shared = shared_isolation();
        let config = launch_config(&root, &authorized_key, &jupyter_token, &shared);
        let command = shared_command(&config, &root).unwrap();

        assert_eq!(
            argv(&command),
            vec![
                "--namespace",
                "prism",
                "run",
                "--rm",
                "--pull",
                "always",
                "--runtime",
                "io.containerd.runc.v2",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_OVERRIDE",
                "--cap-add",
                "KILL",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SETUID",
                "--cap-add",
                "SYS_CHROOT",
                "--pids-limit",
                "2048",
                "--user",
                "0:0",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--gpus",
                &format!("device={TEST_GPU_UUID}"),
                "--memory",
                "24576m",
                "--memory-swap",
                "24576m",
                "--cpus",
                "7",
                "--ulimit",
                "nofile=8192:8192",
                "--tmpfs",
                "/run:rw,nosuid,nodev,mode=0755,size=64m",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=6144m",
                "--tmpfs",
                "/workspace:rw,nosuid,nodev,mode=0700,size=12288m",
                "--mount",
                &format!("type=bind,src={},dst=/run/prism/control,ro", root.display()),
                "--publish",
                "127.0.0.1:2222:2222",
                "--publish",
                "127.0.0.1:8888:8888",
                "--hostname",
                "lease-1",
                "--entrypoint",
                "/bin/sh",
                "--name",
                "lease-1",
                TEST_IMAGE,
                "/run/prism/control/bootstrap.sh",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// The batch profile drops every capability and adds none back. That
    /// asymmetry with the interactive profile is deliberate and it holds in
    /// both modes.
    #[test]
    fn the_shared_batch_argv_keeps_the_capability_set_it_had_under_kata() {
        let root = temporary_directory("golden-shared-batch");
        let shared = shared_isolation();
        let command = batch_command(&BatchConfig {
            image: TEST_IMAGE,
            lease_id: "77",
            command: "nvidia-smi -L",
            workspace_root: &root,
            state_root: &root,
            isolation: &shared,
            limits: TEST_LIMITS,
            duration_seconds: 600,
        })
        .unwrap();

        assert_eq!(
            argv(&command),
            vec![
                "--namespace",
                "prism",
                "run",
                "--rm",
                "--pull",
                "always",
                "--runtime",
                "io.containerd.runc.v2",
                "--read-only",
                "--security-opt",
                "no-new-privileges:true",
                "--cap-drop",
                "ALL",
                "--pids-limit",
                "2048",
                "--user",
                "0:0",
                "--sysctl",
                "net.ipv6.conf.all.disable_ipv6=1",
                "--gpus",
                &format!("device={TEST_GPU_UUID}"),
                "--memory",
                "24576m",
                "--memory-swap",
                "24576m",
                "--cpus",
                "7",
                "--ulimit",
                "nofile=8192:8192",
                "--tmpfs",
                "/run:rw,nosuid,nodev,mode=0755,size=64m",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=6144m",
                "--tmpfs",
                "/workspace:rw,nosuid,nodev,mode=0700,size=12288m",
                "--hostname",
                "77",
                "--entrypoint",
                "/bin/sh",
                "--name",
                "77",
                TEST_IMAGE,
                "-c",
                "nvidia-smi -L",
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Neither mode may reach for the other's way of attaching a card. A Kata
    /// launch that grew a `--gpus` flag would put the host driver in a guest
    /// that has none, and a shared launch that grew a VFIO device would hand a
    /// container the raw IOMMU node.
    #[test]
    fn neither_mode_borrows_the_other_way_of_attaching_the_card() {
        let root = temporary_directory("device-separation");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let kata = kata_isolation(42);
        let shared = shared_isolation();

        for command in [
            kata_command(
                &launch_config(&root, &authorized_key, &jupyter_token, &kata),
                &root,
            )
            .unwrap(),
            batch_command(&BatchConfig {
                image: TEST_IMAGE,
                lease_id: "77",
                command: "true",
                workspace_root: &root,
                state_root: &root,
                isolation: &kata,
                limits: TEST_LIMITS,
                duration_seconds: 60,
            })
            .unwrap(),
        ] {
            let arguments = argv(&command);
            assert!(!arguments.iter().any(|argument| argument == "--gpus"));
            assert!(
                !arguments
                    .iter()
                    .any(|argument| argument.starts_with("device="))
            );
        }

        // Each entry point serves one mode and refuses the other, so a caller
        // cannot reach the wrong argv by picking the wrong function.
        assert!(
            kata_command(
                &launch_config(&root, &authorized_key, &jupyter_token, &shared),
                &root
            )
            .is_err()
        );
        assert!(
            shared_command(
                &launch_config(&root, &authorized_key, &jupyter_token, &kata),
                &root
            )
            .is_err()
        );

        for command in [
            shared_command(
                &launch_config(&root, &authorized_key, &jupyter_token, &shared),
                &root,
            )
            .unwrap(),
            batch_command(&BatchConfig {
                image: TEST_IMAGE,
                lease_id: "77",
                command: "true",
                workspace_root: &root,
                state_root: &root,
                isolation: &shared,
                limits: TEST_LIMITS,
                duration_seconds: 60,
            })
            .unwrap(),
        ] {
            let arguments = argv(&command);
            assert!(
                !arguments
                    .iter()
                    .any(|argument| argument.contains("/dev/vfio"))
            );
            assert!(!arguments.iter().any(|argument| argument.contains("kata")));
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// A shared lease cannot produce a guest report, so a configuration that
    /// asks for one is refused rather than served without evidence.
    #[test]
    fn a_shared_lease_refuses_to_pretend_it_can_attest() {
        let root = temporary_directory("shared-attestation");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let shared = shared_isolation();
        let nonce = "b".repeat(64);
        assert!(
            validate_launch_config(&LaunchConfig {
                attestation_challenge: Some(&nonce),
                ..launch_config(&root, &authorized_key, &jupyter_token, &shared)
            })
            .is_err()
        );
        assert!(
            validate_launch_config(&LaunchConfig {
                agent_policy_digest: Some(&"d".repeat(64)),
                ..launch_config(&root, &authorized_key, &jupyter_token, &shared)
            })
            .is_err()
        );
        assert!(
            validate_launch_config(&LaunchConfig {
                limits: LeaseLimits::UNUSED,
                ..launch_config(&root, &authorized_key, &jupyter_token, &shared)
            })
            .is_err(),
            "a shared lease with no memory limit would take the whole host"
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// The shared bootstrap is a separate script and the passthrough one is
    /// never edited, so a lease gets the script written for the mode it runs
    /// in.
    #[test]
    fn each_mode_gets_the_bootstrap_written_for_it() {
        let root = temporary_directory("bootstrap-selection");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let kata = kata_isolation(42);
        let shared = shared_isolation();

        let passthrough = root.join("passthrough");
        fs::create_dir(&passthrough).unwrap();
        prepare_control_directory(
            &launch_config(&root, &authorized_key, &jupyter_token, &kata),
            &passthrough,
        )
        .unwrap();
        let open = root.join("open");
        fs::create_dir(&open).unwrap();
        prepare_control_directory(
            &launch_config(&root, &authorized_key, &jupyter_token, &shared),
            &open,
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(passthrough.join("bootstrap.sh")).unwrap(),
            WORKSPACE_BOOTSTRAP
        );
        let script = fs::read_to_string(open.join("bootstrap.sh")).unwrap();
        assert_eq!(script, WORKSPACE_BOOTSTRAP_SHARED);
        assert!(
            !script.contains("snp-report"),
            "a shared guest takes no report"
        );
        assert!(
            !script.contains("chmod 0666"),
            "the container toolkit brings the device nodes in already usable"
        );
        assert!(script.contains("attestation_challenge"));
        assert!(script.contains("nvidia-smi -L | grep -c"));
        fs::remove_dir_all(root).unwrap();
    }

    /// The reservation is per card, and the idle workload takes the same one a
    /// lease would, so neither can start under the other.
    #[test]
    fn the_idle_workload_and_a_shared_lease_compete_for_one_lock() {
        let root = temporary_directory("shared-lock");
        let held = reserve_shared_gpu(&root, TEST_GPU_UUID, "idle").unwrap();
        assert!(root.join(format!("gpu-{TEST_GPU_UUID}.lock")).exists());
        assert!(
            DeviceReservation::acquire_slot(
                &root,
                &DeviceSlot::shared_gpu(TEST_GPU_UUID),
                "lease-1"
            )
            .is_err()
        );
        // A second card on the same host is a separate slot.
        assert!(
            reserve_shared_gpu(&root, "GPU-1a2b3c4d-0000-0000-0000-000000000002", "lease-1")
                .is_ok()
        );
        drop(held);
        assert!(
            DeviceReservation::acquire_slot(
                &root,
                &DeviceSlot::shared_gpu(TEST_GPU_UUID),
                "lease-1"
            )
            .is_ok()
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// The record names the process holding the card, so a lock another live
    /// process wrote has to be refused rather than reclaimed.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_lock_another_live_process_holds_is_not_reclaimed() {
        let root = temporary_directory("live-lock");
        let mut holder = Command::new("sleep").arg("30").spawn().unwrap();
        let path = root.join(format!("gpu-{TEST_GPU_UUID}.lock"));
        fs::write(
            &path,
            serde_json::to_vec(&ReservationRecord {
                pid: holder.id(),
                process_start_ticks: process_start_ticks(holder.id()),
                lease_id: "other".to_owned(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(reserve_shared_gpu(&root, TEST_GPU_UUID, "lease-1").is_err());

        let _ = holder.kill();
        let _ = holder.wait();
        assert!(reserve_shared_gpu(&root, TEST_GPU_UUID, "lease-1").is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    /// The passthrough policy is one hop away from the host across a hypervisor
    /// boundary. The shared one sits on the host's bridge, so it also has to
    /// say what the lease may send at the machine underneath it.
    #[test]
    fn the_shared_policy_adds_an_input_chain_and_leaves_the_kata_one_alone() {
        let source = "10.48.0.2".parse().unwrap();
        let kata = egress_policy(source, &kata_isolation(42)).unwrap();
        assert_eq!(
            kata,
            concat!(
                "table inet prism {\n",
                "chain forward {\n",
                "type filter hook forward priority -10; policy accept;\n",
                "ip saddr 10.48.0.2 ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } reject\n",
                "ip saddr 10.48.0.2 tcp dport { 25, 465, 587 } reject\n",
                "}\n",
                "}\n",
            )
        );

        // Everything the passthrough policy says, said the same way, with the
        // table left open for one more chain.
        let shared = egress_policy(source, &shared_isolation()).unwrap();
        assert!(shared.starts_with(&kata[..kata.len() - 2]));
        let input = shared.split_once("chain input {").unwrap().1;
        // Without this first, the replies to the published SSH and Jupyter
        // ports are rejected and every lease on the node fails.
        assert!(
            input.find("ct state established,related accept").unwrap()
                < input.find("reject").unwrap()
        );
        assert!(input.contains("ip saddr 10.48.0.2 udp dport 53 accept"));
        assert!(input.contains("ip saddr 10.48.0.2 tcp dport 53 accept"));
        assert!(shared.ends_with("}\n"));
    }

    /// The renter's image supplies the container's first process, so the policy
    /// has to hold before the address the per-lease one is keyed on exists. One
    /// lease runs per host, which makes the bridge the same scope.
    #[test]
    fn the_startup_policy_says_the_same_thing_keyed_on_the_bridge() {
        let startup = startup_policy();
        let shared = egress_policy("10.48.0.2".parse().unwrap(), &shared_isolation()).unwrap();
        for rule in [PRIVATE_DESTINATIONS, MAIL_PORTS] {
            assert!(startup.contains(rule), "{startup}");
            assert!(shared.contains(rule));
        }
        for chain in ["chain forward {", "chain input {"] {
            assert!(startup.contains(chain), "{startup}");
        }
        let input = startup.split_once("chain input {").unwrap().1;
        assert!(
            input.find("ct state established,related accept").unwrap()
                < input.find("reject").unwrap()
        );
        assert!(input.contains("iifname \"nerdctl0\" reject"));
        assert!(!startup.contains("ip saddr"), "no address is known yet");
    }

    #[test]
    fn accepts_digest_pinned_images() {
        assert!(validate_image_reference("registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    }

    #[test]
    fn rejects_mutable_images_and_path_traversal() {
        assert!(validate_image_reference("registry.example/runtime:latest").is_err());
        assert!(validate_image_reference("registry.example/run'''time@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_image_reference("localhost/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_image_reference("10.0.0.5/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_lease_id("../../outside").is_err());
    }

    /// A batch workload gets the same exclusive GPU as a lease and publishes
    /// nothing: a forwarded port would be a way into a workspace that is not
    /// supposed to have one.
    #[test]
    fn batch_command_takes_the_gpu_and_publishes_nothing() {
        let root = temporary_directory("batch-command");
        let config = BatchConfig {
            image: "docker.io/library/debian@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            lease_id: "77",
            command: "nvidia-smi -L",
            workspace_root: &root,
            state_root: &root,
            isolation: &kata_isolation(42),
            limits: TEST_LIMITS,
            duration_seconds: 600,
        };
        let command = batch_command(&config).unwrap();
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), "nerdctl");
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--device", "/dev/vfio/42"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--runtime", "io.containerd.kata.v2"])
        );
        assert!(!arguments.iter().any(|argument| argument == "--publish"));
        // An ordinary workspace has no report to take, so it never gets the
        // capability that would let it mount its way to one.
        assert!(
            !arguments
                .windows(2)
                .any(|pair| pair == ["--cap-add", "SYS_ADMIN"]),
            "a batch lease must not be granted SYS_ADMIN"
        );
        assert_eq!(arguments.last().unwrap(), "nvidia-smi -L");
    }

    #[test]
    fn batch_refuses_a_mutable_image_or_an_empty_command() {
        let root = temporary_directory("batch-validate");
        let pinned = "docker.io/library/debian@sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let kata = kata_isolation(1);
        let base = BatchConfig {
            image: pinned,
            lease_id: "77",
            command: "true",
            workspace_root: &root,
            state_root: &root,
            isolation: &kata,
            limits: TEST_LIMITS,
            duration_seconds: 60,
        };
        assert!(validate_batch_config(&base).is_ok());
        assert!(
            validate_batch_config(&BatchConfig {
                image: "docker.io/library/debian:latest",
                ..base
            })
            .is_err()
        );
        assert!(
            validate_batch_config(&BatchConfig {
                command: "  ",
                ..base
            })
            .is_err()
        );
        assert!(
            validate_batch_config(&BatchConfig {
                duration_seconds: 0,
                ..base
            })
            .is_err()
        );
    }

    #[test]
    fn kata_command_assigns_one_explicit_vfio_group() {
        let root = temporary_directory("command");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let kata = kata_isolation(42);
        let config = launch_config(&root, &authorized_key, &jupyter_token, &kata);
        let command = kata_command(&config, &root).unwrap();
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), "nerdctl");
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--device", "/dev/vfio/42"])
        );
        assert!(!arguments.iter().any(|argument| argument == "--gpus"));
        // The workspace a renter is handed has no report to take, so it never
        // gets the capability that would let it mount its way to one.
        assert!(
            !arguments
                .windows(2)
                .any(|pair| pair == ["--cap-add", "SYS_ADMIN"]),
            "an ordinary workspace must not be granted SYS_ADMIN"
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "/workspace:rw,nosuid,nodev,mode=0700")
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--cap-drop", "ALL"])
        );
        assert!(arguments.windows(2).any(|pair| pair == ["--user", "0:0"]));
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--read-only", "--security-opt"])
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "127.0.0.1:2222:2222")
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "127.0.0.1:8888:8888")
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// A confidential launch has to pick the shim that can produce a report,
    /// pull the rootfs inside the guest, and carry the policy digest into the
    /// document Kata hashes into HOST_DATA. Anything less starts a guest whose
    /// report says nothing about the workload.
    /// A confidential guest hands its report back on standard output, because
    /// the mount it wrote to is private to the guest. The node stores exactly
    /// the artifacts it expects and nothing else, so a name the guest chooses
    /// cannot decide where a file lands.
    #[test]
    fn printed_evidence_is_stored_under_the_names_the_node_expects() {
        let root = temporary_directory("printed-evidence");
        let evidence = root.join("evidence");
        let script = root.join("emit.sh");
        fs::write(
            &script,
            "#!/bin/sh\n\
             printf 'noise before\\n'\n\
             printf 'prism-evidence guest-report.bin %s\\n' \"$(printf 'report' | base64)\"\n\
             printf 'prism-evidence ../escape.bin %s\\n' \"$(printf 'nope' | base64)\"\n\
             printf 'prism-evidence guest-chain.b64 %s\\n' \"$(printf 'chain' | base64)\"\n\
             printf 'noise after\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut child = Command::new("sh")
            .arg(&script)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let handle = collect_printed_evidence(child.stdout.take().unwrap(), evidence.clone());
        handle.join().unwrap();
        let _ = child.wait();

        assert_eq!(
            fs::read(evidence.join("guest-report.bin")).unwrap(),
            b"report"
        );
        assert_eq!(
            fs::read(evidence.join("guest-chain.b64")).unwrap(),
            b"chain"
        );
        assert!(
            !root.join("escape.bin").exists() && !evidence.join("../escape.bin").exists(),
            "a guest must not be able to name a path outside the evidence directory"
        );
        let _ = fs::write(root.join("emit.sh"), "");
    }

    #[test]
    #[cfg(unix)]
    fn kata_snp_command_takes_the_confidential_shim_and_pins_the_policy() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("snp-command");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let shim = bin.join("containerd-shim-kata-qemu-snp-v2");
        fs::write(&shim, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        let digest = "d".repeat(64);
        let kata = kata_isolation(42);
        let config = launch_config(&root, &authorized_key, &jupyter_token, &kata);
        let command = kata_snp_command_in(&config, &root, &digest, bin.as_os_str()).unwrap();
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();

        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--runtime", "io.containerd.kata-qemu-snp.v2"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--snapshotter", "nydus"])
        );
        // Only a confidential guest gets this, and only so the bootstrap can
        // mount configfs to reach the report interface.
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--cap-add", "SYS_ADMIN"])
        );
        let evidence = format!(
            "type=bind,src={},dst=/run/prism/evidence",
            crate::snp::evidence_directory(&root).display()
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument.as_ref() == evidence)
        );
        let annotation = arguments
            .iter()
            .find(|argument| {
                argument.starts_with("io.katacontainers.config.hypervisor.cc_init_data=")
            })
            .expect("the initdata annotation is what reaches HOST_DATA");
        assert_eq!(
            annotation.as_ref(),
            format!(
                "io.katacontainers.config.hypervisor.cc_init_data={}",
                crate::snp::initdata_annotation(config.lease_id, config.image, &digest)
            )
        );
        // The flags still have to sit ahead of the image, or nerdctl reads them
        // as arguments to the entrypoint.
        let image = arguments
            .iter()
            .position(|argument| argument.as_ref() == config.image)
            .unwrap();
        assert!(
            arguments[..image]
                .iter()
                .any(|argument| argument == "--snapshotter")
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Without a policy digest the report would be genuine and the workload
    /// unmeasured, and without a shim there would be no report at all. Both
    /// refuse rather than quietly starting an ordinary Kata guest.
    #[test]
    #[cfg(unix)]
    fn kata_snp_command_refuses_rather_than_falling_back() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("snp-refusal");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let kata = kata_isolation(42);
        let config = launch_config(&root, &authorized_key, &jupyter_token, &kata);
        let digest = "d".repeat(64);

        assert!(kata_snp_command_in(&config, &root, "", bin.as_os_str()).is_err());
        assert!(kata_snp_command_in(&config, &root, "not-a-digest", bin.as_os_str()).is_err());
        assert!(kata_snp_command_in(&config, &root, &digest, bin.as_os_str()).is_err());

        let shim = bin.join("containerd-shim-kata-qemu-snp-v2");
        fs::write(&shim, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(kata_snp_command_in(&config, &root, &digest, bin.as_os_str()).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    /// The report commits to the host key the renter's session terminates on,
    /// so the key has to exist before the report and the report has to be
    /// written before anything accepts a connection.
    #[test]
    fn the_bootstrap_reports_between_the_host_key_and_the_first_listener() {
        let keygen = WORKSPACE_BOOTSTRAP
            .find("ssh-keygen")
            .expect("the guest generates its own host key");
        let report = WORKSPACE_BOOTSTRAP
            .find("prismd snp-report")
            .expect("the guest takes its own report");
        let sshd = WORKSPACE_BOOTSTRAP
            .find("\"$sshd_path\" -D")
            .expect("sshd is what starts listening");
        let jupyter = WORKSPACE_BOOTSTRAP
            .find("jupyter lab")
            .expect("jupyter is the other listener");

        assert!(keygen < report);
        assert!(report < sshd);
        assert!(report < jupyter);
        assert!(WORKSPACE_BOOTSTRAP.contains("set -eu"));
        assert!(WORKSPACE_BOOTSTRAP.contains("/run/prism/ssh_host_key.pub"));
    }

    /// A confidential lease writes the challenge the guest has to commit to and
    /// a directory for the report to land in. An ordinary lease writes neither,
    /// and its bootstrap therefore takes no report.
    #[test]
    fn the_control_directory_carries_the_challenge_only_when_there_is_one() {
        let root = temporary_directory("control-directory");
        let (authorized_key, jupyter_token) = workspace_credentials(&root);
        let kata = kata_isolation(42);

        let plain = root.join("plain");
        fs::create_dir(&plain).unwrap();
        prepare_control_directory(
            &launch_config(&root, &authorized_key, &jupyter_token, &kata),
            &plain,
        )
        .unwrap();
        assert!(!plain.join("attestation_challenge").exists());
        assert!(!crate::snp::evidence_directory(&plain).exists());

        let attested = root.join("attested");
        fs::create_dir(&attested).unwrap();
        let nonce = "b".repeat(64);
        prepare_control_directory(
            &LaunchConfig {
                attestation_challenge: Some(&nonce),
                agent_policy_digest: Some(&"d".repeat(64)),
                ..launch_config(&root, &authorized_key, &jupyter_token, &kata)
            },
            &attested,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(attested.join("attestation_challenge"))
                .unwrap()
                .trim(),
            nonce
        );
        assert_eq!(
            fs::read_to_string(attested.join("lease_id"))
                .unwrap()
                .trim(),
            "lease-1"
        );
        assert!(crate::snp::evidence_directory(&attested).is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    /// The report has to be readable after the guest exits, which is the one
    /// thing the lease control mount cannot do, and it has to come from the
    /// collector the control plane expects rather than any image on the host.
    #[test]
    fn attestation_command_mounts_a_writable_evidence_directory() {
        let root = temporary_directory("attestation-command");
        let group = VfioGroup {
            id: 42,
            device: PathBuf::from("/dev/vfio/42"),
            pci_devices: vec!["0000:01:00.0".to_owned()],
        };
        let nonce = "b".repeat(64);
        let command = attestation_command(&group, &root, &nonce).unwrap();
        let arguments = command
            .get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>();

        assert_eq!(command.get_program(), "nerdctl");
        let mount = format!("type=bind,src={},dst=/run/prism/evidence", root.display());
        assert!(arguments.iter().any(|argument| argument.as_ref() == mount));
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--device", "/dev/vfio/42"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--device", "/dev/vfio/vfio"])
        );
        assert!(
            arguments
                .iter()
                .any(|argument| argument == ATTESTATION_IMAGE)
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--nonce", nonce.as_str()])
        );
        assert!(!arguments.iter().any(|argument| argument == "--publish"));
        assert!(attestation_command(&group, &root, "not-a-nonce").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_weak_workspace_credentials() {
        assert!(validate_authorized_key("ssh-rsa AAAA").is_err());
        assert!(validate_authorized_key("ssh-ed25519 AAAA").is_ok());
        assert!(validate_jupyter_token("short").is_err());
        assert!(validate_jupyter_token(&"a".repeat(32)).is_ok());
        assert!(validate_jupyter_token(&format!("{}!", "a".repeat(32))).is_err());
    }

    #[test]
    fn egress_policy_blocks_private_metadata_and_mail_destinations() {
        let policy = egress_policy("10.48.0.2".parse().unwrap(), &kata_isolation(42)).unwrap();
        for blocked in [
            "10.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "25, 465, 587",
        ] {
            assert!(policy.contains(blocked));
        }
        assert!(egress_policy("::1".parse().unwrap(), &kata_isolation(42)).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn discovers_only_complete_vfio_gpu_groups() {
        use std::os::unix::fs::symlink;

        let root = temporary_directory("vfio");
        let sysfs = root.join("sys");
        let devices = sysfs.join("kernel/iommu_groups/42/devices");
        let gpu = devices.join("0000:01:00.0");
        let audio = devices.join("0000:01:00.1");
        fs::create_dir_all(&gpu).unwrap();
        fs::create_dir_all(&audio).unwrap();
        fs::create_dir_all(root.join("dev/vfio")).unwrap();
        fs::write(root.join("dev/vfio/42"), []).unwrap();
        fs::write(gpu.join("class"), "0x030200\n").unwrap();
        fs::write(audio.join("class"), "0x040300\n").unwrap();
        symlink("/sys/bus/pci/drivers/vfio-pci", gpu.join("driver")).unwrap();
        symlink("/sys/bus/pci/drivers/vfio-pci", audio.join("driver")).unwrap();

        let groups = discover_vfio_gpu_groups_at(&sysfs, &root.join("dev")).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, 42);
        assert_eq!(groups[0].pci_devices.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prevents_double_reservation_of_a_vfio_group() {
        let root = temporary_directory("locks");
        let first =
            DeviceReservation::acquire_slot(&root, &DeviceSlot::vfio(7), "lease-one").unwrap();
        assert!(DeviceReservation::acquire_slot(&root, &DeviceSlot::vfio(7), "lease-two").is_err());
        drop(first);
        assert!(DeviceReservation::acquire_slot(&root, &DeviceSlot::vfio(7), "lease-two").is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reclaims_a_stale_vfio_reservation() {
        let root = temporary_directory("stale-lock");
        let path = root.join("vfio-9.lock");
        fs::write(
            &path,
            serde_json::to_vec(&ReservationRecord {
                pid: u32::MAX,
                process_start_ticks: Some(u64::MAX),
                lease_id: "stale".to_owned(),
            })
            .unwrap(),
        )
        .unwrap();

        assert!(DeviceReservation::acquire_slot(&root, &DeviceSlot::vfio(9), "lease-new").is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
