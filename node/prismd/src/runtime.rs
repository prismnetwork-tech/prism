use std::{
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
const MAX_LEASE_SECONDS: u32 = 21_600;
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

pub struct LaunchConfig<'a> {
    pub image: &'a str,
    pub lease_id: &'a str,
    pub workspace_root: &'a Path,
    pub state_root: &'a Path,
    pub vfio_group: u32,
    pub duration_seconds: u32,
    pub ssh_authorized_key: &'a Path,
    pub jupyter_token: &'a Path,
    pub ssh_port: u16,
    pub jupyter_port: u16,
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
    if image.chars().any(char::is_whitespace) || image.contains("..") {
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
    validate_launch_config(config)?;
    let vfio_device = format!("/dev/vfio/{}", config.vfio_group);
    let control_mount = format!(
        "type=bind,src={},dst=/run/prism/control,ro",
        control_directory.display()
    );
    let ssh_publish = format!("127.0.0.1:{}:2222", config.ssh_port);
    let jupyter_publish = format!("127.0.0.1:{}:8888", config.jupyter_port);
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
        &vfio_device,
        "--tmpfs",
        "/run:rw,nosuid,nodev,mode=0755",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,mode=1777",
        "--tmpfs",
        "/workspace:rw,nosuid,nodev,mode=0700",
        "--mount",
        &control_mount,
        "--publish",
        &ssh_publish,
        "--publish",
        &jupyter_publish,
        "--hostname",
        config.lease_id,
        "--entrypoint",
        "/bin/sh",
        "--name",
        config.lease_id,
        config.image,
        "/run/prism/control/bootstrap.sh",
    ]);
    Ok(command)
}

pub fn launch(config: LaunchConfig<'_>) -> anyhow::Result<()> {
    validate_launch_config(&config)?;
    let group = VfioGroup::from_system(config.vfio_group)?;
    let _reservation = DeviceReservation::acquire(
        Path::new(SYSTEM_LOCK_ROOT),
        config.vfio_group,
        config.lease_id,
    )?;
    fs::create_dir_all(config.workspace_root)?;
    fs::create_dir_all(config.state_root)?;
    let workspace = workspace_path(config.workspace_root, config.lease_id)?;
    let state_path = state_path(config.state_root, config.lease_id)?;
    if state_path.exists() {
        recover_interrupted_lease(config.lease_id, &workspace, &state_path)?;
    }
    let mut command = kata_command(&config, &workspace)?;
    fs::create_dir_all(&workspace)?;
    prepare_control_directory(&workspace, config.ssh_authorized_key, config.jupyter_token)?;
    persist_state(
        &state_path,
        &LeaseState::new(&config, &group, LeasePhase::Provisioning, None, None),
    )?;
    let mut ready_at = None;
    let result = match command
        .spawn()
        .context("failed to start the Kata workspace through nerdctl")
    {
        Ok(mut child) => {
            let result = run_workspace(
                &config,
                &workspace,
                &state_path,
                &group,
                &mut child,
                &mut ready_at,
            );
            let _ = remove_egress_policy();
            if child.try_wait().ok().flatten().is_none() {
                let _ = stop_container(config.lease_id);
                let _ = child.wait();
            }
            result
        }
        Err(error) => Err(error),
    };
    let cleanup = fs::remove_dir_all(&workspace).context("remove lease workspace");
    let outcome = result.and(cleanup);
    let (phase, error) = match &outcome {
        Ok(()) => (LeasePhase::Completed, None),
        Err(error) => (LeasePhase::Failed, Some(error.to_string())),
    };
    persist_state(
        &state_path,
        &LeaseState::new(&config, &group, phase, error, ready_at),
    )?;
    outcome
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
    validate_authorized_key(&fs::read_to_string(config.ssh_authorized_key)?)?;
    validate_jupyter_token(&fs::read_to_string(config.jupyter_token)?)?;
    Ok(())
}

fn prepare_control_directory(
    workspace: &Path,
    authorized_key: &Path,
    jupyter_token: &Path,
) -> anyhow::Result<()> {
    write_secret(
        &workspace.join("authorized_keys"),
        fs::read(authorized_key)?.as_slice(),
    )?;
    write_secret(
        &workspace.join("jupyter_token"),
        fs::read(jupyter_token)?.as_slice(),
    )?;
    write_secret(
        &workspace.join("bootstrap.sh"),
        WORKSPACE_BOOTSTRAP.as_bytes(),
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

fn run_workspace(
    config: &LaunchConfig<'_>,
    workspace: &Path,
    state_path: &Path,
    group: &VfioGroup,
    child: &mut Child,
    ready_at: &mut Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let ip = wait_for_container_ip(config.lease_id, child, READINESS_TIMEOUT)?;
    install_egress_policy(ip)?;
    write_secret(&workspace.join("network-ready"), b"ready\n")?;
    wait_for_access(config, child, READINESS_TIMEOUT)?;
    *ready_at = Some(Utc::now());
    persist_state(
        state_path,
        &LeaseState::new(config, group, LeasePhase::Ready, None, *ready_at),
    )?;

    let deadline = Instant::now() + Duration::from_secs(u64::from(config.duration_seconds));
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Kata workspace exited before the lease deadline: {status}");
        }
        if Instant::now() >= deadline {
            stop_container(config.lease_id)?;
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
) -> anyhow::Result<IpAddr> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Kata workspace exited before network policy installation: {status}");
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
    anyhow::bail!("Kata workspace did not receive a network address")
}

fn wait_for_access(
    config: &LaunchConfig<'_>,
    child: &mut Child,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let ssh = SocketAddr::from(([127, 0, 0, 1], config.ssh_port));
    let jupyter = SocketAddr::from(([127, 0, 0, 1], config.jupyter_port));
    let mut ssh_ready = false;
    let mut jupyter_ready = false;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Kata workspace exited before access readiness: {status}");
        }
        ssh_ready |= TcpStream::connect_timeout(&ssh, Duration::from_millis(500)).is_ok();
        jupyter_ready |= TcpStream::connect_timeout(&jupyter, Duration::from_millis(500)).is_ok();
        if ssh_ready && jupyter_ready {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
    anyhow::bail!("Kata workspace did not make SSH and Jupyter ready")
}

fn stop_container(lease_id: &str) -> anyhow::Result<()> {
    let status = Command::new("nerdctl")
        .args(["--namespace", "prism", "stop", "--time", "10", lease_id])
        .status()
        .context("stop Kata workspace")?;
    if !status.success() {
        anyhow::bail!("nerdctl could not stop the Kata workspace");
    }
    Ok(())
}

fn install_egress_policy(source: IpAddr) -> anyhow::Result<()> {
    let script = egress_policy(source)?;
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

fn egress_policy(source: IpAddr) -> anyhow::Result<String> {
    let IpAddr::V4(source) = source else {
        anyhow::bail!("workspace network must use IPv4 with IPv6 disabled");
    };
    Ok(format!(
        "table inet prism {{\n\
         chain forward {{\n\
         type filter hook forward priority -10; policy accept;\n\
         ip saddr {source} ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }} reject\n\
         ip saddr {source} tcp dport {{ 25, 465, 587 }} reject\n\
         }}\n\
         }}\n"
    ))
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
    vfio_group: u32,
    pci_devices: Vec<String>,
    phase: LeasePhase,
    ssh_port: u16,
    jupyter_port: u16,
    ready_at: Option<DateTime<Utc>>,
    error: Option<String>,
    updated_at: DateTime<Utc>,
}

impl LeaseState {
    fn new(
        config: &LaunchConfig<'_>,
        group: &VfioGroup,
        phase: LeasePhase,
        error: Option<String>,
        ready_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            lease_id: config.lease_id.to_owned(),
            image: config.image.to_owned(),
            vfio_group: group.id,
            pci_devices: group.pci_devices.clone(),
            phase,
            ssh_port: config.ssh_port,
            jupyter_port: config.jupyter_port,
            ready_at,
            error,
            updated_at: Utc::now(),
        }
    }
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

struct DeviceReservation {
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct ReservationRecord {
    pid: u32,
    process_start_ticks: Option<u64>,
    lease_id: String,
}

impl DeviceReservation {
    fn acquire(root: &Path, vfio_group: u32, lease_id: &str) -> anyhow::Result<Self> {
        validate_lease_id(lease_id)?;
        fs::create_dir_all(root)?;
        let path = root.join(format!("vfio-{vfio_group}.lock"));
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
                        anyhow::bail!("VFIO group {vfio_group} is already reserved");
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
        anyhow::bail!("VFIO group {vfio_group} reservation changed concurrently")
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

    fn launch_config<'a>(
        root: &'a Path,
        authorized_key: &'a Path,
        jupyter_token: &'a Path,
    ) -> LaunchConfig<'a> {
        LaunchConfig {
            image: "registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            lease_id: "lease-1",
            workspace_root: root,
            state_root: root,
            vfio_group: 42,
            duration_seconds: 3_600,
            ssh_authorized_key: authorized_key,
            jupyter_token,
            ssh_port: 2_222,
            jupyter_port: 8_888,
        }
    }

    #[test]
    fn accepts_digest_pinned_images() {
        assert!(validate_image_reference("registry.example/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    }

    #[test]
    fn rejects_mutable_images_and_path_traversal() {
        assert!(validate_image_reference("registry.example/runtime:latest").is_err());
        assert!(validate_image_reference("localhost/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_image_reference("10.0.0.5/runtime@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(validate_lease_id("../../outside").is_err());
    }

    #[test]
    fn kata_command_assigns_one_explicit_vfio_group() {
        let root = temporary_directory("command");
        let authorized_key = root.join("authorized-key");
        let jupyter_token = root.join("jupyter-token");
        fs::write(
            &authorized_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest workspace\n",
        )
        .unwrap();
        fs::write(&jupyter_token, "a".repeat(32)).unwrap();
        let config = launch_config(&root, &authorized_key, &jupyter_token);
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
        let policy = egress_policy("10.48.0.2".parse().unwrap()).unwrap();
        for blocked in [
            "10.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "25, 465, 587",
        ] {
            assert!(policy.contains(blocked));
        }
        assert!(egress_policy("::1".parse().unwrap()).is_err());
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
        let first = DeviceReservation::acquire(&root, 7, "lease-one").unwrap();
        assert!(DeviceReservation::acquire(&root, 7, "lease-two").is_err());
        drop(first);
        assert!(DeviceReservation::acquire(&root, 7, "lease-two").is_ok());
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

        assert!(DeviceReservation::acquire(&root, 9, "lease-new").is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
