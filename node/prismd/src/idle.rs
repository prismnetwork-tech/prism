use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, PipeReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::runtime;

const DEFAULT_STOP_GRACE_SECONDS: u64 = 30;
const DEFAULT_GPU_RELEASE_SECONDS: u64 = 20;
/// Once the grace period runs out the workload gets a kill and this long to
/// disappear. Longer than any process needs, short enough that a renter is not
/// left waiting on a wedged one.
const KILL_GRACE: Duration = Duration::from_secs(10);
const MINIMUM_BACKOFF: Duration = Duration::from_secs(5);
const MAXIMUM_BACKOFF: Duration = Duration::from_secs(300);
/// A workload that stayed up this long was not crash-looping, so the next
/// failure starts counting from the bottom again.
const STABLE_RUN: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(250);
const LOG_BYTES: u64 = 8 * 1024 * 1024;
/// Two readings, because a single free answer between two busy ones is a race
/// with a process that has not finished dying.
const FREE_READINGS_TO_RESUME: u32 = 2;
const IDLE_HOLDER: &str = "idle";

/// What the operator wants this machine doing between leases.
///
/// Two shapes, and never both. Either the daemon runs the workload itself from
/// an argument vector, or systemd owns it under a unit and the daemon only
/// starts and stops that unit.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdleConfig {
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub working_directory: Option<PathBuf>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub systemd_unit: Option<String>,
    #[serde(default = "default_stop_grace_seconds")]
    pub stop_grace_seconds: u64,
    #[serde(default = "default_gpu_release_seconds")]
    pub gpu_release_seconds: u64,
}

fn default_stop_grace_seconds() -> u64 {
    DEFAULT_STOP_GRACE_SECONDS
}

fn default_gpu_release_seconds() -> u64 {
    DEFAULT_GPU_RELEASE_SECONDS
}

/// Read the workload description the daemon will act on.
///
/// The file names a binary the daemon starts and hands credentials to, so
/// anyone who can write it chooses what runs on the machine. Group and other
/// write access is refused rather than warned about.
pub fn load(path: &Path) -> anyhow::Result<IdleConfig> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("read the idle workload configuration at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            anyhow::bail!(
                "{} is writable by group or other; tighten it to 0644 before the daemon will run what it names",
                path.display()
            );
        }
    }
    let config: IdleConfig = serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("read the idle workload configuration at {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

impl IdleConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        match (self.argv.is_empty(), self.systemd_unit.is_none()) {
            (true, true) => {
                anyhow::bail!("an idle workload needs either an argv array or a systemd_unit")
            }
            (false, false) => {
                anyhow::bail!("an idle workload takes an argv array or a systemd_unit, not both")
            }
            (true, false) => self.validate_unit()?,
            (false, true) => self.validate_exec()?,
        }
        for seconds in [self.stop_grace_seconds, self.gpu_release_seconds] {
            if seconds == 0 || seconds > 300 {
                anyhow::bail!(
                    "stop_grace_seconds and gpu_release_seconds must be between 1 and 300"
                );
            }
        }
        Ok(())
    }

    fn validate_exec(&self) -> anyhow::Result<()> {
        let program = Path::new(&self.argv[0]);
        if !program.is_absolute() {
            anyhow::bail!("argv[0] must be an absolute path, not {}", self.argv[0]);
        }
        let metadata = fs::metadata(program)
            .with_context(|| format!("read the idle workload binary at {}", program.display()))?;
        if !metadata.is_file() {
            anyhow::bail!("{} is not a regular file", program.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                anyhow::bail!(
                    "{} is writable by group or other, so this daemon will not run it",
                    program.display()
                );
            }
        }
        let user = self
            .user
            .as_deref()
            .context("an idle workload run from argv needs a user to run as")?;
        if user.is_empty()
            || user.len() > 32
            || user == "root"
            || !user.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            anyhow::bail!("the idle workload user must be an unprivileged account, not {user}");
        }
        if let Some(directory) = &self.working_directory
            && !directory.is_absolute()
        {
            anyhow::bail!("working_directory must be an absolute path");
        }
        for name in self.environment.keys() {
            if name.is_empty() || name.contains('=') || name.contains('\0') {
                anyhow::bail!("{name} is not an environment variable name");
            }
        }
        Ok(())
    }

    fn validate_unit(&self) -> anyhow::Result<()> {
        let unit = self.systemd_unit.as_deref().unwrap_or_default();
        if unit.is_empty()
            || unit.len() > 128
            || !unit.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@')
            })
        {
            anyhow::bail!("{unit} is not a systemd unit name");
        }
        if !self.argv.is_empty() || self.user.is_some() || !self.environment.is_empty() {
            anyhow::bail!(
                "a systemd_unit workload is described by its unit file, so argv, user and environment do not belong here"
            );
        }
        Ok(())
    }
}

/// The two questions the supervisor asks the host, injected so the handshake
/// can be driven without a GPU under it.
pub struct Probes {
    pub gpu_free: Box<dyn Fn(&str) -> bool + Send + Sync>,
    pub lease_containers: Box<dyn Fn() -> bool + Send + Sync>,
}

impl Default for Probes {
    fn default() -> Self {
        Self {
            gpu_free: Box::new(crate::gpu::gpu_is_free),
            lease_containers: Box::new(lease_containers_running),
        }
    }
}

/// A lease container still on the machine, left by a daemon that restarted
/// while one was running. An answer nobody can read counts as one: starting a
/// miner on top of a live lease is the failure this check exists to prevent.
fn lease_containers_running() -> bool {
    match Command::new("nerdctl")
        .args(["--namespace", "prism", "ps", "-q"])
        .output()
    {
        Ok(output) if output.status.success() => !output.stdout.trim_ascii().is_empty(),
        Ok(output) => {
            tracing::warn!(status = %output.status, "could not list lease containers; holding the idle workload");
            true
        }
        Err(error) => {
            tracing::warn!(%error, "could not list lease containers; holding the idle workload");
            true
        }
    }
}

/// How long the machine took to hand the card over, measured rather than
/// assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    pub exit_ms: u64,
    pub free_ms: u64,
    /// The grace period ran out and the workload had to be killed. The card
    /// still came free, but not the way the operator configured it to.
    pub forced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Stopped,
    Running,
    /// A lease has the card.
    Held,
    Quarantined,
}

#[derive(Serialize)]
struct IdleState {
    phase: Phase,
    pid: Option<u32>,
    since: DateTime<Utc>,
    last_error: Option<String>,
    last_release_ms: Option<u64>,
}

enum Running {
    Process(Child),
    /// systemd owns it. The daemon starts and stops the unit and reads
    /// `is-active` for everything else.
    Unit,
}

pub struct Idle {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    config: IdleConfig,
    account: Option<Account>,
    idle_root: PathBuf,
    state_root: PathBuf,
    lease_root: PathBuf,
    lock_root: PathBuf,
    gpu_uuid: String,
    probes: Probes,
    running: Option<Running>,
    /// The group the last workload led. Kept after it is reaped, because the
    /// workers it started outlive it and a stop has to reach them.
    last_group: Option<u32>,
    reservation: Option<runtime::DeviceReservation>,
    quarantined: bool,
    free_readings: u32,
    backoff: Duration,
    resume_at: Option<Instant>,
    started_at: Option<Instant>,
    last_error: Option<String>,
    last_release_ms: Option<u64>,
}

impl Idle {
    pub fn new(
        config: IdleConfig,
        idle_root: PathBuf,
        state_root: PathBuf,
        lease_root: PathBuf,
        gpu_uuid: String,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        let account = config.user.as_deref().map(account).transpose()?;
        if account.is_some_and(|account| account.uid == 0) {
            anyhow::bail!(
                "{} is uid 0; the idle workload must not run as root",
                config.user.as_deref().unwrap_or_default()
            );
        }
        fs::create_dir_all(&idle_root)
            .with_context(|| format!("create {}", idle_root.display()))?;
        own_directory(&state_root)?;
        Ok(Self::with_probes(
            config,
            account,
            idle_root,
            state_root,
            lease_root,
            runtime::system_lock_root().to_path_buf(),
            gpu_uuid,
            Probes::default(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn with_probes(
        config: IdleConfig,
        account: Option<Account>,
        idle_root: PathBuf,
        state_root: PathBuf,
        lease_root: PathBuf,
        lock_root: PathBuf,
        gpu_uuid: String,
        probes: Probes,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                config,
                account,
                idle_root,
                state_root,
                lease_root,
                lock_root,
                gpu_uuid,
                probes,
                running: None,
                last_group: None,
                reservation: None,
                quarantined: false,
                free_readings: 0,
                backoff: MINIMUM_BACKOFF,
                resume_at: None,
                started_at: None,
                last_error: None,
                last_release_ms: None,
            })),
        }
    }

    /// True while this node is not fit to take a lease. Telemetry stops for as
    /// long as it holds, so the offer ages out of matching rather than failing
    /// a fresh lease every few seconds.
    pub fn quarantined(&self) -> bool {
        self.inner.lock().expect("idle supervisor").quarantined
    }

    pub async fn tick(&self) {
        let inner = self.inner.clone();
        let _ = tokio::task::spawn_blocking(move || {
            inner.lock().expect("idle supervisor").tick();
        })
        .await;
    }

    /// Take the card back before a lease starts. An error means it did not come
    /// free, and the lease must not start.
    pub async fn stop_for_lease(&self) -> anyhow::Result<Release> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.lock().expect("idle supervisor").stop_for_lease())
            .await
            .context("the idle workload handshake did not run")?
    }
}

impl Inner {
    fn tick(&mut self) {
        if self.quarantined {
            if !(self.probes.gpu_free)(&self.gpu_uuid) {
                self.free_readings = 0;
                return;
            }
            self.free_readings += 1;
            if self.free_readings < FREE_READINGS_TO_RESUME {
                return;
            }
            self.quarantined = false;
            self.free_readings = 0;
            self.backoff = MINIMUM_BACKOFF;
            self.resume_at = None;
            self.last_error = None;
            tracing::info!("the GPU is free again; resuming the idle workload and telemetry");
        }
        self.reap();
        self.ensure_running();
    }

    fn reap(&mut self) {
        let exit = match &mut self.running {
            None => return,
            Some(Running::Process(child)) => child
                .try_wait()
                .ok()
                .flatten()
                .map(|status| status.to_string()),
            Some(Running::Unit) => {
                (!unit_is_active(self.config.systemd_unit.as_deref().unwrap_or_default()))
                    .then(|| "the unit is not active".to_owned())
            }
        };
        let Some(exit) = exit else { return };
        self.running = None;
        if self.started_at.is_some_and(|at| at.elapsed() >= STABLE_RUN) {
            self.backoff = MINIMUM_BACKOFF;
        }
        self.started_at = None;
        self.reservation = None;
        tracing::warn!(%exit, "the idle workload stopped; restarting after the backoff");
        self.last_error = Some(format!("the idle workload stopped: {exit}"));
        self.hold_off();
        self.write_state(Phase::Stopped);
    }

    fn ensure_running(&mut self) {
        if self.running.is_some() || self.resume_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        if let Err(error) = self.start() {
            tracing::warn!(%error, "could not start the idle workload");
            self.last_error = Some(format!("{error:#}"));
            self.hold_off();
        }
    }

    fn hold_off(&mut self) {
        self.resume_at = Some(Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(MAXIMUM_BACKOFF);
    }

    /// The reservation is the same lock a lease takes, so a workspace started
    /// by hand cannot come up underneath a workload that still holds the card.
    ///
    /// The lease probe runs before every start rather than once at startup: a
    /// container left behind by a daemon that restarted mid-lease holds the card
    /// without holding the lock, and it is still there the next time this node
    /// has nothing to do.
    fn start(&mut self) -> anyhow::Result<()> {
        if (self.probes.lease_containers)() || runtime::lease_in_flight(&self.lease_root) {
            anyhow::bail!(
                "a lease is still running on this node; the idle workload stays down until it ends"
            );
        }
        if self.reservation.is_none() {
            self.reservation = Some(runtime::reserve_shared_gpu(
                &self.lock_root,
                &self.gpu_uuid,
                IDLE_HOLDER,
            )?);
        }
        self.running = Some(match self.config.systemd_unit.clone() {
            Some(unit) => {
                systemctl(&["start", &unit])?;
                Running::Unit
            }
            None => {
                let child = self.spawn()?;
                self.last_group = Some(child.id());
                Running::Process(child)
            }
        });
        self.started_at = Some(Instant::now());
        self.resume_at = None;
        self.write_state(Phase::Running);
        Ok(())
    }

    /// `setpriv` rather than `runuser`, so the process the daemon holds is the
    /// workload itself. `runuser` stays alive supervising a PAM session and puts
    /// two fixed seconds between the stop and the exit, and that is time taken
    /// out of the start of every lease this node serves.
    fn spawn(&self) -> anyhow::Result<Child> {
        let (reader, writer) = std::io::pipe().context("open the idle workload log pipe")?;
        let mut command = match &self.account {
            Some(account) => {
                let mut command = Command::new("setpriv");
                command
                    .args([
                        "--reuid".to_owned(),
                        account.uid.to_string(),
                        "--regid".to_owned(),
                        account.gid.to_string(),
                        "--init-groups".to_owned(),
                        "--inh-caps=-all".to_owned(),
                        "--no-new-privs".to_owned(),
                        "--".to_owned(),
                    ])
                    .args(&self.config.argv);
                command
            }
            None => {
                let mut command = Command::new(&self.config.argv[0]);
                command.args(&self.config.argv[1..]);
                command
            }
        };
        let home = self
            .config
            .working_directory
            .clone()
            .unwrap_or_else(|| self.idle_root.clone());
        command
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", &home)
            .envs(&self.config.environment)
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(writer.try_clone().context("duplicate the log pipe")?)
            .stderr(writer);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Its own process group, so the stop reaches everything the
            // workload started rather than only the process the daemon named.
            command.process_group(0);
        }
        let child = command
            .spawn()
            .with_context(|| format!("start {}", self.config.argv[0]))?;
        tracing::info!(pid = child.id(), "started the idle workload");
        drain_log(reader, self.state_root.join("idle.log"));
        Ok(child)
    }

    fn stop_for_lease(&mut self) -> anyhow::Result<Release> {
        let started = Instant::now();
        self.request_stop();
        let mut forced = false;
        if !self.wait_for_exit(Duration::from_secs(self.config.stop_grace_seconds)) {
            tracing::warn!(
                "the idle workload did not stop within its grace period; killing the process group"
            );
            forced = true;
            self.force_stop();
            self.wait_for_exit(KILL_GRACE);
        }
        let exit_ms = elapsed_ms(started);
        self.collect();

        let free_started = Instant::now();
        let free_deadline = free_started + Duration::from_secs(self.config.gpu_release_seconds);
        while !(self.probes.gpu_free)(&self.gpu_uuid) {
            if Instant::now() >= free_deadline {
                self.quarantine();
                anyhow::bail!("the node could not release the GPU before the lease started");
            }
            thread::sleep(POLL);
        }
        let free_ms = elapsed_ms(free_started);
        self.last_release_ms = Some(exit_ms + free_ms);
        self.last_error = None;
        self.backoff = MINIMUM_BACKOFF;
        self.resume_at = None;
        // Released last, so the launch that follows is the next thing to take
        // it.
        self.reservation = None;
        self.write_state(Phase::Held);
        Ok(Release {
            exit_ms,
            free_ms,
            forced,
        })
    }

    /// Driven by what the operator configured rather than by what this daemon
    /// last saw running. A unit with `Restart=always` is live again seconds
    /// after `reap` let go of it, and the handshake has to reach whatever is on
    /// the card now.
    fn request_stop(&self) {
        match self.config.systemd_unit.as_deref() {
            Some(unit) => {
                if let Err(error) = systemctl(&["stop", "--no-block", unit]) {
                    tracing::warn!(%error, "could not ask systemd to stop the idle workload");
                }
            }
            None => {
                if let Some(group) = self.last_group {
                    signal_group(group, libc::SIGTERM);
                }
            }
        }
    }

    fn force_stop(&self) {
        match self.config.systemd_unit.as_deref() {
            Some(unit) => {
                if let Err(error) = systemctl(&["kill", "--signal=SIGKILL", unit]) {
                    tracing::warn!(%error, "could not kill the idle workload unit");
                }
            }
            None => {
                if let Some(group) = self.last_group {
                    signal_group(group, libc::SIGKILL);
                }
            }
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.workload_is_gone() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(POLL);
        }
    }

    /// Asked of the host rather than of the handle this daemon holds. Under a
    /// systemd unit the answer is `is-active`, which stays true through the
    /// restart window where `reap` has already let go.
    fn workload_is_gone(&mut self) -> bool {
        if let Some(unit) = self.config.systemd_unit.as_deref() {
            return !unit_is_active(unit);
        }
        match &mut self.running {
            Some(Running::Process(child)) => child.try_wait().ok().flatten().is_some(),
            _ => true,
        }
    }

    fn collect(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        self.started_at = None;
        let Running::Process(mut child) = running else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            // Still there after a kill means it is stuck inside the driver.
            // Waiting on it would take the daemon down with it, so it is left
            // to the kernel and the probe below quarantines the node.
            tracing::warn!(
                pid = child.id(),
                "the idle workload did not die; leaving it to the kernel"
            );
            return;
        }
        let _ = child.wait();
    }

    fn quarantine(&mut self) {
        self.quarantined = true;
        self.free_readings = 0;
        self.last_error = Some("the GPU was still busy when a lease needed it".to_owned());
        self.write_state(Phase::Quarantined);
        tracing::error!(
            gpu = %self.gpu_uuid,
            "the GPU did not come free for a lease; the idle workload and telemetry stay down until it does"
        );
    }

    fn write_state(&self, phase: Phase) {
        let state = IdleState {
            phase,
            pid: match &self.running {
                Some(Running::Process(child)) => Some(child.id()),
                _ => None,
            },
            since: Utc::now(),
            last_error: self.last_error.clone(),
            last_release_ms: self.last_release_ms,
        };
        if let Err(error) = persist(&self.state_root.join("state.json"), &state) {
            tracing::warn!(%error, "could not record the idle workload state");
        }
    }
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The directory the daemon keeps its own files in. Root owns it and nobody
/// else may write it: the workload runs under its own account and a directory
/// it can write is a directory where it chooses what root's next write lands
/// on.
fn own_directory(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(error) = builder.create(path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error).with_context(|| format!("create {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("read {}", path.display()))?;
        if !metadata.is_dir() {
            anyhow::bail!("{} is not a directory", path.display());
        }
        let us = unsafe { libc::geteuid() };
        if metadata.uid() != us {
            anyhow::bail!(
                "{} belongs to uid {} and this daemon runs as uid {us}; the daemon keeps its own files where only it can write them",
                path.display(),
                metadata.uid()
            );
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("tighten {} to 0700", path.display()))?;
    }
    Ok(())
}

fn persist(path: &Path, state: &IdleState) -> anyhow::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn signal_group(pid: u32, signal: i32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    // Negative for the whole group. The workload leads its own group, so this
    // reaches the miner and every worker it started.
    unsafe { libc::kill(-pid, signal) };
}

#[cfg(not(unix))]
fn signal_group(_pid: u32, _signal: i32) {}

fn systemctl(arguments: &[&str]) -> anyhow::Result<()> {
    let output = Command::new("systemctl")
        .args(arguments)
        .output()
        .context("run systemctl")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "systemctl {} failed: {}",
            arguments.join(" "),
            detail.trim().chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

fn unit_is_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

/// One log, capped, with one older copy kept. Pool output is noisy and a node
/// left alone for a month should not fill its disk with it.
fn drain_log(reader: PipeReader, path: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let Ok(mut file) = append(&path) else {
            tracing::warn!(path = %path.display(), "could not open the idle workload log");
            return;
        };
        let mut written = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if written + line.len() as u64 > LOG_BYTES
                && fs::rename(&path, path.with_extension("log.1")).is_ok()
                && let Ok(fresh) = append(&path)
            {
                file = fresh;
                written = 0;
            }
            if file.write_all(&line).is_ok() {
                written += line.len() as u64;
            }
        }
    })
}

fn append(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Nothing here follows a link into somewhere else the unit may write.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// The account the workload runs under, resolved once at startup so a name that
/// does not exist on this host is a refusal rather than a restart loop.
#[derive(Debug, Clone, Copy)]
struct Account {
    uid: u32,
    gid: u32,
}

fn account(user: &str) -> anyhow::Result<Account> {
    Ok(Account {
        uid: account_id(user, "-u")?,
        gid: account_id(user, "-g")?,
    })
}

fn account_id(user: &str, which: &str) -> anyhow::Result<u32> {
    let output = Command::new("id")
        .args([which, user])
        .output()
        .context("look up the idle workload account")?;
    if !output.status.success() {
        anyhow::bail!("there is no account named {user} on this host");
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .with_context(|| format!("read the identifiers for {user}"))
}

/// Prove the machine can hand the card over before it is bonded to do so.
///
/// This is the only exercise of the handshake that touches real hardware. It
/// starts the workload, waits for the driver to report a process on the card,
/// runs the same stop a lease runs, and prints what it measured. Passing means
/// the workload stayed inside both of the times the operator configured: a
/// workload that had to be killed, or a card that came free late, fails here
/// rather than on a lease somebody paid for.
pub fn check(
    config: IdleConfig,
    idle_root: PathBuf,
    state_root: PathBuf,
    lease_root: PathBuf,
    gpu_uuid: String,
) -> anyhow::Result<()> {
    let idle = Idle::new(config, idle_root, state_root, lease_root, gpu_uuid.clone())?;
    let mut inner = idle.inner.lock().expect("idle supervisor");
    let stop_grace = inner.config.stop_grace_seconds;
    let release_allowance = inner.config.gpu_release_seconds;

    println!("starting the idle workload");
    inner.start()?;
    let started = Instant::now();
    let claim_deadline = started + Duration::from_secs(120);
    let mut took_the_card = false;
    while Instant::now() < claim_deadline {
        if !(inner.probes.gpu_free)(&gpu_uuid) {
            took_the_card = true;
            break;
        }
        thread::sleep(POLL);
    }
    if took_the_card {
        println!(
            "the driver reported a process on the card after {:.1}s",
            started.elapsed().as_secs_f64()
        );
    } else {
        println!("the workload never took the card, so this only measures stopping it");
    }

    println!("stopping it the way a lease does");
    let release = inner.stop_for_lease()?;
    println!(
        "it exited after {:.1}s and the allowance is {stop_grace}s",
        release.exit_ms as f64 / 1_000.0
    );
    println!(
        "the card was free {:.1}s after that and the allowance is {release_allowance}s",
        release.free_ms as f64 / 1_000.0
    );

    let mut over = Vec::new();
    if release.forced {
        over.push(format!(
            "the workload ignored the stop signal and had to be killed after {stop_grace}s"
        ));
    } else if release.exit_ms > stop_grace * 1_000 {
        over.push(format!(
            "the workload took longer than {stop_grace}s to exit"
        ));
    }
    if release.free_ms > release_allowance * 1_000 {
        over.push(format!(
            "the card took longer than {release_allowance}s to come free"
        ));
    }
    if !over.is_empty() {
        anyhow::bail!(
            "this node cannot hand the GPU to a lease within the times it is configured for: {}",
            over.join(", and ")
        );
    }
    println!("this node can hand the GPU to a lease within the times it is configured for");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "prismd-idle-{name}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn shell_workload(script: &str) -> IdleConfig {
        IdleConfig {
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            stop_grace_seconds: 2,
            gpu_release_seconds: 2,
            ..IdleConfig::default()
        }
    }

    fn supervisor(name: &str, config: IdleConfig, probes: Probes) -> (Idle, PathBuf) {
        let root = temporary_directory(name);
        let state = root.join("state");
        own_directory(&state).unwrap();
        let idle = Idle::with_probes(
            config,
            None,
            root.clone(),
            state,
            root.join("leases"),
            root.join("locks"),
            "GPU-0000".to_owned(),
            probes,
        );
        (idle, root)
    }

    fn probes(free: bool, leases: bool) -> Probes {
        Probes {
            gpu_free: Box::new(move |_| free),
            lease_containers: Box::new(move || leases),
        }
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[test]
    #[cfg(unix)]
    fn a_workload_that_ignores_the_stop_signal_is_killed() {
        let root = temporary_directory("escalation");
        let trapped = root.join("trapped");
        let (idle, supervisor_root) = supervisor(
            "escalation-run",
            shell_workload(&format!(
                "trap '' TERM; : >{}; while :; do sleep 1; done",
                trapped.display()
            )),
            probes(true, false),
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.start().unwrap();
        let pid = match &inner.running {
            Some(Running::Process(child)) => child.id(),
            _ => panic!("the workload did not start"),
        };
        // The signal has to arrive after the trap is installed, or the shell
        // takes the default disposition and the escalation never happens.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !trapped.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(trapped.exists(), "the workload never armed its trap");

        let release = inner.stop_for_lease().unwrap();
        assert!(
            release.exit_ms >= 2_000 && release.forced,
            "the grace period has to run out before the kill: {release:?}"
        );
        assert!(!process_exists(pid));
        drop(inner);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(supervisor_root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn a_workload_that_honours_the_stop_signal_exits_inside_the_grace_period() {
        let (idle, root) = supervisor(
            "clean-stop",
            IdleConfig {
                stop_grace_seconds: 30,
                ..shell_workload("sleep 300")
            },
            probes(true, false),
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.start().unwrap();
        // The workload's own directory is not where the daemon writes.
        assert!(root.join("state").join("state.json").exists());
        assert!(!root.join("state.json").exists());
        let release = inner.stop_for_lease().unwrap();
        assert!(
            release.exit_ms < 10_000 && !release.forced,
            "it should go on the first signal, well inside its grace: {release:?}"
        );
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    /// A miner starts workers and the workers hold the card. Signalling only
    /// the process the daemon spawned leaves them on it.
    #[test]
    #[cfg(unix)]
    fn stopping_the_workload_reaches_the_processes_it_started() {
        let root = temporary_directory("group-kill");
        let marker = root.join("grandchild.pid");
        let (idle, supervisor_root) = supervisor(
            "group-kill-run",
            shell_workload(&format!(
                "sh -c 'echo $$ > {}; sleep 300' & wait",
                marker.display()
            )),
            probes(true, false),
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.start().unwrap();
        // The file exists from the moment the redirect opens it, so this waits
        // for a number rather than for the name.
        let deadline = Instant::now() + Duration::from_secs(30);
        let grandchild = loop {
            if let Some(pid) = fs::read_to_string(&marker)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "the workload started no worker");
            thread::sleep(Duration::from_millis(25));
        };
        assert!(process_exists(grandchild));

        inner.stop_for_lease().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_exists(grandchild) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !process_exists(grandchild),
            "the stop has to reach the whole process group"
        );
        drop(inner);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(supervisor_root).unwrap();
    }

    /// The lease is what has to fail here. Starting it anyway would hand a
    /// renter a card somebody else is still computing on.
    #[test]
    #[cfg(unix)]
    fn a_card_that_never_comes_free_fails_the_lease_and_quarantines_the_node() {
        let (idle, root) = supervisor(
            "never-free",
            shell_workload("sleep 300"),
            probes(false, false),
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.start().unwrap();
        let error = inner.stop_for_lease().unwrap_err().to_string();
        assert!(error.contains("could not release the GPU"), "{error}");
        assert!(inner.quarantined);
        inner.tick();
        assert!(
            inner.quarantined && inner.running.is_none(),
            "a quarantined node restarts neither the workload nor its telemetry"
        );
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    /// Busy, free, busy, free, free. A single free answer between two busy ones
    /// is a race with a process that has not finished dying, so the count only
    /// counts when it runs consecutively.
    #[test]
    #[cfg(unix)]
    fn a_quarantined_node_resumes_after_two_free_readings() {
        let readings = AtomicU32::new(0);
        let (idle, root) = supervisor(
            "recovery",
            shell_workload("sleep 300"),
            Probes {
                gpu_free: Box::new(move |_| {
                    matches!(readings.fetch_add(1, Ordering::SeqCst), 1 | 3 | 4)
                }),
                lease_containers: Box::new(|| false),
            },
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.quarantined = true;
        for reading in 0..4 {
            inner.tick();
            assert!(inner.quarantined, "reading {reading} must not lift it");
        }
        inner.tick();
        assert!(!inner.quarantined);
        assert!(inner.running.is_some());
        inner.request_stop();
        inner.wait_for_exit(Duration::from_secs(5));
        inner.collect();
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn a_crash_loop_backs_off_and_stops_hammering_the_host() {
        let (idle, root) = supervisor("backoff", shell_workload("exit 1"), probes(true, false));
        let mut inner = idle.inner.lock().unwrap();
        inner.start().unwrap();
        assert!(inner.wait_for_exit(Duration::from_secs(30)));

        inner.tick();
        assert_eq!(inner.backoff, MINIMUM_BACKOFF * 2);
        inner.tick();
        assert_eq!(
            inner.backoff,
            MINIMUM_BACKOFF * 2,
            "the backoff holds the restart back"
        );

        inner.resume_at = Some(Instant::now());
        inner.tick();
        assert!(inner.wait_for_exit(Duration::from_secs(30)));
        inner.tick();
        assert_eq!(inner.backoff, MINIMUM_BACKOFF * 4);
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    /// A daemon that restarts mid-lease finds the container still there, and
    /// the workload must not start on top of it. A handshake for the next lease
    /// does not settle the question either: the container is still there.
    #[test]
    #[cfg(unix)]
    fn a_lease_still_on_the_node_holds_the_idle_workload_down() {
        let (idle, root) = supervisor(
            "reconcile-container",
            shell_workload("sleep 300"),
            probes(true, true),
        );
        let mut inner = idle.inner.lock().unwrap();
        inner.tick();
        assert!(inner.running.is_none());

        inner.stop_for_lease().unwrap();
        inner.resume_at = None;
        inner.tick();
        assert!(
            inner.running.is_none(),
            "the workload started on top of a lease container"
        );
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    /// `run_batch` writes no state file, so the container list is the primary
    /// signal and this is the second one.
    #[test]
    #[cfg(unix)]
    fn a_lease_state_file_that_says_ready_holds_the_idle_workload_down() {
        let (idle, root) = supervisor(
            "reconcile-state",
            shell_workload("sleep 300"),
            probes(true, false),
        );
        let leases = root.join("leases");
        fs::create_dir_all(&leases).unwrap();
        fs::write(
            leases.join("77.json"),
            serde_json::json!({
                "lease_id": "77",
                "image": "registry.example/runtime@sha256:aa",
                "isolation": "shared",
                "vfio_group": null,
                "pci_devices": [],
                "phase": "ready",
                "ssh_port": 2_222,
                "jupyter_port": 8_888,
                "ready_at": null,
                "error": null,
                "updated_at": Utc::now().to_rfc3339(),
            })
            .to_string(),
        )
        .unwrap();

        let mut inner = idle.inner.lock().unwrap();
        inner.tick();
        assert!(inner.running.is_none());

        fs::write(
            leases.join("77.json"),
            serde_json::json!({
                "lease_id": "77",
                "image": "registry.example/runtime@sha256:aa",
                "isolation": "shared",
                "vfio_group": null,
                "pci_devices": [],
                "phase": "completed",
                "ssh_port": 2_222,
                "jupyter_port": 8_888,
                "ready_at": null,
                "error": null,
                "updated_at": Utc::now().to_rfc3339(),
            })
            .to_string(),
        )
        .unwrap();
        inner.resume_at = None;
        inner.tick();
        assert!(inner.running.is_some());
        inner.request_stop();
        inner.wait_for_exit(Duration::from_secs(5));
        inner.collect();
        drop(inner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_configuration_that_could_run_anything_is_refused() {
        let unit = IdleConfig {
            systemd_unit: Some("miner.service".to_owned()),
            stop_grace_seconds: 30,
            gpu_release_seconds: 20,
            ..IdleConfig::default()
        };
        assert!(unit.validate().is_ok());
        assert!(IdleConfig::default().validate().is_err());
        assert!(
            IdleConfig {
                argv: vec!["/usr/local/bin/miner".to_owned()],
                user: Some("prismd-idle".to_owned()),
                ..unit.clone()
            }
            .validate()
            .is_err(),
            "a configuration naming both shapes is ambiguous"
        );
        assert!(
            IdleConfig {
                systemd_unit: Some("../../etc/systemd/system/anything".to_owned()),
                ..unit.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            IdleConfig {
                stop_grace_seconds: 0,
                ..unit.clone()
            }
            .validate()
            .is_err()
        );

        let exec = IdleConfig {
            argv: vec!["/bin/sh".to_owned()],
            user: Some("prismd-idle".to_owned()),
            systemd_unit: None,
            ..unit
        };
        assert!(exec.validate().is_ok());
        assert!(
            IdleConfig {
                argv: vec!["miner".to_owned()],
                ..exec.clone()
            }
            .validate()
            .is_err(),
            "a relative argv[0] resolves against a PATH nobody controls"
        );
        assert!(
            IdleConfig {
                user: Some("root".to_owned()),
                ..exec.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            IdleConfig {
                user: None,
                ..exec.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            IdleConfig {
                working_directory: Some(PathBuf::from("relative/path")),
                ..exec
            }
            .validate()
            .is_err()
        );
    }

    /// Anyone who can write the file chooses what the daemon runs, so one the
    /// world can write is refused before it is read.
    #[test]
    #[cfg(unix)]
    fn a_world_writable_configuration_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("permissions");
        let path = root.join("idle.json");
        fs::write(
            &path,
            serde_json::json!({ "systemd_unit": "miner.service" }).to_string(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let config = load(&path).unwrap();
        assert_eq!(config.systemd_unit.as_deref(), Some("miner.service"));
        assert_eq!(config.stop_grace_seconds, DEFAULT_STOP_GRACE_SECONDS);
        assert_eq!(config.gpu_release_seconds, DEFAULT_GPU_RELEASE_SECONDS);
        fs::remove_dir_all(root).unwrap();
    }

    /// The workload runs under an account of its own, so the directory holding
    /// the daemon's state and log has to be one only the daemon can write.
    #[test]
    #[cfg(unix)]
    fn the_directory_the_daemon_writes_is_private_and_never_a_link() {
        use std::os::unix::fs::PermissionsExt;

        let root = temporary_directory("state-directory");
        let state = root.join("idle-state");
        own_directory(&state).unwrap();
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        own_directory(&state).unwrap();

        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let link = root.join("linked-state");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        assert!(own_directory(&link).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn the_log_keeps_one_older_copy_and_stops_growing() {
        let root = temporary_directory("log-rotation");
        let path = root.join("idle.log");
        let (reader, mut writer) = std::io::pipe().unwrap();
        let handle = drain_log(reader, path.clone());
        let line = format!("{}\n", "n".repeat(4_095));
        for _ in 0..(LOG_BYTES / 4_096 + 8) {
            writer.write_all(line.as_bytes()).unwrap();
        }
        drop(writer);
        handle.join().unwrap();

        assert!(path.with_extension("log.1").exists());
        assert!(fs::metadata(&path).unwrap().len() < LOG_BYTES);
        fs::remove_dir_all(root).unwrap();
    }
}
