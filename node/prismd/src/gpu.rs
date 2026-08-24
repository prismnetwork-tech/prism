use std::{
    path::Path,
    process::{Command, Stdio},
};

use anyhow::Context;
use serde::Serialize;

const NVIDIA_SMI: &str = "nvidia-smi";

/// A card the host can see and hand to a container. Under Kata the GPU is bound
/// to vfio-pci and the driver on this side never sees it, so everything here
/// describes the other mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostGpu {
    pub index: u32,
    pub uuid: String,
    pub model: String,
    pub vram_mib: u32,
}

/// One process holding a context on a card. Presence is the whole signal: a
/// row naming the GPU means something is still on it, whatever it reports for
/// memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeApp {
    pub gpu_uuid: String,
    pub pid: u32,
    pub used_mib: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub utilization_bps: u16,
    pub memory_used_mib: u32,
}

pub fn discover() -> anyhow::Result<Vec<HostGpu>> {
    discover_in(Path::new(NVIDIA_SMI))
}

fn discover_in(program: &Path) -> anyhow::Result<Vec<HostGpu>> {
    parse_gpus(&query(
        program,
        &[
            "--query-gpu=index,uuid,name,memory.total",
            "--format=csv,noheader,nounits",
        ],
    )?)
}

/// Whether anything still holds a compute context on this card.
///
/// Fail closed. A driver that will not answer, a binary that is not there and
/// output nobody can parse all mean the same thing here: nobody can say the
/// card is free, so it is not free. Framebuffer memory is deliberately not
/// consulted, because a desktop session holds some of it for as long as the
/// machine is on and the card would never read as free again.
pub fn gpu_is_free(uuid: &str) -> bool {
    match compute_apps() {
        Ok(apps) => !apps.iter().any(|app| app.gpu_uuid == uuid),
        Err(error) => {
            tracing::warn!(%error, "could not read the GPU compute processes; treating the card as busy");
            false
        }
    }
}

pub fn compute_apps() -> anyhow::Result<Vec<ComputeApp>> {
    compute_apps_in(Path::new(NVIDIA_SMI))
}

fn compute_apps_in(program: &Path) -> anyhow::Result<Vec<ComputeApp>> {
    parse_compute_apps(&query(
        program,
        &[
            "--query-compute-apps=gpu_uuid,pid,used_gpu_memory",
            "--format=csv,noheader",
        ],
    )?)
}

pub fn usage(uuid: &str) -> anyhow::Result<Usage> {
    let text = query(
        Path::new(NVIDIA_SMI),
        &[
            "--query-gpu=uuid,utilization.gpu,memory.used",
            "--format=csv,noheader,nounits",
        ],
    )?;
    parse_usage(&text, uuid)
}

pub fn driver_version() -> Option<String> {
    let text = query(
        Path::new(NVIDIA_SMI),
        &["--query-gpu=driver_version", "--format=csv,noheader"],
    )
    .ok()?;
    let version = text.lines().next()?.trim();
    (!version.is_empty() && version != "[N/A]").then(|| version.to_owned())
}

/// Pick the card a lease runs on. One card is served per host, so a machine
/// with several of them needs the operator to say which, by UUID.
pub fn select(gpus: Vec<HostGpu>, requested: Option<&str>) -> anyhow::Result<HostGpu> {
    match requested {
        Some(uuid) => gpus
            .into_iter()
            .find(|gpu| gpu.uuid == uuid)
            .with_context(|| format!("no NVIDIA GPU on this host has the UUID {uuid}")),
        None => {
            let mut gpus = gpus.into_iter();
            let first = gpus
                .next()
                .context("nvidia-smi reports no GPU on this host")?;
            if let Some(second) = gpus.next() {
                anyhow::bail!(
                    "this host has more than one GPU, so --gpu-uuid has to name the one to serve: {}, {}{}",
                    first.uuid,
                    second.uuid,
                    gpus.map(|gpu| format!(", {}", gpu.uuid))
                        .collect::<String>()
                );
            }
            Ok(first)
        }
    }
}

fn query(program: &Path, arguments: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .with_context(|| {
            format!(
                "run {}; the NVIDIA driver has to be installed and on PATH",
                program.display()
            )
        })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "{} exited with {}: {}",
            program.display(),
            output.status,
            truncate(detail.trim())
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("{} printed output that is not UTF-8", program.display()))
}

fn parse_gpus(text: &str) -> anyhow::Result<Vec<HostGpu>> {
    rows(text)
        .map(|fields| {
            let [index, uuid, model, vram_mib] = fields.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("nvidia-smi returned a GPU row this build cannot read")
            })?;
            Ok(HostGpu {
                index: index.parse().context("GPU index is not a number")?,
                uuid: validate_uuid(uuid)?,
                model: validate_model(model)?,
                vram_mib: vram_mib
                    .parse()
                    .context("GPU memory is not a whole number of MiB")?,
            })
        })
        .collect()
}

fn parse_compute_apps(text: &str) -> anyhow::Result<Vec<ComputeApp>> {
    rows(text)
        .map(|fields| {
            let [uuid, pid, used] = fields.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("nvidia-smi returned a compute process row this build cannot read")
            })?;
            Ok(ComputeApp {
                gpu_uuid: validate_uuid(uuid)?,
                pid: pid.parse().context("compute process id is not a number")?,
                used_mib: used
                    .strip_suffix(" MiB")
                    .and_then(|value| value.trim().parse().ok()),
            })
        })
        .collect()
}

fn parse_usage(text: &str, uuid: &str) -> anyhow::Result<Usage> {
    for fields in rows(text) {
        let [row_uuid, utilization, memory_used] = fields.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("nvidia-smi returned a utilization row this build cannot read")
        })?;
        if row_uuid != uuid {
            continue;
        }
        let percent: u16 = utilization
            .parse()
            .context("GPU utilization is not a percentage")?;
        return Ok(Usage {
            utilization_bps: percent.min(100) * 100,
            memory_used_mib: memory_used
                .parse()
                .context("GPU memory in use is not a whole number of MiB")?,
        });
    }
    anyhow::bail!("nvidia-smi did not report on {uuid}")
}

/// nvidia-smi separates CSV fields with a comma and a space and quotes nothing,
/// so a field carrying a comma of its own would shift every field after it.
/// Every caller asks for a fixed number of them and refuses a row that does not
/// have exactly that many.
fn rows(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.split(',').map(str::trim).collect())
}

fn validate_uuid(value: &str) -> anyhow::Result<String> {
    if !value.starts_with("GPU-")
        || value.len() < 8
        || value.len() > 96
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        anyhow::bail!("{} is not a GPU UUID", truncate(value));
    }
    Ok(value.to_owned())
}

/// The model reaches the control plane and an operator's terminal, so it is
/// held to printable ASCII rather than whatever a driver decides to emit.
fn validate_model(value: &str) -> anyhow::Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_graphic() || character == ' ')
    {
        anyhow::bail!("nvidia-smi reported a GPU name this build cannot use");
    }
    Ok(value.to_owned())
}

fn truncate(value: &str) -> String {
    value.chars().take(200).collect()
}

/// The binary nerdctl's `--gpus` reaches for through containerd. Without it the
/// flag fails at container start, which is why preflight asks for it by name
/// rather than for the toolkit package.
pub fn nvidia_container_cli_available() -> bool {
    crate::command_success("nvidia-container-cli", &["--version"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn stub(name: &str, body: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "prismd-gpu-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("nvidia-smi");
        fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn reads_one_card_and_many_cards() {
        let one = parse_gpus(
            "0, GPU-1a2b3c4d-0000-0000-0000-000000000001, NVIDIA H100 80GB HBM3, 81559\n",
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].index, 0);
        assert_eq!(one[0].model, "NVIDIA H100 80GB HBM3");
        assert_eq!(one[0].vram_mib, 81_559);

        let many = parse_gpus(
            "0, GPU-1a2b3c4d-0000-0000-0000-000000000001, NVIDIA GeForce RTX 4090, 24564\n\
             1, GPU-1a2b3c4d-0000-0000-0000-000000000002, NVIDIA GeForce RTX 4090, 24564\n",
        )
        .unwrap();
        assert_eq!(many.len(), 2);
        assert_eq!(many[1].uuid, "GPU-1a2b3c4d-0000-0000-0000-000000000002");
    }

    /// An empty answer means the driver saw no cards. That is a host with
    /// nothing to serve, and the caller decides what to do about it, but it is
    /// not a parse failure.
    #[test]
    fn no_cards_reads_as_an_empty_list() {
        assert!(parse_gpus("").unwrap().is_empty());
        assert!(parse_gpus("\n \n").unwrap().is_empty());
    }

    #[test]
    fn refuses_output_it_cannot_read() {
        assert!(parse_gpus("0, GPU-1a2b, NVIDIA H100\n").is_err());
        assert!(parse_gpus("zero, GPU-1a2b3c4d, NVIDIA H100, 81559\n").is_err());
        assert!(parse_gpus("0, 1a2b3c4d, NVIDIA H100, 81559\n").is_err());
        assert!(parse_gpus("0, GPU-1a2b3c4d, NVIDIA H100, most of it\n").is_err());
        assert!(parse_gpus("0, GPU-1a2b3c4d, NVIDIA, H100, 81559\n").is_err());
    }

    /// A driver that answers with an error must never read as "no GPUs": the
    /// node would enrol as a machine with nothing to serve, or hand a lease a
    /// card it never checked.
    #[test]
    #[cfg(unix)]
    fn a_failing_driver_is_an_error_and_not_an_empty_list() {
        let failing = stub(
            "failing",
            "#!/bin/sh\necho 'NVML: driver/library mismatch' >&2\nexit 9\n",
        );
        let error = discover_in(&failing).unwrap_err().to_string();
        assert!(error.contains("driver/library mismatch"), "{error}");

        let missing = failing.parent().unwrap().join("absent-nvidia-smi");
        assert!(discover_in(&missing).is_err());
        fs::remove_dir_all(failing.parent().unwrap()).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn reads_the_cards_a_working_driver_lists() {
        let working = stub(
            "working",
            "#!/bin/sh\nprintf '0, GPU-1a2b3c4d-0000-0000-0000-000000000001, NVIDIA L40S, 46068\\n'\n",
        );
        let gpus = discover_in(&working).unwrap();
        assert_eq!(gpus.len(), 1);
        assert_eq!(gpus[0].model, "NVIDIA L40S");
        fs::remove_dir_all(working.parent().unwrap()).unwrap();
    }

    #[test]
    fn reads_the_processes_still_holding_a_card() {
        let apps = parse_compute_apps(
            "GPU-1a2b3c4d-0000-0000-0000-000000000001, 4211, 1234 MiB\n\
             GPU-1a2b3c4d-0000-0000-0000-000000000002, 4212, [N/A]\n",
        )
        .unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].pid, 4_211);
        assert_eq!(apps[0].used_mib, Some(1_234));
        assert_eq!(apps[1].used_mib, None);
        assert!(parse_compute_apps("GPU-1a2b3c4d, 4211\n").is_err());
        assert!(parse_compute_apps("GPU-1a2b3c4d, four thousand, 1 MiB\n").is_err());
    }

    /// The handshake asks this question before every lease, and an answer it
    /// cannot get has to hold the lease back rather than wave it through.
    #[test]
    #[cfg(unix)]
    fn an_unreadable_card_is_never_reported_free() {
        let failing = stub("busy-probe", "#!/bin/sh\nexit 2\n");
        assert!(compute_apps_in(&failing).is_err());

        let empty = stub("free-probe", "#!/bin/sh\nexit 0\n");
        assert!(compute_apps_in(&empty).unwrap().is_empty());
        fs::remove_dir_all(failing.parent().unwrap()).unwrap();
        fs::remove_dir_all(empty.parent().unwrap()).unwrap();
    }

    #[test]
    fn utilization_is_reported_in_basis_points() {
        let text = "GPU-1a2b3c4d-0000-0000-0000-000000000001, 37, 2048\n\
                    GPU-1a2b3c4d-0000-0000-0000-000000000002, 0, 12\n";
        let usage = parse_usage(text, "GPU-1a2b3c4d-0000-0000-0000-000000000001").unwrap();
        assert_eq!(usage.utilization_bps, 3_700);
        assert_eq!(usage.memory_used_mib, 2_048);
        assert!(parse_usage(text, "GPU-nothing-here").is_err());
    }

    #[test]
    fn a_second_card_has_to_be_chosen_by_uuid() {
        let first = HostGpu {
            index: 0,
            uuid: "GPU-1a2b3c4d-0000-0000-0000-000000000001".to_owned(),
            model: "NVIDIA GeForce RTX 4090".to_owned(),
            vram_mib: 24_564,
        };
        let second = HostGpu {
            index: 1,
            uuid: "GPU-1a2b3c4d-0000-0000-0000-000000000002".to_owned(),
            ..first.clone()
        };
        assert_eq!(select(vec![first.clone()], None).unwrap(), first);
        let error = select(vec![first.clone(), second.clone()], None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&first.uuid) && error.contains(&second.uuid),
            "{error}"
        );
        assert_eq!(
            select(vec![first.clone(), second.clone()], Some(&second.uuid)).unwrap(),
            second
        );
        assert!(select(vec![first], Some("GPU-not-installed")).is_err());
        assert!(select(Vec::new(), None).is_err());
    }
}
