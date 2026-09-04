use std::{
    env, fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use prism_chain::{
    EthereumSigner, Finality, RpcClient, address as chain_address, selector, word_u128,
};
use prism_protocol::{
    CommandResult, GpuSpec, HostTeeCapability, IsolationMode, LeaseState, NodeCertificateBundle,
    NodeCertificateRequest, NodeCommand, NodeCommandKind, NodeCommandOutcome, NodeCommandPoll,
    NodeCommandReport, NodeCommandReportAck, NodeCommandReportPayload, NodeEnrollment, NodePosture,
    NodeTelemetry, UnsignedNodeCertificateRequest, UnsignedNodeEnrollment, UnsignedTelemetry,
    node_id,
};
use rand::RngCore;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};
use tracing_subscriber::EnvFilter;

mod attestation;
mod dstack;
mod gpu;
mod idle;
mod probe;
mod runtime;
mod snp;
mod tunnel;

/// How long the signed device binding stays valid. Long enough to survive a
/// slow block, short enough that an abandoned signature cannot be replayed.
const REGISTRATION_WINDOW_SECONDS: u128 = 3_600;
/// Seven static words precede the signature in register()'s calldata.
const SIGNATURE_OFFSET: u128 = 7 * 32;
const CONFIRMATION_ATTEMPTS: u32 = 40;
const BATCH_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// A verdict outlives this comfortably, so the refresh is about proving the
/// card is still the one that was verified, not about racing an expiry.
const ATTESTATION_INTERVAL: Duration = Duration::from_secs(6 * 3_600);

/// The registry reverts with custom errors, which reach the operator as a bare
/// four-byte selector inside an RPC message. Translate the ones a registration
/// can actually hit.
const REGISTRY_REVERTS: &[(&str, &str)] = &[
    (
        "3a81d6fc",
        "this device is already registered; retire it before registering again",
    ),
    (
        "30812d42",
        "the node identity or payout wallet is not acceptable to the registry",
    ),
    ("6a43f8d1", "the registry rejected this rate"),
    (
        "70793649",
        "the registration window closed before the transaction landed; run it again",
    ),
    (
        "0c00084b",
        "the operator key did not sign this device binding",
    ),
    (
        "045c4b02",
        "the registration is valid but the bond could not be pulled; fund the operator wallet with PRISM and approve the registry",
    ),
];

#[derive(Parser)]
#[command(name = "prismd", about = "Prism Network GPU node daemon")]
struct Cli {
    #[command(subcommand)]
    command: CommandName,
}

/// How this node serves leases. Declared by the operator and never inferred: a
/// machine that happens to have a bound VFIO group and a kata shim can still be
/// the wrong place to run one, and guessing would change what the node claims
/// about itself without anyone deciding to.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum IsolationArg {
    KataVfio,
    Shared,
}

#[derive(Subcommand)]
enum CommandName {
    Preflight {
        #[arg(long, value_enum, env = "PRISM_ISOLATION", default_value = "kata-vfio")]
        isolation: IsolationArg,
    },
    CreateIdentity {
        #[arg(long, default_value = "/var/lib/prismd/device.json")]
        path: PathBuf,
    },
    Register {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, env = "PRISM_RPC_URL")]
        rpc_url: String,
        #[arg(long, env = "PRISM_NODE_REGISTRY_ADDRESS")]
        registry: String,
        /// Wallet that receives provider payouts. Defaults to the operator.
        #[arg(long)]
        payout_wallet: Option<String>,
        #[arg(long)]
        rate_per_second: u128,
        /// Hex-encoded key of the wallet that posts the bond. It signs the
        /// device binding and pays gas, and it stays on this machine.
        #[arg(long, env = "PRISM_OPERATOR_KEY", hide_env_values = true)]
        operator_key: String,
        #[arg(long, default_value = "prism.node.v1")]
        profile: String,
        /// Check the registration against the chain without spending anything.
        #[arg(long)]
        dry_run: bool,
    },
    Enroll {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
        #[arg(long)]
        operator_wallet: String,
        #[arg(long)]
        payout_wallet: String,
        #[arg(long)]
        gpu_model: String,
        #[arg(long)]
        vram_mib: u32,
        #[arg(long)]
        cuda_major: u16,
        #[arg(long)]
        rate_per_second: u64,
        #[arg(long)]
        benchmark_score: u32,
    },
    Certificate {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
        #[arg(long, default_value = "/var/lib/prismd/tls/node.crt")]
        certificate: PathBuf,
        #[arg(long, default_value = "/var/lib/prismd/tls/node.key")]
        private_key: PathBuf,
        #[arg(long, default_value = "/var/lib/prismd/tls/ca.crt")]
        ca_certificate: PathBuf,
    },
    Heartbeat {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
        #[arg(long, default_value_t = 0)]
        gpu_utilization_bps: u16,
        #[arg(long, default_value_t = 0)]
        gpu_memory_used_mib: u32,
        #[arg(long, default_value_t = false)]
        tunnel_connected: bool,
        #[arg(long, requires = "image_digest")]
        active_lease: Option<String>,
        #[arg(long, requires = "active_lease")]
        image_digest: Option<String>,
    },
    Attest {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
    },
    /// Runs inside a dstack CVM to attest one lease at the confidential rung:
    /// the guest agent quotes the TD and collects the GPU report, both bound to
    /// the lease's own challenges, and the signed evidence goes to the control
    /// plane. Requires the guest agent socket, so it does nothing on a host that
    /// is not a confidential VM.
    AttestLease {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
        #[arg(long)]
        lease_id: u64,
        /// Path to the OpenSSH public host-key line the lease's SSH endpoint
        /// presents. It is bound into the TDX quote so the renter can pin the
        /// session's endpoint to the measured TD.
        #[arg(long)]
        guest_channel_key_file: PathBuf,
    },
    Commands {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        control_plane: String,
        #[arg(long, default_value = "/var/lib/prismd/workspaces")]
        workspace_root: PathBuf,
        #[arg(long, default_value = "/var/lib/prismd/leases")]
        state_root: PathBuf,
        #[arg(long, default_value_t = 2_222)]
        ssh_port: u16,
        #[arg(long, default_value_t = 8_888)]
        jupyter_port: u16,
        #[arg(long, default_value_t = 5)]
        poll_seconds: u64,
        /// SHA-256 of the agent policy measured into the confidential guest
        /// image installed on this host. Setting it is how an operator declares
        /// the node can run leases as confidential guests; without it every
        /// lease runs on the ordinary runtime and takes no report.
        #[arg(long, env = "PRISM_AGENT_POLICY_DIGEST")]
        agent_policy_digest: Option<String>,
        #[arg(long, value_enum, env = "PRISM_ISOLATION", default_value = "kata-vfio")]
        isolation: IsolationArg,
        /// Which card to serve, by UUID. Needed under shared isolation when
        /// the host has more than one.
        #[arg(long, env = "PRISM_GPU_UUID")]
        gpu_uuid: Option<String>,
        /// Memory a shared lease may use. Defaults to three quarters of the
        /// host's.
        #[arg(long, env = "PRISM_LEASE_MEMORY_MIB")]
        lease_memory_mib: Option<u32>,
        /// CPUs a shared lease may use. Defaults to one short of all of them.
        #[arg(long, env = "PRISM_LEASE_CPUS")]
        lease_cpus: Option<u32>,
        /// The workload to run between leases, described by a JSON file.
        /// Without it the node does nothing while it waits.
        #[arg(long, env = "PRISM_IDLE_CONFIG")]
        idle_config: Option<PathBuf>,
    },
    /// Start the configured idle workload, wait for it to take the GPU, then
    /// stop it the way a lease does and report what that cost. Run it before
    /// bonding a node that has one.
    IdleCheck {
        #[arg(long, env = "PRISM_IDLE_CONFIG")]
        idle_config: PathBuf,
        #[arg(long, env = "PRISM_GPU_UUID")]
        gpu_uuid: Option<String>,
        /// The workload's own directory, which it runs in and owns.
        #[arg(long, default_value = "/var/lib/prismd/idle")]
        idle_root: PathBuf,
        /// Where the daemon keeps its own state file and the workload's log.
        /// Root owns this one.
        #[arg(long, default_value = "/var/lib/prismd/idle-state")]
        idle_state_root: PathBuf,
        #[arg(long, default_value = "/var/lib/prismd/leases")]
        state_root: PathBuf,
    },
    /// Runs inside the guest, not on the host: it asks the processor for a
    /// report over the challenge, the lease and the SSH host key this guest
    /// generated, and leaves it where the daemon can carry it.
    SnpReport {
        #[arg(long)]
        challenge_file: PathBuf,
        #[arg(long)]
        lease_id: u64,
        #[arg(long)]
        channel_key_file: PathBuf,
        #[arg(long)]
        output_directory: PathBuf,
    },
    Tunnel {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca_certificate: PathBuf,
        #[arg(long)]
        client_certificate: PathBuf,
        #[arg(long)]
        client_key: PathBuf,
        #[arg(long)]
        connection_id: String,
        #[arg(long, default_value = "127.0.0.1:2222")]
        ssh_target: String,
        #[arg(long, default_value = "127.0.0.1:8888")]
        jupyter_target: String,
        #[arg(long, default_value_t = 8)]
        slots: u16,
    },
    Relay {
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca_certificate: PathBuf,
        #[arg(long)]
        token: String,
        #[arg(long)]
        service: RelayServiceArg,
        #[arg(long)]
        listen: String,
    },
    ValidateImage {
        #[arg(long)]
        image: String,
    },
    Launch {
        #[arg(long)]
        image: String,
        #[arg(long)]
        lease_id: String,
        #[arg(long)]
        vfio_group: Option<u32>,
        #[arg(long, default_value = "/var/lib/prismd/workspaces")]
        workspace_root: PathBuf,
        #[arg(long, default_value = "/var/lib/prismd/leases")]
        state_root: PathBuf,
        #[arg(long)]
        duration_seconds: u32,
        #[arg(long)]
        ssh_authorized_key: PathBuf,
        #[arg(long)]
        jupyter_token: PathBuf,
        #[arg(long, default_value_t = 2_222)]
        ssh_port: u16,
        #[arg(long, default_value_t = 8_888)]
        jupyter_port: u16,
        #[arg(long, value_enum, env = "PRISM_ISOLATION", default_value = "kata-vfio")]
        isolation: IsolationArg,
        #[arg(long, env = "PRISM_GPU_UUID")]
        gpu_uuid: Option<String>,
        #[arg(long, env = "PRISM_LEASE_MEMORY_MIB")]
        lease_memory_mib: Option<u32>,
        #[arg(long, env = "PRISM_LEASE_CPUS")]
        lease_cpus: Option<u32>,
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RelayServiceArg {
    Ssh,
    Jupyter,
}

/// What the flags asked for, before the host is consulted. Kept pure so the
/// combinations this refuses can be proved without a GPU under the test.
#[derive(Debug, PartialEq, Eq)]
enum IsolationRequest {
    KataVfio {
        group: Option<u32>,
    },
    Shared {
        gpu_uuid: Option<String>,
        memory_mib: Option<u32>,
        cpus: Option<u32>,
    },
}

/// clap cannot express these: the conflict is with the value of `--isolation`
/// rather than with the presence of a flag, so the check is written out and
/// the message names the mode the flag belongs to.
fn isolation_request(
    mode: IsolationArg,
    vfio_group: Option<u32>,
    gpu_uuid: Option<String>,
    memory_mib: Option<u32>,
    cpus: Option<u32>,
) -> anyhow::Result<IsolationRequest> {
    match mode {
        IsolationArg::KataVfio => {
            if gpu_uuid.is_some() {
                anyhow::bail!(
                    "--gpu-uuid belongs to --isolation shared; under kata-vfio the card is named by its VFIO group"
                );
            }
            if memory_mib.is_some() || cpus.is_some() {
                anyhow::bail!(
                    "--lease-memory-mib and --lease-cpus belong to --isolation shared; a Kata lease gets the guest the hypervisor gave it"
                );
            }
            Ok(IsolationRequest::KataVfio { group: vfio_group })
        }
        IsolationArg::Shared => {
            if vfio_group.is_some() {
                anyhow::bail!(
                    "--vfio-group belongs to --isolation kata-vfio; under shared the card is named by --gpu-uuid"
                );
            }
            Ok(IsolationRequest::Shared {
                gpu_uuid,
                memory_mib,
                cpus,
            })
        }
    }
}

/// A lease started by hand under Kata names the card it takes. The daemon
/// discovers it instead, which is why this is not part of the request.
fn launch_vfio_group(request: &IsolationRequest) -> anyhow::Result<Option<u32>> {
    let IsolationRequest::KataVfio { group } = request else {
        return Ok(None);
    };
    let group = group.context(
        "--isolation kata-vfio needs --vfio-group to name the card that was passed through",
    )?;
    Ok(Some(group))
}

/// The mode this daemon runs in, resolved once against the host so no lease has
/// to go looking for the card it runs on.
enum IsolationSetting {
    KataVfio,
    Shared {
        gpu: gpu::HostGpu,
        limits: runtime::LeaseLimits,
    },
}

impl IsolationSetting {
    fn resolve(request: IsolationRequest) -> anyhow::Result<Self> {
        match request {
            IsolationRequest::KataVfio { .. } => Ok(Self::KataVfio),
            IsolationRequest::Shared {
                gpu_uuid,
                memory_mib,
                cpus,
            } => {
                let gpu = gpu::select(gpu::discover()?, gpu_uuid.as_deref())?;
                let host = match (memory_mib, cpus) {
                    (Some(_), Some(_)) => runtime::LeaseLimits::UNUSED,
                    _ => runtime::LeaseLimits::for_host()?,
                };
                let limits = runtime::LeaseLimits {
                    memory_mib: memory_mib.unwrap_or(host.memory_mib),
                    cpus: cpus.unwrap_or(host.cpus),
                };
                tracing::info!(
                    gpu = %gpu.uuid,
                    model = %gpu.model,
                    memory_mib = limits.memory_mib,
                    cpus = limits.cpus,
                    "serving open leases on a host-visible GPU"
                );
                Ok(Self::Shared { gpu, limits })
            }
        }
    }

    /// The card the next lease runs on. Under Kata the group is discovered per
    /// command, exactly as it always has been, and a host with none reports the
    /// command failed rather than taking the daemon down.
    fn isolation(&self) -> anyhow::Result<Option<runtime::Isolation>> {
        Ok(match self {
            Self::KataVfio => runtime::discover_vfio_gpu_groups()?
                .into_iter()
                .next()
                .map(|group| runtime::Isolation::KataVfio { group }),
            Self::Shared { gpu, .. } => Some(runtime::Isolation::Shared { gpu: gpu.clone() }),
        })
    }

    fn limits(&self) -> runtime::LeaseLimits {
        match self {
            Self::KataVfio => runtime::LeaseLimits::UNUSED,
            Self::Shared { limits, .. } => *limits,
        }
    }

    fn shared_gpu(&self) -> Option<&gpu::HostGpu> {
        match self {
            Self::KataVfio => None,
            Self::Shared { gpu, .. } => Some(gpu),
        }
    }

    /// A node configured shared reports shared, on any host. Inferring it from
    /// what happens to be installed would let a machine that still has a bound
    /// group and a kata shim claim a class it is not serving.
    fn posture(&self, capability: &HostTeeCapability) -> NodePosture {
        match self {
            Self::KataVfio => local_posture(capability),
            Self::Shared { .. } => NodePosture {
                isolation: IsolationMode::Shared,
                attestation: None,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    supported: bool,
    isolation: &'static str,
    architecture: String,
    linux: bool,
    nvidia_smi: bool,
    driver_version: Option<String>,
    containerd: bool,
    nerdctl: bool,
    kata_runtime: bool,
    iommu: bool,
    vfio: bool,
    nftables: bool,
    swap_disabled: bool,
    nvidia_container_toolkit: bool,
    nvidia_container_cli: bool,
    workspace_ports_free: bool,
    forward_chain_open: bool,
    sev: bool,
    sev_es: bool,
    sev_snp: bool,
    sev_guest_device: bool,
    kata_confidential_runtime: bool,
    vfio_gpu_groups: Vec<runtime::VfioGroup>,
    host_gpus: Vec<gpu::HostGpu>,
    gpu_devices: Vec<PciIdentity>,
}

/// The facts the baseline is decided from, kept apart from the report so the
/// decision is a function of them and of the mode, and nothing else.
struct PreflightChecks {
    linux: bool,
    x86_64: bool,
    containerd: bool,
    nerdctl: bool,
    kata_runtime: bool,
    iommu: bool,
    vfio: bool,
    nftables: bool,
    swap_disabled: bool,
    nvidia_smi: bool,
    nvidia_container_cli: bool,
    workspace_ports_free: bool,
    forward_chain_open: bool,
    vfio_gpu_groups: usize,
    host_gpus: usize,
}

fn preflight_supported(isolation: IsolationArg, checks: &PreflightChecks) -> bool {
    match isolation {
        IsolationArg::KataVfio => {
            checks.linux
                && checks.x86_64
                && checks.containerd
                && checks.nerdctl
                && checks.kata_runtime
                && checks.iommu
                && checks.vfio
                && checks.nftables
                && checks.swap_disabled
                && checks.vfio_gpu_groups > 0
        }
        // No kata, no IOMMU, no VFIO and no requirement to have disabled swap:
        // this is a stock host with a driver, and asking for the passthrough
        // baseline here would only turn away the machines the mode is for.
        IsolationArg::Shared => {
            checks.linux
                && checks.x86_64
                && checks.containerd
                && checks.nerdctl
                && checks.nftables
                && checks.nvidia_smi
                && checks.nvidia_container_cli
                && checks.host_gpus > 0
                && checks.workspace_ports_free
                && checks.forward_chain_open
        }
    }
}

/// Which card, not what class of card. An operator reading this should see
/// 10de:2331 rather than a 3D controller.
#[derive(Debug, Serialize)]
struct PciIdentity {
    address: String,
    vendor_id: String,
    device_id: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceIdentity {
    signing_key_hex: String,
    #[serde(default)]
    telemetry_sequence: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();
    match Cli::parse().command {
        CommandName::Preflight { isolation } => preflight(isolation),
        CommandName::CreateIdentity { path } => create_identity(path),
        CommandName::Register {
            identity,
            rpc_url,
            registry,
            payout_wallet,
            rate_per_second,
            operator_key,
            profile,
            dry_run,
        } => {
            register(Registration {
                identity_path: identity,
                rpc_url,
                registry,
                payout_wallet,
                rate_per_second,
                operator_key,
                profile,
                dry_run,
            })
            .await
        }
        CommandName::Enroll {
            identity,
            control_plane,
            operator_wallet,
            payout_wallet,
            gpu_model,
            vram_mib,
            cuda_major,
            rate_per_second,
            benchmark_score,
        } => {
            enroll(
                identity,
                control_plane,
                operator_wallet,
                payout_wallet,
                GpuSpec {
                    model: gpu_model,
                    vram_mib,
                    cuda_major,
                },
                rate_per_second,
                benchmark_score,
            )
            .await
        }
        CommandName::Heartbeat {
            identity,
            control_plane,
            gpu_utilization_bps,
            gpu_memory_used_mib,
            tunnel_connected,
            active_lease,
            image_digest,
        } => {
            publish_telemetry(
                &identity,
                &control_plane,
                gpu_utilization_bps,
                gpu_memory_used_mib,
                tunnel_connected,
                active_lease,
                image_digest,
                local_posture(host_capability()),
            )
            .await
        }
        CommandName::Certificate {
            identity,
            control_plane,
            certificate,
            private_key,
            ca_certificate,
        } => {
            provision_certificate(
                &identity,
                &control_plane,
                &certificate,
                &private_key,
                &ca_certificate,
            )
            .await
        }
        CommandName::Attest {
            identity,
            control_plane,
        } => {
            attest_once(&identity, &control_plane).await?;
            println!("attestation accepted");
            Ok(())
        }
        CommandName::AttestLease {
            identity,
            control_plane,
            lease_id,
            guest_channel_key_file,
        } => {
            let socket = dstack::socket()
                .context("no dstack guest agent socket: this is not a confidential VM")?;
            let pccs = std::env::var("PRISM_PCCS_URL")
                .unwrap_or_else(|_| prism_pccs::PHALA_PCCS_URL.to_owned());
            let guest_channel_key = fs::read_to_string(&guest_channel_key_file)
                .context("read the guest channel key file")?
                .trim()
                .to_owned();
            attestation::attest_lease_confidential(
                &identity,
                &control_plane,
                &socket,
                &pccs,
                lease_id,
                &guest_channel_key,
            )
            .await?;
            println!("lease attestation accepted");
            Ok(())
        }
        CommandName::Commands {
            identity,
            control_plane,
            workspace_root,
            state_root,
            ssh_port,
            jupyter_port,
            poll_seconds,
            agent_policy_digest,
            isolation,
            gpu_uuid,
            lease_memory_mib,
            lease_cpus,
            idle_config,
        } => {
            let request =
                isolation_request(isolation, None, gpu_uuid, lease_memory_mib, lease_cpus)?;
            command_loop(CommandLoopConfig {
                identity,
                control_plane,
                workspace_root,
                state_root,
                ssh_port,
                jupyter_port,
                poll_seconds,
                agent_policy_digest,
                isolation: IsolationSetting::resolve(request)?,
                idle_config,
            })
            .await
        }
        CommandName::IdleCheck {
            idle_config,
            gpu_uuid,
            idle_root,
            idle_state_root,
            state_root,
        } => {
            let gpu = gpu::select(gpu::discover()?, gpu_uuid.as_deref())?;
            idle::check(
                idle::load(&idle_config)?,
                idle_root,
                idle_state_root,
                state_root,
                gpu.uuid,
            )
        }
        CommandName::SnpReport {
            challenge_file,
            lease_id,
            channel_key_file,
            output_directory,
        } => snp::take_report(&snp::ReportRequest {
            challenge_file: &challenge_file,
            lease_id,
            channel_key_file: &channel_key_file,
            output_directory: &output_directory,
        }),
        CommandName::Tunnel {
            identity,
            gateway,
            server_name,
            ca_certificate,
            client_certificate,
            client_key,
            connection_id,
            ssh_target,
            jupyter_target,
            slots,
        } => {
            let identity = load_identity(&identity)?;
            tunnel::run(
                tunnel::TunnelConfig {
                    gateway,
                    server_name,
                    ca_certificate,
                    client_certificate,
                    client_key,
                    connection_id,
                    ssh_target,
                    jupyter_target,
                    slots,
                },
                signing_key(&identity)?,
            )
            .await
        }
        CommandName::Relay {
            gateway,
            server_name,
            ca_certificate,
            token,
            service,
            listen,
        } => {
            let service = match service {
                RelayServiceArg::Ssh => tunnel::RelayService::Ssh,
                RelayServiceArg::Jupyter => tunnel::RelayService::Jupyter,
            };
            tunnel::run_relay(tunnel::RelayConfig {
                gateway,
                server_name,
                ca_certificate,
                token,
                service,
                listen,
            })
            .await
        }
        CommandName::ValidateImage { image } => {
            runtime::validate_image_reference(&image)?;
            println!("valid");
            Ok(())
        }
        CommandName::Launch {
            image,
            lease_id,
            vfio_group,
            workspace_root,
            state_root,
            duration_seconds,
            ssh_authorized_key,
            jupyter_token,
            ssh_port,
            jupyter_port,
            isolation,
            gpu_uuid,
            lease_memory_mib,
            lease_cpus,
            execute,
        } => {
            let request = isolation_request(
                isolation,
                vfio_group,
                gpu_uuid,
                lease_memory_mib,
                lease_cpus,
            )?;
            let group = launch_vfio_group(&request)?;
            let setting = IsolationSetting::resolve(request)?;
            let isolation = match group {
                Some(group) => runtime::Isolation::KataVfio {
                    group: runtime::VfioGroup::from_system(group)?,
                },
                None => setting
                    .isolation()?
                    .context("no GPU on this host can serve a lease")?,
            };
            let config = runtime::LaunchConfig {
                image: &image,
                lease_id: &lease_id,
                workspace_root: &workspace_root,
                state_root: &state_root,
                isolation: &isolation,
                limits: setting.limits(),
                duration_seconds,
                ssh_authorized_key: &ssh_authorized_key,
                jupyter_token: &jupyter_token,
                ssh_port,
                jupyter_port,
                attestation_challenge: None,
                agent_policy_digest: None,
                released: None,
            };
            let control_directory = workspace_root.join(&lease_id);
            let command = match &isolation {
                runtime::Isolation::KataVfio { .. } => {
                    runtime::kata_command(&config, &control_directory)?
                }
                runtime::Isolation::Shared { .. } => {
                    runtime::shared_command(&config, &control_directory)?
                }
            };
            if execute {
                runtime::launch(config)
            } else {
                println!("{:?}", command);
                Ok(())
            }
        }
    }
}

fn preflight(isolation: IsolationArg) -> anyhow::Result<()> {
    let linux = cfg!(target_os = "linux");
    let architecture = env::consts::ARCH.to_owned();
    let nvidia_smi = command_success("nvidia-smi", &["-L"]);
    let containerd = command_success("ctr", &["version"]);
    let nerdctl = command_success("nerdctl", &["version"]);
    let capability = *host_capability();
    let kata_runtime = capability.kata_runtime;
    let iommu = iommu_available();
    let vfio = Path::new("/dev/vfio/vfio").exists() && Path::new("/sys/module/vfio_pci").exists();
    let nftables = command_success("nft", &["--version"]);
    let swap_disabled = swap_disabled();
    let nvidia_container_toolkit = command_success("nvidia-ctk", &["--version"]);
    let nvidia_container_cli = gpu::nvidia_container_cli_available();
    let workspace_ports_free = port_bindable(2_222) && port_bindable(8_888);
    let forward_chain_open = forward_chain_open();
    let vfio_gpu_groups = runtime::discover_vfio_gpu_groups()?;
    // A driver that answers with an error is reported as one. Reading it as a
    // machine with no cards would enrol a node that cannot serve anything.
    let (host_gpus, driver_error) = match gpu::discover() {
        Ok(gpus) => (gpus, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let gpu_devices = vfio_gpu_groups
        .iter()
        .flat_map(|group| &group.pci_devices)
        .filter_map(|address| {
            probe::pci_identity(address)
                .ok()
                .map(|(vendor, device)| PciIdentity {
                    address: address.clone(),
                    vendor_id: format!("{vendor:04x}"),
                    device_id: format!("{device:04x}"),
                })
        })
        .collect();
    let checks = PreflightChecks {
        linux,
        x86_64: architecture == "x86_64",
        containerd,
        nerdctl,
        kata_runtime,
        iommu,
        vfio,
        nftables,
        swap_disabled,
        nvidia_smi,
        nvidia_container_cli,
        workspace_ports_free,
        forward_chain_open,
        vfio_gpu_groups: vfio_gpu_groups.len(),
        host_gpus: host_gpus.len(),
    };
    let report = PreflightReport {
        supported: preflight_supported(isolation, &checks),
        isolation: match isolation {
            IsolationArg::KataVfio => "kata-vfio",
            IsolationArg::Shared => "shared",
        },
        architecture,
        linux,
        nvidia_smi,
        driver_version: gpu::driver_version(),
        containerd,
        nerdctl,
        kata_runtime,
        iommu,
        vfio,
        nftables,
        swap_disabled,
        nvidia_container_toolkit,
        nvidia_container_cli,
        workspace_ports_free,
        forward_chain_open,
        sev: capability.sev,
        sev_es: capability.sev_es,
        sev_snp: capability.sev_snp,
        sev_guest_device: capability.sev_guest_device,
        kata_confidential_runtime: capability.kata_confidential_runtime,
        vfio_gpu_groups,
        host_gpus,
        gpu_devices,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    match isolation {
        IsolationArg::KataVfio => report_passthrough_findings(&capability),
        IsolationArg::Shared => report_shared_findings(&report, driver_error.as_ref()),
    }
    if !report.supported {
        anyhow::bail!("host does not satisfy the GPU node baseline");
    }
    Ok(())
}

fn report_passthrough_findings(capability: &HostTeeCapability) {
    if capability.sev && !capability.sev_snp {
        eprintln!(
            "SEV is on but SEV-SNP is not exposed by this kernel; host SEV-SNP needs Linux 6.11 or newer, so this node can serve isolated but not attested"
        );
    }
    if capability.sev_snp && !capability.kata_confidential_runtime {
        eprintln!(
            "SEV-SNP is available but containerd has no {} shim, so a lease that needs a guest report cannot run here",
            probe::CONFIDENTIAL_RUNTIME
        );
    }
}

fn report_shared_findings(report: &PreflightReport, driver_error: Option<&anyhow::Error>) {
    if let Some(error) = driver_error {
        eprintln!("the NVIDIA driver did not answer: {error:#}");
    }
    if !report.nvidia_container_cli {
        eprintln!(
            "nvidia-container-cli is missing; install nvidia-container-toolkit, because that binary is what hands the card to a container"
        );
    }
    if report.host_gpus.is_empty() && !report.vfio_gpu_groups.is_empty() {
        eprintln!(
            "every GPU on this host is bound to vfio-pci, so the driver on this side has nothing to serve; unbind one or run with --isolation kata-vfio"
        );
    } else if !report.vfio_gpu_groups.is_empty() {
        eprintln!(
            "a GPU on this host is bound to vfio-pci and stays with whatever is using it; leases run on the cards the driver reports"
        );
    }
    if !report.workspace_ports_free {
        eprintln!(
            "127.0.0.1:2222 or 127.0.0.1:8888 is already in use; free both, because every lease publishes SSH and Jupyter on them"
        );
    }
    if !report.forward_chain_open {
        eprintln!(
            "the iptables FORWARD policy is DROP and nothing lets the container bridge through, so a lease would come up with no network; run `iptables -I FORWARD -i nerdctl0 -j ACCEPT` and `iptables -I FORWARD -o nerdctl0 -j ACCEPT`, and make them persist"
        );
    }
    if !report.swap_disabled {
        eprintln!(
            "swap is on; a lease that fills memory will page instead of failing, and the renter sees it as a slow card"
        );
    }
}

/// Every lease publishes SSH and Jupyter on these two loopback ports, so one
/// taken by something else is a permanent outage rather than a slow start.
fn port_bindable(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Docker sets the FORWARD policy to DROP and adds rules for its own bridge
/// only. Everything behind another bridge is then dropped, and a lease comes
/// up, reports itself ready and reaches nothing.
///
/// A host with no readable ruleset is left alone. Failing enrollment on a
/// question nobody could answer is worse than the outage this warns about.
fn forward_chain_open() -> bool {
    let Ok(output) = Command::new("iptables").args(["-S", "FORWARD"]).output() else {
        return true;
    };
    if !output.status.success() {
        return true;
    }
    let rules = String::from_utf8_lossy(&output.stdout);
    if !rules.lines().any(|line| line.trim() == "-P FORWARD DROP") {
        return true;
    }
    rules.lines().map(str::trim).any(|line| {
        line.starts_with("-A FORWARD")
            && (line == "-A FORWARD -j ACCEPT" || line.contains("nerdctl"))
    })
}

fn create_identity(path: PathBuf) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::bail!("refusing to overwrite an existing device identity");
    }
    let parent = path.parent().context("identity path has no parent")?;
    fs::create_dir_all(parent)?;
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let identity = DeviceIdentity {
        signing_key_hex: hex::encode(key.to_bytes()),
        telemetry_sequence: 0,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(serde_json::to_string(&identity)?.as_bytes())?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&path, serde_json::to_string(&identity)?)?;

    println!("{}", node_id(&key.verifying_key()));
    Ok(())
}

/// Post the bond that makes this device schedulable.
///
/// The registry will not accept an enrollment the operator has not signed, and
/// the control plane will not accept a node the registry has not bonded, so
/// this has to happen before `enroll`. It is the one step an operator cannot
/// perform from the daemon alone, which is why it lives here rather than in a
/// deployment script: a node operator should never have to install a
/// Solidity toolchain to join.
struct Registration {
    identity_path: PathBuf,
    rpc_url: String,
    registry: String,
    payout_wallet: Option<String>,
    rate_per_second: u128,
    operator_key: String,
    profile: String,
    dry_run: bool,
}

async fn register(request: Registration) -> anyhow::Result<()> {
    let Registration {
        identity_path,
        rpc_url,
        registry,
        payout_wallet,
        rate_per_second,
        operator_key,
        profile,
        dry_run,
    } = request;
    let (rpc_url, registry, operator_key, profile) = (&rpc_url, &registry, &operator_key, &profile);
    let payout_wallet = payout_wallet.as_deref();
    let identity_path = identity_path.as_path();

    if rate_per_second == 0 || rate_per_second > u128::from(u64::MAX) {
        anyhow::bail!("rate must be a positive number of USDG base units per second");
    }
    let identity = load_identity(identity_path)?;
    let device_key = signing_key(&identity)?;
    let node = node_id(&device_key.verifying_key());
    let node_word = bytes32(&node)?;

    let rpc = RpcClient::new(rpc_url)?;
    let signer = EthereumSigner::local(operator_key)?;
    let operator = signer.address();
    let payout = match payout_wallet {
        Some(value) => chain_address(value)?,
        None => operator,
    };
    let registry_address = chain_address(registry)?;
    let chain_id = rpc.chain_id().await?;

    let bond_token = read_address(&rpc, registry_address, &call_data("bondToken()", &[])).await?;
    let bond = read_u256(
        &rpc,
        registry_address,
        &call_data("requiredBond(uint128)", &[word_u128(rate_per_second)]),
    )
    .await?;

    let balance = read_u256(
        &rpc,
        bond_token,
        &call_data("balanceOf(address)", &[word_address(operator)]),
    )
    .await?;
    let shortfall = (balance < bond).then(|| {
        format!(
            "operator 0x{} holds {} PRISM and the bond for this rate is {} PRISM",
            hex::encode(operator),
            format_token(balance),
            format_token_required(bond)
        )
    });
    if let Some(shortfall) = &shortfall
        && !dry_run
    {
        anyhow::bail!("{shortfall}");
    }

    let allowance = read_u256(
        &rpc,
        bond_token,
        &call_data(
            "allowance(address,address)",
            &[word_address(operator), word_address(registry_address)],
        ),
    )
    .await?;
    if allowance < bond && !dry_run {
        println!(
            "approving {} PRISM for the registry",
            format_token_required(bond)
        );
        send(
            &rpc,
            &signer,
            bond_token,
            &call_data(
                "approve(address,uint256)",
                &[word_address(registry_address), word_u256(bond)],
            ),
            chain_id,
        )
        .await?;
    }

    let nonce = read_u256(
        &rpc,
        registry_address,
        &call_data("enrollmentNonces(address)", &[word_address(operator)]),
    )
    .await?;
    let head = rpc
        .quantity("eth_blockNumber", serde_json::json!([]))
        .await?;
    let deadline = u128::from(rpc.block_timestamp(head).await?) + REGISTRATION_WINDOW_SECONDS;
    let metadata = keccak(profile.as_bytes());

    // Ask the registry for the digest rather than rebuilding EIP-712 here. The
    // domain separator is bound to the deployed contract, so recomputing it
    // locally is a second place to get the migration wrong.
    let digest = read_word(
        &rpc,
        registry_address,
        &call_data(
            "enrollmentDigest(bytes32,bytes32,address,address,uint128,bytes32,uint256,uint256)",
            &[
                node_word,
                node_word,
                word_address(operator),
                word_address(payout),
                word_u128(rate_per_second),
                metadata,
                word_u256(nonce),
                word_u256(deadline),
            ],
        ),
    )
    .await?;
    let signature = signer.sign_digest(&digest).await?;
    let data = register_calldata(
        node_word,
        payout,
        rate_per_second,
        metadata,
        deadline,
        &signature,
    );

    if dry_run {
        let outcome = simulate(&rpc, operator, registry_address, &data).await;
        // The bond transfer is the last thing register() does, so it is also
        // the first thing to fail for an operator who has not funded or
        // approved yet. Neither says the registration is wrong: the real run
        // approves, and a shortfall is already reported below. Treat a
        // transfer failure as expected while either is outstanding, or the
        // dry run can never pass before the first approval.
        let expected = shortfall.is_some() || allowance < bond;
        if outcome.is_ok() || expected {
            // The node ID came from create-identity and the node is named by
            // --identity, so repeating 66 characters of it here only pushes
            // the number the operator came for off the edge of the terminal.
            println!(
                "registration is valid: would stake {} PRISM at {rate_per_second} USDG base units per second",
                format_token_required(bond)
            );
        }
        if let Some(shortfall) = shortfall {
            anyhow::bail!("{shortfall}");
        }
        if allowance < bond {
            println!("the registry is not approved to take the bond yet; the real run approves it");
        }
        return if expected { Ok(()) } else { outcome };
    }

    println!(
        "staking {} PRISM against {node}",
        format_token_required(bond)
    );
    let hash = send(&rpc, &signer, registry_address, &data, chain_id).await?;
    println!("{hash}");
    Ok(())
}

async fn enroll(
    identity_path: PathBuf,
    control_plane: String,
    operator_wallet: String,
    payout_wallet: String,
    gpu: GpuSpec,
    rate_per_second: u64,
    benchmark_score: u32,
) -> anyhow::Result<()> {
    let identity = load_identity(&identity_path)?;
    let signing_key = signing_key(&identity)?;
    let enrollment = NodeEnrollment::sign(
        UnsignedNodeEnrollment {
            node_id: node_id(&signing_key.verifying_key()),
            device_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            operator_wallet,
            payout_wallet,
            gpu,
            rate_per_second,
            benchmark_score,
            issued_at: Utc::now(),
        },
        &signing_key,
    )?;
    let endpoint = control_plane_endpoint(&control_plane, "v1/nodes/enroll")?;
    let response = http_client()?
        .post(endpoint)
        .json(&enrollment)
        .send()
        .await?;
    require_success(response).await?;
    Ok(())
}

async fn provision_certificate(
    identity_path: &Path,
    control_plane: &str,
    certificate_path: &Path,
    private_key_path: &Path,
    ca_certificate_path: &Path,
) -> anyhow::Result<()> {
    let identity = load_identity(identity_path)?;
    let device_key = signing_key(&identity)?;
    let node = node_id(&device_key.verifying_key());
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.remove(DnType::CommonName);
    params
        .distinguished_name
        .push(DnType::CommonName, node.clone());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr_pem = params.serialize_request(&key_pair)?.pem()?;
    let request = NodeCertificateRequest::sign(
        UnsignedNodeCertificateRequest {
            node_id: node.clone(),
            device_public_key: URL_SAFE_NO_PAD.encode(device_key.verifying_key().as_bytes()),
            request_id: uuid::Uuid::now_v7(),
            csr_pem,
            issued_at: Utc::now(),
        },
        &device_key,
    )?;
    let endpoint = control_plane_endpoint(control_plane, &format!("v1/nodes/{node}/certificates"))?;
    let response = http_client()?.post(endpoint).json(&request).send().await?;
    let status = response.status();
    if !status.is_success() {
        return require_success(response).await;
    }
    let bundle: NodeCertificateBundle = response
        .json()
        .await
        .context("decode certificate response")?;
    persist_certificate_file(private_key_path, key_pair.serialize_pem().as_bytes())?;
    persist_certificate_file(certificate_path, bundle.certificate_pem.as_bytes())?;
    persist_certificate_file(ca_certificate_path, bundle.ca_certificate_pem.as_bytes())?;
    println!(
        "{} {}",
        bundle.fingerprint_sha256,
        bundle.expires_at.to_rfc3339()
    );
    Ok(())
}

fn persist_certificate_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("certificate path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut suffix = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = path.with_extension(format!("tmp-{}", hex::encode(suffix)));
    write_private_file(&temporary, contents)?;
    let result = fs::rename(&temporary, path).context("persist certificate material");
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Reported under the device signature, so a node that overstates its
/// isolation has signed the claim the network would slash it for. A GPU bound
/// to vfio-pci says nothing about what the workload runs inside, so the kata
/// shim has to answer as well before this claims a sandbox.
///
/// Evidence never rides here. It goes on its own signed envelope, against a
/// challenge the control plane issued.
fn local_posture(capability: &HostTeeCapability) -> NodePosture {
    posture_for(
        runtime::discover_vfio_gpu_groups().is_ok_and(|groups| !groups.is_empty()),
        capability,
    )
}

fn posture_for(passthrough: bool, capability: &HostTeeCapability) -> NodePosture {
    let isolation = if passthrough && capability.kata_runtime {
        IsolationMode::KataVfio
    } else {
        IsolationMode::Shared
    };
    NodePosture {
        isolation,
        attestation: None,
    }
}

async fn attest_once(identity_path: &Path, control_plane: &str) -> anyhow::Result<()> {
    // A dstack CVM has no VFIO group to hand over and nothing to boot: the
    // TD itself is the evidence, and the guest agent is what can quote it.
    if let Some(socket) = dstack::socket() {
        let pccs = std::env::var("PRISM_PCCS_URL")
            .unwrap_or_else(|_| prism_pccs::PHALA_PCCS_URL.to_owned());
        return attestation::refresh_tdx(identity_path, control_plane, &socket, &pccs).await;
    }
    let groups = runtime::discover_vfio_gpu_groups()?;
    let group = groups
        .first()
        .context("no VFIO GPU group is available to attest")?;
    attestation::refresh(identity_path, control_plane, group).await
}

/// Attestation keeps its own clock. A report costs a guest boot, which is far
/// longer than a heartbeat, and a node that cannot produce one keeps serving at
/// whatever class the control plane last granted rather than dropping out.
async fn attestation_loop(identity_path: PathBuf, control_plane: String) {
    loop {
        match attest_once(&identity_path, &control_plane).await {
            Ok(()) => tracing::info!("posted GPU attestation"),
            Err(error) => tracing::warn!(%error, "GPU attestation failed; serving unchanged"),
        }
        tokio::time::sleep(ATTESTATION_INTERVAL).await;
    }
}

/// The probe spawns processes and none of what it reads changes without a
/// reboot, so a heartbeat every thirty seconds reuses the first answer.
fn host_capability() -> &'static HostTeeCapability {
    static CAPABILITY: std::sync::OnceLock<HostTeeCapability> = std::sync::OnceLock::new();
    CAPABILITY.get_or_init(probe::host_tee_capability)
}

#[allow(clippy::too_many_arguments)]
async fn publish_telemetry(
    identity_path: &Path,
    control_plane: &str,
    gpu_utilization_bps: u16,
    gpu_memory_used_mib: u32,
    tunnel_connected: bool,
    active_lease: Option<String>,
    image_digest: Option<String>,
    posture: NodePosture,
) -> anyhow::Result<()> {
    let mut identity = load_identity(identity_path)?;
    let signing_key = signing_key(&identity)?;
    let node_id = node_id(&signing_key.verifying_key());
    identity.telemetry_sequence = identity
        .telemetry_sequence
        .checked_add(1)
        .context("telemetry sequence exhausted")?;
    save_identity(identity_path, &identity)?;
    let telemetry = NodeTelemetry::sign(
        UnsignedTelemetry {
            node_id: node_id.clone(),
            sequence: identity.telemetry_sequence,
            observed_at: Utc::now(),
            gpu_utilization_bps,
            gpu_memory_used_mib,
            active_lease,
            tunnel_connected,
            image_digest,
            posture: Some(posture),
        },
        &signing_key,
    )?;
    let endpoint = control_plane_endpoint(control_plane, &format!("v1/nodes/{node_id}/heartbeat"))?;
    let response = http_client()?
        .post(endpoint)
        .json(&telemetry)
        .send()
        .await?;
    require_success(response).await?;
    Ok(())
}

struct CommandLoopConfig {
    identity: PathBuf,
    control_plane: String,
    workspace_root: PathBuf,
    state_root: PathBuf,
    ssh_port: u16,
    jupyter_port: u16,
    poll_seconds: u64,
    agent_policy_digest: Option<String>,
    isolation: IsolationSetting,
    idle_config: Option<PathBuf>,
}

async fn command_loop(config: CommandLoopConfig) -> anyhow::Result<()> {
    if config.poll_seconds == 0 || config.poll_seconds > 60 {
        anyhow::bail!("command poll interval must be between one and 60 seconds");
    }
    if config.ssh_port == 0 || config.jupyter_port == 0 || config.ssh_port == config.jupyter_port {
        anyhow::bail!("workspace access ports are invalid");
    }
    if config.isolation.shared_gpu().is_some() && config.agent_policy_digest.is_some() {
        anyhow::bail!(
            "--agent-policy-digest describes a confidential guest, which --isolation shared cannot start"
        );
    }
    let idle = start_idle_supervisor(&config)?;
    fs::create_dir_all(&config.workspace_root)?;
    fs::create_dir_all(&config.state_root)?;
    let identity = load_identity(&config.identity)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let client = http_client()?;
    let mut last_heartbeat = None;
    let capability = host_capability();
    tracing::info!(
        kata_runtime = capability.kata_runtime,
        sev = capability.sev,
        sev_es = capability.sev_es,
        sev_snp = capability.sev_snp,
        "host TEE capability"
    );
    // A shared lease runs on the host's own kernel, so there is nothing here
    // that could take a report and no reason to keep asking for a verdict.
    // The exception is a dstack CVM: it serves in shared mode because the TD
    // is the boundary, and the TD itself is what attests.
    if config.isolation.shared_gpu().is_none() || dstack::socket().is_some() {
        tokio::spawn(attestation_loop(
            config.identity.clone(),
            config.control_plane.clone(),
        ));
    }

    loop {
        // Ahead of the poll, because the workload the operator configured has
        // to keep running through a control plane this node cannot reach.
        if let Some(idle) = &idle {
            idle.tick().await;
        }
        let command =
            match poll_command(&client, &config.control_plane, &node, &public_key, &key).await {
                Ok(command) => command,
                Err(error) => {
                    tracing::warn!(%error, "node command poll failed; retrying");
                    tokio::time::sleep(Duration::from_secs(config.poll_seconds)).await;
                    continue;
                }
            };
        if let Some(command) = command {
            if let Err(error) = execute_node_command(
                &client,
                &config,
                idle.as_ref(),
                &node,
                &public_key,
                &key,
                command,
            )
            .await
            {
                tracing::error!(%error, "node command execution failed");
                tokio::time::sleep(Duration::from_secs(config.poll_seconds)).await;
            }
            continue;
        }
        // A quarantined node stops publishing so the offer ages out of
        // matching. Failing a fresh lease every few seconds until someone
        // notices is worse than dropping off the list.
        let publishing = idle.as_ref().is_none_or(|idle| !idle.quarantined());
        if publishing
            && last_heartbeat.is_none_or(|last: chrono::DateTime<Utc>| {
                Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(30)
            })
        {
            let usage = idle_gpu_usage(&config.isolation);
            if let Err(error) = publish_telemetry(
                &config.identity,
                &config.control_plane,
                usage.utilization_bps,
                usage.memory_used_mib,
                true,
                None,
                None,
                config.isolation.posture(capability),
            )
            .await
            {
                tracing::warn!(%error, "idle node telemetry failed");
            } else {
                last_heartbeat = Some(Utc::now());
            }
        }
        tokio::time::sleep(Duration::from_secs(config.poll_seconds)).await;
    }
}

/// What the card is doing while nobody is renting it. During a lease this stays
/// at zero: the workload belongs to the renter and its shape is not ours to
/// report.
fn idle_gpu_usage(isolation: &IsolationSetting) -> gpu::Usage {
    let idle = gpu::Usage {
        utilization_bps: 0,
        memory_used_mib: 0,
    };
    let Some(host_gpu) = isolation.shared_gpu() else {
        return idle;
    };
    gpu::usage(&host_gpu.uuid).unwrap_or_else(|error| {
        tracing::debug!(%error, "could not read GPU utilization");
        idle
    })
}

fn start_idle_supervisor(config: &CommandLoopConfig) -> anyhow::Result<Option<idle::Idle>> {
    let Some(path) = &config.idle_config else {
        return Ok(None);
    };
    let Some(gpu) = config.isolation.shared_gpu() else {
        anyhow::bail!(
            "an idle workload needs a GPU the host can use, and under --isolation kata-vfio the card is bound to vfio-pci"
        );
    };
    let workload = idle::load(path)?;
    let root = config
        .state_root
        .parent()
        .unwrap_or(Path::new("/var/lib/prismd"));
    Ok(Some(idle::Idle::new(
        workload,
        root.join("idle"),
        root.join("idle-state"),
        config.state_root.clone(),
        gpu.uuid.clone(),
    )?))
}

/// Take the card back before the lease starts.
///
/// Returns the message to fail the command with when the machine could not
/// hand it over. Launching anyway would sell a renter a card somebody else is
/// still computing on.
async fn release_gpu_for_lease(idle: Option<&idle::Idle>) -> Option<String> {
    let idle = idle?;
    match idle.stop_for_lease().await {
        Ok(release) => {
            tracing::info!(
                exit_ms = release.exit_ms,
                free_ms = release.free_ms,
                forced = release.forced,
                "handed the GPU to the lease"
            );
            None
        }
        Err(error) => Some(format!("{error:#}")),
    }
}

async fn poll_command(
    client: &reqwest::Client,
    control_plane: &str,
    node: &str,
    public_key: &str,
    key: &SigningKey,
) -> anyhow::Result<Option<NodeCommand>> {
    let poll = NodeCommandPoll::sign(
        node.to_owned(),
        public_key.to_owned(),
        uuid::Uuid::now_v7(),
        Utc::now(),
        key,
    )?;
    let endpoint =
        control_plane_endpoint(control_plane, &format!("v1/nodes/{node}/commands/next"))?;
    let response = client.post(endpoint).json(&poll).send().await?;
    let status = response.status();
    if !status.is_success() {
        return require_success(response).await.map(|()| None);
    }
    response
        .json::<Option<NodeCommand>>()
        .await
        .context("decode node command")
}

#[allow(clippy::too_many_arguments)]
async fn execute_node_command(
    client: &reqwest::Client,
    config: &CommandLoopConfig,
    idle: Option<&idle::Idle>,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command: NodeCommand,
) -> anyhow::Result<()> {
    if command.node_id != node || command.expires_at <= Utc::now() {
        report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some("command identity is invalid or expired".to_owned()),
            None,
            None,
        )
        .await?;
        return Ok(());
    }
    if let NodeCommandKind::Batch {
        image,
        command: program,
        duration_seconds,
    } = &command.kind
    {
        return run_batch_command(
            client,
            config,
            idle,
            node,
            public_key,
            key,
            &command,
            image,
            program,
            *duration_seconds,
        )
        .await;
    }
    let NodeCommandKind::Launch {
        image,
        duration_seconds,
        ssh_authorized_key,
        jupyter_token,
    } = command.kind
    else {
        report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some("stop commands require an active runtime supervisor".to_owned()),
            None,
            None,
        )
        .await?;
        return Ok(());
    };
    let image_digest = image
        .rsplit_once('@')
        .map(|(_, digest)| digest.to_owned())
        .context("launch image has no immutable digest")?;
    let Some(isolation) = config.isolation.isolation()? else {
        report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some("no schedulable VFIO GPU group is available".to_owned()),
            None,
            None,
        )
        .await?;
        return Ok(());
    };
    let credential_root = config
        .state_root
        .join(format!(".credentials-{}", command.command_id));
    // The control plane redelivers a command whose lease expired, and it keeps
    // the same id, so this directory can outlive the process that made it. Its
    // contents come from the command being handled right now, which makes
    // clearing it safe and leaving it fatal: a plain create fails with
    // `AlreadyExists` on every retry, and the lease that owns the command can
    // never run again.
    if credential_root.exists() {
        fs::remove_dir_all(&credential_root).context("clear stale lease credentials")?;
    }
    fs::create_dir(&credential_root)?;
    let ssh_key_path = credential_root.join("authorized_keys");
    let jupyter_token_path = credential_root.join("jupyter_token");
    write_private_file(
        &ssh_key_path,
        format!("{}\n", ssh_authorized_key.trim()).as_bytes(),
    )?;
    write_private_file(
        &jupyter_token_path,
        format!("{}\n", jupyter_token.trim()).as_bytes(),
    )?;

    // Whether this node serves confidential guests is the operator's declared
    // configuration, not something inferred per lease: a host with no policy
    // digest installed runs the ordinary runtime and earns no verdict, which
    // costs the renter nothing they were promised. Once the node has declared
    // it, a challenge it cannot fetch fails the command, because launching
    // anyway spends the lease on a session no report will ever cover.
    let challenge = match &config.agent_policy_digest {
        None => None,
        Some(_) => {
            match snp::lease_challenge(&config.control_plane, command.lease_id, node).await {
                Ok(challenge) => Some(challenge),
                Err(error) => {
                    let message = format!("lease attestation challenge unavailable: {error:#}");
                    report_command(
                        client,
                        &config.control_plane,
                        node,
                        public_key,
                        key,
                        command.command_id,
                        NodeCommandOutcome::Failed,
                        Some(message.chars().take(512).collect()),
                        None,
                        None,
                    )
                    .await?;
                    let _ = fs::remove_dir_all(&credential_root);
                    return Ok(());
                }
            }
        }
    };
    let evidence = snp::evidence_directory(&runtime::workspace_path(
        &config.workspace_root,
        &command.lease_id.to_string(),
    )?);

    let lease_id = command.lease_id.to_string();
    if let Some(reason) = release_gpu_for_lease(idle).await {
        report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some(reason.chars().take(512).collect()),
            None,
            None,
        )
        .await?;
        let _ = fs::remove_dir_all(&credential_root);
        return Ok(());
    }
    let workspace_root = config.workspace_root.clone();
    let state_root = config.state_root.clone();
    let ssh_port = config.ssh_port;
    let jupyter_port = config.jupyter_port;
    let limits = config.isolation.limits();
    let launch_lease_id = lease_id.clone();
    let launch_ssh_key = ssh_key_path.clone();
    let launch_jupyter_token = jupyter_token_path.clone();
    let launch_challenge = challenge.as_ref().map(|challenge| challenge.nonce.clone());
    let launch_policy_digest = config.agent_policy_digest.clone();
    let released = Arc::new(AtomicBool::new(false));
    let launch_released = released.clone();
    let mut task = tokio::task::spawn_blocking(move || {
        runtime::launch(runtime::LaunchConfig {
            image: &image,
            lease_id: &launch_lease_id,
            workspace_root: &workspace_root,
            state_root: &state_root,
            isolation: &isolation,
            limits,
            duration_seconds,
            ssh_authorized_key: &launch_ssh_key,
            jupyter_token: &launch_jupyter_token,
            ssh_port,
            jupyter_port,
            attestation_challenge: launch_challenge.as_deref(),
            agent_policy_digest: launch_policy_digest.as_deref(),
            released: Some(&launch_released),
        })
    });
    let mut ready_reported_at = None;
    let mut telemetry_reported_at = None;
    let mut attestation_attempted_at = None;
    while !task.is_finished() {
        if let Some(challenge) = &challenge
            && snp::report_ready(&evidence)
            && attestation_attempted_at.is_none_or(|last: chrono::DateTime<Utc>| {
                Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(10)
            })
        {
            attestation_attempted_at = Some(Utc::now());
            match snp::forward(
                &config.identity,
                &config.control_plane,
                command.lease_id,
                challenge.challenge_id,
                &evidence,
            )
            .await
            {
                Ok(()) => tracing::info!(lease_id = %lease_id, "forwarded the guest attestation"),
                Err(error) => {
                    tracing::warn!(%error, lease_id = %lease_id, "guest attestation forwarding failed; retrying")
                }
            }
        }
        let ready = runtime::lease_phase(&config.state_root, &lease_id)?
            == Some(runtime::LeasePhase::Ready);
        if ready
            && telemetry_reported_at.is_none_or(|last: chrono::DateTime<Utc>| {
                Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(30)
            })
        {
            publish_telemetry(
                &config.identity,
                &config.control_plane,
                0,
                0,
                true,
                Some(lease_id.clone()),
                Some(image_digest.clone()),
                config.isolation.posture(host_capability()),
            )
            .await?;
            telemetry_reported_at = Some(Utc::now());
        }
        if ready
            && ready_reported_at.is_none_or(|last: chrono::DateTime<Utc>| {
                Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(30)
            })
        {
            let ack = report_command_acked(
                client,
                &config.control_plane,
                node,
                public_key,
                key,
                command.command_id,
                NodeCommandOutcome::Ready,
                None,
                None,
                runtime::channel_key(&config.workspace_root, &lease_id),
            )
            .await?;
            ready_reported_at = Some(Utc::now());
            if note_release(&ack, &released) {
                tracing::info!(lease_id = %lease_id, state = ?ack.lease_state, "lease ended early; stopping the workload");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let result = (&mut task).await.context("workspace runtime task failed")?;
    if ready_reported_at.is_some() {
        publish_telemetry(
            &config.identity,
            &config.control_plane,
            0,
            0,
            true,
            Some(lease_id.clone()),
            Some(image_digest),
            config.isolation.posture(host_capability()),
        )
        .await?;
    }
    let _ = fs::remove_dir_all(&credential_root);
    let (outcome, error) = match result {
        Ok(()) => (NodeCommandOutcome::Completed, None),
        Err(error) => {
            let message = error.to_string().chars().take(512).collect();
            (NodeCommandOutcome::Failed, Some(message))
        }
    };
    report_command(
        client,
        &config.control_plane,
        node,
        public_key,
        key,
        command.command_id,
        outcome,
        error,
        None,
        None,
    )
    .await
}

/// A batch command occupies the GPU exactly like a lease does, so it takes the
/// same card and reports through the same signed channel. The difference is
/// what comes back: what the command printed, rather than a way in.
#[allow(clippy::too_many_arguments)]
async fn run_batch_command(
    client: &reqwest::Client,
    config: &CommandLoopConfig,
    idle: Option<&idle::Idle>,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command: &NodeCommand,
    image: &str,
    program: &str,
    duration_seconds: u32,
) -> anyhow::Result<()> {
    let Some(isolation) = config.isolation.isolation()? else {
        return report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some("no schedulable VFIO GPU group is available".to_owned()),
            None,
            None,
        )
        .await;
    };
    let lease_id = command.lease_id.to_string();
    let workspace_root = config.workspace_root.clone();
    let state_root = config.state_root.clone();
    let limits = config.isolation.limits();
    let preflight_isolation = isolation.clone();
    let preflight_image = image.to_owned();
    let preflight_program = program.to_owned();
    let preflight_lease_id = lease_id.clone();
    let preflight = tokio::task::spawn_blocking(move || {
        runtime::preflight_batch(&runtime::BatchConfig {
            image: &preflight_image,
            lease_id: &preflight_lease_id,
            command: &preflight_program,
            workspace_root: &workspace_root,
            state_root: &state_root,
            isolation: &preflight_isolation,
            limits,
            duration_seconds,
        })
    })
    .await?;
    if let Err(error) = preflight {
        return report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some(format!("{error:#}").chars().take(512).collect()),
            None,
            None,
        )
        .await;
    }
    report_command(
        client,
        &config.control_plane,
        node,
        public_key,
        key,
        command.command_id,
        NodeCommandOutcome::Ready,
        None,
        None,
        None,
    )
    .await?;
    match wait_for_batch_authorization(
        client,
        &config.control_plane,
        config.poll_seconds,
        node,
        public_key,
        key,
        command.command_id,
    )
    .await?
    {
        BatchAuthorization::Authorized => {}
        BatchAuthorization::ClaimedElsewhere => return Ok(()),
        BatchAuthorization::TimedOut => {
            return report_command(
                client,
                &config.control_plane,
                node,
                public_key,
                key,
                command.command_id,
                NodeCommandOutcome::Failed,
                Some("lease did not become active before the authorization deadline".to_owned()),
                None,
                None,
            )
            .await;
        }
    }
    if let Some(reason) = release_gpu_for_lease(idle).await {
        return report_command(
            client,
            &config.control_plane,
            node,
            public_key,
            key,
            command.command_id,
            NodeCommandOutcome::Failed,
            Some(reason.chars().take(512).collect()),
            None,
            None,
        )
        .await;
    }

    let workspace_root = config.workspace_root.clone();
    let state_root = config.state_root.clone();
    let limits = config.isolation.limits();
    let image = image.to_owned();
    let program = program.to_owned();
    let outcome = tokio::task::spawn_blocking(move || {
        runtime::run_batch(runtime::BatchConfig {
            image: &image,
            lease_id: &lease_id,
            command: &program,
            workspace_root: &workspace_root,
            state_root: &state_root,
            isolation: &isolation,
            limits,
            duration_seconds,
        })
    })
    .await?;

    match outcome {
        Ok(result) => {
            report_command(
                client,
                &config.control_plane,
                node,
                public_key,
                key,
                command.command_id,
                NodeCommandOutcome::Completed,
                None,
                Some(result),
                None,
            )
            .await
        }
        Err(error) => {
            report_command(
                client,
                &config.control_plane,
                node,
                public_key,
                key,
                command.command_id,
                NodeCommandOutcome::Failed,
                Some(format!("{error:#}").chars().take(512).collect()),
                None,
                None,
            )
            .await
        }
    }
}

enum BatchAuthorization {
    Authorized,
    ClaimedElsewhere,
    TimedOut,
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_batch_authorization(
    client: &reqwest::Client,
    control_plane: &str,
    poll_seconds: u64,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command_id: uuid::Uuid,
) -> anyhow::Result<BatchAuthorization> {
    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/nodes/{node}/commands/{command_id}/authorize"),
    )?;
    let deadline = tokio::time::Instant::now() + BATCH_AUTHORIZATION_TIMEOUT;
    'poll: while tokio::time::Instant::now() < deadline {
        let poll = NodeCommandPoll::sign(
            node.to_owned(),
            public_key.to_owned(),
            uuid::Uuid::now_v7(),
            Utc::now(),
            key,
        )?;
        loop {
            let result = match client.post(endpoint.clone()).json(&poll).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        response
                            .json::<bool>()
                            .await
                            .context("decode batch authorization")
                            .map(|authorized| authorized.then_some(BatchAuthorization::Authorized))
                    } else if matches!(
                        status,
                        reqwest::StatusCode::CONFLICT | reqwest::StatusCode::NOT_FOUND
                    ) {
                        Ok(Some(BatchAuthorization::ClaimedElsewhere))
                    } else {
                        require_success(response).await.map(|()| None)
                    }
                }
                Err(error) => Err(error.into()),
            };
            match result {
                Ok(Some(authorization)) => return Ok(authorization),
                Ok(None) => {
                    tokio::time::sleep(Duration::from_secs(poll_seconds)).await;
                    continue 'poll;
                }
                Err(error) => {
                    tracing::warn!(%command_id, %error, "batch authorization poll failed; retrying the same execution claim");
                    if tokio::time::Instant::now() >= deadline {
                        return Ok(BatchAuthorization::TimedOut);
                    }
                    tokio::time::sleep(Duration::from_secs(poll_seconds)).await;
                }
            }
        }
    }
    Ok(BatchAuthorization::TimedOut)
}

#[allow(clippy::too_many_arguments)]
async fn report_command(
    client: &reqwest::Client,
    control_plane: &str,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command_id: uuid::Uuid,
    outcome: NodeCommandOutcome,
    error: Option<String>,
    result: Option<CommandResult>,
    channel_key: Option<String>,
) -> anyhow::Result<()> {
    report_command_acked(
        client,
        control_plane,
        node,
        public_key,
        key,
        command_id,
        outcome,
        error,
        result,
        channel_key,
    )
    .await
    .map(drop)
}

/// Reports and returns what the control plane said back, which only the ready
/// loop reads: it is where an early release reaches the node.
#[allow(clippy::too_many_arguments)]
async fn report_command_acked(
    client: &reqwest::Client,
    control_plane: &str,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command_id: uuid::Uuid,
    outcome: NodeCommandOutcome,
    error: Option<String>,
    result: Option<CommandResult>,
    channel_key: Option<String>,
) -> anyhow::Result<NodeCommandReportAck> {
    let endpoint = control_plane_endpoint(
        control_plane,
        &format!("v1/nodes/{node}/commands/{command_id}/report"),
    )?;
    let mut delay = 1;
    loop {
        let report = NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: node.to_owned(),
                device_public_key: public_key.to_owned(),
                request_id: uuid::Uuid::now_v7(),
                command_id,
                outcome: outcome.clone(),
                observed_at: Utc::now(),
                error: error.clone(),
                result: result.clone(),
                channel_key: channel_key.clone(),
            },
            key,
        )?;
        let result = match client.post(endpoint.clone()).json(&report).send().await {
            Ok(response) => report_ack(response).await,
            Err(error) => Err(error.into()),
        };
        match result {
            Ok(ack) => return Ok(ack),
            Err(error) => {
                tracing::warn!(%command_id, %error, "node command report failed; retrying");
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(30);
            }
        }
    }
}

/// `register` is the only call here with a dynamic argument, so it is the only
/// one where a hand-rolled encoding can be wrong in a way that still submits.
fn register_calldata(
    node: [u8; 32],
    payout: [u8; 20],
    rate_per_second: u128,
    metadata: [u8; 32],
    deadline: u128,
    signature: &[u8; 65],
) -> Vec<u8> {
    let mut data = call_data(
        "register(bytes32,bytes32,address,uint128,bytes32,uint256,bytes)",
        &[
            node,
            node,
            word_address(payout),
            word_u128(rate_per_second),
            metadata,
            word_u256(deadline),
            word_u256(SIGNATURE_OFFSET),
        ],
    );
    data.extend_from_slice(&word_u256(signature.len() as u128));
    data.extend_from_slice(signature);
    data.extend_from_slice(&[0_u8; 32 - (65 % 32)]);
    data
}

fn call_data(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut data = selector(signature).to_vec();
    for word in words {
        data.extend_from_slice(word);
    }
    data
}

async fn read_word(rpc: &RpcClient, to: [u8; 20], data: &[u8]) -> anyhow::Result<[u8; 32]> {
    let result: String = rpc
        .call(
            "eth_call",
            serde_json::json!([{
                "to": format!("0x{}", hex::encode(to)),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )
        .await?;
    let bytes = hex::decode(
        result
            .strip_prefix("0x")
            .context("call result is not hex")?,
    )?;
    bytes
        .get(..32)
        .context("call returned fewer than 32 bytes")?
        .try_into()
        .map_err(Into::into)
}

/// Run the call without submitting it. The registry checks the operator
/// signature before it moves any tokens, so a revert here separates a
/// registration that is wrong from one that is merely unfunded.
async fn simulate(
    rpc: &RpcClient,
    from: [u8; 20],
    to: [u8; 20],
    data: &[u8],
) -> anyhow::Result<()> {
    let result: anyhow::Result<String> = rpc
        .call(
            "eth_call",
            serde_json::json!([{
                "from": format!("0x{}", hex::encode(from)),
                "to": format!("0x{}", hex::encode(to)),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) => {
            let message = error.to_string();
            for (selector, reason) in REGISTRY_REVERTS {
                if message.contains(selector) {
                    anyhow::bail!("{reason}");
                }
            }
            Err(error)
        }
    }
}

async fn read_u256(rpc: &RpcClient, to: [u8; 20], data: &[u8]) -> anyhow::Result<u128> {
    let word = read_word(rpc, to, data).await?;
    if word[..16].iter().any(|byte| *byte != 0) {
        anyhow::bail!("chain returned a value larger than this tool can represent");
    }
    Ok(u128::from_be_bytes(word[16..].try_into()?))
}

async fn read_address(rpc: &RpcClient, to: [u8; 20], data: &[u8]) -> anyhow::Result<[u8; 20]> {
    let word = read_word(rpc, to, data).await?;
    word[12..].try_into().map_err(Into::into)
}

async fn send(
    rpc: &RpcClient,
    signer: &EthereumSigner,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
) -> anyhow::Result<String> {
    let transaction = rpc.prepare_transaction(signer, to, data, chain_id).await?;
    rpc.submit(&transaction).await?;
    for _ in 0..CONFIRMATION_ATTEMPTS {
        match rpc.finality(&transaction.transaction_hash, 1).await? {
            Finality::Confirmed { .. } => return Ok(transaction.transaction_hash),
            Finality::Reverted { .. } => {
                anyhow::bail!("{} reverted on chain", transaction.transaction_hash)
            }
            Finality::Pending => tokio::time::sleep(Duration::from_secs(3)).await,
        }
    }
    anyhow::bail!(
        "{} did not confirm in time; check it before retrying so the bond is not posted twice",
        transaction.transaction_hash
    )
}

fn bytes32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{value} is not 32 bytes"))
}

fn word_address(value: [u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&value);
    word
}

fn word_u256(value: u128) -> [u8; 32] {
    word_u128(value)
}

fn keccak(value: &[u8]) -> [u8; 32] {
    Keccak256::digest(value).into()
}

/// Whole tokens with the fractional part trimmed, for messages an operator
/// reads. Never use this to decide anything.
fn format_token(value: u128) -> String {
    let whole = value / 10_u128.pow(18);
    let fraction = (value % 10_u128.pow(18)) / 10_u128.pow(14);
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{fraction:04}")
    }
}

/// Same, rounded up. A required amount displayed with its remainder trimmed is
/// a figure that does not actually cover the requirement, and the operator
/// finds out by having the transaction revert.
fn format_token_required(value: u128) -> String {
    let unit = 10_u128.pow(14);
    format_token(value.div_ceil(unit).saturating_mul(unit))
}

fn write_private_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    Ok(())
}

fn load_identity(path: &Path) -> anyhow::Result<DeviceIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("device identity permissions must not grant group or other access");
        }
    }
    serde_json::from_slice(&fs::read(path)?).context("read device identity")
}

fn signing_key(identity: &DeviceIdentity) -> anyhow::Result<SigningKey> {
    let secret: [u8; 32] = hex::decode(&identity.signing_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid device identity"))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn save_identity(path: &Path, identity: &DeviceIdentity) -> anyhow::Result<()> {
    let mut suffix = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = path.with_extension(format!("tmp-{}", hex::encode(suffix)));
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?
    };
    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result = file
        .write_all(&serde_json::to_vec(identity)?)
        .and_then(|()| file.sync_all())
        .context("write device identity")
        .and_then(|()| keep_owner(path, &temporary))
        .and_then(|()| fs::rename(&temporary, path).context("persist device identity"));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// The identity is shared by services that do not run as the same user: the
/// command supervisor needs root to drive containerd, while the tunnel and the
/// certificate renewal drop to `prismd`. Every one of them bumps a sequence and
/// rewrites the file, and a rename hands the replacement whichever owner did the
/// writing. Root writing it once is enough to lock `prismd` out of its own
/// identity, which takes the node off the network until someone chowns it back.
#[cfg(unix)]
fn keep_owner(path: &Path, temporary: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let Ok(existing) = fs::metadata(path) else {
        return Ok(());
    };
    std::os::unix::fs::chown(temporary, Some(existing.uid()), Some(existing.gid()))
        .context("preserve device identity ownership")
}

#[cfg(not(unix))]
fn keep_owner(_path: &Path, _temporary: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn command_success(command: &str, arguments: &[&str]) -> bool {
    Command::new(command)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn iommu_available() -> bool {
    fs::read_dir("/sys/kernel/iommu_groups").is_ok_and(|mut entries| entries.next().is_some())
}

fn swap_disabled() -> bool {
    fs::read_to_string("/proc/swaps")
        .is_ok_and(|contents| contents.lines().skip(1).all(|line| line.trim().is_empty()))
}

fn control_plane_endpoint(base: &str, path: &str) -> anyhow::Result<url::Url> {
    let mut base = url::Url::parse(base).context("control-plane URL is invalid")?;
    if base.username() != ""
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        anyhow::bail!("control-plane URL must not contain credentials, a query or a fragment");
    }
    let local_http = base.scheme() == "http"
        && base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if base.scheme() != "https" && !local_http {
        anyhow::bail!("control-plane URL must use HTTPS outside localhost");
    }
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join(path).context("build control-plane endpoint")
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("prismd/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build control-plane client")
}

/// A released lease is closing or already settled. Anything that can still open
/// access is a lease the node keeps serving.
fn lease_ended_early(state: Option<&LeaseState>) -> bool {
    state.is_some_and(|state| !state.can_still_open_access())
}

/// Records what the control plane said about the lease under a running command.
/// True for the answer that ends the workload, so it is logged once.
fn note_release(ack: &NodeCommandReportAck, released: &AtomicBool) -> bool {
    lease_ended_early(ack.lease_state.as_ref()) && !released.swap(true, Ordering::AcqRel)
}

async fn report_ack(response: reqwest::Response) -> anyhow::Result<NodeCommandReportAck> {
    let status = response.status();
    let body = response.bytes().await?;
    decode_ack(status, &body)
}

/// A control plane from before the acknowledgement answers with no body, which
/// reads as "nothing to say" rather than as a failed report.
fn decode_ack(status: reqwest::StatusCode, body: &[u8]) -> anyhow::Result<NodeCommandReportAck> {
    if !status.is_success() {
        let message: String = String::from_utf8_lossy(body).chars().take(512).collect();
        anyhow::bail!("control plane returned {status}: {message}")
    }
    if body.is_empty() {
        return Ok(NodeCommandReportAck::default());
    }
    serde_json::from_slice(body).context("decode command report acknowledgement")
}

async fn require_success(response: reqwest::Response) -> anyhow::Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let message = response.text().await.unwrap_or_default();
    let message: String = message.chars().take(512).collect();
    anyhow::bail!("control plane returned {status}: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_past_active_ends_the_workload_and_nothing_else_does() {
        for state in [
            LeaseState::Closing,
            LeaseState::SettlementPending,
            LeaseState::Finalized,
            LeaseState::Refunded,
            LeaseState::Failed,
        ] {
            assert!(lease_ended_early(Some(&state)), "{state:?}");
        }
        for state in [
            LeaseState::Funded,
            LeaseState::Provisioning,
            LeaseState::Ready,
            LeaseState::Active,
        ] {
            assert!(!lease_ended_early(Some(&state)), "{state:?}");
        }
        assert!(
            !lease_ended_early(None),
            "an older control plane says nothing"
        );
    }

    /// The acknowledgement to a ready report is how a renter's release reaches
    /// the node. Missing it holds the GPU for the rest of a window nobody is
    /// billed for.
    #[test]
    fn a_release_reaches_the_running_workload_once() {
        let released = AtomicBool::new(false);
        let ack = NodeCommandReportAck {
            lease_state: Some(LeaseState::Active),
        };
        assert!(!note_release(&ack, &released));
        assert!(!released.load(Ordering::Acquire));

        assert!(!note_release(&NodeCommandReportAck::default(), &released));
        assert!(!released.load(Ordering::Acquire));

        let ack = NodeCommandReportAck {
            lease_state: Some(LeaseState::Closing),
        };
        assert!(note_release(&ack, &released));
        assert!(released.load(Ordering::Acquire));
        assert!(!note_release(&ack, &released), "logged once");
        assert!(released.load(Ordering::Acquire));
    }

    #[test]
    fn a_report_answered_with_nothing_is_still_a_report() {
        assert_eq!(
            decode_ack(reqwest::StatusCode::NO_CONTENT, b"").unwrap(),
            NodeCommandReportAck::default()
        );
        assert_eq!(
            decode_ack(reqwest::StatusCode::OK, br#"{"lease_state":"closing"}"#).unwrap(),
            NodeCommandReportAck {
                lease_state: Some(LeaseState::Closing),
            }
        );
        assert!(decode_ack(reqwest::StatusCode::NOT_FOUND, b"unknown command").is_err());
        assert!(decode_ack(reqwest::StatusCode::OK, b"not json").is_err());
    }

    /// Fixture from `cast calldata "register(bytes32,bytes32,address,uint128,
    /// bytes32,uint256,bytes)" …`. A dynamic argument encoded with the wrong
    /// offset or padding still forms a submittable transaction, so the bond
    /// would be spent on a revert.
    #[test]
    fn register_calldata_matches_the_abi() {
        let encoded = register_calldata(
            [0x11; 32],
            [0x22; 20],
            222,
            keccak(b"prism.node.v1"),
            1_786_000_000,
            &[0xab; 65],
        );
        assert_eq!(
            hex::encode(encoded),
            concat!(
                "72823952",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "0000000000000000000000002222222222222222222222222222222222222222",
                "00000000000000000000000000000000000000000000000000000000000000de",
                "bb5d358fded812560c14b46b7578c469283069d2892aecc7fd5680b29557255f",
                "000000000000000000000000000000000000000000000000000000006a743280",
                "00000000000000000000000000000000000000000000000000000000000000e0",
                "0000000000000000000000000000000000000000000000000000000000000041",
                "abababababababababababababababababababababababababababababababab",
                "abababababababababababababababababababababababababababababababab",
                "ab000000000000000000000000000000000000000000000000000000000000",
                "00",
            )
        );
    }

    /// A vfio-bound GPU with no kata shim is a bare host with a passed-through
    /// card. Signing KataVfio for it is the claim this whole path exists to
    /// stop making.
    #[test]
    fn posture_needs_the_kata_shim_and_not_only_a_bound_gpu() {
        let without_kata = HostTeeCapability {
            kata_runtime: false,
            ..HostTeeCapability::default()
        };
        let with_kata = HostTeeCapability {
            kata_runtime: true,
            ..HostTeeCapability::default()
        };

        assert_eq!(
            posture_for(true, &without_kata).isolation,
            IsolationMode::Shared
        );
        assert_eq!(
            posture_for(false, &with_kata).isolation,
            IsolationMode::Shared
        );
        let isolated = posture_for(true, &with_kata);
        assert_eq!(isolated.isolation, IsolationMode::KataVfio);
        assert!(isolated.attestation.is_none());
    }

    fn every_check_passing() -> PreflightChecks {
        PreflightChecks {
            linux: true,
            x86_64: true,
            containerd: true,
            nerdctl: true,
            kata_runtime: true,
            iommu: true,
            vfio: true,
            nftables: true,
            swap_disabled: true,
            nvidia_smi: true,
            nvidia_container_cli: true,
            workspace_ports_free: true,
            forward_chain_open: true,
            vfio_gpu_groups: 1,
            host_gpus: 1,
        }
    }

    /// The passthrough baseline is what it was. The shared one asks for a
    /// driver, the binary that hands a card to a container, and two loopback
    /// ports nothing else has taken, and it asks for none of the passthrough
    /// machinery.
    #[test]
    fn each_mode_asks_the_host_for_what_that_mode_needs() {
        assert!(preflight_supported(
            IsolationArg::KataVfio,
            &every_check_passing()
        ));
        assert!(preflight_supported(
            IsolationArg::Shared,
            &every_check_passing()
        ));

        for missing in [
            PreflightChecks {
                kata_runtime: false,
                ..every_check_passing()
            },
            PreflightChecks {
                iommu: false,
                ..every_check_passing()
            },
            PreflightChecks {
                vfio: false,
                ..every_check_passing()
            },
            PreflightChecks {
                swap_disabled: false,
                ..every_check_passing()
            },
            PreflightChecks {
                vfio_gpu_groups: 0,
                ..every_check_passing()
            },
        ] {
            assert!(!preflight_supported(IsolationArg::KataVfio, &missing));
            assert!(
                preflight_supported(IsolationArg::Shared, &missing),
                "a stock host has none of the passthrough machinery and still serves open leases"
            );
        }

        for missing in [
            PreflightChecks {
                nvidia_smi: false,
                ..every_check_passing()
            },
            PreflightChecks {
                nvidia_container_cli: false,
                ..every_check_passing()
            },
            PreflightChecks {
                host_gpus: 0,
                ..every_check_passing()
            },
            PreflightChecks {
                workspace_ports_free: false,
                ..every_check_passing()
            },
            PreflightChecks {
                forward_chain_open: false,
                ..every_check_passing()
            },
        ] {
            assert!(!preflight_supported(IsolationArg::Shared, &missing));
            assert!(preflight_supported(IsolationArg::KataVfio, &missing));
        }

        for missing in [
            PreflightChecks {
                linux: false,
                ..every_check_passing()
            },
            PreflightChecks {
                x86_64: false,
                ..every_check_passing()
            },
            PreflightChecks {
                containerd: false,
                ..every_check_passing()
            },
            PreflightChecks {
                nerdctl: false,
                ..every_check_passing()
            },
            PreflightChecks {
                nftables: false,
                ..every_check_passing()
            },
        ] {
            assert!(!preflight_supported(IsolationArg::KataVfio, &missing));
            assert!(!preflight_supported(IsolationArg::Shared, &missing));
        }
    }

    /// A machine that still has a bound group and a kata shim, configured to
    /// serve open leases, reports open. Reading the posture off the host would
    /// let it claim a class it is not serving.
    #[test]
    fn a_node_configured_shared_reports_shared_whatever_the_host_has_installed() {
        let with_kata = HostTeeCapability {
            kata_runtime: true,
            ..HostTeeCapability::default()
        };
        let setting = IsolationSetting::Shared {
            gpu: gpu::HostGpu {
                index: 0,
                uuid: "GPU-1a2b3c4d-0000-0000-0000-000000000001".to_owned(),
                model: "NVIDIA GeForce RTX 4090".to_owned(),
                vram_mib: 24_564,
            },
            limits: runtime::LeaseLimits {
                memory_mib: 24_576,
                cpus: 7,
            },
        };
        let posture = setting.posture(&with_kata);
        assert_eq!(posture.isolation, IsolationMode::Shared);
        assert!(posture.attestation.is_none());
    }

    #[test]
    fn a_flag_that_names_one_mode_is_refused_under_the_other() {
        assert!(
            isolation_request(IsolationArg::Shared, Some(5), None, None, None).is_err(),
            "a shared lease takes the card by UUID and there is no group to name"
        );
        assert!(
            isolation_request(
                IsolationArg::KataVfio,
                Some(5),
                Some("GPU-1a2b3c4d".to_owned()),
                None,
                None
            )
            .is_err()
        );
        assert!(
            isolation_request(IsolationArg::KataVfio, Some(5), None, Some(4_096), None).is_err()
        );
        assert!(isolation_request(IsolationArg::KataVfio, Some(5), None, None, Some(4)).is_err());

        assert_eq!(
            isolation_request(IsolationArg::KataVfio, Some(5), None, None, None).unwrap(),
            IsolationRequest::KataVfio { group: Some(5) }
        );
        assert_eq!(
            isolation_request(IsolationArg::Shared, None, None, Some(4_096), Some(4)).unwrap(),
            IsolationRequest::Shared {
                gpu_uuid: None,
                memory_mib: Some(4_096),
                cpus: Some(4),
            }
        );
    }

    /// The daemon discovers the group. A lease started by hand says which card
    /// it takes, so a missing group is a refusal rather than a guess.
    #[test]
    fn a_hand_run_passthrough_launch_has_to_name_its_group() {
        assert!(launch_vfio_group(&IsolationRequest::KataVfio { group: None }).is_err());
        assert_eq!(
            launch_vfio_group(&IsolationRequest::KataVfio { group: Some(42) }).unwrap(),
            Some(42)
        );
        assert_eq!(
            launch_vfio_group(&IsolationRequest::Shared {
                gpu_uuid: None,
                memory_mib: None,
                cpus: None,
            })
            .unwrap(),
            None
        );
    }

    /// A node that says nothing about isolation is the passthrough node this
    /// daemon has always been.
    #[test]
    fn the_isolation_default_is_the_passthrough_node() {
        let cli = Cli::try_parse_from(["prismd", "preflight"]).unwrap();
        assert!(matches!(
            cli.command,
            CommandName::Preflight {
                isolation: IsolationArg::KataVfio
            }
        ));
        let cli = Cli::try_parse_from(["prismd", "preflight", "--isolation", "shared"]).unwrap();
        assert!(matches!(
            cli.command,
            CommandName::Preflight {
                isolation: IsolationArg::Shared
            }
        ));
    }

    #[test]
    fn token_amounts_render_for_humans() {
        assert_eq!(format_token(50_000 * 10_u128.pow(18)), "50000");
        assert_eq!(format_token(1_500_000_000_000_000_000), "1.5000");
        assert_eq!(format_token(0), "0");
    }
}
