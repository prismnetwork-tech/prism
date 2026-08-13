use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
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
    CommandResult, GpuSpec, IsolationMode, NodeCertificateBundle, NodeCertificateRequest,
    NodeCommand, NodeCommandKind, NodeCommandOutcome, NodeCommandPoll, NodeCommandReport,
    NodeCommandReportPayload, NodeEnrollment, NodePosture, NodeTelemetry,
    UnsignedNodeCertificateRequest, UnsignedNodeEnrollment, UnsignedTelemetry, node_id,
};
use rand::RngCore;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};
use tracing_subscriber::EnvFilter;

mod runtime;
mod tunnel;

/// How long the signed device binding stays valid. Long enough to survive a
/// slow block, short enough that an abandoned signature cannot be replayed.
const REGISTRATION_WINDOW_SECONDS: u128 = 3_600;
/// Seven static words precede the signature in register()'s calldata.
const SIGNATURE_OFFSET: u128 = 7 * 32;
const CONFIRMATION_ATTEMPTS: u32 = 40;

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

#[derive(Subcommand)]
enum CommandName {
    Preflight,
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
        vfio_group: u32,
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
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RelayServiceArg {
    Ssh,
    Jupyter,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    supported: bool,
    architecture: String,
    linux: bool,
    nvidia_smi: bool,
    containerd: bool,
    nerdctl: bool,
    kata_runtime: bool,
    iommu: bool,
    vfio: bool,
    nftables: bool,
    swap_disabled: bool,
    nvidia_container_toolkit: bool,
    vfio_gpu_groups: Vec<runtime::VfioGroup>,
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
        CommandName::Preflight => preflight(),
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
            register(
                &identity,
                &rpc_url,
                &registry,
                payout_wallet.as_deref(),
                rate_per_second,
                &operator_key,
                &profile,
                dry_run,
            )
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
        CommandName::Commands {
            identity,
            control_plane,
            workspace_root,
            state_root,
            ssh_port,
            jupyter_port,
            poll_seconds,
        } => {
            command_loop(CommandLoopConfig {
                identity,
                control_plane,
                workspace_root,
                state_root,
                ssh_port,
                jupyter_port,
                poll_seconds,
            })
            .await
        }
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
            execute,
        } => {
            let config = runtime::LaunchConfig {
                image: &image,
                lease_id: &lease_id,
                workspace_root: &workspace_root,
                state_root: &state_root,
                vfio_group,
                duration_seconds,
                ssh_authorized_key: &ssh_authorized_key,
                jupyter_token: &jupyter_token,
                ssh_port,
                jupyter_port,
            };
            let command = runtime::kata_command(&config, &workspace_root.join(&lease_id))?;
            if execute {
                runtime::launch(config)
            } else {
                println!("{:?}", command);
                Ok(())
            }
        }
    }
}

fn preflight() -> anyhow::Result<()> {
    let linux = cfg!(target_os = "linux");
    let architecture = env::consts::ARCH.to_owned();
    let nvidia_smi = command_success("nvidia-smi", &["-L"]);
    let containerd = command_success("ctr", &["version"]);
    let nerdctl = command_success("nerdctl", &["version"]);
    let kata_runtime = command_success("kata-runtime", &["--version"])
        || command_success("kata-qemu", &["--version"]);
    let iommu = iommu_available();
    let vfio = Path::new("/dev/vfio/vfio").exists() && Path::new("/sys/module/vfio_pci").exists();
    let nftables = command_success("nft", &["--version"]);
    let swap_disabled = swap_disabled();
    let nvidia_container_toolkit = command_success("nvidia-ctk", &["--version"]);
    let vfio_gpu_groups = runtime::discover_vfio_gpu_groups()?;
    let report = PreflightReport {
        supported: linux
            && architecture == "x86_64"
            && containerd
            && nerdctl
            && kata_runtime
            && iommu
            && vfio
            && nftables
            && swap_disabled
            && !vfio_gpu_groups.is_empty(),
        architecture,
        linux,
        nvidia_smi,
        containerd,
        nerdctl,
        kata_runtime,
        iommu,
        vfio,
        nftables,
        swap_disabled,
        nvidia_container_toolkit,
        vfio_gpu_groups,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.supported {
        anyhow::bail!("host does not satisfy the GPU node baseline");
    }
    Ok(())
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
async fn register(
    identity_path: &Path,
    rpc_url: &str,
    registry: &str,
    payout_wallet: Option<&str>,
    rate_per_second: u128,
    operator_key: &str,
    profile: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
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
    if balance < bond {
        let shortfall = format!(
            "operator 0x{} holds {} PRISM and the bond for this rate is {} PRISM",
            hex::encode(operator),
            format_token(balance),
            format_token_required(bond)
        );
        if !dry_run {
            anyhow::bail!(shortfall);
        }
        println!("{shortfall}");
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
        simulate(&rpc, operator, registry_address, &data).await?;
        println!(
            "registration is valid: {node} would stake {} PRISM at {rate_per_second} USDG base units per second",
            format_token_required(bond)
        );
        return Ok(());
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
/// isolation has signed the claim the network would slash it for.
fn local_posture() -> NodePosture {
    let isolation = match runtime::discover_vfio_gpu_groups() {
        Ok(groups) if !groups.is_empty() => IsolationMode::KataVfio,
        _ => IsolationMode::Shared,
    };
    NodePosture {
        isolation,
        attestation: None,
    }
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
            posture: Some(local_posture()),
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
}

async fn command_loop(config: CommandLoopConfig) -> anyhow::Result<()> {
    if config.poll_seconds == 0 || config.poll_seconds > 60 {
        anyhow::bail!("command poll interval must be between one and 60 seconds");
    }
    if config.ssh_port == 0 || config.jupyter_port == 0 || config.ssh_port == config.jupyter_port {
        anyhow::bail!("workspace access ports are invalid");
    }
    fs::create_dir_all(&config.workspace_root)?;
    fs::create_dir_all(&config.state_root)?;
    let identity = load_identity(&config.identity)?;
    let key = signing_key(&identity)?;
    let node = node_id(&key.verifying_key());
    let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let client = http_client()?;
    let mut last_heartbeat = None;

    loop {
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
            if let Err(error) =
                execute_node_command(&client, &config, &node, &public_key, &key, command).await
            {
                tracing::error!(%error, "node command execution failed");
                tokio::time::sleep(Duration::from_secs(config.poll_seconds)).await;
            }
            continue;
        }
        if last_heartbeat.is_none_or(|last: chrono::DateTime<Utc>| {
            Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(30)
        }) {
            if let Err(error) = publish_telemetry(
                &config.identity,
                &config.control_plane,
                0,
                0,
                true,
                None,
                None,
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

async fn execute_node_command(
    client: &reqwest::Client,
    config: &CommandLoopConfig,
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
        )
        .await?;
        return Ok(());
    };
    let image_digest = image
        .rsplit_once('@')
        .map(|(_, digest)| digest.to_owned())
        .context("launch image has no immutable digest")?;
    let groups = runtime::discover_vfio_gpu_groups()?;
    let Some(group) = groups.first() else {
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
        )
        .await?;
        return Ok(());
    };
    let credential_root = config
        .state_root
        .join(format!(".credentials-{}", command.command_id));
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

    let lease_id = command.lease_id.to_string();
    let workspace_root = config.workspace_root.clone();
    let state_root = config.state_root.clone();
    let ssh_port = config.ssh_port;
    let jupyter_port = config.jupyter_port;
    let vfio_group = group.id;
    let launch_lease_id = lease_id.clone();
    let launch_ssh_key = ssh_key_path.clone();
    let launch_jupyter_token = jupyter_token_path.clone();
    let mut task = tokio::task::spawn_blocking(move || {
        runtime::launch(runtime::LaunchConfig {
            image: &image,
            lease_id: &launch_lease_id,
            workspace_root: &workspace_root,
            state_root: &state_root,
            vfio_group,
            duration_seconds,
            ssh_authorized_key: &launch_ssh_key,
            jupyter_token: &launch_jupyter_token,
            ssh_port,
            jupyter_port,
        })
    });
    let mut ready_reported_at = None;
    let mut telemetry_reported_at = None;
    while !task.is_finished() {
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
            )
            .await?;
            telemetry_reported_at = Some(Utc::now());
        }
        if ready
            && ready_reported_at.is_none_or(|last: chrono::DateTime<Utc>| {
                Utc::now().signed_duration_since(last) >= chrono::Duration::seconds(30)
            })
        {
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
            )
            .await?;
            ready_reported_at = Some(Utc::now());
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
    )
    .await
}

/// A batch command occupies the GPU exactly like a lease does, so it takes the
/// same VFIO group and reports through the same signed channel. The difference
/// is what comes back: what the command printed, rather than a way in.
#[allow(clippy::too_many_arguments)]
async fn run_batch_command(
    client: &reqwest::Client,
    config: &CommandLoopConfig,
    node: &str,
    public_key: &str,
    key: &SigningKey,
    command: &NodeCommand,
    image: &str,
    program: &str,
    duration_seconds: u32,
) -> anyhow::Result<()> {
    let groups = runtime::discover_vfio_gpu_groups()?;
    let Some(group) = groups.first() else {
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
        )
        .await;
    };

    let lease_id = command.lease_id.to_string();
    let workspace_root = config.workspace_root.clone();
    let state_root = config.state_root.clone();
    let vfio_group = group.id;
    let image = image.to_owned();
    let program = program.to_owned();
    let outcome = tokio::task::spawn_blocking(move || {
        runtime::run_batch(runtime::BatchConfig {
            image: &image,
            lease_id: &lease_id,
            command: &program,
            workspace_root: &workspace_root,
            state_root: &state_root,
            vfio_group,
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
                Some(format!("{error:#}")),
                None,
            )
            .await
        }
    }
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
) -> anyhow::Result<()> {
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
            },
            key,
        )?;
        let result = match client.post(endpoint.clone()).json(&report).send().await {
            Ok(response) => require_success(response).await,
            Err(error) => Err(error.into()),
        };
        match result {
            Ok(()) => return Ok(()),
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
        .and_then(|()| fs::rename(&temporary, path).context("persist device identity"));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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

    #[test]
    fn token_amounts_render_for_humans() {
        assert_eq!(format_token(50_000 * 10_u128.pow(18)), "50000");
        assert_eq!(format_token(1_500_000_000_000_000_000), "1.5000");
        assert_eq!(format_token(0), "0");
    }
}
