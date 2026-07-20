use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const ROBINHOOD_CHAIN_ID: u64 = 4_663;
pub const ROBINHOOD_TESTNET_CHAIN_ID: u64 = 46_630;
pub const USDG_MAINNET: &str = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
pub const MAX_ESCROW_BASE_UNITS: u64 = 50_000_000;
pub const MAX_LEASE_SECONDS: u32 = 21_600;
pub const MAX_NETWORK_LEASES: usize = 25;
const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-enrollment.v1\0";
const TELEMETRY_SIGNATURE_DOMAIN: &[u8] = b"prism.node-telemetry.v1\0";
const TUNNEL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-tunnel.v1\0";
const CERTIFICATE_SIGNATURE_DOMAIN: &[u8] = b"prism.node-certificate.v1\0";
const COMMAND_POLL_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-poll.v1\0";
const COMMAND_REPORT_SIGNATURE_DOMAIN: &[u8] = b"prism.node-command-report.v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub usd_token: String,
    pub rpc_url: String,
    pub explorer_url: String,
}

impl ChainConfig {
    pub fn mainnet(rpc_url: impl Into<String>) -> Self {
        Self {
            chain_id: ROBINHOOD_CHAIN_ID,
            usd_token: USDG_MAINNET.to_owned(),
            rpc_url: rpc_url.into(),
            explorer_url: "https://robinhoodchain.blockscout.com".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub subject: String,
    pub linked_wallets: Vec<String>,
    pub risk_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuSpec {
    pub model: String,
    pub vram_mib: u32,
    pub cuda_major: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeOffer {
    pub node_id: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub device_public_key: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub reliability_bps: u16,
    pub benchmark_score: u32,
    pub bonded: bool,
    pub online: bool,
    pub public_image_only: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEnrollment {
    pub node_id: String,
    pub device_public_key: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub benchmark_score: u32,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNodeEnrollment {
    pub node_id: String,
    pub device_public_key: String,
    pub operator_wallet: String,
    pub payout_wallet: String,
    pub gpu: GpuSpec,
    pub rate_per_second: u64,
    pub benchmark_score: u32,
    pub issued_at: DateTime<Utc>,
}

impl NodeEnrollment {
    pub fn sign(unsigned: UnsignedNodeEnrollment, key: &SigningKey) -> Result<Self, ProtocolError> {
        let payload = signature_payload(ENROLLMENT_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            operator_wallet: unsigned.operator_wallet,
            payout_wallet: unsigned.payout_wallet,
            gpu: unsigned.gpu,
            rate_per_second: unsigned.rate_per_second,
            benchmark_score: unsigned.benchmark_score,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeEnrollment {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                operator_wallet: self.operator_wallet.clone(),
                payout_wallet: self.payout_wallet.clone(),
                gpu: self.gpu.clone(),
                rate_per_second: self.rate_per_second,
                benchmark_score: self.benchmark_score,
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            ENROLLMENT_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeTelemetry {
    pub node_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub gpu_utilization_bps: u16,
    pub gpu_memory_used_mib: u32,
    pub active_lease: Option<String>,
    pub tunnel_connected: bool,
    pub image_digest: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedTelemetry {
    pub node_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub gpu_utilization_bps: u16,
    pub gpu_memory_used_mib: u32,
    pub active_lease: Option<String>,
    pub tunnel_connected: bool,
    pub image_digest: Option<String>,
}

impl NodeTelemetry {
    pub fn sign(unsigned: UnsignedTelemetry, key: &SigningKey) -> Result<Self, ProtocolError> {
        let payload = signature_payload(TELEMETRY_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            sequence: unsigned.sequence,
            observed_at: unsigned.observed_at,
            gpu_utilization_bps: unsigned.gpu_utilization_bps,
            gpu_memory_used_mib: unsigned.gpu_memory_used_mib,
            active_lease: unsigned.active_lease,
            tunnel_connected: unsigned.tunnel_connected,
            image_digest: unsigned.image_digest,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedTelemetry {
                node_id: self.node_id.clone(),
                sequence: self.sequence,
                observed_at: self.observed_at,
                gpu_utilization_bps: self.gpu_utilization_bps,
                gpu_memory_used_mib: self.gpu_memory_used_mib,
                active_lease: self.active_lease.clone(),
                tunnel_connected: self.tunnel_connected,
                image_digest: self.image_digest.clone(),
            },
            &self.signature,
            key,
            TELEMETRY_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelRegistration {
    pub node_id: String,
    pub device_public_key: String,
    pub connection_id: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedTunnelRegistration {
    pub node_id: String,
    pub device_public_key: String,
    pub connection_id: String,
    pub issued_at: DateTime<Utc>,
}

impl TunnelRegistration {
    pub fn sign(
        unsigned: UnsignedTunnelRegistration,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = signature_payload(TUNNEL_SIGNATURE_DOMAIN, &unsigned)?;
        let signature = key.sign(&payload);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            connection_id: unsigned.connection_id,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedTunnelRegistration {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                connection_id: self.connection_id.clone(),
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            TUNNEL_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCertificateRequest {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub csr_pem: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNodeCertificateRequest {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub csr_pem: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCertificateBundle {
    pub certificate_id: Uuid,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub fingerprint_sha256: String,
    pub expires_at: DateTime<Utc>,
}

impl NodeCertificateRequest {
    pub fn sign(
        unsigned: UnsignedNodeCertificateRequest,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let signature = key.sign(&signature_payload(CERTIFICATE_SIGNATURE_DOMAIN, &unsigned)?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            csr_pem: unsigned.csr_pem,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeCertificateRequest {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                csr_pem: self.csr_pem.clone(),
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            CERTIFICATE_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRequest {
    pub image: String,
    pub duration_seconds: u32,
    pub min_vram_mib: u32,
    pub preferred_node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseQuote {
    pub quote_id: Uuid,
    pub node_id: String,
    pub image: String,
    pub duration_seconds: u32,
    pub min_vram_mib: u32,
    pub rate_per_second: u64,
    pub maximum_escrow: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Funded,
    Provisioning,
    Ready,
    Active,
    Closing,
    SettlementPending,
    Disputed,
    Finalized,
    Refunded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseRecord {
    pub lease_id: u64,
    pub quote_id: Uuid,
    pub node_id: String,
    pub renter_wallet: String,
    pub image: String,
    pub duration_seconds: u32,
    pub rate_per_second: u64,
    pub maximum_escrow: u64,
    pub funding_transaction_hash: String,
    pub state: LeaseState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommand {
    pub command_id: Uuid,
    pub node_id: String,
    pub lease_id: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub kind: NodeCommandKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeCommandKind {
    Launch {
        image: String,
        duration_seconds: u32,
        ssh_authorized_key: String,
        jupyter_token: String,
    },
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandPoll {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnsignedNodeCommandPoll {
    node_id: String,
    device_public_key: String,
    request_id: Uuid,
    issued_at: DateTime<Utc>,
}

impl NodeCommandPoll {
    pub fn sign(
        node_id: String,
        device_public_key: String,
        request_id: Uuid,
        issued_at: DateTime<Utc>,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let unsigned = UnsignedNodeCommandPoll {
            node_id,
            device_public_key,
            request_id,
            issued_at,
        };
        let signature = key.sign(&signature_payload(
            COMMAND_POLL_SIGNATURE_DOMAIN,
            &unsigned,
        )?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            issued_at: unsigned.issued_at,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &UnsignedNodeCommandPoll {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                issued_at: self.issued_at,
            },
            &self.signature,
            key,
            COMMAND_POLL_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeCommandOutcome {
    Ready,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandReport {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub command_id: Uuid,
    pub outcome: NodeCommandOutcome,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCommandReportPayload {
    pub node_id: String,
    pub device_public_key: String,
    pub request_id: Uuid,
    pub command_id: Uuid,
    pub outcome: NodeCommandOutcome,
    pub observed_at: DateTime<Utc>,
    pub error: Option<String>,
}

impl NodeCommandReport {
    pub fn sign(
        unsigned: NodeCommandReportPayload,
        key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let signature = key.sign(&signature_payload(
            COMMAND_REPORT_SIGNATURE_DOMAIN,
            &unsigned,
        )?);
        Ok(Self {
            node_id: unsigned.node_id,
            device_public_key: unsigned.device_public_key,
            request_id: unsigned.request_id,
            command_id: unsigned.command_id,
            outcome: unsigned.outcome,
            observed_at: unsigned.observed_at,
            error: unsigned.error,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtocolError> {
        verify_signature(
            &NodeCommandReportPayload {
                node_id: self.node_id.clone(),
                device_public_key: self.device_public_key.clone(),
                request_id: self.request_id,
                command_id: self.command_id,
                outcome: self.outcome.clone(),
                observed_at: self.observed_at,
                error: self.error.clone(),
            },
            &self.signature,
            key,
            COMMAND_REPORT_SIGNATURE_DOMAIN,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicReceipt {
    pub receipt_id: Uuid,
    pub lease_id: String,
    pub node_id_hash: String,
    pub gpu_model: String,
    pub runtime_seconds: u64,
    pub charged_base_units: u64,
    pub refunded_base_units: u64,
    pub provider_paid_base_units: u64,
    pub failure_class: Option<String>,
    pub outcome: ReceiptOutcome,
    pub receipt_hash: String,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementEvidence {
    pub lease_id: u64,
    pub lease_nonce: u128,
    pub node_id: String,
    pub device_public_key: String,
    pub gpu_model: String,
    pub image_digest: String,
    pub rate_per_second: u64,
    pub deposit_base_units: u64,
    pub duration_seconds: u32,
    pub access_started_at: u64,
    pub access_ended_at: u64,
    pub cuda_ready_at: u64,
    pub interactive_access_ready_at: u64,
    pub gateway_closed_at: u64,
    #[serde(default)]
    pub execution: ExecutionEvidence,
    pub node_telemetry: Vec<NodeTelemetry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ExecutionEvidence {
    #[default]
    Physical,
    Vast {
        instance_id: u64,
        hourly_cost_micros: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiptPayload {
    receipt_id: Uuid,
    lease_id: String,
    node_id_hash: String,
    gpu_model: String,
    runtime_seconds: u64,
    charged_base_units: u64,
    refunded_base_units: u64,
    provider_paid_base_units: u64,
    failure_class: Option<String>,
    outcome: ReceiptOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Finalized,
    Refunded,
    Disputed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessGrant {
    pub token_id: Uuid,
    pub lease_id: String,
    pub node_id: String,
    pub connection_id: String,
    pub ssh_user: String,
    pub jupyter_path: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum LeaseAccess {
    Gateway {
        lease_id: u64,
        token: String,
        gateway_host: String,
        relay_port: u16,
        ssh_user: String,
        jupyter_path: String,
        jupyter_token: String,
        expires_at: DateTime<Utc>,
    },
    DirectSsh {
        lease_id: u64,
        ssh_host: String,
        ssh_port: u16,
        ssh_user: String,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone)]
pub struct CredentialCipher(Aes256Gcm);

impl CredentialCipher {
    pub fn from_hex(value: &str) -> Result<Self, ProtocolError> {
        let bytes = hex::decode(value).map_err(|_| ProtocolError::InvalidEncryptionKey)?;
        if bytes.len() != 32 {
            return Err(ProtocolError::InvalidEncryptionKey);
        }
        Ok(Self(
            Aes256Gcm::new_from_slice(&bytes).map_err(|_| ProtocolError::InvalidEncryptionKey)?,
        ))
    }

    pub fn encrypt(&self, value: &str) -> Result<EncryptedSecret, ProtocolError> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_value = nonce.into();
        let ciphertext = self
            .0
            .encrypt(&nonce_value, value.as_bytes())
            .map_err(|_| ProtocolError::Encryption)?;
        Ok(EncryptedSecret {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, secret: &EncryptedSecret) -> Result<String, ProtocolError> {
        let nonce = URL_SAFE_NO_PAD
            .decode(&secret.nonce)
            .map_err(|_| ProtocolError::Encryption)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&secret.ciphertext)
            .map_err(|_| ProtocolError::Encryption)?;
        if nonce.len() != 12 {
            return Err(ProtocolError::Encryption);
        }
        let nonce_value: [u8; 12] = nonce.try_into().map_err(|_| ProtocolError::Encryption)?;
        let nonce_value = Nonce::from(nonce_value);
        let plaintext = self
            .0
            .decrypt(&nonce_value, ciphertext.as_ref())
            .map_err(|_| ProtocolError::Encryption)?;
        String::from_utf8(plaintext).map_err(|_| ProtocolError::Encryption)
    }
}

pub fn node_id(device_public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(device_public_key.as_bytes());
    format!("0x{}", hex::encode(digest))
}

pub fn verifying_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidPublicKey)?,
    )
    .map_err(|_| ProtocolError::InvalidPublicKey)
}

pub fn receipt_hash(receipt: &PublicReceipt) -> Result<String, ProtocolError> {
    let payload = ReceiptPayload {
        receipt_id: receipt.receipt_id,
        lease_id: receipt.lease_id.clone(),
        node_id_hash: receipt.node_id_hash.clone(),
        gpu_model: receipt.gpu_model.clone(),
        runtime_seconds: receipt.runtime_seconds,
        charged_base_units: receipt.charged_base_units,
        refunded_base_units: receipt.refunded_base_units,
        provider_paid_base_units: receipt.provider_paid_base_units,
        failure_class: receipt.failure_class.clone(),
        outcome: receipt.outcome.clone(),
    };
    Ok(hex::encode(Sha256::digest(canonical_json(&payload)?)))
}

pub fn receipt_hash_matches(receipt: &PublicReceipt) -> Result<bool, ProtocolError> {
    Ok(receipt.receipt_hash == receipt_hash(receipt)?)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_string(value).map_err(ProtocolError::Serialization)
}

fn signature_payload<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, ProtocolError> {
    let encoded = canonical_json(value)?;
    let mut payload = Vec::with_capacity(domain.len() + encoded.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(encoded.as_bytes());
    Ok(payload)
}

fn verify_signature<T: Serialize>(
    value: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
    domain: &[u8],
) -> Result<(), ProtocolError> {
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&signature).map_err(|_| ProtocolError::InvalidSignature)?;
    let payload = signature_payload(domain, value)?;
    key.verify(&payload, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("serialization failed")]
    Serialization(#[source] serde_json::Error),
    #[error("credential encryption key is invalid")]
    InvalidEncryptionKey,
    #[error("credential encryption failed")]
    Encryption,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let telemetry = NodeTelemetry::sign(
            UnsignedTelemetry {
                node_id: node_id(&key.verifying_key()),
                sequence: 1,
                observed_at: Utc::now(),
                gpu_utilization_bps: 4_200,
                gpu_memory_used_mib: 1_024,
                active_lease: None,
                tunnel_connected: true,
                image_digest: Some("sha256:abc".to_owned()),
            },
            &key,
        )
        .unwrap();

        assert!(telemetry.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn enrollment_round_trip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let enrollment = NodeEnrollment::sign(
            UnsignedNodeEnrollment {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                operator_wallet: "0x1111111111111111111111111111111111111111".to_owned(),
                payout_wallet: "0x2222222222222222222222222222222222222222".to_owned(),
                gpu: GpuSpec {
                    model: "NVIDIA L4".to_owned(),
                    vram_mib: 24_576,
                    cuda_major: 12,
                },
                rate_per_second: 1_000,
                benchmark_score: 10_000,
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(enrollment.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn receipt_hash_excludes_the_hash_field() {
        let mut receipt = PublicReceipt {
            receipt_id: Uuid::now_v7(),
            lease_id: "lease-1".to_owned(),
            node_id_hash: "0x1234".to_owned(),
            gpu_model: "NVIDIA L4".to_owned(),
            runtime_seconds: 60,
            charged_base_units: 1_000,
            refunded_base_units: 0,
            provider_paid_base_units: 900,
            failure_class: None,
            outcome: ReceiptOutcome::Finalized,
            receipt_hash: String::new(),
            transaction_hash: "0x5678".to_owned(),
        };
        receipt.receipt_hash = receipt_hash(&receipt).unwrap();

        assert!(receipt_hash_matches(&receipt).unwrap());
        receipt.runtime_seconds = 61;
        assert!(!receipt_hash_matches(&receipt).unwrap());
        receipt.runtime_seconds = 60;
        receipt.transaction_hash = "0x9999".to_owned();
        assert!(receipt_hash_matches(&receipt).unwrap());
    }

    #[test]
    fn credential_cipher_rejects_tampering() {
        let cipher = CredentialCipher::from_hex(&"11".repeat(32)).unwrap();
        let mut secret = cipher.encrypt("temporary credential").unwrap();
        assert_eq!(cipher.decrypt(&secret).unwrap(), "temporary credential");
        secret.ciphertext.push('A');
        assert!(cipher.decrypt(&secret).is_err());
    }

    #[test]
    fn tunnel_registration_is_bound_to_the_connection() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut registration = TunnelRegistration::sign(
            UnsignedTunnelRegistration {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                connection_id: "connection-1".to_owned(),
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(registration.verify(&key.verifying_key()).is_ok());
        registration.connection_id = "connection-2".to_owned();
        assert!(registration.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn certificate_request_is_bound_to_the_csr() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut request = NodeCertificateRequest::sign(
            UnsignedNodeCertificateRequest {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                request_id: Uuid::now_v7(),
                csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nrequest\n-----END CERTIFICATE REQUEST-----"
                    .to_owned(),
                issued_at: Utc::now(),
            },
            &key,
        )
        .unwrap();

        assert!(request.verify(&key.verifying_key()).is_ok());
        request.csr_pem.push('x');
        assert!(request.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn command_reports_are_bound_to_the_command_and_outcome() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let command_id = Uuid::now_v7();
        let mut report = NodeCommandReport::sign(
            NodeCommandReportPayload {
                node_id: node_id(&key.verifying_key()),
                device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
                request_id: Uuid::now_v7(),
                command_id,
                outcome: NodeCommandOutcome::Ready,
                observed_at: Utc::now(),
                error: None,
            },
            &key,
        )
        .unwrap();

        assert!(report.verify(&key.verifying_key()).is_ok());
        report.command_id = Uuid::now_v7();
        assert!(report.verify(&key.verifying_key()).is_err());
    }
}
