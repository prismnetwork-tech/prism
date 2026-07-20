use std::{env, net::IpAddr};

use anyhow::Context;
use aws_sdk_kms::{
    Client as KmsClient,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use k256::{
    PublicKey,
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashSigner},
    pkcs8::DecodePublicKey,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha3::{Digest, Keccak256};

#[derive(Clone)]
pub struct RpcClient {
    client: reqwest::Client,
    url: url::Url,
}

pub enum EthereumSigner {
    Kms(KmsSigner),
    Local(LocalSigner),
}

pub struct KmsSigner {
    client: KmsClient,
    key_id: String,
    public_key: VerifyingKey,
    address: [u8; 20],
}

pub struct LocalSigner {
    key: SigningKey,
    address: [u8; 20],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedTransaction {
    pub nonce: u64,
    pub raw_transaction: String,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionReceipt {
    pub status: String,
    pub block_number: String,
    pub block_hash: String,
    #[serde(default)]
    pub logs: Vec<ChainLog>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finality {
    Pending,
    Confirmed {
        block_number: u64,
        block_hash: String,
    },
    Reverted {
        block_number: u64,
        block_hash: String,
    },
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: serde_json::Value,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
    timestamp: String,
}

impl RpcClient {
    pub fn new(value: &str) -> anyhow::Result<Self> {
        let url = secure_rpc_url(value)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            url,
        })
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<T> {
        let response = self
            .client
            .post(self.url.clone())
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<RpcResponse>()
            .await?;
        if let Some(error) = response.error {
            anyhow::bail!("RPC {method} failed with {}: {}", error.code, error.message);
        }
        serde_json::from_value(response.result).context("RPC response contains an invalid result")
    }

    pub async fn quantity(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> anyhow::Result<u64> {
        let value: String = self.call(method, params).await?;
        parse_quantity(&value)
    }

    pub async fn chain_id(&self) -> anyhow::Result<u64> {
        self.quantity("eth_chainId", serde_json::json!([])).await
    }

    pub async fn prepare_transaction(
        &self,
        signer: &EthereumSigner,
        to: [u8; 20],
        data: &[u8],
        chain_id: u64,
    ) -> anyhow::Result<PreparedTransaction> {
        let from = format!("0x{}", hex::encode(signer.address()));
        let destination = format!("0x{}", hex::encode(to));
        let nonce = self
            .quantity(
                "eth_getTransactionCount",
                serde_json::json!([from, "pending"]),
            )
            .await?;
        let gas_price = self.quantity("eth_gasPrice", serde_json::json!([])).await?;
        let gas_limit = self
            .quantity(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": from,
                    "to": destination,
                    "data": format!("0x{}", hex::encode(data)),
                    "value": "0x0"
                }]),
            )
            .await?;
        let unsigned = legacy_unsigned_transaction(nonce, gas_price, gas_limit, to, data, chain_id);
        let digest: [u8; 32] = Keccak256::digest(&unsigned).into();
        let signature = signer.sign_digest(&digest).await?;
        let raw =
            legacy_signed_transaction(nonce, gas_price, gas_limit, to, data, chain_id, &signature);
        Ok(PreparedTransaction {
            nonce,
            transaction_hash: format!("0x{}", hex::encode(Keccak256::digest(&raw))),
            raw_transaction: format!("0x{}", hex::encode(raw)),
        })
    }

    pub async fn submit(&self, transaction: &PreparedTransaction) -> anyhow::Result<()> {
        let known: Option<serde_json::Value> = self
            .call(
                "eth_getTransactionByHash",
                serde_json::json!([transaction.transaction_hash]),
            )
            .await?;
        if known.is_some() {
            return Ok(());
        }
        let hash: String = self
            .call(
                "eth_sendRawTransaction",
                serde_json::json!([transaction.raw_transaction]),
            )
            .await?;
        if !hash.eq_ignore_ascii_case(&transaction.transaction_hash) {
            anyhow::bail!("RPC returned an unexpected transaction hash");
        }
        Ok(())
    }

    pub async fn finality(
        &self,
        transaction_hash: &str,
        confirmations: u64,
    ) -> anyhow::Result<Finality> {
        let receipt: Option<TransactionReceipt> = self
            .call(
                "eth_getTransactionReceipt",
                serde_json::json!([transaction_hash]),
            )
            .await?;
        let Some(receipt) = receipt else {
            return Ok(Finality::Pending);
        };
        let block_number = parse_quantity(&receipt.block_number)?;
        let current = self
            .quantity("eth_blockNumber", serde_json::json!([]))
            .await?;
        if current < block_number.saturating_add(confirmations) {
            return Ok(Finality::Pending);
        }
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([receipt.block_number, false]),
            )
            .await?;
        if block.is_none_or(|block| !block.hash.eq_ignore_ascii_case(&receipt.block_hash)) {
            return Ok(Finality::Pending);
        }
        let finality = if parse_quantity(&receipt.status)? == 1 {
            Finality::Confirmed {
                block_number,
                block_hash: receipt.block_hash,
            }
        } else {
            Finality::Reverted {
                block_number,
                block_hash: receipt.block_hash,
            }
        };
        Ok(finality)
    }

    pub async fn transaction_receipt(
        &self,
        transaction_hash: &str,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        self.call(
            "eth_getTransactionReceipt",
            serde_json::json!([transaction_hash]),
        )
        .await
    }

    pub async fn block_timestamp(&self, block_number: u64) -> anyhow::Result<u64> {
        let block: Option<BlockHeader> = self
            .call(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{block_number:x}"), false]),
            )
            .await?;
        parse_quantity(&block.context("confirmed block is unavailable")?.timestamp)
    }
}

impl EthereumSigner {
    pub async fn from_environment(key_id_env: &str) -> anyhow::Result<Self> {
        if env::var("PRISM_ALLOW_DEVELOPMENT_SIGNER").as_deref() == Ok("1") {
            let encoded = env::var("PRISM_DEVELOPMENT_PRIVATE_KEY")
                .context("PRISM_DEVELOPMENT_PRIVATE_KEY is required for the development signer")?;
            return Ok(Self::Local(LocalSigner::new(&encoded)?));
        }
        let key_id = env::var(key_id_env).with_context(|| format!("{key_id_env} is required"))?;
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        Ok(Self::Kms(
            KmsSigner::new(KmsClient::new(&config), key_id).await?,
        ))
    }

    pub fn address(&self) -> [u8; 20] {
        match self {
            Self::Kms(signer) => signer.address,
            Self::Local(signer) => signer.address,
        }
    }

    pub async fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        match self {
            Self::Kms(signer) => signer.sign_digest(digest).await,
            Self::Local(signer) => signer.sign_digest(digest),
        }
    }
}

impl KmsSigner {
    async fn new(client: KmsClient, key_id: String) -> anyhow::Result<Self> {
        let output = client.get_public_key().key_id(&key_id).send().await?;
        if output.key_spec().map(|spec| spec.as_str()) != Some("ECC_SECG_P256K1") {
            anyhow::bail!("KMS key must use ECC_SECG_P256K1");
        }
        let der = output
            .public_key()
            .context("KMS response contains no public key")?
            .as_ref();
        let public_key = VerifyingKey::from(PublicKey::from_public_key_der(der)?);
        let address = ethereum_address(&public_key);
        Ok(Self {
            client,
            key_id,
            public_key,
            address,
        })
    }

    async fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await?;
        let der = output
            .signature()
            .context("KMS response contains no signature")?
            .as_ref();
        ethereum_signature(digest, &Signature::from_der(der)?, &self.public_key)
    }
}

impl LocalSigner {
    fn new(value: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
        let key = SigningKey::from_slice(&bytes).context("development private key is invalid")?;
        let address = ethereum_address(key.verifying_key());
        Ok(Self { key, address })
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
        let signature: Signature = self.key.sign_prehash(digest)?;
        ethereum_signature(digest, &signature, self.key.verifying_key())
    }
}

pub fn address(value: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(
        value
            .strip_prefix("0x")
            .context("address must start with 0x")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("address must contain 20 bytes"))
}

pub fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

pub fn word_bytes32(value: [u8; 32]) -> [u8; 32] {
    value
}

pub fn selector(signature: &str) -> [u8; 4] {
    Keccak256::digest(signature.as_bytes())[..4]
        .try_into()
        .expect("selector is four bytes")
}

pub fn parse_quantity(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(
        value
            .strip_prefix("0x")
            .context("RPC quantity is not hex")?,
        16,
    )
    .context("RPC quantity exceeds uint64")
}

fn ethereum_address(public_key: &VerifyingKey) -> [u8; 20] {
    let encoded = public_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    digest[12..]
        .try_into()
        .expect("Ethereum address is 20 bytes")
}

fn ethereum_signature(
    digest: &[u8; 32],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> anyhow::Result<[u8; 65]> {
    let signature = signature.normalize_s().unwrap_or(*signature);
    let recovery_id = [0_u8, 1_u8]
        .into_iter()
        .filter_map(RecoveryId::from_byte)
        .find(|recovery_id| {
            VerifyingKey::recover_from_prehash(digest, &signature, *recovery_id)
                .is_ok_and(|recovered| recovered == *public_key)
        })
        .context("signature does not recover the configured public key")?;
    let bytes = signature.to_bytes();
    let mut output = [0_u8; 65];
    output[..64].copy_from_slice(&bytes);
    output[64] = 27 + recovery_id.to_byte();
    Ok(output)
}

fn legacy_unsigned_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&chain_id);
    stream.append(&0_u8);
    stream.append(&0_u8);
    stream.out().to_vec()
}

fn legacy_signed_transaction(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: [u8; 20],
    data: &[u8],
    chain_id: u64,
    signature: &[u8; 65],
) -> Vec<u8> {
    let v = chain_id * 2 + 35 + u64::from(signature[64] - 27);
    let mut stream = RlpStream::new_list(9);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&0_u8);
    stream.append(&data);
    stream.append(&v);
    stream.append(&trim_integer(&signature[..32]));
    stream.append(&trim_integer(&signature[32..64]));
    stream.out().to_vec()
}

fn trim_integer(value: &[u8]) -> &[u8] {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first..]
}

fn secure_rpc_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value)?;
    let local_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
    if url.scheme() != "https" && !local_http {
        anyhow::bail!("RPC URL must use HTTPS outside localhost");
    }
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("RPC URL must not contain credentials");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_signer_produces_recoverable_low_s_signatures() {
        let signer =
            LocalSigner::new("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let digest = [7_u8; 32];
        let signature = signer.sign_digest(&digest).unwrap();
        assert!(matches!(signature[64], 27 | 28));
        let parsed = Signature::from_slice(&signature[..64]).unwrap();
        assert!(parsed.normalize_s().is_none());
        assert_eq!(
            hex::encode(signer.address),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn transaction_is_bound_to_chain_id() {
        let signature = {
            let mut signature = [1_u8; 65];
            signature[64] = 27;
            signature
        };
        let first = legacy_signed_transaction(1, 2, 3, [4_u8; 20], &[5], 4_663, &signature);
        let second = legacy_signed_transaction(1, 2, 3, [4_u8; 20], &[5], 46_630, &signature);
        assert_ne!(Keccak256::digest(first), Keccak256::digest(second));
    }
}
